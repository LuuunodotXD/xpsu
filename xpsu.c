/*
 * xpsu (express su) - minimalist doas-like privilege escalation tool for Linux
 * No PAM: authentication against /etc/shadow via crypt()
 *
 * Usage:
 *   xpsu [-u user] command [args...]
 *
 * Config: /etc/xpsu.conf
 *   permit [nopass] [persist] [keepenv] identity [as target] [cmd path [args ...]]
 *   deny   identity [as target]
 *
 * Examples:
 *   permit nopass lunoo as root
 *   permit persist lunoo as root
 *   permit lunoo as root cmd /usr/bin/xpkg
 *   deny bob
 *
 * Build:
 *   gcc -O2 -Wall -o xpsu xpsu.c -lcrypt
 * Install (must be run as root):
 *   install -o root -g root -m 4755 xpsu /usr/local/bin/xpsu
 *   install -o root -g root -m 0640 xpsu.conf /etc/xpsu.conf
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <crypt.h>
#include <termios.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define PERSIST_DIR "/run/xpsu"
#define PERSIST_TIMEOUT 300 /* seconds a successful auth stays valid, like sudo's default timestamp window */

typedef struct rule {
    int allow;          /* 1 = permit, 0 = deny */
    int nopass;
    int persist;
    int keepenv;
    char ident[64];     /* user name or :group */
    char target[64];    /* target user, defaults to "root" */
    int has_cmd;
    char cmd[PATH_MAX]; /* required command path */
    char *cmdargs[MAX_ARGS];
    int cmdargc;
    struct rule *next;
} rule_t;

static rule_t *rules_head = NULL;

static void die(const char *msg) {
    fprintf(stderr, "xpsu: %s\n", msg);
    exit(1);
}

static void die_perm(void) {
    fprintf(stderr, "xpsu: not authorized\n");
    exit(1);
}

/* ---------- /etc/xpsu.conf parser ---------- */

static char *dup_or_die(const char *s) {
    char *r = strdup(s);
    if (!r) die("out of memory");
    return r;
}

static void parse_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) die("could not open /etc/xpsu.conf");

    char line[MAX_LINE];
    int lineno = 0;
    rule_t *tail = NULL;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        char *save = NULL;
        char *tok = strtok_r(p, " \t\r\n", &save);
        if (!tok) continue;

        rule_t *r = calloc(1, sizeof(rule_t));
        if (!r) die("out of memory");
        strcpy(r->target, "root");

        if (strcmp(tok, "permit") == 0) r->allow = 1;
        else if (strcmp(tok, "deny") == 0) r->allow = 0;
        else {
            fprintf(stderr, "xpsu: invalid line %d in %s\n", lineno, path);
            free(r);
            continue;
        }

        tok = strtok_r(NULL, " \t\r\n", &save);
        while (tok && (strcmp(tok, "nopass") == 0 || strcmp(tok, "persist") == 0 || strcmp(tok, "keepenv") == 0)) {
            if (strcmp(tok, "nopass") == 0) r->nopass = 1;
            else if (strcmp(tok, "persist") == 0) r->persist = 1;
            else r->keepenv = 1;
            tok = strtok_r(NULL, " \t\r\n", &save);
        }

        if (!tok) {
            fprintf(stderr, "xpsu: line %d missing identity in %s\n", lineno, path);
            free(r);
            continue;
        }
        strncpy(r->ident, tok, sizeof(r->ident) - 1);

        tok = strtok_r(NULL, " \t\r\n", &save);
        if (tok && strcmp(tok, "as") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &save);
            if (!tok) { fprintf(stderr, "xpsu: line %d 'as' with no target\n", lineno); free(r); continue; }
            strncpy(r->target, tok, sizeof(r->target) - 1);
            tok = strtok_r(NULL, " \t\r\n", &save);
        }

        if (tok && strcmp(tok, "cmd") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &save);
            if (!tok) { fprintf(stderr, "xpsu: line %d 'cmd' with no path\n", lineno); free(r); continue; }
            r->has_cmd = 1;
            strncpy(r->cmd, tok, sizeof(r->cmd) - 1);

            tok = strtok_r(NULL, " \t\r\n", &save);
            if (tok && strcmp(tok, "args") == 0) {
                tok = strtok_r(NULL, " \t\r\n", &save);
            }
            while (tok && r->cmdargc < MAX_ARGS - 1) {
                r->cmdargs[r->cmdargc++] = dup_or_die(tok);
                tok = strtok_r(NULL, " \t\r\n", &save);
            }
        }

        r->next = NULL;
        if (tail) tail->next = r; else rules_head = r;
        tail = r;
    }
    fclose(f);
}

/* ---------- identity check (user or :group) ---------- */

static int ident_matches(const char *ident, const char *user, uid_t uid) {
    if (ident[0] == ':') {
        struct group *g = getgrnam(ident + 1);
        if (!g) return 0;
        for (char **m = g->gr_mem; m && *m; m++)
            if (strcmp(*m, user) == 0) return 1;
        struct passwd *pw = getpwuid(uid);
        if (pw && pw->pw_gid == g->gr_gid) return 1;
        return 0;
    }
    return strcmp(ident, user) == 0;
}

/* ---------- resolve absolute path of a command via PATH ---------- */

static int resolve_path(const char *cmd, char *out, size_t outlen) {
    if (cmd[0] == '/') {
        if (access(cmd, X_OK) != 0) return -1;
        snprintf(out, outlen, "%s", cmd);
        return 0;
    }
    const char *path = getenv("PATH");
    if (!path) path = "/usr/bin:/bin:/usr/local/bin";
    char pathcopy[4096];
    strncpy(pathcopy, path, sizeof(pathcopy) - 1);
    pathcopy[sizeof(pathcopy) - 1] = '\0';

    char *save = NULL;
    char *dir = strtok_r(pathcopy, ":", &save);
    while (dir) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, cmd);
        if (access(full, X_OK) == 0) {
            snprintf(out, outlen, "%s", full);
            return 0;
        }
        dir = strtok_r(NULL, ":", &save);
    }
    return -1;
}

/* ---------- find the last matching rule (doas-style precedence) ---------- */

static rule_t *find_matching_rule(const char *user, uid_t uid, const char *target,
                                   const char *cmdpath, char **cmdargv, int cmdargc) {
    rule_t *best = NULL;
    for (rule_t *r = rules_head; r; r = r->next) {
        if (!ident_matches(r->ident, user, uid)) continue;
        if (strcmp(r->target, target) != 0) continue;

        if (r->has_cmd) {
            if (strcmp(r->cmd, cmdpath) != 0) continue;
            if (r->cmdargc > 0) {
                if (r->cmdargc != cmdargc) continue;
                int ok = 1;
                for (int i = 0; i < r->cmdargc; i++) {
                    if (strcmp(r->cmdargs[i], cmdargv[i]) != 0) { ok = 0; break; }
                }
                if (!ok) continue;
            }
        }
        best = r; /* last matching rule wins */
    }
    return best;
}

/* ---------- persist (timestamp cache), mirrors sudo's timestamp window ---------- */

static void persist_path(char *buf, size_t len, uid_t uid, const char *target) {
    snprintf(buf, len, PERSIST_DIR "/%d_%s", (int)uid, target);
}

static int persist_valid(uid_t uid, const char *target) {
    char path[PATH_MAX];
    persist_path(path, sizeof(path), uid, target);
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    /* reject if not owned by root or if group/other writable: avoid tampering */
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))) return 0;
    time_t now = time(NULL);
    if (now < st.st_mtime) return 0; /* clock went backwards, don't trust it */
    return (now - st.st_mtime) <= PERSIST_TIMEOUT;
}

static void persist_update(uid_t uid, const char *target) {
    if (mkdir(PERSIST_DIR, 0700) != 0 && errno != EEXIST) return;
    /* directory may already exist from a previous run; make sure perms are tight */
    chmod(PERSIST_DIR, 0700);

    char path[PATH_MAX];
    persist_path(path, sizeof(path), uid, target);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd); /* O_TRUNC on an existing file also refreshes mtime */
}

/* ---------- password reading without terminal echo ---------- */

static void read_password(char *buf, size_t len) {
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) die("tcgetattr failed");
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    printf("password: ");
    fflush(stdout);
    if (!fgets(buf, len, stdin)) buf[0] = '\0';
    printf("\n");

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    size_t l = strlen(buf);
    if (l > 0 && buf[l - 1] == '\n') buf[l - 1] = '\0';
}

static int authenticate(const char *user) {
    struct spwd *sp = getspnam(user);
    if (!sp) return -1;

    char password[256];
    read_password(password, sizeof(password));

    struct crypt_data data;
    data.initialized = 0;
    char *hash = crypt_r(password, sp->sp_pwdp, &data);
    memset(password, 0, sizeof(password));

    if (!hash) return -1;
    return strcmp(hash, sp->sp_pwdp) == 0 ? 0 : -1;
}

/* ---------- environment setup ---------- */

static void setup_env(struct passwd *target_pw, int keepenv) {
    if (!keepenv) {
        char *term = getenv("TERM");
        char *display = getenv("DISPLAY");
        char termbuf[64] = {0}, dispbuf[64] = {0};
        if (term) strncpy(termbuf, term, sizeof(termbuf) - 1);
        if (display) strncpy(dispbuf, display, sizeof(dispbuf) - 1);

        clearenv();

        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
        setenv("HOME", target_pw->pw_dir, 1);
        setenv("USER", target_pw->pw_name, 1);
        setenv("LOGNAME", target_pw->pw_name, 1);
        setenv("SHELL", target_pw->pw_shell, 1);
        if (termbuf[0]) setenv("TERM", termbuf, 1);
        if (dispbuf[0]) setenv("DISPLAY", dispbuf, 1);
    } else {
        setenv("HOME", target_pw->pw_dir, 1);
        setenv("USER", target_pw->pw_name, 1);
        setenv("LOGNAME", target_pw->pw_name, 1);
    }
}

/* ---------- logging (syslog, LOG_AUTHPRIV like doas/sudo) ---------- */

static void log_args(char *dst, size_t dstlen, char **argv, int argc) {
    dst[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < argc; i++) {
        int n = snprintf(dst + used, dstlen - used, "%s%s", i ? " " : "", argv[i]);
        if (n < 0 || (size_t)n >= dstlen - used) break;
        used += n;
    }
}

int main(int argc, char *argv[]) {
    const char *target_user = "root";
    int argi = 1;

    if (argc >= 3 && strcmp(argv[1], "-u") == 0) {
        target_user = argv[2];
        argi = 3;
    }

    if (argi >= argc) {
        fprintf(stderr, "usage: xpsu [-u user] command [args...]\n");
        return 1;
    }

    openlog("xpsu", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);

    uid_t real_uid = getuid();
    struct passwd *real_pw = getpwuid(real_uid);
    if (!real_pw) die("could not identify the current user");

    struct passwd *target_pw = getpwnam(target_user);
    if (!target_pw) die("unknown target user");

    parse_config("/etc/xpsu.conf");

    char cmdpath[PATH_MAX];
    if (resolve_path(argv[argi], cmdpath, sizeof(cmdpath)) != 0)
        die("command not found in PATH");

    char **rest_args = &argv[argi + 1];
    int rest_argc = argc - argi - 1;

    rule_t *r = find_matching_rule(real_pw->pw_name, real_uid, target_user,
                                    cmdpath, rest_args, rest_argc);

    if (!r || !r->allow) {
        syslog(LOG_WARNING, "%s not permitted to run %s as %s",
               real_pw->pw_name, cmdpath, target_user);
        closelog();
        die_perm();
    }

    int already_valid = r->persist && persist_valid(real_uid, target_user);

    if (!r->nopass && !already_valid) {
        if (authenticate(real_pw->pw_name) != 0) {
            syslog(LOG_WARNING, "failed authentication for %s as %s",
                   real_pw->pw_name, target_user);
            closelog();
            die_perm();
        }
        if (r->persist) persist_update(real_uid, target_user);
    }

    char argsbuf[2048];
    log_args(argsbuf, sizeof(argsbuf), rest_args, rest_argc);
    syslog(LOG_NOTICE, "%s ran %s%s%s as %s",
           real_pw->pw_name, cmdpath, rest_argc ? " " : "", argsbuf, target_user);
    closelog();

    setup_env(target_pw, r->keepenv);

    if (initgroups(target_pw->pw_name, target_pw->pw_gid) != 0) die("initgroups failed");
    if (setgid(target_pw->pw_gid) != 0) die("setgid failed");
    if (setuid(target_pw->pw_uid) != 0) die("setuid failed");

    execv(cmdpath, &argv[argi]);
    die("execv failed");
    return 1;
}
