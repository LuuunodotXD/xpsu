/*
 * xpsu (express su) - minimalist doas-like privilege escalation tool for Linux
 * No PAM: authentication against /etc/shadow via crypt()
 *
 * Usage:
 *   xpsu [-n] [-u user] command [args...]
 *   xpsu -L                 forget cached (persist) authentication
 *   xpsu -C file            check the syntax of a config file and exit
 *
 * Config: /etc/xpsu.conf
 *   permit [nopass] [persist] [keepenv] identity [as target] [cmd path [args [arg ...]]]
 *   deny   identity [as target] [cmd path [args [arg ...]]]
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
 *       -fPIE -pie -Wl,-z,relro,-z,now -o xpsu xpsu.c -lcrypt
 * Install (as root):
 *   install -o root -g root -m 4755 xpsu /usr/local/bin/xpsu
 *   install -o root -g root -m 0640 xpsu.conf /etc/xpsu.conf
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <crypt.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>

#define CONF_PATH        "/etc/xpsu.conf"
#define STATE_DIR        "/run/xpsu"       /* tmpfs: cleared on reboot */
#define SAFE_PATH        "/usr/local/bin:/usr/bin:/bin"

#define MAX_LINE         1024
#define MAX_ARGS         64
#define MAX_RULES        1024
#define MAX_CONF_SIZE    (64 * 1024)

#define PERSIST_TIMEOUT  300   /* seconds a cached authentication stays valid */
#define TRIES_PER_RUN    3     /* password attempts per invocation            */
#define FAIL_DELAY       2     /* seconds to sleep after a wrong password     */
#define MAX_FAILS        5     /* failures inside FAIL_WINDOW -> lockout      */
#define FAIL_WINDOW      600   /* seconds                                     */
#define LOCKOUT_TIME     300   /* seconds                                     */
#define PROMPT_TIMEOUT   60    /* seconds to type the password                */

typedef struct rule {
    int allow;
    int nopass, persist, keepenv;
    char ident[64];
    char target[64];
    int has_cmd;
    char cmd[PATH_MAX];
    int has_args;                /* "args" given: argument list must match exactly */
    char *cmdargs[MAX_ARGS];
    int cmdargc;
    int line;
    struct rule *next;
} rule_t;

struct acct {
    char name[256];
    uid_t uid;
    gid_t gid;
    char dir[PATH_MAX];
    char shell[PATH_MAX];
};

static rule_t *rules_head = NULL;
static struct rlimit saved_core;

/* ---------- helpers ---------- */

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
    va_list ap;
    fputs("xpsu: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void die_perm(void) __attribute__((noreturn));
static void die_perm(void) {
    fprintf(stderr, "xpsu: not authorized\n");
    exit(1);
}

static char *dup_or_die(const char *s) {
    char *r = strdup(s);
    if (!r) die("out of memory");
    return r;
}

static void sanitize(char *s) {
    for (; *s; s++)
        if (!isprint((unsigned char)*s)) *s = '?';
}

static int ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char d = 0;
    for (size_t i = 0; i < la; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static int64_t now_boot(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec;
}

/* ---------- process hardening ---------- */

static void harden_process(void) {
    /* make sure 0,1,2 are open so later opens can't land on them */
    for (int fd = 0; fd < 3; fd++) {
        if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
            if (open("/dev/null", O_RDWR) < 0) _exit(1);
        }
    }
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++) close(fd);

    umask(022);
    prctl(PR_SET_DUMPABLE, 0);

    /* no core dumps while we may hold a password in memory;
     * the original limit is restored right before exec */
    getrlimit(RLIMIT_CORE, &saved_core);
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
}

/* ---------- account lookup (copies: getpw* uses ONE static buffer) ---------- */

static int acct_from_pw(struct acct *a, const struct passwd *pw) {
    if (!pw) return -1;
    if (snprintf(a->name, sizeof a->name, "%s", pw->pw_name) >= (int)sizeof a->name) return -1;
    if (snprintf(a->dir, sizeof a->dir, "%s", pw->pw_dir) >= (int)sizeof a->dir) return -1;
    if (snprintf(a->shell, sizeof a->shell, "%s", pw->pw_shell && *pw->pw_shell ? pw->pw_shell : "/bin/sh")
        >= (int)sizeof a->shell) return -1;
    a->uid = pw->pw_uid;
    a->gid = pw->pw_gid;
    return 0;
}

/* ---------- /etc/xpsu.conf parser ---------- */

static int conf_errors;

static void conf_err(const char *path, int line, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void conf_err(const char *path, int line, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "xpsu: %s:%d: ", path, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    conf_errors++;
}

static char *tok_next(char *s, char **save) {
    char *t = strtok_r(s, " \t\r\n", save);
    if (t && t[0] == '#') return NULL;   /* trailing comment */
    return t;
}

static void free_rule(rule_t *r) {
    if (!r) return;
    for (int i = 0; i < r->cmdargc; i++) free(r->cmdargs[i]);
    free(r);
}

static rule_t *parse_rule(char *line, const char *path, int lineno) {
    char *save = NULL;
    char *tok = tok_next(line, &save);
    if (!tok) return NULL;

    rule_t *r = calloc(1, sizeof *r);
    if (!r) die("out of memory");
    r->line = lineno;
    snprintf(r->target, sizeof r->target, "root");

    if (strcmp(tok, "permit") == 0) r->allow = 1;
    else if (strcmp(tok, "deny") == 0) r->allow = 0;
    else { conf_err(path, lineno, "unknown keyword '%s'", tok); goto bad; }

    tok = tok_next(NULL, &save);
    while (tok && (!strcmp(tok, "nopass") || !strcmp(tok, "persist") || !strcmp(tok, "keepenv"))) {
        if (!strcmp(tok, "nopass")) r->nopass = 1;
        else if (!strcmp(tok, "persist")) r->persist = 1;
        else r->keepenv = 1;
        tok = tok_next(NULL, &save);
    }

    if (!tok) { conf_err(path, lineno, "missing identity"); goto bad; }
    if (strlen(tok) >= sizeof r->ident) { conf_err(path, lineno, "identity too long"); goto bad; }
    if (tok[0] == ':' && tok[1] == '\0') { conf_err(path, lineno, "empty group name"); goto bad; }
    strcpy(r->ident, tok);

    tok = tok_next(NULL, &save);
    if (tok && !strcmp(tok, "as")) {
        tok = tok_next(NULL, &save);
        if (!tok) { conf_err(path, lineno, "'as' with no target"); goto bad; }
        if (strlen(tok) >= sizeof r->target) { conf_err(path, lineno, "target too long"); goto bad; }
        strcpy(r->target, tok);
        tok = tok_next(NULL, &save);
    }

    if (tok && !strcmp(tok, "cmd")) {
        tok = tok_next(NULL, &save);
        if (!tok) { conf_err(path, lineno, "'cmd' with no path"); goto bad; }
        if (tok[0] != '/') { conf_err(path, lineno, "cmd path must be absolute: '%s'", tok); goto bad; }
        if (strlen(tok) >= sizeof r->cmd) { conf_err(path, lineno, "cmd path too long"); goto bad; }
        r->has_cmd = 1;
        strcpy(r->cmd, tok);

        tok = tok_next(NULL, &save);
        if (tok && !strcmp(tok, "args")) {   /* "args" alone = no arguments allowed */
            r->has_args = 1;
            tok = tok_next(NULL, &save);
        }
        while (tok) {
            if (r->cmdargc >= MAX_ARGS - 1) { conf_err(path, lineno, "too many args"); goto bad; }
            r->cmdargs[r->cmdargc++] = dup_or_die(tok);
            r->has_args = 1;
            tok = tok_next(NULL, &save);
        }
    } else if (tok) {
        conf_err(path, lineno, "unexpected token '%s'", tok);
        goto bad;
    }
    return r;

bad:
    free_rule(r);
    return NULL;
}

/* check_only: file belongs to the caller, so ownership problems are warnings */
static void parse_config(const char *path, int check_only) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die("cannot open %s: %s", path, strerror(errno));

    struct stat st;
    if (fstat(fd, &st) != 0) die("cannot stat %s", path);
    if (!S_ISREG(st.st_mode)) die("%s is not a regular file", path);
    if (st.st_size > MAX_CONF_SIZE) die("%s is too large", path);

    int perm_bad = 0;
    if (st.st_uid != 0) { perm_bad = 1; fprintf(check_only ? stderr : stderr, "xpsu: %s must be owned by root\n", path); }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) { perm_bad = 1; fprintf(stderr, "xpsu: %s must not be writable by group/others\n", path); }
    if (perm_bad) {
        if (!check_only) {
            syslog(LOG_ALERT, "refusing insecure config file %s (uid=%u mode=%o)",
                   path, (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777));
            exit(1);
        }
        fprintf(stderr, "xpsu: (warning: xpsu would refuse this file when installed like this)\n");
    }

    FILE *f = fdopen(fd, "r");
    if (!f) die("fdopen failed");

    char line[MAX_LINE];
    int lineno = 0, nrules = 0;
    rule_t *tail = NULL;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') {
            conf_err(path, lineno, "line too long");
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) ;
            continue;
        }
        rule_t *r = parse_rule(line, path, lineno);
        if (!r) continue;
        if (++nrules > MAX_RULES) { conf_err(path, lineno, "too many rules"); free_rule(r); break; }

        if (check_only) {
            if (r->ident[0] == ':') {
                if (!getgrnam(r->ident + 1))
                    fprintf(stderr, "xpsu: %s:%d: warning: unknown group '%s'\n", path, lineno, r->ident + 1);
            } else if (!getpwnam(r->ident))
                fprintf(stderr, "xpsu: %s:%d: warning: unknown user '%s'\n", path, lineno, r->ident);
            if (!getpwnam(r->target))
                fprintf(stderr, "xpsu: %s:%d: warning: unknown target '%s'\n", path, lineno, r->target);
            if (r->has_cmd && access(r->cmd, X_OK) != 0)
                fprintf(stderr, "xpsu: %s:%d: warning: %s is not executable\n", path, lineno, r->cmd);
        }

        if (tail) tail->next = r; else rules_head = r;
        tail = r;
    }
    fclose(f);

    /* fail closed: a config with errors is never partially trusted */
    if (conf_errors && !check_only) {
        syslog(LOG_ALERT, "%d error(s) in %s, refusing to run", conf_errors, path);
        die("%d error(s) in %s, refusing to run", conf_errors, path);
    }
}

/* ---------- matching ---------- */

static int ident_matches(const char *ident, const struct acct *user) {
    if (ident[0] == ':') {
        struct group *g = getgrnam(ident + 1);
        if (!g) return 0;
        for (char **m = g->gr_mem; m && *m; m++)
            if (strcmp(*m, user->name) == 0) return 1;
        return g->gr_gid == user->gid;
    }
    return strcmp(ident, user->name) == 0;
}

/* resolve via PATH; ignores relative PATH entries (they depend on cwd) */
static int resolve_path(const char *cmd, char *out, size_t outlen) {
    struct stat st;
    char full[PATH_MAX];

    if (strchr(cmd, '/')) {
        if (cmd[0] != '/') {   /* ./foo, bin/foo: make absolute from cwd */
            char cwd[PATH_MAX];
            if (!getcwd(cwd, sizeof cwd)) return -1;
            if (snprintf(full, sizeof full, "%s/%s", cwd, cmd) >= (int)sizeof full) return -1;
        } else if (snprintf(full, sizeof full, "%s", cmd) >= (int)sizeof full) return -1;
        if (access(full, X_OK) != 0 || stat(full, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
        snprintf(out, outlen, "%s", full);
        return 0;
    }

    const char *path = getenv("PATH");
    if (!path || !*path) path = SAFE_PATH;
    char *pc = strdup(path);
    if (!pc) die("out of memory");
    char *save = NULL;
    int rc = -1;
    for (char *dir = strtok_r(pc, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        if (dir[0] != '/') continue;
        if (snprintf(full, sizeof full, "%s/%s", dir, cmd) >= (int)sizeof full) continue;
        if (access(full, X_OK) == 0 && stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            snprintf(out, outlen, "%s", full);
            rc = 0;
            break;
        }
    }
    free(pc);
    return rc;
}

/* last matching rule wins (doas-style) */
static rule_t *find_matching_rule(const struct acct *user, const char *target,
                                  const char *cmdpath, char **cmdargv, int cmdargc) {
    rule_t *best = NULL;
    for (rule_t *r = rules_head; r; r = r->next) {
        if (!ident_matches(r->ident, user)) continue;
        if (strcmp(r->target, target) != 0) continue;
        if (r->has_cmd) {
            if (strcmp(r->cmd, cmdpath) != 0) continue;
            if (r->has_args) {
                if (r->cmdargc != cmdargc) continue;
                int ok = 1;
                for (int i = 0; i < r->cmdargc; i++)
                    if (strcmp(r->cmdargs[i], cmdargv[i]) != 0) { ok = 0; break; }
                if (!ok) continue;
            }
        }
        best = r;
    }
    return best;
}

/* ---------- state directory (/run/xpsu) ---------- */

static int open_state_dir(void) {
    if (mkdir(STATE_DIR, 0700) != 0 && errno != EEXIST) return -1;
    int fd = open(STATE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0) { close(fd); return -1; }
    if ((st.st_mode & 07777) != 0700 && fchmod(fd, 0700) != 0) { close(fd); return -1; }
    return fd;
}

static int safe_state_file(const struct stat *st) {
    return S_ISREG(st->st_mode) && st->st_uid == 0 && (st->st_mode & 077) == 0 && st->st_nlink == 1;
}

static void scan_state(int dirfd, const char *prefix, int stale_only) {
    int d = dup(dirfd);
    if (d < 0) return;
    DIR *dir = fdopendir(d);
    if (!dir) { close(d); return; }
    rewinddir(dir);
    time_t now = time(NULL);
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) != 0) continue;
        if (stale_only) {
            struct stat st;
            if (fstatat(dirfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
            if (now >= st.st_mtime && now - st.st_mtime <= 4 * PERSIST_TIMEOUT) continue;
        }
        unlinkat(dirfd, e->d_name, 0);
    }
    closedir(dir);
}

/* ---------- persist: timestamps bound to uid + target + tty + session ---------- */

struct sess {
    int sid;
    int tty;                      /* controlling tty device number (0 = none) */
    unsigned long long start;     /* session leader start time (jiffies since boot) */
};

struct ts_rec {
    char magic[8];
    uint32_t uid, target_uid;
    int32_t sid, tty_nr;
    uint64_t sid_start;
    int64_t stamp;                /* CLOCK_BOOTTIME seconds */
};

static int proc_stat(pid_t pid, int *sid, int *tty, unsigned long long *start) {
    char path[64], buf[1024];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *p = strrchr(buf, ')');   /* comm may contain spaces/parens */
    if (!p) return -1;
    int s, t;
    unsigned long long st;
    if (sscanf(p + 1, " %*c %*d %*d %d %d %*d %*u %*u %*u %*u %*u %*u %*u "
                      "%*d %*d %*d %*d %*d %*d %llu", &s, &t, &st) != 3) return -1;
    if (sid) *sid = s;
    if (tty) *tty = t;
    if (start) *start = st;
    return 0;
}

static int get_session(struct sess *s) {
    int sid, tty;
    unsigned long long dummy;
    if (proc_stat(getpid(), &sid, &tty, &dummy) != 0 || tty == 0) return -1;
    unsigned long long start;
    if (proc_stat(sid, NULL, NULL, &start) != 0) return -1;
    s->sid = sid; s->tty = tty; s->start = start;
    return 0;
}

static void ts_name(char *buf, size_t len, uid_t uid, uid_t tuid, const struct sess *s) {
    snprintf(buf, len, "ts_%u_%u_%d_%d", (unsigned)uid, (unsigned)tuid, s->sid, s->tty);
}

static int persist_valid(int dirfd, uid_t uid, uid_t tuid, const struct sess *s) {
    char name[96];
    ts_name(name, sizeof name, uid, tuid, s);
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    struct ts_rec rec;
    int ok = 0;
    if (fstat(fd, &st) == 0 && safe_state_file(&st) &&
        read(fd, &rec, sizeof rec) == (ssize_t)sizeof rec) {
        int64_t now = now_boot();
        ok = now >= 0 &&
             memcmp(rec.magic, "XPSUTS01", 8) == 0 &&
             rec.uid == uid && rec.target_uid == tuid &&
             rec.sid == s->sid && rec.tty_nr == s->tty &&
             rec.sid_start == s->start &&
             rec.stamp <= now && now - rec.stamp <= PERSIST_TIMEOUT;
    }
    close(fd);
    return ok;
}

static void persist_update(int dirfd, uid_t uid, uid_t tuid, const struct sess *s) {
    char name[96];
    ts_name(name, sizeof name, uid, tuid, s);
    scan_state(dirfd, "ts_", 1);
    unlinkat(dirfd, name, 0);
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return;
    struct ts_rec rec;
    memset(&rec, 0, sizeof rec);
    memcpy(rec.magic, "XPSUTS01", 8);
    rec.uid = uid; rec.target_uid = tuid;
    rec.sid = s->sid; rec.tty_nr = s->tty; rec.sid_start = s->start;
    rec.stamp = now_boot();
    if (write(fd, &rec, sizeof rec) != (ssize_t)sizeof rec) unlinkat(dirfd, name, 0);
    close(fd);
}

/* ---------- brute-force limiter: persistent per-uid failure counter ---------- */

struct fail_rec {
    char magic[8];
    int64_t first;          /* start of the current failure window */
    int64_t locked_until;
    uint32_t count;
    uint32_t pad;
};

static int open_fail_file(int dirfd, uid_t uid, struct fail_rec *rec) {
    char name[64];
    snprintf(name, sizeof name, "fail_%u", (unsigned)uid);
    int fd = openat(dirfd, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !safe_state_file(&st) || flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    memset(rec, 0, sizeof *rec);
    if (pread(fd, rec, sizeof *rec, 0) != (ssize_t)sizeof *rec || memcmp(rec->magic, "XPSUFL01", 8) != 0) {
        memset(rec, 0, sizeof *rec);
        memcpy(rec->magic, "XPSUFL01", 8);
    }
    return fd;
}

static void save_fail(int fd, const struct fail_rec *rec) {
    if (pwrite(fd, rec, sizeof *rec, 0) != (ssize_t)sizeof *rec) { /* best effort */ }
}

/* ---------- password prompt (on /dev/tty, with signal + timeout handling) ---------- */

static volatile sig_atomic_t g_sig;
static void on_sig(int s) { g_sig = s; }

static void tty_puts(int tty, const char *s) {
    if (write(tty, s, strlen(s)) < 0) { /* ignore */ }
}

static int read_password(int tty, const char *prompt, char *buf, size_t len) {
    struct termios oldt, newt;
    if (tcgetattr(tty, &oldt) != 0) return -1;
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ECHONL);
    newt.c_lflag |= ICANON;

    static const int sigs[] = { SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGTSTP, SIGALRM };
    struct sigaction sa, old[sizeof sigs / sizeof sigs[0]];
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;          /* no SA_RESTART: read() must return EINTR */
    sigemptyset(&sa.sa_mask);
    g_sig = 0;
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &sa, &old[i]);

    int ok = -1;
    size_t n = 0;
    if (tcsetattr(tty, TCSAFLUSH, &newt) == 0) {
        tty_puts(tty, prompt);
        alarm(PROMPT_TIMEOUT);
        char c;
        while (!g_sig) {
            ssize_t r = read(tty, &c, 1);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            if (c == '\n') { ok = 0; break; }
            if (n < len - 1) buf[n++] = c;
        }
        alarm(0);
        tcsetattr(tty, TCSAFLUSH, &oldt);
        tty_puts(tty, "\n");
    }
    buf[n] = '\0';
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &old[i], NULL);
    if (g_sig) ok = -1;
    if (ok != 0) explicit_bzero(buf, len);
    return ok;
}

/* ---------- authentication ---------- */

enum { AUTH_OK = 0, AUTH_FAIL = -1, AUTH_LOCKED = -2, AUTH_ERR = -3 };

static int check_password(const char *hash, const char *password) {
    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd) die("out of memory");
    char *res = crypt_r(password, hash, cd);
    int ok = res && res[0] != '*' && ct_equal(res, hash);
    explicit_bzero(cd, sizeof *cd);
    free(cd);
    return ok;
}

static int authenticate(int dirfd, const struct acct *user, int noninteractive) {
    struct spwd *sp = getspnam(user->name);
    if (!sp || !sp->sp_pwdp) { fprintf(stderr, "xpsu: no shadow entry for %s\n", user->name); return AUTH_ERR; }

    char hash[256];
    if (snprintf(hash, sizeof hash, "%s", sp->sp_pwdp) >= (int)sizeof hash) return AUTH_ERR;
    if (hash[0] == '\0' || hash[0] == '!' || hash[0] == '*') {
        fprintf(stderr, "xpsu: account %s has no usable password\n", user->name);
        return AUTH_ERR;
    }
    if (sp->sp_expire >= 0 && (long)(time(NULL) / 86400) > sp->sp_expire) {
        fprintf(stderr, "xpsu: account %s has expired\n", user->name);
        return AUTH_ERR;
    }
    if (noninteractive) { fprintf(stderr, "xpsu: a password is required\n"); return AUTH_ERR; }

    int tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty < 0) { fprintf(stderr, "xpsu: no tty available to ask for a password\n"); return AUTH_ERR; }

    struct fail_rec rec;
    int ffd = open_fail_file(dirfd, user->uid, &rec);   /* held (flock) during the whole prompt */
    if (ffd < 0) { close(tty); fprintf(stderr, "xpsu: cannot access rate-limit state\n"); return AUTH_ERR; }

    int rc = AUTH_FAIL;
    int64_t now = now_boot();
    if (now < 0) { rc = AUTH_ERR; goto out; }

    if (rec.locked_until > now) {
        fprintf(stderr, "xpsu: too many failed attempts, try again in %lld seconds\n",
                (long long)(rec.locked_until - now));
        rc = AUTH_LOCKED;
        goto out;
    }
    if (rec.locked_until) { rec.locked_until = 0; rec.count = 0; }

    char prompt[320], password[256];
    snprintf(prompt, sizeof prompt, "[xpsu] password for %s: ", user->name);

    for (int attempt = 0; attempt < TRIES_PER_RUN; attempt++) {
        if (read_password(tty, prompt, password, sizeof password) != 0) { rc = AUTH_ERR; break; }
        int ok = check_password(hash, password);
        explicit_bzero(password, sizeof password);

        if (ok) {
            memset(&rec, 0, sizeof rec);
            memcpy(rec.magic, "XPSUFL01", 8);
            save_fail(ffd, &rec);
            rc = AUTH_OK;
            break;
        }

        now = now_boot();
        if (rec.count == 0 || now - rec.first > FAIL_WINDOW) { rec.count = 0; rec.first = now; }
        rec.count++;
        if (rec.count >= MAX_FAILS) {
            rec.locked_until = now + LOCKOUT_TIME;
            rec.count = 0;
            save_fail(ffd, &rec);
            syslog(LOG_ALERT, "%s locked out for %d seconds after %d failed attempts",
                   user->name, LOCKOUT_TIME, MAX_FAILS);
            fprintf(stderr, "xpsu: too many failed attempts, locked for %d seconds\n", LOCKOUT_TIME);
            rc = AUTH_LOCKED;
            break;
        }
        save_fail(ffd, &rec);
        sleep(FAIL_DELAY);
        if (attempt + 1 < TRIES_PER_RUN) tty_puts(tty, "Sorry, try again.\n");
    }
out:
    close(ffd);   /* releases the flock */
    close(tty);
    return rc;
}

/* ---------- environment ---------- */

static int safe_env_value(const char *v) {
    if (!v || !*v || strlen(v) >= 64) return 0;
    for (; *v; v++)
        if (!isalnum((unsigned char)*v) && !strchr("._:/+-@", *v)) return 0;
    return 1;
}

static void scrub_env(void) {
    static const char *bad[] = { "IFS", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS",
                                 "PS4", "GLOBIGNORE", "CDPATH", NULL };
    for (int i = 0; environ && environ[i]; ) {
        char name[128];
        const char *eq = strchr(environ[i], '=');
        size_t nl = eq ? (size_t)(eq - environ[i]) : strlen(environ[i]);
        int drop = 0;
        if (nl < sizeof name) {
            memcpy(name, environ[i], nl);
            name[nl] = '\0';
            if (strncmp(name, "LD_", 3) == 0) drop = 1;
            for (int j = 0; bad[j] && !drop; j++)
                if (strcmp(name, bad[j]) == 0) drop = 1;
            if (drop) { unsetenv(name); continue; }   /* environ shifted: don't advance */
        }
        i++;
    }
}

static void setup_env(const struct acct *target, const struct acct *caller, int keepenv) {
    if (!keepenv) {
        const char *t = getenv("TERM"), *d = getenv("DISPLAY");
        char termbuf[64] = {0}, dispbuf[64] = {0};
        if (safe_env_value(t)) snprintf(termbuf, sizeof termbuf, "%s", t);
        if (safe_env_value(d)) snprintf(dispbuf, sizeof dispbuf, "%s", d);
        clearenv();
        setenv("PATH", SAFE_PATH, 1);
        if (termbuf[0]) setenv("TERM", termbuf, 1);
        if (dispbuf[0]) setenv("DISPLAY", dispbuf, 1);
    } else {
        scrub_env();
    }
    setenv("HOME", target->dir, 1);
    setenv("USER", target->name, 1);
    setenv("LOGNAME", target->name, 1);
    setenv("SHELL", target->shell, 1);
    setenv("XPSU_USER", caller->name, 1);
}

/* ---------- main ---------- */

static void join_args(char *dst, size_t dstlen, char **argv, int argc) {
    dst[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < argc; i++) {
        int n = snprintf(dst + used, dstlen - used, "%s%s", i ? " " : "", argv[i]);
        if (n < 0 || (size_t)n >= dstlen - used) break;
        used += n;
    }
    sanitize(dst);
}

static void usage(void) {
    fprintf(stderr, "usage: xpsu [-n] [-u user] command [args...]\n"
                    "       xpsu -L\n"
                    "       xpsu -C file\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    harden_process();

    const char *target_user = "root";
    const char *check_file = NULL;
    int clear_ts = 0, noninteractive = 0, opt;

    while ((opt = getopt(argc, argv, "+u:LnC:h")) != -1) {
        switch (opt) {
        case 'u': target_user = optarg; break;
        case 'L': clear_ts = 1; break;
        case 'n': noninteractive = 1; break;
        case 'C': check_file = optarg; break;
        default:  usage();
        }
    }

    if (check_file) {            /* syntax check, runs with the caller's own privileges */
        if (geteuid() == 0 && getuid() != 0 && seteuid(getuid()) != 0) die("cannot drop privileges");
        parse_config(check_file, 1);
        if (conf_errors) return 1;
        printf("xpsu: %s: syntax ok\n", check_file);
        return 0;
    }

    if (geteuid() != 0) die("must be installed setuid root");

    openlog("xpsu", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);

    struct acct caller, target;
    if (acct_from_pw(&caller, getpwuid(getuid())) != 0) die("could not identify the current user");

    if (clear_ts) {
        int d = open_state_dir();
        if (d >= 0) {
            char prefix[32];
            snprintf(prefix, sizeof prefix, "ts_%u_", (unsigned)caller.uid);
            scan_state(d, prefix, 0);
            close(d);
        }
        return 0;
    }

    if (optind >= argc) usage();
    char **cmdv = &argv[optind];

    if (acct_from_pw(&target, getpwnam(target_user)) != 0) die("unknown target user");

    parse_config(CONF_PATH, 0);

    char cmdpath[PATH_MAX];
    if (resolve_path(cmdv[0], cmdpath, sizeof cmdpath) != 0) die("command not found");

    char **rest_args = &cmdv[1];
    int rest_argc = argc - optind - 1;

    char logpath[PATH_MAX];
    snprintf(logpath, sizeof logpath, "%s", cmdpath);
    sanitize(logpath);

    rule_t *r = find_matching_rule(&caller, target.name, cmdpath, rest_args, rest_argc);
    if (!r || !r->allow) {
        syslog(LOG_WARNING, "%s not permitted to run %s as %s", caller.name, logpath, target.name);
        die_perm();
    }

    int via_persist = 0;
    if (!r->nopass) {
        int dirfd = open_state_dir();
        if (dirfd < 0) die("cannot open state directory " STATE_DIR);

        struct sess sess;
        int have_sess = r->persist && get_session(&sess) == 0;   /* persist needs a tty */

        if (have_sess && persist_valid(dirfd, caller.uid, target.uid, &sess)) {
            via_persist = 1;
        } else {
            int rc = authenticate(dirfd, &caller, noninteractive);
            if (rc == AUTH_FAIL)
                syslog(LOG_WARNING, "failed authentication for %s as %s (%d tries)",
                       caller.name, target.name, TRIES_PER_RUN);
            else if (rc == AUTH_LOCKED)
                syslog(LOG_WARNING, "locked-out attempt by %s as %s", caller.name, target.name);
            if (rc != AUTH_OK) {
                if (rc == AUTH_FAIL) fprintf(stderr, "xpsu: authentication failed\n");
                return 1;
            }
            if (have_sess) persist_update(dirfd, caller.uid, target.uid, &sess);
        }
        close(dirfd);
    }

    char argsbuf[2048];
    join_args(argsbuf, sizeof argsbuf, rest_args, rest_argc);
    syslog(LOG_NOTICE, "%s ran %s%s%s as %s%s", caller.name, logpath,
           rest_argc ? " " : "", argsbuf, target.name, via_persist ? " (persist)" : "");
    closelog();

    setup_env(&target, &caller, r->keepenv);
    setrlimit(RLIMIT_CORE, &saved_core);

    if (initgroups(target.name, target.gid) != 0) die("initgroups failed");
    if (setresgid(target.gid, target.gid, target.gid) != 0) die("setresgid failed");
    if (setresuid(target.uid, target.uid, target.uid) != 0) die("setresuid failed");
    if (target.uid != 0 && setuid(0) == 0) die("privileges were not dropped properly");

    execv(cmdpath, cmdv);
    die("execv %s failed: %s", cmdpath, strerror(errno));
}
