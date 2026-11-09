# xpsu (express su)

A minimalist reimplementation of OpenBSD's `doas` for Linux, no PAM.
Authentication is done directly against `/etc/shadow` via `crypt()`.
Every successful run, failed authentication, lockout and permission
denial is logged to `syslog` (facility `authpriv`, same as `doas`/`sudo`).

## Build

```sh
make
```

or, by hand, with hardening flags:

```sh
gcc -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -fPIE -pie -Wl,-z,relro,-z,now -o xpsu xpsu.c -lcrypt
```

## Install (must be run as root)

Validate the config **before** installing it (see `-C` below), then:

```sh
su
make install
```

This installs the binary with the setuid-root bit at
`/usr/local/bin/xpsu` (mode `4755`), and copies a sample
`/etc/xpsu.conf` if one doesn't already exist.

**Important:** `xpsu.conf` must be a regular file, owned by `root`, and
not writable by group or others, or xpsu refuses to run (and logs an
alert). `make install` already sets `root:root 0640`.

## Usage

```sh
xpsu [-n] [-u user] command [args...]
xpsu -L
xpsu -C file
```

| Option    | Meaning                                                                    |
|-----------|----------------------------------------------------------------------------|
| `-u user` | run the command as `user` (default `root`)                                 |
| `-n`      | non-interactive: fail instead of asking for a password                     |
| `-L`      | forget your cached (`persist`) authentication                              |
| `-C file` | check the syntax of a config file and exit (no command is run)             |

### Checking a config file

```sh
xpsu -C ./xpsu.conf && install -o root -g root -m 0640 xpsu.conf /etc/xpsu.conf
```

`-C` runs with **your own** privileges (root is dropped), so it can't be
used to read files you couldn't read anyway. To check the installed
file, run it as root: `su -c 'xpsu -C /etc/xpsu.conf'`.

It prints every error with `file:line` and exits with status 1 if there
is any. It also prints warnings (which don't fail the check) for unknown
users/groups/targets, non-executable `cmd` paths, and for ownership or
permission problems that would make xpsu refuse the file once installed.

## /etc/xpsu.conf syntax

```
permit [nopass] [persist] [keepenv] identity [as target] [cmd path [args [arg ...]]]
deny   identity [as target] [cmd path [args [arg ...]]]
```

- `identity`: a user name, or `:groupname` to match a whole group
- `target`: the user the command runs as (default `root`)
- `nopass`: skip the password prompt
- `persist`: cache a successful authentication for a few minutes
  (default 300s, see `PERSIST_TIMEOUT` in `xpsu.c`); see
  [Persist](#persist) below
- `keepenv`: keep the caller's environment instead of resetting it
  (by default the environment is cleared, keeping only `PATH`,
  `HOME`, `USER`, `LOGNAME`, `SHELL`, a validated `TERM` and `DISPLAY`)
- `cmd`: restrict the rule to a specific command, given as an
  **absolute path**
  - no `args`: any arguments are allowed
  - `args a b c`: the arguments must match exactly
  - `args` alone: the command must be run with **no** arguments
- `#` starts a comment, either on its own line or at the end of a line

The **last matching rule** wins (same precedence as the original
`doas`).

Examples:

```
permit nopass lunoo as root
permit persist :wheel
permit lunoo as root cmd /usr/bin/xpkg
permit lunoo as root cmd /bin/ls args -l /tmp   # only "ls -l /tmp"
permit lunoo as root cmd /sbin/reboot args      # only "reboot", no arguments
deny bob
```

The config is parsed strictly: **any error makes xpsu refuse to run**
(nobody is let in, nothing is partially trusted). Unknown keywords,
missing identities, relative `cmd` paths, trailing garbage and
over-long lines are all errors. Run `xpsu -C` before installing.

## Persist

A `persist` authentication is cached in `/run/xpsu/ts_*`, root-owned,
mode `0600`. The cache is bound to:

- your uid and the target uid
- your session id and controlling tty
- the start time of the session leader (so a recycled session id
  doesn't inherit someone else's timestamp)

Time is measured with `CLOCK_BOOTTIME`, so changing the system clock
does not extend or revive a timestamp. Without a controlling tty,
`persist` is disabled and the password is always asked. The window is
absolute: using the cache does not renew it. `xpsu -L` clears it.

## Brute-force protection

- 3 password attempts per run, with a 2 second delay after each failure
- 5 failures within 10 minutes lock the user out for 5 minutes, across
  runs and across terminals; state is kept per uid in `/run/xpsu/fail_<uid>`
  and guarded by `flock`, so parallel attempts can't bypass it
- the password prompt times out after 60 seconds
- accounts with no usable password (`!`, `*`, empty) or an expired
  account are refused

All of these are constants at the top of `xpsu.c`. Since `/run` is a
tmpfs, lockouts and cached authentications are cleared on reboot.

## Hardening

- the config is opened with `O_NOFOLLOW` and checked via `fstat` on the
  open file descriptor
- the password is read from `/dev/tty`, terminal echo is restored on
  Ctrl+C / SIGTERM, and the buffer is wiped after use
- password hashes are compared in constant time
- inherited file descriptors are closed, core dumps are disabled while
  xpsu runs (the original limit is restored before the command runs)
- privileges are dropped with `setresuid`/`setresgid`, and xpsu checks
  that root can't be regained
- `LD_*`, `IFS`, `BASH_ENV`, `ENV`, `SHELLOPTS` and similar variables are
  removed even with `keepenv`
- `XPSU_USER` is set to the name of the invoking user
- relative entries in the caller's `PATH` are ignored when looking up
  the command
- control characters in logged arguments are replaced, so they can't
  forge extra syslog lines

## Logging

All decisions go to syslog under `LOG_AUTHPRIV`:

- successful run: `xpsu: <user> ran <cmd> <args> as <target>`
  (with a trailing `(persist)` if the cached authentication was used)
- failed auth: `xpsu: failed authentication for <user> as <target> (3 tries)`
- lockout: `xpsu: <user> locked out for <n> seconds after <n> failed attempts`
- denied by policy: `xpsu: <user> not permitted to run <cmd> as <target>`
- insecure or invalid config: `xpsu: refusing insecure config file ...` /
  `xpsu: <n> error(s) in /etc/xpsu.conf, refusing to run`

Check `/var/log/auth.log` (or your distro's equivalent) to review
these.

## Changes from the previous version

- **Bug fix:** the caller's identity was overwritten by the target
  user's data (`getpwuid`/`getpwnam` share one static buffer), which
  broke rule matching and made xpsu ask for the *target's* password.
- **Stricter config:** relative `cmd` paths (which never matched
  anything), trailing garbage and any syntax error are now rejected
  instead of silently ignored.
- New options `-C`, `-L`, `-n`, and the `args`-alone form of `cmd`.

## Limitations

- Linux only (uses `/proc`, `CLOCK_BOOTTIME` and `/run`)
- `cmd` matching is exact, no glob/wildcards
- no "safe path" checking as thorough as upstream `doas`; the command is
  found through the caller's `PATH` (absolute entries only)
- with `keepenv`, the caller's `PATH` and the rest of the environment
  are kept (except the variables listed under Hardening)
- while a user is at the password prompt, a second `xpsu` by the same
  user waits for the first one to finish (up to the 60 s prompt timeout)

### Made by LuuunoXD for FreeRoot Busybox/Linux (but runs on most linux distros).
