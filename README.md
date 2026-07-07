# xpsu (express su)

A minimalist reimplementation of OpenBSD's `doas` for Linux, no PAM.
Authentication is done directly against `/etc/shadow` via `crypt()`.
Every successful/failed run and permission denial is logged to
`syslog` (facility `auth`, same as `doas`/`sudo`).

## Build 

```sh
make
```

## Install (must be run as root)

```sh
su
make install
```

This installs the binary with the setuid-root bit at
`/usr/local/bin/xpsu` (mode `4755`), and copies a sample
`/etc/xpsu.conf` if one doesn't already exist.

**Important:** `xpsu.conf` must be owned by `root` and must not be
writable by other users, or anyone could self-authorize. `make
install` already sets `root:root 0640`.

## /etc/xpsu.conf syntax

```
permit [nopass] [persist] [keepenv] identity [as target] [cmd path [args ...]]
deny   identity [as target]
```

- `identity`: a user name, or `:groupname` to match a whole group
- `target`: the user the command runs as (default `root`)
- `nopass`: skip the password prompt
- `persist`: cache a successful authentication for a few minutes
  (default 300s, see `PERSIST_TIMEOUT` in `xpsu.c`) so repeated
  calls in that window don't re-prompt for a password. The cache
  lives in `/run/xpsu/<uid>_<target>`, root-owned, mode `0600`.
- `keepenv`: keep the caller's environment instead of resetting it
  (by default the environment is cleared, keeping only `PATH`,
  `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM` and `DISPLAY`)
- `cmd`: restrict the rule to a specific command (absolute path or
  name resolved through `PATH`); if `args` are given, all arguments
  must match exactly

The **last matching rule** wins (same precedence as the original
`doas`).

## Usage

```sh
xpsu command [args...]
xpsu -u user command [args...]
```

## Logging

All decisions go to syslog under `LOG_AUTHPRIV`:

- successful run: `xpsu: <user> ran <cmd> <args> as <target>`
- failed auth: `xpsu: failed authentication for <user> as <target>`
- denied by policy: `xpsu: <user> not permitted to run <cmd> as <target>`

Check `/var/log/auth.log` (or your distro's equivalent) to review
these.

## Limitations of this version

- `cmd` matching is exact, no glob/wildcards
- No "safe path" checking as thorough as upstream `doas`
- `persist` is keyed by uid+target only, not tied to a specific tty
  session like sudo's timestamp files are

### Made by LuuunoXD for FreeRoot Busybox/Linux (but runs on most linux distros).
