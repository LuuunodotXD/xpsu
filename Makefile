CC         = gcc
CFLAGS     = -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS    = -pie -Wl,-z,relro,-z,now
LDLIBS     = -lcrypt
PREFIX     = /usr/local
SYSCONFDIR = /etc
# DESTDIR is for packaging only: xpsu itself always reads /etc/xpsu.conf
DESTDIR    =

CONF       = $(DESTDIR)$(SYSCONFDIR)/xpsu.conf

all: xpsu

xpsu: xpsu.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o xpsu xpsu.c $(LDLIBS)

# validate the sample config in this directory (no root needed)
check: xpsu
	./xpsu -C xpsu.conf

install: xpsu
	@echo "checking sample xpsu.conf..."
	./xpsu -C xpsu.conf
	install -d $(DESTDIR)$(PREFIX)/bin
	install -o root -g root -m 4755 xpsu $(DESTDIR)$(PREFIX)/bin/xpsu
	@if [ ! -f $(CONF) ]; then \
		install -d $(DESTDIR)$(SYSCONFDIR); \
		install -o root -g root -m 0640 xpsu.conf $(CONF); \
		echo "installed $(CONF) (edit as needed)"; \
	else \
		echo "$(CONF) already exists, not overwriting"; \
		echo "checking the existing config against this version..."; \
		./xpsu -C $(CONF) || echo "WARNING: $(CONF) has errors: this xpsu will refuse to run until they are fixed"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/xpsu
	@echo "left $(CONF) and /run/xpsu in place"

clean:
	rm -f xpsu

.PHONY: all check install uninstall clean
