CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
LDLIBS  = -lcrypt
PREFIX  = /usr/local

all: xpsu

xpsu: xpsu.c
	$(CC) $(CFLAGS) -o xpsu xpsu.c $(LDLIBS)

install: xpsu
	install -o root -g root -m 4755 xpsu $(PREFIX)/bin/xpsu
	@if [ ! -f /etc/xpsu.conf ]; then \
		install -o root -g root -m 0640 xpsu.conf /etc/xpsu.conf; \
		echo "installed /etc/xpsu.conf (edit as needed)"; \
	else \
		echo "/etc/xpsu.conf already exists, not overwriting"; \
	fi

clean:
	rm -f xpsu

.PHONY: all install clean
