# pq-audit-gui — GTK3 front-end for the pq-audit CLI
CC      ?= cc
CSTD    ?= -std=c11
WARN     = -Wall -Wextra
OPT     ?= -O2
PKG      = gtk+-3.0
CFLAGS  += $(CSTD) $(WARN) $(OPT) $(shell pkg-config --cflags $(PKG))
LDLIBS  += $(shell pkg-config --libs $(PKG))
BIN      = pq-audit-gui

# install layout (override with PREFIX=…, DESTDIR=… for packaging)
PREFIX  ?= /usr/local
DESTDIR ?=
APPID    = dev.pqaudit.gui
BINDIR     = $(DESTDIR)$(PREFIX)/bin
ICONBASE   = $(DESTDIR)$(PREFIX)/share/icons/hicolor
ICONDIR    = $(ICONBASE)/scalable/apps
DESKTOPDIR = $(DESTDIR)$(PREFIX)/share/applications

all: $(BIN)

$(BIN): pq-audit-gui.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: $(BIN)
	install -Dm755 $(BIN) $(BINDIR)/$(BIN)
	install -Dm644 $(APPID).svg $(ICONDIR)/$(APPID).svg
	install -Dm644 $(APPID).desktop $(DESKTOPDIR)/$(APPID).desktop
	-gtk-update-icon-cache -f -t $(ICONBASE) 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "installed $(BIN) to $(BINDIR)"

uninstall:
	rm -f $(BINDIR)/$(BIN)
	rm -f $(ICONDIR)/$(APPID).svg
	rm -f $(DESKTOPDIR)/$(APPID).desktop
	-gtk-update-icon-cache -f -t $(ICONBASE) 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "uninstalled $(BIN)"

clean:
	rm -f $(BIN)

.PHONY: all install uninstall clean
