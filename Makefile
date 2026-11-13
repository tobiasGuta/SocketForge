PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
PYTHON ?= /usr/bin/python3

APP_ID := io.github.tobiasGuta.SocketForge
APPDIR := $(DATADIR)/socketforge
ASSETS := socketforge/assets
DESKTOP := $(DATADIR)/applications/$(APP_ID).desktop
ICON := $(DATADIR)/icons/hicolor/256x256/apps/$(APP_ID).png

.PHONY: run install uninstall

run:
	$(PYTHON) -m socketforge

install:
	install -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(APPDIR)/socketforge/assets"
	install -m 644 socketforge/*.py "$(DESTDIR)$(APPDIR)/socketforge/"
	install -m 644 $(ASSETS)/* "$(DESTDIR)$(APPDIR)/socketforge/assets/"
	install -Dm644 "data/$(APP_ID).desktop" "$(DESTDIR)$(DESKTOP)"
	install -Dm644 "$(ASSETS)/$(APP_ID).png" "$(DESTDIR)$(ICON)"
	$(PYTHON) -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(f"#!{sys.executable}\nimport runpy\nimport sys\nsys.path.insert(0, {sys.argv[2]!r})\nrunpy.run_module(\"socketforge\", run_name=\"__main__\")\n")' "$(DESTDIR)$(BINDIR)/socketforge" "$(APPDIR)"
	chmod 755 "$(DESTDIR)$(BINDIR)/socketforge"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/socketforge" "$(DESTDIR)$(DESKTOP)" "$(DESTDIR)$(ICON)"
	rm -rf "$(DESTDIR)$(APPDIR)/socketforge"
	rmdir "$(DESTDIR)$(APPDIR)"
