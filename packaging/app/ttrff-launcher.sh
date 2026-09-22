#!/bin/bash
# ttrff.app/Contents/MacOS/ttrff -- the .app's executable.
#
# A thin exec of the Homebrew-installed launcher: the formula writes this file into the
# .app bundle with the Cellar paths baked in (see the formula's `app` stanza). The tray
# itself is a menu-bar app (LSBackgroundOnly -- no Dock icon, no window); launching the
# .app from Spotlight just starts it, and the tray's single-instance guard makes a
# second launch a no-op.
exec "#{TTRFF_BIN}" "$@"
