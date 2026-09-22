# ttrff tray

A tiny **menu-bar (macOS) / system-tray (Windows)** app that runs the ttrff cosmetic mods for
you — no terminal, no commands. It watches for the Toontown Rewritten engine and, while
**Mods enabled** is on, auto-attaches the resident injector as soon as the game starts and
keeps it running while you play. On quit or disable it triggers the injector's **clean revert**
and waits for it, so the game is never left with a live hook.

Same menu and behavior on both platforms. It is a thin **supervisor** — it shells out to the
existing injector (`../frida/trampoline_inject.py`, modset mode) and never touches the injection
internals.

## The menu

```
ttrff — mods active          (status: waiting for game / attaching… / mods active / …)
─────────────
✓ Mods enabled               master switch: auto-attach when the game is up
─────────────
✓ Teleport                   per-group toggles — edit modset.json and re-apply live
✓ Shticker Book
✓ Screen iris
✓ Building doors
✓ Street tunnels
✓ Battle (intro/outro)
─────────────
  Re-apply config now        stop + re-attach to pick up modset.json changes
  Open modset.json…
  Open injector log…
─────────────
  Quit                       clean revert, then exit
```

Toggling a group edits [`../modset.json`](../modset.json) and, if the mods are currently
attached, re-applies automatically. (Battle's deliberately-disabled mid-fight `movie-track`
row is *pinned* — turning the Battle group off and back on never resurrects it.)

## Install & run

**Dependencies:** `pystray`, `pillow`, `psutil` (plus `frida` on Windows).

### macOS — Homebrew (recommended)

```sh
brew install --HEAD nscake/tap/ttrff
ttrff
```

Installs the menu-bar deps + the whole injector toolset and gives you a `ttrff` command.
Your editable mod table is seeded to `~/Library/Application Support/ttrff/modset.json` on first
run (menu toggles edit that copy). Update later with `brew uninstall ttrff && brew install --HEAD
nscake/tap/ttrff`.

### Windows — Scoop (recommended)

```powershell
scoop bucket add nscake https://github.com/NSCake/scoop-bucket
scoop install ttrff
ttrff
```

Then start it any time with `ttrff` (first run creates the venv, ~a minute; after that it's
instant). Installs from the **NSCake scoop-bucket** (the Windows analog of the `nscake`
Homebrew tap — one bucket for all NSCake packages). The manifest points at this repo's rolling
`windows-latest` release — rebuilt on every push to `main`, so it tracks HEAD like the
Homebrew `--HEAD` formula. The `ttrff` launcher creates a private venv
(pystray/pillow/psutil/frida) inside the app dir on first run; it needs `python` on PATH
(`scoop install python`). Your editable mod table is seeded to `%LOCALAPPDATA%\ttrff\modset.json`
on first run (menu toggles edit that copy); `scoop update ttrff` never clobbers it. Update =
`scoop update ttrff` (new artifact) — or `scoop uninstall ttrff` + reinstall for a fully clean
slate.

### Run from source (simplest)

```sh
pip install -r tray/requirements.txt
python tray/ttrff_tray.py
```

### Or install a `ttrff` command

```sh
pip install -e ./tray      # editable, so it still finds the repo's frida/ and modset.json
ttrff
```

Verify wiring without launching or changing anything:

```sh
python tray/ttrff_tray.py --selftest
```

### macOS

Attaching to the hardened engine needs root, so the tray launches the **signed**
`frida/run-injector.sh` via `sudo -n` (relies on the existing passwordless-sudo setup — the
same thing the manual `sudo … run-injector.sh` command uses). The tray app itself runs as your
normal user. `frida` is **not** a macOS dependency; the bundled `frida/ttr-frida-runner` carries
it.

### Windows

Attaching to a same-user process needs **no** elevation, so the tray runs the injector directly
under the Python that launched the tray (`sys.executable`) — that Python needs `frida`
(the `pip install` above pulls it in on Windows). The clean-stop path is the same stop-file
mechanism (`%TEMP%\ttrmod-stop`), now also drivable via `scripts\tt-mod-stop.cmd`.

The tray icon matches the macOS one: same tinted `eyes.png` source, rendered as a multi-size
ICO (16→128 px, LANCZOS) and loaded at the exact small-icon size for the tray, so it stays crisp
at 100–200% display scaling (the Windows counterpart of the macOS Retina patch).

> Windows support for the *injector* itself: the tray app and all host plumbing (stop-file,
> process detection, detached launch, revert logic) now run on Windows and are offline-tested
> (24/24 in `localtest/stoprevert_test.py`). **Attaching to the live engine is still macOS-only**
> until the per-build vault hashes and CPython-3.8 struct offsets are re-derived for the Windows
> engine binary (see `../STATUS.md`) — the injector refuses to attach on Windows with the
> bundled macOS-arm64 tables (override with `TTRMOD_WIN_TABLE=1` once a Windows table is derived).

## How it stays crash-safe

The injector is launched **detached** (its own process group / session), so a tray crash can
never kill it mid-hook — which is exactly what crashes the game. The tray only ever stops it by
dropping the **stop-file** (`/tmp/ttrmod-stop`, or `%TEMP%\ttrmod-stop` on Windows), which makes
the injector restore every wrapped method *before* it detaches. If the game is idle when you
quit (no frame running to execute the revert), the tray leaves the injector alone to finish on
its own rather than force-killing it — the safe state. This replaces the old "never Ctrl+C, use
`scripts/tt-mod-stop`" footgun with normal Quit.

## Retargeting (env overrides)

Everything is overridable so the Windows agent (or a moved checkout) needs no code edits:

| env var | default | purpose |
|---|---|---|
| `TTRFF_REPO` | parent of `tray/` | repo root holding `frida/` + `modset.json` |
| `TTRMOD_MODSET` | `<repo>/modset.json` | the mod table to load |
| `TTRFF_ENGINE_NAMES` | `TTREngine,Toontown Rewritten` | process name/exe/cmdline substrings to match |
| `TTRFF_INJECTOR_PYTHON` | `sys.executable` | (Win/Linux) Python that runs the injector — must have `frida` |
| `TTRFF_STOPFILE` | `/tmp/ttrmod-stop` (posix) | clean-stop file, shared with the injector |
| `TTRFF_LOG` | temp dir | injector stdout/stderr log (menu → "Open injector log…") |

Cosmetic-only, on the owner's own client and account — see the repo [`README.md`](../README.md).
Do not distribute.
