# AGENTS.md

Working notes for coding agents in this repo. Read `README.md` (what/why + running) and `STATUS.md` (deep engine-RE details) for the full picture; this file is the practical orientation + hard-won gotchas.

## What this repo is

Cosmetic-only animation-speed mods for the owner's **own** Toontown Rewritten client, applied at runtime to the live, hardened official client via a native frida trampoline on Panda3D's `MetaInterval.start`. No movement/turn/aim/damage logic, no server-validated advantage. **Do not distribute; do not add anything beyond client-side visual timing.**

## Layout

| path | what |
|---|---|
| `modset.json` | the mod table: `{match, factor, group}` rows; first match wins (order specific → broad) |
| `frida/trampoline_inject.py` | the resident injector (modset mode) — the core |
| `frida/run-injector.sh` | signed wrapper for the scoped sudoers NOPASSWD rule; resolves repo root from its own location, so it works from dev checkout or Homebrew Cellar |
| `frida/ttr-frida-runner` | bundled, signed frida runner (macOS dep — `frida` is NOT pip-installed here) |
| `frida/inject.py`, `diag.py` | older/diagnostic inject paths (`TTRMOD_SCRIPT` overrides) |
| `tray/ttrff_tray.py` | menu-bar supervisor app; shells out to the injector, never touches internals |
| `localtest/` | offline tests against a local open-toontown client (`rig.py` is the shared harness) |
| `scripts/tt-*` | window-driver helpers (winctl + OCR); `tt-lib` is sourced by the others |
| `capi-symbols*.json`, `offsets.json`, `opcode_map.json` | per-build RE data the injector loads at runtime |
| `STATUS.md` | the living technical doc — engine internals, per-build addresses, fragility notes |

## Running / testing

- Validate the mod table offline, no game needed: `python3 localtest/modset_test.py`
- Live run: `sudo -n env TTRMOD_MODE=modset TTRMOD_SCRIPT=frida/trampoline_inject.py frida/run-injector.sh`
- Tray app: `python tray/ttrff_tray.py --selftest` (wiring check, launches nothing), then run it for real
- Discover new interval names: add `TTRMOD_LOGNAMES=1` → `[IVALNAME]` lines, plus `[SCALED]` on each match

## Hard rules & gotchas

- **NEVER stop the injector with Ctrl+C or SIGINT** — the runner dies too hard for the clean revert to run and the game crashes on the next animation. Use `scripts/tt-mod-stop` (drop-file → revert → wait) or `kill -TERM`. The tray app already does this correctly.
- **lldb is dead on TTREngine** — `debugserver` reliably SIGSEGVs on attach (TTR-specific). Don't retry it; use frida/`task_for_pid`/`vmmap` instead.
- **Attaching needs root on macOS** (`task_for_pid`), via the signed `run-injector.sh` + passwordless sudo. AMFI-off does not help.
- **Every hardcoded address is per-build.** The engine auto-patches; re-derive offsets/UUIDs on each new build (see STATUS.md "Fragility"). Engine is CPython 3.8.17, arm64, image base `0x100000000`.
- **Minimize crashes**: the client phones home to Sentry on crash and the minidump would name `frida-agent` while attached. The trampoline route deliberately uses only `setattr` + native calls (no marshal/exec/eval) to stay low-risk.
- **Battle round pacing is server-gated** — scaling the mid-battle attack movie was tried and deliberately disabled (feels worse). Don't re-enable it; the intro/outro scaling is the keeper.
- **The engine's game code is AES-encrypted** (`TTRGame.vlt`) and decrypted to a RAM filesystem at runtime — you can't read game Python statically; capture names live with `TTRMOD_LOGNAMES=1`.

## Tray app specifics

- `tray/eyes.png` is the menu-bar icon (Toontown eyeballs, extracted from the official logo SVG); `_make_image()` tints it by status color and falls back to a drawn glyph if the file is missing. Regenerate/replace it as a 64×64 RGBA with transparency.
- macOS dock icon is hidden via `NSApplicationActivationPolicyProhibited` (PyObjC, a pystray dependency) in `TrayApp.run()`.
- Pillow ≥ 10 removed `Image.ANTIALIAS`, which pystray 0.19.x calls — `_make_image()` restores the alias. Keep that shim.
- The tray launches the injector **detached** (own process group) so a tray crash can't kill it mid-hook; it only ever stops via the stop-file.
- Env overrides for retargeting (Windows agent, moved checkouts): `TTRFF_REPO`, `TTRMOD_MODSET`, `TTRFF_ENGINE_NAMES`, `TTRFF_INJECTOR_PYTHON`, `TTRFF_STOPFILE`, `TTRFF_LOG`. No code edits should be needed to retarget.

## Publishing / install (macOS, this machine)

- Distribution is Homebrew: `brew install --HEAD nscake/tap/ttrff` (HEAD-only formula; it pip-installs pinned prebuilt wheels into a private venv and copies `tray/`, `frida/`, `scripts/`, the RE data tables, and `modset.json` into `libexec`).
- "Publish" = commit + push to `origin/main` (`NSExceptional/ttrff`). "Install" = `brew uninstall ttrff && brew install --HEAD nscake/tap/ttrff`. Verify with `ttrff --selftest` and check the Cellar is at the new commit.
- The user's editable mod table lives at `~/Library/Application Support/ttrff/modset.json` (seeded from the read-only Cellar default on first run) — don't clobber it.
- New files the tray/injector need at runtime must be added to the formula's `libexec.install` list in the nscake tap, or they won't ship.

## Conventions

- 4-space indent; match the file you're editing.
- Keep the tray a thin supervisor — injection logic changes go in `frida/`, not `tray/`.
- `STATUS.md` is the living doc: update it (not just commit messages) when engine internals or per-build facts change.
- Sensitive-RE/instrumentation work against the live game goes in subagents, following the device-capture handshake (see memory notes referenced in STATUS.md).
- Don't manually wrap lines in markdown (or commit messages) — let text reflow.
