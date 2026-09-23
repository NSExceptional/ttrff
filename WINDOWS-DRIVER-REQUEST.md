# Request: a Windows window-driver (`winctl` equivalent) for the TTR client

**Status:** request / spec. Not yet implemented. Written for the agent picking this up.

## Why

`scripts/tt-*` can drive the **macOS** client end-to-end: `tt-to-playground` takes the client from `dead` (nothing running) through the launcher, title screen, and toon picker, into the playground, with no human at the keyboard. That rests on `winctl`, a macOS-only CLI (list windows / screenshot / click / key / accessibility-describe).

Windows has no equivalent, so every live run here needs a human to launch the game, log in, and park the toon somewhere useful. That is exactly the constraint STATUS.md's **capture handshake** exists to work around ("for any timed capture where the agent can't observe target state ... wait for an explicit go"). A Windows driver removes that constraint and unblocks unattended RE/instrumentation runs — which is the current bottleneck on deriving the Windows per-build table.

**Scope: out-of-process only.** Window management, screen capture, synthetic input, OCR. This tool must never attach to, inject into, or read the memory of `TTREngine64.exe` — that is the injector's job and it is a separate, riskier track. Keep them completely separate.

## Prior art: the macOS contract to mirror

Read `scripts/tt-lib`, `scripts/tt-state`, and `scripts/tt-to-playground` first. The layering is the part worth copying:

| layer | file | job |
|---|---|---|
| primitives | `winctl` (external, macOS-only) | list / shot / click / key / describe |
| helpers | `tt-lib` | window resolution, capture, pixel probes, OCR, input, launcher GO-press |
| classifier | `tt-state` | current screen → exactly one token |
| driver | `tt-to-playground` | state machine: re-read state each tick, resume from the right step |

The `winctl` verbs `tt-lib` actually depends on:

```
winctl list --all --json                       -> [{windowId, title, w, h, ...}]
winctl shot "win:<id>" out.png --json          -> {nonblack: 0..1}
winctl click "win:<id>" <x> <y>                 (window-local pixels)
winctl click "win:<id>" --id <axid> --press     (accessibility element)
winctl describe "win:<id>" --actionable --json -> [{role, label, id}]
winctl key "win:<id>" <keyname>                 (e.g. return, up)
```

The state tokens, which the Windows classifier should reproduce exactly so the two platforms stay conceptually parallel:

```
launcher | title | connecting | toonselect | playground | sleep | disconnected | dead
```

Design properties worth preserving, because they were earned the hard way:
- **Everything addressed by window-local *fraction*, never absolute pixels** — resolution/DPI independent (`tt_px`, `tt_click_frac` take 0..1).
- **`tt-state` never exits empty.** On any unexpected internal error it falls back to a safe token and lets the caller keep polling.
- **The driver re-reads state every tick** and resumes from whatever screen it finds, rather than running a fixed script. Cold loads are slow and screens flap.
- **Transient-state guard**: `playground` is confirmed by re-reading ~1.3 s later, because a fading toon-select can momentarily look like the HUD.

## Verified Windows facts

Measured on this box (Windows 10 Pro N 19045, `TTREngine64.exe` 3.2.0.609, game running). **Do not re-derive these; do re-check anything marked assumption.**

Window topology under the engine PID — note most of it is junk that must be filtered out:

```
hwnd     title                   class                  rect               client  flags
240b62   Toontown Rewritten      WinGraphicsWindow0     159x27@-25600,-25600  0x0   VIS MIN POPUP   <-- the render window
c0d0c    __wglDummyWindowFodder  NVOpenGLPbuffer        384x238@26,26       369x200 hidden          <-- NVIDIA junk
250bd6   NVOGLDC invisible       NVOpenGLPbuffer        384x238@77,77       369x200 hidden          <-- NVIDIA junk
70c10    Default IME             IME                    0x0@0,0             0x0     hidden          <-- IME junk
3d0ea4   MSCTFIME UI             MSCTFIME UI            0x0@0,0             0x0     hidden          <-- IME junk
```

Launcher (separate process, `Launcher.exe`; **two** PIDs were live simultaneously — handle that):

```
6e0b16   Toontown Rewritten Lau  Qt5152QWindowIcon      720x544@1016,284    720x544 hidden
180b6c   Launcher                Qt5152QWindowPopupDr   171x66@1428,565     171x65  hidden POPUP
```

Consequences you must design around:

1. **The render window is `class == "WinGraphicsWindow0"` and `title == "Toontown Rewritten"`.** Key off the class, not the title alone — Panda3D's class name is the stable discriminator, and the launcher's title starts with the same words.
2. **It was MINIMIZED** — `IsIconic` true, rect `159x27 @ -25600,-25600`, **client rect `0x0`**. Any driver that trusts `GetWindowRect` or `GetClientRect` without restoring first will compute garbage coordinates and click nothing. Restore (`ShowWindow SW_RESTORE`) and verify a sane client rect before capture or input. The macOS `tt_game_win` filters `w>=400 and h>=300` for the same class of reason.
3. **The launcher is Qt5** (`Qt5152QWindowIcon`). Qt5 exposes a UI Automation tree, so the launcher's GO button is likely reachable via UIA — the Windows analogue of the macOS `--id _NS:222 --press` path, with a geometry-fraction fallback exactly as `tt_press_go` does.
4. **The renderer is OpenGL** (confirmed in the client log: `...|win|AMD64...|OpenGL|...`). This is the single biggest technical risk — see below.
5. The client runs ~9.2 fps steadily in this environment. Time out generously; do not treat slowness as a hang.
6. The client **logs itself out after roughly half an hour** of inactivity (observed: launched 13:25, orderly `closing shard` → `clientLogout` at ~13:59). The driver should expect to re-navigate, and long unattended sessions need either periodic activity or tolerance of a re-login.

## The hard parts (address these explicitly)

### Capture on an OpenGL window

`PrintWindow` / `BitBlt` from the window DC commonly return **black** for OpenGL and D3D windows. Since `tt-state` is built on screenshots, getting this wrong makes everything downstream useless.

Recommended order:
1. **Screen-region grab of the window rect** after restoring and foregrounding the window (`PIL.ImageGrab.grab(bbox=...)`, or `mss`). Simple, no exotic dependencies, and the window has to be foreground for `SendInput` anyway — so one constraint covers both. Downside: requires the window visible and unoccluded, so the automation owns the desktop while it runs.
2. **Windows Graphics Capture API** (Win10 1803+) if occlusion-independence turns out to matter. Correct for GPU-composited windows but a much heavier dependency.
3. `PrintWindow` with `PW_RENDERFULLCONTENT` — *try it first as a cheap probe*, since if it happens to work everything gets easier. Verify it returns a non-black image with real game content; do not assume.

Whichever you pick, keep `tt_shot`'s `nonblack` fraction in the output — `tt-state` uses it as a free cheap signal.

### Synthetic input

Two options, genuinely different trade-offs:

- **`SendInput`** — real driver-level input. Most likely to work with Panda3D (which may use raw input and/or `GetAsyncKeyState`, both of which ignore posted messages). **Requires the target window to be foreground** and moves the physical cursor. This is the recommended default.
- **`PostMessage`/`SendMessage`** (`WM_LBUTTONDOWN`/`WM_KEYDOWN`/...) — works on a background window and doesn't hijack the cursor, but Panda3D may ignore it entirely.

Try `PostMessage` as an experiment because the ergonomics are much better; fall back to `SendInput` the moment a DirectGUI button doesn't respond. Record which one actually worked in `STATUS.md`.

Two traps:
- **DPI awareness.** Mark the process per-monitor-DPI-aware (`SetProcessDpiAwarenessContext`) or every coordinate is silently scaled wrong on a non-100% display.
- **UIPI.** If `TTREngine64.exe` runs elevated and the driver doesn't, Windows silently discards synthetic input to it. Check integrity levels; if they differ, say so rather than producing a tool that mysteriously does nothing.

### Recommended shape

**One Python CLI, ctypes against `user32`/`gdi32`** — not a compiled binary. Python is already a hard dependency (tray + injector), ctypes needs no build step or code signing, and it keeps the install story as-is.

Do **not** port `tt-lib`/`tt-state`/`tt-to-playground` to Git-Bash shell scripts. They lean on `jq`, `awk`, ImageMagick and `pgrep`, none of which ship on Windows. Put the equivalent logic in Python (Pillow replaces ImageMagick for pixel probes and cropping), leaving `tesseract` as the only external tool — installable via `scoop install tesseract`. Keep the macOS scripts untouched; Windows gets a sibling implementation with the same tokens and the same verbs.

Suggested layout, matching the existing convention that `scripts/` holds window-driver helpers:

```
scripts/ttwin.py          primitives: list / shot / click / key / describe / restore   (+ a --json mode)
scripts/tt_state_win.py   screen -> one token (same eight tokens as tt-state)
scripts/tt_to_pg_win.py   state machine -> playground
scripts/tt-to-playground.cmd   thin launcher, mirroring tt-mod-stop.cmd
```

## Deliverables

1. The CLI above, with `--json` output shaped like `winctl`'s where practical, so the two platforms read alike.
2. A state classifier producing exactly the eight tokens, never exiting empty.
3. A driver that takes the client from `dead` → `playground` unattended, and is **resumable from any intermediate screen**.
4. A `--selftest` that verifies window discovery, capture (non-black), and OCR availability **without launching or clicking anything** — mirroring `tray/ttrff_tray.py --selftest`.
5. `STATUS.md` updated per repo convention with what was found: which capture path worked, which input path worked, the calibration fractions, and any per-build window facts.

## Acceptance criteria

- From a cold box (no game running), one command ends with the toon standing in a playground.
- The classifier returns the correct token from each of: launcher, title, connecting, toon picker, playground, a disconnect modal, and a sleeping toon.
- Re-running the driver while already in the playground is a no-op that exits 0.
- Nothing in the tool attaches to, injects into, or reads memory from the engine process.

## Constraints

- 4-space indent; match the file you're editing. Don't hand-wrap markdown.
- Keep it out-of-process. No frida, no `task_for_pid`-equivalent, no memory reads.
- Prefer stdlib + already-present deps (`pillow`, `psutil` are installed). Justify any new dependency.
- Calibration fractions belong in named constants at the top of the file, like `tt-to-playground`'s `TOON_SLOT_X` / `OK_X`, not scattered through the code.
- Credentials: the launcher may need a login. Do **not** hardcode or commit credentials; read them from the environment or the existing saved-login state, and say in `STATUS.md` which you relied on.

## Open questions for the implementer

1. Does `PrintWindow(PW_RENDERFULLCONTENT)` return real content for `WinGraphicsWindow0`, or black? Decides the whole capture strategy — **test this first**, it is the cheapest high-information probe.
2. Does Panda3D honour `PostMessage` clicks on DirectGUI buttons, or is `SendInput` required?
3. Does the Qt5 launcher expose its GO button through UIA, or is a geometry-fraction click needed?
4. Why two `Launcher.exe` PIDs? Which one owns the real window, and is the second one a watchdog that will relaunch things underneath you?
5. Does the client remember the login, or is credential entry needed on every cold start?
6. Is there a windowed mode / fixed resolution that makes calibration fractions stable? If the client can go true-fullscreen-exclusive, capture and input both get harder — consider forcing windowed via `settings.json` in the install dir.
