# ttr-mods

Personal, cosmetic quality-of-life tweaks for the owner's **own** Toontown
Rewritten client, on the owner's own machine and account. It attaches to the
running game and shortens a handful of **purely visual** battle animations by
scaling their Panda3D interval play-rates.

## What this is (and is not)

- **Is:** a runtime tool that speeds up cosmetic battle playback (cog-death
  explosion, dodge step-back, door open/close, combat run-in) so battles feel
  snappier.
- **Is not:** a competitive cheat. It touches **no** movement/turn/aim/damage
  logic and grants **no** server-validated advantage. Everything it changes is
  client-side animation timing. Combat run-in is included only because the first
  battle round is **client-driven** (the server starts the round when your
  client reports `d_joinDone`, capped only by fallback timers), so a faster
  run-in animation legitimately gets you to the input round sooner — see
  "Design note" below.

Client modification is **ToS-gray and at your own risk.** The owner has accepted
that. Do not distribute or use on accounts you do not own.

## How it works

TTREngine statically embeds CPython 3.7 (Panda3D 1.11) with its symbol table
**stripped**, and — because it's a frozen Panda3D *deploy-stub* build — the
entire `PyRun_*` family (`PyRun_SimpleString`, `PyRun_String`, …) is
**dead-stripped**; the app's frozen `__main__` runs via import + `PyEval_EvalCode`,
so those source-runner entry points were never linked. The surviving C-API
functions must be called by **address**. The tool therefore:

1. Reads the running binary's **arm64 Mach-O UUID** and looks up the CPython
   C-API vmaddrs for that exact build in `offsets.json` (derived once with the
   `re` skill; see "Re-deriving offsets").
2. Drives `lldb` (AMFI is disabled on this machine, so attaching to the
   hardened-runtime process is permitted) to run, on the live interpreter, the
   **`exec_builtins`** primitive — every step callable by address, no
   `PyRun_*` needed:
   ```
   gil  = PyGILState_Ensure();
   bmod = PyImport_ImportModule("builtins");
   main = PyImport_AddModule("__main__");
   gd   = PyModule_GetDict(main);
   PyObject_CallMethod(bmod, "exec", "sO", bootstrap, gd);  // execs payload in __main__
   PyGILState_Release(gil);
   ```
   (A `compile_eval` fallback — `Py_CompileStringExFlags` + `PyEval_EvalCode` —
   is also implemented, selectable via `offsets.json`.) Before calling, it
   verifies each function's prologue bytes and **aborts** if they don't match
   (guards against a silently auto-patched engine).
3. `inproc/payload.py` runs inside the game and monkeypatches the loaded modules.

`payload.py` prefers **wrapping the animation factory functions** and scaling
the returned interval with `.setPlayRate(factor)` — which is robust regardless
of the build's internal literals — and only edits module constants where the
constant itself is the knob. It is **idempotent** (re-running always re-wraps
from the stored true original, never stacks) and **reversible** (`--revert`
restores every original). An optional import hook re-applies patches when a
target module loads later, so you can attach at the login screen.

## Files

| path | role |
|------|------|
| `ttrmod` | bash entrypoint |
| `driver.py` | host side: find PID, look up offsets, drive lldb |
| `lldb/attach.py` | runs in lldb: attach, verify, call the C-API primitive |
| `inproc/payload.py` | runs inside TTREngine: the actual monkeypatches |
| `config.json` | which groups are on + their speed factors |
| `offsets.json` | per-build CPython C-API vmaddrs (keyed by UUID) |

## Run steps

1. Launch Toontown Rewritten normally and log in (the owner does this; the tool
   never logs in or drives gameplay). Reaching the login screen is enough to
   attach, but the battle modules only load in-district, so apply once you're in
   a playground/street for the patches to bind immediately (the import hook will
   otherwise bind them the moment those modules import).
2. Apply:
   ```
   cd ~/Developer/ttr-mods
   ./ttrmod
   ```
   You'll see which patches applied/were skipped. It's safe to re-run.
3. Revert (restores originals in the live process, no restart needed):
   ```
   ./ttrmod --revert
   ```
4. Inspect the last in-process result:
   ```
   ./ttrmod --status
   ```

Tune `config.json` (per-group `enabled` + `factor`) and re-run to change speeds
live. `factor` is a speed multiplier: `2.0` ≈ twice as fast.

**In-battle visual confirmation must be done by the owner in a live session.**
This tool does not verify the on-screen result.

## Patches wired

| group (config key) | factor use | targets |
|--------------------|-----------|---------|
| `cog_death` | `SUIT_LOSE_DURATION` ÷ factor; `setPlayRate` on tracks | `MovieUtil.SUIT_LOSE_DURATION`, `MovieUtil.createSuitDeathTrack`, `MovieUtil.createSuitReviveTrack` |
| `dodge` | `setPlayRate` on the dodge multitracks | `MovieUtil.createToonDodgeMultitrack`, `MovieUtil.createSuitDodgeMultitrack` |
| `door` | `setPlayRate` on the client enter/exit tracks | `DistributedDoor.avatarEnterDoorTrack`, `DistributedDoor.avatarExitDoorTrack` (client half only; the server-side door FSM hold is **not** client-changeable) |
| `runin` | walk speed × factor | `BattleBase.suitSpeed`, `BattleBase.toonSpeed` |

Each target is tried under both TTR's bare module name (`MovieUtil`) and the
open-toontown dotted name (`toontown.battle.MovieUtil`). If a name differs in a
future build, the payload logs what names *are* present in the module (see
`modules_seen` in `/tmp/ttrmod-status.json`) and skips gracefully.

## Design note — how much of "combat entry" is shortenable

From the open-toontown AI battle FSM, the first round is **client-driven**: the
join interval is pure animation time, and the instant the last client sends
`d_joinDone` → adjust → the AI enters `WaitForInput`. The server timers
(`MAX_JOIN_T` + `SERVER_BUFFER_TIME`, the adjusting timer, `SERVER_INPUT_TIMEOUT
= CLIENT_INPUT_TIMEOUT + 2s`) are **upper-bound fallbacks**, not floors — they
add no latency on the fast path. So speeding the client run-in genuinely brings
the input round forward. The only server-side padding a client mod **cannot**
remove is the fixed `0.8 s` `movieDelay` before a multi-toon attack movie and
the `2.0 s` `SERVER_BUFFER_TIME` baked into any timer that actually has to fall
back.

## Re-deriving offsets (after a TTR engine patch)

TTR auto-patches `TTREngine`, which changes its UUID and function addresses.
When `./ttrmod` reports "no offsets recorded for this build" / "missing
addresses" (or the prologue verify fails), re-derive with the `re` skill
(IDA/Hopper) on the arm64 slice of `…/Contents/MacOS/TTREngine`. For the
`exec_builtins` primitive locate these (all core-runtime, present in the frozen
build):

- `PyGILState_Ensure` / `PyGILState_Release` — `pystate.c`, near the `autoTLSkey`
  / "thread state must be current when releasing" strings. (For the current
  build: Ensure `0x100a79e10`, Release `0x100a79f54`.)
- `PyImport_ImportModule`, `PyImport_AddModule` — `import.c` (xref `"__main__"`,
  `sys.modules`).
- `PyModule_GetDict` — `moduleobject.c` (tiny; returns `md_dict`).
- `PyObject_CallMethod` — `call.c` / `abstract.c`.
- `PyErr_Print` (optional) — `pythonrun.c`, xref "Error in sys.excepthook:".

The whole `PyRun_*` family is **dead-stripped** — do not look for
`PyRun_SimpleString`. If the import/call functions are hard to pin, switch the
build's `"primitive"` to `"compile_eval"` and instead locate `PyEval_EvalCode`
(`ceval.c`) and `Py_CompileStringExFlags` (`pythonrun.c`).

Add an entry under the new UUID in `offsets.json` with the vmaddrs and the first
16 prologue bytes of each (space-separated hex) in `verify`.
