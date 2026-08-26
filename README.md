# ttr-mods

Personal, cosmetic quality-of-life tweaks for the owner's **own** Toontown
Rewritten client, on the owner's own machine and account. It attaches to the
running game and shortens a handful of **purely visual** battle animations by
scaling their Panda3D interval play-rates.

## What this is (and is not)

- **Is:** a runtime tool that (a) speeds up cosmetic battle playback (cog-death
  explosion, dodge step-back, door open/close, combat run-in) so battles feel
  snappier, and (b) draws an always-on, read-only **street HUD** — current street
  name, active ToonTasks, and gag inventory — so you don't have to open the
  Shticker Book.
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
**stripped**, and — because it's a frozen, LTO-inlined *deploy-stub* build — three
things are gone that a normal injector would use: the whole `PyRun_*` family is
**dead-stripped**, the **bytecode compiler is stripped** (`exec`/`eval` are
code-object-only; there is no in-process `source → code` path), and
`PyModule_GetDict` / `PyImport_AddModule` / `PyBytes_FromStringAndSize` are all
**inlined away** (no standalone addresses to call). The surviving C-API functions
must be called by **address**. The tool therefore uses the **`marshal_evalcode`**
primitive:

1. Reads the running binary's **arm64 Mach-O UUID** and looks up the CPython
   C-API vmaddrs for that exact build in `offsets.json` (derived once with the
   `re` skill; see "Re-deriving offsets").
2. On the **host**, compiles `payload.py` to a code object and `marshal.dumps`
   it — using a real **CPython 3.7** (`TTRMOD_PY37`, python.org 3.7, or
   `python3.7` on `PATH`). The marshal/code-object format is version-locked, so a
   3.8+ blob will not load in the engine's 3.7; any 3.7.x works, including x86_64
   under Rosetta (only `compile()`+`marshal.dumps()` are used).
3. Drives `lldb` (AMFI is disabled on this machine, so attaching to the
   hardened-runtime process is permitted) to run, on the live interpreter, every
   step callable by address:
   ```
   gd   = *(void**)(*(void**)(*(void**)current_tstate + 24) + 48);  // f_globals, read BEFORE the GIL
   gil  = PyGILState_Ensure();
   buf  = <AllocateMemory + WriteMemory of the 3.7 marshal blob>;
   ba   = PyByteArray_FromStringAndSize(buf, len);   // copies; buffer then freed
   co   = marshal.loads(0, ba);                       // METH_O; module arg ignored
   res  = PyEval_EvalCode(co, gd, gd);                // execs payload
   if (!res) PyErr_PrintEx(1);
   PyGILState_Release(gil);
   ```
   `f_globals` is read off the live frame **before** `PyGILState_Ensure` (Ensure
   can swap the current thread-state to lldb's calling thread, whose frame is
   NULL). Before calling anything it verifies each function's prologue bytes and
   **aborts** if they don't match (guards against a silently auto-patched engine).
   (Two legacy string primitives, `exec_builtins` and `compile_eval`, remain in
   the code for other/hypothetical builds but are dead-stripped in shipping TTR.)
4. `inproc/payload.py` runs inside the game and monkeypatches the loaded modules.

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
| `driver.py` | host side: find PID, look up offsets, marshal payload on 3.7, drive lldb |
| `lldb/attach.py` | runs in lldb: attach, verify, call the C-API primitive |
| `inproc/payload.py` | runs inside TTREngine: the animation monkeypatches |
| `inproc/hud.py` | runs inside TTREngine: the read-only street HUD overlay (concatenated ahead of payload.py) |
| `config.json` | which groups/HUD are on + their options |
| `offsets.json` | per-build CPython C-API vmaddrs (keyed by UUID) |

## Requirements

- **AMFI disabled** on this machine (permits attaching to the hardened-runtime
  process).
- A host **CPython 3.7** to marshal the payload for the engine's 3.7 interpreter.
  Set `TTRMOD_PY37=/path/to/python3.7`, or install python.org 3.7 (the driver
  also auto-finds `/Library/Frameworks/Python.framework/Versions/3.7/bin/python3.7`
  and `python3.7` on `PATH`). Any 3.7.x, incl. x86_64 under Rosetta — only
  `compile()`+`marshal.dumps()` are used, so no extension modules are needed.

## Run steps

1. Launch Toontown Rewritten normally and log in (the owner does this; the tool
   never logs in or drives gameplay). Reaching the login screen is enough to
   attach, but the battle modules only load in-district, so apply once you're in
   a playground/street for the patches to bind immediately (the import hook will
   otherwise bind them the moment those modules import).
2. **Smoke test first (read-only, changes nothing):**
   ```
   cd ~/Developer/ttr-mods
   ./ttrmod --probe
   ```
   Expect a `probe` report listing current values, e.g.
   `cog_death_duration  MovieUtil.SUIT_LOSE_DURATION = 6.0`. This proves the whole
   attach → marshal → eval → payload pipeline works without altering gameplay.
3. Apply:
   ```
   ./ttrmod
   ```
   You'll see which patches applied/were skipped. It's safe to re-run.
4. Revert (restores originals in the live process, no restart needed):
   ```
   ./ttrmod --revert
   ```
5. Inspect the last in-process result:
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

## Street HUD overlay (`inproc/hud.py`)

An always-on, **read-only** overlay drawn with Panda3D `OnscreenText`, anchored to
the window corners so it tracks on resize. It shows, while you're on a street
(hidden in playgrounds/interiors unless `always_show`):

- **Street name** — resolved from the current zoneId via `ZoneUtil.getBranchZone`
  + `ToontownGlobals.StreetNames` (playground/hood-name fallback).
- **Active ToonTasks** — each quest rendered by reusing the game's own `Quest`
  objects (`Quests.getQuest(id).getString()` + `.getProgressString(av, questDesc)`
  + `.getLocationName()`), plus the turn-in NPC and its street.
- **Gag inventory** — a per-track grid of counts by level (`inventory.numItem`),
  with `.` for levels not yet unlocked.

Config (`config.json` → `hud`): `enabled`, `show_tasks`, `show_inventory`,
`show_street_name`, `always_show` (default false = street-only), `refresh_hz`
(default 4), `scale`. It's built on the main thread via `taskMgr` (thread-safe
scene-graph construction) and **persists after lldb detaches**, like the animation
patches; `--revert` destroys the nodes and removes the tasks. Every game-attribute
lookup is guarded — a TTR rename can blank a panel but never crashes the game.
Reads only client-side state; no server interaction, no gameplay logic touched.

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
`marshal_evalcode` primitive locate these (all core-runtime, present in the
frozen build):

- `PyGILState_Ensure` / `PyGILState_Release` — `pystate.c`, near the `autoTLSkey`
  / "thread state must be current when releasing" strings. (Current build: Ensure
  `0x100a79e10`, Release `0x100a79f54`.)
- `PyEval_EvalCode` — `ceval.c` (thin wrapper over `_PyEval_EvalCodeWithName`).
- `marshal.loads` impl — `marshalmodule.c`; METH_O `(module, arg)`, xref the
  `"bad marshal data"` strings. (Current: `0x100a76a20`.)
- `PyByteArray_FromStringAndSize` — `bytearrayobject.c`; any bytes-like the
  `marshal.loads` `y*` parse accepts works. (Current: `0x1009791b4`.)
- `PyErr_PrintEx` (optional but recommended) — `pythonrun.c`, xref "Error in
  sys.excepthook:"; called with arg `1`.
- The **current thread-state global** (`_PyThreadState_Current` /
  `_PyRuntime.gilstate.tstate_current`) plus the `tstate→frame` (24) and
  `frame→f_globals` (48) offsets, recorded under `globals_from_frame`. `f_globals`
  is read off the live frame because `PyModule_GetDict`/`PyImport_AddModule` are
  inlined away.

The whole `PyRun_*` family **and** the bytecode compiler are **dead-stripped** —
do not look for `PyRun_SimpleString` or `Py_CompileString*`; there is no
in-process source→code path, which is why the payload is marshalled on a 3.7
host.

Add an entry under the new UUID in `offsets.json` with the vmaddrs (both decimal
in `addrs` and hex in `vmaddrs_hex`), the `globals_from_frame` block, and the
first 16 prologue bytes of each function (space-separated hex) in `verify`.
