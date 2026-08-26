# Status — injection tool

**Cosmetic patch logic (`inproc/payload.py`): complete.** Idempotent, reversible
(`--revert`), defensive, `setPlayRate`-wrapper based (robust to the build's
internal literals). Targets cog-death explosion, dodge step-back, door client
animation, combat run-in — no movement/turn/aim/damage. Adds a read-only
`probe` mode for the live smoke test (reports current target values, changes
nothing).

**Read-only street HUD (`inproc/hud.py`): complete, pending live confirm.**
Concatenated ahead of payload.py into the one code object. Draws street name +
active ToonTasks + gag inventory via `OnscreenText`, built on the main thread
through `taskMgr` (persists after detach), reversible on `--revert`. Data
extraction validated headless under 3.7; the game-attribute paths (open-toontown
`Quests`/`ZoneUtil`/`ToontownBattleGlobals` etc.) and DirectGui rendering need a
live check — a few are flagged medium-confidence (`panda3d.core` vs
`pandac.PandaModules` for `TextNode`, `experience.getExp`, TTR-only zone keys).
Guards degrade a panel gracefully rather than crashing if a name differs.

**Host/lldb driver framework: complete.** Attaches (AMFI disabled permits it),
verifies prologue bytes, drives the interpreter.

**Injection primitive (`marshal_evalcode`): COMPLETE and host-validated.**
Only a live in-game smoke test remains.

TTREngine embeds a **hardened, LTO-inlined, symbol-stripped CPython 3.7** (Panda3D
1.11 deploy-stub). Consequences for getting code to run in-process:

- `PyRun_*` (SimpleString/String/…) is **dead-stripped** — never linked.
- `exec()`/`eval()` are **code-object-only**: `builtin_exec`/`builtin_eval` have no
  string-compile branch. `exec("...source...", g)` cannot work.
- The **bytecode compiler is stripped** (compile.c/symtable.c/ast.c gone) — there
  is no in-process `source → code` path.
- `PyModule_GetDict` / `PyImport_AddModule` / `PyObject_CallMethod` /
  `PyBytes_FromStringAndSize` are all **inlined**, so there are no standalone
  addresses to call.

The route that works: **marshal a code object on the host (with a real 3.7),
inject the bytes, `marshal.loads` in-process, hand it to `PyEval_EvalCode`**,
reading `f_globals` off the live frame (no module-dict call to pin).

## Wired pipeline (as implemented)

Host (`driver.py`):
1. Find a CPython **3.7** (`TTRMOD_PY37`, python.org 3.7, or `python3.7`). The
   marshal/code-object format is version-locked, so a 3.8+ blob will not load in
   the engine's 3.7. Any 3.7.x works — x86_64 under Rosetta is fine (only
   `compile()`+`marshal.dumps()` are used).
2. `compile(header + payload.py)` → `marshal.dumps` → hex into the job. The header
   bakes the config/status paths into the code object (no in-process env plumbing).

In-lldb (`lldb/attach.py`, primitive `marshal_evalcode`):
1. Read `f_globals` off `_PyThreadState_Current` **before** touching the GIL
   (Ensure can swap current-tstate to lldb's calling thread, whose frame is NULL).
2. `PyGILState_Ensure()`.
3. `AllocateMemory`+`WriteMemory` the marshal blob → scratch buffer.
4. `PyByteArray_FromStringAndSize(buf, len)` (copies) → free the buffer.
5. `marshal.loads(0, bytearray)` → code object (METH_O; module arg ignored).
6. `PyEval_EvalCode(co, gd, gd)`; on NULL → `PyErr_PrintEx(1)`.
7. `PyGILState_Release()`.

## Recovered addresses (arm64 slice, UUID `4C4C44C3-5555-3144-A136-F2D2B4A39415`; as-linked vmaddrs, image base `0x100000000`)

| function | vmaddr |
|---|---|
| `PyGILState_Ensure` | `0x100a79e10` |
| `PyGILState_Release` | `0x100a79f54` |
| `PyEval_EvalCode` | `0x100a38d44` |
| `PyErr_PrintEx` | `0x100a7a2c8` (call with arg `1`) |
| `marshal.loads` impl | `0x100a76a20` (`(module_ignored, bytes_obj)`) |
| `PyByteArray_FromStringAndSize` | `0x1009791b4` |
| `r_object` (marshal core) | `0x100a7493c` (unused fallback) |

Globals without a pinnable call — read off the live frame:
```
tstate = *(void**)0x101C0ACD8   # _PyThreadState_Current
frame  = *(void**)(tstate + 24) # tstate->frame
gd     = *(void**)(frame  + 48) # frame->f_globals  (has __builtins__)
```

## Remaining work

**Live smoke test** (owner's running game — arm-and-wait, the tool never logs in
or drives gameplay):
1. `python3 driver.py --probe` at the playground → expect a `probe` report listing
   e.g. `MovieUtil.SUIT_LOSE_DURATION = 6.0`. Proves attach → marshal → eval →
   payload ran, changing nothing.
2. `python3 driver.py` to apply, then a battle to eyeball the shortened cog-death
   explosion / dodge; `python3 driver.py --revert` to restore.

## Fragility note

Every address here is specific to this engine build; the prologue-`verify` bytes
make the tool **refuse to run** against a changed binary rather than call into
the wrong address. TTR auto-patches the engine, so re-derive with the `re` skill
when the arm64 UUID changes. This per-build cost is the main argument for doing
the *movement/animation* work on a private server (plain Python, no addresses).
The 3.7 host dependency is a build-time need only (marshalling the payload).
