# Status — injection primitive

**Cosmetic patch logic (`inproc/payload.py`): complete.** Idempotent, reversible
(`--revert`), defensive, `setPlayRate`-wrapper based (robust to the build's
internal literals). Targets cog-death explosion, dodge step-back, door client
animation, combat run-in — no movement/turn/aim/damage.

**Host/lldb driver framework: complete.** Attaches (AMFI disabled permits it),
verifies prologue bytes, drives the interpreter.

**Injection primitive: blocked on the engine's build shape — needs a rework +
one more address before it can run.** What the RE turned up:

TTREngine embeds a **hardened, LTO-inlined, symbol-stripped CPython 3.7** (Panda3D
1.11 deploy-stub). Consequences for getting code to run in-process:

- `PyRun_*` (SimpleString/String/…) is **dead-stripped** — never linked.
- `exec()`/`eval()` are **code-object-only**: `builtin_exec`/`builtin_eval` have no
  string-compile branch (they raise *"arg 1 must be a code object"*). So
  `exec("...source...", g)` cannot work regardless of how it's invoked.
- The **bytecode compiler is stripped** (compile.c/symtable.c/ast.c gone) — there
  is no in-process `source → code` path (`Py_CompileString*` unusable).
- `PyModule_GetDict` / `PyImport_AddModule` / `PyObject_CallMethod` /
  `PyBytes_FromStringAndSize` are all **inlined**, so there are no standalone
  addresses to call.

The only viable route is therefore: **marshal a code object on the host, inject
the bytes, `marshal.loads` it in-process, and hand it to `PyEval_EvalCode`.**

## Recovered addresses (arm64 slice, UUID `4C4C44C3-5555-3144-A136-F2D2B4A39415`; as-linked vmaddrs, image base `0x100000000`)

| function | vmaddr | confidence |
|---|---|---|
| `PyGILState_Ensure` | `0x100a79e10` | high |
| `PyGILState_Release` | `0x100a79f54` | high |
| `PyEval_EvalCode` | `0x100a38d44` | high — `(co, globals, locals)` |
| `PyErr_PrintEx` | `0x100a7a2c8` | high — call with arg `1` for `PyErr_Print` |
| `marshal.loads` impl | `0x100a76a20` | med-high — `(self_ignored, bytes_obj) → code object` |
| `r_object` (marshal core) | `0x100a7493c` | fallback path |

Globals dict without any pinnable call — read it off the live frame:
```
tstate = *(void**)0x101C0ACD8   # current PyThreadState
frame  = *(void**)(tstate + 24) # tstate->frame
gd     = *(void**)(frame  + 48) # frame->f_globals  (has __builtins__)
```

## Remaining work to make it runnable

1. ~~Pin the bytes constructor~~ **DONE** — `PyByteArray_FromStringAndSize` =
   `0x1009791b4` (yields a `bytearray`, which `marshal.loads` accepts via the
   buffer protocol). `offsets.json` is now complete and internally consistent
   (all seven addresses populated, decimals match hex, prologue-`verify` bytes
   recorded; a stale-decimal bug that would have tripped the verify-abort was
   fixed). The only step left before this is runnable:
2. **Rewire `driver.py` / `lldb/attach.py`** from the `exec_builtins` primitive to:
   marshal `compile(payload_src)` on a matching 3.7.x host → inject bytes →
   `marshal.loads` → read `gd` from the frame → `PyEval_EvalCode(co, gd, gd)` →
   `PyErr_PrintEx(1)` on NULL → release the GIL.
3. **Live smoke test** (owner's session): attach at the playground, confirm a
   value read (`MovieUtil.SUIT_LOSE_DURATION`), then in-battle visual check.

## Fragility note

Every address here is specific to this engine build. TTR auto-patches the engine
periodically; when the arm64 UUID changes, all of the above must be re-derived
with the `re` skill. The prologue-`verify` bytes in `offsets.json` make the tool
**refuse to run** against a changed binary rather than call into the wrong
address — safe, but it means a re-RE step after each engine patch. This
per-build cost is the main argument for doing the movement/animation work on a
private server (plain Python, no addresses) instead.
