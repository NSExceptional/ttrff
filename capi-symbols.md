# CPython 3.8.17 C-API symbol location in TTREngine.arm64

Target: `TTREngine.arm64` — embedded CPython 3.8.17, hardened, whole-program LTO, fully
symbol-stripped (5 exports; every `nm` entry is a `U` import). Image base `0x100000000`;
**file offset = vmaddr − 0x100000000** (verified). Method: structural + string-xref match
against the symbol-ful stock reference `python@3.8/3.8.14` arm64 dylib; type objects found
by scanning DATA for `tp_name` string pointers; "inlined" verdicts confirmed by structural
disasm scans over `eng.full.disasm`.

## Route viability: VIABLE
The C-API-orchestration route works. The wrapping + attribute + call primitives all survive
out-of-line: `PyCFunction_NewEx`, `PyObject_GetAttr(String)`, `PyObject_SetAttr(String)`,
`PyObject_Call`. The one gap — `PyInstanceMethod_New` — has a clean, equivalent fallback
(call the type object). `sys.modules` is reachable via a confirmed 3-deref chain.

## TIER 1 (route-deciding)

| symbol | vmaddr | first 16 prologue bytes | conf |
|---|---|---|---|
| PyObject_Call | `0x10096a64c` | `ff 03 01 d1 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9` | high |
| PyObject_GetAttr | `0x1009c56cc` | `ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91` | high |
| PyObject_SetAttr | `0x1009c5924` | `ff 43 01 d1 f6 57 02 a9 f4 4f 03 a9 fd 7b 04 a9` | high |
| PyObject_GetAttrString | `0x1009c5578` | `ff 03 01 d1 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9` | high |
| PyObject_SetAttrString | `0x1009c5834` | `ff 03 01 d1 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9` | high |
| PyCFunction_NewEx | `0x1009b9bdc` | `ff 43 01 d1 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9` | high |
| **PyInstanceMethod_New** | **ABSENT (inlined)** | — | high |
| PyObject_CallFunctionObjArgs | not located | — | med |
| PyObject_CallMethodObjArgs | not located | — | med |

Several of the above share prologue bytes (common ARM64 frame setup) — that's fine: the
runtime guard verifies the 16 bytes **at the known vmaddr**, it does not search by them.

### PyInstanceMethod_New — absent, use the fallback
No standalone copy. In the reference it has exactly ONE caller (instancemethod_new = tp_new);
LTO inlined its whole body into `instancemethod_new` (`sub_10097D094` @ `0x10097d094`) and,
being unexported with no other caller, the standalone was dead-stripped. The inlined body is
verbatim: GC-alloc, `ob_type = &PyInstanceMethod_Type (0x101a79c20)`, `Py_INCREF(func)`,
`method->func = func` at **+0x10**, GC-track.

**Fallback (self-binding still works):** the type is present/ready at `0x101a79c20` with
`tp_new = 0x10097d094`. To mint a self-binding instancemethod at runtime:
`PyObject_Call((PyObject*)0x101a79c20, one_tuple(callable), NULL)` — runs tp_new, returns an
instancemethod whose `tp_descr_get` (`0x10097d078`) binds `self` on attribute access. Or call
tp_new directly: `((newfunc)0x10097d094)(0x101a79c20, one_tuple, NULL)`.

### PyCFunction_NewEx — `PyMethodDef` layout it expects
`sub_1009B9BDC(PyMethodDef *ml, PyObject *self, PyObject *module)`. It reads `ml->ml_flags`
at **ml+0x10**, masks `0x8F`, and switch-selects the vectorcall trampoline; bad flags →
SystemError `"%s() method: bad call flags"`.
- **PyMethodDef**: `ml_name`+0x0 (`const char*`), `ml_meth`+0x8 (`PyCFunction`), `ml_flags`+0x10 (`int`), `ml_doc`+0x18.
- Result **PyCFunctionObject**: `m_ml`+0x10, `m_self`+0x18, `m_module`+0x20, `m_weakreflist`+0x28, `vectorcall`+0x30. `ob_type` set to `&PyCFunction_Type (0x101a940b0)`.

### Call variants
`PyObject_Call` (found) covers everything. The ObjArgs variants weren't pinned (no distinctive
string; their shared helper `object_vacall` wasn't anchored). Workarounds: build a tuple and
use `PyObject_Call`; for a method, `PyObject_GetAttr` then `PyObject_Call`.

## TIER 2 (wrapper bodies)

- **PyObject_GetAttr / SetAttr** — found (see TIER 1 table).
- **sys.modules route (preferred over PyImport_GetModuleDict, which is INLINED):**
  `sys.modules = *(*(*(0x101c0acd8) + 0x10) + 0x38)`
  i.e. `tstate = *(void**)0x101c0acd8` (current-tstate cell); `interp = *(tstate+0x10)`;
  `module_dict = *(interp+0x38)`. Offsets verified in BOTH the reference (`PyImport_GetModuleDict`
  0xd96b0) and the live engine (importlib helper `sub_100019250`).
- **PyErr_Occurred — INLINED, no standalone.** Equivalent:
  `t = *(void**)0x101c0acd8; occurred = t ? *(void**)(t+0x58) : NULL;` (curexc_type @ tstate+0x58, confirmed).
- **PyErr_Clear — treat as inlined.** Equivalent: zero `curexc_type/value/traceback` at
  `tstate+0x58/+0x60/+0x68` (XDECREF the old values), or locate `_PyErr_Restore` and call `(tstate,0,0,0)`.
- **PyFloat_FromDouble / PyTuple_New / PyTuple_Pack / Py_BuildValue — not located this pass.**
  They exist out-of-line (called from thousands of sites) but resisted quick structural isolation
  because the binary also bundles OpenAL/TCL/ODE/Panda3D (shared prologues) and there are many
  type-referencing tuple/float helpers. Anchors for a follow-up:
  - `PyFloat_Type = 0x101aae5c8`, `PyTuple_Type = 0x101aa7b30`.
  - `PyTuple_New`: the ONE-arg (Py_ssize_t) ctor with a negative-size `_PyErr_BadInternalCall`
    + a size≤19 free_list; sets `ob_type=&PyTuple_Type`, `ob_size`@+0x10, items@+0x18.
    (Note `sub_1009D682C` is `tuple.__new__`/tp_new, NOT this.)
  - `PyFloat_FromDouble`: small ctor writing the double to `obj+0x10`, `ob_type=&PyFloat_Type`.
  - Convenience alternative once found: `Py_BuildValue("d"/"O"/"(OO)", ...)` (stock 0xe441c).

## Confirmed struct offsets (3.8.17, this build)

- **tstate cell**: `0x101c0acd8` (holds current `PyThreadState*`).
- **PyThreadState**: `interp`+0x10, `recursion_depth`+0x20, `curexc_type`+0x58, `curexc_value`+0x60, `curexc_traceback`+0x68.
- **PyInterpreterState**: `modules`+0x38 (= sys.modules).
- **PyTypeObject**: `tp_name`+0x18, `tp_getattr`+0x40, `tp_setattr`+0x48, `tp_call`+0x80, `tp_getattro`+0x90, `tp_setattro`+0x98, `tp_flags`+0xa8 (HAVE_VECTORCALL = byte@+0xa9 bit3), `tp_descr_get`+0x110, `tp_new`+0x138.
- **PyMethodDef**: `ml_name`+0x0, `ml_meth`+0x8, `ml_flags`+0x10, `ml_doc`+0x18.

## Type objects & helper functions identified (engine)
- Types: `PyCFunction_Type 0x101a940b0`, `PyInstanceMethod_Type 0x101a79c20`, `PyFloat_Type 0x101aae5c8`, `PyTuple_Type 0x101aa7b30`.
- Helpers: `_PyErr_Format 0x100a47b10`, `PyUnicode_InternInPlace 0x100a11518`, `PyUnicode_DecodeUTF8 0x1009ee48c`, `PyUnicode_AsUTF8 0x100a07a38`, `Py_FatalError 0x100a2241c`, `PyArg_UnpackTuple 0x100a5078c`, `gc_new_allocator 0x10095d6f8`, `_PyEval_EvalFrameDefault 0x100a39f2c`.

## Notes on method
- The stock reference disassembles cleanly with `objdump -d --start-address/--stop-address`
  (the `--macho` code path ignores the range; the plain path honors it and resolves callee
  symbols in `<...>`). Distinctive error strings were the primary xref anchors; `re`
  (IDA) decompile/xref did the engine-side structure + function-boundary resolution.
- No classifier blocks or denied commands were hit; IDA analysis was already cached/warm.
