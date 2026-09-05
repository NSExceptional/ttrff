# CPython 3.8.17 C-API symbol location in TTREngine.arm64 — pass 2

Target: `TTREngine.arm64` (Toontown Rewritten), embedded CPython 3.8.17, hardened + whole-program
LTO, fully symbol-stripped. Image base `0x100000000`; **file offset = vmaddr − 0x100000000**.
Method: structural + string/type-xref match against the symbol-ful stock `python@3.8/3.8.14` arm64
dylib, every identity cross-checked with IDA (`re`) decompilation. `prologue16` = first 16 raw
little-endian bytes for a runtime memcmp guard at the vmaddr.

## TIER 1 — route-unblocking (all found)

| symbol | vmaddr | first 16 prologue bytes | conf |
|---|---|---|---|
| **PyDict_GetItemString** | `0x10098e890` | `f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 01 aa` | high |
| **PyTuple_New** | `0x1009d6e68` | `ff 03 01 d1 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9` | high |
| **PyTuple_SetItem** | `0x1009d7a38` | `ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 08 04 40 f9` | high |

- **PyDict_GetItemString(dict, const char* name)** returns a **borrowed** ref into the dict,
  **NULL if absent**, and **clears** any lookup error — exactly the `sys.modules[name]` semantics.
  Confirmed twice: (a) structural match to stock (strlen → make temp unicode key via the UTF-8
  decoder `0x1009ee48c` → `PyDict_GetItem` `0x10098da6c` → Py_DECREF key → return; fail path inlines
  PyErr_Clear zeroing `tstate+0x58/+0x60/+0x68`); (b) the engine's **own importlib helper**
  `sub_100019250` calls it as `PyDict_GetItemString(sys.modules, "_frozen_importlib")`.
- **PyTuple_New(n)** then fill with **PyTuple_SetItem(t,i,v)** (steals `v`, requires refcount==1 —
  true for a fresh tuple). For the 1-tuple `(callable,)` self-bind trick this is all you need.
  You can also write items directly at `t+0x18+8*i` (slots start NULL; add your own INCREF).
- `PyTuple_Pack` was left unpinned — redundant given New+SetItem. It exists out-of-line as a small
  `va_list` caller of PyTuple_New in the tupleobject.c cluster (~`0x1009d74xx`) if ever wanted.

## TIER 2 — wrapper bodies

| symbol | vmaddr | first 16 prologue bytes | conf |
|---|---|---|---|
| PyTuple_GetItem | `0x1009d79b0` | `ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 08 04 40 f9` | high |
| PyTuple_Size | `0x1009d7954` | `ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 08 04 40 f9` | high |
| PyObject_GetItem | `0x10096c1dc` | `ff 43 01 d1 f6 57 02 a9 f4 4f 03 a9 fd 7b 04 a9` | high |
| PyObject_GetIter | `0x10096ef98` | `ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91` | high |
| PyIter_Next | `0x10096f104` | `f6 57 bd a9 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91` | high |
| PyUnicode_AsUTF8 | `0x100a14074` | `01 00 80 d2 70 ce ff 17` (8-byte thunk) | high |
| PyFloat_FromDouble | **INLINED** | — (recipe below) | high |
| PyFloat_AsDouble | **INLINED** | — (equiv below) | high |

- **PyUnicode_AsUTF8 correction:** the prior pass's `0x100a07a38` is actually
  **PyUnicode_AsUTF8AndSize** (2-arg: `str, size*`). The thin `PyUnicode_AsUTF8` is `0x100a14074`
  (`mov x1,#0; b 0x100a07a38`). `AsUTF8(s) == AsUTF8AndSize(s, NULL)` — either works for a substring
  test (returns the internal UTF-8 buffer; do not free).
- **PyObject_GetItem** is an alternate dict indexer (`GetItem(sys.modules, unicode_name)` via the
  dict's `mp_subscript`), but returns a **new** ref and **raises KeyError** on miss — prefer
  `PyDict_GetItemString` for the borrowed/NULL contract.

### PyFloat_FromDouble — inlined, use this recipe
No standalone survives (verified inlined in marshal `sub_100A76E4C`, `_PyFloat_Init`
`sub_100994E7C`, `float.__float__` `sub_100996018`). PyFloat is a **non-GC 24-byte** object with a
dedicated free-list; the double is stored as an integer store, which is why "str d" scans missed it.

```c
// float layout: [+0]=ob_refcnt, [+8]=ob_type, [+0x10]=ob_fval(double)
PyObject* make_float(double v) {
    void* op = *(void**)0x101be9588;                 // float free_list head
    if (op) { *(void**)0x101be9588 = *(void**)((char*)op+8);   // pop
              (*(int32_t*)0x101be9590)--; }                    // numfree--
    else { op = ((void*(*)(void*,size_t)) *(void**)0x101a7a668) // pymalloc
                  (*(void**)0x101a7a660, 24); if(!op) return 0; }
    *(void**)((char*)op+8)    = (void*)0x101aae5c8;   // ob_type = &PyFloat_Type
    *(intptr_t*)op            = 1;                    // ob_refcnt = 1
    *(double*)((char*)op+0x10)= v;                    // ob_fval
    return op;                                        // (skip the flags&2 / 0x101c0a51c debug hooks)
}
```

### PyFloat_AsDouble — inlined (PyFloat_AS_DOUBLE macro), use this
```c
double as_double(PyObject* op) {
    if (*(void**)((char*)op+8) == (void*)0x101aae5c8) // Py_TYPE(op)==&PyFloat_Type
        return *(double*)((char*)op+0x10);
    PyObject* f = ((PyObject*(*)(PyObject*))0x10096e65c)(op); // PyNumber_Float
    if (!f) return -1.0;
    double d = *(double*)((char*)f+0x10); /* Py_DECREF(f) */ return d;
}
```

## Type objects & data (this pass)
- `PyTuple_Type 0x101aa7b30`, `PyFloat_Type 0x101aae5c8` (flags byte `0x101aae671`),
  `PyUnicode_Type 0x101aa77c0` (NEW), `PyLong_Type 0x101aade08` (NEW), `PyComplex_Type 0x101a858b8` (NEW).
- **sys.modules** (re-confirmed via `sub_100019250`): `*(*(*(void**)0x101c0acd8 + 0x10) + 0x38)`.
- **float free-list**: head `0x101be9588`, count(int32) `0x101be9590` (MAXFREELIST 100).
- **tuple free-list**: array base `0x101bec788`, count array `0x101bec738`.
- **pymalloc**: `((void*(*)(void*,size_t)) *(void**)0x101a7a668)(*(void**)0x101a7a660, size)`.
- **gc alloc** (`_PyObject_GC_New/NewVar` family) `0x10095d6f8`.

## Type-slot offsets confirmed (3.8.17, this build)
tp_flags byte `+0xab` (DICT_SUBCLASS bit5=0x20, TUPLE bit2, UNICODE bit4, LONG bit0, LIST bit1),
tp_as_sequence `+0x68` (sq_item `+0x18`), tp_as_mapping `+0x70` (mp_subscript `+0x8`),
tp_hash `+0x78`, tp_iter `+0xd8`, tp_iternext `+0xe0`, tp_as_number `+0x60` (nb_float `+0x90`).
PyDictObject: ma_used `+0x10`, ma_version `+0x18`, ma_keys `+0x20`, ma_values `+0x28`; unicode cached hash at key`+0x18`.

## Supporting helpers identified
- **PyDict_GetItem `0x10098da6c`** (borrowed, no-raise-on-miss; checks DICT_SUBCLASS flag, unicode-key
  fast path vs `&PyUnicode_Type`, else `tp_hash`).
- **PyNumber_Float `0x10096e65c`**, **PyComplex_FromDoubles `0x10097f6ac`**, **_Py_HashDouble `0x100a1d6e8`**.
- **unicode_decode_utf8 / PyUnicode_FromStringAndSize(char*,len,...) `0x1009ee48c`** (prior pass's
  "DecodeUTF8"; ~1273 callers).
- Error helpers: `_PyErr_Format 0x100a47b10`, inline-BadInternalCall target `0x100a46704`,
  PyErr_SetString-like `0x100a46b2c`, PyErr_ExceptionMatches-like `0x100a46bf4`, raise-with-tstate `0x100a461d4`.

## Method notes
- The engine keeps full source-path strings (`/builds/mirai/python/cpython/Objects/tupleobject.c`,
  `.../dictobject.c`, …); the `objdump` "literal pool for" annotation is over-eager (attached to far
  more instructions than the real xref), so it is a hint, not a count — real references were pinned
  with IDA. Source **line-number immediates** (`mov w8,#<line>` before the inlined `_PyErr_Format`
  BadInternalCall) DID match stock 3.8.14 (tuple: New=85/0x55, Size=142/0x8e, GetItem=153/0x99,
  SetItem=169/0xa9) and were the decisive per-function disambiguator for the tuple accessors.
- Several functions share the first 16 bytes (common ARM64 frame setup). That is expected and fine —
  the runtime guard verifies bytes AT the known vmaddr; it does not search by them.
- No classifier blocked any command; IDA analysis was already cached/warm (`.i64` present).
