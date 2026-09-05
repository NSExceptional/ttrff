# ttr-mods — live TTR injection: technical status

_Living technical doc for the **LIVE official-client** injection track (this repo). Organized by
topic, not by date. The mods themselves are done + tested on the local open-toontown client; that
separate shipping track is documented in `~/Developer/toontown-dev/PROJECT-NOTES.md`.
Last updated 2026-09-05._

> Sensitive-RE hygiene: keep instrumentation/injection work in subagents, and for any run against
> the live game follow the device-capture handshake. See the memory notes
> `[[feedback-subagents-for-sensitive-re]]` and `[[feedback-device-capture-handshake]]`.

---

## Goal & hard constraint

- **Goal (home#77):** cosmetic quality-of-life **animation-speed** mods on the **LIVE official TTR
  client** — snappier battle playback (all attacks, cog-death explosion, dodge step-back, run-in,
  faceoff), teleport/tunnel/book/iris transitions — plus a read-only street HUD (tasks, gags,
  street name). No movement/turn/aim/damage logic; no server-validated advantage.
- **HARD RULE — strictly client-side.** Every mod must port **1:1 to the real TTR server** later, so
  it may only touch client code / client-driven timing. Never anything server-authoritative
  (`*AI.py`, shared constants like `BattleBase` suit/toon speed). Consequence accepted: where a
  delay is server-enforced (e.g. the door's `DistributedDoorAI` phase holds), it stays; a client mod
  can only speed the visuals. Run-in is fair game because the first battle round is **client-driven**
  (AI advances on `d_joinDone`; server timers are upper-bound fallbacks, not floors).
- **Live is mandatory.** "Local is done. We are not giving up on live." The local open-toontown
  client is the separate, already-shipping track (source edits, no injection, no ban risk); it exists
  to develop/validate the mods, not as a substitute for the live goal.
- **Blunt cost/benefit (on record):** the mods already work + are tested on local open-toontown;
  the live-official track is crash-prone (a Sentry minidump names frida on every fault) and must be
  re-derived on each engine auto-patch. Pursue live only because the official client is a hard
  requirement.

## Current state

**Milestone-1 COMPLETE (2026-09-05) — live native dispatch PROVEN end-to-end.** The C-API
orchestration route is validated on the live hardened engine: install a self-binding native
trampoline on a real game method → the game's own call runs OUR native `NativeCallback` → the
wrapper calls the original → game survives → clean revert. Zero injected bytecode, so all three
anti-injection layers are bypassed. Details below.

**Milestone-2 step 1 DONE + LIVE-PROVEN (2026-09-05) — self-discovering wrap-after, incl. class
resolution by method signature.** The two primitives PASS on stock 3.8: (a) the **manual PyFloat
builder** and (b) the **generic wrap-after trampoline** (native port of `payload.py`'s
`_make_wrap_after`/`_apply_after`, with the exception-clear discipline). (c) The vault loads the
target classes under **fully HASHED module names**, so resolving them by name FAILS. Fixed by a
read-only **"find class by METHOD SIGNATURE" scan** (`ST.scanBySignature`/`classSignature`, shared
verbatim between `frida/trampoline_inject.py` and `localtest/findcls_test.py`, offline PASS) plus a
method-name **substring discovery** scan (`ST.scanBySubstr`) for when method names are hashed too.
New read-only modes: `TTRMOD_MODE=findcls` (classes defining ALL of `TTRMOD_METHODS`) and `findmeth`
(N exact group scans via `;`-separated `TTRMOD_METHODS` + a `TTRMOD_SUBSTR` method-name sweep +
`TTRMOD_LISTCLS` class dumps). **mod1 now self-discovers its class by signature** (env override
`TTRMOD_TMOD`/`TTRMOD_TCLS`; interval attr override `TTRMOD_ATTR`; first-fire `__dict__` probe via
`TTRMOD_PROBE_ATTRS=1`).

**Live result (2026-09-05, ~5 careful runs, ZERO crashes, every run reverted rc:0, game always
alive):** mod1 self-discovery + wrap-after is PROVEN end-to-end — but the tunnel TARGET in
`payload.py`/old notes is WRONG for TTR (it was copied from open-toontown). See "The tunnel target,
re-derived live" below. Net: `fires=1` on the real self-discovered method (`LocalToon.tunnelOut`),
clean revert, no crash — but `setPlayRate` never lands because the walk interval is NOT stored on the
toon instance. The speedup itself is **still blocked** pending a different hook for the walk interval.

---

## The target — TTREngine

- **Engine:** `TTREngine` (universal Mach-O; app at `/Applications/Toontown Launcher.app`, install
  at `~/Library/Application Support/Toontown Rewritten/`). = **Panda3D 1.11 + a frozen, hardened,
  whole-program-LTO, symbol-stripped CPython 3.8.17.**
  - **It is 3.8.17, NOT 3.7** (all early "3.7" notes — including this repo's stale `README.md` — are
    wrong). Tells: version strings `3.8.17` / `.cpython-38-darwin.so` / `cpython-38`, and the
    smoking gun `co_posonlyargcount` (the code-object field PEP 570 added in 3.8). Marshal/code-object
    format is version-locked, so any host marshalling must use **3.8** (`/opt/homebrew/bin/python3.8`
    = 3.8.14; micro version irrelevant — only the 3.8 minor matters; standalone 3.8.17 in
    `scratchpad/python`). A 3.7 blob under this 3.8 engine hard-crashes.
  - Fully symbol-stripped: 5 exports, every `nm` entry is a `U` import. Whole-program LTO inlines many
    hot C-API functions to no standalone address (see reference tables).
- **Game code vault:** all game Python is compiled + **AES-encrypted in `TTRGame.vlt`** (a `VT17`
  container, single AES blob, flat ~7.95 bit/byte entropy, no `.pyc`/zlib on disk; cleartext metadata
  `CREATOR=container`, `MWZ=baskerville_borkborks`, `VERSION=ttr-live-v4.4.2`). Engine decrypts it to
  a **RAM filesystem** at runtime (LibreSSL / Apple `CCCrypt`; symbol chain
  `decryptFile`→`decompressFile`→`VirtualFileMountRamdisk`) and imports it as normal (but ciphered,
  see layer #3) Python. Key is embedded/derived in the binary, not a plaintext string (recover only
  via a debugger breakpoint on `decryptFile`/`CCCrypt`).
- **Attach:** frida via `task_for_pid` — run as **root** (AMFI-off doesn't grant the entitlement's
  task-port power; `task_for_pid` needs root even for one's own non-hardened procs). **lldb is DEAD**
  on this binary: `debugserver` reliably SIGSEGVs attaching to TTREngine specifically (async signal
  during `ptrace(PT_ATTACHEXC)`), even on stable Xcode 16.4 — TTR-specific, not toolchain. Don't
  retry lldb. `task_for_pid` + `vmmap` work fine.
- **Crash reporting = Sentry (phone-home vector).** Statically-linked sentry-native 0.6.5 + Breakpad
  minidump + curl HTTP POST (`application/x-sentry-envelope`, `.crashreport`). DSN is **not**
  hardcoded (supplied via env or the vault; endpoint unknown statically). It fires **on crash** and
  uploads a minidump whose loaded-module list **would name `frida-agent` if we crash while attached**.
  No continuous integrity beacon. **⇒ MINIMIZE CRASHES.** (open-toontown has zero telemetry; Sentry
  is TTR's proprietary add.)
- **What the engine does NOT have (adversarial static RE):** no C-level anti-debug (no
  `ptrace`/`PT_DENY_ATTACH`, no `csops`/`CS_DEBUGGED`, no `P_TRACED` sysctl, zero raw syscalls in the
  slice); no anti-frida/anti-injection (no frida/gum/gadget/cynject/27042 strings; a
  `DYLD_INSERT_LIBRARIES` string exists with 0 xrefs); no in-memory self-integrity (no `__TEXT`
  checksum, no self-`csops`). Panda3D **Multifile signature-verify** IS compiled in (LibreSSL
  X509/ECDSA) but only checks signed **on-disk** files (ToonSec) — blind to RAM patches. The
  **Launcher** hash-verifies files vs a server manifest (`getGameHashFromManifest`/`sha1Hash`/
  `TTRPatcher`) — on-disk / pre-launch, reverts disk edits, blind to RAM injection.
- **Unknown gap — Python-level detection:** the authoritative game Python is encrypted in the vault
  (unreadable statically), and the engine is 3.8, so PEP-578 audit hooks are possible — a native
  `PySys_AddAuditHook` (stripped C) or Python `sys.addaudithook` (in the vault) could make
  `marshal.loads`/`exec`/`compile`/`import` observable. **At the first clean dynamic session,
  enumerate `sys` audit hooks, `sys.meta_path`, `builtins.__import__` identity, and loaded dylibs**
  before doing anything heavier. (Running marshalled code via `PyEval_EvalCode` is the most
  audit-observable action; the chosen trampoline route uses `setattr` + native calls, the lowest-risk
  actions.)
- **Build identity:** arm64 Mach-O **UUID `4C4C44C3-5555-3144-A136-F2D2B4A39415`** (May 2024 build),
  image base `0x100000000`, **file offset = vmaddr − 0x100000000**. ASLR slide is random per launch,
  computed at runtime. **Every address in this doc is per-build** — re-derive on each TTR engine
  auto-patch (see Fragility).

---

## The three anti-injection layers

### Layer 1 — `marshal` `TYPE_CODE` disabled → **WORKED AROUND**
The engine's `marshal` refuses to unmarshal code objects. `r_object` (`0x100a7493c`) dispatches via a
jump table at `0x1015a4af2` (16-bit entries; `handler = 0x100a74a04 + entry*4`; index = `typecode −
0x28`). The entry for **`TYPE_CODE` (`0x63`, index 59) = `83` → handler `0x100a74b50`, the SAME
address as the out-of-range error branch**, which loads the literal `"bad marshal data (unknown type
code)"`. So `marshal.loads(<any code object>)` returns NULL for every code object, while every basic
field type (bytes/tuple/str/int/float) works. This is invisible to string-based analysis (a
data-driven jump-table entry, not a check). It kills the old `marshal_evalcode` primitive.
**Workaround (built, largely superseded):** host-side marshal the code object's 16 FIELDS as a pure
data tuple (no `TYPE_CODE`), inject, `marshal.loads` → the tuple, rebuild via
`PyCode_NewWithPosOnlyArgs`. Verified: the rebuilt object is a real `code` object whose fields match
the host exactly. (Now superseded by the trampoline route, which needs no code objects at all.)

### Layer 2 — `f_builtins` (+40) is read-only → **BYPASSED**
In this frozen+LTO build the builtins dict is read-only, so the first `STORE_NAME` write to it faults
(`x=1` hard-faulted while a read-only `open(...)` survived). **Fix: exec/store into `f_globals`
(+48)**, a writable module dict that still resolves builtins via its `__builtins__`. (Only relevant to
the eval path; the trampoline route writes via `PyObject_SetAttrString`, not `STORE_NAME`.)

### Layer 3 — per-instruction **opcode CIPHER** → **NOT bypassed by running bytecode; SIDESTEPPED**
The eval loop does not dispatch on raw bytecode. True order = **raw byte → deobfuscate(position, key)
→ dispatch table → handler**, verified instruction-by-instruction (adversarial review,
`scratchpad/approach-review.md`):
- **Fetch** `0x100a3a774` (`ldrh w10,[x19],#2` — 16-bit instruction word).
- **Key** = `co+0x80` (the `co_zombieframe` slot; `ldr x8,[x16,#0x80]`, `x16` = the code object).
  XOR'd in 3× across the deobf.
- **Deobf** `0x100a3a774`–`0x100a3a7d4`: position-dependent — opcode × `mult1 = 2·(off>>6)+1` ×
  `mult2 = 4·i+1` (both odd), plus a byte-rotate `R` that is **non-identity even at i=0** — and
  key-dependent. Fully deobfuscated opcode at `0x100a3a7d4` (`eor w27,…`).
- **Table index** = deobfuscated value: `and x10,x27,#0xff` @ `0x100a3a858`.
- **Table** @ `0x1015a420e` (256 × uint16 LE); `handler = 0x100a3a578 + table[idx]*4` @
  `0x100a3a860`. 124 valid / 132 → the "unknown opcode" `SystemError` default handler `0x100a3f830`
  (the `"unknown opcode"` string ref site is `0x100a3f85c`). The 124/132 split is just the engine's
  internal opcode set — **not** evidence of a permutation.
- **Opargs are ciphered too:** `*0x89` accumulator (`0x100a3a824`, seed −1 @ `0x100a3a380`).
- **Consequence:** the same logical opcode needs a **different stored byte at every position**, so no
  static byte-substitution table can produce runnable bytecode (even index 0 is rotated by `R`). This
  is why injected standard-compiled bytecode → real `SystemError`.
- **`co_code` is not mangled by marshal** (loadonly readback: rebuilt `1/0` =
  `640064011b00010064025300`, consts intact) — the wall is purely the eval-loop cipher.
- **Status:** we can build AND invoke a reconstructed code object without crashing the game, but it
  does not execute correctly because of this cipher. **Bypassed by the chosen route** (native C-API
  orchestration runs no bytecode). Cipher-reverse is only a corrected fallback.

---

## Our approach — C-API "native trampoline" orchestration (CHOSEN)

Do the mods with **no injected bytecode at all**, so the opcode cipher never applies. Install native
wrappers on game methods and drive everything through the engine's own C-API by address:

- **Install a wrapper:** frida `NativeCallback` (our C) → `PyCFunction_NewEx` (wrap it as a Python
  callable with a `PyMethodDef` we allocate) → **self-bind** by calling the `instancemethod` TYPE
  object `PyInstanceMethod_Type` (`0x101a79c20`) with a 1-tuple `(callable,)` — the engine's fallback
  because `PyInstanceMethod_New` is inlined — → `PyObject_SetAttrString` onto the class. When the game
  calls `inst.method(...)`, dispatch enters OUR native code, which calls the original via
  `PyObject_Call` and controls the return.
- **Calling convention (confirmed):** a METH_VARARGS cfunc installed via instancemethod receives
  `args = (inst, *call_args)` with `self`/`m_self` = NULL; **return a NEW ref** (INCREF `None` for a
  pass-through).
- **Wrapper body** (call original → find the just-started interval via `getattr` /
  `activeIntervals` → `setPlayRate(factor)`) is a handful of `PyObject_GetAttr(String)` /
  `PyObject_Call` / `PyFloat_FromDouble` calls inside the `NativeCallback`.
- **Module readiness:** replace the payload's old `builtins.__import__` hook with a **frida-side
  `sys.modules` poll** (chain confirmed live, see reference tables) that applies each group once its
  module appears (battle/transition modules load lazily, only on first battle/transition).
- **Also consider** hooking Panda3D `CInterval::set_play_rate` natively (Panda C++ symbols are far
  less stripped) for a global rate scale — evaluated as an alternative; harder to target only the
  cosmetic intervals.

**Legacy eval path (superseded, still in `frida/inject.py`):** reconstruct code objects via
`PyCode_NewWithPosOnlyArgs` and run them with `PyEval_EvalCode` into `f_globals` (+48). Kept for
reference and diagnostics; blocked by layer 3, so not the shipping route.

**Source injection is NOT an option (verified dead 2026-09-04):** the compiler is genuinely
dead-stripped — no source→code path exists in the binary (see Dead ends).

---

## What's PROVEN / works

- **Trampoline mechanism — offline PASS** (`localtest/trampoline_test.py`): on stock arm64 3.8,
  `NativeCallback`→`PyCFunction_NewEx`→instancemethod-type-call self-bind→`setattr` on a class;
  `inst.method()` dispatched into native code **13354×**, called the original, controlled the return
  (`14`→`None`), process alive.
- **Manual PyFloat builder — offline PASS (milestone-2a)** (`localtest/pyfloat_test.py`): on stock
  arm64 3.8, built a float by raw memory both ways in the recipe — **free-list pop** (relink via the
  +8 slot, `numfree`--) and **pymalloc** — then round-tripped it via `ob_fval` @ +0x10, exported
  `PyFloat_AsDouble`, arithmetic (`PyNumber_Add` 2.0+2.0→4.0), and a real function call
  (`triple(2.0)`→6.0). The free-list head/`numfree` were located by disassembling the interpreter's
  own `PyFloat_FromDouble` (the offline analog of the game RE) and confirmed behaviorally (freeing a
  float made the discovered head point at it; the manual pop reused that exact slot). **Layout is
  IDENTICAL to the game** (`ob_type` +0x8, `ob_fval` +0x10, basicsize 0x18, head/`numfree` 8 apart);
  only the absolute addresses differ. Validates the recipe against the game's 3.8.17.
- **Wrap-after trampoline — offline PASS (milestone-2b)** (`localtest/wrapafter_test.py`): the native
  C-API port of `payload.py`'s `_make_wrap_after`/`_apply_after`, driven deterministically against
  plain-Python mocks. Proved: original called **exactly once**, its result **passed through**
  unchanged, `setPlayRate` called **once with the correct float factor** (5.0), the `iname_sub`
  activeIntervals path scaled **only** the substring-matching interval (others untouched), and on a
  **deliberately-missing interval attr** the wrapper returned cleanly with the tstate exception
  **set-then-CLEARED** (no leak) — the exact discipline `abortleak_test.py` enforces.
- **Live milestone-1 — PASS (2026-09-05):** installed a pass-through native trampoline on
  `GravityWalker.enableAvatarControls` (module `vlt24ab6c6d.vlt5e2c0e32.GravityWalker`, class
  `GravityWalker`) on the in-world toon; toggling a menu made the game call it → dispatched into our
  `NativeCallback` (**`fires=1`**) → wrapper called the original → game **survived** → reverted clean
  (`rc=0`). Full C-API-orchestration route proven live end-to-end; zero injected bytecode → all three
  walls bypassed.
- **Exception-clear fix — validated offline A/B + live** (`localtest/abortleak_test.py`): a failed
  injected C-API call (esp. `getattr`) leaves a pending exception on the tstate; detaching without
  clearing → the game inherits it → `SystemError: PyEval_EvalFrameEx returned a result with an error
  set` → panic/disconnect. No-clear branch → target DIES with that exact error; clear branch →
  survives.
- **frida attach WORKS** (`frida/ftest.py`): bare attach + no-op agent `ping`→`pong <base>`, clean
  detach, even on a frozen engine. Offsets verify on the live binary (prologue bytes match;
  `verified:true`).

---

## Dead ends (what does NOT work, and why)

- **`marshal_evalcode`** — layer 1 (`TYPE_CODE` disabled) → `marshal.loads` returns NULL for any code
  object.
- **exec into `f_builtins` (+40)** — read-only in this frozen+LTO build → `STORE_NAME` write-fault
  (a live hard-fault that Sentry swallowed → minidump). Use `f_globals` (+48).
- **Cipher-skip via the flag `0x101c0a9a0`** — it gates the line-tracing prologue (`0x100a3a394`,
  `cbz → 0x100a3a55c`), **not** dispatch; the dispatch fetch loads the key unconditionally.
- **Cipher-skip by patching deobf → identity** — the deobf/dispatch tail is **inlined ~70×** (no
  single patch site), and patching corrupts the game's own concurrently-running frames (which need
  the cipher for their pre-ciphered bytecode).
- **Static opcode-permutation map** — it's a **position + key cipher, not a permutation**; a
  position-independent `b[i]=s2e[b[i]]` cannot run at any position. `opcode_map.json` (which recovered
  the engine's internal opcode *renumbering* — the deobf target, not a stored-byte map) was renamed
  `opcode_map.json.WRONG-MODEL`; the translation pass is inert. (Kept, labeled, for the corrected
  cipher-reverse fallback.)
- **Source injection** — VERIFIED DEAD (`scratchpad/compiler-probe.md`): the tokenizer → parser →
  ast.c → symtable.c → compile.c pipeline is entirely stripped. `PyCode_NewWithPosOnlyArgs`
  (`0x10097d318`) has exactly 4 callers, all non-compilers (`code.__new__` `0x10097e46c`,
  `code.replace()` `0x10097e868`, marshal `r_object` `0x100a7493c`, and a stub `0x100a82170` that
  discards its source arg → an empty code object). compile.c / symtable.c / tokenizer.c contribute
  **zero** distinctive strings (no symtable pass ⇒ can't compile source even in principle). The
  `"Missing parentheses in call to 'print'/'exec'"` strings are a stranded `pythonrun.c` hint
  fragment; `"too many nested compilations"` is TCL, not CPython; `exec`/`eval` were edited to reject
  source (`"arg 1 must be a code object"`).
- **Running a reconstructed code object via `PyEval_EvalCode`** — can be built + invoked without
  crashing, but doesn't execute correctly (layer 3). Also required the right context to even survive:
  the `_PyEval_EvalFrameDefault` hook must run on the **MAIN thread** (a `PyGILState_Ensure` hook on a
  background Panda C-thread crashes on the minimal foreign tstate) and must `Interceptor.detachAll()`
  immediately before `EvalCode` (else the payload's own frame-evals re-enter the frida trampoline →
  deadlock/FREEZE); `onEnter` runs on the main thread so it must stay minimal (an unbounded
  `readUtf8String` of an exception message froze the game).
- **lldb / debugserver** — SIGSEGV on attach, TTR-specific (see The target).
- **3.7 marshal blob** — wrong version under the 3.8 engine → field-shift → "bad marshal data" or a
  wild-read native crash.
- **Retracted mid-session theory (do not resurrect):** that the tstate cell `0x101c0acd8` was wrong /
  the instability was a "corrupting clear." DISPROVEN from disasm — the cell and curexc offsets
  `+0x58/0x60/0x68` are **correct**, and the `SystemError` reads were real.

---

## Next steps — milestone-2 and beyond

0. **DONE (offline) — step 1:** (a) manual `PyFloat` build and (b) generic wrap-after trampoline are
   implemented as native C-API and PASS on stock 3.8 (`localtest/pyfloat_test.py`,
   `localtest/wrapafter_test.py`). (c) the first live target is wired as `TTRMOD_MODE=mod1`
   (`LocalToon.handleTunnelIn`/`Out`, attr `tunnelTrack`, ×5.0). See "What's PROVEN".
1. **mod1 LIVE — DONE (self-discovery + fire proven; speedup still blocked).** The signature scan +
   wrap-after fire on the real `LocalToon.tunnelOut` (`fires=1`, clean revert, no crash). The walk
   interval is NOT on `self` (see "The tunnel target, re-derived live"), so the tunnel speedup needs
   a **different interval hook** (Panda `CInterval::set_play_rate` / `Sequence` ctor scaling during
   the walk window, or the concrete Place builder method) — that is now the next real task for this
   group. The class-resolution problem is fully solved (signature scan).
2. **Then the remaining `setPlayRate` groups** from `inproc/payload.py`, each as a native wrap-after
   trampoline (the machinery is generic and validated): battle/faceoff/runin/teleport/book, plus the
   `transitions` (divide-`t`) scaler which is a **separate** native op (no interval discovery) still
   to build.
3. **`sys.modules` poll** for lazily-loaded battle/transition modules (replaces the `__import__`
   hook), applying each group as its module appears. (mod1's LocalToon is resident in-world, so it
   needs no poll; battle/transition modules will.)
4. **Then the full mod set**, then the **HUD** (`inproc/hud.py`; port the read-only street overlay to
   the live route). All wrapper targets (`Movie.play`, etc.) are normal-dispatch on their own classes
   → they will fire.
5. **Discipline:** ONE careful live run per change, after offline validation; keep live runs few
   (each crash risks a Sentry minidump).

---

## Reference tables — hard-won addresses & offsets

**All values are for arm64 UUID `4C4C44C3-5555-3144-A136-F2D2B4A39415`, image base `0x100000000`
(file offset = vmaddr − 0x100000000). Re-derive on every engine auto-patch.** Sources: `offsets.json`
(legacy eval path), `capi-symbols.json`/`.md` (pass 1), `capi-symbols2.json`/`.md` (pass 2 —
authoritative where it corrects pass 1).

### CPython C-API — located out-of-line (callable by address)

| symbol | vmaddr | notes |
|---|---|---|
| `PyObject_Call` | `0x10096a64c` | `(callable, args_tuple, kwargs)`; covers all calls |
| `PyObject_GetAttr` | `0x1009c56cc` | standalone; also inlined into GetAttrString |
| `PyObject_SetAttr` | `0x1009c5924` | |
| `PyObject_GetAttrString` | `0x1009c5578` | |
| `PyObject_SetAttrString` | `0x1009c5834` | install the trampoline on the class |
| `PyCFunction_NewEx` | `0x1009b9bdc` | `(PyMethodDef*, self, module)`; reads `ml_flags` @ ml+0x10, mask `0x8F` |
| `PyObject_GetItem` | `0x10096c1dc` | new ref; raises KeyError on miss (prefer `PyDict_GetItemString`) |
| `PyObject_GetIter` | `0x10096ef98` | |
| `PyIter_Next` | `0x10096f104` | new ref; NULL at end |
| `PyDict_GetItemString` | `0x10098e890` | **borrowed** ref, NULL if absent, clears lookup error = `sys.modules[name]` semantics |
| `PyDict_GetItem` | `0x10098da6c` | borrowed, no-raise-on-miss (getter under GetItemString) |
| `PyTuple_New` | `0x1009d6e68` | `(n)`; items at tuple+0x18+8*i (start NULL) |
| `PyTuple_SetItem` | `0x1009d7a38` | **steals** ref; only on a fresh tuple (refcount==1) |
| `PyTuple_GetItem` | `0x1009d79b0` | borrowed |
| `PyTuple_Size` | `0x1009d7954` | |
| `PyUnicode_AsUTF8` | `0x100a14074` | thin wrapper `mov x1,#0; b 0x100a07a38` |
| `PyUnicode_AsUTF8AndSize` | `0x100a07a38` | 2-arg `(str, size*)`; **pass-1 mislabeled this as AsUTF8** |
| `PyUnicode_FromStringAndSize` / `unicode_decode_utf8` | `0x1009ee48c` | `(char*, len, …)`; ~1273 callers |
| `PyUnicode_InternInPlace` | `0x100a11518` | |
| `PyNumber_Float` | `0x10096e65c` | normalize a number to a new float ref |
| `PyComplex_FromDoubles` | `0x10097f6ac` | |
| `_Py_HashDouble` | `0x100a1d6e8` | |
| `gc_new_allocator` (`_PyObject_GC_New/NewVar` family) | `0x10095d6f8` | |
| `PyArg_UnpackTuple` | `0x100a5078c` | |
| `Py_FatalError` | `0x100a2241c` | |
| `_PyErr_Format` | `0x100a47b10` | |
| `PyErr_SetString`-like `(obj_exc, const char*)` | `0x100a46b2c` | |
| `PyErr_ExceptionMatches`-like | `0x100a46bf4` | |
| raise-with-tstate (`_PyErr_SetObject`-ish) | `0x100a461d4` | |
| inline-BadInternalCall target (`fmt,file,line→raise`) | `0x100a46704` | |
| `PyBytes_FromString` | `0x100968af4` | single-char + empty-bytes caches |

### CPython C-API — INLINED (no standalone; use the recipe)

| symbol | equivalent / recipe |
|---|---|
| `PyInstanceMethod_New` | Call the TYPE: `PyObject_Call((PyObject*)PyInstanceMethod_Type 0x101a79c20, one_tuple(callable), NULL)`. `tp_new = 0x10097d094`, `tp_descr_get = 0x10097d078` (binds `self` on attr access); `im->func` @ +0x10, basicsize 0x18. |
| `PyFloat_FromDouble` | Build a 24-byte non-GC float: pop freelist head `0x101be9588` (decrement count `0x101be9590`) else pymalloc; set `ob_type = 0x101aae5c8` (PyFloat_Type), `ob_refcnt = 1`, `ob_fval`(double) @ +0x10. |
| `PyFloat_AsDouble` | If `ob_type == PyFloat_Type 0x101aae5c8` read double @ +0x10; else `PyNumber_Float 0x10096e65c` then read +0x10. |
| `PyErr_Occurred` | `t = *(void**)0x101c0acd8; occurred = t ? *(void**)(t+0x58) : NULL;` |
| `PyErr_Clear` | Zero `curexc_type/value/traceback` @ tstate `+0x58/+0x60/+0x68` (XDECREF the olds), or call `_PyErr_Restore(tstate,0,0,0)`. |
| `PyImport_GetModuleDict` | `sys.modules = *(*(*(void**)0x101c0acd8 + 0x10) + 0x38)` (see below). |
| `PyModule_GetDict`, `PyImport_AddModule`, `PyBytes_FromStringAndSize` | inlined away (per `offsets.json`); no standalone. |

### CPython C-API — not located (workaround exists)

| symbol | workaround |
|---|---|
| `PyObject_CallFunctionObjArgs` | build a tuple + `PyObject_Call` |
| `PyObject_CallMethodObjArgs` | `PyObject_GetAttr` then `PyObject_Call` |
| `PyTuple_Pack` | `PyTuple_New` + `PyTuple_SetItem` |
| `Py_BuildValue` | not located (would be the convenient single primitive for `"d"`/`"O"`/`"(OO)"`) |

### Type objects
`PyCFunction_Type 0x101a940b0`, `PyInstanceMethod_Type 0x101a79c20`, `PyFloat_Type 0x101aae5c8`
(flags byte `0x101aae671`), `PyTuple_Type 0x101aa7b30`, `PyUnicode_Type 0x101aa77c0`,
`PyLong_Type 0x101aade08`, `PyComplex_Type 0x101a858b8`, `PySeqIter_Type 0x101a7a100`.

### tstate / curexc / interp / sys.modules
- **Current-tstate cell** `_PyThreadState_Current` = `0x101c0acd8` (holds the current
  `PyThreadState*`). **VERIFIED CORRECT** in the eval-loop disasm (`adrp 0x101c0a000 + ldr #0xcd8`) —
  the earlier "suspect/wrong cell" note was retracted.
- **`PyThreadState`:** `interp` +0x10, `recursion_depth` +0x20, `frame` +24 (0x18),
  `curexc_type` **+0x58**, `curexc_value` **+0x60**, `curexc_traceback` **+0x68**.
- **`PyInterpreterState`:** `modules` +0x38 (= `sys.modules`).
- **`sys.modules` chain:** `*(*(*(void**)0x101c0acd8 + 0x10) + 0x38)` (tstate → interp+0x10 →
  modules+0x38). Confirmed live (importlib helper `sub_100019250`).

### The opcode cipher — dispatch details (layer 3)
Frame evaluator entry `_PyEval_EvalFrameDefault` `0x100a39f2c` (prologue `sub sp,sp,#0x160`, loads
tstate page `0x101c0a000`). Loop top `0x100a3a76c`. Fetch `0x100a3a774` (`ldrh w10,[x19],#2`). Key =
`co+0x80` (co_zombieframe; `ldr x8,[x16,#0x80]`). Deobf `0x100a3a774`–`0x100a3a7d4` (`mult1 =
2·(off>>6)+1` @ `0x100a3a794`; `mult2 = 4·i+1` @ `0x100a3a7b8`; result `eor w27` @ `0x100a3a7d4`).
Table index `and x10,x27,#0xff` @ `0x100a3a858`. Table `0x1015a420e` (256×u16 LE), `handler =
0x100a3a578 + table[idx]*4` @ `0x100a3a860`. Unknown-opcode `SystemError` default `0x100a3f830`
(string ref site `0x100a3f85c`). Oparg cipher `*0x89` accumulator `0x100a3a824` (seed −1
`0x100a3a380`). Tracing flag `0x101c0a9a0` (gates tracing prologue `0x100a3a394` → `0x100a3a55c`,
NOT dispatch).

### Legacy eval-path addresses (`offsets.json`; primitive superseded, addresses still valid)
| symbol | vmaddr | notes |
|---|---|---|
| `_PyEval_EvalFrameDefault` | `0x100a39f2c` | hook target; `args[0]` = PyFrameObject |
| `PyEval_EvalCode` | `0x100a38d44` | `(co, globals, locals)` |
| `PyCode_NewWithPosOnlyArgs` | `0x10097d318` | 16 args (6 int + `co_code`,`co_consts` in x0–x7; 8 on stack) |
| `PyByteArray_FromStringAndSize` | `0x1009791b4` | build the bytearray for `marshal.loads` |
| `marshal.loads` impl | `0x100a76a20` | `(module_ignored, bytes_like)`; TYPE_CODE disabled |
| `r_object` (marshal core) | `0x100a7493c` | jump table `0x1015a4af2`; TYPE_CODE → error `0x100a74b50` |
| `PyGILState_Ensure` / `Release` | `0x100a79e10` / `0x100a79f54` | not used by the trampoline route |
| `PyErr_PrintEx` | `0x100a7a2c8` | **AVOID** (prints/imports traceback; faults on a NULL/pending exc) |
| `code_new` (`code.__new__`) | `0x10097e46c` | one of the 4 PyCode_New callers |
| `code_replace` (`code.replace()`) | `0x10097e868` | |
| empty-code stub (discards source) | `0x100a82170` | |
| PyCode_New reconstruction field order | — | argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, co_code, co_consts, co_names, co_varnames, co_freevars, co_cellvars, co_filename, co_name, co_firstlineno, co_lnotab |

### Struct / object layouts
- **`PyMethodDef`:** `ml_name` +0x0, `ml_meth` +0x8, `ml_flags` +0x10 (METH_* mask `0x8F`; VARARGS =
  `0x1`), `ml_doc` +0x18.
- **`PyCFunctionObject`:** `m_ml` +0x10, `m_self` +0x18, `m_module` +0x20, `m_weakreflist` +0x28,
  `vectorcall` +0x30; `ob_type = PyCFunction_Type`.
- **`PyInstanceMethodObject`:** `func` +0x10 (basicsize 0x18).
- **`PyTypeObject`:** `tp_name` +0x18, `tp_getattr` +0x40, `tp_setattr` +0x48, `tp_as_number` +0x60
  (`nb_float` +0x90), `tp_as_sequence` +0x68 (`sq_item` +0x18), `tp_as_mapping` +0x70 (`mp_subscript`
  +0x8), `tp_hash` +0x78, `tp_call` +0x80, `tp_getattro` +0x90, `tp_setattro` +0x98, `tp_flags`
  +0xa8 (HAVE_VECTORCALL = byte @ +0xa9 bit3), subclass-flags byte @ **+0xab** (**TYPE_SUBCLASS
  bit7=0x80** — the `PyType_Check` test used by the signature scan; DICT bit5=0x20, LIST bit1, TUPLE
  bit2, UNICODE bit4, LONG bit0), `tp_iter` +0xd8, `tp_iternext` +0xe0, **`tp_dict` +0x108**,
  `tp_descr_get` +0x110, `tp_new` +0x138, **`tp_mro` +0x158** (a tuple; ob_size +0x10, items +0x18).
  All confirmed on stock 3.8 in `localtest/findcls_test.py` and live in the engine (findcls/findmeth
  scans returned correct classes). Layout is 3.8-ABI-stable, identical stock-vs-engine.
- **`PyTupleObject`:** `ob_size` +0x10, `ob_item[]` +0x18 (+24).
- **`PyLongObject`:** `ob_size` +0x10, `ob_digit` +0x18/+24 (30-bit digits).
- **`PyFloatObject`:** `ob_fval`(double) +0x10 (basicsize 0x18).
- **`PyDictObject`:** `ma_used` +0x10, `ma_version_tag` +0x18, `ma_keys` +0x20, `ma_values` +0x28;
  unicode cached hash at key +0x18.
- **`PyCodeObject`:** `co_zombieframe` (the cipher key slot) @ +0x80.

### Allocators & free-lists
- **pymalloc:** `((void*(*)(void*,size_t)) *(void**)0x101a7a668)(*(void**)0x101a7a660, size)`.
- **float free-list:** head `0x101be9588`, count(int32) `0x101be9590` (MAXFREELIST 100).
- **tuple free-list:** array base `0x101bec788`, count array `0x101bec738`.

---

## TTR structure & targeting gotchas

- **Vault module naming:** game Python loads under vault-namespaced names — `vlt24ab6c6d.*` =
  toontown, `vlt1609aac2.*` = direct/otp. Subpackages are sometimes readable (`hood`, `effects`,
  `speedchat`), often hashed; **method names are partly hashed too** (`Emote.doEmote` →
  `vlte6225981`; `GravityWalker`'s per-frame handler is a `vlt…`, only `enable`/`disableAvatarControls`
  / `enabled` are readable).
- **The local toon is NOT `base.localAvatar`.** Both `base.localAvatar` and the `localAvatar` global
  are absent even in-world (247 base attrs, none toon-typed) — it lives in the client-repo object
  table behind hashed names.
- **Pick fire targets carefully:** avoid FSM `enter`/`exit` (capture-bound — wrapping the class attr
  misses); avoid base-class methods (instances are subclasses → MRO shadows the class attr). Wrap
  **concrete instance classes** with **normal-dispatch** methods. The real mod targets (`Movie.play`,
  etc.) are normal-dispatch on their own classes → they fire. (`fires=0` demos on `SpeedChat.enter`,
  `Emote.isEnabled`, `Avatar.loop` were bad-target picks, not mechanism failures.)
- **Lazy modules:** battle/transition modules aren't loaded until first battle/transition → need the
  `sys.modules` poll to bind their patches when they appear.
- **Resolve classes by SIGNATURE, not name (the general fix).** Vault modules AND many class/method
  names are hashed (`vlt…`), so name lookups fail. The signature scan (findcls) is the robust
  primitive for ALL 7 mod groups: give it the readable methods a target class defines and it returns
  the (hashed) class object to wrap. When the methods themselves are hashed, the substring sweep
  (findmeth `TTRMOD_SUBSTR`) reveals the readable ones on the target class, and `findmeth
  TTRMOD_LISTCLS=<mod>::<cls>` dumps a hashed class's own method names to identify it.

### The tunnel target, re-derived live (2026-09-05) — the old target was WRONG

The `tunnel` group in `inproc/payload.py` (and the old mod1 wiring) assumed open-toontown names:
`LocalToon.handleTunnelIn`/`handleTunnelOut`, interval attr `tunnelTrack`. **None of that exists in
TTR.** Discovered empirically with findcls/findmeth (all read-only, in-world Toontown Central):

- **`handleTunnelIn`/`handleTunnelOut` DO NOT EXIST** — exact signature scans returned 0 (both, and
  each alone). A `TTRMOD_SUBSTR="unnel"` sweep found the REAL tunnel machinery instead.
- **LocalToon = hashed** module **`vlt24ab6c6d.vlt7892fa9a.vlt725d40df`**, class **`vlt725d40df`**
  (identified via a `findmeth TTRMOD_LISTCLS` dump: readable methods incl. `isLocal`,
  `enableAvatarControls`/`disableAvatarControls`, `neverDisable`, `setName`, `getZoneId`, plus a
  readable **`tunnelOut`**; ~179 own methods, the rest hashed `vlt…` incl. `tunnelIn`).
- **The tunnel walk = `LocalToon.tunnelOut`** (readable; `tunnelIn` is hashed away). It's a
  NORMAL-dispatch method (not FSM enter/exit) → wrapping the class attr fires. **`tunnelOut` alone
  is a unique signature** (exact scan count 1) → mod1 self-discovers LocalToon with
  `TTRMOD_METHODS="tunnelOut"`.
- **The Place FSM = hashed** module **`vlt24ab6c6d.hood.vlta74f0161`**, class **`vlta74f0161`** — the
  base Place with `enterWalk`/`enterDoorIn`/`enterTeleportIn`/`enterTunnelIn`/`enterTunnelOut`/
  `exitTunnelIn`/`exitTunnelOut` etc. These are ClassicFSM **capture-bound** enter/exit handlers →
  **bad wrap targets** (wrapping the class attr misses; the FSM captured the bound method at build).
- **LIVE PROOF (`TTRMOD_MODE=mod1 TTRMOD_METHODS="tunnelOut"`):** self-discovery resolved
  `vlt725d40df` by signature (`all_direct:true`), wrapped `tunnelOut` (`setattr_rc:0`); walking
  Mr. Beanwhip through a Punchline Place tunnel fired the wrapper (`fires=1`), the walk-through
  played, game survived, clean revert (`rc:0`). The native-trampoline + self-discovery route is fully
  proven on a real, self-found, hashed target.
- **BUT the speedup does NOT land — the walk interval is not on the toon.** The first-fire `__dict__`
  probe (right after `tunnelOut` returns) shows: `self.track` is **`NoneType`**; there is **no**
  `tunnelTrack`; **no** `activeIntervals` attr at all; and a scan of all 620 instance attrs by VALUE
  TYPE finds **no** `Interval`/`Sequence`/`Parallel`/`Lerp` (only two `CollisionHandlerPusher`s). So
  `tunnelOut`'s walk is a **fire-and-forget interval** (started without being stored on `self`, or
  built async / on the Place), which the wrap-after-then-`getattr(self, attr)` pattern cannot reach.
  `_apply_after` returned 0 (clean no-op) every run — hence no crash, but no speed change.
- **Exact NEXT STEP to actually speed the tunnel walk:** don't look on `self`. Options, in order:
  (1) hook Panda **`CInterval::set_play_rate`** / the `Sequence`/`Interval` **constructor** natively
  (Panda C++ symbols are far less stripped) and scale any interval created during the walk window;
  (2) wrap the Place's tunnel path instead (but its FSM enter/exit are capture-bound — would need to
  target the concrete builder method it calls, discoverable by another substring sweep like
  `"tunnel"`/`"walk"` on `vlta74f0161`); (3) if the interval is stored under a hashed attr set a
  frame or two later, poll `self.__dict__` for a newly-appearing `Interval`-typed value instead of a
  fixed attr. Whichever wins, the class resolution is already solved by the signature scan.

---

## Files & how to run

| path | role |
|---|---|
| `frida/trampoline_inject.py` | **the live C-API-orchestration injector** (current route). Modes (`TTRMOD_MODE`): `install` (pass-through, milestone-1) / `selftest` / `list` / `listcls` / **`findcls`** (classes defining ALL of `TTRMOD_METHODS`, by signature) / **`findmeth`** (N exact group scans via `;`-sep `TTRMOD_METHODS` + `TTRMOD_SUBSTR` method-name sweep + `TTRMOD_LISTCLS=<mod>::<cls>,…` dumps) / **`mod1`** (self-discovering wrap-after speedup). Env: `TTRMOD_METHODS` (signature), `TTRMOD_TMOD`/`TTRMOD_TCLS` (name-based override), `TTRMOD_ATTR` (interval attr), `TTRMOD_PROBE_ATTRS=1` (first-fire `__dict__` probe), `TTRMOD_POLL` (poll secs). Carries the manual-PyFloat builder, generic wrap-after (attr/iname_attr/iname_sub), and the shared read-only signature/substring scans. |
| `frida/inject.py` | legacy eval path (marshal.loads + `PyCode_NewWithPosOnlyArgs` + `PyEval_EvalCode`); diagnostic modes `--hello` (+`TTRMOD_HELLOSRC`), `TTRMOD_NOEVAL`, `TTRMOD_TESTOBJ`+`TTRMOD_TESTSRC`, `TTRMOD_LOADONLY`. `Process.setExceptionHandler`→`/tmp/ttrmod-crash.json`; hang → thread `sample()`→`/tmp/ttrmod-sample.json`; self-exits (no 120s hangs). |
| `frida/ftest.py` | proven bare-attach sanity check |
| `frida/diag.py` | attach diagnostics |
| `frida/run-injector.sh` | sudo wrapper (root attach) |
| `frida/ttr-frida-runner` + `.runner-env` | signed/entitled py3.13 + frida17 runner; `debugger.entitlements` |
| `inproc/payload.py` | the 7 `setPlayRate`-wrapper monkeypatch groups (battle/runin/teleport/tunnel/book/iris) — the logic being ported to native trampolines |
| `inproc/hud.py` | read-only street HUD (tasks, gags, street name); concatenated ahead of payload for the eval path |
| `localtest/rig.py` | offline busy-loop target (forces C→Python boundaries so the frame-eval hook fires) |
| `localtest/inject_local.py` | offline injector; resolves C-API host-side via `xcrun dyld_info -exports` |
| `localtest/recon_test.py` | offline reconstruction + EvalCode recipe validation (stock 3.8) |
| `localtest/trampoline_test.py` | **offline PROOF of the trampoline route** (PASS) |
| `localtest/pyfloat_test.py` | **offline PROOF of the manual PyFloat builder** (milestone-2a, PASS) — free-list + pymalloc branches, round-trip via `ob_fval`/`PyFloat_AsDouble`/arithmetic/function-call; free-list addrs discovered by disassembling `PyFloat_FromDouble` |
| `localtest/wrapafter_test.py` | **offline PROOF of the wrap-after trampoline** (milestone-2b, PASS) — orig-once + pass-through + `setPlayRate(factor)` + `iname_sub` selectivity + clean-miss-with-exception-cleared, against mocks |
| `localtest/findcls_test.py` | **offline PROOF of the signature/substring class scan** (PASS) — registers a real target class under a hashed-looking `sys.modules` key + decoys (one-method / none), inheritance/mixed cases, attr!=`__name__`, and a junk module (ints/funcs/str/bytes/module/list); asserts the scan finds EXACTLY the all-methods classes with correct direct-vs-inherited attribution, no false-positives, junk-safe; widen surfaces single-method decoys; substring scan (own-dict) matches by method-name substring; and the mod1 self-discover→wrap path (HIT setPlayRate(5.0) + MISS clean-tstate). Carries the scan helpers **verbatim** from `trampoline_inject.py`. |
| `localtest/abortleak_test.py` | offline A/B proving the exception-clear discipline |
| `lldb/attach.py` | dead lldb path (kept for reference; do not use) |
| `driver.py` | lldb-era host driver (legacy) |
| `ttrmod` | bash entrypoint (legacy `--probe`/apply/`--revert` wrapper) |
| `config.json` | groups (battle 3, runin 3, teleport 5, tunnel 5, book 100, iris 5) + `install_import_hook`; HUD block, off for first live test |
| `offsets.json` | per-build eval-path C-API vmaddrs, keyed by UUID (+ prologue `verify` bytes) |
| `capi-symbols.json` / `.md` | trampoline-route symbols, pass 1 |
| `capi-symbols2.json` / `.md` | trampoline-route symbols, pass 2 (authoritative corrections) |
| `opcode_map.json.WRONG-MODEL` | the disproven static opcode map (kept, labeled — cipher is position+key, not a permutation) |
| `README.md` | **STALE** — describes the abandoned CPython-3.7 / lldb / `marshal_evalcode` approach and old patch groups; superseded by this doc. |

### Driver scripts (`scripts/` — winctl window automation)

Reusable shell that drives the LIVE macOS client through the `winctl` CLI (out-of-process capture +
input, **no injection**) so an operator/agent can put the game in a known state without hand-clicking.
Pure bash; deps `winctl`, `magick` (ImageMagick), `tesseract`, `jq`, `awk` — all already on this box.

| script | usage | what it does |
|---|---|---|
| `scripts/tt-lib` | `source scripts/tt-lib` | shared helpers: engine/launcher pid + window resolution, screenshot, pixel probe, OCR, GO-press. The single place window/proc parsing lives. Not run directly. |
| `scripts/tt-state` | `scripts/tt-state [-v]` | prints ONE token: `launcher`\|`title`\|`connecting`\|`toonselect`\|`playground`\|`sleep`\|`disconnected`\|`dead`. `-v` adds reasoning on stderr. |
| `scripts/tt-to-playground` | `scripts/tt-to-playground` | from wherever we are, drive into the playground (reads `tt-state`, resumes from the right step). Exit 0 once `playground`; ends with a wake tap so the toon is AWAKE. `TT_TIMEOUT=<s>` overrides the 260s cap. |
| `scripts/tt-kill` | `scripts/tt-kill [--all]` | SIGTERM→SIGKILL the engine (`TTREngine`) only; `--all` also kills the launcher. |
| `scripts/tt-recover` | `scripts/tt-recover` | overnight crash/hang recovery: soft fix first (wake / dismiss / re-nav via `tt-to-playground`), then engine-kill + relaunch, then full cold start. |
| `scripts/tt-sample` | `scripts/tt-sample <interval_ms> <count> <outdir>` | burst-capture timestamped render frames (`frame_<elapsed_ms>.png`) for measuring animation/transition durations. |

**How `tt-state` classifies** (topology → nonblack → pixel probe → OCR; "rough but reliable"):
- `dead` no engine + no launcher · `launcher` launcher window/proc up, no engine render window ·
  `connecting` engine proc up but no render window yet, or a near-black/loading surface, or OCR says
  connecting/retrieving/loading/logging-in.
- With the render window up (title exactly `Toontown Rewritten`, ~720×478; ignore the junk
  1280×33 / 0×0 siblings): `disconnected` = centered pale-yellow modal + OCR `went to bed / sleepy /
  disconnect / connection lost / too many …`; `toonselect` = OCR `pick a toon / play this toon`;
  `title` = OCR `press any key / to enter`; `playground` = saturated laff-meter swatch in the
  top-left HUD corner; `sleep` = HUD present + a floating-`Z` OCR hit above the toon (best-effort).

**Engine vs launcher:** both report app name "Toontown Rewritten" to the window server, so the scripts
key off the COMMAND — engine = `…/TTREngine`, launcher = `…/Toontown Launcher` — never the app column.

> **CAVEAT — screen lock kills input.** A real password-lock (`CGSSessionScreenIsLocked=Yes`) makes
> WindowServer DROP all synthetic input, so every `winctl key/click/hold` is silently swallowed while
> `tt_shot`/OCR still work (backing-store read) — meaning `tt-state` stays correct but navigation
> can't progress. A screensaver (no lock) is fine. Panda3D DirectButtons (the went-to-bed OK, the
> toon-select slots) also need the game app briefly frontmost; the launcher GO is an AppKit AXButton
> (`--id _NS:222 --press`) and actuates in the background.

**Run (current route):** `sudo -n env TTRMOD_SCRIPT=… /Users/tanner/Developer/ttr-mods/frida/run-injector.sh`
(legacy eval path also `--hello|--probe|--apply|--revert`). Run as **root**; a TEMP grant lives at
`/etc/sudoers.d/ttrmod-frida` (NOPASSWD ALL — **remove when done:** `sudo rm
/etc/sudoers.d/ttrmod-frida`).

> **RULE (learned the hard way):** any injected C-API call that can fail — especially `getattr` — MUST
> clear the pending exception (curexc @ tstate `+0x58`/`+0x60`/`+0x68`) before the game resumes. A
> leaked `AttributeError` on detach → the game inherits it → `SystemError: PyEval_EvalFrameEx returned
> a result with an error set` → panic. Apply the same clear-on-every-abort-path discipline to the
> eval path AND the C-API paths.

## Fragility / re-deriving per build

Every address here is specific to this engine build; the tool's prologue `verify` bytes make it
**refuse** a changed binary. TTR auto-patches the engine → when the arm64 UUID changes, re-derive with
the `re` skill (IDA/Hopper) on the arm64 slice of `…/Contents/MacOS/TTREngine`. The 3.8 host
dependency is build-time only (marshalling for the legacy path). Re-deriving the frame-eval entry:
its ceval.c error strings (`"unknown opcode"` @ `0x100a3f85c`, `"referenced before assignment"`, `"no
locals when…"`) are unique to `_PyEval_EvalFrameDefault`. `lipo -thin arm64`, then full-disasm with
`llvm-objdump -d --arch=arm64 --no-show-raw-insn` (its `--start-address` is IGNORED on Mach-O —
disasm all, grep; strings are reached via `adrp`+`add`, not raw pointers). Find the adrp+add to
`"unknown opcode"` → walk back to the enclosing big-frame prologue (`sub sp,sp,#0x160`, loads tstate
page `0x101c0a000`) = entry `0x100a39f2c`. Cold error paths are LTO-outlined to separate funcs —
ignore; hook the entry.

---

## Appendix — cosmetics via content packs (separate track, safe + solved)

_Not part of the injection tool; captured here so the finding isn't lost when the memory was slimmed.
TTR supports **cosmetic** overrides (music, textures, audio, fonts, cursor) with **no injection** and
no ban risk._

- **Content-pack system:** drop files into `resources/<PackName>/` mirroring the phase tree; the VFS
  mounts `resources/` ahead of the base phase files. `settings.json` has `content-pack-order` /
  `content-packs-disabled`. Content packs can override **textures/audio/fonts/cursor — NOT models or
  NPC dialogue**.
- **Menu music:** `phase_3.mf → phase_3/audio/bgm/ttr_theme.ogg` (Ogg Vorbis 44.1k stereo 128k,
  ~84s) plus seasonal siblings `ttr_theme_{winter,halloween,toonfest,aprilfools,oilspill}.ogg` —
  replace all to be date-proof. Encode:
  `ffmpeg -i in -c:a libvorbis -ar 44100 -ac 2 -b:a 128k ttr_theme.ogg`.
- **Textures:** small 128–256px `.jpg` plus a separate `name_a.rgb` alpha map (upscale both); replace
  at the same internal path.
- **Do NOT edit `phase_*.mf` in place:** they're signed (ToonSec Root CA) and the launcher checksums
  them vs a server manifest → modified phase files get re-downloaded/reverted. Assets are standard
  Panda3D multifiles (`multify` from `pip install panda3d`).
