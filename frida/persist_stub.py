"""Persistent method stubs: a wrapper's entry point that outlives the frida agent.

THE PROBLEM. Every mod is installed as a Python method whose machine code (a frida NativeCallback)
and method definition live in the AGENT's memory. Revert puts the original methods back on their
classes, but that does not reach:

  * a call already IN FLIGHT -- the game's main thread inside a wrapped MetaInterval.start when the
    session detaches returns into agent code that is being torn down;
  * a LINGERING REFERENCE -- anything that captured the wrapped method earlier (a `Func(ival.start)`
    in a Sequence, an event handler) keeps calling the wrapper after the agent is gone.

Either way the game ends up executing freed agent memory: a crash, or a freeze if it lands on a
lock that no longer has an owner. Quitting the mods "sometimes froze the game" -- this is the
mechanism that fits.

THE STUB. A 4 KB page from VirtualAlloc -- the game's own address space, never freed, so it survives
the agent -- holding the method definition, the original function, PyObject_Call's address, and
six instructions:

        mov  rax, [slot]        ; where calls go while the mods are live
        test rax, rax
        jz   bypass
        jmp  rax                ; live: tail-jump into the agent's callback, same arguments
    bypass:
        mov  rcx, [orig]        ; reverted: PyObject_Call(orig, args, kwargs) -- the call the
        jmp  [PyObject_Call]    ;   wrapper itself would have made, minus the mod

The method is METH_VARARGS|METH_KEYWORDS, i.e. called as f(self, args, kwargs) in rcx/rdx/r8, so
the bypass only has to swap rcx for the original and tail-call. Only jumps, no stack use: the
return address on the stack is the caller's, which keeps CET shadow stacks (enforced on this
client -- a mismatched return is a fail-fast) and unwinding untouched.

Revert zeroes the slot (one aligned 8-byte store) BEFORE restoring the originals, so from then on
nothing enters the agent through any path; the host then waits for in-flight calls to drain before
detaching. Windows x64 only -- elsewhere the wrapper falls back to the plain agent-memory method.

Validated offline by localtest/persiststub_test.py against a throwaway CPython process.
"""

STUB_JS = r"""
// Build a persistent stub for NativeCallback `cb` wrapping Python callable `orig`. Returns
// {page, slot, mdef} -- pass mdef to PyCFunction_NewEx -- or null when unavailable (not Windows x64,
// or VirtualAlloc failed), in which case the caller keeps the agent-memory method definition.
function ttrmodMakeStub(valloc, cb, orig, pyCall, label) {
  if (!valloc || Process.platform !== 'windows' || Process.arch !== 'x64') return null;
  var page = valloc(ptr(0), 4096, 0x3000, 0x40);      // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
  if (page.isNull()) return null;
  page.writePointer(cb);                              // +0x00 slot: the agent's callback while live
  page.add(0x08).writePointer(orig);                  // +0x08 the original Python function
  page.add(0x10).writePointer(pyCall);                // +0x10 PyObject_Call
  var mdef = page.add(0x18);                          // +0x18 PyMethodDef (32 bytes)
  var name = page.add(0x38);                          // +0x38 method name (<= 23 chars + NUL)
  var code = page.add(0x50);                          // +0x50 code
  name.writeUtf8String(String(label || 'ttrmod').slice(0, 23));
  mdef.writePointer(name);
  mdef.add(8).writePointer(code);
  mdef.add(16).writeU32(0x3);                         // METH_VARARGS | METH_KEYWORDS
  mdef.add(20).writeU32(0);
  mdef.add(24).writePointer(ptr(0));
  code.writeByteArray([
    0x48, 0x8B, 0x05, 0xA9, 0xFF, 0xFF, 0xFF,         // 50: mov rax, [rip-0x57]   ; slot
    0x48, 0x85, 0xC0,                                 // 57: test rax, rax
    0x74, 0x02,                                       // 5A: jz 5E
    0xFF, 0xE0,                                       // 5C: jmp rax
    0x48, 0x8B, 0x0D, 0xA3, 0xFF, 0xFF, 0xFF,         // 5E: mov rcx, [rip-0x5D]   ; orig
    0xFF, 0x25, 0xA5, 0xFF, 0xFF, 0xFF,               // 65: jmp [rip-0x5B]        ; PyObject_Call
    0xCC                                              // 6B: int3
  ]);
  return { page: page, slot: page, mdef: mdef };
}
// Send every future call straight to the original. One aligned pointer store: atomic on x64.
function ttrmodBypassStub(stub) {
  stub.slot.writePointer(ptr(0));
}
// VirtualAlloc, or null off Windows.
function ttrmodVirtualAlloc() {
  try {
    if (Process.platform !== 'windows') return null;
    var k32 = Process.getModuleByName('kernel32.dll');
    return new NativeFunction(k32.getExportByName('VirtualAlloc'), 'pointer',
                              ['pointer', 'size_t', 'uint32', 'uint32']);
  } catch (e) { return null; }
}
"""
