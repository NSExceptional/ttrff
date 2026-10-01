#!/usr/bin/env python3
# localtest/persiststub_test.py -- OFFLINE validation of the persistent method stub (Windows x64).
#
# THE BUG THIS GUARDS. Quitting the mods sometimes froze the game. Each mod is a Python method whose
# code and method definition live in the frida agent; revert restores the originals on their
# classes, but a call in flight at detach, or a reference captured earlier (a Func(ival.start) in a
# Sequence), still enters the wrapper after the agent is gone -- executing freed memory. The stub
# (frida/persist_stub.py) moves the method's entry point into memory that outlives the agent and,
# once reverted, sends every call straight to the original.
#
# WHAT THIS PROVES, against a throwaway CPython we own (same x64 calling convention as the engine):
#   1. a wrapper installed through the stub dispatches into the agent and calls the original
#      (result unchanged, fires counted, in-flight count returns to 0);
#   2. a bound method captured WHILE WRAPPED keeps working after revert AND after the agent is
#      detached and unloaded -- the case that used to execute freed memory;
#   3. the class method is the original again after revert;
#   4. the target survives the whole sequence, with no wrong result on either path.
# With --control it also runs the same sequence WITHOUT the stub, which is expected to kill the
# target once the captured reference is called after detach -- showing the test can tell the two
# apart.
#
#   run:  python localtest/persiststub_test.py [--control]      (Windows, x64 CPython, frida)

import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "frida"))
import persist_stub  # noqa: E402

TARGET = r'''
import os, sys, time
FLAG = sys.argv[1]
class Ival(object):
    calls = 0
    def start(self, x):
        Ival.calls += 1
        return x * 2
LINGER = []
print("[target] pid=%d" % os.getpid(), flush=True)
i = bad = linger_ok = 0
while True:
    i += 1
    if Ival().start(i) != 2 * i:
        bad += 1
    if not LINGER and os.path.exists(FLAG):
        LINGER.append(Ival().start)       # captured while the wrapper is installed
    if LINGER:
        if LINGER[0](i) == 2 * i:
            linger_ok += 1
        else:
            bad += 1
    if i % 50 == 0:
        print("[target] i=%d bad=%d linger_ok=%d" % (i, bad, linger_ok), flush=True)
    time.sleep(0.002)
'''

HARNESS_JS = persist_stub.STUB_JS + r'''
var S = null;
rpc.exports = {
  install: function (useStub) {
    var py = null;
    Process.enumerateModules().forEach(function (m) { if (/^python3\d+\.dll$/i.test(m.name)) py = m; });
    if (!py) return { err: 'no python3x.dll' };
    function f(n, r, a) { return new NativeFunction(py.getExportByName(n), r, a); }
    S = { fires: 0, inflight: 0, keep: [], useStub: !!useStub };
    S.Call = f('PyObject_Call', 'pointer', ['pointer', 'pointer', 'pointer']);
    S.GetAttr = f('PyObject_GetAttrString', 'pointer', ['pointer', 'pointer']);
    S.SetAttr = f('PyObject_SetAttrString', 'int', ['pointer', 'pointer', 'pointer']);
    S.CFunc = f('PyCFunction_NewEx', 'pointer', ['pointer', 'pointer', 'pointer']);
    S.TupleNew = f('PyTuple_New', 'pointer', ['long']);
    S.TupleSet = f('PyTuple_SetItem', 'int', ['pointer', 'long', 'pointer']);
    S.AddModule = f('PyImport_AddModule', 'pointer', ['pointer']);
    S.Ensure = f('PyGILState_Ensure', 'int', []);
    S.Release = f('PyGILState_Release', 'void', ['int']);
    S.imType = py.getExportByName('PyInstanceMethod_Type');
    S.pyCall = py.getExportByName('PyObject_Call');
    var g = S.Ensure();
    try {
      var main = S.AddModule(Memory.allocUtf8String('__main__'));
      S.cls = S.GetAttr(main, Memory.allocUtf8String('Ival'));
      S.mn = Memory.allocUtf8String('start');
      S.orig = S.GetAttr(S.cls, S.mn);
      var cb = new NativeCallback(function (self, args, kwargs) {
        S.inflight++;
        try { S.fires++; return S.Call(S.orig, args, kwargs); }
        finally { S.inflight--; }
      }, 'pointer', ['pointer', 'pointer', 'pointer']);
      S.keep.push(cb);
      var mdef;
      S.stub = S.useStub ? ttrmodMakeStub(ttrmodVirtualAlloc(), cb, S.orig, S.pyCall, 'ttrmod_test') : null;
      if (S.useStub && !S.stub) return { err: 'stub unavailable' };
      if (S.stub) mdef = S.stub.mdef;
      else {
        var nm = Memory.allocUtf8String('ttrmod_test'); S.keep.push(nm);
        mdef = Memory.alloc(32); S.keep.push(mdef);
        mdef.writePointer(nm); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(3); mdef.add(24).writePointer(ptr(0));
      }
      var cfunc = S.CFunc(mdef, ptr(0), ptr(0));
      var t = S.TupleNew(1); S.TupleSet(t, 0, cfunc);
      var im = S.Call(S.imType, t, ptr(0));
      var rc = S.SetAttr(S.cls, S.mn, im);
      return { rc: rc, stub: S.stub ? S.stub.page.toString() : null };
    } finally { S.Release(g); }
  },
  revert: function () {
    var g = S.Ensure();
    try {
      if (S.stub) ttrmodBypassStub(S.stub);
      return { rc: S.SetAttr(S.cls, S.mn, S.orig) };
    } finally { S.Release(g); }
  },
  stats: function () { return { fires: S ? S.fires : -1, inflight: S ? S.inflight : -1 }; }
};
'''


class Target(object):
    def __init__(self):
        self.flag = os.path.join(tempfile.mkdtemp(prefix="ttrmod-stub-"), "capture")
        src = os.path.join(os.path.dirname(self.flag), "target.py")
        open(src, "w").write(TARGET)
        self.p = subprocess.Popen([sys.executable, "-u", src, self.flag],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines = []
        line = self.p.stdout.readline()
        self.pid = int(line.split("pid=")[1])
        import threading
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.append(line.strip())

    def last(self):
        for line in reversed(self.lines):
            if line.startswith("[target] i="):
                return dict(kv.split("=") for kv in line.split()[1:])
        return None

    def alive(self):
        return self.p.poll() is None

    def kill(self):
        if self.alive():
            self.p.kill()


def run(use_stub):
    import frida
    label = "stub" if use_stub else "control (no stub)"
    t = Target()
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, ("  -- " + detail) if detail else ""))

    try:
        session = frida.get_local_device().attach(t.pid)
        script = session.create_script(HARNESS_JS)
        script.load()
        ex = script.exports_sync
        r = ex.install(use_stub)
        check("%s: wrapper installed" % label, r.get("rc") == 0, str(r))
        time.sleep(0.5)
        open(t.flag, "w").close()                      # target captures the wrapped bound method
        time.sleep(0.5)
        st = ex.stats()
        check("%s: calls go through the agent while live" % label, st["fires"] > 50, str(st))
        r = ex.revert()
        check("%s: reverted" % label, r.get("rc") == 0, str(r))
        time.sleep(0.3)
        st = ex.stats()
        check("%s: nothing in flight after revert" % label, st["inflight"] == 0, str(st))
        fires_at_revert = st["fires"]
        time.sleep(0.3)
        st = ex.stats()
        if use_stub:
            check("stub: captured reference no longer enters the agent once reverted",
                  st["fires"] == fires_at_revert, "fires %d -> %d" % (fires_at_revert, st["fires"]))
        script.unload()
        session.detach()
        before = t.last() or {}
        time.sleep(2.0)
        after = t.last() or {}
        survived = t.alive()
        if use_stub:
            check("stub: target survives the detach", survived)
            check("stub: captured reference still answers after detach",
                  int(after.get("linger_ok", 0)) > int(before.get("linger_ok", 0)) > 0,
                  "linger_ok %s -> %s" % (before.get("linger_ok"), after.get("linger_ok")))
            check("stub: no wrong result on either path", after.get("bad") == "0", str(after))
        else:
            print("  [info] control: target %s after detach (last: %s)"
                  % ("SURVIVED" if survived else "DIED", after))
            checks.append(True)
    finally:
        t.kill()
    return all(checks)


def main():
    if not (sys.platform.startswith("win") and sys.maxsize > 2 ** 32):
        print("[persiststub] SKIP: needs Windows x64")
        return 0
    ok = run(True)
    if "--control" in sys.argv:
        run(False)
    print("[persiststub] VERDICT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
