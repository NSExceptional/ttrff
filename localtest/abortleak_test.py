#!/usr/bin/env python3
# localtest/abortleak_test.py -- OFFLINE validation of the exception-clear fix.
#
# The live crash was (plausibly) caused by a failed PyObject_GetAttrString leaving a pending
# AttributeError on the thread-state that we detached without clearing -> the game inherited it.
# The fix: clear curexc (tstate +0x58/+0x60/+0x68) on every abort/exit path.
#
# This reproduces the exact hazard on a stock arm64 CPython 3.8 we spawn, and proves the clear
# works: inside a frame-eval hook we getattr a MISSING attribute (sets AttributeError), confirm
# PyErr_Occurred() is set, apply the clear, confirm PyErr_Occurred() is now NULL, and confirm the
# target process keeps running (a leaked exception would have taken it down).
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/abortleak_test.py frida/run-injector.sh

import sys, os, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")
NOCLEAR = bool(os.environ.get("TTRMOD_NOCLEAR"))   # A/B: skip the clear to show the exc persists

SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyImport_AddModule":        "_PyImport_AddModule",
    "PyErr_Occurred":            "_PyErr_Occurred",
    "_PyThreadState_UncheckedGet": "__PyThreadState_UncheckedGet",
}


def framework_dylib(target_py):
    code = ("import sysconfig, os\n"
            "v = sysconfig.get_config_var\n"
            "print(os.path.join(v('PYTHONFRAMEWORKPREFIX'), v('PYTHONFRAMEWORK')+'.framework',\n"
            "                   'Versions', v('VERSION'), v('PYTHONFRAMEWORK')))\n")
    p = subprocess.run([target_py, "-c", code], capture_output=True, text=True)
    path = p.stdout.strip()
    if not path or not os.path.exists(path):
        raise SystemExit("no framework dylib for %s: %r\n%s" % (target_py, path, p.stderr))
    return os.path.realpath(path)


def resolve_offsets(dylib):
    out = subprocess.run(["xcrun", "dyld_info", "-exports", dylib], capture_output=True, text=True).stdout
    want = {v: k for k, v in SYMS.items()}
    offs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("0x") and parts[1] in want:
            offs[want[parts[1]]] = int(parts[0], 16)
    missing = [k for k in SYMS if k not in offs]
    if missing:
        raise SystemExit("missing exports: %s" % missing)
    return offs


AGENT = r"""
'use strict';
var ST = null;
rpc.exports = {
  init: function (p) {
    var out = { ok:false, notes:[], resolved:{} };
    try {
      var mods = Process.enumerateModules(), m = null;
      for (var i=0;i<mods.length;i++){ if (mods[i].path === p.module_path){ m = mods[i]; break; } }
      if (!m){ for (var j=0;j<mods.length;j++){ if (/Python\.framework|\/Python$|libpython/i.test(mods[j].path)){ m=mods[j]; break; } } }
      if (!m){ out.notes.push('python module not found'); return out; }
      var base = m.base;
      function at(n){ var a = base.add(ptr(p.offsets[n])); out.resolved[n]=a.toString(); return a; }
      ST = {
        noclear: p.noclear, done:false,
        frame_eval: at('_PyEval_EvalFrameDefault'),
        GetAttrStr: new NativeFunction(at('PyObject_GetAttrString'), 'pointer', ['pointer','pointer']),
        AddModule:  new NativeFunction(at('PyImport_AddModule'), 'pointer', ['pointer']),
        Occurred:   new NativeFunction(at('PyErr_Occurred'), 'pointer', []),
        TState:     new NativeFunction(at('_PyThreadState_UncheckedGet'), 'pointer', []),
      };
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },
  arm: function () {
    ST.listener = Interceptor.attach(ST.frame_eval, {
      onEnter: function () {
        if (ST.done) return; ST.done = true;
        try {
          var mod = ST.AddModule(Memory.allocUtf8String('__main__'));    // borrowed, valid object
          // FAILING getattr on a missing attr -> returns NULL AND sets AttributeError on the tstate
          var bad = ST.GetAttrStr(mod, Memory.allocUtf8String('__ttrmod_missing_attr__'));
          var occ1 = ST.Occurred();                                      // should be NON-null now
          var cleared = 'skipped';
          if (!ST.noclear) {
            var t = ST.TState();                                         // the fix: zero curexc @ +0x58/60/68
            if (!t.isNull()){ t.add(0x58).writePointer(ptr(0)); t.add(0x60).writePointer(ptr(0)); t.add(0x68).writePointer(ptr(0)); }
            cleared = 'applied';
          }
          var occ2 = ST.Occurred();                                      // after clear: should be NULL
          try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
          send({t:'done', r:{ getattr_returned_null: bad.isNull(),
                              exc_set_before_clear: !occ1.isNull(),
                              clear: cleared,
                              exc_after: occ2.isNull() ? 'CLEARED' : 'STILL-SET' }});
        } catch(e){ send({t:'done', r:{err:String(e)}}); }
      }
    });
    return { ok:true };
  }
};
"""


def main():
    import frida
    dylib = framework_dylib(TARGET_PY)
    offsets = resolve_offsets(dylib)
    loop = ("import time\n"
            "t=time.time()\n"
            "while time.time()-t < 20:\n"
            "    s = sum(i*i for i in range(300))\n")
    tgt = subprocess.Popen([TARGET_PY, "-c", loop]); time.sleep(0.4)
    print("[abortleak] target_py=%s pid=%d noclear=%s" % (TARGET_PY, tgt.pid, NOCLEAR))

    done = threading.Event(); box = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            pl = m.get("payload") or {}
            if pl.get("t") == "done": box["r"] = pl.get("r"); done.set()
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()

    try:
        session = frida.attach(tgt.pid)
    except Exception as e:
        tgt.kill(); raise SystemExit("attach failed (arm64 target required): %s" % e)
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib,
                    "noclear": NOCLEAR})
    if not init.get("ok"):
        print("[abortleak] init failed:", json.dumps(init)); tgt.kill(); return
    ex.arm()
    done.wait(10.0)
    print("[abortleak] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(2.0)   # let the target keep running: a leaked exc would surface/crash here
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = (not NOCLEAR and r.get("exc_set_before_clear") and r.get("exc_after") == "CLEARED" and alive)
    print("[abortleak] target_alive_after=%s" % alive)
    print("[abortleak] VERDICT: %s" % ("PASS -- failed getattr set an exception; our clear emptied it; target survived"
                                       if verdict else ("(noclear A/B run)" if NOCLEAR else "FAIL -- see result")))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
