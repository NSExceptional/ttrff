#!/usr/bin/env python3
# localtest/inject_local.py -- OFFLINE mechanism test on a local arm64 CPython we own.
# Answers the exact question that hard-crashed TTREngine: can we run a marshalled code
# object via PyEval_EvalCode from INSIDE a frida Interceptor callback (on the target's
# own thread, GIL held) without crashing?
#
#   modes:
#     hello  -- tiny code object (writes a file). Does eval-in-hook work at all?
#     storm  -- code object doing ~200k reentrant frame-evals INSIDE the hook. Tests the
#               "callback storm / reentrancy" hypothesis for the frame-eval crash.
#
#   run (target pid required):
#     TTRMOD_SCRIPT=localtest/inject_local.py frida/run-injector.sh <mode> <pid>
#
# Resolves the C-API by reading the target framework dylib's export trie HOST-SIDE
# (`dyld_info -exports`), then hands the agent module-relative offsets -- same offset+
# slide model as the real TTREngine injector, avoiding frida's in-agent symbol API
# (which came back empty on this build). Globals come from PyEval_GetGlobals() (no
# struct offsets); the blob is marshalled with the target's own interpreter.

import sys
import os
import time
import json
import threading
import subprocess

HELLO_FILE = "/tmp/ttrmod-local-hello"

# C name -> exact Mach-O trie symbol (leading-underscore convention)
SYMS = {
    "PyEval_EvalCode": "_PyEval_EvalCode",
    "PyEval_GetGlobals": "_PyEval_GetGlobals",
    "PyMarshal_ReadObjectFromString": "_PyMarshal_ReadObjectFromString",
    "PyErr_PrintEx": "_PyErr_PrintEx",
    "_PyEval_EvalFrameDefault": "__PyEval_EvalFrameDefault",
}

MODE = "hello"
PID = None
for a in sys.argv[1:]:
    if a in ("hello", "storm"):
        MODE = a
    elif a.isdigit():
        PID = int(a)


def framework_dylib(target_py):
    code = ("import sysconfig, os\n"
            "v = sysconfig.get_config_var\n"
            "print(os.path.join(v('PYTHONFRAMEWORKPREFIX'), v('PYTHONFRAMEWORK')+'.framework',\n"
            "                   'Versions', v('VERSION'), v('PYTHONFRAMEWORK')))\n")
    p = subprocess.run([target_py, "-c", code], capture_output=True, text=True)
    path = p.stdout.strip()
    if not path or not os.path.exists(path):
        raise SystemExit("could not locate framework dylib for %s (got %r)" % (target_py, path))
    return path


def resolve_offsets(dylib):
    out = subprocess.run(["xcrun", "dyld_info", "-exports", dylib],
                         capture_output=True, text=True).stdout
    want = {v: k for k, v in SYMS.items()}   # trie symbol -> C name
    offs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("0x") and parts[1] in want:
            offs[want[parts[1]]] = int(parts[0], 16)
    missing = [k for k in SYMS if k not in offs]
    if missing:
        raise SystemExit("missing exports in %s: %s" % (dylib, missing))
    return offs


def marshal_with(target_py, src):
    helper = ("import sys, marshal\n"
              "src = sys.stdin.buffer.read().decode('utf-8')\n"
              "sys.stdout.buffer.write(marshal.dumps(compile(src, 'ttrmod-local', 'exec')))\n")
    p = subprocess.run([target_py, "-c", helper], input=src.encode("utf-8"), capture_output=True)
    if p.returncode != 0 or not p.stdout:
        raise SystemExit("marshal failed: " + p.stderr.decode("utf-8", "replace"))
    return p.stdout


AGENT = r"""
'use strict';
var ST = null;
rpc.exports = {
  init: function (p) {
    var out = { ok:false, notes:[], module:null, resolved:{} };
    try {
      // find the target's python framework dylib module by path
      var mods = Process.enumerateModules();
      var m = null;
      for (var i=0;i<mods.length;i++){ if (mods[i].path === p.module_path){ m = mods[i]; break; } }
      if (!m){ for (var j=0;j<mods.length;j++){ if (/Python\.framework|\/Python$|libpython/i.test(mods[j].path)){ m = mods[j]; break; } } }
      if (!m){ out.notes.push('python module not found');
               out.sample_mods = mods.slice(0,60).map(function(x){return x.path;}); return out; }
      out.module = m.path; var base = m.base; out.base = base.toString();
      function at(name){ var a = base.add(ptr(p.offsets[name])); out.resolved[name]=a.toString(); return a; }

      var buf = Memory.alloc(p.blob.length); buf.writeByteArray(p.blob);
      ST = {
        buf: buf, blen: p.blob.length,
        globals_mode: p.globals_mode, frame_arg: p.frame_arg, fg_off: p.f_globals_off,
        ReadObj:    new NativeFunction(at('PyMarshal_ReadObjectFromString'), 'pointer', ['pointer','long']),
        GetGlobals: new NativeFunction(at('PyEval_GetGlobals'),              'pointer', []),
        EvalCode:   new NativeFunction(at('PyEval_EvalCode'),                'pointer', ['pointer','pointer','pointer']),
        PrintEx:    new NativeFunction(at('PyErr_PrintEx'),                  'void',    ['int']),
        frame_eval: at('_PyEval_EvalFrameDefault')
      };
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },
  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function (args) {
          if (ST.done) return;
          var gd;
          try {
            if (ST.globals_mode === 'frame') {
              var f = args[ST.frame_arg];        // 3.7: _PyEval_EvalFrameDefault(f, throwflag)
              if (f.isNull()) return;
              gd = f.add(ST.fg_off).readPointer(); // f->f_globals  (the TTREngine read path)
            } else {
              gd = ST.GetGlobals();
            }
          } catch(e){ return; }
          if (gd.isNull()) return;
          ST.done = true;
          try {
            send({t:'stage', s:'got_globals', mode:ST.globals_mode, gd:gd.toString(), gd_type:gd.add(8).readPointer().toString()});
            var co = ST.ReadObj(ST.buf, ST.blen);
            if (co.isNull()){ send({t:'done', r:{ok:false, stage:'PyMarshal_ReadObjectFromString NULL'}}); return; }
            send({t:'stage', s:'co_ok', co:co.toString(), co_type:co.add(8).readPointer().toString()});
            var res = ST.EvalCode(co, gd, gd);
            if (res.isNull()) ST.PrintEx(1);
            send({t:'done', r:{ok:!res.isNull(), stage:'done', res:res.toString()}});
          } catch(e){ send({t:'done', r:{ok:false, stage:'eval ex', err:String(e)}}); }
        }
      });
      return { ok:true };
    } catch(e){ return { ok:false, notes:['arm ex: '+e] }; }
  },
  disarm: function () { try { if(ST && ST.listener){ ST.listener.detach(); ST.listener=null; } } catch(e){} }
};
"""


def main():
    import frida
    if not PID:
        raise SystemExit("usage: inject_local.py <hello|storm> <pid>")
    target_py = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.14")
    dylib = framework_dylib(target_py)
    offsets = resolve_offsets(dylib)
    dylib = os.path.realpath(dylib)          # match the runtime (Cellar) path frida reports
    if MODE == "storm":
        # sum(map(pyfunc,...)) forces 200k C->Python boundaries, each RE-ENTERING our
        # hooked _PyEval_EvalFrameDefault (done-guarded) -- reproduces the 3.7 "every
        # call re-enters the hook" storm that a plain (inline) loop would not on 3.11+.
        src = ("def leaf(i):\n"
               "    return i * i\n"
               "x = sum(map(leaf, range(200000)))\n"
               "open(%r, 'w').write('storm ' + str(x))\n") % HELLO_FILE
    else:
        src = "open(%r, 'w').write('hello')\n" % HELLO_FILE
    blob = marshal_with(target_py, src)
    try:
        if os.path.exists(HELLO_FILE):
            os.remove(HELLO_FILE)
    except Exception:
        pass
    print("[local] mode=%s pid=%d blob=%dB dylib=%s" % (MODE, PID, len(blob), dylib))
    print("[local] offsets:", {k: hex(v) for k, v in offsets.items()})

    done = threading.Event(); box = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            p = m.get("payload") or {}
            if p.get("t") == "done": box["r"] = p.get("r"); done.set()
            elif p.get("t") == "stage": print("[stage]", json.dumps(p)); sys.stdout.flush()
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()

    session = frida.attach(PID); session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"blob": list(blob), "offsets": {k: hex(v) for k, v in offsets.items()},
                    "module_path": dylib,
                    "globals_mode": os.environ.get("TTRMOD_GLOBALS", "getglobals"),
                    "frame_arg": int(os.environ.get("TTRMOD_FRAME_ARG", "0")),
                    "f_globals_off": int(os.environ.get("TTRMOD_FGLOBALS_OFF", "48"))})
    print("[local] init:", json.dumps(init, indent=2))
    if not init.get("ok"):
        session.detach(); return
    ex.arm()
    fired = done.wait(15.0)
    if box.get("detached"):
        print("[local] !! DETACHED (%s) -- target CRASHED running code in the hook" % box["detached"])
    elif not fired:
        print("[local] hook never fired in 15s (unexpected)")
    else:
        print("[local] result:", json.dumps(box.get("r"), indent=2))
    exists = os.path.exists(HELLO_FILE)
    print("[local] %s exists=%s content=%r" %
          (HELLO_FILE, exists, open(HELLO_FILE).read() if exists else None))
    try:
        ex.disarm(); sc.unload(); session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
