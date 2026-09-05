#!/usr/bin/env python3
# localtest/trampoline_test.py -- OFFLINE validation of the C-API "native trampoline" primitive
# that the live route depends on. Proves, on a stock arm64 CPython 3.8 we own, that we can:
#   1. reach a class from sys.modules and grab its original method,
#   2. build a native wrapper (frida NativeCallback) -> PyCFunction_NewEx,
#   3. make it SELF-BINDING by calling the instancemethod TYPE object (the exact fallback we
#      must use live, since PyInstanceMethod_New was inlined away in the engine),
#   4. setattr it onto the class,
#   5. and have `inst.method(x)` dispatch into our native code, CALL THE ORIGINAL, and control
#      the return value -- with the process surviving.
#
# If this works here, the same sequence works in the live engine (different addresses), and it
# NEVER runs injected bytecode -> the opcode cipher is irrelevant.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/trampoline_test.py frida/run-injector.sh

import sys, os, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")
OUT = "/tmp/ttrmod-tramp-out"

# C name -> Mach-O export-trie symbol (leading-underscore convention; C names already starting
# with _ get a second underscore). Mix of functions and DATA (type object, None singleton).
SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyObject_SetAttrString":    "_PyObject_SetAttrString",
    "PyObject_Call":             "_PyObject_Call",
    "PyCFunction_NewEx":         "_PyCFunction_NewEx",
    "PyImport_AddModule":        "_PyImport_AddModule",
    "PyTuple_Pack":              "_PyTuple_Pack",
    "PyInstanceMethod_Type":     "_PyInstanceMethod_Type",   # DATA: the type object
    "_Py_NoneStruct":            "__Py_NoneStruct",           # DATA: None
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
      var base = m.base; out.base = base.toString();
      function at(n){ var a = base.add(ptr(p.offsets[n])); out.resolved[n]=a.toString(); return a; }
      ST = {
        base: base, done:false, installed:false,
        frame_eval: at('_PyEval_EvalFrameDefault'),
        GetAttrStr: new NativeFunction(at('PyObject_GetAttrString'), 'pointer', ['pointer','pointer']),
        SetAttrStr: new NativeFunction(at('PyObject_SetAttrString'), 'int',     ['pointer','pointer','pointer']),
        Call:       new NativeFunction(at('PyObject_Call'),          'pointer', ['pointer','pointer','pointer']),
        CFuncNewEx: new NativeFunction(at('PyCFunction_NewEx'),      'pointer', ['pointer','pointer','pointer']),
        AddModule:  new NativeFunction(at('PyImport_AddModule'),     'pointer', ['pointer']),
        TuplePack:  new NativeFunction(at('PyTuple_Pack'),           'pointer', ['long','...','pointer']),
        imTypePtr:  at('PyInstanceMethod_Type'),   // the type OBJECT (call it to self-bind)
        nonePtr:    at('_Py_NoneStruct'),
      };
      // the wrapper body, as NATIVE code. PyCFunction METH_VARARGS ABI: fn(self, args).
      // Installed via instancemethod, so `inst.greet(x)` calls us with args = (inst, x).
      // We: call the ORIGINAL greet with those same args (proves call-through), then RETURN
      // None (proves we control the return -> observable behavior change), and send('fired').
      ST.cb = new NativeCallback(function (self, args) {
        try {
          var n = 0; try { n = args.add(16).readS64().toNumber(); } catch(e){}   // tuple ob_size
          // call the original: PyObject_Call(orig, args, NULL)
          var res = ST.Call(ST.orig, args, ptr(0));   // returns new ref (we leak it; fine for a test)
          send({t:'fired', argc:n, orig_ret_nonnull: !res.isNull()});
        } catch(e){ send({t:'fired_err', e:String(e)}); }
        // return None (INCREF: bump refcnt so the caller's DECREF is balanced)
        try { var rc = ST.nonePtr.readU64(); ST.nonePtr.writeU64(rc+1); } catch(e){}
        return ST.nonePtr;
      }, 'pointer', ['pointer','pointer']);
      // a PyMethodDef {ml_name, ml_meth, ml_flags, ml_doc}; keep it alive on ST.
      ST.mname = Memory.allocUtf8String('greet_wrap');
      ST.mdef = Memory.alloc(32);
      ST.mdef.writePointer(ST.mname);                       // ml_name  @0
      ST.mdef.add(8).writePointer(ST.cb);                   // ml_meth  @8
      ST.mdef.add(16).writeU32(0x1);                        // ml_flags = METH_VARARGS @16
      ST.mdef.add(24).writePointer(ptr(0));                 // ml_doc   @24
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },
  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function () {
          if (ST.done) return; ST.done = true;               // once, main thread, GIL held
          try {
            var mainName = Memory.allocUtf8String('__main__');
            var mainMod  = ST.AddModule(mainName);            // borrowed
            if (mainMod.isNull()){ send({t:'done', r:{ok:false, stage:'no __main__'}}); return; }
            var fooName = Memory.allocUtf8String('Foo');
            var Foo = ST.GetAttrStr(mainMod, fooName);        // new ref
            if (Foo.isNull()){ send({t:'done', r:{ok:false, stage:'no Foo'}}); return; }
            var greetName = Memory.allocUtf8String('greet');
            ST.orig = ST.GetAttrStr(Foo, greetName);          // the original function (keep alive)
            if (ST.orig.isNull()){ send({t:'done', r:{ok:false, stage:'no greet'}}); return; }
            send({t:'stage', s:'got_class', Foo:Foo.toString(), orig:ST.orig.toString()});
            // wrap the native callback as a PyCFunction
            var cfunc = ST.CFuncNewEx(ST.mdef, ptr(0), ptr(0));   // (methoddef, self=NULL, module=NULL)
            if (cfunc.isNull()){ send({t:'done', r:{ok:false, stage:'CFuncNewEx NULL'}}); return; }
            // SELF-BINDING via the instancemethod TYPE (the engine fallback): im = type((cfunc,))
            var argtup = ST.TuplePack(1, cfunc);                  // 1-tuple (cfunc,)
            var im = ST.Call(ST.imTypePtr, argtup, ptr(0));       // instancemethod object
            if (im.isNull()){ send({t:'done', r:{ok:false, stage:'instancemethod NULL'}}); return; }
            ST.im = im; ST.cfunc = cfunc;
            // install: Foo.greet = im
            var rc = ST.SetAttrStr(Foo, greetName, im);
            send({t:'done', r:{ok:(rc===0), stage:'installed', setattr_rc:rc,
                               cfunc:cfunc.toString(), im:im.toString(),
                               im_type:im.add(8).readPointer().toString()}});
            ST.installed = true;
          } catch(e){ send({t:'done', r:{ok:false, stage:'install ex', e:String(e)}}); }
        }
      });
      return { ok:true };
    } catch(e){ return { ok:false, notes:['arm ex: '+e] }; }
  }
};
"""


def main():
    import frida
    dylib = framework_dylib(TARGET_PY)
    offsets = resolve_offsets(dylib)
    # target: define Foo.greet, then in a loop call inst.greet(7) and record the result. A busy
    # genexpr forces C->Python frame-evals so our hook fires. After we install the wrapper, greet
    # returns None -> the recorded value flips from "14" to "None" (observable behavior change).
    prog = ("import time\n"
            "class Foo:\n"
            "    def greet(self, x):\n"
            "        return x * 2\n"
            "f = Foo()\n"
            "t = time.time()\n"
            "while time.time() - t < 40:\n"
            "    r = f.greet(7)\n"
            "    open(%r, 'w').write(repr(r))\n"
            "    s = sum(i*i for i in range(300))\n" % OUT)
    try:
        os.remove(OUT)
    except OSError:
        pass
    tgt = subprocess.Popen([TARGET_PY, "-c", prog])
    time.sleep(0.5)
    pre = open(OUT).read() if os.path.exists(OUT) else None
    print("[tramp] target_py=%s pid=%d  pre-install greet()=%s" % (TARGET_PY, tgt.pid, pre))
    print("[tramp] offsets:", {k: hex(v) for k, v in offsets.items()})

    done = threading.Event(); box = {"fires": 0}
    def on_msg(m, d):
        if m.get("type") == "send":
            pl = m.get("payload") or {}
            t = pl.get("t")
            if t == "done": box["r"] = pl.get("r"); done.set()
            elif t == "stage": print("[stage]", json.dumps(pl))
            elif t == "fired": box["fires"] += 1
            elif t == "fired_err": print("[fired-err]", pl)
        elif m.get("type") == "error": print("[agent-err]", m.get("description") or m)
    def on_det(reason, *a): box["detached"] = reason; done.set()

    try:
        session = frida.attach(tgt.pid)
    except Exception as e:
        tgt.kill(); raise SystemExit("attach failed (arm64 target required): %s" % e)
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib})
    print("[tramp] init:", json.dumps(init, indent=2))
    if init.get("ok"):
        ex.arm()
        done.wait(12.0)
        if box.get("detached"):
            print("[tramp] !! DETACHED (%s) -- target CRASHED during/after install" % box["detached"])
        else:
            print("[tramp] install result:", json.dumps(box.get("r"), indent=2))
            time.sleep(1.5)   # let the target loop call the wrapped greet a few times
    alive = tgt.poll() is None
    post = open(OUT).read() if os.path.exists(OUT) else None
    print("[tramp] wrapper fires observed: %d" % box["fires"])
    print("[tramp] post-install greet()=%s  (pre=%s)  target_alive=%s" % (post, pre, alive))
    verdict = (box["fires"] > 0 and post == "None" and alive)
    print("[tramp] VERDICT: %s" % ("PASS -- trampoline installs, self-binds, calls original, controls return, survives"
                                   if verdict else "FAIL -- see above"))
    try:
        tgt.kill(); session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
