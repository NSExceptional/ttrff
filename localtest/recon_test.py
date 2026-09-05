#!/usr/bin/env python3
# localtest/recon_test.py -- OFFLINE validation of inject.py's *reconstruction* recipe.
#
# Live finding (2026-09-03): running `open(...)` (reads globals only) SURVIVED with a
# Python SystemError, but `x=1` (STORE_NAME -> WRITES globals) HARD-FAULTED the engine.
# We exec with globals = the frame's dict; inject.py currently reads f_builtins (+40).
# Hypothesis: the engine's builtins dict is frozen/read-only (normal for a frozen+LTO
# CPython), so the first WRITE faults. Fix: exec into f_globals (+48), a writable module
# dict. This harness proves the reconstruction+STORE_NAME path is sound on a 3.8 we own
# (where BOTH +40 and +48 are writable), so the ONLY live variable left is +40 vs +48.
#
# Mirrors inject.py's arm/onEnter EXACTLY: marshal the 16 code-object FIELDS as a tuple
# (pure data) -> PyMarshal_ReadObjectFromString -> PyCode_NewWithPosOnlyArgs ->
# Interceptor.detachAll() -> PyEval_EvalCode(code, gd, gd). Symbols come from the target
# dylib's export trie (dyld_info -exports); offset+slide model, same as the real injector.
#
#   run:  localtest/recon_test.py            # default globals = f_globals (+48), the fix
#         TTRMOD_GOFF=40 localtest/recon_test.py   # f_builtins (+40), the current live path
#
# Spawns its own arm64 python3.8 target (busy loop forcing C->Python frame-evals), so
# nothing external is needed and the live game is never touched.

import sys
import os
import time
import json
import threading
import subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")
GOFF = int(os.environ.get("TTRMOD_GOFF", "48"))          # 48=f_globals (fix), 40=f_builtins (live)
OUT = "/tmp/ttrmod-recon-hello"

# C name -> Mach-O trie symbol (leading-underscore convention; C names already starting
# with _ get a second underscore).
SYMS = {
    "PyEval_EvalCode": "_PyEval_EvalCode",
    "PyCode_NewWithPosOnlyArgs": "_PyCode_NewWithPosOnlyArgs",
    "PyMarshal_ReadObjectFromString": "_PyMarshal_ReadObjectFromString",
    "_PyEval_EvalFrameDefault": "__PyEval_EvalFrameDefault",
    # Exception handling: compare the proper C-API (Occurred/Clear) against the manual
    # tstate+88 read inject.py currently uses, to prove which is sound before wiring the
    # engine's PyErr_* addresses.
    "PyErr_Occurred": "_PyErr_Occurred",
    "PyErr_Clear": "_PyErr_Clear",
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
        raise SystemExit("could not locate framework dylib for %s (got %r)\n%s"
                         % (target_py, path, p.stderr))
    return os.path.realpath(path)


def resolve_offsets(dylib):
    out = subprocess.run(["xcrun", "dyld_info", "-exports", dylib],
                         capture_output=True, text=True).stdout
    want = {v: k for k, v in SYMS.items()}
    offs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("0x") and parts[1] in want:
            offs[want[parts[1]]] = int(parts[0], 16)
    missing = [k for k in SYMS if k not in offs]
    if missing:
        raise SystemExit("missing exports in %s: %s" % (dylib, missing))
    return offs


def marshal_fields(target_py, src):
    # EXACT field order from inject.py build_blob (the 16 PyCode_NewWithPosOnlyArgs args).
    helper = ("import sys, marshal\n"
              "src = sys.stdin.buffer.read().decode('utf-8')\n"
              "c = compile(src, 'ttrmod-recon', 'exec')\n"
              "f = (c.co_argcount, c.co_posonlyargcount, c.co_kwonlyargcount, c.co_nlocals,\n"
              "     c.co_stacksize, c.co_flags, c.co_code, c.co_consts, c.co_names,\n"
              "     c.co_varnames, c.co_freevars, c.co_cellvars, c.co_filename, c.co_name,\n"
              "     c.co_firstlineno, c.co_lnotab)\n"
              "sys.stdout.buffer.write(marshal.dumps(f))\n")
    p = subprocess.run([target_py, "-c", helper], input=src.encode("utf-8"), capture_output=True)
    if p.returncode != 0 or not p.stdout:
        raise SystemExit("fields marshal failed: " + p.stderr.decode("utf-8", "replace"))
    return p.stdout


AGENT = r"""
'use strict';
var ST = null;
rpc.exports = {
  init: function (p) {
    var out = { ok:false, notes:[], resolved:{} };
    try {
      var mods = Process.enumerateModules(), m = null;
      for (var i=0;i<mods.length;i++){ if (mods[i].path === p.module_path){ m = mods[i]; break; } }
      if (!m){ for (var j=0;j<mods.length;j++){ if (/Python\.framework|\/Python$|libpython/i.test(mods[j].path)){ m = mods[j]; break; } } }
      if (!m){ out.notes.push('python module not found'); return out; }
      out.module = m.path; var base = m.base; out.base = base.toString();
      function at(name){ var a = base.add(ptr(p.offsets[name])); out.resolved[name]=a.toString(); return a; }

      var blob = new Uint8Array(p.blob);
      var buf = Memory.alloc(blob.length); buf.writeByteArray(blob);
      ST = {
        goff: p.goff, buf: buf, blen: blob.length, done:false,
        frame_eval: at('_PyEval_EvalFrameDefault'),
        EvalCo:  new NativeFunction(at('PyEval_EvalCode'), 'pointer', ['pointer','pointer','pointer']),
        ReadObj: new NativeFunction(at('PyMarshal_ReadObjectFromString'), 'pointer', ['pointer','long']),
        Occurred: new NativeFunction(at('PyErr_Occurred'), 'pointer', []),
        Clear:    new NativeFunction(at('PyErr_Clear'), 'void', []),
        TState:   new NativeFunction(at('_PyThreadState_UncheckedGet'), 'pointer', []),
        PyCodeNew: new NativeFunction(at('PyCode_NewWithPosOnlyArgs'), 'pointer',
          ['int','int','int','int','int','int','pointer','pointer',
           'pointer','pointer','pointer','pointer','pointer','pointer','int','pointer'])
      };
      // Same fault catcher as the live injector, so an offline crash is diagnosable too.
      Process.setExceptionHandler(function (details) {
        try { send({t:'crash', typ:details.type, pc:details.context.pc?details.context.pc.toString():null,
                    addr:details.address?details.address.toString():null}); } catch(e){}
        return false;
      });
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
            var fr = args[0]; if (fr.isNull()) return;
            gd = fr.add(ST.goff).readPointer(); if (gd.isNull()) return;
            var tp = gd.add(8).readPointer(); if (tp.isNull()) return;
            var nm = tp.add(24).readPointer(); if (nm.isNull()) return;
            if (nm.readCString() !== 'dict') return;   // wait for a frame with a real dict
          } catch(e){ return; }
          ST.done = true;
          try {
            send({t:'stage', s:'got_globals', goff:ST.goff, gd:gd.toString()});
            var T = ST.ReadObj(ST.buf, ST.blen);
            if (T.isNull()){ send({t:'done', r:{ok:false, stage:'ReadObject NULL'}}); return; }
            function item(i){ return T.add(24 + i*8).readPointer(); }
            function longval(o){ var sz=o.add(16).readS64().toNumber(); if(sz===0) return 0;
                                 var neg=sz<0, k=neg?-sz:sz, v=0;
                                 for (var i=0;i<k;i++){ v += o.add(24+i*4).readU32()*Math.pow(2,30*i); }
                                 return neg?-v:v; }
            var ac=longval(item(0)), po=longval(item(1)), kw=longval(item(2)), nl=longval(item(3)),
                ss=longval(item(4)), fl=longval(item(5)), fln=longval(item(14));
            send({t:'stage', s:'ints', argcount:ac, posonly:po, kwonly:kw, nlocals:nl, stacksize:ss, flags:fl});
            var code = ST.PyCodeNew(ac, po, kw, nl, ss, fl,
              item(6), item(7), item(8), item(9), item(10), item(11), item(12), item(13), fln, item(15));
            if (code.isNull()){ send({t:'done', r:{ok:false, stage:'PyCode_New NULL'}}); return; }
            var ctn='?'; try { ctn = code.add(8).readPointer().add(24).readPointer().readCString(); } catch(e){}
            send({t:'stage', s:'code_built', code_type:ctn});
            try { Interceptor.detachAll(); Interceptor.flush(); ST.listener=null; } catch(e){}
            send({t:'stage', s:'pre_eval'});
            var res = ST.EvalCo(code, gd, gd);
            var out = {ok:!res.isNull(), stage:'done', res:res.toString()};
            if (res.isNull()){
              function tpname(typtr){ try { if(typtr.isNull()) return null; return typtr.add(24).readPointer().readCString(); } catch(e){ return 'read-err:'+e; } }
              out.exc_api = tpname(ST.Occurred());                       // method B: PyErr_Occurred (proper)
              try { var ts = ST.TState();                                // method A: manual tstate+88 (inject.py's way)
                    out.exc_off = ts.isNull() ? 'tstate-null' : tpname(ts.add(88).readPointer()); }
              catch(e){ out.exc_off = 'off-err:'+e; }
              ST.Clear();                                                // clear via API...
              out.after_clear = ST.Occurred().isNull() ? 'CLEARED' : 'STILL-SET';  // ...verify gone
            }
            send({t:'done', r:out});
          } catch(e){ send({t:'done', r:{ok:false, stage:'eval ex', err:String(e)}}); }
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
    # Default: STORE_NAME (writes globals) + a builtin call (open) + file write. Override with
    # TTRMOD_SRC to run the live discriminator ladder offline ("1/0", "raise KeyError",
    # "import sys\nraise KeyError") and see exc_api vs exc_off for each.
    src = os.environ.get("TTRMOD_SRC",
                         "x = 41 + 1\n"
                         "open(%r, 'w').write('recon x=%%d goff=%%d\\n' %% (x, %d))\n" % (OUT, GOFF))
    blob = marshal_fields(TARGET_PY, src)
    try:
        os.remove(OUT)
    except OSError:
        pass

    # Spawn our own target: a busy loop forcing C->Python boundaries so the frame-eval
    # hook fires immediately (sum(map(fn,...)) re-enters _PyEval_EvalFrameDefault per item).
    loop = ("import time\n"
            "def leaf(i):\n"
            "    return i * i\n"
            "t = time.time()\n"
            "while time.time() - t < 30:\n"
            "    s = sum(map(leaf, range(20000)))\n")
    tgt = subprocess.Popen([TARGET_PY, "-c", loop])
    time.sleep(0.4)
    print("[recon] target_py=%s pid=%d goff=%d blob=%dB" % (TARGET_PY, tgt.pid, GOFF, len(blob)))
    print("[recon] offsets:", {k: hex(v) for k, v in offsets.items()})

    done = threading.Event(); box = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            pl = m.get("payload") or {}
            if pl.get("t") == "done": box["r"] = pl.get("r"); done.set()
            elif pl.get("t") == "crash": box["crash"] = pl; print("[crash]", json.dumps(pl)); sys.stdout.flush()
            elif pl.get("t") == "stage": print("[stage]", json.dumps(pl)); sys.stdout.flush()
        elif m.get("type") == "error":
            print("[agent-err]", m.get("description") or m); sys.stdout.flush()
    def on_det(reason, *a): box["detached"] = reason; done.set()

    try:
        session = frida.attach(tgt.pid)
    except Exception as e:
        tgt.kill(); raise SystemExit("attach failed (arm64 target required): %s" % e)
    session.on("detached", on_det)
    sc = session.create_script(AGENT); sc.on("message", on_msg); sc.load()
    ex = sc.exports_sync
    init = ex.init({"blob": list(blob), "offsets": {k: hex(v) for k, v in offsets.items()},
                    "module_path": dylib, "goff": GOFF})
    print("[recon] init:", json.dumps(init, indent=2))
    if init.get("ok"):
        ex.arm()
        fired = done.wait(15.0)
        if box.get("detached"):
            print("[recon] !! DETACHED (%s) -- target CRASHED (write-fault reproduced?)" % box["detached"])
        elif not fired:
            print("[recon] hook never fired in 15s")
        else:
            print("[recon] result:", json.dumps(box.get("r"), indent=2))
    alive = tgt.poll() is None
    exists = os.path.exists(OUT)
    print("[recon] target_alive=%s  %s exists=%s content=%r"
          % (alive, OUT, exists, open(OUT).read() if exists else None))
    try:
        tgt.kill(); session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
