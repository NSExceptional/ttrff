#!/usr/bin/env python3
# frida/inject.py -- runs the ttrff payload inside the live TTREngine via FRIDA,
# instead of lldb (whose debugserver SIGSEGVs attaching to this engine).
#
# Run as root (task_for_pid on the hardened engine needs it here):
#   sudo /Users/tanner/Developer/ttrff/frida/run-injector.sh [--probe|--apply|--revert]
#
# APPROACH -- PyEval_EvalCode INTERCEPTOR (replaces the old GIL-polling recipe):
#   The earlier driver read _PyThreadState_Current and then PyGILState_Ensure()'d to
#   run code. That RACES the GIL (the engine is mostly in C with the GIL released) and,
#   worse, Ensure() blocks until it can acquire the GIL -- if the game is parked in
#   Python holding it (menu/select loop) that block is forever, and killing the stuck
#   injector wedges the engine (forced relaunch).
#
#   We hook a CPython C function that runs ON THE GAME'S OWN THREAD with the GIL already
#   held, so there is NO acquire-block, no race, no freeze risk. The target is
#   `PyGILState_Ensure()`, hooked on onLeave (GIL is held on return). A live diagnostic
#   measured it firing ~1875x/s during play with a reachable current-frame f_globals
#   99.96% of the time -- so it fires within ~1ms of arming (no in-game trigger needed)
#   and gives us execution globals. In onLeave we read the current thread state's top
#   frame -> f_globals (the same read the old lldb path used, but now GUARANTEED under a
#   held GIL); if it's momentarily NULL we skip and catch the next call.
#   ROOT CAUSE OF THE EARLY CRASHES (2026-08-30): the blob was marshalled with CPython
#   3.7 but the ENGINE IS 3.8.17 (co_posonlyargcount / PEP 570). A 3.7 code object read by
#   3.8's marshal shifts every field -> corrupt code object / wild read -> native crash
#   (NOT a hook/storm problem; a local arm64 rig proved eval-in-hook + 200k reentrant
#   fires are both fine). FIX: marshal with 3.8 (find_marshal_py). Both hooks below crashed
#   ONLY because of this; the earlier "callback storm" post-mortem was wrong.
#   HOOK NOTES:
#     * `_PyEval_EvalFrameDefault` (per-frame evaluator, addr in memory 0x100a39f2c) --
#       viable now, valid globals via args[0]->f_globals; fires per Python call.
#     * `PyEval_EvalCode` -- never fires in-game (all modules preloaded at startup;
#       nothing new imports). Measured 0/6s. Not usable as the trigger.
#
#   In onLeave we (once): set a done-guard, read f_globals, marshal.loads the blob,
#   PyEval_EvalCode it with that globals dict, report via send(), and return. The
#   payload's own bytecode runs through _PyEval_EvalFrameDefault (NOT hooked) and does
#   not re-enter PyGILState_Ensure, so there is no storm. Python then disarms (detach
#   from the frida thread).
#
# Cosmetic-only; fully reversible via --revert.

import os
import sys
import json
import time
import threading
import tempfile
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAYLOAD = os.path.join(ROOT, "inproc", "payload.py")
OFFSETS = os.path.join(ROOT, "offsets.json")
CONFIG = os.path.join(ROOT, "config.json")
OPMAP = os.path.join(ROOT, "opcode_map.json")   # standard->engine opcode permutation (if reversed)
STATUS = "/tmp/ttrmod-status.json"

MODE = "probe"
for a in sys.argv[1:]:
    if a in ("--probe", "--apply", "--revert", "--hello"):
        MODE = a[2:]


def find_marshal_py():
    # TTREngine is CPython **3.8.17** (confirmed: version string + `co_posonlyargcount`,
    # the PEP-570 field 3.8 added). marshal's code-object layout is version-locked, so the
    # blob MUST be produced by 3.8 -- a 3.7 blob loaded under 3.8 shifts every code-object
    # field ("bad marshal data (unknown type code)" / wild read -> native crash). Any 3.8.x
    # works (micro version only affects the .pyc magic, which raw marshal doesn't use).
    for c in [os.environ.get("TTRMOD_PY38"),
              "/opt/homebrew/bin/python3.8",
              "/Library/Frameworks/Python.framework/Versions/3.8/bin/python3.8",
              "python3.8"]:
        if not c:
            continue
        try:
            v = subprocess.check_output([c, "-c", "import sys;print(sys.version_info[:2])"],
                                        text=True, stderr=subprocess.DEVNULL).strip()
            if v == "(3, 8)":
                return c
        except Exception:
            continue
    raise SystemExit("need a CPython 3.8 to marshal the payload for the 3.8.17 engine "
                     "(set TTRMOD_PY38)")


HELLO = "/tmp/ttrmod-hello"


def build_blob(cfg_path):
    if os.environ.get("TTRMOD_TESTOBJ"):
        # Diagnostic: marshal an arbitrary object (TTRMOD_TESTSRC, a Python expr) to
        # isolate which marshal type code crashes the engine's r_object. Default = a
        # trivial tuple (int/str/float/list/None/dict). Set e.g. TTRMOD_TESTSRC="b'x'*8"
        # to test a bytes object (TYPE_STRING), the type a code object adds over the tuple.
        expr = os.environ.get("TTRMOD_TESTSRC", "(1, 'ttrmod', 2.5, [3, 4], None, {'k': 'v'})")
        helper = ("import sys, marshal\n"
                  "sys.stdout.buffer.write(marshal.dumps(eval(%r)))\n" % expr)
        p = subprocess.run([find_marshal_py(), "-c", helper], capture_output=True)
        if p.returncode != 0 or not p.stdout:
            raise SystemExit("testobj marshal failed:\n" + p.stderr.decode("utf-8", "replace"))
        return p.stdout
    if MODE == "hello":
        # Phase-1 test of the reconstruction primitive: marshal the hello code object's
        # FIELDS tuple (no nested code -> pure data -> unmarshals fine on the hardened
        # engine); the agent rebuilds the code object via PyCode_New and runs it.
        # TTRMOD_HELLOSRC overrides the test source, e.g. "1/0" to prove the reconstructed
        # code EXECUTES via a bytecode-only exception (no names/builtins), isolating the
        # eval mechanism from I/O/builtins availability.
        src = os.environ.get("TTRMOD_HELLOSRC",
                             "open(%r,'w').write('hello from ttrmod eval\\n')" % HELLO)
        # Translate co_code opcodes standard->engine (the engine's opcodes are REMAPPED; see
        # STATUS.md journey #9). Uses opcode_map.json if present; TTRMOD_NOXLATE disables it
        # (for A/B). An opcode missing from the map aborts loudly (surfaces map gaps).
        helper = ("import sys, marshal, os, json\n"
                  "src = sys.stdin.buffer.read().decode('utf-8')\n"
                  "c = compile(src, 'ttrmod-hello', 'exec')\n"
                  "s2e = {}; mp = os.environ.get('TTRMOD_OPMAP')\n"
                  "if mp and os.path.exists(mp) and not os.environ.get('TTRMOD_NOXLATE'):\n"
                  "    s2e = {int(k): v for k, v in json.load(open(mp)).get('std_to_engine', {}).items()}\n"
                  "def tr(code):\n"
                  "    if not s2e: return code\n"
                  "    b = bytearray(code)\n"
                  "    for i in range(0, len(b), 2):\n"
                  "        if b[i] in s2e: b[i] = s2e[b[i]]\n"
                  "        else: sys.exit('opcode %d (off %d) not in opcode_map' % (b[i], i))\n"
                  "    return bytes(b)\n"
                  "cc = tr(c.co_code)\n"
                  "f = (c.co_argcount, c.co_posonlyargcount, c.co_kwonlyargcount, c.co_nlocals,\n"
                  "     c.co_stacksize, c.co_flags, cc, c.co_consts, c.co_names,\n"
                  "     c.co_varnames, c.co_freevars, c.co_cellvars, c.co_filename, c.co_name,\n"
                  "     c.co_firstlineno, c.co_lnotab)\n"
                  "sys.stdout.buffer.write(marshal.dumps(f))\n")
        p = subprocess.run([find_marshal_py(), "-c", helper], input=src.encode("utf-8"),
                           capture_output=True, env={**os.environ, "TTRMOD_OPMAP": OPMAP})
        if p.returncode != 0 or not p.stdout:
            raise SystemExit("3.8 fields marshal failed:\n" + p.stderr.decode("utf-8", "replace"))
        return p.stdout
    header = ("import os\n"
              "os.environ['TTRMOD_CFG'] = %r\n"
              "os.environ['TTRMOD_STATUS'] = %r\n") % (cfg_path, STATUS)
    src = header + "# ==== payload ====\n" + open(PAYLOAD).read()
    helper = ("import sys, marshal\n"
              "src = sys.stdin.buffer.read().decode('utf-8')\n"
              "co = compile(src, 'ttrmod-payload', 'exec')\n"
              "sys.stdout.buffer.write(marshal.dumps(co))\n")
    p = subprocess.run([find_marshal_py(), "-c", helper], input=src.encode("utf-8"),
                       capture_output=True)
    if p.returncode != 0 or not p.stdout:
        raise SystemExit("3.8 marshal failed:\n" + p.stderr.decode("utf-8", "replace"))
    return p.stdout


def write_cfg():
    if MODE == "hello":
        return None
    cfg = json.load(open(CONFIG))
    if MODE == "revert":
        cfg["revert"] = True
    elif MODE == "probe":
        cfg["probe"] = True
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, prefix="ttrmod-cfg-")
    json.dump(cfg, tf)
    tf.close()
    os.chmod(tf.name, 0o644)   # inject.py runs as root; the game (user) must read it
    return tf.name


def find_pid():
    out = subprocess.check_output(["pgrep", "-f", "Toontown Rewritten"], text=True).split()
    for pid in out:
        try:
            cmd = subprocess.check_output(["ps", "-o", "command=", "-p", pid], text=True)
        except Exception:
            continue
        if "TTREngine" in cmd or "Toontown Rewritten.app" in cmd:
            return int(pid)
    return int(out[0]) if out else None


AGENT_JS = r"""
'use strict';
var ST = null;   // staged state

rpc.exports = {
  // Resolve + verify addresses, build NativeFunctions, stage the marshal blob.
  init: function (params) {
    var out = { ok:false, verified:false, notes:[], resolved:{} };
    try {
      var base = Process.mainModule.base;
      var slide = base.sub(ptr(params.image_base));
      out.load_base = base.toString(); out.slide = slide.toString();
      function rt(v){ return ptr(v).add(slide); }

      var A = {};
      for (var k in params.addrs){ A[k] = rt(params.addrs[k]); out.resolved[k]=A[k].toString(); }
      var bad = [];
      for (var k in params.verify){
        var want = params.verify[k];
        var got = new Uint8Array(A[k].readByteArray(want.length));
        for (var i=0;i<want.length;i++){ if(got[i]!==want[i]){ bad.push(k); break; } }
      }
      if (bad.length){ out.notes.push('VERIFY FAILED (binary changed?): '+bad.join(',')); return out; }
      out.verified = true;

      var blob = new Uint8Array(params.blob);
      var buf = Memory.alloc(blob.length);
      buf.writeByteArray(blob);

      ST = {
        hook: A.eval_frame_default,        // _PyEval_EvalFrameDefault(f, throwflag): MAIN thread,
                                           // full thread-state. We detach the interceptor BEFORE
                                           // EvalCode so our code's frame-evals don't re-enter it.
        globals_off: params.globals_off,   // frame -> f_globals (+48)
        tstate_ptr: rt(params.tstate_ptr), // _PyThreadState_Current (curexc read/clear)
        noeval: !!params.noeval,           // diagnostic: stop after ba_dump, before marshal.loads
        testobj: !!params.testobj,         // diagnostic: blob is a trivial non-code obj; stop after marshal.loads
        loadonly: !!params.loadonly,        // diagnostic: stop after marshal.loads (any blob), no EvalCode
        buf: buf, blen: blob.length,
        BAFrom:  new NativeFunction(A.bytes_from_string_and_size, 'pointer', ['pointer','long']),
        Loads:   new NativeFunction(A.marshal_loads, 'pointer', ['pointer','pointer']),
        EvalCo:  new NativeFunction(A.eval_code, 'pointer', ['pointer','pointer','pointer']),
        // PyCode_NewWithPosOnlyArgs(argcount,posonly,kwonly,nlocals,stacksize,flags [x0-x5],
        //   code,consts [x6-x7], names,varnames,freevars,cellvars,filename,name,firstlineno,lnotab [stack])
        PyCodeNew: new NativeFunction(A.pycode_new, 'pointer',
          ['int','int','int','int','int','int','pointer','pointer',
           'pointer','pointer','pointer','pointer','pointer','pointer','int','pointer']),
        slide: slide, base: base,
        listener: null, armed: false, done: false, result: null
      };

      // The CORRECT post-EvalCode exception read+clear: PyErr_Occurred() returns the current
      // exc type and PyErr_Clear() clears it, both fetching the thread-state INTERNALLY -- so
      // no dependence on the (wrong) _PyThreadState_Current cell or curexc offsets, which was
      // reading a garbage tstate (bogus "SystemError") and corrupting memory on the clear.
      // Bound only if their addresses are present in offsets.json; else we fall back to the
      // legacy manual tstate+88 path below (SUSPECT).
      if (A.err_occurred) { try { ST.ErrOccurred = new NativeFunction(A.err_occurred, 'pointer', []); } catch(e){ out.notes.push('ErrOccurred bind: '+e); } }
      if (A.err_clear)    { try { ST.ErrClear    = new NativeFunction(A.err_clear, 'void', []); } catch(e){ out.notes.push('ErrClear bind: '+e); } }

      // Native exception handler: catch the EvalCode fault in-flight and write the fault
      // address + registers + backtrace to disk (survives the crash). Addresses minus the
      // slide = vmaddrs we can map to functions in the disasm -> the exact crash cause.
      Process.setExceptionHandler(function (details) {
        var c = details.context;
        // ESSENTIALS FIRST (register reads only -- cannot hang), written+flushed before the
        // risky backtrace, so we always get the faulting PC even if backtrace hangs.
        try {
          function vm(p){ try { return ptr(p).toString()+' vm=0x'+ptr(p).sub(ST.slide).toString(16); } catch(e){ return String(p); } }
          var f = new File('/tmp/ttrmod-crash.json', 'w');
          f.write(JSON.stringify({
            type: details.type,
            pc: c.pc?vm(c.pc):null, lr: c.lr?vm(c.lr):null,
            fault_addr: details.address?vm(details.address):null,
            mem: details.memory?{op:details.memory.operation, addr:details.memory.address?vm(details.memory.address):null}:null,
            x0:c.x0?c.x0.toString():null, x1:c.x1?c.x1.toString():null, x2:c.x2?c.x2.toString():null
          }, null, 2)+'\n');
          f.flush(); f.close();
        } catch(e){}
        try { send({t:'crash', pc: c.pc?c.pc.toString():null}); } catch(e){}
        // Backtrace is best-effort (FUZZY; can hang) -> a SEPARATE file so it never blocks the above.
        try {
          function vm2(p){ try { return ptr(p).toString()+' vm=0x'+ptr(p).sub(ST.slide).toString(16); } catch(e){ return String(p); } }
          var bt = Thread.backtrace(c, Backtracer.FUZZY).slice(0,24).map(vm2);
          var g = new File('/tmp/ttrmod-crash-bt.json','w'); g.write(JSON.stringify(bt,null,2)+'\n'); g.flush(); g.close();
        } catch(e){}
        return false;
      });

      out.ok = true; return out;
    } catch(e){ out.notes.push('init exception: '+e); return out; }
  },

  // Install the interceptor on _PyEval_EvalFrameDefault (the per-frame bytecode
  // evaluator, called for every Python call -- fires within ~1ms, and runs on the
  // MAIN game thread where marshal/eval are safe, unlike PyGILState_Ensure which fires
  // on Panda's background C threads). onEnter args[0] is the live PyFrameObject; we read
  // args[0]->f_globals (+48) and, the first time it's a real dict, run the payload with
  // it as execution globals, then send('done'). Reentrant frames hit the done-guard.
  arm: function () {
    if (!ST) return { ok:false, notes:['init not called'] };
    if (ST.armed) return { ok:true, notes:['already armed'] };
    try {
      ST.listener = Interceptor.attach(ST.hook, {
        onEnter: function (args) {
          if (ST.done) return;                       // one-shot; ignore reentry
          var gd;
          try {
            var fr = args[0]; if (fr.isNull()) return;    // the live PyFrameObject (main thread)
            // Use f_globals (+48, ST.globals_off): a WRITABLE module dict. NOT f_builtins
            // (+40): in this frozen+LTO engine the builtins dict is read-only, so code that
            // ASSIGNS a name (STORE_NAME) faults on the first write while read-only code
            // (LOAD_NAME) survives -- confirmed live (`open(...)` survived, `x=1` hard-faulted)
            // and offline on stock 3.8 (localtest/recon_test.py: both offsets run STORE_NAME
            // fine because stock builtins is writable, isolating the fault to the engine's RO
            // builtins). f_globals resolves builtins via its __builtins__ and takes our writes.
            gd = fr.add(ST.globals_off).readPointer(); if (gd.isNull()) return;
            // GUARD: only accept a frame whose f_globals is a real dict. A stale/garbage
            // frame -> non-dict "globals" -> PyEval_EvalCode faults natively. Verify
            // gd->ob_type->tp_name == "dict" (PyTypeObject.tp_name @ +24 on 3.8); if not,
            // SKIP this fire and wait for a clean one (turns a crash into a safe skip).
            var tp = gd.add(8).readPointer(); if (tp.isNull()) return;
            var nm = tp.add(24).readPointer(); if (nm.isNull()) return;
            if (nm.readCString() !== 'dict') {
              if (!ST.warned){ ST.warned = true; send({t:'stage', s:'globals_not_dict', tp_name: nm.readCString()}); }
              return;
            }
          } catch(e){ return; }
          ST.done = true;                            // set BEFORE eval -> no re-run
          try {
            // Staged sends: each flushes before the next (riskier) native call, so if a
            // call hard-crashes the process we still see how far we got.
            send({t:'stage', s:'got_globals', gd:gd.toString(),
                  gd_type: gd.add(8).readPointer().toString(), gd_refcnt: gd.readU64().toString()});
            // The engine's marshal DISABLES code-object unmarshalling (TYPE_CODE -> "bad
            // marshal data"), so we marshal only the code object's FIELDS (a pure-data
            // tuple, which unmarshals fine) and rebuild the code object in-process via
            // PyCode_NewWithPosOnlyArgs. Blob = marshal((argcount,posonly,kwonly,nlocals,
            // stacksize,flags,code,consts,names,varnames,freevars,cellvars,filename,name,
            // firstlineno,lnotab)).
            var ba = ST.BAFrom(ST.buf, ST.blen);
            if (ba.isNull()){ ST.result={ok:false,stage:'PyByteArray_FromStringAndSize NULL'};
                              send({t:'done', r:ST.result}); return; }
            send({t:'stage', s:'ba_ok', ba:ba.toString()});
            if (ST.noeval){ ST.result={ok:false, stage:'noeval: stopped before marshal.loads'};
                            send({t:'done', r:ST.result}); return; }
            var T = ST.Loads(ptr(0), ba);              // the FIELDS tuple (pure data)
            if (T.isNull()){ ST.result={ok:false,stage:'marshal.loads(fields) NULL'};
                             send({t:'done', r:ST.result}); return; }
            var T_tn='?'; try { T_tn = T.add(8).readPointer().add(24).readPointer().readCString(); } catch(e){}
            var nitems = T.add(16).readS64().toNumber();
            send({t:'stage', s:'fields_ok', tp:T_tn, n:nitems});
            // read tuple item i (3.8 PyTupleObject: ob_item inline @ +24) and small-int values
            function item(i){ return T.add(24 + i*8).readPointer(); }
            function longval(o){ var sz=o.add(16).readS64().toNumber(); if(sz===0) return 0;
                                 var neg=sz<0, k=neg?-sz:sz, v=0;
                                 for (var i=0;i<k;i++){ v += o.add(24+i*4).readU32()*Math.pow(2,30*i); }
                                 return neg?-v:v; }
            var ac=longval(item(0)), po=longval(item(1)), kw=longval(item(2)), nl=longval(item(3)),
                ss=longval(item(4)), fl=longval(item(5)), fln=longval(item(14));
            send({t:'stage', s:'ints', argcount:ac, posonly:po, kwonly:kw, nlocals:nl,
                  stacksize:ss, flags:fl, firstlineno:fln});
            var code = ST.PyCodeNew(ac, po, kw, nl, ss, fl,
              item(6), item(7), item(8), item(9), item(10), item(11), item(12), item(13),
              fln, item(15));
            if (code.isNull()){ ST.result={ok:false,stage:'PyCode_New returned NULL'};
                                send({t:'done', r:ST.result}); return; }
            var code_tn='?'; try { code_tn = code.add(8).readPointer().add(24).readPointer().readCString(); } catch(e){}
            send({t:'stage', s:'code_built', code:code.toString(), code_type:code_tn});
            if (ST.loadonly){
              // SAFE integrity check (no eval): read the rebuilt object's co_code (PyCodeObject
              // +48 in 3.8) and report its type/len/first bytes, so the host can compare to the
              // known-good co_code -> distinguishes "hardened marshal mangled the bytecode" from
              // "opcodes are remapped" (which would leave co_code byte-correct).
              var cc = {};
              try {
                function tpn(o){ try { return o.add(8).readPointer().add(24).readPointer().readCString(); } catch(e){ return '?'; } }
                var cobytes = code.add(48).readPointer();                        // co_code (a bytes obj)
                var clen = cobytes.add(16).readS64().toNumber();                  // PyBytesObject ob_size @ +16
                var hex=''; var n=Math.min(clen, 160);
                for (var bi=0; bi<n; bi++){ var b=cobytes.add(32+bi).readU8(); hex += (b<16?'0':'')+b.toString(16); }  // ob_sval @ +32 (after ob_shash)
                cc = { co_code_type: tpn(cobytes), co_code_len: clen, co_code_hex: hex };
                // co_consts (PyCodeObject +56): a tuple. Report its length + each item's type
                // (and small-int value) -> catches a mangled constants pool (LOAD_CONST garbage).
                var consts = code.add(56).readPointer();
                var ct = tpn(consts), cn = consts.add(16).readS64().toNumber();
                var items = [];
                for (var ci=0; ci<Math.min(cn,8); ci++){
                  var it = consts.add(24+ci*8).readPointer();
                  var itn = tpn(it), iv = null;
                  if (itn === 'int'){ try { var sz=it.add(16).readS64().toNumber(); iv = (sz===0)?0:(it.add(24).readU32()*(sz<0?-1:1)); } catch(e){} }
                  items.push(iv===null ? itn : (itn+'='+iv));
                }
                cc.co_consts = { type: ct, len: cn, items: items };
              } catch(e){ cc = { err: String(e) }; }
              ST.result={ok:(code_tn==='code'), stage:'code built (loadonly)', code_type:code_tn, cc:cc};
              send({t:'done', r:ST.result}); return;
            }
            // Remove our trampoline from _PyEval_EvalFrameDefault BEFORE running the code,
            // so the payload's own frame-evals execute on the pristine function (no
            // re-entry through the frida bridge -> no reentrancy freeze).
            try { Interceptor.detachAll(); Interceptor.flush(); ST.listener = null; } catch(e){}
            send({t:'stage', s:'pre_eval'});
            var res = ST.EvalCo(code, gd, gd);         // run the rebuilt code object
            send({t:'stage', s:'post_eval', res:res.toString()});
            var exc = null, excmethod = null;
            if (res.isNull()){
              // The payload raised a Python exception. Capture its class name, then CLEAR it
              // so the game's own frame does not inherit it and crash. Keep this MINIMAL:
              // onEnter runs ON the game's main thread, so anything slow here freezes the game.
              if (ST.ErrOccurred && ST.ErrClear){
                // PREFERRED: proper C-API. Fetches the tstate internally -> no wrong-cell/
                // wrong-offset hazard, no corrupting writes.
                excmethod = 'api';
                try { var et = ST.ErrOccurred();
                      if (!et.isNull()) { try { exc = et.add(24).readPointer().readCString(); } catch(e){ exc='?'; } } }
                catch(e){ exc = 'occurred-error: '+e; }
                try { ST.ErrClear(); } catch(e){}
              } else {
                // LEGACY FALLBACK (SUSPECT): manual _PyThreadState_Current cell + curexc @
                // 88/96/104. The cell address is likely wrong on this build -> bogus type and a
                // corrupting clear; used only if PyErr_Occurred/Clear aren't wired in offsets.json.
                excmethod = 'manual';
                try {
                  var tsp = ST.tstate_ptr.readPointer();
                  var et2 = tsp.add(88).readPointer();
                  if (!et2.isNull()){
                    try { exc = et2.add(24).readPointer().readCString(); } catch(e){ exc='?'; }
                    tsp.add(88).writePointer(ptr(0));      // clear curexc_type
                    tsp.add(96).writePointer(ptr(0));      // clear curexc_value
                    tsp.add(104).writePointer(ptr(0));     // clear curexc_traceback
                  }
                } catch(e){ exc = 'exc-read-error: '+e; }
              }
            }
            ST.result = { ok:!res.isNull(), stage:'done', res:res.toString(), exc:exc, exc_method:excmethod };
            send({t:'done', r:ST.result});
          } catch(e){
            ST.result = { ok:false, stage:'eval exception', err:String(e) };
            send({t:'done', r:ST.result});
          }
        }
      });
      ST.armed = true;
      return { ok:true };
    } catch(e){ return { ok:false, notes:['arm exception: '+e] }; }
  },

  // Detach the hook from the frida thread (never from inside onEnter).
  disarm: function () {
    try { if (ST && ST.listener){ ST.listener.detach(); ST.listener=null; } } catch(e){}
    try { Interceptor.flush(); } catch(e){}
    if (ST) ST.armed = false;
    return { ok:true, done: ST?ST.done:false, result: ST?ST.result:null };
  },

  // For the HANG/deadlock case: backtrace every thread so we can see WHERE the stuck
  // thread is parked (which engine function EvalCode deadlocked in). Runs on frida's
  // own thread, so it works even while the game thread holds the GIL frozen.
  sample: function () {
    function vm(p){ try { return ptr(p).toString()+' vm=0x'+ptr(p).sub(ST.slide).toString(16); } catch(e){ return String(p); } }
    var out = [];
    try {
      var ths = Process.enumerateThreads();
      for (var i=0;i<ths.length;i++){
        var t = ths[i]; var e = { id:t.id, state:t.state };
        try { e.pc = vm(t.context.pc); } catch(x){}
        try { e.bt = Thread.backtrace(t.context, Backtracer.FUZZY).slice(0,20).map(vm); } catch(x){ e.bt = 'bt-err:'+x; }
        out.push(e);
      }
    } catch(x){ out.push({err:String(x)}); }
    return out;
  },

  status: function () {
    return { done: ST?ST.done:false, armed: ST?ST.armed:false, result: ST?ST.result:null };
  }
};
"""


def main():
    import frida

    off = json.load(open(OFFSETS))
    ent = next(v for k, v in off.items() if not k.startswith("_"))
    verify = {k: [int(b, 16) for b in s.split()] for k, s in ent.get("verify", {}).items()}
    gff = ent["globals_from_frame"]

    cfg_path = write_cfg()
    if MODE != "revert" and os.path.exists(STATUS):
        os.remove(STATUS)
    if MODE == "hello" and os.path.exists(HELLO):
        os.remove(HELLO)
    for _f in ('/tmp/ttrmod-crash.json',):
        try:
            if os.path.exists(_f): os.remove(_f)
        except Exception: pass
    blob = build_blob(cfg_path)

    params = {
        "image_base": hex(ent["image_base_vmaddr"]),
        "addrs": {k: hex(v) for k, v in ent["addrs"].items()},
        "verify": verify,
        "tstate_ptr": hex(int(str(gff["current_tstate_ptr_vmaddr"]), 0)),
        "frame_off": gff["tstate_to_frame_offset"],
        "globals_off": gff["frame_to_f_globals_offset"],
        "blob": list(blob),
        "noeval": bool(os.environ.get("TTRMOD_NOEVAL")),
        "testobj": bool(os.environ.get("TTRMOD_TESTOBJ")),
        "loadonly": bool(os.environ.get("TTRMOD_LOADONLY")),
    }

    pid = find_pid()
    if not pid:
        raise SystemExit("TTREngine not running")
    print("[ttrmod-frida] mode=%s pid=%d blob=%dB noeval=%s" %
          (MODE, pid, len(blob), params["noeval"]))
    print("[ttrmod-frida] expected blob head: %s" %
          " ".join("%02x" % b for b in blob[:24]))

    done_evt = threading.Event()
    box = {}

    def on_message(message, data):
        if message.get("type") == "send":
            p = message.get("payload") or {}
            if isinstance(p, dict) and p.get("t") == "done":
                box["result"] = p.get("r")
                done_evt.set()
            elif isinstance(p, dict) and p.get("t") == "stage":
                box.setdefault("stages", []).append(p.get("s"))
                print("[stage]", json.dumps(p))
                sys.stdout.flush()
            else:
                print("[agent-msg]", p)
        elif message.get("type") == "error":
            print("[agent-error]", message.get("description") or message)

    def on_detached(reason, *a):
        box["detached"] = reason
        done_evt.set()

    session = frida.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(AGENT_JS)
    script.on("message", on_message)
    script.load()
    ex = script.exports_sync

    init = ex.init(params)
    print("[ttrmod-frida] init:", json.dumps(
        {k: init.get(k) for k in ("ok", "verified", "slide", "notes")}, indent=2))
    if not init.get("ok"):
        print("[ttrmod-frida] init failed:", init.get("notes"))
        session.detach(); return

    arm = ex.arm()
    if not arm.get("ok"):
        print("[ttrmod-frida] arm failed:", arm.get("notes"))
        session.detach(); return
    print("[ttrmod-frida] armed interceptor on _PyEval_EvalFrameDefault (main thread; detached before eval); "
          "it fires within ~1ms (no in-game action needed)...")

    # The hook fires within ~1ms. Short wait: if no 'done' and not detached, the game is
    # likely HUNG (EvalCode deadlock) -> sample all thread stacks to see where it's stuck.
    fired = done_evt.wait(6.0)
    if box.get("detached"):
        print("[ttrmod-frida] !! frida session DETACHED (reason=%s) -- process took a FAULT. "
              "See /tmp/ttrmod-crash.json (+ -bt)." % box.get("detached"))
    elif fired:
        print("[ttrmod-frida] payload ran:", json.dumps(box.get("result"), indent=2))
    else:
        print("[ttrmod-frida] no 'done' in 6s -> likely HUNG in EvalCode. Sampling thread stacks...")
        sbox = {}
        t = threading.Thread(target=lambda: sbox.__setitem__("s", ex.sample()), daemon=True)
        t.start(); t.join(8.0)
        if "s" in sbox:
            open("/tmp/ttrmod-sample.json", "w").write(json.dumps(sbox["s"], indent=2))
            print("[ttrmod-frida] wrote thread sample to /tmp/ttrmod-sample.json (%d threads)" % len(sbox["s"]))
        else:
            print("[ttrmod-frida] sample() also hung (game deeply frozen) -- no stack data")
        os._exit(2)   # don't linger 120s; the game is frozen and needs a relaunch

    if not box.get("detached"):
        try:
            ex.disarm(); script.unload(); session.detach()
        except Exception:
            pass

    for _ in range(30):
        if os.path.exists(STATUS):
            break
        time.sleep(0.1)
    if os.path.exists(STATUS):
        print("[ttrmod-frida] in-process payload status (%s):" % STATUS)
        print(open(STATUS).read())
    elif MODE == "hello":
        print("[ttrmod-frida] hello file present:" , os.path.exists(HELLO))
    else:
        print("[ttrmod-frida] no status file written by payload")


if __name__ == "__main__":
    main()
