#!/usr/bin/env python3
# localtest/pyfloat_test.py -- OFFLINE validation of the MANUAL PyFloat builder that the live
# route needs (milestone-2 step a). In the engine `PyFloat_FromDouble` is INLINED (no exported
# symbol), so we must build a float object by raw memory per the STATUS.md recipe:
#
#   float = 24-byte NON-GC object; pop the float free-list head (decrement numfree) else pymalloc;
#   set ob_refcnt=1 @ +0, ob_type=&PyFloat_Type @ +8, ob_fval(double) @ +0x10.
#
# We cannot run this against the live binary, so we build the EQUIVALENT on a stock arm64
# CPython 3.8 we own: resolve this interpreter's own PyFloat_Type + float free-list layout,
# construct floats via raw memory the SAME way (both the free-list-pop branch and the pymalloc
# branch), and prove round-trip:
#   - read back via ob_fval @ +0x10 AND via the exported PyFloat_AsDouble,
#   - use the built float as an operand in arithmetic (PyNumber_Add),
#   - use it as an argument in a real Python function call (triple(x) -> x*3).
#
# This validates the BUILD MECHANICS and layout assumptions so the identical code against the
# game's 3.8.17 (same struct layout, different addresses) will work. Stock-vs-game offset notes
# are printed at the end.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/pyfloat_test.py frida/run-injector.sh

import sys, os, re, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")

# C name -> Mach-O export-trie symbol (leading-underscore convention; names already starting with
# _ get a second underscore). Mix of functions and DATA (PyFloat_Type).
SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyObject_Call":             "_PyObject_Call",
    "PyImport_AddModule":        "_PyImport_AddModule",
    "PyObject_Malloc":           "_PyObject_Malloc",       # == the engine's pymalloc branch
    "PyFloat_AsDouble":          "_PyFloat_AsDouble",       # read-back cross-check
    "PyNumber_Add":              "_PyNumber_Add",           # arithmetic round-trip
    "PyNumber_Float":            "_PyNumber_Float",
    "PyTuple_Pack":              "_PyTuple_Pack",           # build (F,) for the call round-trip
    "PyFloat_FromDouble":        "_PyFloat_FromDouble",     # cross-check + free-list disasm anchor
    "PyFloat_Type":              "_PyFloat_Type",           # DATA: the type object (== game 0x101aae5c8)
    "PyErr_Occurred":            "_PyErr_Occurred",
    "PyErr_Clear":               "_PyErr_Clear",
}

# game-side reference values (STATUS.md reference tables), printed for the stock-vs-game diff.
GAME = {
    "PyFloat_Type":     0x101aae5c8,
    "float_free_list":  0x101be9588,
    "float_numfree":    0x101be9590,
    "ob_fval_off":      0x10,
    "ob_type_off":      0x8,
    "basicsize":        0x18,
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


def resolve_freelist(dylib, fromdouble_off):
    """The offline analog of RE'ing the game: disassemble PyFloat_FromDouble and read the two
    global accesses at entry -- `ldr x?, [x?, #off]` (the free-list head) and the 32-bit
    `ldr w?, [x?, #off]` (numfree). Returns (free_list_off, numfree_off). These are file-scope
    statics (NOT exported), exactly like the game where they were hand-located at fixed vmaddrs."""
    out = subprocess.run(["otool", "-arch", "arm64", "-tV", dylib], capture_output=True, text=True).stdout
    lines = out.splitlines()
    start = None
    for i, ln in enumerate(lines):
        head = ln.split(None, 1)[0] if ln.split() else ""
        if re.fullmatch(r"[0-9a-fA-F]{8,16}", head) and int(head, 16) == fromdouble_off:
            start = i
            break
    if start is None:
        return None, None
    page = {}   # reg -> resolved adrp page address
    free_list = numfree = None
    for ln in lines[start:start + 30]:
        m_adrp = re.search(r"\badrp\s+(x\d+),.*;\s*0x([0-9a-fA-F]+)", ln)
        if m_adrp:
            page[m_adrp.group(1)] = int(m_adrp.group(2), 16)
            continue
        m_ldr = re.search(r"\bldr\s+([wx]\d+),\s*\[(x\d+),\s*#0x([0-9a-fA-F]+)\]", ln)
        if m_ldr:
            dst, base, disp = m_ldr.group(1), m_ldr.group(2), int(m_ldr.group(3), 16)
            if base in page:
                addr = page[base] + disp
                if dst.startswith("x") and free_list is None:
                    free_list = addr
                elif dst.startswith("w") and numfree is None:
                    numfree = addr
            if free_list is not None and numfree is not None:
                break
    return free_list, numfree


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
        base: base, done:false,
        frame_eval: at('_PyEval_EvalFrameDefault'),
        GetAttrStr: new NativeFunction(at('PyObject_GetAttrString'), 'pointer', ['pointer','pointer']),
        Call:       new NativeFunction(at('PyObject_Call'),          'pointer', ['pointer','pointer','pointer']),
        AddModule:  new NativeFunction(at('PyImport_AddModule'),     'pointer', ['pointer']),
        Malloc:     new NativeFunction(at('PyObject_Malloc'),        'pointer', ['ulong']),
        AsDouble:   new NativeFunction(at('PyFloat_AsDouble'),       'double',  ['pointer']),
        NumberAdd:  new NativeFunction(at('PyNumber_Add'),           'pointer', ['pointer','pointer']),
        TuplePack:  new NativeFunction(at('PyTuple_Pack'),           'pointer', ['long','...','pointer']),
        FromDouble: new NativeFunction(at('PyFloat_FromDouble'),     'pointer', ['double']),
        Occurred:   new NativeFunction(at('PyErr_Occurred'),         'pointer', []),
        Clear:      new NativeFunction(at('PyErr_Clear'),            'void',    []),
        FloatType:  at('PyFloat_Type'),
        free_list:  p.free_list_off != null ? base.add(ptr(p.free_list_off)) : null,
        numfree:    p.numfree_off   != null ? base.add(ptr(p.numfree_off))   : null,
        FTYPE_OFF: 0x8, FVAL_OFF: 0x10, BASICSIZE: 0x18, DEALLOC_OFF: 0x30,
      };
      out.free_list = ST.free_list ? ST.free_list.toString() : null;
      out.numfree   = ST.numfree   ? ST.numfree.toString()   : null;
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },

  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function () {
          if (ST.done) return; ST.done = true;                 // once, main thread, GIL held
          var R = { ok:false };
          try {
            // ---- shared field-setter mirroring the engine recipe ----
            function setFields(op, v){
              op.writeU64(1);                                    // ob_refcnt = 1   (+0)
              op.add(ST.FTYPE_OFF).writePointer(ST.FloatType);   // ob_type = &PyFloat_Type (+8)
              op.add(ST.FVAL_OFF).writeDouble(v);                // ob_fval = v     (+0x10)
              return op;
            }
            // ---- BUILD via the pymalloc branch (recipe else-path) ----
            function makeFloatMalloc(v){
              var op = ST.Malloc(ST.BASICSIZE);                  // 24 bytes, pymalloc (== engine ctx/fn deref)
              if (op.isNull()) return ptr(0);
              return setFields(op, v);
            }
            // ---- BUILD via the free-list branch (recipe if-path) ----
            function makeFloatFreelist(v){
              if (!ST.free_list) return ptr(0);
              var head = ST.free_list.readPointer();
              if (head.isNull()) return ptr(0);                  // caller must pre-populate
              var next = head.add(ST.FTYPE_OFF).readPointer();   // next stored in ob_type slot (+8)
              ST.free_list.writePointer(next);                   // free_list = head->next
              if (ST.numfree) ST.numfree.writeS32(ST.numfree.readS32() - 1);   // numfree--
              return setFields(head, v);
            }

            // =================== (1) MALLOC-branch build of 2.0 ===================
            var F = makeFloatMalloc(2.0);
            if (F.isNull()){ R.stage='malloc float NULL'; send({t:'done', r:R}); return; }
            R.malloc = {
              ob_type_is_PyFloat: F.add(ST.FTYPE_OFF).readPointer().equals(ST.FloatType),
              raw_ob_fval:        F.add(ST.FVAL_OFF).readDouble(),        // manual read @ +0x10
              as_double:          ST.AsDouble(F),                        // exported PyFloat_AsDouble
            };
            // arithmetic: F + F -> 4.0
            var G = ST.NumberAdd(F, F);
            R.malloc.add_result = G.isNull() ? null : ST.AsDouble(G);
            R.malloc.add_type_is_PyFloat = (!G.isNull()) && G.add(ST.FTYPE_OFF).readPointer().equals(ST.FloatType);
            // function-call round-trip: triple(F) -> 6.0  (proves it's a first-class arg)
            var main = ST.AddModule(Memory.allocUtf8String('__main__'));
            var triple = ST.GetAttrStr(main, Memory.allocUtf8String('triple'));
            if (!triple.isNull()){
              var args = ST.TuplePack(1, F);                             // (F,)  (Pack increfs F)
              var H = ST.Call(triple, args, ptr(0));
              R.malloc.call_result = H.isNull() ? null : ST.AsDouble(H);
            } else { ST.Clear(); R.malloc.call_result = 'no triple'; }

            // =================== (2) FREE-LIST-branch build of 3.0 ===================
            // Populate the free-list deterministically: build a float with the REAL FromDouble,
            // then push it back with the type's own tp_dealloc (float_dealloc) so free_list==it.
            // This also CROSS-CHECKS that the host-discovered free_list address is the real one.
            if (ST.free_list){
              var Fr = ST.FromDouble(1.5);
              var deallocPtr = ST.FloatType.add(ST.DEALLOC_OFF).readPointer();  // tp_dealloc @ +0x30
              var Dealloc = new NativeFunction(deallocPtr, 'void', ['pointer']);
              Dealloc(Fr);                                                // float_dealloc(Fr): pushes to free-list
              var head_now = ST.free_list.readPointer();
              var numfree_before = ST.numfree ? ST.numfree.readS32() : null;
              var cross_ok = head_now.equals(Fr);                         // discovered addr is the real free_list
              var popped = makeFloatFreelist(3.0);                        // recipe if-branch: pop head, relink, count--
              R.freelist = {
                cross_check_head_is_freed: cross_ok,
                popped_is_reused_slot:     (!popped.isNull()) && popped.equals(Fr),   // pop reused Fr's memory
                numfree_before:            numfree_before,
                numfree_after:             ST.numfree ? ST.numfree.readS32() : null,
                raw_ob_fval:               popped.isNull() ? null : popped.add(ST.FVAL_OFF).readDouble(),
                as_double:                 popped.isNull() ? null : ST.AsDouble(popped),
                ob_type_is_PyFloat:        (!popped.isNull()) && popped.add(ST.FTYPE_OFF).readPointer().equals(ST.FloatType),
              };
            } else {
              R.freelist = { skipped: 'free_list address not discovered host-side' };
            }

            // final verdict
            var mv = R.malloc, fv = R.freelist || {};
            R.ok = !!(mv.ob_type_is_PyFloat && mv.raw_ob_fval === 2.0 && mv.as_double === 2.0 &&
                      mv.add_result === 4.0 && mv.call_result === 6.0);
            R.freelist_ok = !!(fv.cross_check_head_is_freed && fv.popped_is_reused_slot &&
                               fv.as_double === 3.0 && fv.ob_type_is_PyFloat &&
                               (fv.numfree_after === null || fv.numfree_after === fv.numfree_before - 1));
            if (!ST.Occurred().isNull()) ST.Clear();
            try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
            send({t:'done', r:R});
          } catch(e){ try{ST.Clear();}catch(_){} R.err=String(e); send({t:'done', r:R}); }
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
    free_list_off, numfree_off = resolve_freelist(dylib, offsets["PyFloat_FromDouble"])
    if free_list_off is None:
        # fallback for the pinned 3.8.14 build if the disasm parse ever changes format
        free_list_off, numfree_off = 0x225300, 0x225308
        print("[pyfloat] free-list disasm parse failed; using pinned 3.8.14 fallback offsets")
    print("[pyfloat] dylib=%s" % dylib)
    print("[pyfloat] exported offsets: %s" % {k: hex(v) for k, v in offsets.items()})
    print("[pyfloat] discovered free_list@+%s  numfree@+%s (host-side disasm of PyFloat_FromDouble)"
          % (hex(free_list_off), hex(numfree_off)))

    # target: define triple() then idle-loop (busy genexpr forces C->Python frame-evals so the hook fires)
    prog = ("import time\n"
            "def triple(x):\n"
            "    return x * 3\n"
            "t = time.time()\n"
            "while time.time() - t < 30:\n"
            "    s = sum(i*i for i in range(300))\n")
    tgt = subprocess.Popen([TARGET_PY, "-c", prog]); time.sleep(0.4)
    print("[pyfloat] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
                    "free_list_off": hex(free_list_off), "numfree_off": hex(numfree_off)})
    print("[pyfloat] init:", json.dumps(init, indent=2))
    if init.get("ok"):
        ex.arm()
        if not done.wait(15.0):
            print("[pyfloat] hook never fired in 15s")
        elif box.get("detached"):
            print("[pyfloat] !! DETACHED (%s) -- target crashed during build" % box["detached"])
        else:
            print("[pyfloat] result:", json.dumps(box.get("r"), indent=2))
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and r.get("freelist_ok") and alive)
    print("[pyfloat] target_alive=%s" % alive)
    print("[pyfloat] VERDICT: %s" % (
        "PASS -- hand-built float (malloc AND free-list branch) round-trips via ob_fval, "
        "PyFloat_AsDouble, arithmetic, and a function call; layout matches the game recipe"
        if verdict else "FAIL -- see result above"))
    # stock-vs-game offset diff
    print("[pyfloat] stock-vs-game layout: ob_type_off=+0x8 (game +0x8), ob_fval_off=+0x10 "
          "(game +0x10), basicsize=0x18 (game 0x18) -- IDENTICAL. Only the absolute addresses "
          "differ: stock PyFloat_Type=%s free_list=%s numfree=%s ; game PyFloat_Type=%s "
          "free_list=%s numfree=%s."
          % (init.get("resolved", {}).get("PyFloat_Type"), init.get("free_list"), init.get("numfree"),
             hex(GAME["PyFloat_Type"]), hex(GAME["float_free_list"]), hex(GAME["float_numfree"])))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
