#!/usr/bin/env python3
# localtest/wrapafter_test.py -- OFFLINE validation of the "wrap-after" trampoline (milestone-2
# step b): the native C-API port of payload.py's _make_wrap_after / _apply_after. The wrapper:
#   1. calls the ORIGINAL method (bound self + *args + **kwargs) exactly once, captures its result;
#   2. locates the interval the method just started, replicating _apply_after's discovery:
#        - {"attr": A}        -> getattr(self, A)
#        - {"iname_attr": N}  -> self.activeIntervals[getattr(self, N)]
#        - {"iname_sub": S}   -> every self.activeIntervals[k] where S in k
#   3. builds a float `factor` by hand (the step-a recipe) and calls interval.setPlayRate(factor);
#   4. returns the ORIGINAL result (pass-through).
#
# CRITICAL discipline (caused a live crash before -- see abortleak_test.py): every C-API call that
# can fail -- especially each getattr in discovery -- clears the pending exception before control
# returns, so a failed lookup never leaves an exception set on the tstate. Only a genuine exception
# from the ORIGINAL method is propagated (result==NULL short-circuits, exc left intact).
#
# Validated against plain-Python MOCKS whose target method starts a mock "interval" recording
# whether/how setPlayRate was called. Calls are driven DETERMINISTICALLY from inside the hook
# (exactly once each), like trampoline_inject.py's selftest -- no loop race. We prove:
#   - original called exactly once, its result passed through unchanged;
#   - setPlayRate called once with the correct float factor;
#   - iname_sub scales only the substring-matching interval, leaving others untouched;
#   - on a deliberately-missing interval attr the trampoline returns cleanly, result still passed
#     through, and NO exception is left set on the tstate.
#
#   run:  sudo -n env TTRMOD_SCRIPT=localtest/wrapafter_test.py frida/run-injector.sh

import sys, os, time, json, threading, subprocess

TARGET_PY = os.environ.get("TTRMOD_TARGET_PY", "/opt/homebrew/bin/python3.8")

SYMS = {
    "_PyEval_EvalFrameDefault":  "__PyEval_EvalFrameDefault",
    "PyObject_GetAttrString":    "_PyObject_GetAttrString",
    "PyObject_SetAttrString":    "_PyObject_SetAttrString",
    "PyObject_Call":             "_PyObject_Call",
    "PyObject_GetItem":          "_PyObject_GetItem",
    "PyObject_GetIter":          "_PyObject_GetIter",
    "PyIter_Next":               "_PyIter_Next",
    "PyUnicode_AsUTF8":          "_PyUnicode_AsUTF8",
    "PyCFunction_NewEx":         "_PyCFunction_NewEx",
    "PyImport_AddModule":        "_PyImport_AddModule",
    "PyTuple_New":               "_PyTuple_New",
    "PyTuple_Pack":              "_PyTuple_Pack",
    "PyObject_Malloc":           "_PyObject_Malloc",
    "PyFloat_AsDouble":          "_PyFloat_AsDouble",
    "PyLong_AsLong":             "_PyLong_AsLong",
    "PyErr_Occurred":            "_PyErr_Occurred",
    "PyErr_Clear":               "_PyErr_Clear",
    "PyInstanceMethod_Type":     "_PyInstanceMethod_Type",   # DATA
    "PyFloat_Type":              "_PyFloat_Type",            # DATA
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


# Mocks + instances live in the target's __main__. Each scenario's target method starts a mock
# interval and returns a distinctive sentinel int so pass-through is observable.
TARGET_PROG = r"""
import time

class MockInterval:
    def __init__(self, tag=""):
        self.tag = tag
        self.spr_count = 0
        self.last_rate = 0.0
    def setPlayRate(self, f):
        self.spr_count += 1
        self.last_rate = float(f)

class Movie:                       # attr-mode target
    play_count = 0
    def play(self, *a, **k):
        Movie.play_count += 1
        self.track = MockInterval("movie")
        return 4242                # sentinel

class MovieNoTrack:                # attr-mode MISS target (never sets self.track)
    play_count = 0
    def play(self, *a, **k):
        MovieNoTrack.play_count += 1
        return 7                   # sentinel

class Battle:                      # iname_sub target
    join_count = 0
    def makeSuitJoin(self, *a, **k):
        Battle.join_count += 1
        self.iv_match = MockInterval("suit-1-to-pending")
        self.iv_other = MockInterval("other")
        self.activeIntervals = {"suit-1-to-pending": self.iv_match, "other": self.iv_other}
        return 99                  # sentinel

movie = Movie()
movie_nt = MovieNoTrack()
battle = Battle()

t = time.time()
while time.time() - t < 30:
    s = sum(i*i for i in range(300))   # busy: forces C->Python frame-evals so the hook fires
"""


AGENT = r"""
'use strict';
var ST = null;
function cstr(s){ return Memory.allocUtf8String(s); }
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
        base: base, done:false, keep:[],
        frame_eval: at('_PyEval_EvalFrameDefault'),
        GetAttrStr: new NativeFunction(at('PyObject_GetAttrString'), 'pointer', ['pointer','pointer']),
        SetAttrStr: new NativeFunction(at('PyObject_SetAttrString'), 'int',     ['pointer','pointer','pointer']),
        Call:       new NativeFunction(at('PyObject_Call'),          'pointer', ['pointer','pointer','pointer']),
        GetItem:    new NativeFunction(at('PyObject_GetItem'),       'pointer', ['pointer','pointer']),
        GetIter:    new NativeFunction(at('PyObject_GetIter'),       'pointer', ['pointer']),
        IterNext:   new NativeFunction(at('PyIter_Next'),            'pointer', ['pointer']),
        AsUTF8:     new NativeFunction(at('PyUnicode_AsUTF8'),       'pointer', ['pointer']),
        CFuncNewEx: new NativeFunction(at('PyCFunction_NewEx'),      'pointer', ['pointer','pointer','pointer']),
        AddModule:  new NativeFunction(at('PyImport_AddModule'),     'pointer', ['pointer']),
        TupleNew:   new NativeFunction(at('PyTuple_New'),            'pointer', ['long']),
        TuplePack:  new NativeFunction(at('PyTuple_Pack'),           'pointer', ['long','...','pointer']),
        Malloc:     new NativeFunction(at('PyObject_Malloc'),        'pointer', ['ulong']),
        AsDouble:   new NativeFunction(at('PyFloat_AsDouble'),       'double',  ['pointer']),
        AsLong:     new NativeFunction(at('PyLong_AsLong'),          'long',    ['pointer']),
        Occurred:   new NativeFunction(at('PyErr_Occurred'),         'pointer', []),
        Clear:      new NativeFunction(at('PyErr_Clear'),            'void',    []),
        imType:     at('PyInstanceMethod_Type'),
        FloatType:  at('PyFloat_Type'),
      };
      ST.clearExc = function(){ try { if (!ST.Occurred().isNull()) ST.Clear(); } catch(e){} };
      ST.pack1 = function(o){ return ST.TuplePack(1, o); };
      // step-a float builder (pymalloc branch): 24-byte non-GC float, ob_type=&PyFloat_Type.
      ST.makeFloat = function(v){
        var op = ST.Malloc(0x18); if (op.isNull()) return ptr(0);
        op.writeU64(1); op.add(8).writePointer(ST.FloatType); op.add(0x10).writeDouble(v);
        return op;
      };
      // interval.setPlayRate(factor): getattr the method, call it with (factor,). Clears on any miss.
      ST.setPlayRate = function(iv, factorVal){
        var meth = ST.GetAttrStr(iv, cstr('setPlayRate'));
        if (meth.isNull()){ ST.clearExc(); return false; }
        var f = ST.makeFloat(factorVal); if (f.isNull()) return false;
        var r = ST.Call(meth, ST.pack1(f), ptr(0));
        if (r.isNull()){ ST.clearExc(); return false; }
        return true;
      };
      // GENERIC discovery == payload.py's _apply_after (attr / iname_attr / iname_sub).
      // Returns {mode, applied, exc_before, exc_after} -- exc_* only meaningful on a miss path.
      ST.applyAfter = function(inst, spec, factorVal){
        var info = { mode:spec.mode, applied:0 };
        try {
          if (spec.mode === 'attr'){
            var iv = ST.GetAttrStr(inst, cstr(spec.attr));
            if (iv.isNull()){ info.miss=true; info.exc_before = !ST.Occurred().isNull();
                              ST.clearExc(); info.exc_after = ST.Occurred().isNull(); return info; }
            if (ST.setPlayRate(iv, factorVal)) info.applied++;
          } else if (spec.mode === 'iname_attr'){
            var nm = ST.GetAttrStr(inst, cstr(spec.iname_attr));
            if (nm.isNull()){ info.miss=true; ST.clearExc(); return info; }
            var ivals = ST.GetAttrStr(inst, cstr('activeIntervals'));
            if (ivals.isNull()){ info.miss=true; ST.clearExc(); return info; }
            var iv2 = ST.GetItem(ivals, nm);
            if (iv2.isNull()){ info.miss=true; ST.clearExc(); return info; }
            if (ST.setPlayRate(iv2, factorVal)) info.applied++;
          } else if (spec.mode === 'iname_sub'){
            var ivals2 = ST.GetAttrStr(inst, cstr('activeIntervals'));
            if (ivals2.isNull()){ info.miss=true; ST.clearExc(); return info; }
            var it = ST.GetIter(ivals2);                       // iterating a dict yields keys
            if (it.isNull()){ ST.clearExc(); return info; }
            var k;
            while (!(k = ST.IterNext(it)).isNull()){
              var ks = null; try { ks = ST.AsUTF8(k).readCString(); } catch(e){ ks = null; }
              if (ks && ks.indexOf(spec.iname_sub) >= 0){
                var iv3 = ST.GetItem(ivals2, k);
                if (!iv3.isNull()){ if (ST.setPlayRate(iv3, factorVal)) info.applied++; }
                else ST.clearExc();
              }
            }
            ST.clearExc();   // iterator exhaustion is clean, but never leave anything pending
          }
        } catch(e){ info.err = String(e); ST.clearExc(); }
        return info;
      };
      // build a wrap-after NativeCallback (METH_VARARGS|KEYWORDS=0x3): call orig once, discover, return orig result.
      ST.makeWrapAfter = function(orig, spec, factorVal){
        var cb = new NativeCallback(function (self, args, kwargs) {
          var result = ST.Call(orig, args, kwargs.isNull()?ptr(0):kwargs);   // ORIGINAL, exactly once
          if (result.isNull()){ return result; }             // orig raised -> propagate (do NOT clear)
          try {
            var inst = ptr(0);
            try { if (args.add(0x10).readS64().toNumber() >= 1) inst = args.add(0x18).readPointer(); } catch(e){}
            if (!inst.isNull()){ ST.lastDiag = ST.applyAfter(inst, spec, factorVal); }
          } catch(e){ ST.clearExc(); }
          ST.clearExc();                                      // nothing of OURS pending on return
          return result;                                      // pass the original result through
        }, 'pointer', ['pointer','pointer','pointer']);
        ST.keep.push(cb);
        var mname = cstr('ttrmod_wrapafter'); ST.keep.push(mname);
        var mdef = Memory.alloc(32); ST.keep.push(mdef);
        mdef.writePointer(mname); mdef.add(8).writePointer(cb); mdef.add(16).writeU32(0x3); mdef.add(24).writePointer(ptr(0));
        var cfunc = ST.CFuncNewEx(mdef, ptr(0), ptr(0)); if (cfunc.isNull()) return ptr(0);
        ST.keep.push(cfunc);
        var im = ST.Call(ST.imType, ST.pack1(cfunc), ptr(0)); if (im.isNull()) return ptr(0);
        ST.keep.push(im); return im;
      };
      ST.getMain = function(){ return ST.AddModule(cstr('__main__')); };
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },

  arm: function () {
    try {
      ST.listener = Interceptor.attach(ST.frame_eval, {
        onEnter: function () {
          if (ST.done) return; ST.done = true;                 // once, main thread, GIL held
          var R = {};
          // AsLong/AsDouble return native ints/doubles; L() coerces PyLong->JS number for compares.
          function L(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsLong(o); ST.clearExc(); return v.toNumber ? v.toNumber() : v; }
          function D(o){ if (o.isNull()){ ST.clearExc(); return null; } var v = ST.AsDouble(o); ST.clearExc(); return v; }
          try {
            var main = ST.getMain();
            if (main.isNull()){ send({t:'done', r:{ok:false, stage:'no __main__'}}); return; }

            // helper: install `im` on cls.meth, call inst.meth() once, return the call's result ptr.
            function runOne(clsName, instName, meth, spec, factorVal){
              var cls  = ST.GetAttrStr(main, cstr(clsName));
              var inst = ST.GetAttrStr(main, cstr(instName));
              if (cls.isNull() || inst.isNull()){ ST.clearExc(); return {err:'no '+clsName+'/'+instName}; }
              var mn = cstr(meth); ST.keep.push(mn); ST.keep.push(cls); ST.keep.push(inst);
              var orig = ST.GetAttrStr(cls, mn);
              if (orig.isNull()){ ST.clearExc(); return {err:'no '+clsName+'.'+meth}; }
              ST.keep.push(orig);
              ST.lastDiag = null;
              var im = ST.makeWrapAfter(orig, spec, factorVal);
              if (im.isNull()){ return {err:'wrap build NULL'}; }
              var rc = ST.SetAttrStr(cls, mn, im);
              var bound = ST.GetAttrStr(inst, mn);              // -> our im, bound to inst
              var res = bound.isNull() ? ptr(0) : ST.Call(bound, ST.TupleNew(0), ptr(0));
              ST.SetAttrStr(cls, mn, orig);                     // revert immediately
              var rl = res.isNull()? null : ST.AsLong(res); ST.clearExc();
              return { setattr_rc:rc, res_null:res.isNull(),
                       res_long: (rl===null)? null : (rl.toNumber? rl.toNumber() : rl),
                       diag: ST.lastDiag, inst:inst, cls:cls };
            }

            // ---------- scenario HIT: attr-mode (Movie.play, attr='track', factor 5.0) ----------
            var h = runOne('Movie', 'movie', 'play', {mode:'attr', attr:'track'}, 5.0);
            var movie = h.inst;
            var play_count = L(ST.GetAttrStr(movie, cstr('play_count')));
            var track = ST.GetAttrStr(movie, cstr('track'));
            var spr_count = track.isNull()? null : L(ST.GetAttrStr(track, cstr('spr_count')));
            var last_rate = track.isNull()? null : D(ST.GetAttrStr(track, cstr('last_rate')));
            ST.clearExc();
            R.hit = { orig_called_once: (play_count === 1),
                      result_passed_through: (h.res_long === 4242),
                      setPlayRate_calls: spr_count,
                      setPlayRate_factor: last_rate,
                      diag: h.diag };

            // ---------- scenario MISS: attr absent (MovieNoTrack.play, attr='track') ----------
            var mm = runOne('MovieNoTrack', 'movie_nt', 'play', {mode:'attr', attr:'track'}, 5.0);
            var occ_after = ST.Occurred().isNull();             // nothing left on the tstate?
            R.miss = { orig_called_once: (L(ST.GetAttrStr(mm.cls, cstr('play_count'))) === 1),
                       result_passed_through: (mm.res_long === 7),
                       getattr_missed: !!(mm.diag && mm.diag.miss),
                       exc_set_before_clear: !!(mm.diag && mm.diag.exc_before),
                       exc_after_clear: (mm.diag && mm.diag.exc_after) ? 'CLEARED' : 'STILL-SET',
                       tstate_clean_after_call: occ_after };
            ST.clearExc();

            // ---------- scenario SUB: iname_sub (Battle.makeSuitJoin, sub='to-pending', factor 3.0) ----------
            var s = runOne('Battle', 'battle', 'makeSuitJoin', {mode:'iname_sub', iname_sub:'to-pending'}, 3.0);
            var battle = s.inst;
            var iv_match = ST.GetAttrStr(battle, cstr('iv_match'));
            var iv_other = ST.GetAttrStr(battle, cstr('iv_other'));
            R.sub = { orig_called_once: (L(ST.GetAttrStr(s.cls, cstr('join_count'))) === 1),
                      result_passed_through: (s.res_long === 99),
                      matched_interval_rate:  iv_match.isNull()? null : D(ST.GetAttrStr(iv_match, cstr('last_rate'))),
                      matched_spr_calls:      iv_match.isNull()? null : L(ST.GetAttrStr(iv_match, cstr('spr_count'))),
                      other_interval_rate:    iv_other.isNull()? null : D(ST.GetAttrStr(iv_other, cstr('last_rate'))),
                      other_spr_calls:        iv_other.isNull()? null : L(ST.GetAttrStr(iv_other, cstr('spr_count'))),
                      matched_count:          (s.diag && s.diag.applied) };
            ST.clearExc();

            R.ok = !!(R.hit.orig_called_once && R.hit.result_passed_through &&
                      R.hit.setPlayRate_calls === 1 && R.hit.setPlayRate_factor === 5.0 &&
                      R.miss.orig_called_once && R.miss.result_passed_through &&
                      R.miss.getattr_missed && R.miss.exc_set_before_clear &&
                      R.miss.exc_after_clear === 'CLEARED' && R.miss.tstate_clean_after_call &&
                      R.sub.orig_called_once && R.sub.result_passed_through &&
                      R.sub.matched_interval_rate === 3.0 && R.sub.matched_spr_calls === 1 &&
                      R.sub.other_spr_calls === 0);
            if (!ST.Occurred().isNull()) ST.Clear();
            try { Interceptor.detachAll(); Interceptor.flush(); } catch(e){}
            send({t:'done', r:R});
          } catch(e){ try{ST.Clear();}catch(_){} send({t:'done', r:{ok:false, stage:'arm ex', e:String(e)}}); }
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
    tgt = subprocess.Popen([TARGET_PY, "-c", TARGET_PROG]); time.sleep(0.4)
    print("[wrapafter] target_py=%s pid=%d" % (TARGET_PY, tgt.pid))

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
    init = ex.init({"offsets": {k: hex(v) for k, v in offsets.items()}, "module_path": dylib})
    if not init.get("ok"):
        print("[wrapafter] init failed:", json.dumps(init, indent=2)); tgt.kill(); return
    ex.arm()
    if not done.wait(15.0):
        print("[wrapafter] hook never fired in 15s")
    elif box.get("detached"):
        print("[wrapafter] !! DETACHED (%s) -- target crashed" % box["detached"])
    else:
        print("[wrapafter] result:", json.dumps(box.get("r"), indent=2))
    time.sleep(1.0)    # a leaked exception would surface here
    alive = tgt.poll() is None
    r = box.get("r") or {}
    verdict = bool(r.get("ok") and alive)
    print("[wrapafter] target_alive=%s" % alive)
    print("[wrapafter] VERDICT: %s" % (
        "PASS -- original called once + result passed through; setPlayRate(5.0) once (attr); "
        "iname_sub scaled only the matching interval; clean miss with the tstate exception cleared"
        if verdict else "FAIL -- see result above"))
    try: tgt.kill(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
