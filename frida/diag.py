#!/usr/bin/env python3
# frida/diag.py -- SAFE diagnostic. Hooks a few candidate CPython C-API functions with
# pure COUNTERS (no payload, no reentrant eval, no NativeFunction work) for a few
# seconds, to learn which one actually fires during steady-state gameplay and whether a
# live globals dict is reachable from it. Cannot run the payload; cannot storm; the
# counters are cheap. Use this to choose the real injection hook.
#
#   sudo -n TTRMOD_SCRIPT=frida/diag.py /Users/tanner/Developer/ttr-mods/frida/run-injector.sh
#
# Reports, after WINDOW seconds:
#   eval_code   : how many PyEval_EvalCode calls (module exec/import)
#   gil_ensure  : how many PyGILState_Ensure calls, and of those how many had a live
#                 current-thread frame with non-NULL f_globals (=> usable globals there)
# NOTE: intentionally does NOT hook _PyEval_EvalFrameDefault (the hyper-hot recursive
# frame evaluator) -- hooking it crashed the engine before. This diag is read-only.

import os
import sys
import json
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OFFSETS = os.path.join(ROOT, "offsets.json")
WINDOW = float(os.environ.get("TTRMOD_DIAG_WINDOW", "6"))


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
var C = { eval_code:0, gil_ensure:0, gil_with_globals:0, sample_gd:null };
var S = null;

rpc.exports = {
  init: function (p) {
    var out = { ok:false, verified:false, notes:[] };
    try {
      var base = Process.mainModule.base;
      var slide = base.sub(ptr(p.image_base));
      function rt(v){ return ptr(v).add(slide); }
      var A = {};
      for (var k in p.addrs){ A[k] = rt(p.addrs[k]); }
      // verify the two we hook + the tstate read
      var chk = ['eval_code','gil_ensure'];
      for (var i=0;i<chk.length;i++){
        var k=chk[i], want=p.verify[k];
        var got=new Uint8Array(A[k].readByteArray(want.length));
        for (var j=0;j<want.length;j++){ if(got[j]!==want[j]){ out.notes.push('verify '+k+' FAILED'); return out; } }
      }
      out.verified = true;
      S = { A:A, tstate_ptr: rt(p.tstate_ptr), frame_off:p.frame_off, globals_off:p.globals_off };

      Interceptor.attach(A.eval_code, { onEnter: function(){ C.eval_code++; } });
      Interceptor.attach(A.gil_ensure, { onLeave: function(){
        C.gil_ensure++;
        try {
          var tsp = S.tstate_ptr.readPointer(); if (tsp.isNull()) return;
          var fr = tsp.add(S.frame_off).readPointer(); if (fr.isNull()) return;
          var gd = fr.add(S.globals_off).readPointer(); if (gd.isNull()) return;
          C.gil_with_globals++;
          if (!C.sample_gd) C.sample_gd = gd.toString();
        } catch(e){}
      }});
      out.ok = true; return out;
    } catch(e){ out.notes.push('init ex: '+e); return out; }
  },
  counts: function(){ return C; }
};
"""


def main():
    import frida
    off = json.load(open(OFFSETS))
    ent = next(v for k, v in off.items() if not k.startswith("_"))
    verify = {k: [int(b, 16) for b in s.split()] for k, s in ent.get("verify", {}).items()}
    gff = ent["globals_from_frame"]
    params = {
        "image_base": hex(ent["image_base_vmaddr"]),
        "addrs": {k: hex(v) for k, v in ent["addrs"].items()},
        "verify": {k: verify[k] for k in ("eval_code", "gil_ensure")},
        "tstate_ptr": hex(int(str(gff["current_tstate_ptr_vmaddr"]), 0)),
        "frame_off": gff["tstate_to_frame_offset"],
        "globals_off": gff["frame_to_f_globals_offset"],
    }
    pid = find_pid()
    if not pid:
        raise SystemExit("TTREngine not running")
    print("[diag] pid=%d window=%.0fs" % (pid, WINDOW))
    session = frida.attach(pid)
    script = session.create_script(AGENT_JS)
    script.load()
    ex = script.exports_sync
    init = ex.init(params)
    print("[diag] init:", json.dumps(init, indent=2))
    if not init.get("ok"):
        session.detach(); return
    print("[diag] counting for %.0fs -- PLAY NORMALLY (walk, fight, open UI)..." % WINDOW)
    time.sleep(WINDOW)
    counts = ex.counts()
    print("[diag] counts over %.0fs:" % WINDOW, json.dumps(counts, indent=2))
    rate = counts["gil_ensure"] / WINDOW
    print("[diag] gil_ensure ~%.1f/s; %d of them had usable f_globals; eval_code=%d"
          % (rate, counts["gil_with_globals"], counts["eval_code"]))
    try:
        script.unload(); session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
