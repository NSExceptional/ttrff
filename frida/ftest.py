#!/usr/bin/env python3
# Minimal frida sanity test: attach, run a NO-OP agent (no memory reads, no GIL, no
# NativeFunctions), call ping, detach. Cannot freeze the game. Isolates whether
# frida.attach/rpc works on this engine at all.
import sys, time, threading, subprocess

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

AGENT = "rpc.exports = { ping: function(){ return 'pong ' + Process.mainModule.base; } };"

def main():
    import frida
    pid = find_pid()
    print("[ftest] pid=%s" % pid); sys.stdout.flush()

    box = {}
    def work():
        try:
            s = frida.attach(pid); box["attached"] = True
            sc = s.create_script(AGENT); sc.load(); box["loaded"] = True
            box["ping"] = sc.exports_sync.ping()
            sc.unload(); s.detach(); box["done"] = True
        except Exception as e:
            box["err"] = repr(e)

    t = threading.Thread(target=work, daemon=True); t.start(); t.join(8.0)
    print("[ftest] result:", {k: box.get(k) for k in ("attached","loaded","ping","done","err")})
    sys.stdout.flush()
    if "done" not in box:
        print("[ftest] HUNG before completion (last reached: %s)" %
              ("ping" if box.get("loaded") else "load" if box.get("attached") else "attach"))
        import os; os._exit(2)

main()
