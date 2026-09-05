#!/usr/bin/env python3
# Local mechanism-test target. A busy Python loop so _PyEval_EvalFrameDefault fires
# constantly (main thread, GIL held, valid frames) -- the condition our injector needs.
# Owned process; crash it freely.
import os, sys, time

def leaf(i):
    return i * i

def spin(n):
    # sum(map(pyfunc, ...)) forces a C->Python boundary per element, so
    # _PyEval_EvalFrameDefault is entered at its C ABI each call (3.11+ inlines
    # Python->Python calls, so a plain loop would never re-enter it).
    return sum(map(leaf, range(n)))

print("[rig] pid=%d py=%s exe=%s" % (os.getpid(), sys.version.split()[0], sys.executable),
      flush=True)
i = 0
while True:
    spin(200)
    i += 1
    if i % 1000 == 0:
        print("[rig] tick", i, flush=True)
    time.sleep(0.001)
