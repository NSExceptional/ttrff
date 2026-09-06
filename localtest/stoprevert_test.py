#!/usr/bin/env python3
# localtest/stoprevert_test.py -- OFFLINE validation of the CRASH-SAFE STOP + REVERT path.
#
# THE BUG THIS GUARDS. In persistent (modset "play") mode the host stays resident, and on stop it MUST
# revert EVERY installed wrap BEFORE the frida session drops -- the trampolines live in the agent's
# memory and die with the session, so any wrap still installed then points at freed memory and the
# constantly-firing MetaInterval.start hook crashes the game on the very next interval start. The live
# crash was exactly this: Ctrl+C on the compiled runner (frida/ttr-frida-runner, under sudo) killed the
# process BEFORE the host's revert ran, leaving the hook dangling. The fix: a STOP FILE polled in the
# resident loop (the reliable path), a SIGTERM handler, and a revert that restores ALL wraps and
# detaches ONLY once confirmed -- staying attached (game alive) if it can't confirm.
#
# WHAT THIS PROVES (drives the REAL host functions in frida/trampoline_inject.py against a faithful
# fake agent -- no frida, no root, no live game, fully deterministic):
#   1. revert enumerates & restores ALL installed wraps (start-wrap + a context wrap + more) -- assert
#      NONE remain installed -- and detaches only after that;
#   2. the STOP FILE triggers a graceful stop (wait_for_stop returns 'stop-file'), and the file is
#      consumed after a confirmed revert+detach (so a stale file never poisons the next run);
#   3. a real SIGTERM triggers the same graceful stop;
#   4. a revert that CANNOT be confirmed (game idle/frozen) does NOT detach -- it stays attached;
#   5. a revert where a setattr FAILS (a wrap would still dangle) does NOT detach either;
#   6. bounded (test/poll) modes still terminate on timeout;
#   7. exception-clean throughout; request_stop is idempotent (first reason wins).
#
#   run:  python3 localtest/stoprevert_test.py      (any python3; no root/frida/target needed)

import os
import sys
import time
import signal
import tempfile
import threading
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load_injector():
    """Import frida/trampoline_inject.py by path. It imports NO frida at module load (frida is
    imported inside main()), so this is safe under any python3 with no root/target."""
    path = os.path.join(ROOT, "frida", "trampoline_inject.py")
    spec = importlib.util.spec_from_file_location("trampoline_inject", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ti = load_injector()


class FakeAgent:
    """Faithful model of the frida agent's install/revert (ST.installed + ST.recordInstall + the
    revert() rpc export in frida/trampoline_inject.py). class_table maps (cls, method) -> the current
    handler; installing a wrap sets a TRAMPOLINE sentinel; revert() enumerates ST.installed and
    restores each recorded original, then posts a 'reverted' message (rc + all_ok) into the host box +
    Event exactly as the real on_msg callback does.

    mode:
      'live'   -- the revert hook fires immediately (a running game), restoring wraps + confirming.
      'frozen' -- the one-shot hook is armed but NEVER fires (game idle/frozen): revert() does nothing
                  (no restore, no confirm) -- the host must then NOT detach.
    fail_methods -- methods whose setattr-restore 'fails' (rc != 0): they are NOT restored, all_ok is
                    False -- the host must NOT detach (a dangling wrap would crash the game)."""

    TRAMP = "TRAMPOLINE"

    def __init__(self, box, rev, mode="live", fail_methods=()):
        self.box = box
        self.rev = rev
        self.mode = mode
        self.fail = set(fail_methods)
        self.installed = []           # mirrors ST.installed (via record_install == ST.recordInstall)
        self.class_table = {}         # (cls, method) -> current handler
        self.revert_calls = 0

    # ST.recordInstall + the SetAttrStr that installs the trampoline, in one step.
    def install(self, cls, method):
        orig = "orig:%s.%s" % (cls, method)
        self.class_table[(cls, method)] = self.TRAMP          # class attr now points at our trampoline
        self.installed.append({"cls": cls, "mn": method, "orig": orig})   # recorded so revert restores it

    # rpc exports the host calls:
    def fires(self):
        return len(self.installed)

    def appliedBy(self):
        return {}

    def scaledInfo(self):
        return {}

    def revert(self):
        self.revert_calls += 1
        if self.mode == "frozen":
            return {"ok": True}       # hook armed but never fires -> no restore, no 'reverted' message
        rcs = []
        all_ok = True
        for it in self.installed:
            key = (it["cls"], it["mn"])
            if it["mn"] in self.fail:
                rcs.append(-1)        # setattr-restore failed -> wrap left installed
                all_ok = False
            else:
                self.class_table[key] = it["orig"]   # restore original
                rcs.append(0)
        # deliver the 'reverted' message the way main()'s on_msg does:
        self.box["revert_rc"] = rcs
        self.box["revert_ok"] = bool(all_ok)
        self.box["reverted"] = True
        self.rev.set()
        return {"ok": True, "n": len(self.installed)}

    def remaining_installed(self):
        """Wraps whose class attr still points at our trampoline (i.e. NOT restored)."""
        return sorted("%s.%s" % k for k, v in self.class_table.items() if v == self.TRAMP)


class FakeSession:
    def __init__(self):
        self.detach_calls = 0

    def detach(self):
        self.detach_calls += 1


def counting_alive(true_for):
    """alive_check that returns True for the first `true_for` calls, then False (game 'gone')."""
    state = {"n": 0}

    def _c():
        state["n"] += 1
        return state["n"] <= true_for
    return _c


# ------------------------------- the cases -------------------------------
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name, (" -- " + detail) if detail else ""))


def case_revert_restores_all():
    """(1) Install a start-wrap + a context wrap + more; a CONFIRMED revert restores ALL of them
    (assert NONE remain installed) and detaches exactly once."""
    box = {}
    rev = threading.Event()
    ag = FakeAgent(box, rev, mode="live")
    # the exact shape modset installs: the MetaInterval.start wrap-after + the tunnelOut/tunnelIn
    # context wrap-arounds + (for good measure) a second interval class's start.
    ag.install("MetaInterval", "start")      # the constantly-firing wrap -- the dangerous one
    ag.install("LocalToon", "tunnelOut")     # context wrap-around (departure)
    ag.install("LocalToon", "tunnelIn")      # context wrap-around (arrival)
    ag.install("Interval", "start")          # a second start wrap (non-Meta intervals)
    before = ag.remaining_installed()
    sess = FakeSession()
    ok = ti.revert_and_detach(ag, sess, box, rev, "start/tunnelOut/tunnelIn",
                              alive_check=lambda: True, confirm_timeout=0.5,
                              log=lambda *a: None)
    after = ag.remaining_installed()
    check("several wraps were installed (>=4)", len(before) >= 4, "installed=%s" % before)
    check("revert_and_detach returned True (confirmed)", ok is True)
    check("NONE remain installed after revert", after == [], "remaining=%s" % after)
    check("all revert rc == 0", box.get("revert_ok") is True and all(x == 0 for x in box.get("revert_rc", [1])))
    check("session.detach() called exactly once", sess.detach_calls == 1, "calls=%d" % sess.detach_calls)


def case_no_confirm_no_detach():
    """(4) A revert that can't confirm (frozen game) must NOT detach -- stay attached until the game
    is gone (trampolines then moot)."""
    box = {}
    rev = threading.Event()
    ag = FakeAgent(box, rev, mode="frozen")
    ag.install("MetaInterval", "start")
    ag.install("LocalToon", "tunnelOut")
    sess = FakeSession()
    # alive: True at start + True after the 1st timeout, then False (game closed) -> give up, no detach.
    ok = ti.revert_and_detach(ag, sess, box, rev, "start/tunnelOut",
                              alive_check=counting_alive(2), confirm_timeout=0.05,
                              log=lambda *a: None)
    check("frozen revert: session.detach() NEVER called", sess.detach_calls == 0, "calls=%d" % sess.detach_calls)
    check("frozen revert: returned False (gave up, stayed safe)", ok is False)
    check("frozen revert: wraps left INSTALLED (attached => no dangle)", ag.remaining_installed() != [])


def case_failed_setattr_no_detach():
    """(5) If a setattr-restore FAILS (a wrap would still dangle), do NOT detach."""
    box = {}
    rev = threading.Event()
    ag = FakeAgent(box, rev, mode="live", fail_methods={"tunnelOut"})
    ag.install("MetaInterval", "start")
    ag.install("LocalToon", "tunnelOut")     # this one's restore will 'fail'
    sess = FakeSession()
    ok = ti.revert_and_detach(ag, sess, box, rev, "start/tunnelOut",
                              alive_check=counting_alive(3), confirm_timeout=0.05,
                              log=lambda *a: None)
    check("failed setattr: session.detach() NEVER called", sess.detach_calls == 0, "calls=%d" % sess.detach_calls)
    check("failed setattr: returned False", ok is False)
    check("failed setattr: the failing wrap is still flagged installed",
          "LocalToon.tunnelOut" in ag.remaining_installed(), "remaining=%s" % ag.remaining_installed())
    check("failed setattr: host retried the revert (re-armed)", ag.revert_calls >= 2, "revert_calls=%d" % ag.revert_calls)


def case_stopfile_triggers_stop():
    """(2) The STOP FILE makes wait_for_stop return 'stop-file'."""
    box = {}
    stop = ti.make_stop_state()
    fd, sf = tempfile.mkstemp(prefix="ttrmod-stop-test-")
    os.close(fd)  # file EXISTS -> should stop immediately
    try:
        reason = ti.wait_for_stop(box, stop, sf, persist=True, poll_s=0.0,
                                  fires_fn=lambda: 0, log=lambda *a: None, tick=0.01)
        check("stop file => wait_for_stop returns 'stop-file'", reason == "stop-file", "reason=%r" % reason)
        check("stop file => stop state reason recorded", stop["stop"] and stop["reason"] == "stop-file")
    finally:
        if os.path.exists(sf):
            os.remove(sf)


def case_full_stopfile_flow_consumes_file():
    """(2) Full flow: stop file present -> wait_for_stop stops -> confirmed revert+detach ->
    clear_stopfile CONSUMES it (mirrors main()'s exact teardown)."""
    box = {}
    rev = threading.Event()
    stop = ti.make_stop_state()
    ag = FakeAgent(box, rev, mode="live")
    ag.install("MetaInterval", "start")
    ag.install("LocalToon", "tunnelOut")
    sess = FakeSession()
    fd, sf = tempfile.mkstemp(prefix="ttrmod-stop-test-")
    os.close(fd)
    try:
        reason = ti.wait_for_stop(box, stop, sf, persist=True, poll_s=0.0,
                                  fires_fn=ag.fires, log=lambda *a: None, tick=0.01)
        ok = ti.revert_and_detach(ag, sess, box, rev, "start/tunnelOut",
                                  alive_check=lambda: True, confirm_timeout=0.5, log=lambda *a: None)
        ti.clear_stopfile(sf)     # main() consumes the file after revert+detach
        check("full flow: stopped via stop-file", reason == "stop-file")
        check("full flow: revert confirmed + detached", ok is True and sess.detach_calls == 1)
        check("full flow: NONE remain installed", ag.remaining_installed() == [])
        check("full flow: stop file consumed (removed)", not os.path.exists(sf))
    finally:
        if os.path.exists(sf):
            os.remove(sf)


def case_sigterm_triggers_stop():
    """(3) A real SIGTERM (kill -TERM) makes wait_for_stop return 'SIGTERM'. Delivered from a
    background thread while the loop is running; a bounded poll_s is a safety net so the test can
    never hang."""
    box = {}
    stop = ti.make_stop_state()
    prev = ti.install_sigterm(stop, log=lambda *a: None)   # must run on the main thread
    try:
        def _fire():
            time.sleep(0.15)
            os.kill(os.getpid(), signal.SIGTERM)
        th = threading.Thread(target=_fire, daemon=True)
        th.start()
        t0 = time.time()
        # persist=False with poll_s=5.0 as a HARD safety timeout (returns 'timeout' if the signal
        # somehow never arrives) so this test cannot hang; SIGTERM should win within ~0.2s.
        reason = ti.wait_for_stop(box, stop, "/nonexistent/ttrmod-stop-xyz", persist=False,
                                  poll_s=5.0, fires_fn=None, log=lambda *a: None, tick=0.02)
        dt = time.time() - t0
        th.join(timeout=1.0)
        check("SIGTERM => wait_for_stop returns 'SIGTERM'", reason == "SIGTERM", "reason=%r (%.2fs)" % (reason, dt))
        check("SIGTERM => stop state recorded", stop["stop"] and stop["reason"] == "SIGTERM")
        check("SIGTERM => broke the loop quickly (< 2s)", dt < 2.0, "%.2fs" % dt)
    finally:
        try:
            if prev is not None:
                signal.signal(signal.SIGTERM, prev)
            else:
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
        except Exception:
            pass


def case_bounded_timeout_terminates():
    """(6) Bounded (test/poll) modes still return 'timeout'. Uses a FAKE clock so it's instant."""
    box = {}
    stop = ti.make_stop_state()
    clk = {"t": 1000.0}

    def now_fn():
        return clk["t"]

    def sleep_fn(dt):
        clk["t"] += dt      # advance the fake clock instead of really sleeping

    reason = ti.wait_for_stop(box, stop, "/nonexistent/ttrmod-stop-xyz", persist=False, poll_s=3.0,
                              fires_fn=lambda: 0, log=lambda *a: None, tick=0.5,
                              now_fn=now_fn, sleep_fn=sleep_fn)
    check("bounded mode returns 'timeout'", reason == "timeout", "reason=%r" % reason)


def case_request_stop_idempotent():
    """(7) request_stop is idempotent -- the FIRST reason wins (so an incidental later trigger can't
    rewrite why we stopped)."""
    stop = ti.make_stop_state()
    ti.request_stop(stop, "stop-file")
    ti.request_stop(stop, "SIGTERM")
    check("request_stop keeps the first reason", stop["stop"] and stop["reason"] == "stop-file",
          "reason=%r" % stop["reason"])


def main():
    cases = [
        ("revert restores ALL installed wraps (none remain)", case_revert_restores_all),
        ("stop file triggers graceful stop", case_stopfile_triggers_stop),
        ("full stop-file flow consumes the file", case_full_stopfile_flow_consumes_file),
        ("SIGTERM triggers graceful stop", case_sigterm_triggers_stop),
        ("no-confirm revert does NOT detach (stays attached)", case_no_confirm_no_detach),
        ("failed setattr does NOT detach", case_failed_setattr_no_detach),
        ("bounded mode still times out", case_bounded_timeout_terminates),
        ("request_stop is idempotent", case_request_stop_idempotent),
    ]
    exc_clean = True
    for title, fn in cases:
        print("[stoprevert] %s" % title)
        try:
            fn()
        except Exception as e:
            exc_clean = False
            check("%s (no unexpected exception)" % title, False, "raised %r" % e)
        print("")
    check("exception-clean throughout", exc_clean)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    allok = passed == total
    print("[stoprevert] %d/%d checks passed" % (passed, total))
    print("[stoprevert] VERDICT: %s" % (
        "PASS -- the stop file and SIGTERM trigger a revert that restores EVERY installed wrap "
        "(start-wrap + context wraps + more; none remain) before detach; a revert that can't confirm "
        "(or whose setattr fails) does NOT detach -- it stays attached, game alive; the stop file is "
        "consumed on a clean stop; bounded modes still time out; exception-clean throughout"
        if allok else "FAIL -- see the failing checks above"))
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
