#!/usr/bin/env python3
"""ttrff tray -- a tiny cross-platform menu-bar / system-tray controller for the ttrff mods.

It does three things, identically on macOS and Windows:

  1. Watches for the Toontown Rewritten engine process (`TTREngine`).
  2. While "Mods enabled" is on, auto-attaches the resident injector
     (`frida/trampoline_inject.py`, modset mode) as soon as the game appears, and keeps it
     running while you play -- no terminal, no commands.
  3. On quit or disable, triggers the injector's CLEAN revert (the stop-file) and waits for
     it, so the game is never left with a live hook (which is what crashed it on Ctrl+C).

The MENU and BEHAVIOR are the same on both platforms. The only platform-specific piece is
*how* the injector subprocess is launched, because attaching to the hardened engine needs
root on macOS but nothing special on Windows:

  * macOS  -- `sudo -n` + the signed `frida/run-injector.sh` (task_for_pid needs root here).
  * Windows -- the injector runs directly under a Python that has `frida` installed
               (attaching to a same-user process needs no elevation).

This is a supervisor only: it shells out to the EXISTING injector and never touches the
injection internals. Cosmetic-only, owner's own client -- see the repo README.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

try:
    import psutil
except ImportError:                      # reported by --selftest; required for the tray
    psutil = None

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"

# ---- paths & config (all overridable by env, so the Windows agent can retarget without edits) ----

def _repo_root():
    return os.environ.get("TTRFF_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPO = _repo_root()
RUN_INJECTOR_SH = os.path.join(REPO, "frida", "run-injector.sh")
TRAMPOLINE_PY = os.path.join(REPO, "frida", "trampoline_inject.py")
DEFAULT_MODSET = os.path.join(REPO, "modset.json")   # the shipped default (read-only under Homebrew)
# The editable mod table. Under Homebrew the wrapper points TTRMOD_MODSET at a user-writable copy
# (the repo's modset.json lives in a read-only Cellar); it is seeded from DEFAULT_MODSET on first run.
MODSET_PATH = os.environ.get("TTRMOD_MODSET") or DEFAULT_MODSET
LOGFILE = os.environ.get("TTRFF_LOG") or os.path.join(tempfile.gettempdir(), "ttrff-tray-injector.log")

# Stop-file: keep the established /tmp default on posix (matches scripts/tt-mod-stop and the
# injector's own default) so the two stop paths agree; use the temp dir on Windows (no /tmp).
STOPFILE = (os.environ.get("TTRFF_STOPFILE") or os.environ.get("TTRMOD_STOPFILE")
            or (os.path.join(tempfile.gettempdir(), "ttrmod-stop") if IS_WINDOWS else "/tmp/ttrmod-stop"))

# Substring(s) that identify the game process (name / exe / cmdline). "TTREngine" also matches
# the Windows "TTREngine.exe". Override with TTRFF_ENGINE_NAMES="a,b,c".
ENGINE_NAMES = [s.strip() for s in
                (os.environ.get("TTRFF_ENGINE_NAMES") or "TTREngine,Toontown Rewritten").split(",")
                if s.strip()]

# On Windows/Linux the injector runs under this Python (must have `frida`); default = ours.
INJECTOR_PYTHON = os.environ.get("TTRFF_INJECTOR_PYTHON") or sys.executable

POLL_SECS = 2.0                          # how often the supervisor reconciles
STOP_WAIT_SECS = 25.0                    # how long to wait for a clean revert before giving up
FAST_EXIT_SECS = 8.0                     # an injector that dies within this = a failed attach
STATUS_COLORS = {                        # menu-bar icon tint by state
    "off":      (139, 148, 158),         # grey
    "waiting":  (139, 148, 158),
    "starting": (210, 168, 60),          # amber
    "stopping": (210, 168, 60),
    "active":   (63, 185, 80),           # green
    "error":    (218, 76, 76),           # red
}
STATUS_TEXT = {
    "off": "off", "waiting": "waiting for game", "starting": "attaching…",
    "stopping": "reverting…", "active": "mods active", "error": "attach failed (see log)",
}

# Menu groups -> label. Each maps to modset.json switches via _group_switches().
GROUPS = [
    ("teleport", "Teleport"),
    ("book", "Shticker Book"),
    ("transitions", "Screen iris"),
    ("door", "Building doors"),
    ("tunnel", "Street tunnels"),
    ("battle", "Battle (intro/outro)"),
]


# ---------------------------------- engine detection ----------------------------------

def find_engine_pid():
    """Return the pid of the running TTR engine, or None. Cross-platform via psutil."""
    if psutil is None:
        return None
    needles = [n.lower() for n in ENGINE_NAMES]
    for p in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            info = p.info
            hay = " ".join(filter(None, [
                info.get("name") or "",
                info.get("exe") or "",
                " ".join(info.get("cmdline") or []),
            ])).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
        if any(n in hay for n in needles):
            return p.pid
    return None


# ---------------------------------- modset (group toggles) ----------------------------------

def _switch_enabled(sw):
    return sw.get("enabled", True) is not False

def _switch_pinned(sw):
    return bool(sw.get("pinned_disabled"))

def _group_switches(spec, group):
    """Every modset row/section the given menu group controls."""
    out = [e for e in spec.get("entries", []) if e.get("group") == group]
    out += [c for c in spec.get("context", []) if c.get("group") == group]
    if group == "tunnel":                # tunnel also has two dedicated sections
        for key in ("tunnel_localtoon_iris", "tunnel_identity"):
            if isinstance(spec.get(key), dict):
                out.append(spec[key])
    return out

def seed_modset():
    """Under Homebrew, MODSET_PATH is a user-writable copy that may not exist yet -- create it from
    the shipped read-only default on first run. No-op when they're the same file (dev checkout)."""
    if MODSET_PATH == DEFAULT_MODSET or os.path.exists(MODSET_PATH):
        return
    try:
        import shutil
        d = os.path.dirname(MODSET_PATH)
        if d:
            os.makedirs(d, exist_ok=True)
        shutil.copyfile(DEFAULT_MODSET, MODSET_PATH)
    except Exception:
        pass


def load_modset():
    with open(MODSET_PATH) as f:
        return json.load(f)

def group_is_on(spec, group):
    sws = _group_switches(spec, group)
    return any(_switch_enabled(s) for s in sws if not _switch_pinned(s))

def set_group(spec, group, on):
    """Enable/disable a whole group, preserving deliberately pinned-off rows (e.g. movie-track)."""
    for s in _group_switches(spec, group):
        if _switch_pinned(s):
            continue
        s["enabled"] = bool(on)

def save_modset(spec):
    tmp = MODSET_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(spec, f, indent=2)     # round-trip preserves all keys incl. the _comment docs
        f.write("\n")
    os.replace(tmp, MODSET_PATH)


# ---------------------------------- the supervisor ----------------------------------

class Supervisor:
    """Owns the injector subprocess and reconciles desired state (enabled?) with reality
    (game up? injector alive?) on a background thread. All subprocess work happens here; the
    menu callbacks only flip flags and ask for a refresh."""

    def __init__(self, on_change=None):
        self._lock = threading.RLock()
        self._stop_evt = threading.Event()
        self.enabled = True              # master toggle (auto-inject when the game is up)
        self.dirty = False               # config changed -> re-apply while injected
        self.status = "off"
        self.proc = None                 # the injector Popen (launched detached)
        self._proc_started = 0.0
        self._fails = 0                  # consecutive fast-exits -> backoff
        self._next_try = 0.0
        self._notified_error = False
        self.on_change = on_change or (lambda: None)
        self._thread = None

    # ---- lifecycle ----
    def start(self):
        self._thread = threading.Thread(target=self._run, name="ttrff-supervisor", daemon=True)
        self._thread.start()

    def shutdown(self):
        """Called on quit: stop the loop, then cleanly revert the injector if it's live."""
        self._stop_evt.set()
        self._stop_injector_clean(reason="quit")

    # ---- injector process control ----
    def _launch_cmd(self):
        """Return (argv, env_or_None). macOS re-injects env through `sudo env` (sudo resets it)."""
        if IS_MAC:
            argv = ["sudo", "-n", "env",
                    "TTRMOD_MODE=modset",
                    "TTRMOD_SCRIPT=frida/trampoline_inject.py",
                    "TTRMOD_STOPFILE=" + STOPFILE,
                    "TTRMOD_MODSET=" + MODSET_PATH,
                    RUN_INJECTOR_SH]
            return argv, None            # env passed inline; child inherits the rest
        env = dict(os.environ)
        env.update(TTRMOD_MODE="modset", TTRMOD_STOPFILE=STOPFILE, TTRMOD_MODSET=MODSET_PATH)
        return [INJECTOR_PYTHON, TRAMPOLINE_PY], env

    def _injector_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def _launch_injector(self):
        argv, env = self._launch_cmd()
        try:
            logf = open(LOGFILE, "a", buffering=1)
        except Exception:
            logf = subprocess.DEVNULL
        try:
            logf.write("\n=== launch %s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(argv)))
        except Exception:
            pass
        # Detached: a tray crash must NEVER kill the injector mid-wrap (that would crash the game).
        # The injector is only ever stopped via its stop-file, so it can revert first.
        kw = dict(cwd=REPO, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        if IS_WINDOWS:
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
        else:
            kw["start_new_session"] = True
        if env is not None:
            kw["env"] = env
        try:
            self._clear_stopfile()
            self.proc = subprocess.Popen(argv, **kw)
            self._proc_started = time.time()
        except Exception as e:
            self.proc = None
            self._note_error("could not launch injector: %s" % e)

    def _clear_stopfile(self):
        try:
            if os.path.exists(STOPFILE):
                os.remove(STOPFILE)
        except Exception:
            pass

    def _stop_injector_clean(self, reason=""):
        """Drop the stop-file so the injector reverts BEFORE it detaches, then wait for it to exit.
        If the game is gone, there's nothing to revert -> just reap. If it can't confirm the revert
        while the game is alive (idle game, no frame running the hook), leave it: it's the SAFE state
        and it will finish + exit on its own -- do NOT force-kill (that crashes the game)."""
        if not self._injector_alive():
            self._reap()
            return True
        engine_up = find_engine_pid() is not None
        if not engine_up:
            # Game already exited -> the frida session dropped; the hook is moot. Reap.
            self._terminate_dead_game()
            return True
        try:
            open(STOPFILE, "w").close()
        except Exception:
            pass
        deadline = time.time() + STOP_WAIT_SECS
        while time.time() < deadline:
            if self.proc.poll() is not None:     # injector reverted + exited cleanly
                self._reap()
                return True
            if find_engine_pid() is None:        # game vanished mid-stop -> safe to reap
                self._terminate_dead_game()
                return True
            time.sleep(0.4)
        # Timed out with the game still alive: SAFE state (wraps restored-or-live). Leave it.
        return False

    def _terminate_dead_game(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self._reap()

    def _reap(self):
        self.proc = None
        self._clear_stopfile()

    # ---- menu-facing actions (just flip flags; the loop does the work) ----
    def set_enabled(self, on):
        with self._lock:
            self.enabled = bool(on)
            self._fails = 0
            self._next_try = 0.0
            self._notified_error = False
        self._wake()

    def mark_dirty(self):
        with self._lock:
            self.dirty = True
        self._wake()

    def _wake(self):
        # nudge the loop to reconcile promptly (it also polls on its own)
        self.on_change()

    # ---- error surfacing ----
    def _note_error(self, msg):
        try:
            with open(LOGFILE, "a") as f:
                f.write("[tray] %s\n" % msg)
        except Exception:
            pass

    # ---- the reconcile loop ----
    def _run(self):
        while not self._stop_evt.is_set():
            try:
                self._reconcile()
            except Exception as e:
                self._note_error("reconcile error: %s" % e)
            self._stop_evt.wait(POLL_SECS)

    def _reconcile(self):
        with self._lock:
            enabled = self.enabled
            dirty = self.dirty
            self.dirty = False

        engine_pid = find_engine_pid()
        prev = self.status

        if not enabled:
            if self._injector_alive():
                self._set_status("stopping")
                self._stop_injector_clean(reason="disabled")
            self._set_status("off")
        elif engine_pid is None:
            # No game. If an injector is somehow still around, it will exit as the session drops.
            if self._injector_alive() and find_engine_pid() is None:
                self._reap()
            self._set_status("waiting")
        else:
            # Game is up and mods are enabled.
            if dirty and self._injector_alive():
                self._set_status("stopping")
                self._stop_injector_clean(reason="reapply")
                self._launch_injector()
                self._set_status("starting")
            elif not self._injector_alive():
                now = time.time()
                # Detect a just-exited injector to drive backoff (failed attach vs. clean end).
                if self.proc is not None and self.proc.poll() is not None:
                    if now - self._proc_started < FAST_EXIT_SECS:
                        self._fails += 1
                        self._next_try = now + min(60.0, 5.0 * self._fails)
                        self._note_error("injector exited after %.1fs (attach failed?); backoff %ds"
                                         % (now - self._proc_started, int(self._next_try - now)))
                    else:
                        self._fails = 0
                    self._reap()
                if now >= self._next_try:
                    if self._fails >= 5 and not self._notified_error:
                        self._notified_error = True
                        self._set_status("error")
                    else:
                        self._set_status("starting")
                        self._launch_injector()
                else:
                    self._set_status("error" if self._fails >= 5 else "starting")
            else:
                self._fails = 0
                self._notified_error = False
                self._set_status("active")

        if self.status != prev:
            self.on_change()

    def _set_status(self, s):
        self.status = s


# ---------------------------------- the tray UI ----------------------------------

def _make_image(color):
    from PIL import Image, ImageDraw
    # pystray 0.19.x calls PIL.Image.ANTIALIAS when it resizes the menu-bar icon, but Pillow >= 10
    # removed that name (renamed to Resampling.LANCZOS). Restore the alias so the icon can render.
    if not hasattr(Image, "ANTIALIAS"):
        Image.ANTIALIAS = Image.Resampling.LANCZOS
    # The Toontown eyeballs (extracted from the official logo), tinted by status color.
    eyes_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eyes.png")
    try:
        img = Image.open(eyes_path).convert("RGBA")
    except Exception:
        img = None
    if img is not None:
        # tint: recolor every opaque pixel with the status color, keep the pupils dark
        px = img.load()
        w, h = img.size
        for y in range(h):
            for x in range(w):
                r, g, b, a = px[x, y]
                if a == 0:
                    continue
                lum = (r + g + b) / 3.0
                if lum < 128:
                    px[x, y] = (0, 0, 0, a)          # pupil / outline stays black
                else:
                    px[x, y] = color + (a,)          # eye white takes the status tint
        return img
    # fallback: the old fast-forward glyph
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([4, 4, 60, 60], fill=color + (255,))
    # a white fast-forward glyph (two triangles) -- the "ff" in ttrff
    d.polygon([(20, 20), (20, 44), (36, 32)], fill=(255, 255, 255, 255))
    d.polygon([(34, 20), (34, 44), (50, 32)], fill=(255, 255, 255, 255))
    return img


def _patch_pystray_hidpi():
    """Make pystray's macOS backend render the menu-bar icon at Retina resolution.

    pystray 0.19.x resizes the icon to the status-bar thickness in *pixels* (e.g. 22x22)
    and builds the NSImage from a PNG with no DPI metadata, so it renders @1x and looks
    blurry on @2x displays. Replace its _assert_image with a HiDPI-aware version that
    adds a 2x representation via NSBitmapImageRep.
    """
    try:
        import io as _io
        import PIL.Image as _PILImage
        import pystray._darwin as _darwin
        import AppKit
        import Foundation
    except Exception:
        return

    def _assert_image(self):
        thickness = self._status_bar.thickness()
        size = (int(thickness), int(thickness))
        if self._icon_image and self._icon_image.size() == size:
            return

        def _png_at(px):
            im = self._icon
            if im.size != px:
                im = im.resize(px, _PILImage.Resampling.LANCZOS)
            b = _io.BytesIO()
            im.save(b, "png")
            return b.getvalue()

        icon = AppKit.NSImage.alloc().initWithSize_(AppKit.NSSize(*size))
        for scale in (2, 1):                       # 2x first: macOS picks the best match
            px = (size[0] * scale, size[1] * scale)
            data = _png_at(px)
            nsdata = Foundation.NSData(data)
            rep = AppKit.NSBitmapImageRep.imageRepWithData_(nsdata)
            if rep is None:
                continue
            rep.setSize_(AppKit.NSSize(*size))
            rep.setPixelsWide_(px[0])
            rep.setPixelsHigh_(px[1])
            icon.addRepresentation_(rep)
        self._icon_image = icon
        self._status_item.button().setImage_(icon)

    _darwin.Icon._assert_image = _assert_image


class TrayApp:
    def __init__(self):
        self.sup = Supervisor(on_change=self._refresh)
        self.icon = None

    # ---- menu model ----
    def _status_line(self):
        return "ttrff — " + STATUS_TEXT.get(self.sup.status, self.sup.status)

    def _group_checked(self, group):
        try:
            return group_is_on(load_modset(), group)
        except Exception:
            return False

    def _toggle_group(self, group):
        def handler(icon, item):
            try:
                spec = load_modset()
                set_group(spec, group, not group_is_on(spec, group))
                save_modset(spec)
            except Exception as e:
                self.sup._note_error("group toggle failed: %s" % e)
                return
            self.sup.mark_dirty()        # re-apply if currently injected
            self._refresh()
        return handler

    def _toggle_enabled(self, icon, item):
        self.sup.set_enabled(not self.sup.enabled)
        self._refresh()

    def _open_config(self, icon, item):
        _open_path(MODSET_PATH)

    def _open_log(self, icon, item):
        _open_path(LOGFILE)

    def _reapply(self, icon, item):
        self.sup.mark_dirty()

    def _quit(self, icon, item):
        self.sup.shutdown()
        icon.stop()

    def _build_menu(self):
        from pystray import Menu, MenuItem
        items = [
            MenuItem(lambda item: self._status_line(), None, enabled=False),
            Menu.SEPARATOR,
            MenuItem("Mods enabled", self._toggle_enabled,
                     checked=lambda item: self.sup.enabled),
            Menu.SEPARATOR,
        ]
        for key, label in GROUPS:
            items.append(MenuItem(label, self._toggle_group(key),
                                  checked=(lambda item, k=key: self._group_checked(k))))
        items += [
            Menu.SEPARATOR,
            MenuItem("Re-apply config now", self._reapply),
            MenuItem("Open modset.json…", self._open_config),
            MenuItem("Open injector log…", self._open_log),
            Menu.SEPARATOR,
            MenuItem("Quit", self._quit),
        ]
        return Menu(*items)

    def _refresh(self):
        if self.icon is None:
            return
        try:
            self.icon.icon = _make_image(STATUS_COLORS.get(self.sup.status, (139, 148, 158)))
            self.icon.title = self._status_line()
            self.icon.update_menu()
        except Exception:
            pass

    def run(self):
        from pystray import Icon
        if IS_MAC:
            # No dock icon: become a background/agent app (menu-bar item only).
            try:
                from AppKit import NSApplication, NSApplicationActivationPolicyProhibited
                NSApplication.sharedApplication().setActivationPolicy_(
                    NSApplicationActivationPolicyProhibited
                )
            except Exception:
                pass
            _patch_pystray_hidpi()
        self.icon = Icon("ttrff", icon=_make_image(STATUS_COLORS["off"]),
                         title=self._status_line(), menu=self._build_menu())

        def setup(icon):
            icon.visible = True
            self.sup.start()

        self.icon.run(setup=setup)       # blocks the main thread (required on macOS)


def _open_path(path):
    try:
        if IS_MAC:
            subprocess.Popen(["open", path])
        elif IS_WINDOWS:
            os.startfile(path)           # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


# ---------------------------------- selftest / CLI ----------------------------------

def selftest():
    print("ttrff tray selftest")
    print("  platform      :", sys.platform, "(mac)" if IS_MAC else ("(windows)" if IS_WINDOWS else "(other)"))
    print("  repo          :", REPO)
    print("  modset.json   :", MODSET_PATH, "OK" if os.path.exists(MODSET_PATH) else "MISSING!")
    print("  run-injector  :", RUN_INJECTOR_SH, "OK" if os.path.exists(RUN_INJECTOR_SH) else "MISSING")
    print("  trampoline.py :", TRAMPOLINE_PY, "OK" if os.path.exists(TRAMPOLINE_PY) else "MISSING")
    print("  stop-file     :", STOPFILE)
    print("  log-file      :", LOGFILE)
    print("  engine names  :", ENGINE_NAMES)
    print("  inject python :", INJECTOR_PYTHON)

    sup = Supervisor()
    argv, env = sup._launch_cmd()
    print("  launch argv   :", " ".join(argv))
    if env is not None:
        extra = {k: env[k] for k in ("TTRMOD_MODE", "TTRMOD_STOPFILE", "TTRMOD_MODSET") if k in env}
        print("  launch env    :", extra)

    print("  deps          : psutil=%s  pystray=%s  PIL=%s" % (
        _dep_ok("psutil"), _dep_ok("pystray"), _dep_ok("PIL")))

    if psutil is not None:
        pid = find_engine_pid()
        print("  engine        :", ("running pid=%d" % pid) if pid else "not running")
    else:
        print("  engine        : (psutil not installed -- cannot detect)")

    try:
        spec = load_modset()
        print("  groups        :")
        for key, label in GROUPS:
            n = len(_group_switches(spec, key))
            print("      %-13s %-22s %s  (%d switch%s)"
                  % (key, label, "ON " if group_is_on(spec, key) else "off", n, "" if n == 1 else "es"))
    except Exception as e:
        print("  groups        : ERROR reading modset.json:", e)
    print("\nOK -- selftest complete (no injector launched).")


def _dep_ok(mod):
    try:
        __import__(mod)
        return "ok"
    except Exception:
        return "MISSING"


def main():
    ap = argparse.ArgumentParser(description="ttrff tray -- menu-bar/tray controller for the ttrff mods.")
    ap.add_argument("--selftest", action="store_true",
                    help="print resolved paths, launch command, engine + group status, then exit "
                         "(launches no injector; seeds the mod table on first run)")
    args = ap.parse_args()

    seed_modset()   # first run: create the user-writable mod table from the shipped default

    if args.selftest:
        selftest()
        return

    missing = [m for m in ("psutil", "pystray", "PIL") if _dep_ok(m) != "ok"]
    if missing:
        sys.exit("missing dependencies: %s\n  pip install pystray pillow psutil"
                 % ", ".join("pillow" if m == "PIL" else m for m in missing))

    TrayApp().run()


if __name__ == "__main__":
    main()
