# ttrff

Personal, cosmetic quality-of-life tweaks for the owner's **own** Toontown Rewritten
client, on the owner's own machine and account. It attaches to the running game at
runtime and speeds up a set of **purely visual** animations (teleport, Shticker Book
open/close, screen iris, building doors, street-tunnel walks, and cog-battle
movie/faceoff/run-in) all at once, driven by a small config table the owner can edit.

## What this is (and is not)

- **Is:** a runtime tool that makes cosmetic animations snappier by changing only their
  playback rate. Nothing else is touched.
- **Is not:** a competitive cheat. It changes **no** movement / turn / aim / damage logic
  and grants **no** server-validated advantage — only client-side animation *timing*.
  Because it only touches client-side rendering, everything it speeds up ports 1:1 to the
  real server — but a server-paced delay (a building door's phase hold, the wait between
  cog-battle rounds) is **unaffected**: only the visuals around it get snappier.

Client modification is **ToS-gray and at your own risk.** The owner has accepted that.
**Do not distribute, and do not use on accounts you do not own.**

## How it works (high level)

Every Panda3D `Sequence`/`Parallel`/`Track` in the game is one Python `MetaInterval`, and
starting one calls its `MetaInterval.start()`. The tool installs a single native wrapper on
that one method (using an in-process C-API "trampoline" — no injected Python bytecode, which
is what makes it work on the hardened official client; see [`STATUS.md`](STATUS.md) for the
full engine reverse-engineering). In the wrapper, right after an interval starts, it reads
the interval's `getName()` and — **only** if the name matches an entry in the config table —
calls `setPlayRate(factor)` on it. Any name that matches no entry is left completely alone,
so gameplay-timing intervals are never affected. On detach it restores the original method.

Because animations like teleport, book, doors, and battle are broadcast to everyone nearby,
the same hook also speeds those up when other toons trigger them in your zone — still purely
a change to *your* client's rendering.

## Running it

The config lives in [`modset.json`](modset.json) — a list of `{ "match", "factor", "group" }`
rows (`match` = a substring of the interval name; `factor` = speed multiplier, so `3.0`
means about one-third the duration; first matching row wins, so order specific → broad).
Edit factors, disable a group, or add a newly-discovered name there.

Validate the table logic offline first (no game needed):

    python3 localtest/modset_test.py     # via the signed frida runner; see STATUS.md

Then run against the live client (attaches as root and applies the whole table, staying resident so
the mods keep working while you play):

    sudo -n env TTRMOD_MODE=modset \
        TTRMOD_SCRIPT=frida/trampoline_inject.py frida/run-injector.sh

Trigger animations (teleport via the book, open/close the book, walk through a building door, be near
a cog battle, walk through a street tunnel) to see them speed up. Add `TTRMOD_LOGNAMES=1` to log every
started interval's name (`[IVALNAME]`) — so you can discover new ones — plus a `[SCALED] <name>
x<factor> (<group>)` line each time a match is scaled.

**Stop it with `scripts/tt-mod-stop` (from another terminal) — NOT Ctrl+C.** The tool must restore
the original game methods *before* it detaches; if the frida session drops while the wrapper is still
installed, the game crashes on the next animation. `tt-mod-stop` triggers that clean revert and waits
for it. Do **not** use Ctrl+C: the runner dies too hard on SIGINT for the revert to run (`kill -TERM`
also works). For a time-boxed run that reverts on its own after N seconds, add `TTRMOD_POLL=<seconds>`.

## Group coverage

| group | what speeds up | status |
|---|---|---|
| teleport | teleport out/in (Shticker Book) | confirmed live |
| book | Shticker Book open/close | confirmed live |
| transitions | the screen iris on any zone change | confirmed live |
| door | building door swing + toon walk in/out | confirmed live |
| battle | cog-battle faceoff, attack/reward movie, run-in | names captured live; scales on the next in-zone battle (cosmetic only — round pacing stays server-gated) |
| tunnel | the street-tunnel walk (in and out) | fires on your own tunnel entry only. **Departure** (walking in) is caught by a context wrap on the readable `LocalToon.tunnelOut`; **arrival** (walking out) is caught deterministically by matching the walk to `LocalToon`'s own method set + the iris that fires with it — no hardcoded per-build hash. See `STATUS.md`. |

Factors are conservative (teleport ~4×, everything else ~3×) and easy to tune in
`modset.json`.

## More

The authoritative, living technical document is [`STATUS.md`](STATUS.md): the target engine,
the anti-injection layers it works around, the interval-name catalog, the exact per-group
status, all recovered addresses/offsets, and how to re-derive them when TTR auto-patches the
engine. (Any 3.7 / lldb / `marshal_evalcode` details in old commits are **obsolete** — see
`STATUS.md`.)
