# ttr-mods

Personal, cosmetic quality-of-life tweaks for the owner's **own** Toontown Rewritten
client, on the owner's own machine and account. It attaches to the running game at
runtime and speeds up a set of **purely visual** animations (teleport, Shticker Book
open/close, screen iris, building doors, and cog-battle movie/faceoff/run-in) all at
once, driven by a small config table the owner can edit.

## What this is (and is not)

- **Is:** a runtime tool that makes cosmetic animations snappier by changing only their
  playback rate. Nothing else is touched.
- **Is not:** a competitive cheat. It changes **no** movement / turn / aim / damage logic
  and grants **no** server-validated advantage — only client-side animation *timing*.
  Where a delay is server-enforced (e.g. a building door's phase hold), that delay stays;
  the mod only speeds the visuals around it. Everything it changes ports 1:1 to the real
  TTR server.

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

Then run against the live client (attaches as root, applies the whole table, polls while you
trigger animations, then reverts cleanly):

    sudo -n env TTRMOD_MODE=modset TTRMOD_LOGNAMES=1 TTRMOD_POLL=150 \
        TTRMOD_SCRIPT=frida/trampoline_inject.py frida/run-injector.sh

`TTRMOD_LOGNAMES=1` prints every started interval's name (`[IVALNAME]`) so you can discover
new ones, and prints `[SCALED] <name> x<factor> (<group>)` each time a match is scaled.
Trigger animations (teleport via the book, open/close the book, walk through a building door,
be near a cog battle) to see them speed up. The tool reverts and detaches on its own.

## Group coverage

| group | what speeds up | status |
|---|---|---|
| teleport | teleport out/in (Shticker Book) | confirmed live |
| book | Shticker Book open/close | confirmed live |
| transitions | the screen iris on any zone change | confirmed live |
| door | building door swing + toon walk in/out | confirmed live |
| battle | cog-battle faceoff, attack/reward movie, run-in | names captured live; scales on the next in-zone battle |
| tunnel | the street-tunnel walk | in the table; only fires on your own tunnel entry |

Factors are conservative (teleport ~4×, everything else ~3×) and easy to tune in
`modset.json`.

## More

The authoritative, living technical document is [`STATUS.md`](STATUS.md): the target engine,
the anti-injection layers it works around, the interval-name catalog, the exact per-group
status, all recovered addresses/offsets, and how to re-derive them when TTR auto-patches the
engine. (Any 3.7 / lldb / `marshal_evalcode` details in old commits are **obsolete** — see
`STATUS.md`.)
