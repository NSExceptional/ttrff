# ttr-mods

Personal, cosmetic quality-of-life tweaks for the owner's **own** Toontown Rewritten
client, on the owner's own machine and account. It attaches to the running game at
runtime and speeds up a handful of **purely visual** animations (battle playback,
teleport/tunnel/book/iris transitions), plus an always-on read-only street HUD.

## What this is (and is not)

- **Is:** a runtime tool that makes cosmetic animations snappier and draws a read-only
  HUD (street name, active ToonTasks, gag inventory).
- **Is not:** a competitive cheat. It touches **no** movement / turn / aim / damage logic
  and grants **no** server-validated advantage — everything it changes is client-side
  animation timing. Strictly client-side, so it ports 1:1 to the real server.

Client modification is **ToS-gray and at your own risk.** The owner has accepted that.
Do not distribute or use on accounts you do not own.

## Status / how it works

**In active development — the technical approach is not final, so it's intentionally not
documented here yet.** The authoritative, living technical doc is
[`STATUS.md`](STATUS.md): the target engine, the anti-injection layers, the current
injection approach, what works, dead ends, next steps, and all recovered
addresses/offsets.

(This README will be rewritten with the finalized run steps once the injector is done.
Any 3.7 / lldb / `marshal_evalcode` details you may find in old commits or files are
**obsolete** — see `STATUS.md`.)
