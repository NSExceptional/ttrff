#!/usr/bin/env python3
"""Route planning over the zone's real collision geometry, for the bag bot.

WHY THIS EXISTS
    The bot used to aim straight at its bag and rely on reflexes -- whiskers, a wall guard, a
    timed detour -- to get round whatever was in between. That cannot work when the way to a bag
    starts by walking AWAY from it. Standing in the Cartoonival entrance corridor with a bag off
    to the left, every reflex points back into the corridor's long side wall, so the bot turned
    into it, bounced off, and turned into it again. The fix is to know the way before setting off.

HOW
    The client already hands us the zone's walls exactly (`worldstate.fetch_walls`: polygon edges
    plus the spheres/capsules of posts and trunks). They are rasterised once per zone into an
    occupancy grid, grown by the toon's own radius so the planner can treat the toon as a point,
    and no-go triggers (tunnel mouths, minigame seats) are painted in as blocked too. A* finds the
    grid path, and string-pulling keeps only the corners, so the route is a handful of straight
    legs. Each tick the bot steers at the furthest route point it can see directly.

    Pillow (already a tray dependency) does the rasterising; the search is plain Python. A 680 x
    760 unit zone at one cell per unit is ~0.5 MB and plans in well under a second.

HEIGHT
    Walls only count if they span the toon's feet-to-head band (a curb below the feet or an awning
    overhead does not block). The grid is built for the height the toon is at, and the bot rebuilds
    it when the toon has climbed or dropped a few units.
"""
import heapq
import math

from PIL import Image, ImageDraw

# Cell values. WALL and NOGO block; NEAR (within a couple of units of a wall) is passable but
# costs more, so routes run down the middle of a corridor rather than scraping one side of it --
# steering is only good to a few degrees, and a route hugging a wall invites bumping into it.
FREE, WALL, NOGO, NEAR = 0, 1, 2, 4
BLOCKED = WALL | NOGO
NEAR_EXTRA = 2.0            # units beyond the toon's radius that count as "near"
NEAR_COST = 2.5             # cost multiplier for stepping through a NEAR cell
SIGHT_RADIUS = 0.5          # walls grown by only this much when asking "can I see that point?"
REACHED = 2.0               # a waypoint this close counts as reached
SQRT2 = math.sqrt(2.0)
_STEPS = ((1, 0, 1.0), (-1, 0, 1.0), (0, 1, 1.0), (0, -1, 1.0),
          (1, 1, SQRT2), (1, -1, SQRT2), (-1, 1, SQRT2), (-1, -1, SQRT2))

TOON_RADIUS = 1.4           # Toontown's avatar collision radius: how far the toon's centre stays
                            # from any wall, hence how much every wall is grown by
ZBAND = (-1.0, 4.0)         # a wall matters if it spans any of [feet-1, feet+4]
MAX_CELLS = 2500000         # refuse to build a grid bigger than this (~2.5 MB)


def in_band(zmin, zmax, z, band=ZBAND):
    return not (zmax < z + band[0] or zmin > z + band[1])


def round_radius(rd, z, band=ZBAND):
    """The radius a round solid actually presents at the toon's height, or None if it misses.

    A sphere or capsule is NOT a vertical cylinder of its full radius: at a height dz away from its
    axis it is only sqrt(r^2 - dz^2) wide. Treating a big sphere centred below the feet as full
    width put the toon "inside" it -- every whisker read 0, the wall guard vetoed every step, and
    the bot wiggled on the spot until the toon fell asleep and the game logged it out.
    """
    x1, y1, x2, y2, zmin, zmax, r = rd
    a0, a1 = zmin + r, zmax - r                 # the axis' own height range
    b0, b1 = z + band[0], z + band[1]
    dz = max(a0 - b1, b0 - a1, 0.0)
    if dz >= r:
        return None
    return math.sqrt(r * r - dz * dz)


class Route(object):
    """A planned path: world points from the start to the goal, and how far along it we are."""

    def __init__(self, pts, goal):
        self.pts = pts                 # [(x, y)], the last one is the goal itself
        self.goal = goal
        self.idx = 0                   # index of the current waypoint; only ever increases
        self.tail = [0.0] * len(pts)   # path length from pts[i] to the end
        for i in range(len(pts) - 2, -1, -1):
            self.tail[i] = self.tail[i + 1] + math.hypot(pts[i + 1][0] - pts[i][0],
                                                        pts[i + 1][1] - pts[i][1])

    def remaining(self, x, y):
        """Distance still to walk: straight to the current waypoint, then along the route."""
        p = self.pts[self.idx]
        return math.hypot(p[0] - x, p[1] - y) + self.tail[self.idx]


class NavGrid(object):
    """Occupancy grid for one zone at one height. Cell values: FREE, WALL or NOGO."""

    def __init__(self, segs, rounds, nogo, z, cell=1.0, radius=TOON_RADIUS, band=ZBAND,
                 margin=40.0, include=()):
        self.z, self.cell, self.radius = z, cell, radius
        walls = [s for s in segs if in_band(s[4], s[5], z, band)]
        rnd = []
        for r in rounds:
            re_ = round_radius(r, z, band)
            if re_ is not None:
                rnd.append(r[:6] + (re_,))
        xs, ys = [], []
        for s in walls:
            xs += (s[0], s[2])
            ys += (s[1], s[3])
        for r in rnd:
            xs += (r[0] - r[6], r[2] + r[6])
            ys += (r[1] - r[6], r[3] + r[6])
        for p in include:                      # the toon, so it is always on the grid
            xs.append(p[0])
            ys.append(p[1])
        if not xs:
            xs, ys = [0.0], [0.0]
        self.x0 = math.floor(min(xs) - margin)
        self.y0 = math.floor(min(ys) - margin)
        self.W = int(math.ceil((max(xs) + margin - self.x0) / cell))
        self.H = int(math.ceil((max(ys) + margin - self.y0) / cell))
        if self.W * self.H > MAX_CELLS:
            raise ValueError("zone too large for a %.1f-unit grid: %dx%d" % (cell, self.W, self.H))

        im = Image.new("L", (self.W, self.H), FREE)
        d = ImageDraw.Draw(im)
        # Paint order sets precedence: NEAR, then no-go, then walls on top.
        for s in walls:
            self._thick(d, s[0], s[1], s[2], s[3], radius + NEAR_EXTRA, NEAR)
        for r in rnd:
            self._thick(d, r[0], r[1], r[2], r[3], r[6] + radius + NEAR_EXTRA, NEAR)
        for o in nogo:
            self._disc(d, o["x"], o["y"], o["r"], NOGO)
        for s in walls:
            self._thick(d, s[0], s[1], s[2], s[3], radius, WALL)
        for r in rnd:
            self._thick(d, r[0], r[1], r[2], r[3], r[6] + radius, WALL)
        self.g = im.tobytes()
        # A second, THIN grid for line of sight while following a route. Route corners sit exactly
        # on the grown walls (that is what string-pulling produces), so from a spot a unit off the
        # line the next corner is "hidden" behind the growth -- and the bot turned a hundred
        # degrees to step one unit onto the exact corner, then turned back. Seeing past a corner
        # only needs the walls themselves plus a sliver.
        im2 = Image.new("L", (self.W, self.H), FREE)
        d2 = ImageDraw.Draw(im2)
        for o in nogo:
            self._disc(d2, o["x"], o["y"], o["r"], NOGO)
        for s in walls:
            self._thick(d2, s[0], s[1], s[2], s[3], SIGHT_RADIUS, WALL)
        for r in rnd:
            self._thick(d2, r[0], r[1], r[2], r[3], r[6] + SIGHT_RADIUS, WALL)
        self.gv = im2.tobytes()
        self.n_walls, self.n_rounds = len(walls), len(rnd)

    # -- rasterising ---------------------------------------------------------------------------
    def _px(self, x, y):
        """World -> PIL pixel coordinate (PIL addresses pixel CENTRES)."""
        return ((x - self.x0) / self.cell - 0.5, (y - self.y0) / self.cell - 0.5)

    def _disc(self, d, x, y, r, val):
        cx, cy = self._px(x, y)
        rp = r / self.cell
        d.ellipse([cx - rp, cy - rp, cx + rp, cy + rp], fill=val)

    def _thick(self, d, x1, y1, x2, y2, r, val):
        """A segment grown by r on every side: a thick line plus a disc on each end."""
        w = max(1, int(round(2.0 * r / self.cell)))
        if (x1, y1) != (x2, y2):
            d.line([self._px(x1, y1), self._px(x2, y2)], fill=val, width=w)
        self._disc(d, x1, y1, r, val)
        self._disc(d, x2, y2, r, val)

    # -- queries -------------------------------------------------------------------------------
    def cell_of(self, x, y):
        return int((x - self.x0) // self.cell), int((y - self.y0) // self.cell)

    def centre(self, i, j):
        return self.x0 + (i + 0.5) * self.cell, self.y0 + (j + 0.5) * self.cell

    def value(self, i, j):
        if i < 0 or j < 0 or i >= self.W or j >= self.H:
            return WALL
        return self.g[j * self.W + i]

    def free_at(self, x, y):
        return not (self.value(*self.cell_of(x, y)) & BLOCKED)

    def nearest_free(self, i, j, max_r):
        """The FREE cell nearest (i, j), searching out to max_r cells, or None."""
        if not (self.value(i, j) & BLOCKED):
            return i, j
        for r in range(1, int(max_r) + 1):
            best, bd = None, None
            for di in range(-r, r + 1):
                for dj in (-r, r) if abs(di) != r else range(-r, r + 1):
                    if not (self.value(i + di, j + dj) & BLOCKED):
                        dd = di * di + dj * dj
                        if bd is None or dd < bd:
                            best, bd = (i + di, j + dj), dd
            if best:
                return best
        return None

    def los(self, ax, ay, bx, by, skip=0.0, sight=False):
        """True if the straight line a->b crosses no blocked cell (after the first `skip` units,
        so a toon brushing a wall -- inside the grown margin -- can still see past it). `sight`
        tests against the thin grid instead of the one grown by the toon's radius."""
        dx, dy = bx - ax, by - ay
        L = math.hypot(dx, dy)
        if L < 1e-6:
            return True
        step = 0.25 * self.cell
        n = int(L / step) + 1
        ux, uy = dx / L, dy / L
        g, W, H, x0, y0, c = self.gv if sight else self.g, self.W, self.H, self.x0, self.y0, self.cell
        k = int(skip / step)
        while k <= n:
            t = min(k * step, L)
            i = int((ax + ux * t - x0) // c)
            j = int((ay + uy * t - y0) // c)
            if i < 0 or j < 0 or i >= W or j >= H or g[j * W + i] & BLOCKED:
                return False
            k += 1
        return True

    # -- planning ------------------------------------------------------------------------------
    def plan(self, sx, sy, gx, gy, start_search=30.0, goal_search=4.0, max_expand=600000):
        """A Route from (sx, sy) to (gx, gy), or None if there is no way through.

        The start may sit inside a grown wall (brushing it) or a no-go ring (arriving from a
        tunnel), so it snaps to the nearest free cell; the goal snaps within a few units, since a
        bag hard against a wall is still reachable by touch.
        """
        s = self.nearest_free(*self.cell_of(sx, sy), max_r=start_search / self.cell)
        t = self.nearest_free(*self.cell_of(gx, gy), max_r=goal_search / self.cell)
        if s is None or t is None:
            return None
        cells = self._astar(s, t, max_expand)
        if cells is None:
            return None
        pts = self._pull([self.centre(i, j) for i, j in cells])
        pts.append((gx, gy))
        return Route(pts, (gx, gy))

    def _astar(self, s, t, max_expand):
        W, H, g = self.W, self.H, self.g
        start, goal = s[1] * W + s[0], t[1] * W + t[0]
        tx, ty = t
        gs = {start: 0.0}
        parent = {start: -1}
        closed = bytearray(W * H)
        heap = [(0.0, start)]
        pop, push = heapq.heappop, heapq.heappush
        expanded = 0
        while heap:
            _, cur = pop(heap)
            if closed[cur]:
                continue
            if cur == goal:
                break
            closed[cur] = 1
            expanded += 1
            if expanded > max_expand:
                return None
            cx, cy = cur % W, cur // W
            gc = gs[cur]
            for dx, dy, cost in _STEPS:
                nx, ny = cx + dx, cy + dy
                if nx < 0 or ny < 0 or nx >= W or ny >= H:
                    continue
                n = ny * W + nx
                v = g[n]
                if v & BLOCKED or closed[n]:
                    continue
                if dx and dy and (g[cy * W + nx] & BLOCKED or g[ny * W + cx] & BLOCKED):
                    continue                      # never cut a corner between two walls
                ng = gc + (cost * NEAR_COST if v & NEAR else cost)
                if ng < gs.get(n, 1e18):
                    gs[n] = ng
                    parent[n] = cur
                    hx, hy = abs(nx - tx), abs(ny - ty)
                    # octile distance, nudged up a hair so ties break toward the goal
                    push(heap, (ng + 1.001 * (hx + hy + (SQRT2 - 2.0) * min(hx, hy)), n))
        else:
            return None
        if goal not in parent:
            return None
        out, cur = [], goal
        while cur != -1:
            out.append((cur % W, cur // W))
            cur = parent[cur]
        out.reverse()
        return out

    def _pull(self, pts):
        """String-pulling: keep only the points where the path has to turn."""
        if len(pts) <= 2:
            return list(pts)
        out, i, n = [pts[0]], 0, len(pts)
        while i < n - 1:
            k = i + 1
            while k + 1 < n and self.los(pts[i][0], pts[i][1], pts[k + 1][0], pts[k + 1][1]):
                k += 1
            out.append(pts[k])
            i = k
        return out

    def waypoint(self, route, x, y):
        """The furthest route point visible from (x, y), at or beyond the current one.

        Advances route.idx. Returns None when none of them is visible -- the toon has been pushed
        off its route -- which is the caller's cue to plan again.
        """
        last = len(route.pts) - 1
        for k in range(last, route.idx - 1, -1):
            p = route.pts[k]
            if self.los(x, y, p[0], p[1], skip=1.0, sight=True):
                # Standing on a corner already: aim at the one after it rather than shuffling
                # the last unit or two onto the exact point.
                if k < last and math.hypot(p[0] - x, p[1] - y) < REACHED:
                    k += 1
                route.idx = k
                return route.pts[k]
        return None


# ---- exact whiskers (steering reflexes) ---------------------------------------------------------
def _ray_seg(mx, my, dx, dy, x1, y1, x2, y2):
    ex, ey = x2 - x1, y2 - y1
    den = dx * ey - dy * ex
    if abs(den) < 1e-9:
        return None
    wx, wy = x1 - mx, y1 - my
    t = (wx * ey - wy * ex) / den
    u = (wx * dy - wy * dx) / den
    return t if t >= 0.0 and 0.0 <= u <= 1.0 else None


def _ray_circle(mx, my, dx, dy, cx, cy, r):
    fx, fy = mx - cx, my - cy
    c = fx * fx + fy * fy - r * r
    if c <= 0.0:
        return 0.0                          # already inside it
    b = fx * dx + fy * dy
    disc = b * b - c
    if disc < 0.0:
        return None
    t = -b - math.sqrt(disc)
    return t if t >= 0.0 else None


def round_hit(mx, my, dx, dy, rd, r=None):
    """Distance along a ray to a capsule (x1, y1, x2, y2, zmin, zmax, r), or None. `r` overrides
    the stored radius (pass round_radius() for the cross-section at the toon's height)."""
    x1, y1, x2, y2, _, _, r0 = rd
    r = r0 if r is None else r
    best = None
    for t in (_ray_circle(mx, my, dx, dy, x1, y1, r), _ray_circle(mx, my, dx, dy, x2, y2, r)):
        if t is not None and (best is None or t < best):
            best = t
    L = math.hypot(x2 - x1, y2 - y1)
    if L > 1e-6:
        nx, ny = -(y2 - y1) / L * r, (x2 - x1) / L * r
        for s in (1.0, -1.0):
            t = _ray_seg(mx, my, dx, dy, x1 + s * nx, y1 + s * ny, x2 + s * nx, y2 + s * ny)
            if t is not None and (best is None or t < best):
                best = t
    return best
