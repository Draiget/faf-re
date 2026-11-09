"""Builds the water-levels test map (.plans/water-levels/PLAN.md): a shipped map's terrain with
spline-shaped features carved into it, and water bodies at their own levels.

    python make_map.py <base map folder> <output maps folder>

for example `make_map.py "<game>/maps/SCMP_012" "<game>/maps"`, which writes
`<game>/maps/faf_re_waterlevels/` (scmap, scenario, save, script). Nothing binary is kept in the
repo: the map is generated from the base map each time.

Every feature is a closed uniform Catmull-Rom spline (the curve the engine uses for a body's
`Outline`, `WaterBodyOutlinePolygon` in src/moho/sim/WaterBodies.cpp), so the terrain and the
water come from the same control points:

- the sea at 3, in a bay dug into the north-west corner (the base map's floor is about 3.9);
- a mesa raised to 34 with a crater lake at 30 (outline, no seed);
- a hill at 26 with three terraced pools at 23, 20 and 17 (outline and seed each), split by dikes;
- a ridge at 16 along a winding spline with a river channel at 14 (outline around the channel);
- a polder dug to 1 inside a dike at 6, below the sea but kept dry by a dry body (FillTo = 3).

The water only shows in the sim (and in a game) with `sim_FixWaterBodies 1` until a FAF game
version carries the feature; the renderer does not draw the bodies yet.
"""
import math
import os
import re
import shutil
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scmap import ScMap  # noqa: E402

NAME = "faf_re_waterlevels"
STEPS = 8  # kWaterBodyOutlineSteps
SEA = (3.0, 1.5, 0.0)  # elevation, deep, abyss: the base map's desert floor is about 3.9


def spline_polygon(points):
    """The engine's WaterBodyOutlinePolygon: closed uniform Catmull-Rom, STEPS points per span."""
    n = len(points)
    out = []
    for span in range(n):
        p0, p1, p2, p3 = points[(span - 1) % n], points[span], points[(span + 1) % n], points[(span + 2) % n]
        for step in range(STEPS):
            t = step / STEPS
            xy = []
            for axis in range(2):
                a = 2.0 * p1[axis]
                b = p2[axis] - p0[axis]
                c = (2.0 * p0[axis] - 5.0 * p1[axis]) + (4.0 * p2[axis] - p3[axis])
                d = (3.0 * p1[axis] - p0[axis]) + (p3[axis] - 3.0 * p2[axis])
                xy.append(0.5 * (((a + b * t) + c * t * t) + d * t * t * t))
            out.append((xy[0], xy[1]))
    return out


def contains(poly, x, z):
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, zi = poly[i]
        xj, zj = poly[j]
        if (zi > z) != (zj > z):
            if x < xi + (z - zi) / (zj - zi) * (xj - xi):
                inside = not inside
        j = i
    return inside


def edge_distance(poly, x, z):
    best = float("inf")
    j = len(poly) - 1
    for i in range(len(poly)):
        ax, az = poly[j]
        bx, bz = poly[i]
        dx, dz = bx - ax, bz - az
        length2 = dx * dx + dz * dz
        t = 0.0 if length2 == 0.0 else max(0.0, min(1.0, ((x - ax) * dx + (z - az) * dz) / length2))
        px, pz = ax + dx * t - x, az + dz * t - z
        best = min(best, px * px + pz * pz)
        j = i
    return math.sqrt(best)


def signed_distance(poly, x, z):
    """Negative inside the curve."""
    d = edge_distance(poly, x, z)
    return -d if contains(poly, x, z) else d


def smoothstep(edge0, edge1, value):
    t = max(0.0, min(1.0, (value - edge0) / (edge1 - edge0)))
    return t * t * (3.0 - 2.0 * t)


def ellipse(cx, cz, rx, rz, count=8, wobble=0.0):
    pts = []
    for k in range(count):
        angle = 2.0 * math.pi * k / count
        r = 1.0 + wobble * math.sin(3.0 * angle)
        pts.append((round(cx + rx * r * math.cos(angle), 2), round(cz + rz * r * math.sin(angle), 2)))
    return pts


def scaled(points, factor):
    cx = sum(p[0] for p in points) / len(points)
    cz = sum(p[1] for p in points) / len(points)
    return [(round(cx + (x - cx) * factor, 2), round(cz + (z - cz) * factor, 2)) for x, z in points]


def ribbon(path, half_width):
    """Control points of a closed curve around an open polyline: one side forward, the other back."""
    left, right = [], []
    for k, (x, z) in enumerate(path):
        ax, az = path[max(k - 1, 0)]
        bx, bz = path[min(k + 1, len(path) - 1)]
        dx, dz = bx - ax, bz - az
        length = math.hypot(dx, dz) or 1.0
        nx, nz = -dz / length, dx / length
        left.append((round(x + nx * half_width, 2), round(z + nz * half_width, 2)))
        right.append((round(x - nx * half_width, 2), round(z - nz * half_width, 2)))
    return left + right[::-1]


class Terrain:
    def __init__(self, scmap):
        self.w = scmap.width + 1
        self.h = scmap.height + 1
        self.scale = scmap.height_scale
        self.z = [v * self.scale for v in scmap.heights()]

    def apply(self, poly, margin, fn):
        """fn(old, signed distance) -> new, over the vertices within `margin` of the curve's box."""
        xs = [p[0] for p in poly]
        zs = [p[1] for p in poly]
        x0, x1 = max(0, int(min(xs) - margin)), min(self.w - 1, int(max(xs) + margin) + 1)
        z0, z1 = max(0, int(min(zs) - margin)), min(self.h - 1, int(max(zs) + margin) + 1)
        for z in range(z0, z1 + 1):
            for x in range(x0, x1 + 1):
                i = z * self.w + x
                self.z[i] = fn(self.z[i], signed_distance(poly, x, z))

    def raise_to(self, points, top, falloff):
        """Plateau: `top` inside the curve, blending back to the old ground over `falloff` outside."""
        self.apply(spline_polygon(points), falloff,
                   lambda old, d: old + (max(old, top) - old) * (1.0 - smoothstep(0.0, falloff, d)))

    def dig_to(self, points, floor, falloff):
        """Basin: `floor` inside the curve, rising back to the old ground over `falloff` outside."""
        self.apply(spline_polygon(points), falloff,
                   lambda old, d: old + (min(old, floor) - old) * (1.0 - smoothstep(0.0, falloff, d)))

    def words(self):
        return [max(0, min(65535, int(round(v / self.scale)))) for v in self.z]


def fill_bodies(terrain, specs):
    """The engine's CWaterBodies::Build in Python, for the preview: the level of each vertex, or None."""
    w, h = terrain.w, terrain.h
    owner = [None] * (w * h)
    for spec in specs:
        poly = spline_polygon(spec["outline"]) if spec.get("outline") else None
        inside = (lambda x, z: contains(poly, x, z)) if poly else (lambda x, z: True)
        below = lambda i: terrain.z[i] < spec["fill"]
        level = None if spec.get("dry") else spec["level"]
        if "seed" not in spec:
            for z in range(h):
                for x in range(w):
                    i = z * w + x
                    if owner[i] is None and below(i) and inside(x, z):
                        owner[i] = ("body", level)
            continue
        sx, sz = int(math.floor(spec["seed"][0] + 0.5)), int(math.floor(spec["seed"][1] + 0.5))
        stack = [(sx, sz)]
        if owner[sz * w + sx] is not None or not below(sz * w + sx) or not inside(sx, sz):
            continue
        owner[sz * w + sx] = ("body", level)
        while stack:
            x, z = stack.pop()
            for nx, nz in ((x - 1, z), (x + 1, z), (x, z - 1), (x, z + 1)):
                if 0 <= nx < w and 0 <= nz < h:
                    i = nz * w + nx
                    if owner[i] is None and below(i) and inside(nx, nz):
                        owner[i] = ("body", level)
                        stack.append((nx, nz))
    return owner


def write_preview(path, terrain, owner, scale=3):
    """Terrain in grey by height, water in blue (darker when deeper), bodies' levels as hue."""
    w, h = terrain.w, terrain.h
    top = max(terrain.z) or 1.0
    rows = []
    for z in range(h):
        row = bytearray()
        for x in range(w):
            i = z * w + x
            ground = terrain.z[i]
            shade = int(60 + 180 * ground / top)
            o = owner[i]
            level = o[1] if o is not None else (SEA[0] if ground < SEA[0] else None)
            if o is not None and o[1] is None:
                colour = (min(255, shade + 40), shade, int(shade * 0.6))  # dry body: tinted ground
            elif level is not None and ground < level:
                depth = min(1.0, (level - ground) / 10.0)
                hue = level / 34.0
                colour = (int(30 + 120 * hue), int(90 + 100 * (1 - depth)), int(200 + 55 * (1 - depth)))
            else:
                colour = (shade, shade, shade)
            row += bytes(colour) * scale
        for _ in range(scale):
            rows.append(b"\x00" + bytes(row))
    raw = b"".join(rows)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * scale, h * scale, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def lua_points(points):
    return "{ " + ", ".join("{ %g, %g }" % p for p in points) + " }"


def build(base_dir, out_root):
    base = os.path.basename(os.path.normpath(base_dir))
    scmap = ScMap(open(os.path.join(base_dir, base + ".scmap"), "rb").read())
    terrain = Terrain(scmap)
    bodies = []
    specs = []

    # Sea bay in the north-west corner, away from both starts (south-west and north-east).
    terrain.dig_to(ellipse(24, 24, 44, 38, wobble=0.1), 0.0, 10.0)

    # Mesa with a crater lake: raised to 34, crater dug to 24, lake at 30.
    mesa = ellipse(88, 104, 30, 24, wobble=0.08)
    crater = ellipse(88, 104, 15, 11, wobble=0.12)
    terrain.raise_to(mesa, 34.0, 10.0)
    terrain.dig_to(crater, 24.0, 5.0)
    bodies.append("{ Elevation = 30, Deep = 28, Abyss = 25, Outline = %s }" % lua_points(scaled(crater, 1.35)))
    specs.append({"level": 30.0, "fill": 30.0, "outline": scaled(crater, 1.35)})

    # Hill with three terraced pools, each its own level, split by dikes at the hill's height.
    hill = [(140, 132), (206, 128), (214, 150), (204, 172), (140, 176), (130, 154)]
    terrain.raise_to(hill, 26.0, 10.0)
    for cx, level in ((152, 23.0), (172, 20.0), (192, 17.0)):
        pool = ellipse(cx, 152, 6.5, 11, count=6)
        terrain.dig_to(pool, level - 5.0, 2.5)
        bodies.append("{ Elevation = %g, Seed = { %g, 152 }, Outline = %s }" % (level, cx, lua_points(scaled(pool, 1.2))))
        specs.append({"level": level, "fill": level, "seed": (cx, 152), "outline": scaled(pool, 1.2)})

    # Ridge at 16 along a winding spline, a river channel at 14 dug into it (floor 9).
    path = [(52, 196), (78, 186), (104, 200), (130, 210), (156, 198), (182, 204), (204, 216)]
    terrain.raise_to(ribbon(path, 9.0), 16.0, 8.0)
    channel = path[1:-1]
    terrain.dig_to(ribbon(channel, 2.5), 9.0, 3.0)
    bodies.append("{ Elevation = 14, Deep = 12, Abyss = 10, Outline = %s }" % lua_points(ribbon(channel, 5.0)))
    specs.append({"level": 14.0, "fill": 14.0, "outline": ribbon(channel, 5.0)})

    # Polder: a dike at 6 around ground dug to 1, below the sea (3) and kept dry.
    dike = ellipse(196, 64, 22, 18)
    inside = ellipse(196, 64, 15, 11)
    terrain.raise_to(dike, 6.0, 5.0)
    terrain.dig_to(inside, 1.0, 3.0)
    bodies.append("{ Dry = true, FillTo = %g, Outline = %s }" % (SEA[0], lua_points(scaled(inside, 1.15))))
    specs.append({"dry": True, "fill": SEA[0], "outline": scaled(inside, 1.15)})

    scmap.set_heights(terrain.words())
    scmap.set_water(True, *SEA)

    out_dir = os.path.join(out_root, NAME)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, NAME + ".scmap"), "wb") as f:
        f.write(scmap.data)

    scenario = open(os.path.join(base_dir, base + "_scenario.lua"), encoding="latin-1").read()
    scenario = scenario.replace("/maps/%s/%s" % (base, base), "/maps/%s/%s" % (NAME, NAME))
    scenario = scenario.replace("/maps/%s/%s" % (base.lower(), base.lower()), "/maps/%s/%s" % (NAME, NAME))
    scenario = re.sub(r"name\s*=\s*'[^']*'", "name = 'FAF RE water levels'", scenario, count=1)
    scenario = re.sub(r"name\s*=\s*\"[^\"]*\"", "name = \"FAF RE water levels\"", scenario, count=1)
    table = "    WaterBodies = {\n" + "".join("        %s,\n" % b for b in bodies) + "    },\n"
    scenario = re.sub(r"(ScenarioInfo\s*=\s*\{\n)", lambda m: m.group(1) + table, scenario, count=1)
    if "WaterBodies" not in scenario:
        raise SystemExit("could not place WaterBodies in the scenario")
    if "/maps/%s/" % NAME not in scenario:
        raise SystemExit("could not point the scenario at the new map files")
    with open(os.path.join(out_dir, NAME + "_scenario.lua"), "w", encoding="latin-1", newline="\n") as f:
        f.write("-- Generated by faf-re tools/scenarios/water-levels/make_map.py from %s.\n" % base)
        f.write(scenario)
    shutil.copyfile(os.path.join(base_dir, base + "_save.lua"), os.path.join(out_dir, NAME + "_save.lua"))
    # The test's own script: checks the water and logs WATERTEST lines.
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copyfile(os.path.join(here, "map", NAME + "_script.lua"), os.path.join(out_dir, NAME + "_script.lua"))

    owner = fill_bodies(terrain, specs)
    write_preview(os.path.join(out_dir, NAME + "_water_preview.png"), terrain, owner)
    for k, spec in enumerate(specs):
        cells = sum(1 for o in owner if o is not None and o is not None and o[1] == (None if spec.get("dry") else spec["level"]))
        print("body %d: %s, %d vertices" % (k + 1, "dry" if spec.get("dry") else "level %g" % spec["level"], cells))
    heights = terrain.z
    flooded = sum(1 for v in heights if v < SEA[0])
    print("RESULT wrote %s: %d bodies, sea %g, %.1f%% of vertices below the sea, terrain %.2f..%.2f" % (
        out_dir, len(bodies), SEA[0], 100.0 * flooded / len(heights), min(heights), max(heights)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    build(sys.argv[1], sys.argv[2])
