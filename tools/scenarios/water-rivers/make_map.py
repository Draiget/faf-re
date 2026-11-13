"""Builds the water-rivers test map (docs/projects/RIVERS.md): a shipped map's terrain with a plateau raised and
three rivers cut into it, each described by a `River` key of a water body in the scenario.

    python make_map.py <base map folder> <output maps folder>

for example `make_map.py "<game>/maps/SCMP_012" "<vault>/maps"`, which writes `<vault>/maps/faf_re_waterrivers/`
(scmap, scenario, save, script). Nothing binary is kept in the repo: the map is generated from the base map each time.

The terrain is a plateau at 50 over the middle of the map, with:

- river A (x 28 .. 205, z 52 .. 86): a deep river (bed 5 under the surface) that falls from 44 to 28, with a 7.5
  unit waterfall at (130, 76) where it steps from 39 to 31.5 (the bed drops 8.5 there, so the plunge pool is deep);
  the movement checks of naval, hover, submarine, amphibious and air units run on it;
- river B (z 112): a shallow river (the bed 0.04 under the surface everywhere), flat at 41, a fall of exactly 0.75
  at x = 70 down to 40.25 and flat on. The bed steps down by the same 0.75, which the slope limit (0.75) lets a
  land unit walk, so the fall is the only thing that stops a tank there;
- river B2 (z 140): the same bed and surface heights as B, but no fall: the surface runs down from 41 to 40.25 over
  10 units, and a tank walks across.

The bed follows each river's own level (the engine's derivation, repeated here in double precision), so every
vertex in the channel is wet and the banks rise to the plateau over 6 to 8 units.
"""
import importlib.util
import math
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "water-levels"))
from scmap import ScMap  # noqa: E402

_spec = importlib.util.spec_from_file_location("waterlevels_make_map", os.path.join(HERE, "..", "water-levels", "make_map.py"))
wl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wl)

NAME = "faf_re_waterrivers"
STEPS = 8  # kRiverDefaultSteps
PLATEAU = 50.0

# (x, z, Level, HalfWidth, Fall below or None)
RIVER_A = [
    (28, 64, 44.0, 6, None),
    (64, 52, 43.0, 6, None),
    (100, 60, 41.5, 7, None),
    (130, 76, 39.0, 7, 31.5),
    (162, 86, 30.5, 8, None),
    (205, 82, 28.0, 8, None),
]
RIVER_B = [
    (40, 112, 41.0, 5, None),
    (70, 112, 41.0, 5, 40.25),
    (80, 112, 40.25, 5, None),
    (120, 112, 40.25, 5, None),
]
RIVER_B2 = [
    (40, 140, 41.0, 5, None),
    (70, 140, 41.0, 5, None),
    (80, 140, 40.25, 5, None),
    (120, 140, 40.25, 5, None),
]


def catmull(p0, p1, p2, p3, t):
    a = 2.0 * p1
    b = p2 - p0
    c = (2.0 * p0 - 5.0 * p1) + (4.0 * p2 - p3)
    d = (3.0 * p1 - p0) + (p3 - 3.0 * p2)
    return 0.5 * (((a + b * t) + c * t * t) + d * t * t * t)


def segments(points):
    """The engine's RiverSegments: (x0, z0, x1, z1, level0, level1, half0, half1)."""
    out = []
    n = len(points)
    for span in range(n - 1):
        p1, p2 = points[span], points[span + 1]
        p0 = points[span - 1] if span > 0 else p1
        p3 = points[min(span + 2, n - 1)]
        start = p1[4] if p1[4] is not None else p1[2]
        end = p2[2]
        last = (p1[0], p1[1], start, p1[3])
        for step in range(1, STEPS + 1):
            t = step / STEPS
            if step == STEPS:
                x, z, level, half = p2[0], p2[1], end, p2[3]
            else:
                x = catmull(p0[0], p1[0], p2[0], p3[0], t)
                z = catmull(p0[1], p1[1], p2[1], p3[1], t)
                level = start + (end - start) * t
                half = p1[3] + (p2[3] - p1[3]) * t
            if (x - last[0]) ** 2 + (z - last[1]) ** 2 > 0.0:
                out.append((last[0], last[1], x, z, last[2], level, last[3], half))
            last = (x, z, level, half)
    return out


def nearest(segs, x, z):
    """(distance, level, half width) at the nearest segment, ties to the lower one."""
    best = None
    for s in segs:
        x0, z0, x1, z1, l0, l1, h0, h1 = s
        dx, dz = x1 - x0, z1 - z0
        t = max(0.0, min(1.0, ((x - x0) * dx + (z - z0) * dz) / (dx * dx + dz * dz)))
        ex, ez = x - (x0 + dx * t), z - (z0 + dz * t)
        d2 = ex * ex + ez * ez
        if best is None or d2 < best[0]:
            best = (d2, l0 + (l1 - l0) * t, h0 + (h1 - h0) * t)
    return math.sqrt(best[0]), best[1], best[2]


def carve(terrain, points, depth_of, bank):
    """Digs the channel: the bed `depth_of(level, x)` under the river's level within the half width, rising to the
    plateau over `bank` units beyond it."""
    segs = segments(points)
    pad = max(p[3] for p in points) + bank + 2
    xs = [p[0] for p in points]
    zs = [p[1] for p in points]
    x0, x1 = max(0, int(min(xs) - pad)), min(terrain.w - 1, int(max(xs) + pad))
    z0, z1 = max(0, int(min(zs) - pad)), min(terrain.h - 1, int(max(zs) + pad))
    for z in range(z0, z1 + 1):
        for x in range(x0, x1 + 1):
            d, level, half = nearest(segs, x, z)
            if d > half + bank:
                continue
            bed = depth_of(level, x)
            if d <= half:
                value = bed
            else:
                value = bed + (PLATEAU - bed) * wl.smoothstep(0.0, bank, d - half)
            i = z * terrain.w + x
            terrain.z[i] = min(terrain.z[i], value)


def lua_point(p):
    text = "{ %g, %g, Level = %g, HalfWidth = %g" % (p[0], p[1], p[2], p[3])
    if p[4] is not None:
        text += ", Fall = true, Below = %g" % p[4]
    return text + " }"


def lua_river(name, points, elevation):
    return "{ Name = '%s', Elevation = %g, River = { Points = { %s } } }" % (
        name, elevation, ", ".join(lua_point(p) for p in points))


def build(base_dir, out_root):
    base = os.path.basename(os.path.normpath(base_dir))
    scmap = ScMap(open(os.path.join(base_dir, base + ".scmap"), "rb").read())
    terrain = wl.Terrain(scmap)

    plateau = [(10, 30), (125, 24), (245, 30), (250, 100), (245, 170), (125, 176), (10, 170), (5, 100)]
    terrain.raise_to(plateau, PLATEAU, 12.0)

    # A: bed 5 under the level above the fall, 6 under it below.
    carve(terrain, RIVER_A, lambda level, x: level - (5.0 if level > 35.0 else 6.0), 8.0)
    # B and B2: the bed 5/128 under the surface; whole words so the engine's depth is exactly 0.0390625.
    shallow = lambda level, x: math.floor(level * 128.0 + 0.5) / 128.0 - 5.0 / 128.0
    carve(terrain, RIVER_B, shallow, 6.0)
    carve(terrain, RIVER_B2, shallow, 6.0)

    scmap.set_heights(terrain.words())
    # No sea: the rivers are all the water there is.
    scmap.set_water(False, -10000.0, -10000.0, -10000.0)

    out_dir = os.path.join(out_root, NAME)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, NAME + ".scmap"), "wb") as f:
        f.write(scmap.data)

    scenario = open(os.path.join(base_dir, base + "_scenario.lua"), encoding="latin-1").read()
    scenario = scenario.replace("/maps/%s/%s" % (base, base), "/maps/%s/%s" % (NAME, NAME))
    scenario = re.sub(r"name\s*=\s*'[^']*'", "name = 'FAF RE water rivers'", scenario, count=1)
    table = "    WaterBodies = {\n" + "".join("        %s,\n" % b for b in (
        lua_river("A", RIVER_A, 44.0), lua_river("B", RIVER_B, 41.0), lua_river("B2", RIVER_B2, 41.0))) + "    },\n"
    scenario = re.sub(r"(ScenarioInfo\s*=\s*\{\n)", lambda m: m.group(1) + table, scenario, count=1)
    if "WaterBodies" not in scenario or "/maps/%s/" % NAME not in scenario:
        raise SystemExit("could not place WaterBodies in the scenario or point it at the new map files")
    with open(os.path.join(out_dir, NAME + "_scenario.lua"), "w", encoding="latin-1", newline="\n") as f:
        f.write("-- Generated by faf-re tools/scenarios/water-rivers/make_map.py from %s.\n" % base)
        f.write(scenario)
    shutil.copyfile(os.path.join(base_dir, base + "_save.lua"), os.path.join(out_dir, NAME + "_save.lua"))
    shutil.copyfile(os.path.join(HERE, "map", NAME + "_script.lua"), os.path.join(out_dir, NAME + "_script.lua"))
    print("RESULT wrote %s: 3 rivers, terrain %.2f..%.2f" % (out_dir, min(terrain.z), max(terrain.z)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    build(sys.argv[1], sys.argv[2])
