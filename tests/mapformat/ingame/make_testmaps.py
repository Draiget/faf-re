"""python tests/mapformat/ingame/make_testmaps.py [maps_folder]

Writes the in-game test maps for the Classic bridge into the user's Maps folder, plus expected.json (heights, terrain ids).

mapfmt_ext_a: 256 x 256 cells, stock height step (min 0, 2^-7), two splat layers, water at 25, two start markers.
mapfmt_ext_b: 256 x 192 cells (non-square), fine height step (min 10, 2^-9) so the bridge must quantise.
"""
import json, math, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "tools", "mapformat"))
from mapfmt.builder import MapBuilder          # noqa: E402
from mapfmt.schema import plane                # noqa: E402
import golden_content as G                     # noqa: E402

MAPS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.expanduser("~"), "Documents", "My Games", "Gas Powered Games", "Supreme Commander Forged Alliance", "Maps")


def heights(cx, cz, min_h, step_log2):
    vals, units = [], []
    for z in range(cz + 1):
        for x in range(cx + 1):
            h = 30.0 + 14.0 * math.sin(x / 17.0) * math.cos(z / 23.0) + 0.05 * ((x * 7 + z * 13) % 11)
            v = int(round((h - min_h) / (2.0 ** step_log2)))
            vals.append(v)
            units.append(min_h + v * (2.0 ** step_log2))
    return vals, units


def build(stem, cx, cz, min_h, step_log2):
    vals, units = heights(cx, cz, min_h, step_log2)
    grid, hght, _ = G.grid_hght(cx, cz, min_h, step_log2, 1, vals)
    sw, sh = cx, cz
    wa = bytes(max(0, 255 - (x * 255 // sw)) for z in range(sh) for x in range(sw))
    wb = bytes(255 - v for v in wa)
    ids = bytes(5 if x > cx // 2 else 0 for z in range(cz) for x in range(cx))
    mat = lambda i, n, a, nr: {"id": i, "name": n, "albedo": a, "normal": nr, "orm": "", "height": "", "flags": 0b10000,  # noqa: E731
                               "tileSize": 12.0 if i == 0 else 20.0, "rotationDeg": 0.0, "normalStrength": 1.0,
                               "roughnessScale": 1.0, "metalness": 0.0, "parallaxScale": 0.0,
                               "heightBlendSharpness": 1.0, "macroInfluence": 0.0, "gameplaySurface": 0xFFFF}
    marker = lambda n, x, z, a: {"type": 1, "name": n, "pos": [x, 30.0, z], "yawDeg": 0.0, "army": a, "flags": 0, "props": [], "links": []}  # noqa: E731
    items = [
        ("META", 0, G.meta(stem), False), ("GRID", 0, grid, False), ("HGHT", 0, hght, True),
        ("PLAY", 0, {"x0": 0, "z0": 0, "x1": cx, "z1": cz, "borderMode": 1, "polygon": []}, False),
        ("GPLY", 0, {"legacyTerrainIds": 1,
                     "surfaces": [{"id": 0, "name": "Default", "flags": 0, "speedMul": 256, "effectsKey": ""},
                                  {"id": 5, "name": "Dirt", "flags": 0, "speedMul": 256, "effectsKey": "Dirt"}],
                     "idWidth": 1, "ids": plane(ids, 1), "masks": []}, True),
        ("WBOD", 0, {"bodies": [{"id": 0, "name": "Water", "kind": 0, "level": 25.0, "extentKind": 0}]}, False),
        ("PROP", 0, {"blueprints": ["/env/common/props/rocks/rock01_prop.bp"],
                     "props": [{"blueprintIndex": 0, "pos": [60.0 + 9 * i, 33.0, 80.0], "rot": [0.0, 0.0, 0.0, 1.0],
                                "scale": [1.0, 1.0, 1.0], "flags": 0} for i in range(4)]}, False),
        ("MATL", 0, {"materials": [mat(0, "Grass", "/env/evergreen/layers/grass001_albedo.dds", "/env/evergreen/layers/grass001_normals.dds"),
                                   mat(1, "Dirt", "/env/evergreen/layers/dirt001_albedo.dds", "/env/evergreen/layers/dirt001_normals.dds")]}, False),
        ("SPLT", 0, {"width": sw, "height": sh, "mode": 1, "layers": 2, "materialIds": [0, 1],
                     "planes": [plane(wa, 1), plane(wb, 1)]}, True),
        ("LITE", 0, {"sunDir": [0.5, 0.75, 0.4330127], "sunColor": [1.0, 0.95, 0.85], "sunIntensity": 1.6, "sunAngularDeg": 0.5,
                     "hasMoon": 0, "ambientMode": 0, "ambient": [0.45, 0.5, 0.6], "ground": [0.3, 0.3, 0.3], "ambientIntensity": 1.0,
                     "shadowFill": [0.3, 0.3, 0.38], "shadowDistance": 500.0, "cascades": 1, "shadowBias": 0.001953125,
                     "shadowStrength": 1.0, "fogMode": 1, "fogColor": [0.7, 0.78, 0.9], "fogStart": 300.0, "fogEnd": 900.0,
                     "fogDensity": 0.0, "fogHeightFalloff": 0.0, "fogBaseHeight": 0.0, "toneMap": 0, "exposureEV": 0.0,
                     "bloomIntensity": 0.08, "bloomThreshold": 1.0, "lut": ""}, False),
    ]
    items = G._n(items)
    b = MapBuilder(3, G.__dict__.get("guid", lambda n: b"\0" * 16)(stem) if callable(G.__dict__.get("guid")) else b"\0" * 16)
    for cid, inst, d, compress in items:
        b.add(cid, d, inst, compress)
    data = b.build(0, 0, 0)

    folder = os.path.join(MAPS, stem)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, stem + ".scmap"), "wb") as f:
        f.write(data)
    vf = "/maps/%s/%s" % (stem, stem)
    with open(os.path.join(folder, stem + "_scenario.lua"), "w") as f:
        f.write("""version = 3
ScenarioInfo = {
    name = '%s',
    description = 'Container 3 test map for the Classic bridge',
    preview = '',
    map_version = 1,
    type = 'skirmish',
    starts = true,
    size = { %d, %d },
    reclaim = { 0, 0 },
    map = '%s.scmap',
    save = '%s_save.lua',
    script = '%s_script.lua',
    norushradius = 40,
    Configurations = {
        standard = {
            teams = { { name = 'FFA', armies = { 'ARMY_1', 'ARMY_2' } } },
            customprops = {},
        },
    },
}
""" % (stem, cx, cz, vf, vf, vf))
    armies = ""
    for i, (x, z) in enumerate([(cx * 0.25, cz * 0.5), (cx * 0.75, cz * 0.5)], 1):
        armies += """        ['ARMY_%d'] = { ['personality'] = '', ['plans'] = '', ['color'] = 0, ['faction'] = 0,
            ['Economy'] = { ['mass'] = 0, ['energy'] = 0 }, ['Alliances'] = {}, ['ArmyIndex'] = %d,
            ['Units'] = { ['type'] = 'GROUP', ['orders'] = '', ['platoon'] = '',
                ['Units'] = { ['INITIAL'] = { ['type'] = 'GROUP', ['orders'] = '', ['platoon'] = '', ['Units'] = {} } } },
            ['PreBuiltUnits'] = {} },
""" % (i, i)
    markers = ""
    for i, (x, z) in enumerate([(cx * 0.25, cz * 0.5), (cx * 0.75, cz * 0.5)], 1):
        markers += """                ['ARMY_%d'] = { ['color'] = 'ff800080', ['type'] = 'Blank Marker', ['prop'] = '/env/common/props/markers/M_Blank_prop.bp',
                    ['orientation'] = VECTOR3( 0, 0, 0 ), ['position'] = VECTOR3( %g, 30, %g ) },
""" % (i, x, z)
    with open(os.path.join(folder, stem + "_save.lua"), "w") as f:
        f.write("""Scenario = {
    ['next_area_id'] = '0', ['Props'] = {}, ['Areas'] = {},
    ['MasterChain'] = { ['_MASTERCHAIN_'] = { ['Markers'] = {
%s            } } },
    ['Chains'] = {}, ['Orders'] = {}, ['next_queue_id'] = '1', ['Platoons'] = {}, ['next_platoon_id'] = '1',
    ['next_chain_id'] = '1', ['next_marker_id'] = '1',
    ['Armies'] = {
%s    },
}
""" % (markers, armies))
    pts = [(10, 10), (64, 64), (100, 40), (127, 96), (128, 96), (200, 150), (250, 20), (30, 180 if cz > 180 else cz - 8)]
    exp = []
    for (x, z) in pts:
        x, z = min(x, cx), min(z, cz)
        exp.append({"x": x, "z": z, "h": units[z * (cx + 1) + x], "id": 5 if x > cx // 2 else 0})
    with open(os.path.join(folder, stem + "_script.lua"), "w") as f:
        f.write("""local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

function OnPopulate()
    ScenarioUtils.InitializeArmies()
end

local points = {
%s}

function OnStart(self)
    ForkThread(function()
        WaitSeconds(2)
        local fmt = GetMapFormat and GetMapFormat() or nil
        if fmt then
            LOG('MAPFMT-TEST format id=' .. tostring(fmt.id) .. ' name=' .. tostring(fmt.name) .. ' container=' .. tostring(fmt.container)
                .. ' revision=' .. tostring(fmt.revision) .. ' required=' .. tostring(fmt.requiredFeatures) .. ' simHash=' .. tostring(fmt.simHash))
            for i, n in ipairs(fmt.features) do LOG('MAPFMT-TEST feature ' .. n) end
        else
            LOG('MAPFMT-TEST GetMapFormat missing')
        end
        local sx, sz = GetMapSize()
        LOG('MAPFMT-TEST size ' .. tostring(sx) .. ' ' .. tostring(sz))
        for i, p in ipairs(points) do
            local h = GetTerrainHeight(p[1], p[2])
            local tt = GetTerrainType(p[1], p[2])
            LOG(string.format('MAPFMT-TEST h x=%%d z=%%d got=%%.5f expect=%%.5f type=%%s expectId=%%d', p[1], p[2], h, p[3], tostring(tt and tt.Name), p[4]))
        end
        LOG('MAPFMT-TEST surface water ' .. tostring(GetSurfaceHeight(10, 10)))
        LOG('MAPFMT-TEST done')
    end)
end
""" % "".join("    {%d, %d, %.6f, %d},\n" % (e["x"], e["z"], e["h"], e["id"]) for e in exp))
    return folder, exp


if __name__ == "__main__":
    out = {}
    for stem, cx, cz, mn, st in [("mapfmt_ext_a", 256, 256, 0.0, -7), ("mapfmt_ext_b", 256, 192, 10.0, -9)]:
        out[stem] = build(stem, cx, cz, mn, st)[1]
        print("wrote", stem)
    print(json.dumps(out)[:200])
