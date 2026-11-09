# Water bodies: lakes at their own levels

A map has one sea at one level. Water bodies add lakes, pools and rivers at other levels, and dry ground below the sea, without touching the `.scmap`. Each body is a few lines in the map's `_scenario.lua`.

**Where it works:** in this engine, with the game switch `sim_FixWaterBodies` on. No FAF release turns it on yet; for testing, start the game with `/con sim_FixWaterBodies=1`. With the switch off, in the original game, or in any other engine, the map plays and looks as if the bodies weren't there: sea only. So a map whose layout depends on its lakes is a different map where they're off.

Map editors keep opening the map: they ignore a scenario key they don't know.

## Example

In `<map>_scenario.lua`, inside `ScenarioInfo = { ... }`:

```lua
ScenarioInfo = {
    WaterBodies = {
        -- a lake on a plateau: fills the basin around the seed up to 48
        { Elevation = 48, Seed = { 312, 205 } },
        -- a lake with its own shading depths, kept inside a rectangle
        { Elevation = 12, Deep = 9, Abyss = 2, Seed = { 700, 640 }, Bounds = { 600, 560, 800, 720 } },
        -- dry ground below a sea at 17.5 (a polder): filled like a body, but no water
        { Dry = true, FillTo = 17.5, Seed = { 120, 900 } },
    },
    name = 'My map',
    -- ... the rest as before
}
```

## How a body fills

A body starts at its seed and spreads to every connected point of the terrain that lies below its level, like water poured into a basin. It stops where the terrain rises above the level, so its shore needs no walls. A lake higher than the sea, a crater lake on a plateau and a pond in a valley all work this way.

- Positions are map units, the same `x, z` you see for units and markers in the editor. The fill works on the height field's points (one per map unit); the seed takes the nearest one.
- The terrain at the seed must be below the level, or the body is skipped.
- Bodies fill in list order. Ground an earlier body took stays with it.
- At most 255 bodies per map.
- Levels are flat. A sloping river or a waterfall is several bodies, each at its own level.

## Fields

| Field | Needed | What it does |
|---|---|---|
| `Elevation` | yes, unless `Dry` | The water level. |
| `Seed = { x, z }` | yes, unless there's an `Outline` | Where the fill starts. |
| `Outline = { {x, z}, {x, z}, ... }` | no | 3 or more points of a closed smooth curve; the body stays inside it. See below. |
| `FillTo` | only with `Dry` | The fill takes ground below this level instead of below `Elevation`. |
| `Dry = true` | no | The body has no water. With `FillTo` = the sea's level it keeps a low area dry. |
| `Bounds = { x0, z0, x1, z1 }` | no | The fill stays inside this rectangle (map units, edges included). |
| `Deep`, `Abyss` | no | Levels used only for the water's colour, as the sea's deep and abyss levels. By default the sea's distances below its level, applied to this body; on a map without a sea, 2.5 and 15 below. Both must be below `Elevation`. |

### Outlines

An outline is a closed curve through its points (a Catmull-Rom spline). Use it to:

- **keep a body from leaking** into ground below its level that you don't want flooded, for example a river channel cut into a slope;
- **put two pools at different levels in one basin**: give each pool an outline and no seed. Without a seed, every point inside the outline that is below the level belongs to the body.

The curve passes through its points but bulges outward between them, about 2 map units in the middle of each side of a 16-unit square. Leave a few units between neighbouring outlines.

## In the game

Each body behaves like the sea at its own level:

- Naval units float on it and can't leave it: a ship in a raised lake stays in that lake. Pathfinding treats separate lakes as separate water.
- Hover units ride on it; land units can't enter deep water; amphibious units walk on its bed.
- Shots and splashes hit the surface at the body's level; build placement and the build preview use the level where you build.
- A dry body is land: tanks drive on its floor even below the sea.
- AI and Lua see the same levels: `GetSurfaceHeight(x, z)` returns the water level where there is water.

How it's drawn:

- Each body gets the same water as the sea (waves, colour by depth, shoreline, sun reflection) at its level. The sea is not drawn over a dry body.
- The minimap and the zoomed-out map show bodies as water and dry bodies as land.
- The lake the camera sees most also reflects units; other lakes reflect only the sky.

## Limits

- **Steep banks look stepped under water.** The water colour comes from a map with one value per 2 x 2 map units. A bank that rises several units within that, running diagonally, shows a small saw-tooth in the colour under the water. Gentle banks look smooth.
- **Units under a lake** don't get the underwater colour on their own model, as they do in the sea; the water drawn over them still colours them.
- **Wave generators** (the shore waves a map places) stay at the sea.
- **Shine:** when zoomed in, dry ground below the highest lake shines a little less.

## Checking a map

The game log lists every body it filled, once for the game and once for the window:

```
info: Water bodies: 1 at 30, 836 cells in [70, 106] x [88, 117]
info: Water bodies: drawing 6 waters in 302 quads
```

A body that can't fill gets a warning with the reason, for example `water body 2 skipped: terrain at its seed (312, 205) is not below 48 or is another body's`, or `Outline is not 3 or more { x, z } points`. With the switch off the log says `the map describes some, but this game has them off (sim_FixWaterBodies); sea only`.

An example map with a crater lake, three pools at different levels, a river on a ridge and a dry area below the sea is made by `tools/scenarios/water-levels/make_map.py`; `tools/scenarios/1p-waterlevels-main.yaml` plays it and checks each water.
