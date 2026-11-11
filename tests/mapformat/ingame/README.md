# In-game test of the Classic bridge

`make_testmaps.py` writes two container 3 maps into the user's Maps folder: `mapfmt_ext_a` (256 x 256, stock height step, two splat layers, water at 25) and
`mapfmt_ext_b` (256 x 192 non-square, height step 2^-9 with a minimum of 10, so the bridge quantises). Each map's `_script.lua` logs `MAPFMT-TEST ...` lines
(`GetMapFormat()`, `GetMapSize()`, heights and terrain types at fixed points next to the expected values). `run_map.ps1` runs one on the engine built from this checkout
and prints those lines.

Result of 2026-11-04 (Direct3D 11): both maps load, `GetMapFormat()` reports Extended rev 1 with its feature names, sizes 256x256 and 256x192, every height equal to the expected value
for map A and within 1/128 for map B (as logged: "heights rounded to 1/128 units, largest error 0.0039"), terrain type ids arrive as Dirt05; the picture shows the splat textures, fog, shoreline and the unit.
Not checked: D3D12 on this master-based build logs `DeviceD3D12.cpp(2424) HRESULT 0x80004005` on every frame and stays black (cause not investigated; Direct3D 11 is clean).
