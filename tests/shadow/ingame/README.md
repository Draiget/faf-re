# In-game shadow filter scenes

Not part of the engine: copy one `shadow_scene_*.lua` as `<exe folder>/fafengine/lua/test/dynlights_test.lua` (the sim hook in `data/fafengine/lua/simInit.lua` runs it) and one `shadow_camera_*.lua` as `.../dynlights_camera.lua` (the user-interface hook in `ui/game/gamemain.lua` runs it), then start a skirmish
(`main_x64.exe /init init_faf.lua /nobugreport /d3d12 /windowed 1600 900 /nomovie /nosound /seed 7 /faction 1 /map /maps/adaptive_acid_lakes.v0004/adaptive_acid_lakes_scenario.lua`, with `FAF_GAL_DUMP_DIR` / `FAF_GAL_DUMP_SECONDS=1` for frames, `FAF_GPU_PROFILE=150` for GPU times).

| File | What |
|---|---|
| `shadow_scene_wide.lua` | 8 land units, 8 structures, a 12-piece wall and 3 air units next to the commander |
| `shadow_scene_close.lua` | the commander, 2 T3 units, tanks, two point defences, 4 wall pieces and a gunship, for close-up pairs |
| `shadow_camera_wide.lua` / `_close.lua` | pause at 8 s, zoom 28 / 14, cycle `ren_ShadowFilter` 0, 1, 2, 3, 4, 0 (5 s each) and draw "SHADOW MODE n" on screen |
| `shadow_camera_perf.lua` | zoom 45, 9 s per mode, 0 1 2 3 4 0 4 3 2 1 0 (for `FAF_GPU_PROFILE` at 3840x2160) |
| `shadow_camera_bias.lua` | zoom 6 on the commander: `ren_ShadowFilterBias` / `ren_ShadowFilterSlope` variations |
| `pick_frames.py <dumpdir> <out>` | groups the dumped frames by the on-screen label and saves the last frame of each group |
| `perf.py <log> [--merge]` | per-pass GPU ms per mode from the render profile blocks of a log |
| `grid.py` | crops and tiles the picked frames |
