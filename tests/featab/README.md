Feature on/off capture scripts (see tests/lights/ingame for how the test hooks are installed): `featab_scene.lua` stages the scene
(`AB_SCENE = 'static'`), `featab_camera.lua` runs `AB_STEPS` (console commands per step, camera presets) with a numbered marker in the frame's corner,
`steps_*.lua` are step lists (shadow filter levels, ambient occlusion levels, filter-off comparison, ray-traced shadows), `frames.py` picks the
frame of each step from a `FAF_GAL_DUMP_DIR` dump, crops and compares them.
