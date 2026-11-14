-- Golden cases of the erosion suite (docs/projects/editor/TERRAIN_GEN_DESIGN.md, stage T3). One line per case: label | op | params | inputs | checksum.
-- Shared by the native test (engine/faf-re/src/moho/editor/tests/EdErosionTest.cpp: runs these with 1, 2, 3, 5 and 8 threads and rewrites the checksums with --update) and the
-- in-editor self test (selftest_erosion.lua: the same cases through the ed_field_* natives). Fixtures: H = mountain field 65 x 65 = add(affine(ridged seed=11 scale=26 octaves=3 persistence=0.4, mul=55), affine(perlin seed=111 scale=13 octaves=3, mul=8)),
-- R = perlin 65 x 65 seed=4 scale=14 octaves=3 (0..1 erodibility), F = const 33 x 33 value=10. The checksum is FNV-1a over the float32 bit patterns (ed_field_checksum), valid for the editor build (MSVC x64, no FMA contraction).

-- The cases from hydraulic_pinned on cover the map edge option (edge=pinned is the old behaviour) and the settings that vary the erosion or keep the terrain's range and volume.
-- Hillslope creep (creep = 2 passes per round by default) changed every droplet case below except the creep=0 one: droplet_creep0 carries the checksum `droplet` had before creep existed (the old
-- solver is unchanged), droplet_creep4 / droplet_creep_mask cover a stronger creep and creep with a mask and variation (protect, hardness).
-- The droplet cases use the default of 32 feedback rounds (they had 4: droplet_rounds4 is the old behaviour, its checksum is the one `droplet` had before), the stream cases the
-- smooth cut share F / (1 + F) and the valley width that grows with the catchment (width_vary, route_every).

Cases = [[
hydraulic|erode_hydraulic|iterations=60|a=H|4e24ea4c5e5dcd93
hydraulic_wear|erode_hydraulic|iterations=60,output=wear|a=H|e40d60a1bbc562b2
hydraulic_deposit|erode_hydraulic|iterations=60,output=deposit|a=H|aa621a4b5dc0a6c8
hydraulic_flow|erode_hydraulic|iterations=60,output=flow|a=H|25fdf4eb1a8b1fcc
hydraulic_water|erode_hydraulic|iterations=60,output=water|a=H|8ddb57d1d2d25c78
hydraulic_thermal|erode_hydraulic|iterations=60,thermal=0.5,talus=0.6|a=H|b5e355ea15602b4f
hydraulic_closed|erode_hydraulic|iterations=60,edge=closed|a=H|4b07ed21402cf6e9
hydraulic_mask|erode_hydraulic|iterations=60|a=H,mask=R|52f33e431d89e757
droplet|erode_droplet|density=0.8,seed=3|a=H|1a5a53e59c6d9a79
droplet_wear|erode_droplet|density=0.8,seed=3,output=wear|a=H|73e10af6989cc7b7
droplet_deposit|erode_droplet|density=0.8,seed=3,output=deposit|a=H|353ceb787731e146
droplet_thermal|erode_droplet|density=0.8,seed=3,thermal=0.5,thermal_steps=10|a=H|009548aab3be3858
droplet_mask|erode_droplet|density=0.8,seed=3|a=H,mask=R|29e779318aac1ba0
stream|erode_stream|iterations=6|a=H|1f0131c0c949a5f8
stream_wear|erode_stream|iterations=6,output=wear|a=H|213772c0890eb481
stream_flow|erode_stream|iterations=6,output=flow|a=H|81b86adb8b1434f8
stream_mask|erode_stream|iterations=6|a=H,mask=R|87e3cbf4a3c68a05
slope_area|slope_area|bins=10,first=2|a=H|707ff2bdee825b0d
hydraulic_nomasks|erode_hydraulic|iterations=60,masks=0|a=H|4e24ea4c5e5dcd93
basin_depth|basin_depth||a=H|506840f3723647f5
hydraulic_pinned|erode_hydraulic|iterations=60,edge=pinned|a=H|c322f2e192afd840
hydraulic_vary|erode_hydraulic|iterations=60,vary=0.6,rain_vary=0.5,protect=0.5,keep_range=1,seed=5|a=H|c14e755412a55273
droplet_old_rule|erode_droplet|density=0.8,seed=3,accel=0|a=H|fba30229e74ab612
droplet_vary|erode_droplet|density=0.8,seed=3,vary=0.6,rain_vary=0.5,protect=0.5,drop_vary=0.5,thermal=0.4,thermal_steps=4|a=H|3d87329f291df26f
droplet_conserve|erode_droplet|density=0.8,seed=3,conserve=1,max_change=2|a=H|69c7b815234c5a51
stream_jitter|erode_stream|iterations=6,jitter=0.5,vary=0.5,rain_vary=0.5,protect=0.5,seed=2|a=H|bc27d518280d70af
droplet_rounds4|erode_droplet|density=0.8,seed=3,rounds=4|a=H|61e9b262b74e8894
droplet_rounds1|erode_droplet|density=0.8,seed=3,rounds=1|a=H|92b431901e3781ad
droplet_creep0|erode_droplet|density=0.8,seed=3,creep=0|a=H|3f798e896678586b
droplet_creep4|erode_droplet|density=0.8,seed=3,creep=4|a=H|98f69bc2c0ffeaaf
droplet_creep_mask|erode_droplet|density=0.8,seed=3,creep=3,vary=0.5,protect=0.5,drop_vary=0.5|a=H,mask=R|49b01cbf76df8d9b
stream_width0|erode_stream|iterations=6,width_vary=0|a=H|bb598651e5b92649
stream_route3|erode_stream|iterations=6,route_every=3|a=H|7c91d68825f08555
stream_hierarchy|erode_stream|iterations=6,k=0.1,width_vary=1,widen=2,area_min=20|a=H|2d75ed50e18c29bc
]]
