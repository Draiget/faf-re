-- Golden cases of the field engine (docs/projects/editor/TERRAIN_GEN_DESIGN.md, stage T1). One line per case: label | op | params | inputs | checksum.
-- Shared by the native test (engine/faf-re/src/moho/editor/tests/EdFieldTest.cpp: builds and checks these with 1, 2, 3, 5 and 8 threads, and
-- rewrites the checksums with --update) and the in-editor self test (selftest_fields.lua: the same cases through the ed_field_* natives).
-- params: k=v,k=v with v a number, a word, or a list x:y;x:y (flattened). inputs: name=Fixture,... with the fixtures
--   A = perlin width=33,height=33,seed=7,scale=12,octaves=4      H = affine(A, mul=40, add=10) (a height field)
--   M = voronoi width=33,height=33,scale=10,seed=5               N = perlin width=33,height=33,seed=9,scale=9,octaves=3
-- The checksum is FNV-1a over the float32 bit patterns (ed_field_checksum); it holds for the editor build (MSVC x64, fp:precise, no FMA contraction).

Cases = [[
const|const|width=8,height=6,value=0.25||8b70bc3ee0cdfd0d
white|white|width=33,height=33,seed=3||506f3c02c04b5153
perlin|perlin|width=33,height=33,seed=1,scale=10,octaves=5||69692f3452b75d1c
perlin_cell4|perlin|width=33,height=33,seed=1,scale=40,octaves=3,cell=4,ox=8,oz=16||de95f5c79c7dae61
simplex|simplex|width=33,height=33,seed=2,scale=14,octaves=4||d2e3583626b558a8
ridged|ridged|width=33,height=33,seed=4,scale=16,octaves=4||40b3fc1922b5f6f6
ridged_simplex|ridged|width=33,height=33,seed=4,scale=16,octaves=4,basis=simplex||c307704100d35dd0
billow|billow|width=33,height=33,seed=5,scale=16,octaves=3||363ad4380694cfb2
voronoi_f1|voronoi|width=33,height=33,seed=6,scale=9||fd44db3bfcad39ff
voronoi_f2|voronoi|width=33,height=33,seed=6,scale=9,mode=f2||86d22014b5676513
voronoi_edge|voronoi|width=33,height=33,seed=6,scale=9,mode=edge,jitter=0.8||ba2fd42b4d0c3f05
voronoi_id|voronoi|width=33,height=33,seed=6,scale=9,mode=id||65b11b3fc804e63e
voronoi_crack|voronoi|width=33,height=33,seed=6,scale=9,mode=crack,thickness=0.15||58b7c1ee0b1dd507
gradient|gradient|width=33,height=33,angle=30,lo=0.1,hi=0.9||60463a64755edb42
radial|radial|width=33,height=33||25cca749ef1b32db
radial_off|radial|width=33,height=33,cx=8,cz=10,radius=20,clamp=0||504f1ca750b83272
blur|blur|radius=2.5|a=A|08aeb662112c702c
box|box|radius=2|a=A|d4b79ceac67da274
blur_mask|blur|radius=3|a=A,mask=M|7f9ba93c1ae735dc
clamp|clamp|lo=0.3,hi=0.7|a=A|c75da484bae4ef69
invert|invert||a=A|674560361f5bcaf4
abs|abs||a=H|0a84ede38f94a480
gamma|gamma|gamma=2.2|a=A|a6776855b92b4dfe
affine|affine|mul=3,add=-1|a=A|2903707a7aeb6ecf
smoothstep|smoothstep|edge0=0.3,edge1=0.6|a=A|ccec7267c0d10334
threshold|threshold|value=0.5|a=A|4b886bfe70881453
normalize|normalize|lo=-1,hi=1|a=A|6d7916612dff65eb
quantize|quantize|step=0.0078125|a=H|798869575eadbd14
remap|remap|points=0:0;0.4:0.1;0.6:0.9;1:1,smooth=1|a=A|710051254af6fe4e
remap_linear|remap|points=0:0.2;0.5:0.9;1:0.4,smooth=0|a=A|8459d8ffbfba8abe
levels|levels|in_lo=0.2,in_hi=0.8,gamma=1.5,out_lo=0.1,out_hi=0.9|a=A|88e464dab123fb97
terrace|terrace|steps=5,sharpness=0.6|a=A|55d6cf962114468d
warp|warp|strength=6|a=H,dx=A,dz=N|048cc005458b01ad
warp_wrap|warp|strength=6,edge=wrap|a=H,dx=N,dz=A|92b09428aff148e5
offset|offset|move_x=5,move_z=-3|a=H|48b7047fabe93cb4
offset_frac|offset|move_x=2.5,move_z=1.25,edge=clamp|a=H|67b7e062b8b10564
rotate|rotate|angle=30|a=H|28b10b445e9d2684
rotate_fill|rotate|angle=-50,edge=fill,fill=-5|a=H|919cd40e54cca13e
scale|scale|factor=1.7|a=H|0b64bdbead5490c5
mirror_x|mirror|mode=x|a=H|d55bdb3f1611067e
mirror_z|mirror|mode=z,side=1|a=H|404648003d15a354
mirror_xz|mirror|mode=xz|a=H|41e29f718c7319b7
mirror_rot2|mirror|mode=rot2|a=H|86fd1477f1cb9d53
mirror_rot4|mirror|mode=rot4|a=H|472ba78d97b6ead7
mirror_rot4_side1|mirror|mode=rot4,side=1|a=H|de741e53b385202f
mirror_diag|mirror|mode=diag|a=H|10639c76a45d09a8
mirror_adiag|mirror|mode=adiag,side=1|a=H|7492ca6397378f59
crop|crop|x0=4,z0=6,x1=20,z1=25|a=H|ad4b1cb03802b3b9
resize|resize|width=20,height=17|a=H|b70885c0c8997ece
min|min||a=A,b=N|1cb8be4b1f6c6fa4
max|max||a=A,b=N|e8809c2647774d7d
add|add||a=A,b=N|0c8c3696da74589e
add_value|add|value=0.5|a=A|7b69388a307b72a1
sub|sub||a=A,b=N|8873d01c1e06c33b
mul|mul||a=A,b=N|bcc7c610320af9d6
blend_overlay|blend|mode=overlay,opacity=0.8|a=A,b=N,mask=M|958cdc1980e854c8
blend_screen|blend|mode=screen|a=A,b=N|8588b457832f513e
blend_diff|blend|mode=diff|a=A,b=N|a3bbeca3f280c5bb
slope_degrees|slope|mode=degrees|a=H|1523f201d7fe0baa
slope_degrees_r3|slope|mode=degrees,radius=3|a=H|dd6f4b9b58d5a250
slope_gradient|slope|mode=gradient|a=H|1f86da996c50842a
slope_rating|slope|mode=rating,window=1|a=H|0d801b9edb4feecc
slope_rating_w3|slope|mode=rating,window=3|a=H|58c337ec8a8ec5d4
slope_variation|slope|mode=variation,window=2|a=H|c78373ab796fbe42
height_band|height_band|lo=20,hi=35,soft=5|a=H|59c1b22fb75d8019
curvature|curvature|radius=2,gain=40|a=H|c48f240917f7814c
curvature_raw|curvature|raw=1|a=H|346a75a8cfbae6b1
water_below|water_below|level=25,soft=3|a=H|e1a4b6dc9d588c7a
water_above|water_above|level=25|a=H|ccdd059b70b5af83
water_depth|water_depth|level=30|a=H|a5437a49ef1e6d00
shore|shore|level=28,width=2,soft=3|a=H|2c3770596e590c86
distance|distance|threshold=35|a=H|2f7bba71af3e4535
distance_inside|distance|threshold=25,mode=inside,range=10|a=H|9150d372470fe752
distance_signed|distance|threshold=30,mode=signed|a=H|3073a550e36853b8
thermal|thermal|iterations=30,talus=0.4,rate=0.5|a=H|8487212979230e65
thermal_mask|thermal|iterations=20,talus=0.3|a=H,mask=M|e976fac3b62fc152
aspect|aspect|azimuth=30,flat=0.2|a=H|b6714a7b37a0a18f
aspect_degrees|aspect|mode=degrees,radius=2|a=H|f90143e3b9ece3b4
flow_cells|flow|mode=cells|a=H|3156e7c5e369fa35
flow_area|flow|mode=area|a=H|3156e7c5e369fa35
flow_log|flow|range=3000|a=H|61d584e5c056a618
resample_same|resample||a=A,like=N|799c3e60c8061477
]]
