// Terrain tessellation (engine addition, ren_TerrainTessellation; Direct3D 12 and Vulkan only).
//
// The engine appends this file to FAF's effects/terrain.fx when it loads that effect on a
// Direct3D 12 or Vulkan device; Direct3D 9 and 11 never see it. It adds a tessellated twin
// "<name>Tess" of each terrain technique that draws the heightfield's triangles, which the
// engine selects instead of "<name>" while ren_TerrainTessellation is on. If this file fails
// to compile against terrain.fx, the game logs it and draws the terrain as before.
//
// Each terrain triangle is split on the GPU, more finely near the camera, and the new points
// are pushed down where the ground texture is darker than its own surroundings, so cracks,
// gaps between rocks and furrows sink into the ground. The ground only goes down, never up:
// decals, splats, props and units stay on the original surface. Every terrain pass that the
// screen-space normals and colour passes combine uses the same geometry.
//
// The engine reads this file at startup from the game folder (fafengine/effects), so it can be
// changed without rebuilding the engine.

#if defined(DIRECT3D12) || defined(VULKAN)

// ---- settings ---------------------------------------------------------------------------

// How deep the darkest crack goes, in world units (a land factory is about 4 wide).
static const float TerrainTessDepthScale = 0.3;
// Relief from brightness: how much darker than its surroundings a texel must be to reach full depth.
static const float TerrainTessContrast = 3.0;
// Mip levels between the fine texture sample and the "surroundings" sample.
static const float TerrainTessCoarseLevels = 4.0;
// Tessellation: pieces per world unit of edge at distance 1; the result is capped.
static const float TerrainTessDensity = 300.0;
static const float TerrainTessMaxFactor = 32.0;
// Camera distance over which the effect fades out; past the end the terrain is untouched.
static const float TerrainTessFadeStart = 60.0;
static const float TerrainTessFadeEnd = 160.0;
// Camera distance at which the relief reads mip 0; each doubling reads one level coarser.
static const float TerrainTessLodDistance = 12.0;
// Share of relief layers in the ground's blend where relief starts, and where it is at full strength.
static const float TerrainTessCoverageStart = 0.35;
static const float TerrainTessCoverageFull = 0.85;

// How much relief each ground layer gets, set by the engine from the layer's file name
// (TerrainTessellation.cpp): 1 for rock, sand, dirt, gravel and the like, 0 for grass, moss and
// other plants (their detail is far finer than the geometry and only smears), 0.5 otherwise.
// x y z w: lower, stratum 0, 1, 2 / strata 3 to 6 / stratum 7.
float4 TerrainTessLayers0;
float4 TerrainTessLayers1;
float4 TerrainTessLayers2;

// ---- control points ---------------------------------------------------------------------

// One heightfield vertex as the vertex buffer holds it: x and z in world units, y in height
// units (times HeightScale for world units).
struct TERRAIN_TESS_POINT
{
    float4 mPosition : TEXCOORD0;
};

TERRAIN_TESS_POINT TerrainTessVS(position_t p : POSITION0)
{
    TERRAIN_TESS_POINT result;
    result.mPosition = float4(p);
    return result;
}

float3 TerrainTessWorld(float4 grid)
{
    return float3(grid.x, grid.y * HeightScale, grid.z);
}

// Fraction of the effect at this camera distance.
float TerrainTessFade(float distanceToCamera)
{
    return 1 - smoothstep(TerrainTessFadeStart, TerrainTessFadeEnd, distanceToCamera);
}

// The tessellation factor of one edge, from its two ends only, so the two triangles that
// share an edge split it alike and no gap opens between them.
float TerrainTessEdge(float4 a, float4 b)
{
    float3 worldA = TerrainTessWorld(a);
    float3 worldB = TerrainTessWorld(b);
    float distanceToCamera = max(distance((worldA + worldB) * 0.5, CameraPosition.xyz), 1.0);
    if (distanceToCamera >= TerrainTessFadeEnd) {
        return 1;
    }
    float factor = distance(worldA, worldB) * TerrainTessDensity / distanceToCamera;
    return clamp(factor, 1, TerrainTessMaxFactor);
}

// Hull shader: the factors of the edges opposite a, b and c, and of the inside.
float4 TerrainTessFactors(TERRAIN_TESS_POINT a, TERRAIN_TESS_POINT b, TERRAIN_TESS_POINT c)
{
    float4 factors;
    factors.x = TerrainTessEdge(b.mPosition, c.mPosition);
    factors.y = TerrainTessEdge(c.mPosition, a.mPosition);
    factors.z = TerrainTessEdge(a.mPosition, b.mPosition);
    factors.w = (factors.x + factors.y + factors.z) / 3;
    return factors;
}

// ---- relief -----------------------------------------------------------------------------

float TerrainTessLuma(float4 colour)
{
    return dot(colour.rgb, float3(0.299, 0.587, 0.114));
}

// 0 where a texel is as bright as its surroundings or brighter, up to 1 where it is much darker,
// times the layer's weight (TerrainTessLayers*) and its share of the blend; no texture reads for a
// layer without relief or one that barely shows.
float TerrainTessRelief(sampler2D s, float2 uv, float lod, float weight, float share)
{
    if (weight * share <= 0.01) {
        return 0;
    }
    float fine = TerrainTessLuma(tex2Dlod(s, float4(uv, 0, lod)));
    float coarse = TerrainTessLuma(tex2Dlod(s, float4(uv, 0, lod + TerrainTessCoarseLevels)));
    return saturate((coarse - fine) * TerrainTessContrast / max(coarse, 0.05)) * weight * share;
}

// How far below the surface the ground at `world` goes, blended over the strata the same way
// the colour pass blends their albedos. Always all eight strata: every pass must place the
// ground alike, and the basis passes don't know the map's shader (on a four-strata map the
// second mask is empty and adds nothing).
float TerrainTessDepth(float3 world)
{
    float distanceToCamera = distance(world, CameraPosition.xyz);
    float fade = TerrainTessFade(distanceToCamera);
    if (fade <= 0) {
        return 0;
    }
    float2 uv = world.xz * TerrainScale.xy;
    float lod = clamp(log2(max(distanceToCamera, 1.0) / TerrainTessLodDistance), 0, 8);

    float4 mask0 = saturate(tex2Dlod(UtilitySamplerA, float4(uv, 0, 0)) * 2 - 1);
    float4 mask1 = saturate(tex2Dlod(UtilitySamplerB, float4(uv, 0, 0)) * 2 - 1);
    // Each layer's share of the blend: the colour pass lerps lower, stratum 0, ... stratum 7 in turn,
    // so a layer keeps its mask times what every later layer leaves. Same result as that chain, but a
    // layer that doesn't show is never sampled (most ground shows two or three of the nine).
    float share7 = mask1.w;
    float rest = 1 - mask1.w;
    float share6 = mask1.z * rest; rest *= 1 - mask1.z;
    float share5 = mask1.y * rest; rest *= 1 - mask1.y;
    float share4 = mask1.x * rest; rest *= 1 - mask1.x;
    float share3 = mask0.w * rest; rest *= 1 - mask0.w;
    float share2 = mask0.z * rest; rest *= 1 - mask0.z;
    float share1 = mask0.y * rest; rest *= 1 - mask0.y;
    float share0 = mask0.x * rest; rest *= 1 - mask0.x;
    float shareLower = rest;
    // How much of the visible ground is a layer with relief. Where grass half covers sand, the sand's
    // ripples would otherwise shade ground that looks green; the relief fades out as that share drops
    // below about half.
    float coverage = shareLower * TerrainTessLayers0.x + share0 * TerrainTessLayers0.y + share1 * TerrainTessLayers0.z +
                     share2 * TerrainTessLayers0.w + share3 * TerrainTessLayers1.x + share4 * TerrainTessLayers1.y +
                     share5 * TerrainTessLayers1.z + share6 * TerrainTessLayers1.w + share7 * TerrainTessLayers2.x;
    float strength = smoothstep(TerrainTessCoverageStart, TerrainTessCoverageFull, coverage);
    if (strength <= 0) {
        return 0;
    }
    float relief = TerrainTessRelief(LowerAlbedoSampler, uv * LowerAlbedoTile.xy, lod, TerrainTessLayers0.x, shareLower);
    relief += TerrainTessRelief(Stratum0AlbedoSampler, uv * Stratum0AlbedoTile.xy, lod, TerrainTessLayers0.y, share0);
    relief += TerrainTessRelief(Stratum1AlbedoSampler, uv * Stratum1AlbedoTile.xy, lod, TerrainTessLayers0.z, share1);
    relief += TerrainTessRelief(Stratum2AlbedoSampler, uv * Stratum2AlbedoTile.xy, lod, TerrainTessLayers0.w, share2);
    relief += TerrainTessRelief(Stratum3AlbedoSampler, uv * Stratum3AlbedoTile.xy, lod, TerrainTessLayers1.x, share3);
    relief += TerrainTessRelief(Stratum4AlbedoSampler, uv * Stratum4AlbedoTile.xy, lod, TerrainTessLayers1.y, share4);
    relief += TerrainTessRelief(Stratum5AlbedoSampler, uv * Stratum5AlbedoTile.xy, lod, TerrainTessLayers1.z, share5);
    relief += TerrainTessRelief(Stratum6AlbedoSampler, uv * Stratum6AlbedoTile.xy, lod, TerrainTessLayers1.w, share6);
    relief += TerrainTessRelief(Stratum7AlbedoSampler, uv * Stratum7AlbedoTile.xy, lod, TerrainTessLayers2.x, share7);
    relief *= strength;
    // The upper albedo layer paints over the strata and has no relief of its own.
    float upper = tex2Dlod(UpperAlbedoSampler, float4(uv * UpperAlbedoTile.xy, 0, lod)).w;
    relief *= 1 - upper;
    return relief * TerrainTessDepthScale * fade;
}

// The world position of one generated point on the original surface.
float4 TerrainTessSurface(float3 weights, TERRAIN_TESS_POINT a, TERRAIN_TESS_POINT b, TERRAIN_TESS_POINT c)
{
    float4 grid = a.mPosition * weights.x + b.mPosition * weights.y + c.mPosition * weights.z;
    return float4(TerrainTessWorld(grid), grid.w);
}

// ---- domain shaders: TerrainVS and TerrainGlowVS on a float position ---------------------
// (terrain.fx's versions take position_t, which is uint4 under Direct3D 10 and later and
// would drop the fraction of a generated point)

// `surface` is the point on the original surface. The shadow map holds that surface, so the
// shadow lookup uses it: from the sunken point every crack would read as shadowed.
VS_OUTPUT TerrainTessOutput(float4 surface, uniform bool shadowed)
{
    VS_OUTPUT result;
    float4 position = surface;
    position.y -= TerrainTessDepth(surface.xyz);

    result.nearScales = float4(Stratum0AlbedoTile.x, Stratum1AlbedoTile.x, Stratum2AlbedoTile.x, Stratum3AlbedoTile.x);
    result.farScales =  float4(Stratum0NormalTile.x, Stratum1NormalTile.x, Stratum2NormalTile.x, Stratum3NormalTile.x);

    result.mPos = calculateHomogenousCoordinate(position);
    result.mTexWT = position.xzyw;
    result.mTexSS = result.mPos;
    result.mTexDecal = float4(0, 0, 0, 0);
    result.mViewDirection = normalize(position.xyz - CameraPosition.xyz);

    if (shadowed && (1 == ShadowsEnabled)) {
        result.mShadow = mul(surface, ShadowMatrix);
        result.mShadow.x = (+result.mShadow.x + result.mShadow.w) * 0.5;
        result.mShadow.y = (-result.mShadow.y + result.mShadow.w) * 0.5;
        result.mShadow.z -= 0.01f;
    } else {
        result.mShadow = float4(0, 0, 0, 1);
    }
    return result;
}

VS_OUTPUT TerrainTessDS(float3 weights, TERRAIN_TESS_POINT a, TERRAIN_TESS_POINT b, TERRAIN_TESS_POINT c,
                        uniform bool shadowed)
{
    return TerrainTessOutput(TerrainTessSurface(weights, a, b, c), shadowed);
}

VS_OUTPUT TerrainTessGlowDS(float3 weights, TERRAIN_TESS_POINT a, TERRAIN_TESS_POINT b, TERRAIN_TESS_POINT c,
                            uniform bool shadowed)
{
    VS_OUTPUT result = TerrainTessOutput(TerrainTessSurface(weights, a, b, c), shadowed);
    float4 offset = float4(0, 0, 0, 0);
    sincos(Time * 0.125, offset.x, offset.y);
    offset *= 0.01;
    result.mTexDecal = offset;
    return result;
}

// ---- normals: the relief's slope tilts the layers' normals ----------------------------------
// Lighting reads the normals pass, not the geometry, so sunken ground alone barely shows. These
// add the relief's slope, sampled a short step away along x and z, to the normal FAF's normals
// pass blends from the layers' normal maps (tangent space: x along world x, y along world z).

// Slope gain: 1 tilts as much as the sunken geometry slopes. The geometry sinks at most
// TerrainTessDepthScale, too little for the eye from above; the shading carries most of the depth.
static const float TerrainTessShade = 6.0;
// World units between the slope samples.
static const float TerrainTessShadeStep = 0.15;
// Direction of the normal maps' y axis against world z.
static const float TerrainTessShadeSignY = 1.0;

float4 TerrainTessTilt(float4 encoded, float3 world)
{
    float depth = TerrainTessDepth(world);
    float alongX = TerrainTessDepth(world + float3(TerrainTessShadeStep, 0, 0)) - depth;
    float alongZ = TerrainTessDepth(world + float3(0, 0, TerrainTessShadeStep)) - depth;
    float3 normal = encoded.xyz * 2 - 1;
    normal.xy += float2(alongX, alongZ * TerrainTessShadeSignY) * (TerrainTessShade / TerrainTessShadeStep);
    return float4(normalize(normal) * 0.5 + 0.5, encoded.w);
}

float4 TerrainTessNormalsPS(VS_OUTPUT inV) : COLOR
{
    return TerrainTessTilt(TerrainNormalsPS(inV), inV.mTexWT.xzy);
}

float4 TerrainTessNormalsXP(VS_OUTPUT inV) : COLOR
{
    return TerrainTessTilt(TerrainNormalsXP(inV), inV.mTexWT.xzy);
}

// The basis passes: TerrainVS on the original surface, pulled a hair towards the camera. Where
// the ground barely sinks (green layers, far away), the original surface and the tessellated one
// lie at almost the same depth and LessEqual would drop the basis on rounding alone.
VS_OUTPUT TerrainTessBasisVS(position_t p : POSITION0)
{
    VS_OUTPUT result = TerrainVS(p, false);
    result.mPos.z -= 0.0001 * result.mPos.w;
    return result;
}

// ---- techniques -------------------------------------------------------------------------

// No tessellated TTerrainDepth: that pass draws the terrain into the sun's shadow map
// (Shadow.cpp), and the shadow lookups above use the original surface, so the map must hold it.

technique TTerrainTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_RGBA )
        DepthState( Depth_Enable )

        VertexShader = compile vs_1_1 TerrainTessVS();
        HullShader = compile hs_5_0 TerrainTessFactors();
        DomainShader = compile ds_5_0 TerrainTessDS( true );
        PixelShader = compile ps_2_a TerrainPS( true );
    }
}

technique TTerrainXPTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_RGBA )
        DepthState( Depth_Enable )

        VertexShader = compile vs_1_1 TerrainTessVS();
        HullShader = compile hs_5_0 TerrainTessFactors();
        DomainShader = compile ds_5_0 TerrainTessDS( true );
        PixelShader = compile ps_2_a TerrainAlbedoXP();
    }
}

technique TTerrainGlowTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_RGBA )
        DepthState( Depth_Enable )

        VertexShader = compile vs_1_1 TerrainTessVS();
        HullShader = compile hs_5_0 TerrainTessFactors();
        DomainShader = compile ds_5_0 TerrainTessGlowDS( true );
        PixelShader = compile ps_2_a TerrainGlowPS( true );
    }
}

technique TTerrainNormalsTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_RG )
        DepthState( Depth_Enable )

        VertexShader = compile vs_1_1 TerrainTessVS();
        HullShader = compile hs_5_0 TerrainTessFactors();
        DomainShader = compile ds_5_0 TerrainTessDS( false );
        PixelShader = compile ps_2_0 TerrainTessNormalsPS();
    }
}

technique TTerrainNormalsXPTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_RG )
        DepthState( Depth_Enable )

        VertexShader = compile vs_1_1 TerrainTessVS();
        HullShader = compile hs_5_0 TerrainTessFactors();
        DomainShader = compile ds_5_0 TerrainTessDS( false );
        PixelShader = compile ps_2_0 TerrainTessNormalsXP();
    }
}

// The basis passes draw per normal-map tile, from a triangulation of their own, which the
// tessellator would sink a little differently from the terrain the normals pass drew: where
// theirs came out lower the depth test dropped it, left the heightmap normal (B/A) at zero and
// frame.fx shaded those spots near-black. They draw the original surface instead, which lies on
// or above the sunken one (TerrainTessBasisVS), and leave the depth buffer as the normals pass wrote it.
technique TTerrainBasisTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_BA )
        DepthState( Depth_Enable_LessEqual_Write_None )

        VertexShader = compile vs_1_1 TerrainTessBasisVS();
        PixelShader = compile ps_2_0 TerrainBasisPS();
    }
}

technique TTerrainBasisBiCubicTess
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable_Write_BA )
        DepthState( Depth_Enable_LessEqual_Write_None )

        VertexShader = compile vs_1_1 TerrainTessBasisVS();
        PixelShader = compile ps_2_0 TerrainBasisPSBiCubic();
    }
}

#endif
