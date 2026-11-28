#include "moho/render/lights/LightEffectPatch.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <vector>

namespace moho::lights
{
  namespace
  {
    using std::size_t;
    using std::string;
    using std::string_view;

    constexpr size_t npos = string::npos;

    // ------------------------------------------------------------------------------------------------ HLSL (effect
    // dialect)

    // Declarations and the grid walk both effects share. Positions are absolute world units. The data layout is
    // LightGrid.h's.
    constexpr const char* kCommonDecl = R"HLSL(
// ---- FAF dynamic lights (LightEffectPatch): light data and light grid textures, see docs/DYNAMIC_LIGHTS.md ----
texture dynLightData;
texture dynLightGrid;
sampler2D dynLightDataSampler = sampler_state
{
    Texture   = (dynLightData);
    MipFilter = NONE;
    MinFilter = POINT;
    MagFilter = POINT;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
sampler2D dynLightGridSampler = sampler_state
{
    Texture   = (dynLightGrid);
    MipFilter = NONE;
    MinFilter = POINT;
    MagFilter = POINT;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
float4 dynLightParams;     // gridOriginX, gridOriginZ, 1 / cellSize, lightCount
float4 dynLightGridSize;   // cellsX, cellsZ, 1 / gridWidth (1024), 1 / gridRows
float4 dynLightDataSize;   // 1 / dataWidth, 1 / dataRows, dataWidth, dataRows

float4 DynLightTexel(float k)
{
    float row = floor(k * dynLightDataSize.x);
    float col = k - row * dynLightDataSize.z;
    return tex2Dlod(dynLightDataSampler, float4((col + 0.5) * dynLightDataSize.x, (row + 0.5) * dynLightDataSize.y, 0, 0));
}

// The grid texture is one linear store of texels (column k mod 1024, row k div 1024): a table texel per cell (x = first list texel,
// y = list texels), then the lists of "light index + 1", four to a texel. A cell lists every light that reaches it, so two cells never
// disagree about a light near their border: no lit squares.
float4 DynLightGridTexel(float k)
{
    float row = floor(k * dynLightGridSize.z);
    float col = k - row * 1024.0;
    return tex2Dlod(dynLightGridSampler, float4((col + 0.5) * dynLightGridSize.z, (row + 0.5) * dynLightGridSize.w, 0, 0));
}

// The lists of the grid cell that holds the world position: the first texel and the texel count of its lights, and of its shadow casters
// (occ.x, occ.y); 0 outside the map.
void DynLightCell(float3 worldPos, out float first, out float texels, out float2 occ)
{
    first = 0.0;
    texels = 0.0;
    occ = float2(0.0, 0.0);
    float2 cell = floor((worldPos.xz - dynLightParams.xy) * dynLightParams.z);
    if (cell.x >= 0 && cell.y >= 0 && cell.x < dynLightGridSize.x && cell.y < dynLightGridSize.y && dynLightParams.w > 0.5)
    {
        float4 t = DynLightGridTexel(cell.y * dynLightGridSize.x + cell.x);
        first = t.x;
        texels = t.y;
        occ = t.zw;
    }
}

// Soft shadow of the shadow casters of the cell (oriented boxes standing in for the units, shaded as ellipsoids; four texels each in the data texture from texel 12288 on: centre, then the
// three half-extent vectors with 1 / length squared in w). The ray from the pixel `p` to the light (`d` = pixel to light) is cut against each
// box in the box's own frame; the length of the ray inside a box, over 0.8 units, is how much of the light it takes (a box the ray only
// grazes shades a little: a soft edge). A box the pixel is on (its own unit) and a light inside a box (a muzzle flash at the barrel) are skipped.
float DynLightShadow(float3 p, float3 d, float2 occ)
{
    float shadow = 1.0;
    float len = length(d);
    if (len < 0.05)
    {
        return 1.0;
    }
    for (int t = 0; t < 8; ++t)
    {
        if ((float)t >= occ.y)
        {
            break;
        }
        float4 e = DynLightGridTexel(occ.x + (float)t);
        for (int q = 0; q < 4; ++q)
        {
            float entry = (q == 0) ? e.x : ((q == 1) ? e.y : ((q == 2) ? e.z : e.w));
            if (entry > 0.5)
            {
                float k0 = 12288.0 + (entry - 1.0) * 4.0;
                float4 c = DynLightTexel(k0);
                float4 a0 = DynLightTexel(k0 + 1.0);
                float4 a1 = DynLightTexel(k0 + 2.0);
                float4 a2 = DynLightTexel(k0 + 3.0);
                float3 rel = p - c.xyz;
                float3 x = float3(dot(rel, a0.xyz) * a0.w, dot(rel, a1.xyz) * a1.w, dot(rel, a2.xyz) * a2.w);
                float3 dd = float3(dot(d, a0.xyz) * a0.w, dot(d, a1.xyz) * a1.w, dot(d, a2.xyz) * a2.w);
                // The box is a stand-in for the unit: its shadow as a box was a hard square the size of the unit's footprint. The caster is the
                // ellipsoid inside the box (0.8 of its half extents: the engine's box is already grown by a quarter), so the shadow is a soft rounded blob: the ray's length inside the
                // unit sphere of the normalised frame, 0 at the silhouette and growing smoothly towards the middle.
                float3 xs = x * 1.25;
                float3 ds = dd * 1.25;
                float3 ls = xs + ds;
                if (dot(xs, xs) > 1.0 && dot(ls, ls) > 1.0)
                {
                    float a2s = dot(ds, ds);
                    float bs = dot(xs, ds);
                    float cs = dot(xs, xs) - 1.0;
                    float disc = bs * bs - a2s * cs;
                    if (disc > 0.0 && a2s > 0.00000001)
                    {
                        float root = sqrt(disc);
                        float tEnter = max((-bs - root) / a2s, 0.0);
                        float tExit = min((-bs + root) / a2s, 1.0);
                        if (tExit > tEnter)
                        {
                            float thick = saturate((tExit - tEnter) * sqrt(a2s));   // 0 .. 2 across the ellipsoid, 1 is half its width
                            thick = thick * thick * (3.0 - 2.0 * thick);
                            // a light is not a point: the shadow gets lighter the further the pixel is behind the caster (a penumbra that grows)
                            float behind = saturate(tEnter * len / 10.0);
                            shadow *= 1.0 - 0.6 * thick * (1.0 - 0.6 * behind);
                        }
                    }
                }
            }
        }
    }
    return shadow;
}

// One light as the pixel sees it: closest point of the light's segment (a point light has a zero-length one; a spotlight is a point
// light with a cone), windowed falloff. Returns the attenuation; `toLight` is the vector from the pixel to that point, `colour` the
// light's colour x intensity.
float DynLightAt(float entry, float3 worldPos, float2 occ, out float3 toLight, out float3 colour)
{
    float k = (entry - 1.0) * 3.0;
    float4 a = DynLightTexel(k);
    float4 c = DynLightTexel(k + 2.0);
    bool spot = a.w < 0.0;   // a spotlight is stored with a negative radius
    float r = max(abs(a.w), 0.001);
    float3 seg = spot ? float3(0, 0, 0) : c.xyz - a.xyz;
    float t = saturate(dot(worldPos - a.xyz, seg) / max(dot(seg, seg), 0.0001));
    toLight = a.xyz + seg * t - worldPos;
    float atten = saturate(1 - dot(toLight, toLight) / (r * r));
    atten *= 0.35 + 0.65 * atten;   // softer tail than atten^2: a light just above the ground must still reach the ground around it
    if (spot)
    {
        float cd = dot(-normalize(toLight), c.xyz);
        atten *= saturate((cd - c.w) / max((1.0 - c.w) * 0.5, 0.0001));
    }
    colour = float3(0, 0, 0);
    if (atten > 0.002)
    {
        colour = DynLightTexel(k + 1.0).rgb;   // fetched only by the lights that reach this pixel
        if (occ.y > 0.5 && r <= 40.0)   // a light that lights a screen casts no shadows
        {
            atten *= DynLightShadow(worldPos, toLight, occ);
        }
    }
    return atten;
}
)HLSL";

    constexpr const char* kFieldDecl = R"HLSL(
// ---- FAF light field (LightField.cpp, docs/LIGHTING_V2.md): the lights summed once per cell of a world-fixed field, sampled here ----
texture dynField;
sampler2D dynFieldSampler = sampler_state
{
    Texture   = (dynField);
    MipFilter = NONE;
    MinFilter = LINEAR;
    MagFilter = LINEAR;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
float4 dynFieldParams;    // originX, originZ, 1 / cellSize, cells
float4 dynFieldParams2;   // x: 1 = sample the field (0 = the grid path), layers, 1 / atlas width, 1 / atlas height
float4 dynFieldLayerH;    // height of each layer above the terrain
float4 dynFieldWater;     // x: 1 = the third part of the atlas carries the water level of each cell in y (a map with water bodies); y: 1 = the terrain takes the sun shadow

float4 DynFieldFetch(float2 c, float layer, float part)
{
    float cells = dynFieldParams.w;
    return tex2Dlod(dynFieldSampler, float4((layer * cells + c.x) * dynFieldParams2.z, (part * cells + c.y) * dynFieldParams2.w, 0, 0));
}

// E: colour x attenuation of all lights; DW: xyz the sum of luminance x attenuation x direction to the light, w the sum of luminance x attenuation.
// Layers: 0 the terrain 0.5 above it (the sea bed under water), 1 to 4 the surface (water or terrain) 0.3, 3, 10 and 30 above it. The alpha of
// layer 0 is the terrain height, of layer 1 the surface height: a point under the surface blends the sea bed layer with the surface layer.
void DynFieldSample(float3 p, out float3 E, out float4 DW)
{
    E = float3(0, 0, 0);
    DW = float4(0, 0, 0, 0);
    float cells = dynFieldParams.w;
    float2 c = (p.xz - dynFieldParams.xy) * dynFieldParams.z;
    if (c.x > -1.0 && c.y > -1.0 && c.x < cells + 1.0 && c.y < cells + 1.0)
    {
        c = clamp(c, 0.5, cells - 0.5);
        float ground = DynFieldFetch(c, 0.0, 0.0).a;
        float surface = DynFieldFetch(c, 1.0, 0.0).a;
        float l0 = 1.0;
        float l1 = 1.0;
        float w = 0.0;
        if (p.y <= surface + 0.3)
        {
            if (surface - ground > 0.1)
            {
                l0 = 0.0;
                w = saturate((p.y - (ground + 0.5)) / max(surface + 0.3 - ground - 0.5, 0.05));
            }
        }
        else
        {
            float h = p.y - surface;
            if (h > 10.0)
            {
                l0 = 3.0; l1 = 4.0; w = saturate((h - 10.0) / 20.0);
            }
            else if (h > 3.0)
            {
                l0 = 2.0; l1 = 3.0; w = (h - 3.0) / 7.0;
            }
            else
            {
                l0 = 1.0; l1 = 2.0; w = saturate((h - 0.3) / 2.7);
            }
        }
        E = lerp(DynFieldFetch(c, l0, 0.0).rgb, DynFieldFetch(c, l1, 0.0).rgb, w);
        DW = lerp(DynFieldFetch(c, l0, 1.0), DynFieldFetch(c, l1, 1.0), w);
    }
}

// The level of the water over a world position on a map with water bodies, from the cell the position falls in (the cell's own texel: the
// lookup is at the texel centre, so the linear filter returns it unmixed and a lake never takes the level of the sea next to it).
// `fallback` where the field does not carry levels or does not reach the position. A dry cell has -10000.
float DynFieldWaterLevel(float3 p, float fallback)
{
    float cells = dynFieldParams.w;
    float2 c = (p.xz - dynFieldParams.xy) * dynFieldParams.z;
    if (dynFieldParams2.x > 0.5 && dynFieldWater.x > 0.5 && c.x > 0.0 && c.y > 0.0 && c.x < cells && c.y < cells)
    {
        return DynFieldFetch(floor(c) + 0.5, 1.0, 2.0).g;
    }
    return fallback;
}

// How much of the sun reaches a world position (part 3 of the atlas, layers 0 and 1): the terrain between it and the sun.
float DynFieldSun(float3 p)
{
    float vis = 1.0;
    float cells = dynFieldParams.w;
    float2 c = (p.xz - dynFieldParams.xy) * dynFieldParams.z;
    if (dynFieldParams2.x > 0.5 && c.x > -1.0 && c.y > -1.0 && c.x < cells + 1.0 && c.y < cells + 1.0)
    {
        c = clamp(c, 0.5, cells - 0.5);
        float ground = DynFieldFetch(c, 0.0, 0.0).a;
        float surface = DynFieldFetch(c, 1.0, 0.0).a;
        vis = DynFieldFetch(c, 1.0, 2.0).x;
        if (p.y <= surface + 0.3 && surface - ground > 0.1)
        {
            vis = lerp(DynFieldFetch(c, 0.0, 2.0).x, vis, saturate((p.y - (ground + 0.5)) / max(surface + 0.3 - ground - 0.5, 0.05)));
        }
    }
    return vis;
}

// The terrain's own read of the sun shadow: the march over the height field gives blocky patches on hill faces, so the terrain
// shaders take it only while ren_DynLightsTerrainSunShadow is on (dynFieldWater.y); meshes and water read DynFieldSun directly.
float DynFieldSunTerrain(float3 p)
{
    return dynFieldWater.y > 0.5 ? DynFieldSun(p) : 1.0;
}

// The wrapped diffuse term of a surface with normal n: the grid path sums colour x atten x saturate((n.l + 0.5) / 1.5) per light, which is
// linear in n.l between -0.5 and 1, so the sum is E / 3 + 2 / 3 x E x dot(n, D) / W.
float3 DynFieldDiffuse(float3 E, float4 DW, float3 n)
{
    return max(E * (1.0 / 3.0) + E * ((2.0 / 3.0) * dot(n, DW.xyz) / max(DW.w, 0.0001)), 0.0);
}

float3 DynFieldTerrain(float3 worldPos, float3 normal)
{
    float3 E;
    float4 DW;
    DynFieldSample(worldPos, E, DW);
    return DynFieldDiffuse(E, DW, normal);
}
// ---- end FAF light field ----
)HLSL";

    // The field as light of the water surface: glints of the combined light on the wave normal and the light scattered
    // back out of the water.
    constexpr const char* kWaterLightCode = R"HLSL(
// ---- FAF dynamic lights on the water (LightEffectPatch): the light field at the water surface ----
float3 FafWaterLights(float3 worldPos, float3 N, float3 V, float depth)
{
    float3 total = float3(0, 0, 0);
    if (dynFieldParams2.x > 0.5)
    {
        float3 E;
        float4 DW;
        DynFieldSample(float3(worldPos.x, WaterElevation + 0.3, worldPos.z), E, DW);
        float lenD = length(DW.xyz);
        float3 l = DW.xyz / max(lenD, 0.0001);
        float dirness = saturate(lenD / max(DW.w, 0.0001));
        float roughness = 1.0 / SunShininess;
        float nDotL = max(dot(N, l), 0.0);
        float nDotV = abs(dot(N, V)) + 0.001;
        float3 h = normalize(V + l);
        float NDF = NormalDistribution(N, h, roughness);
        float G = GeometrySmith(N, nDotV, l, roughness);
        float F = FresnelSchlick(max(dot(h, V), 0.0), 0.02);
        float3 glint = (PI * NDF * G * F / (4.0 * nDotV * nDotL + 0.0001)) * nDotL * E * dirness;
        // the light that enters the water and comes back out: the colour of the water, more of it over deep water
        float3 scatter = DynFieldDiffuse(E, DW, float3(0, 1, 0)) * waterColor * (0.35 * saturate(0.25 + depth * 2.0));
        total = glint + scatter;
        float top = max(total.x, max(total.y, total.z));
        total = total / (1.0 + 0.2 * top);
    }
    return total;
}
)HLSL";

    // The sun's shadow of the terrain, into the shadow term both effects already use: the shadow coordinates of a pixel
    // come from its world position through the sun's shadow matrix, so the inverse matrix gives the world position back
    // and the field says how much sun reaches it.
    constexpr const char* kSunDecl = R"HLSL(
float4x4 dynShadowInv;   // inverse of the sun shadow matrix
float4 dynSunInfo;       // x: 1 when the sun shadow camera is valid

float FieldSunVisibility(float4 clip)
{
    float vis = 1.0;
    if (dynFieldParams2.x > 0.5 && dynSunInfo.x > 0.5)
    {
        float4 w = mul(clip, dynShadowInv);
        vis = DynFieldSun(w.xyz / w.w);
    }
    return vis;
}

// The terrain effect's shadow coordinates (x, y mapped to texture space, z lowered by 0.01) back to the clip position.
float FieldSunVisTerrain(float4 c)
{
    return FieldSunVisibility(float4(2.0 * c.x - c.w, c.w - 2.0 * c.y, c.z + 0.01, c.w));
}

)HLSL";

    constexpr const char* kSunWrapperMesh = R"HLSL(
float ComputeShadow( float4 shadowCoords, uniform bool hiDefFiltering )
{
    float shadow = ComputeShadowBase( shadowCoords, hiDefFiltering );
    // ComputeShadowTexcoord mapped the clip position to texture space: undo it
    float4 clip = float4( 2.0 * shadowCoords.x - shadowCoords.w, shadowCoords.w - 2.0 * shadowCoords.y, shadowCoords.z * shadowCoords.w, shadowCoords.w );
    return shadow * FieldSunVisibility( clip );
}
)HLSL";

    constexpr const char* kSunWrapperTerrain = R"HLSL(
float ComputeShadow( float4 vShadowCoord )
{
    return ComputeShadowBase( vShadowCoord ) * FieldSunVisTerrain( vShadowCoord );
}
)HLSL";

    constexpr const char* kMeshLightCode = R"HLSL(
float4 dynLightCamera;   // world position of the camera (set per view)

void DynLightsBRDFOne(float entry, float3 worldPos, float2 occ, float3 n, float3 v, float nDotV, float3 F0, float3 albedo, float metallic, float roughness, inout float3 total)
{
    float3 d;
    float3 lightColour;
    float atten = DynLightAt(entry, worldPos, occ, d, lightColour);
    if (atten > 0.002)   // the cell is bigger than the light: most entries do not reach this pixel, and the BRDF is the expensive part
    {
        float3 l = normalize(d);
        float3 h = normalize(v + l);
        float nDotL = max(dot(n, l), 0.0);
        float3 F = FresnelSchlick(max(dot(h, v), 0.0), F0);
        float NDF = NormalDistribution(n, h, roughness);
        float G = GeometrySmith(n, nDotV, l, roughness);
        float3 reflected = PI * NDF * G * F / (4.0 * nDotV * nDotL + 0.0001);
        float3 refracted = (float3(1, 1, 1) - F) * (1.0 - metallic) * albedo;
        float wrapL = saturate((dot(n, l) + 0.35) / 1.35);   // wrapped diffuse: lights next to a surface still light it
        total += (refracted * wrapL + reflected * nDotL) * lightColour * atten;
    }
}

void DynLightsBRDFQuad(float4 e, float3 worldPos, float2 occ, float3 n, float3 v, float nDotV, float3 F0, float3 albedo, float metallic, float roughness, inout float3 total)
{
    if (e.x > 0.5) { DynLightsBRDFOne(e.x, worldPos, occ, n, v, nDotV, F0, albedo, metallic, roughness, total); }
    if (e.y > 0.5) { DynLightsBRDFOne(e.y, worldPos, occ, n, v, nDotV, F0, albedo, metallic, roughness, total); }
    if (e.z > 0.5) { DynLightsBRDFOne(e.z, worldPos, occ, n, v, nDotV, F0, albedo, metallic, roughness, total); }
    if (e.w > 0.5) { DynLightsBRDFOne(e.w, worldPos, occ, n, v, nDotV, F0, albedo, metallic, roughness, total); }
}

// The field path of the mesh light: the lights of the position as one light (their summed colour from their mean direction; the
// directional share of the sum decides how much of it is specular), diffuse from the linear wrap of the field.
float3 DynFieldBRDF(float3 worldPos, float3 n, float3 v, float3 albedo, float metallic, float roughness)
{
    float3 E;
    float4 DW;
    DynFieldSample(worldPos, E, DW);
    float nDotV = abs(dot(n, v)) + 0.001;
    float3 F0 = lerp(float3(0.04, 0.04, 0.04), albedo, metallic);
    float lenD = length(DW.xyz);
    float3 l = DW.xyz / max(lenD, 0.0001);
    float dirness = saturate(lenD / max(DW.w, 0.0001));
    float3 h = normalize(v + l);
    float nDotL = max(dot(n, l), 0.0);
    float3 F = FresnelSchlick(max(dot(h, v), 0.0), F0);
    float NDF = NormalDistribution(n, h, roughness);
    float G = GeometrySmith(n, nDotV, l, roughness);
    float3 reflected = PI * NDF * G * F / (4.0 * nDotV * nDotL + 0.0001);
    float3 refracted = (float3(1, 1, 1) - F) * (1.0 - metallic) * albedo;
    float3 total = refracted * DynFieldDiffuse(E, DW, n) + reflected * nDotL * E * dirness;
    float top = max(total.x, max(total.y, total.z));
    return total / (1.0 + 0.2 * top);
}

float3 DynLightsBRDF(float3 worldPos, float3 n, float3 v, float3 albedo, float metallic, float roughness)
{
    if (dynFieldParams2.x > 0.5)
    {
        return DynFieldBRDF(worldPos, n, v, albedo, metallic, roughness);
    }
    float first;
    float texels;
    float2 occ;
    DynLightCell(worldPos, first, texels, occ);
    float nDotV = abs(dot(n, v)) + 0.001;
    float3 F0 = lerp(float3(0.04, 0.04, 0.04), albedo, metallic);
    float3 total = float3(0, 0, 0);
    // the whole list of the cell, four lights to a texel, strongest first (a cell holds 256 lights at most)
    for (int t = 0; t < 64; ++t)
    {
        if ((float)t >= texels)
        {
            break;
        }
        DynLightsBRDFQuad(DynLightGridTexel(first + (float)t), worldPos, occ, n, v, nDotV, F0, albedo, metallic, roughness, total);
    }
    float top = max(total.x, max(total.y, total.z));
    return total / (1.0 + 0.2 * top);   // soft limit at 5 on the brightest channel: the hue stays however strong the light is (a limit per channel drifts every strong light to white)
}

// tangent-space meshes (units, normal-mapped props). The result is masked for the water-mirrored pass instead of clip()ped.
float4 DynLightsPS(NORMALMAPPED_VERTEX vertex) : COLOR0
{
    float3x3 rotationMatrix = float3x3(vertex.binormal, vertex.tangent, vertex.normal);
    float3 n = ComputeNormal(normalsSampler, vertex.texcoord0.zw, rotationMatrix);
    float4 albedoTex = tex2D(albedoSampler, vertex.texcoord0.xy);
    float4 specular = tex2D(specularSampler, vertex.texcoord0.xy);
    float3 albedo = lerp(albedoTex.rgb, vertex.color.rgb * 0.6, saturate(specular.a * 2.5));
    float3 v = normalize(vertex.viewDirection);
    float3 lit = float3(0, 0, 0);
    if (mirrored < 0.5)   // the water reflection pass draws the mesh again: it gets no lights (the result was masked away, now it is not even computed)
    {
        lit = DynLightsBRDF(dynLightCamera.xyz - v * vertex.depth.y, n, v, albedo, saturate(specular.r), saturate(0.8 - specular.g * 0.5));
    }
    return float4(lit, albedoTex.a);   // alpha: the alpha test of the technique still applies
}

// vertex-normal props (trees, rocks, ...): no tangent frame, no specular map
float4 DynLightsVertexNormalPS(VERTEXNORMAL_VERTEX vertex) : COLOR0
{
    float4 albedoTex = tex2D(albedoSampler, vertex.texcoord0.xy);
    float3 v = normalize(vertex.viewDirection);
    float3 lit = float3(0, 0, 0);
    if (mirrored < 0.5)
    {
        lit = DynLightsBRDF(dynLightCamera.xyz - v * vertex.texcoord0.z, normalize(vertex.normal), v, albedoTex.rgb, 0.0, 0.8);
    }
    return float4(lit, albedoTex.a);
}
)HLSL";

    // Terrain: the light term at a world position with a normal, shared by the composite light pass and
    // CalculateLighting.
    constexpr const char* kTerrainLightFunction = R"HLSL(
void DynLightTerrainOne(float entry, float3 worldPos, float2 occ, float3 normal, inout float3 total)
{
    float3 d;
    float3 lightColour;
    float atten = DynLightAt(entry, worldPos, occ, d, lightColour);
    if (atten > 0.002)
    {
        total += lightColour * (atten * saturate((dot(normal, normalize(d)) + 0.5) / 1.5));   // wrapped: a light just above the ground lights it
    }
}

void DynLightTerrainQuad(float4 e, float3 worldPos, float2 occ, float3 normal, inout float3 total)
{
    if (e.x > 0.5) { DynLightTerrainOne(e.x, worldPos, occ, normal, total); }
    if (e.y > 0.5) { DynLightTerrainOne(e.y, worldPos, occ, normal, total); }
    if (e.z > 0.5) { DynLightTerrainOne(e.z, worldPos, occ, normal, total); }
    if (e.w > 0.5) { DynLightTerrainOne(e.w, worldPos, occ, normal, total); }
}

// All the lights of the cell (the composite light pass).
float3 DynLightTerrain(float3 worldPos, float3 normal)
{
    if (dynFieldParams2.x > 0.5)
    {
        return DynFieldTerrain(worldPos, normal);
    }
    float first;
    float texels;
    float2 occ;
    DynLightCell(worldPos, first, texels, occ);
    float3 total = float3(0, 0, 0);
    for (int t = 0; t < 64; ++t)
    {
        if ((float)t >= texels)
        {
            break;
        }
        DynLightTerrainQuad(DynLightGridTexel(first + (float)t), worldPos, occ, normal, total);
    }
    return total;
}

// Every decal and splat layer lights itself through CalculateLighting, so this one runs several times per pixel where the composite pass
// runs once. It reads the whole list of the cell: a cut list (the 16 strongest) differs from cell to cell wherever a base has more lights
// than that, and the lit ground then jumps at the cell borders (squares).
float3 DynLightTerrainFew(float3 worldPos, float3 normal)
{
    if (dynFieldParams2.x > 0.5)
    {
        return DynFieldTerrain(worldPos, normal);
    }
    float first;
    float texels;
    float2 occ;
    DynLightCell(worldPos, first, texels, occ);
    float3 total = float3(0, 0, 0);
    for (int t = 0; t < 64; ++t)
    {
        if ((float)t >= texels)
        {
            break;
        }
        DynLightTerrainQuad(DynLightGridTexel(first + (float)t), worldPos, occ, normal, total);
    }
    return total;
}
)HLSL";

    constexpr const char* kTerrainPassCode = R"HLSL(
// FAF dynamic lights: an extra pass after the terrain composite multiplies the lit terrain colour by (1 + light), using the terrain
// normals buffer and the interpolated world position (decals and splats add the same lights inside CalculateLighting).
float4 TerrainLightsPS( VS_OUTPUT inV ) : COLOR
{
    float3 normal = normalize(SampleScreen(NormalSampler, inV.mTexSS).xyz * 2 - 1);
    float3 total = DynLightTerrain(inV.mTexWT.xzy, normal);   // mTexWT = (x, z, height)
    float top = max(total.x, max(total.y, total.z));
    return float4(0.75 * total / (1.0 + 0.125 * top), 0);   // soft limit at 6 on the brightest channel, the hue is kept; the pass multiplies the terrain by (1 + light)
}

)HLSL";

    constexpr const char* kTerrainPass = R"HLSL(
    pass PDynLight
    {
        // FAF dynamic lights: dest * (src + 1), colour only (the alpha channel carries the specular/glow mask)
        AlphaBlendEnable = true;
        ColorWriteEnable = 0x07;
        SrcBlend = DestColor;
        DestBlend = One;
        ZEnable = true;
        ZFunc = LessEqual;
        ZWriteEnable = false;

        VertexShader = compile vs_1_1 TerrainVS(true);
        PixelShader = compile ps_3_0 TerrainLightsPS();
    }
)HLSL";

    // ------------------------------------------------------------------------------------------------ text helpers

    bool IsIdentChar(
      const char c
    )
    {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    }

    bool IsSpace(
      const char c
    )
    {
      return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    size_t SkipSpace(
      const string& s,
      size_t i
    )
    {
      while (i < s.size() && IsSpace(s[i])) {
        ++i;
      }
      return i;
    }

    size_t SkipInlineSpace(
      const string& s,
      size_t i
    )
    {
      while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) {
        ++i;
      }
      return i;
    }

    // `needle` at the start of a line (position 0 or after '\n') from `from`; npos if none.
    size_t FindAtLineStart(
      const string& s,
      const string_view needle,
      size_t from
    )
    {
      for (;;) {
        const size_t p = s.find(needle, from);
        if (p == npos) {
          return npos;
        }
        if (p == 0 || s[p - 1] == '\n') {
          return p;
        }
        from = p + 1;
      }
    }

    size_t CountOccurrences(
      const string& s,
      const string_view needle
    )
    {
      size_t n = 0;
      for (size_t p = s.find(needle); p != npos; p = s.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    }

    // The end of a function that starts at `start`: the first "\n}\n" after it (the engine's FX style closes functions
    // at column 0).
    size_t FunctionEnd(
      const string& s,
      const size_t start
    )
    {
      const size_t p = s.find("\n}\n", start);
      return p == npos ? npos : p + 3;
    }

    // Parses `<key> = compile <profile> <name>(<args>);` anywhere in `block`; false if absent or oddly shaped.
    struct ShaderCall
    {
      string profile;
      string call; // name(args)
      string name;
    };

    bool ParseShaderAssignment(
      const string& block,
      const string_view key,
      ShaderCall& out
    )
    {
      for (size_t p = block.find(key); p != npos; p = block.find(key, p + 1)) {
        if (p > 0 && IsIdentChar(block[p - 1])) {
          continue;
        }
        size_t i = SkipSpace(block, p + key.size());
        if (i >= block.size() || block[i] != '=') {
          continue;
        }
        i = SkipSpace(block, i + 1);
        if (block.compare(i, 7, "compile") != 0) {
          continue;
        }
        i = SkipSpace(block, i + 7);
        size_t j = i;
        while (j < block.size() && IsIdentChar(block[j])) {
          ++j;
        }
        out.profile = block.substr(i, j - i);
        i = SkipSpace(block, j);
        j = i;
        while (j < block.size() && IsIdentChar(block[j])) {
          ++j;
        }
        out.name = block.substr(i, j - i);
        if (out.name.empty() || j >= block.size() || block[j] != '(') {
          return false;
        }
        const size_t close = block.find(')', j);
        if (close == npos) {
          return false;
        }
        out.call = block.substr(i, close + 1 - i);
        const size_t semi = SkipSpace(block, close + 1);
        return semi < block.size() && block[semi] == ';';
      }
      return false;
    }

    // The first line of `block` whose text (ignoring blanks) is `RasterizerState(...)`; the trimmed line, or empty.
    string FindRasterizerLine(
      const string& block
    )
    {
      size_t pos = 0;
      while (pos < block.size()) {
        size_t eol = block.find('\n', pos);
        if (eol == npos) {
          eol = block.size();
        }
        size_t a = SkipInlineSpace(block, pos);
        size_t b = eol;
        while (b > a && (block[b - 1] == '\r' || block[b - 1] == ' ' || block[b - 1] == '\t')) {
          --b;
        }
        if (block.compare(a, 15, "RasterizerState") == 0 && b > a && block[b - 1] == ')') {
          return block.substr(a, b - a);
        }
        pos = eol + 1;
      }
      return {};
    }

    // `#ifndef DIRECT3D10 / AlphaTestEnable = true; ... #endif` as written in the block, or empty.
    string FindAlphaTestBlock(
      const string& block
    )
    {
      for (size_t p = block.find("#ifndef DIRECT3D10"); p != npos; p = block.find("#ifndef DIRECT3D10", p + 1)) {
        size_t i = SkipSpace(block, p + 18);
        if (block.compare(i, 22, "AlphaTestEnable = true") == 0) {
          const size_t end = block.find("#endif", i);
          if (end == npos) {
            return {};
          }
          return block.substr(p, end + 6 - p);
        }
      }
      return {};
    }

    struct TechniqueSpan
    {
      string name;
      size_t begin; // "technique" keyword
      size_t end;   // start of the next technique (or the end of the text)
    };

    std::vector<TechniqueSpan> FindTechniques(
      const string& s
    )
    {
      std::vector<TechniqueSpan> spans;
      size_t p = FindAtLineStart(s, "technique", 0);
      while (p != npos) {
        size_t i = p + 9;
        if (i >= s.size() || !IsSpace(s[i])) {
          p = FindAtLineStart(s, "technique", p + 1);
          continue;
        }
        i = SkipSpace(s, i);
        size_t j = i;
        while (j < s.size() && IsIdentChar(s[j])) {
          ++j;
        }
        TechniqueSpan span;
        span.name = s.substr(i, j - i);
        span.begin = p;
        spans.push_back(span);
        p = FindAtLineStart(s, "technique", j);
        // techniques need whitespace after the keyword, so this skips the word "techniques" in comments at line start
        // as well
      }
      for (size_t k = 0; k < spans.size(); ++k) {
        spans[k].end = k + 1 < spans.size() ? spans[k + 1].begin : s.size();
      }
      return spans;
    }

    // Puts `annotation` (one line, no newline) at the start of the technique's annotation block `< ... >`; false if it
    // has none.
    bool AddAnnotation(
      string& block,
      const string_view annotation
    )
    {
      // technique Name [ws] <
      size_t i = 9;
      i = SkipSpace(block, i);
      while (i < block.size() && IsIdentChar(block[i])) {
        ++i;
      }
      i = SkipSpace(block, i);
      if (i >= block.size() || block[i] != '<') {
        return false;
      }
      block.insert(i + 1, string("\n    ") + string(annotation));
      return true;
    }

    bool ContainsTechnique(
      const char* const* names,
      const size_t count,
      const string& name
    )
    {
      for (size_t i = 0; i < count; ++i) {
        if (name == names[i]) {
          return true;
        }
        const string hf = string(names[i]) + "_HighFidelity";
        if (name == hf) {
          return true;
        }
      }
      return false;
    }

    // ------------------------------------------------------------------------------------------------ mesh.fx

    // Mesh techniques with a tangent frame that get the light pass (their name, with or without _HighFidelity), as
    // make_lab_shaders.py.
    constexpr const char* kLitTangent[] = {
      "Unit",
      "Insect",
      "Aeon",
      "Seraphim",
      "AeonCZAR",
      "UEFNavy",
      "CybranNavy",
      "AeonNavy",
      "SeraphimNavy",
      "Metal",
      "NomadsUnit",
      "NormalMappedAlpha",
      "NormalMappedAlphaNoShadow",
      "UndulatingNormalMappedAlpha",
      "BloatingNormalMappedAlpha",
      "BlackenedNormalMappedAlpha",
      "NormalMappedGlow",
      "NormalMappedTerrain",
    };
    constexpr const char* kTangentVertexShaders[] =
      {"NormalMappedVS", "UnitFalloffVS", "UndulatingNormalMappedVS", "BloatingNormalMappedVS"};

    // Vertex shaders that return the lit structs: store the view distance (the pixel shader rebuilds the world position
    // from it).
    bool PatchVertexShaders(
      string& s,
      int& patched,
      string& error
    )
    {
      static const string_view kTypes[] = {"NORMALMAPPED_VERTEX", "VERTEXNORMAL_VERTEX"};
      static const string_view kNormalize = "    vertex.viewDirection = normalize(vertex.viewDirection);";
      for (const string_view type : kTypes) {
        size_t p = FindAtLineStart(s, type, 0);
        while (p != npos) {
          // "<TYPE> <Name>(" at the start of a line
          size_t i = p + type.size();
          if (i < s.size() && s[i] == ' ') {
            size_t j = i + 1;
            while (j < s.size() && IsIdentChar(s[j])) {
              ++j;
            }
            if (j > i + 1 && j < s.size() && s[j] == '(') {
              const string name = s.substr(i + 1, j - i - 1);
              const size_t end = FunctionEnd(s, j);
              if (end == npos) {
                error = "mesh.fx: no end for vertex shader " + name;
                return false;
              }
              string body = s.substr(p, end - p);
              const size_t norm = body.find(kNormalize);
              if (norm != npos) {
                bool done = false;
                if (type == "NORMALMAPPED_VERTEX" && body.find("vertex.depth") != npos) {
                  body.insert(
                    norm, "    vertex.depth.y = length(vertex.viewDirection); // FAF dynamic lights: view distance\n"
                  );
                  done = true;
                } else if (name == "VertexNormalVS") {
                  // texcoord0.zw is unused by the VertexNormal pixel shaders; the uv is assigned AFTER the view
                  // direction here, so keep the distance in a local and write .z after the uv line
                  body.insert(
                    norm,
                    "    float dynLightDist = length(vertex.viewDirection); // FAF dynamic lights: view distance\n"
                  );
                  const size_t uv = body.find("    vertex.texcoord0 = ");
                  const size_t eol = uv == npos ? npos : body.find('\n', uv);
                  if (eol == npos) {
                    error = "mesh.fx: VertexNormalVS has no texcoord0 line";
                    return false;
                  }
                  body.insert(eol + 1, "    vertex.texcoord0.z = dynLightDist;\n");
                  done = true;
                }
                if (done) {
                  s.replace(p, end - p, body);
                  ++patched;
                  p = FindAtLineStart(s, type, p + body.size());
                  continue;
                }
              }
              p = FindAtLineStart(s, type, end);
              continue;
            }
          }
          p = FindAtLineStart(s, type, p + 1);
        }
      }
      return true;
    }
  } // namespace

  PatchedEffect EffectForName(
    const std::string& baseName
  )
  {
    if (baseName == "mesh") {
      return PatchedEffect::Mesh;
    }
    if (baseName == "terrain") {
      return PatchedEffect::Terrain;
    }
    return PatchedEffect::None;
  }

  // Best effort, after the lights patch: moves the field block ahead of ComputeShadow and wraps that function so the
  // terrain's sun shadow (the field's third part) multiplies the shadow term. A source that does not look as expected
  // is left alone.
  static int AddSunShadow(
    std::string& s,
    const bool mesh,
    const bool pbrReads = true
  )
  {
    if (!mesh) {
      // The terrain shaders know their world position (mTexWT = x, z, height): the sun's shadow of the field multiplies
      // every read of the shadow map, the ones of the PBR shaders (tex2D(ShadowSampler, X.mShadow.xy).g) and
      // CalculateLighting's.
      int patched = 0;
      const std::string anchor = "float ComputeShadow( float4 vShadowCoord )";
      // The sun-under-water function goes after the field block (it reads the water level of the field), which sits
      // just ahead of CalculateLighting and so ahead of every read of the shadow that it wraps.
      const std::string litAnchor = "// calculate the lit pixels\nfloat4 CalculateLighting(";
      const bool under = CountOccurrences(s, anchor) == 1 && CountOccurrences(s, litAnchor) == 1 &&
        s.find("float DynFieldWaterLevel(") != std::string::npos &&
        s.find("float DynFieldWaterLevel(") < s.find(litAnchor);
      const std::string key = "tex2D(ShadowSampler, ";
      const std::string tail = ".mShadow.xy).g";
      size_t at = pbrReads ? 0 : std::string::npos;
      while (at != std::string::npos && (at = s.find(key, at)) != std::string::npos) {
        const size_t first = at + key.size();
        size_t last = first;
        while (last < s.size() && IsIdentChar(s[last])) {
          ++last;
        }
        if (last > first && s.compare(last, tail.size(), tail) == 0) {
          const size_t end = last + tail.size();
          const std::string var = s.substr(first, last - first);
          const std::string replacement = under
            ? "FafSunUnder(" + s.substr(at, end - at) + " * DynFieldSunTerrain(" + var + ".mTexWT.xzy), " + var +
              ".mTexWT.xzy)"
            : "(" + s.substr(at, end - at) + " * DynFieldSunTerrain(" + var + ".mTexWT.xzy))";
          s.replace(at, end - at, replacement);
          at += replacement.size();
          ++patched;
        } else {
          at += key.size();
        }
      }
      // the same reads after the shadow filter patch (ShadowEffectPatch.cpp): ShadowLookup(X.mShadow)
      const std::string filterKey = "ShadowLookup(";
      const std::string filterTail = ".mShadow)";
      at = pbrReads ? 0 : std::string::npos;
      while (at != std::string::npos && (at = s.find(filterKey, at)) != std::string::npos) {
        const size_t first = at + filterKey.size();
        size_t last = first;
        while (last < s.size() && IsIdentChar(s[last])) {
          ++last;
        }
        if (last > first && s.compare(last, filterTail.size(), filterTail) == 0) {
          const size_t end = last + filterTail.size();
          const std::string var = s.substr(first, last - first);
          const std::string replacement = under
            ? "FafSunUnder(" + s.substr(at, end - at) + " * DynFieldSunTerrain(" + var + ".mTexWT.xzy), " + var +
              ".mTexWT.xzy)"
            : "(" + s.substr(at, end - at) + " * DynFieldSunTerrain(" + var + ".mTexWT.xzy))";
          s.replace(at, end - at, replacement);
          at += replacement.size();
          ++patched;
        } else {
          at += filterKey.size();
        }
      }
      const std::string line =
        "    float shadow = ( inShadows && ( 1 == ShadowsEnabled ) ) ? ComputeShadow(shadowCoords) : 1;\n";
      if (CountOccurrences(s, line) == 1) {
        s.insert(
          s.find(line) + line.size(),
          under ? "    shadow = FafSunUnder(shadow * DynFieldSunTerrain(worldTerrain.xzy), worldTerrain.xzy);\n"
                : "    shadow *= DynFieldSunTerrain(worldTerrain.xzy);\n"
        );
        ++patched;
      }
      // The sun through water: a sea bed point sees the sun along a path that grows with the depth and the water takes
      // the light out of it, so the contrast of a shadow fades with the depth. Without it the shadow of a tree on the
      // shore falls on the sea bed far out in the water and is seen through the clear water as a dark tree shape
      // nowhere near a tree.
      if (under) {
        s.insert(
          s.find(litAnchor),
          "// ---- FAF sun under water (LightEffectPatch) ----\n"
          "float FafSunUnder(float sun, float3 p)\n"
          "{\n"
          "    float depth = max(DynFieldWaterLevel(p, WaterElevation) - p.y, 0.0);\n"
          "    float transmit = exp(-depth * 0.12 / max(SunDirection.y, 0.25));\n"
          "    return 1.0 - transmit * (1.0 - sun);\n"
          "}\n\n"
        );
      }
      return patched;
    }
    const std::string startMark = "// ---- FAF light field (LightField.cpp";
    const std::string endMark = "// ---- end FAF light field ----\n";
    const size_t fs = s.find(startMark);
    const size_t fe = fs == std::string::npos ? std::string::npos : s.find(endMark, fs);
    const std::string sig = mesh ? "float ComputeShadow( float4 shadowCoords, uniform bool hiDefFiltering )"
                                 : "float ComputeShadow( float4 vShadowCoord )";
    if (fs == std::string::npos || fe == std::string::npos || CountOccurrences(s, sig) != 1) {
      return 0;
    }
    const size_t sigAt = s.find(sig);
    const size_t fnEnd = FunctionEnd(s, sigAt);
    if (fnEnd == std::string::npos || sigAt > fs || fnEnd > fs) {
      return 0;
    }
    const size_t blockEnd = fe + endMark.size();
    const std::string block = s.substr(fs, blockEnd - fs);
    s.erase(fs, blockEnd - fs);
    s.insert(fnEnd, mesh ? kSunWrapperMesh : kSunWrapperTerrain);
    s.replace(sigAt, std::string("float ComputeShadow").size(), "float ComputeShadowBase");
    s.insert(sigAt, block + kSunDecl);
    return 1;
  }

  EffectPatchResult PatchMeshEffect(
    std::string& source,
    const int flood
  )
  {
    EffectPatchResult result;
    string s = source;

    if (s.find("dynLightData") != npos) {
      result.error = "mesh.fx: already patched";
      return result;
    }

    int vsPatched = 0;
    if (!PatchVertexShaders(s, vsPatched, result.error)) {
      return result;
    }
    if (vsPatched < 3) {
      result.error = "mesh.fx: only " + std::to_string(vsPatched) + " vertex shaders could store the view distance";
      return result;
    }

    // the one pixel shader that read depth.y (WreckagePS)
    const string depthRead = "0.01 * vertex.depth.y";
    if (CountOccurrences(s, depthRead) != 2) {
      result.error = "mesh.fx: the wreckage shader changed (depth.y reads)";
      return result;
    }
    for (size_t p = s.find(depthRead); p != npos; p = s.find(depthRead, p)) {
      const string replacement = "0.01 * (time - vertex.material.x)";
      s.replace(p, depthRead.size(), replacement);
      p += replacement.size();
    }

    // light shaders after PBR_Seraphim (they need ComputeNormal, the samplers and the PBR helper functions)
    const size_t pbr = s.find("float4 PBR_Seraphim(");
    const size_t pbrEnd = pbr == npos ? npos : FunctionEnd(s, pbr);
    if (pbrEnd == npos) {
      result.error = "mesh.fx: PBR_Seraphim not found";
      return result;
    }
    {
      string code = string(kCommonDecl) + kFieldDecl + kMeshLightCode;
      if (flood != 0) {
        for (const char* const ret :
             {"    return float4(lit * (1 - saturate(mirrored)), albedoTex.a);   // alpha: the alpha test of the "
              "technique still applies",
              "    return float4(lit * (1 - saturate(mirrored)), albedoTex.a);"}) {
          const size_t at = code.find(ret);
          if (at != npos) {
            code.replace(at, strlen(ret), "    return float4(1, 0, 1, albedoTex.a);   // /dynlightsflood");
          }
        }
        for (size_t at = code.find("    return float4(lit * (1 - saturate(mirrored)), albedoTex.a);"); at != npos;
             at = code.find("    return float4(lit * (1 - saturate(mirrored)), albedoTex.a);")) {
          code.replace(
            at,
            strlen("    return float4(lit * (1 - saturate(mirrored)), albedoTex.a);"),
            "    return float4(1, 0, 1, albedoTex.a);   // /dynlightsflood"
          );
        }
      }
      s.insert(pbrEnd, code);
    }

    // the light pass on the single-pass lit techniques
    std::vector<TechniqueSpan> spans = FindTechniques(s);
    string out;
    out.reserve(s.size() + 64 * 1024);
    size_t pos = 0;
    constexpr size_t kTangentCount = sizeof(kLitTangent) / sizeof(kLitTangent[0]);
    constexpr size_t kVsCount = sizeof(kTangentVertexShaders) / sizeof(kTangentVertexShaders[0]);
    for (const TechniqueSpan& span : spans) {
      const bool tangent = ContainsTechnique(kLitTangent, kTangentCount, span.name);
      const bool vertexNormal = span.name == "VertexNormal_HighFidelity";
      if (!tangent && !vertexNormal) {
        continue;
      }
      string block = s.substr(span.begin, span.end - span.begin);
      if (CountOccurrences(block, "pass ") != 1) {
        continue; // multi-pass techniques are left alone, as in the generator
      }
      ShaderCall vs;
      if (!ParseShaderAssignment(block, "VertexShader", vs)) {
        continue;
      }
      if (tangent) {
        bool known = false;
        for (size_t k = 0; k < kVsCount; ++k) {
          known = known || vs.name == kTangentVertexShaders[k];
        }
        if (!known) {
          continue;
        }
      }
      const string rasterizer = FindRasterizerLine(block);
      const string alphaTest = FindAlphaTestBlock(block);
      const char* const ps = tangent ? "DynLightsPS" : "DynLightsVertexNormalPS";

      string pass = "\n    pass PDynLight\n    {\n        // FAF dynamic lights: light-only pass, additive (see " +
        string(ps) + ")\n";
      if (!rasterizer.empty()) {
        pass += "        " + rasterizer + "\n";
      }
      if (!alphaTest.empty()) {
        pass += alphaTest + "\n";
      }
      pass += "        AlphaBlendEnable = true;\n        ColorWriteEnable = 0x07;\n        SrcBlend = One;\n        "
              "DestBlend = One;\n"
              "        ZEnable = true;\n        ZFunc = LessEqual;\n        ZWriteEnable = false;\n\n";
      pass += "        VertexShader = compile " + vs.profile + " " + vs.call +
        ";\n        PixelShader = compile ps_3_0 " + ps + "();\n    }\n";

      const size_t close = block.find_last_of('}');
      if (close == npos) {
        continue;
      }
      // keep the text before the closing brace as it is, trimmed of trailing blank lines like the generator
      size_t cut = close;
      while (cut > 0 && block[cut - 1] == '\n') {
        --cut;
      }
      string patched = block.substr(0, cut) + "\n" + pass + block.substr(close);
      if (!AddAnnotation(patched, "int dynLightPasses = 1;")) {
        continue; // no annotation block to mark it: the pass could not be dropped when idle, so do not add it
      }
      out.append(s, pos, span.begin - pos);
      out += patched;
      pos = span.end;
      ++result.techniques;
    }
    if (result.techniques < 10) {
      result.error = "mesh.fx: only " + std::to_string(result.techniques) + " techniques could take the light pass";
      return result;
    }
    out.append(s, pos, npos);

    result.sunShadowSites = AddSunShadow(out, true);
    result.sunShadow = result.sunShadowSites > 0;
    source = std::move(out);
    result.patched = true;
    return result;
  }

  EffectPatchResult PatchTerrainEffect(
    std::string& source,
    const int flood,
    const bool sunReads
  )
  {
    EffectPatchResult result;
    string s = source;

    if (s.find("dynLightData") != npos) {
      result.error = "terrain.fx: already patched";
      return result;
    }

    const string marker = "technique TTerrainDepth";
    if (CountOccurrences(s, marker) != 1) {
      result.error = "terrain.fx: TTerrainDepth not found";
      return result;
    }

    // CalculateLighting: the decal and splat shaders light through it, so the lights go into its sun term
    const string anchor = "// calculate the lit pixels\nfloat4 CalculateLighting(";
    if (CountOccurrences(s, anchor) != 1) {
      result.error = "terrain.fx: CalculateLighting not found";
      return result;
    }
    const string sunTerm =
      "    float3 light = SunColor * saturate( SunDotNormal) * shadow + SunAmbience * ambientOcclusion + specular;\n";
    if (CountOccurrences(s, sunTerm) != 1) {
      result.error = "terrain.fx: the sun term of CalculateLighting changed";
      return result;
    }
    {
      const size_t p = s.find(sunTerm);
      s.insert(
        p + sunTerm.size(), "    light += DynLightTerrainFew(worldTerrain.xzy, inNormal);   // FAF dynamic lights\n"
      );
    }
    {
      const size_t p = s.find(anchor);
      s.insert(p, string(kCommonDecl) + kFieldDecl + kTerrainLightFunction + "\n");
    }

    // the pixel shader of the composite pass goes ahead of the first technique
    {
      const size_t p = s.find(marker);
      string code = kTerrainPassCode;
      if (flood != 0) {
        const string ret = "    return float4(0.75 * total / (1.0 + 0.125 * top), 0);";
        const size_t at = code.find(ret);
        if (at != npos) {
          code.replace(
            at,
            ret.size(),
            flood == 2 ? // the world position as a 20-unit checker: shows the pass gets world coordinates
              "    return float4(frac(inV.mTexWT.x / 20.0), frac(inV.mTexWT.y / 20.0), 0, 0);   // /dynlightsflood2"
                       : "    return float4(1, 0, 1, 0);   // /dynlightsflood"
          );
        }
      }
      s.insert(p, code);
    }

    // the light pass at the end of every composite technique
    std::vector<TechniqueSpan> spans = FindTechniques(s);
    string out;
    out.reserve(s.size() + 8 * 1024);
    size_t pos = 0;
    for (const TechniqueSpan& span : spans) {
      string block = s.substr(span.begin, span.end - span.begin);
      const size_t header = block.find('>');
      if (header == npos) {
        continue;
      }
      if (block.substr(0, header).find("usage = \"composite\"") == npos) {
        continue;
      }
      // closing brace of the technique body: match braces from the first '{' after the annotation block
      size_t k = block.find('{', header);
      if (k == npos) {
        continue;
      }
      int depth = 0;
      for (;; ++k) {
        if (k >= block.size()) {
          k = npos;
          break;
        }
        if (block[k] == '{') {
          ++depth;
        } else if (block[k] == '}') {
          if (--depth == 0) {
            break;
          }
        }
      }
      if (k == npos) {
        continue;
      }
      string patched = block.substr(0, k) + kTerrainPass + block.substr(k);
      if (!AddAnnotation(patched, "int dynLightPasses = 1;")) {
        continue;
      }
      out.append(s, pos, span.begin - pos);
      out += patched;
      pos = span.end;
      ++result.techniques;
    }
    if (result.techniques < 5) {
      result.error = "terrain.fx: only " + std::to_string(result.techniques) + " composite techniques found";
      return result;
    }
    out.append(s, pos, npos);

    result.sunShadowSites = AddSunShadow(out, false, sunReads);
    result.sunShadow = result.sunShadowSites > 0;
    source = std::move(out);
    result.patched = true;
    return result;
  }

  EffectPatchResult PatchWaterEffect(
    std::string& source
  )
  {
    EffectPatchResult result;
    constexpr string_view kShader = "float4 HighFidelityPS(";
    constexpr string_view kCrest =
      "water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);";
    if (
      CountOccurrences(source, kShader) != 1 || CountOccurrences(source, kCrest) != 1 ||
      source.find("FafWaterLights") != npos
    ) {
      result.error = "HighFidelityPS or its wave crest line not found exactly once";
      return result;
    }
    const size_t shader = source.find(kShader);
    if (source.find("float3 calculateSunReflection") == npos || source.find("float3 calculateSunReflection") > shader) {
      result.error = "calculateSunReflection (the BRDF helpers) not defined before HighFidelityPS";
      return result;
    }
    string text = source;
    const size_t crest = text.find(kCrest);
    text.insert(
      crest + kCrest.size(), "\n    water += FafWaterLights(ViewPosition - inV.mViewVec, N, viewVector, waterDepth);"
    );
    // the terrain's shadow on the water: the sun reflection is cut where the shore blocks the sun
    constexpr string_view kSunLine = "sunReflection *= waterTexture.r;";
    if (CountOccurrences(text, kSunLine) == 1) {
      text.insert(
        text.find(kSunLine) + kSunLine.size(),
        "\n    sunReflection *= DynFieldSun(float3(ViewPosition.x - inV.mViewVec.x, WaterElevation, ViewPosition.z - "
        "inV.mViewVec.z));"
      );
    }
    text.insert(text.find(kShader), string(kFieldDecl) + kWaterLightCode + "\n");
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::lights
