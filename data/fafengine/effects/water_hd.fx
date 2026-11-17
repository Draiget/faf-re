// Detailed water (engine addition, ren_WaterDetail; Direct3D 12 and Vulkan only).
//
// The engine appends this file to FAF's effects/water2.fx when it loads that effect on a Direct3D 12 or
// Vulkan device; Direct3D 9 and 11 never see it. FAF's high-fidelity water pass is pointed at
// WaterHdSelectPS below, which draws FAF's HighFidelityPS or this file's WaterHdPS by WaterHdEnabled (the
// engine sets it from ren_WaterDetail on each draw). If this file fails to compile against water2.fx, the
// game logs it and draws the water as before.
//
// It keeps each map's water settings (colour, depth tint range, normal maps and their movement, sun
// colour, shininess and direction, reflection amounts) and adds on top of them:
//   - swell: four travelling waves along the map's wind (the first normal layer's movement), longer and
//     faster ones first, calmer in shallow water;
//   - distance roughness: waves and normal-map detail smaller than a pixel turn into roughness of the
//     sun's highlight instead of flickering, so the sun's path on the water widens towards the horizon;
//   - sparkles: small glints of the sun that come and go on the water near the camera;
//   - colour by depth: FAF's tint between the map's own limits, with red going first, so shallows lean
//     cyan; the tint thins out as the camera comes close, so the bottom shows through near water;
//   - caustics: moving light lines on the bottom of shallow, sunlit water;
//   - relief: wave slopes facing the sun a little lighter, the others a little darker;
//   - shore: the reflection and the sun fade out at the waterline (no hard edge), and a thin foam line
//     runs in and out along it.
//
// The random values behind the caustics, sparkles and foam come from a small noise texture the engine builds
// once (WaterHdNoise), which costs far less than hashing per pixel.
//
// The engine reads this file at startup from the game folder (fafengine/effects), so it can be changed
// without rebuilding the engine.

#if defined(DIRECT3D12) || defined(VULKAN)

// ---- settings ---------------------------------------------------------------------------

// Swell: four waves, each wavelength in world units (a frigate is about 4 long), slope and direction off the
// wind in radians (WaterHdPS lists them).
// Wave speed in world units per second for a wavelength L: WaterHdSwellSpeed * sqrt(L).
static const float WaterHdSwellSpeed = 0.40;
// Depth (the water map's 0..1) below which the swell calms down.
static const float WaterHdSwellShallow = 0.12;
// The map's normal layers: share of their slope that is kept.
static const float WaterHdMapNormalScale = 1.0;
// A wave is drawn while its wavelength is at least this many pixels; below, it becomes roughness.
static const float WaterHdPixelsPerWave = 4.0;

// Sun highlight. Maps whose sun direction points down use the original Phong exponent; this turns it into
// a roughness (sqrt(2 / (n + 2)) times this scale) and scales the highlight's brightness.
static const float WaterHdLegacyRoughnessScale = 0.35;
static const float WaterHdLegacySunGain = 0.6;
static const float WaterHdSunGain = 1.0;

// Sparkles: cell size in world units, slope range of the facets, angular tolerance (radians), brightness.
static const float WaterHdSparkleCell = 0.55;
static const float WaterHdSparkleSlope = 0.16;
static const float WaterHdSparkleTolerance = 0.035;
static const float WaterHdSparkleGain = 3.0;
static const float WaterHdSparkleSpin = 0.8;

// Colour by depth: FAF tints by clamp(depth, waterLerp.x, waterLerp.y); a channel the map's colour has none
// of reaches the tint this many times faster (red in a blue sea), so shallows lean cyan.
static const float WaterHdTintFaster = 1.0;
// Seeing through near water: below this camera distance the tint and the reflection are cut to the share
// below, reaching full strength at the far distance.
static const float WaterHdClearNear = 25.0;
static const float WaterHdClearFar = 140.0;
static const float WaterHdClearTint = 0.5;
static const float WaterHdClearReflection = 0.5;

// Shore: depth over which the surface fades in from the waterline. The foam is a thin line along the waterline
// that runs up and back (swash): its mean depth, how far it moves, its width, speed (cycles per second), brightness.
static const float WaterHdShoreFade = 0.015;
static const float WaterHdFoamDepth = 0.010;
static const float WaterHdFoamSwash = 0.006;
static const float WaterHdFoamWidth = 0.006;
static const float WaterHdFoamSpeed = 0.12;
static const float WaterHdFoamGain = 0.35;

// Caustics: the sun focused by the waves into moving bright lines on a shallow bottom. Pattern scale (cycles per
// world unit), speed, sharpness, brightness, and the depths where they are strongest and where they are gone.
static const float WaterHdCausticScale = 0.45;
static const float WaterHdCausticSpeed = 0.35;
static const float WaterHdCausticSharp = 7.0;
static const float WaterHdCausticGain = 0.5;
static const float WaterHdCausticFull = 0.04;
static const float WaterHdCausticEnd = 0.30;

// Wave relief: slopes facing the sun lighter, the others darker, so the swell reads from above.
static const float WaterHdRelief = 1.2;

// ---- helpers ----------------------------------------------------------------------------

// Engine addition: a 256x256 tiling texture of random bytes, four independent values per texel, that the engine
// builds once and binds as WaterHdNoise. Without it (an engine that doesn't bind it) every read is 0: no caustics,
// sparkles or foam wobble.
texture WaterHdNoise;
sampler WaterHdNoiseSampler = sampler_state
{
    Texture   = <WaterHdNoise>;
    MipFilter = POINT;
    MinFilter = LINEAR;
    MagFilter = LINEAR;
    AddressU  = WRAP;
    AddressV  = WRAP;
};
static const float WaterHdNoiseSize = 256.0;

// Smooth value noise in 0..1 with lattice spacing 1: the lattice values are the texels, and one filtered read at a
// smoothstep-remapped position gives the same smooth interpolation as hashing the four corners. channel picks which
// of the texel's four independent values.
float WaterHdSmoothNoise(float2 p, float4 channel)
{
    const float2 i = floor(p);
    const float2 f = p - i;
    const float2 u = f * f * (3.0 - 2.0 * f);
    return dot(tex2Dlod(WaterHdNoiseSampler, float4((i + u + 0.5) * (1.0 / WaterHdNoiseSize), 0.0, 0.0)), channel);
}

// The four random values of a lattice cell (an exact texel read).
float4 WaterHdCellRandom(float2 cell)
{
    return tex2Dlod(WaterHdNoiseSampler, float4((cell + 0.5) * (1.0 / WaterHdNoiseSize), 0.0, 0.0));
}

// Caustic lines: where two drifting noise fields are equal, a thin bright line; two scales.
float WaterHdCausticLayer(float2 p, float2 drift0, float2 drift1, float seconds)
{
    const float a = WaterHdSmoothNoise(p + drift0 * seconds, float4(1, 0, 0, 0));
    const float b = WaterHdSmoothNoise(p * 1.37 + float2(5.2, 1.3) + drift1 * seconds, float4(0, 1, 0, 0));
    const float ridge = saturate(1.0 - abs(a - b) * WaterHdCausticSharp);
    return ridge * ridge * ridge;
}

float WaterHdCaustics(float2 position, float seconds)
{
    const float2 p = position * WaterHdCausticScale;
    const float s = WaterHdCausticSpeed;
    return WaterHdCausticLayer(p, float2(s, 0.3 * s), float2(-0.6 * s, s), seconds) * 0.7
        + WaterHdCausticLayer(p * 2.1 + 3.7, float2(-s, 0.8 * s), float2(0.4 * s, -s), seconds) * 0.3;
}

// Schlick's Fresnel with plain multiplies (FAF's pow goes through the translator's sign-safe wrapper).
float WaterHdFresnel(float cosine, float f0)
{
    const float m = 1.0 - cosine;
    const float m2 = m * m;
    return f0 + (1.0 - f0) * m2 * m2 * m;
}

// A normal-map texel (FAF's encoding, z up) as a normal, and the slope variance its mip lost (Toksvig:
// 1 / |n| - 1, here as its series in e = 1 - |n|^2, which needs no square root).
float4 WaterHdLayer(float4 texel)
{
    const float3 n = texel.xyz * 2.0 - 1.0;
    const float e = saturate(1.0 - dot(n, n));
    return float4(n, e * (0.5 + 0.375 * e));
}

// One swell wave, in the wind's frame: position is (along the wind, across it), turnCos and turnSin turn the wave
// off the wind. Adds its slope (in that frame, before the shallows calm it) where a pixel can show it, else its
// squared slope to lost. perWave is 1 / (footprint * WaterHdPixelsPerWave). Every argument but the position and
// perWave is a constant or the same for the whole draw, so the compiler folds them.
void WaterHdSwell(inout float2 slopeSum, inout float lost, float2 position, float seconds, float perWave,
                  float wavelength, float slope, float turnCos, float turnSin, float offset, bool small)
{
    const float k = 6.2831853 / wavelength;
    const float drawn = saturate(wavelength * perWave - 1.0);
    lost += slope * slope * (1.0 - drawn);
    // The small waves go below a pixel in far views: skip them there (small is a constant per call).
    [branch] if (small && drawn <= 0.0) {
        return;
    }
    const float phase = (k * turnCos) * position.x + (k * turnSin) * position.y
        + (offset - k * WaterHdSwellSpeed * sqrt(wavelength) * seconds);
    float s, c;
    sincos(phase, s, c);
    // A sharpened sine: narrow crests, wide troughs.
    slopeSum += float2(turnCos, turnSin) * (slope * drawn * c * (1.0 + 0.6 * s));
}

// ---- pixel shader -----------------------------------------------------------------------

float4 WaterHdPS( VS_OUTPUT inV,
                  uniform bool alphaTestEnable,
                  uniform int alphaFunc,
                  uniform int alphaRef ) : COLOR
{
    float4 waterTexture = tex2D(UtilitySamplerC, inV.mTexUV);
    const float waterDepth = waterTexture.g;
    const float3 worldPos = ViewPosition - inV.mViewVec;
    const float seconds = Time * 0.1;

    const float viewDistance = length(inV.mViewVec);
    float3 viewVector = inV.mViewVec / max(viewDistance, 1e-6);

    float OneOverW = 1.0 / inV.mScreenPos.w;
    inV.mScreenPos.xyz *= OneOverW;
    float2 screenPos = inV.mScreenPos.xy * ViewportScaleOffset.xy + ViewportScaleOffset.zw;

    float4 backGroundPixels = tex2D(RefractionSampler, screenPos);
    float mask = saturate(backGroundPixels.a * 255);
    // One pixel of the screen in its 0..1 coordinates.
    const float screenPixel = max(abs(ddx(screenPos.x)), abs(ddy(screenPos.y)));

    // World units one pixel covers here.
    const float2 worldDx = ddx(worldPos.xz);
    const float2 worldDy = ddy(worldPos.xz);
    const float footprint = max(sqrt(max(dot(worldDx, worldDx), dot(worldDy, worldDy))), 1e-4);

    // The map's four normal layers as gradients, as FAF sums them, plus what their mips averaged away.
    const float4 W0 = tex2D(NormalSampler0, inV.mLayer0);
    const float4 W1 = tex2D(NormalSampler1, inV.mLayer1);
    const float4 W2 = tex2D(NormalSampler2, inV.mLayer2);
    const float4 W3 = tex2D(NormalSampler3, inV.mLayer3);
    const float4 l0 = WaterHdLayer(W0);
    const float4 l1 = WaterHdLayer(W1);
    const float4 l2 = WaterHdLayer(W2);
    const float4 l3 = WaterHdLayer(W3);
    // The layers' mean slope: their summed normal over its summed height, as FAF sums them.
    const float3 layerSum = l0.xyz + l1.xyz + l2.xyz + l3.xyz;
    float2 gradient = -layerSum.xy * (WaterHdMapNormalScale / max(layerSum.z, 1.0));
    float variance = (l0.w + l1.w + l2.w + l3.w) * 0.0625 * WaterHdMapNormalScale;

    // Crest foam as FAF draws it (alpha of the normal layers).
    const float waveCrest = saturate(W0.a + W1.a + W2.a + W3.a - waveCrestThreshold);

    // Swell along the wind.
    float2 wind = normal1Movement;
    wind = (dot(wind, wind) > 1e-8) ? normalize(wind) : float2(0.6, 0.8);
    const float calm = saturate(waterDepth / WaterHdSwellShallow);
    const float perWave = 1.0 / (footprint * WaterHdPixelsPerWave);
    const float2 across = float2(-wind.y, wind.x);
    const float2 inWind = float2(dot(worldPos.xz, wind), dot(worldPos.xz, across));
    float2 slopeSum = float2(0.0, 0.0);
    float lost = 0.0;
    // Wavelength, slope, the cosine and sine of the turn off the wind (0, 0.55, -0.70, -1.25 rad), phase.
    WaterHdSwell(slopeSum, lost, inWind, seconds, perWave, 41.0, 0.05, 1.0, 0.0, 0.0, false);
    WaterHdSwell(slopeSum, lost, inWind, seconds, perWave, 26.0, 0.048, 0.852525, 0.522687, 1.7, false);
    WaterHdSwell(slopeSum, lost, inWind, seconds, perWave, 16.5, 0.045, 0.764842, -0.644218, 3.4, false);
    WaterHdSwell(slopeSum, lost, inWind, seconds, perWave, 6.6, 0.038, 0.315322, -0.948985, 6.8, true);
    gradient += (wind * slopeSum.x + across * slopeSum.y) * calm;
    variance += 0.5 * calm * calm * lost;

    float3 N = normalize(float3(-gradient.x, 1.0, -gradient.y));

    float3 R = reflect(-viewVector, N);

    float2 refractionPos = screenPos;
    const float2 bend = sqrt(waterDepth) * refractionScale * N.xz * OneOverW;
    refractionPos -= bend;
    // Where the bend is under a quarter of a pixel (most far water) the bent read would return the straight one.
    float4 refractedPixels = backGroundPixels;
    [branch] if (dot(bend, bend) > 0.0625 * screenPixel * screenPixel) {
        refractedPixels = tex2Dlod(RefractionSampler, float4(refractionPos, 0.0, 0.0));
        refractedPixels.rgb = lerp(refractedPixels, backGroundPixels, saturate(refractedPixels.a * 255)).rgb;
    }

    // Caustics on a shallow, sunlit bottom (the bottom point is taken below the surface along the wave normal).
    {
        const float3 toSun = (SunDirection.y < 0.0) ? -SunDirection : SunDirection;
        const float shallow = saturate(waterDepth / WaterHdCausticFull)
            * saturate((WaterHdCausticEnd - waterDepth) / (WaterHdCausticEnd - WaterHdCausticFull));
        const float strength = WaterHdCausticGain * shallow * waterTexture.r * saturate(toSun.y * 3.0);
        // Deep water, shadow and a low sun have none: most of a map's water skips them.
        [branch] if (strength > 0.0) {
            const float2 bottom = worldPos.xz + N.xz * (2.0 + 20.0 * waterDepth);
            refractedPixels.rgb *= 1.0 + strength * WaterHdCaustics(bottom, seconds);
        }
    }

    // Colour by depth: FAF's tint, a channel the map's colour lacks going first, thinner near the camera.
    const float strongest = max(max(waterColor.r, waterColor.g), max(waterColor.b, 1e-3));
    const float3 share = saturate(waterColor / strongest);
    const float3 tint = clamp(waterDepth * (1.0 + WaterHdTintFaster * (1.0 - share)), waterLerp.x, waterLerp.y);
    const float distant = saturate((viewDistance - WaterHdClearNear) / (WaterHdClearFar - WaterHdClearNear));
    refractedPixels.rgb = lerp(refractedPixels.rgb, waterColor, tint * lerp(WaterHdClearTint, 1.0, distant));

    float4 unitReflections = tex2D(ReflectionSampler, refractionPos);

    float4 skyReflection = texCUBE(SkySampler, R);
    float3 reflections = lerp(skyReflection.rgb, unitReflections.rgb, saturate(unitReflections.a));

    float NDotV = saturate(dot(viewVector, N));
    float fresnel = WaterHdFresnel(NDotV, 0.08);
    float skyAmount = (skyreflectionAmount == 1.5) ? 1.0 : skyreflectionAmount;
    float3 water = lerp(refractedPixels.rgb, reflections,
        saturate(fresnel * skyAmount) * lerp(WaterHdClearReflection, 1.0, distant));

    // Wave relief, faded out in the shallows where the bottom shows.
    {
        const float3 toSun = (SunDirection.y < 0.0) ? -SunDirection : SunDirection;
        const float2 sunFlat = normalize(toSun.xz + float2(1e-4, 0.0));
        water *= 1.0 + WaterHdRelief * dot(N.xz, sunFlat) * saturate(waterDepth / 0.1);
    }

    // The sun: GGX whose roughness carries the slope variance the pixel can't show.
    const bool legacySun = SunDirection.y < 0.0;
    const float3 L = legacySun ? -SunDirection : SunDirection;
    const float baseRoughness = legacySun ? sqrt(2.0 / (SunShininess + 2.0)) * WaterHdLegacyRoughnessScale
                                          : 1.0 / max(SunShininess, 1.0);
    const float roughness = sqrt(baseRoughness * baseRoughness + 2.0 * variance);
    const float3 H = normalize(viewVector + L);
    const float NDotL = saturate(dot(N, L));
    const float sunFresnel = WaterHdFresnel(saturate(dot(H, viewVector)), 0.02);
    const float sunVisible = waterTexture.r * (1.0 - saturate(unitReflections.a * 4.0)) * step(0.0, L.y);
    float3 sunReflection = float3(0, 0, 0);
    [branch] if (NDotL > 0.0 && sunVisible > 0.0) {
        const float nDotV = abs(dot(N, viewVector)) + 0.001;
        const float D = NormalDistribution(N, H, roughness);
        const float G = GeometrySmith(N, nDotV, L, roughness);
        sunReflection = (PI * D * G * sunFresnel / (4.0 * nDotV * NDotL + 0.0001)) * NDotL * SunColor;
        sunReflection *= legacySun ? WaterHdLegacySunGain : WaterHdSunGain;
    }

    // Sparkles: in each cell a small facet whose tilt turns over time flashes when it mirrors the sun. Worked in
    // slopes: a facet mirrors the sun when its slope is -H.xz / H.y, and near that a slope miss d turns the facet by
    // about |d| * H.y^2 radians. Facets lean at most WaterHdSparkleSlope off the wave, so a pixel whose wave slope
    // misses by more than that plus the tolerance can't flash and skips the cell hash.
    const float sparkleDrawn = saturate(WaterHdSparkleCell / (footprint * 3.0) - 1.0);
    const float hy = max(H.y, 0.05);
    const float2 mirrorSlope = -H.xz / hy;
    const float2 miss = gradient - mirrorSlope;
    const float reach = WaterHdSparkleSlope + WaterHdSparkleTolerance / (hy * hy);
    [branch] if (sparkleDrawn > 0.0 && L.y > 0.0 && sunVisible > 0.0 && dot(miss, miss) < reach * reach) {
        const float2 q = worldPos.xz / WaterHdSparkleCell;
        const float2 cell = floor(q);
        const float2 inCell = q - cell;
        const float4 random = WaterHdCellRandom(cell);
        const float2 r0 = random.xy;
        const float2 r1 = random.zw;
        const float2 fromCentre = inCell - (0.2 + 0.6 * r0);
        const float spot = saturate(1.0 - length(fromCentre) * 5.0);
        const float turn = r1.x * 6.2831853 + seconds * WaterHdSparkleSpin * (0.5 + r1.y);
        float ts, tc;
        sincos(turn, ts, tc);
        const float2 facetMiss = miss + WaterHdSparkleSlope * sqrt(r1.y) * float2(tc, ts);
        const float angle2 = dot(facetMiss, facetMiss) * (hy * hy * hy * hy);
        const float aligned = saturate(1.0 - angle2 / (WaterHdSparkleTolerance * WaterHdSparkleTolerance));
        sunReflection += SunColor * (WaterHdSparkleGain * sunFresnel * 50.0 * aligned * aligned * spot * spot * sparkleDrawn);
    }

    water += sunReflection * sunVisible;

    // FAF's crest foam.
    water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);

    // Foam: a thin line along the waterline that runs up and back, a little irregular along the shore. Only the
    // shallowest water can have it.
    [branch] if (waterDepth < WaterHdFoamDepth + WaterHdFoamSwash + WaterHdFoamWidth && waterTexture.a < 1.0) {
        const float wobble = WaterHdSmoothNoise(worldPos.xz * 0.25, float4(0, 0, 1, 0));
        const float edge = WaterHdFoamDepth + WaterHdFoamSwash * sin(6.2831853 * (seconds * WaterHdFoamSpeed + wobble));
        const float foam = saturate(1.0 - abs(waterDepth - edge) / WaterHdFoamWidth)
            * (0.6 + 0.4 * WaterHdSmoothNoise(worldPos.xz * 1.1 + seconds * 0.15, float4(0, 0, 0, 1))) * (1 - waterTexture.a);
        const float lit = 0.55 + 0.45 * waterTexture.r;
        water = lerp(water, waveCrestColor * lit, foam * foam * WaterHdFoamGain);
    }

    // Soft waterline: the surface fades in over the first bit of depth, showing the ground under it.
    const float surface = saturate(waterDepth / WaterHdShoreFade);
    water = lerp(backGroundPixels.rgb, water, surface);

    float4 returnPixels;
    returnPixels.rgb = water;
    returnPixels.a = 1 - mask;
    return returnPixels;
}

// FAF's high-fidelity water pass draws through this (the engine points it here when it appends the file).
float WaterHdEnabled = 0;

float4 WaterHdSelectPS( VS_OUTPUT inV,
                        uniform bool alphaTestEnable,
                        uniform int alphaFunc,
                        uniform int alphaRef ) : COLOR
{
    if (WaterHdEnabled > 0.5) {
        return WaterHdPS(inV, alphaTestEnable, alphaFunc, alphaRef);
    }
    return HighFidelityPS(inV, alphaTestEnable, alphaFunc, alphaRef);
}

#endif
