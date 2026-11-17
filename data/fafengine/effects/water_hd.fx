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
//   - swell: six travelling waves along the map's wind (the first normal layer's movement), longer and
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
// The engine reads this file at startup from the game folder (fafengine/effects), so it can be changed
// without rebuilding the engine.

#if defined(DIRECT3D12) || defined(VULKAN)

// ---- settings ---------------------------------------------------------------------------

// Swell: six waves, each wavelength in world units (a frigate is about 4 long), slope and direction off the
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

float2 WaterHdHash22(float2 p)
{
    float3 p3 = frac(float3(p.xyx) * float3(0.1031, 0.1030, 0.0973));
    p3 += dot(p3, p3.yzx + 33.33);
    return frac((p3.xx + p3.yz) * p3.zy);
}

float WaterHdValueNoise(float2 p)
{
    const float2 i = floor(p);
    const float2 f = frac(p);
    const float2 u = f * f * (3.0 - 2.0 * f);
    const float a = WaterHdHash22(i).x;
    const float b = WaterHdHash22(i + float2(1, 0)).x;
    const float c = WaterHdHash22(i + float2(0, 1)).x;
    const float d = WaterHdHash22(i + float2(1, 1)).x;
    return lerp(lerp(a, b, u.x), lerp(c, d, u.x), u.y);
}

// Caustic lines: where two drifting noise fields are equal, a thin bright line; two scales.
float WaterHdCausticLayer(float2 p, float2 drift0, float2 drift1, float seconds)
{
    const float a = WaterHdValueNoise(p + drift0 * seconds);
    const float b = WaterHdValueNoise(p * 1.37 + float2(5.2, 1.3) + drift1 * seconds);
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

// A normal-map texel (FAF's encoding, z up) as a height gradient, and the slope variance its mip lost (Toksvig).
float3 WaterHdLayerGradient(float4 texel)
{
    const float3 n = texel.xyz * 2.0 - 1.0;
    const float len = max(length(n), 0.001);
    const float variance = saturate((1.0 - len) / len);
    const float up = max(n.z, 0.25);
    return float3(-n.x / up, -n.y / up, variance);
}

// One swell wave: adds its gradient where a pixel can show it, else its slope variance.
void WaterHdSwell(inout float2 gradient, inout float variance, float2 position, float seconds, float windAngle,
                  float footprint, float calm, float wavelength, float slope, float angle, float offset)
{
    const float2 direction = float2(cos(windAngle + angle), sin(windAngle + angle));
    const float k = 6.2831853 / wavelength;
    const float phase = k * (dot(direction, position) - WaterHdSwellSpeed * sqrt(wavelength) * seconds) + offset;
    const float amount = slope * calm;
    const float drawn = saturate(wavelength / (footprint * WaterHdPixelsPerWave) - 1.0);
    // A sharpened sine: narrow crests, wide troughs.
    gradient += direction * (amount * cos(phase) * (1.0 + 0.6 * sin(phase)) * drawn);
    variance += 0.5 * amount * amount * (1.0 - drawn);
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

    float3 viewVector = normalize(inV.mViewVec);

    float OneOverW = 1.0 / inV.mScreenPos.w;
    inV.mScreenPos.xyz *= OneOverW;
    float2 screenPos = inV.mScreenPos.xy * ViewportScaleOffset.xy + ViewportScaleOffset.zw;

    float4 backGroundPixels = tex2D(RefractionSampler, screenPos);
    float mask = saturate(backGroundPixels.a * 255);

    // World units one pixel covers here.
    const float footprint = max(max(length(ddx(worldPos.xz)), length(ddy(worldPos.xz))), 1e-4);

    // The map's four normal layers as gradients, as FAF sums them, plus what their mips averaged away.
    const float4 W0 = tex2D(NormalSampler0, inV.mLayer0);
    const float4 W1 = tex2D(NormalSampler1, inV.mLayer1);
    const float4 W2 = tex2D(NormalSampler2, inV.mLayer2);
    const float4 W3 = tex2D(NormalSampler3, inV.mLayer3);
    const float3 g0 = WaterHdLayerGradient(W0);
    const float3 g1 = WaterHdLayerGradient(W1);
    const float3 g2 = WaterHdLayerGradient(W2);
    const float3 g3 = WaterHdLayerGradient(W3);
    float2 gradient = (g0.xy + g1.xy + g2.xy + g3.xy) * (0.25 * WaterHdMapNormalScale);
    float variance = (g0.z + g1.z + g2.z + g3.z) * 0.0625 * WaterHdMapNormalScale;

    // Crest foam as FAF draws it (alpha of the normal layers).
    const float waveCrest = saturate(W0.a + W1.a + W2.a + W3.a - waveCrestThreshold);

    // Swell along the wind.
    float2 wind = normal1Movement;
    wind = (dot(wind, wind) > 1e-8) ? normalize(wind) : float2(0.6, 0.8);
    const float windAngle = atan2(wind.y, wind.x);
    const float calm = saturate(waterDepth / WaterHdSwellShallow);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 41.0, 0.050, 0.00, 0.0);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 26.0, 0.048, 0.55, 1.7);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 16.5, 0.045, -0.70, 3.4);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 10.5, 0.042, 1.05, 5.1);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 6.6, 0.038, -1.25, 6.8);
    WaterHdSwell(gradient, variance, worldPos.xz, seconds, windAngle, footprint, calm, 4.2, 0.034, 0.30, 8.5);

    float3 N = normalize(float3(-gradient.x, 1.0, -gradient.y));

    float3 R = reflect(-viewVector, N);

    float2 refractionPos = screenPos;
    refractionPos -= sqrt(waterDepth) * refractionScale * N.xz * OneOverW;
    float4 refractedPixels = tex2D(RefractionSampler, refractionPos);
    refractedPixels.rgb = lerp(refractedPixels, backGroundPixels, saturate(refractedPixels.a * 255)).rgb;

    // Caustics on a shallow, sunlit bottom (the bottom point is taken below the surface along the wave normal).
    {
        const float3 toSun = (SunDirection.y < 0.0) ? -SunDirection : SunDirection;
        const float shallow = saturate(waterDepth / WaterHdCausticFull)
            * saturate((WaterHdCausticEnd - waterDepth) / (WaterHdCausticEnd - WaterHdCausticFull));
        const float2 bottom = worldPos.xz + N.xz * (2.0 + 20.0 * waterDepth);
        const float caustic = WaterHdCaustics(bottom, seconds);
        refractedPixels.rgb *= 1.0 + WaterHdCausticGain * caustic * shallow * waterTexture.r * saturate(toSun.y * 3.0);
    }

    // Colour by depth: FAF's tint, a channel the map's colour lacks going first, thinner near the camera.
    const float strongest = max(max(waterColor.r, waterColor.g), max(waterColor.b, 1e-3));
    const float3 share = saturate(waterColor / strongest);
    const float3 tint = clamp(waterDepth * (1.0 + WaterHdTintFaster * (1.0 - share)), waterLerp.x, waterLerp.y);
    const float distant = saturate((length(inV.mViewVec) - WaterHdClearNear) / (WaterHdClearFar - WaterHdClearNear));
    refractedPixels.rgb = lerp(refractedPixels.rgb, waterColor, tint * lerp(WaterHdClearTint, 1.0, distant));

    float4 unitReflections = tex2D(ReflectionSampler, refractionPos);

    float4 skyReflection = texCUBE(SkySampler, R);
    float3 reflections = lerp(skyReflection.rgb, unitReflections.rgb, saturate(unitReflections.a));

    float NDotV = saturate(dot(viewVector, N));
    float fresnel = FresnelSchlick(NDotV, 0.08);
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
    const float sunVisible = waterTexture.r * (1.0 - saturate(unitReflections.a * 4.0)) * step(0.0, L.y);
    float3 sunReflection = float3(0, 0, 0);
    if (NDotL > 0.0) {
        const float nDotV = abs(dot(N, viewVector)) + 0.001;
        const float F = FresnelSchlick(saturate(dot(H, viewVector)), 0.02);
        const float D = NormalDistribution(N, H, roughness);
        const float G = GeometrySmith(N, nDotV, L, roughness);
        sunReflection = (PI * D * G * F / (4.0 * nDotV * NDotL + 0.0001)) * NDotL * SunColor;
        sunReflection *= legacySun ? WaterHdLegacySunGain : WaterHdSunGain;
    }

    // Sparkles: in each cell a small facet whose tilt turns over time flashes when it mirrors the sun.
    const float sparkleDrawn = saturate(WaterHdSparkleCell / (footprint * 3.0) - 1.0);
    if (sparkleDrawn > 0.0 && L.y > 0.0) {
        const float2 q = worldPos.xz / WaterHdSparkleCell;
        const float2 cell = floor(q);
        const float2 inCell = q - cell;
        const float2 r0 = WaterHdHash22(cell);
        const float2 r1 = WaterHdHash22(cell + 17.31);
        const float2 centre = 0.2 + 0.6 * r0;
        const float spot = saturate(1.0 - length(inCell - centre) / 0.2);
        const float turn = r1.x * 6.2831853 + seconds * WaterHdSparkleSpin * (0.5 + r1.y);
        const float2 tilt = WaterHdSparkleSlope * sqrt(r1.y) * float2(cos(turn), sin(turn));
        const float2 facetGradient = gradient + tilt;
        const float3 facet = normalize(float3(-facetGradient.x, 1.0, -facetGradient.y));
        const float cosTolerance = cos(WaterHdSparkleTolerance);
        const float aligned = saturate((dot(facet, H) - cosTolerance) / (1.0 - cosTolerance));
        const float F = FresnelSchlick(saturate(dot(H, viewVector)), 0.02);
        sunReflection += SunColor * (WaterHdSparkleGain * F * 50.0 * aligned * aligned * spot * spot * sparkleDrawn);
    }

    water += sunReflection * sunVisible;

    // FAF's crest foam.
    water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);

    // Foam: a thin line along the waterline that runs up and back, a little irregular along the shore.
    {
        const float wobble = WaterHdValueNoise(worldPos.xz * 0.25);
        const float edge = WaterHdFoamDepth + WaterHdFoamSwash * sin(6.2831853 * (seconds * WaterHdFoamSpeed + wobble));
        const float foam = saturate(1.0 - abs(waterDepth - edge) / WaterHdFoamWidth)
            * (0.6 + 0.4 * WaterHdValueNoise(worldPos.xz * 1.1 + seconds * 0.15)) * (1 - waterTexture.a);
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
