#include "editor/doc/EdLooks.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    float Mix(
      const float a,
      const float b,
      const float t
    )
    {
      return a + (b - a) * t;
    }

    template <std::size_t N>
    void MixAll(
      float (&out)[N],
      const float (&a)[N],
      const float (&b)[N],
      const float t
    )
    {
      for (std::size_t i = 0; i < N; ++i) {
        out[i] = Mix(a[i], b[i], t);
      }
    }

    /** The file as a cursor: little-endian values, NUL-ended strings, every read checked. */
    class Cursor
    {
    public:
      explicit Cursor(
        const std::string& bytes
      )
        : mBytes(bytes)
      {}

      template <class T>
      bool Take(
        T& out
      )
      {
        if (mAt + sizeof(T) > mBytes.size()) {
          return false;
        }
        std::memcpy(&out, mBytes.data() + mAt, sizeof(T));
        mAt += sizeof(T);
        return true;
      }
      bool Skip(
        const std::uint64_t count
      )
      {
        if (count > mBytes.size() - mAt) {
          return false;
        }
        mAt += static_cast<std::size_t>(count);
        return true;
      }
      bool String(
        std::string& out
      )
      {
        const std::size_t end = mBytes.find('\0', mAt);
        if (end == std::string::npos) {
          return false;
        }
        out.assign(mBytes, mAt, end - mAt);
        mAt = end + 1;
        return true;
      }
      bool SkipString()
      {
        std::string scratch;
        return String(scratch);
      }
      /** A count: non-negative and not more than the file could hold. */
      bool Count(
        std::int32_t& out,
        const std::int32_t most
      )
      {
        return Take(out) && out >= 0 && out <= most;
      }
      /** A size-prefixed payload skipped. */
      bool SkipSized()
      {
        std::uint32_t size = 0;
        return Take(size) && Skip(size);
      }

    private:
      const std::string& mBytes;
      std::size_t mAt = 0;
    };
  } // namespace

  Look BlendLook(
    const Look& from,
    const Look& to,
    float amount,
    const unsigned sections
  )
  {
    amount = std::clamp(amount, 0.0f, 1.0f);
    const bool take = amount >= 0.5f;
    Look out = from;
    if ((sections & kLookLighting) != 0u) {
      LightingState& l = out.lighting;
      const LightingState& a = from.lighting;
      const LightingState& b = to.lighting;
      l.multiplier = Mix(a.multiplier, b.multiplier, amount);
      MixAll(l.sunDirection, a.sunDirection, b.sunDirection, amount);
      MixAll(l.sunAmbience, a.sunAmbience, b.sunAmbience, amount);
      MixAll(l.sunColor, a.sunColor, b.sunColor, amount);
      MixAll(l.shadowFill, a.shadowFill, b.shadowFill, amount);
      MixAll(l.specular, a.specular, b.specular, amount);
      l.bloom = Mix(a.bloom, b.bloom, amount);
      MixAll(l.fogColor, a.fogColor, b.fogColor, amount);
      l.fogStart = Mix(a.fogStart, b.fogStart, amount);
      l.fogEnd = Mix(a.fogEnd, b.fogEnd, amount);
    }
    if ((sections & kLookWater) != 0u) {
      WaterNumbers& w = out.water.shader;
      const WaterNumbers& a = from.water.shader;
      const WaterNumbers& b = to.water.shader;
      MixAll(w.mWaterColor, a.mWaterColor, b.mWaterColor, amount);
      MixAll(w.mWaterLerp, a.mWaterLerp, b.mWaterLerp, amount);
      w.mRefractionScale = Mix(a.mRefractionScale, b.mRefractionScale, amount);
      w.mFresnelBias = Mix(a.mFresnelBias, b.mFresnelBias, amount);
      w.mFresnelPower = Mix(a.mFresnelPower, b.mFresnelPower, amount);
      w.mUnitReflectionAmount = Mix(a.mUnitReflectionAmount, b.mUnitReflectionAmount, amount);
      w.mSkyReflectionAmount = Mix(a.mSkyReflectionAmount, b.mSkyReflectionAmount, amount);
      w.mSunShininess = Mix(a.mSunShininess, b.mSunShininess, amount);
      w.mSunStrength = Mix(a.mSunStrength, b.mSunStrength, amount);
      MixAll(w.mSunDirection, a.mSunDirection, b.mSunDirection, amount);
      MixAll(w.mSunColor, a.mSunColor, b.mSunColor, amount);
      w.mSunReflectionAmount = Mix(a.mSunReflectionAmount, b.mSunReflectionAmount, amount);
      w.mSunGlow = Mix(a.mSunGlow, b.mSunGlow, amount);
      if (take) {
        out.water.textures[0] = to.water.textures[0]; // the cubemap
        out.water.textures[1] = to.water.textures[1]; // the colour ramp
      }
    }
    if ((sections & kLookWaves) != 0u) {
      WaterNumbers& w = out.water.shader;
      const WaterNumbers& a = from.water.shader;
      const WaterNumbers& b = to.water.shader;
      MixAll(w.mNormalRepeatRate, a.mNormalRepeatRate, b.mNormalRepeatRate, amount);
      MixAll(w.mNormal1Movement, a.mNormal1Movement, b.mNormal1Movement, amount);
      MixAll(w.mNormal2Movement, a.mNormal2Movement, b.mNormal2Movement, amount);
      MixAll(w.mNormal3Movement, a.mNormal3Movement, b.mNormal3Movement, amount);
      MixAll(w.mNormal4Movement, a.mNormal4Movement, b.mNormal4Movement, amount);
      if (take) {
        for (int i = 2; i < 6; ++i) {
          out.water.textures[i] = to.water.textures[i];
        }
      }
    }
    if ((sections & kLookSky) != 0u && to.hasSky) {
      SkyboxState& s = out.sky;
      const SkyboxState& a = from.sky;
      const SkyboxState& b = to.sky;
      MixAll(s.position, a.position, b.position, amount);
      s.horizonHeight = Mix(a.horizonHeight, b.horizonHeight, amount);
      s.scale = Mix(a.scale, b.scale, amount);
      s.subtractHeight = Mix(a.subtractHeight, b.subtractHeight, amount);
      s.zenithHeight = Mix(a.zenithHeight, b.zenithHeight, amount);
      MixAll(s.horizonColor, a.horizonColor, b.horizonColor, amount);
      MixAll(s.zenithColor, a.zenithColor, b.zenithColor, amount);
      s.decalGlow = Mix(a.decalGlow, b.decalGlow, amount);
      s.cirrusMultiplier = Mix(a.cirrusMultiplier, b.cirrusMultiplier, amount);
      MixAll(s.cirrusColor, a.cirrusColor, b.cirrusColor, amount);
      for (int i = 0; i < 4; ++i) {
        MixAll(s.cirrus[i].frequency, a.cirrus[i].frequency, b.cirrus[i].frequency, amount);
        s.cirrus[i].speed = Mix(a.cirrus[i].speed, b.cirrus[i].speed, amount);
        MixAll(s.cirrus[i].direction, a.cirrus[i].direction, b.cirrus[i].direction, amount);
      }
      if (take) {
        s.subdivisionsAxis = b.subdivisionsAxis;
        s.subdivisionsHeight = b.subdivisionsHeight;
        s.albedo = b.albedo;
        s.glow = b.glow;
        s.planets = b.planets;
        s.cirrusTexture = b.cirrusTexture;
      }
      out.hasSky = from.hasSky || take;
    }
    if (take) {
      out.name = to.name;
      out.cubes = (sections & kLookSky) != 0u ? to.cubes : from.cubes;
    }
    return out;
  }

  bool LookFromScmap(
    const std::string& bytes,
    Look& look,
    std::string& error
  )
  {
    Cursor in(bytes);
    const auto fail = [&](const char* const what) {
      error = what;
      return false;
    };
    if (bytes.compare(0, 4, "Map\x1a") != 0) {
      return fail("not a .scmap (no Map header)");
    }
    // Magic, major version, two words, width and height as floats, a float, a short; then the preview.
    std::int32_t previewBytes = 0, version = 0, width = 0, height = 0;
    float heightScale = 0.0f;
    if (
      !in.Skip(4 + 4 + 4 + 4 + 4 + 4 + 4 + 2) || !in.Take(previewBytes) || previewBytes < 0 ||
      !in.Skip(static_cast<std::uint32_t>(previewBytes)) || !in.Take(version) || !in.Take(width) || !in.Take(height) ||
      !in.Take(heightScale) || width <= 0 || height <= 0 || width > 8192 || height > 8192
    ) {
      return fail("the .scmap's header can't be read");
    }
    if (version <= 0) {
      version = 56;
    }
    const auto v = static_cast<std::uint32_t>(version);
    if (!in.Skip(static_cast<std::uint64_t>(width + 1) * static_cast<std::uint64_t>(height + 1) * 2u)) {
      return fail("the .scmap ends in its heights");
    }
    std::uint8_t shaderByte = 0;
    if (v >= 0x36u && !in.Take(shaderByte)) {
      return fail("the .scmap ends early");
    }
    Look read;
    std::string scratch;
    std::string skycube;
    if (!in.String(scratch) || !in.String(scratch) || !in.String(skycube)) {
      return fail("the .scmap ends early");
    }
    // Environment lookups: one name below 0x37, else name pairs (CWldTerrainRes::LoadEnvironmentLookups).
    if (v < 0x37u) {
      if (!in.SkipString()) {
        return fail("the .scmap ends early");
      }
    } else {
      std::int32_t count = 0;
      if (!in.Count(count, 1024)) {
        return fail("the .scmap's environment cubes can't be read");
      }
      for (std::int32_t i = 0; i < count; ++i) {
        std::string name, cube;
        if (!in.String(name) || !in.String(cube)) {
          return fail("the .scmap ends early");
        }
        read.cubes.emplace_back(std::move(name), std::move(cube));
      }
    }
    // Lighting and fog: 23 floats (CWldTerrainRes::LoadLightingAndFog), as LightingFromScmap reads them.
    float l[23];
    for (float& value : l) {
      if (!in.Take(value)) {
        return fail("the .scmap ends in its lighting");
      }
    }
    LightingState& lighting = read.lighting;
    lighting.multiplier = l[0];
    std::memcpy(lighting.sunDirection, l + 1, sizeof(lighting.sunDirection));
    std::memcpy(lighting.sunAmbience, l + 4, sizeof(lighting.sunAmbience));
    std::memcpy(lighting.sunColor, l + 7, sizeof(lighting.sunColor));
    std::memcpy(lighting.shadowFill, l + 10, sizeof(lighting.shadowFill));
    std::memcpy(lighting.specular, l + 13, sizeof(lighting.specular));
    lighting.bloom = l[17];
    std::memcpy(lighting.fogColor, l + 18, sizeof(lighting.fogColor));
    lighting.fogStart = l[21];
    lighting.fogEnd = l[22];
    // Water: on, its three levels, then CWaterShaderProperties::Load's 20 floats, two paths, 4 floats, 4 waves.
    std::uint8_t waterOn = 0;
    WaterState& water = read.water;
    if (!in.Take(waterOn) || !in.Take(water.elevation) || !in.Take(water.deep) || !in.Take(water.abyss)) {
      return fail("the .scmap ends in its water");
    }
    water.enabled = waterOn != 0;
    WaterNumbers& w = water.shader;
    float* const header[20] = {
      &w.mWaterColor[0],   &w.mWaterColor[1], &w.mWaterColor[2],   &w.mWaterLerp[0],         &w.mWaterLerp[1],
      &w.mRefractionScale, &w.mFresnelBias,   &w.mFresnelPower,    &w.mUnitReflectionAmount, &w.mSkyReflectionAmount,
      &w.mSunShininess,    &w.mSunStrength,   &w.mSunDirection[0], &w.mSunDirection[1],      &w.mSunDirection[2],
      &w.mSunColor[0],     &w.mSunColor[1],   &w.mSunColor[2],     &w.mSunReflectionAmount,  &w.mSunGlow,
    };
    for (float* const value : header) {
      if (!in.Take(*value)) {
        return fail("the .scmap ends in its water");
      }
    }
    if (!in.String(water.textures[0]) || !in.String(water.textures[1])) {
      return fail("the .scmap ends in its water");
    }
    for (float& repeat : w.mNormalRepeatRate) {
      if (!in.Take(repeat)) {
        return fail("the .scmap ends in its water");
      }
    }
    float* const movement[4] = {w.mNormal1Movement, w.mNormal2Movement, w.mNormal3Movement, w.mNormal4Movement};
    for (int i = 0; i < 4; ++i) {
      if (!in.Take(movement[i][0]) || !in.Take(movement[i][1]) || !in.String(water.textures[2 + i])) {
        return fail("the .scmap ends in its water");
      }
    }
    // Past the rest, to the sky; a file that can't be followed keeps what was read, without a sky.
    look = read;
    look.hasSky = false;
    const auto noSky = [&]() {
      return true;
    };
    // Wave generators (WaveSystem::Load): two paths, 13 floats, 4 more after format 51.
    std::int32_t generators = 0;
    if (!in.Count(generators, 1 << 20)) {
      return noSky();
    }
    for (std::int32_t i = 0; i < generators; ++i) {
      if (!in.SkipString() || !in.SkipString() || !in.Skip(13u * 4u + (v > 51u ? 16u : 0u))) {
        return noSky();
      }
    }
    // The topographic palette (from 0x38) and the imager offset (from 0x39).
    if ((v >= 0x38u && !in.Skip(24u)) || (v >= 0x39u && !in.Skip(4u))) {
      return noSky();
    }
    // Texturing (CWldTerrainRes::LoadTexturing): the strata, then the decals and their groups.
    if (v < 54u) {
      if (!in.SkipString() || !in.Skip(4u)) {
        return noSky();
      }
      for (int pair = 0; pair < 5; ++pair) {
        if (!in.SkipString() || !in.SkipString() || !in.Skip(8u)) {
          return noSky();
        }
      }
      if (!in.SkipString() || !in.SkipString() || !in.Skip(8u)) {
        return noSky();
      }
    } else {
      for (int layer = 0; layer < 19; ++layer) {
        if (!in.SkipString() || !in.Skip(4u)) {
          return noSky();
        }
      }
    }
    std::int32_t decals = 0;
    if (!in.Skip(8u) || !in.Count(decals, 1 << 22)) {
      return noSky();
    }
    for (std::int32_t i = 0; i < decals; ++i) {
      std::int32_t names = 0;
      if (!in.Skip(8u) || !in.Count(names, 16)) {
        return noSky();
      }
      for (std::int32_t n = 0; n < names; ++n) {
        std::int32_t length = 0;
        if (!in.Count(length, 1 << 16) || !in.Skip(static_cast<std::uint32_t>(length))) {
          return noSky();
        }
      }
      if (!in.Skip(11u * 4u + 4u)) {
        return noSky();
      }
    }
    std::int32_t groups = 0;
    if (!in.Count(groups, 1 << 20)) {
      return noSky();
    }
    for (std::int32_t i = 0; i < groups; ++i) {
      std::int32_t members = 0;
      if (
        !in.Skip(4u) || !in.SkipString() || !in.Count(members, 1 << 22) ||
        !in.Skip(4u * static_cast<std::uint32_t>(members))
      ) {
        return noSky();
      }
    }
    // The legacy record list: two dwords and a count of sized records.
    std::int32_t records = 0;
    if (!in.Skip(8u) || !in.Count(records, 1 << 20)) {
      return noSky();
    }
    for (std::int32_t i = 0; i < records; ++i) {
      if (!in.SkipSized()) {
        return noSky();
      }
    }
    // Stratum masks: two sheets from 0x36, else a count.
    if (v >= 0x36u) {
      if (!in.SkipSized() || !in.SkipSized()) {
        return noSky();
      }
    } else {
      std::int32_t masks = 0;
      if (!in.Count(masks, 64)) {
        return noSky();
      }
      for (std::int32_t i = 0; i < masks; ++i) {
        if (!in.SkipSized()) {
          return noSky();
        }
      }
    }
    std::int32_t waterMaps = 0;
    if (!in.Count(waterMaps, 64)) {
      return noSky();
    }
    for (std::int32_t i = 0; i < waterMaps; ++i) {
      if (!in.SkipSized()) {
        return noSky();
      }
    }
    // Foam, flatness and depth bias at half size, then the terrain types a byte a cell.
    const std::uint64_t half = static_cast<std::uint64_t>(width >> 1) * static_cast<std::uint64_t>(height >> 1);
    if (!in.Skip(3u * half) || !in.Skip(static_cast<std::uint64_t>(width) * static_cast<std::uint64_t>(height))) {
      return noSky();
    }
    if (v < 0x35u && (!in.SkipString() || !in.SkipString())) {
      return noSky();
    }
    if (v < 0x3Au) {
      return noSky();
    }
    // The sky (SkyDome::Load), in SkyboxNow's names.
    SkyboxState sky;
    std::int32_t planets = 0;
    std::int32_t discarded = 0;
    if (
      !in.Take(sky.position) || !in.Take(sky.horizonHeight) || !in.Take(sky.scale) || !in.Take(sky.subtractHeight) ||
      !in.Take(sky.subdivisionsAxis) || !in.Take(sky.subdivisionsHeight) || !in.Take(sky.zenithHeight) ||
      !in.Take(sky.horizonColor) || !in.Take(sky.zenithColor) || !in.Take(sky.decalGlow) || !in.String(sky.albedo) ||
      !in.String(sky.glow) || !in.Count(planets, 4096)
    ) {
      return noSky();
    }
    for (std::int32_t i = 0; i < planets; ++i) {
      SkyboxPlanet planet;
      if (!in.Take(planet)) {
        return noSky();
      }
      sky.planets.push_back(planet);
    }
    if (
      !in.SkipString() || !in.SkipString() || !in.SkipString() || !in.Take(sky.cirrusMultiplier) ||
      !in.Take(sky.cirrusColor) || !in.String(sky.cirrusTexture) || !in.Take(discarded) || !in.Take(sky.cirrus)
    ) {
      return noSky();
    }
    // A sky that reads as nonsense (the walk lost its place) isn't kept.
    if (
      sky.subdivisionsAxis < 3 || sky.subdivisionsAxis > 256 || sky.subdivisionsHeight < 1 ||
      sky.subdivisionsHeight > 256
    ) {
      return noSky();
    }
    look.sky = std::move(sky);
    look.hasSky = true;
    return true;
  }
} // namespace faf::editor
