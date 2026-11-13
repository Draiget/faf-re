#pragma once

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

namespace faf::editor
{
  /**
   * The map's lighting as the `.scmap` keeps it and the terrain resource gives it (Get/SetLightingMultiplier,
   * SunDirection, SunAmbience, SunColor, ShadowFillColor, SpecularColor, Bloom, FogInfo). The fog is
   * FAForeverMapEditor's colour, start and end: SFogInfo's first five floats as WRenViewport::FogOn reads them (the
   * colour packed from the first three, the start from the fourth, the end from the fifth), whatever their recovered
   * names say.
   */
  /**
   * The sun's direction as the Lighting panel shows it (the mockup's): its azimuth, the angle round the vertical from
   * +x towards +z, and its elevation above the horizon, both in degrees. The direction is the unit vector to the sun
   * (y up); a zero vector reads as straight up.
   */
  inline void SunAnglesOf(
    const float (&direction)[3],
    float& azimuthDegrees,
    float& elevationDegrees
  )
  {
    const double x = direction[0];
    const double y = direction[1];
    const double z = direction[2];
    const double length = std::sqrt(x * x + y * y + z * z);
    if (length <= 0.0) {
      azimuthDegrees = 0.0f;
      elevationDegrees = 90.0f;
      return;
    }
    azimuthDegrees = static_cast<float>(std::atan2(z, x) * 57.29577951308232);
    elevationDegrees = static_cast<float>(std::asin(std::clamp(y / length, -1.0, 1.0)) * 57.29577951308232);
  }

  /** The unit direction for an azimuth and an elevation in degrees (SunAnglesOf's inverse). */
  inline void SunDirectionOf(
    const float azimuthDegrees,
    const float elevationDegrees,
    float (&direction)[3]
  )
  {
    const double az = static_cast<double>(azimuthDegrees) / 57.29577951308232;
    const double el = static_cast<double>(elevationDegrees) / 57.29577951308232;
    direction[0] = static_cast<float>(std::cos(el) * std::cos(az));
    direction[1] = static_cast<float>(std::sin(el));
    direction[2] = static_cast<float>(std::cos(el) * std::sin(az));
  }

  struct LightingState
  {
    float multiplier = 1.0f;
    float sunDirection[3] = {0.0f, 1.0f, 0.0f};
    float sunAmbience[3] = {0.0f, 0.0f, 0.0f};
    float sunColor[3] = {1.0f, 1.0f, 1.0f};
    float shadowFill[3] = {0.0f, 0.0f, 0.0f};
    float specular[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    float bloom = 0.0f;
    float fogColor[3] = {1.0f, 1.0f, 1.0f};
    float fogStart = 0.0f;
    float fogEnd = 1000.0f;

    bool operator==(
      const LightingState& other
    ) const
    {
      return std::memcmp(this, &other, sizeof(*this)) == 0;
    }
  };

  /** FAForeverMapEditor's lighting settings file (`.scmlighting`): JsonUtility's dump of its LightingData. */
  std::string LightingToScmlighting(const LightingState& lighting);
  /** Reads a `.scmlighting` into `lighting` (every field it has); false with `error`. */
  bool LightingFromScmlighting(const std::string& text, LightingState& lighting, std::string& error);

  /**
   * A map's lighting from its `.scmap` bytes: the header, preview and height field skipped, then the shader,
   * background, sky cubemap and environment cubemaps (one name below version 0x37, else a count of name pairs, as
   * CWldTerrainRes::LoadEnvironmentLookups reads them), then CWldTerrainRes::LoadLightingAndFog's 23 floats. False with
   * `error` for a file it can't follow.
   */
  bool LightingFromScmap(const std::string& bytes, LightingState& lighting, std::string& error);
} // namespace faf::editor
