#pragma once

#include <cstring>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A planet (a sky decal) as the `.scmap` keeps it: SkyDome's 0x28-byte upload record, ten floats. */
  struct SkyboxPlanet
  {
    float position[3] = {0.0f, 0.0f, 0.0f};
    float rotation = 0.0f;
    float scale[2] = {1.0f, 1.0f};
    float uv[4] = {0.0f, 0.0f, 1.0f, 1.0f};
  };
  static_assert(sizeof(SkyboxPlanet) == 0x28, "a planet is SkyDome's 0x28-byte upload record");

  /** A cirrus layer: one of SkyDome's four 20-byte records (SkyDome::Load 0x00815FA0 reads exactly four). */
  struct SkyboxCirrusLayer
  {
    float frequency[2] = {0.0f, 0.0f};
    float speed = 0.0f;
    float direction[2] = {0.0f, 0.0f};
  };
  static_assert(sizeof(SkyboxCirrusLayer) == 20, "a cirrus layer is a 20-byte record");

  /**
   * The map's sky as the `.scmap` keeps it (SkyDome, read at map version 0x3A and up, derived from the map's size
   * below), in FAForeverMapEditor's names: the dome, horizon and zenith, the planets and their textures, the cirrus.
   */
  struct SkyboxState
  {
    float position[3] = {256.0f, 0.0f, 256.0f};
    float horizonHeight = 0.0f;
    float scale = 2343.0f;
    float subtractHeight = 1.256637f;
    int subdivisionsAxis = 16;
    int subdivisionsHeight = 6;
    float zenithHeight = 174.5082f;
    float horizonColor[3] = {0.0f, 0.0f, 0.0f};
    float zenithColor[3] = {0.0f, 0.0f, 0.0f};
    float decalGlow = 0.1f;
    std::string albedo;
    std::string glow;
    std::vector<SkyboxPlanet> planets;
    float cirrusMultiplier = 1.8f;
    float cirrusColor[3] = {1.0f, 1.0f, 1.0f};
    std::string cirrusTexture;
    SkyboxCirrusLayer cirrus[4];
    /**
     * The reflections' cube map and the picture behind the dome (the `.scmap`'s header, CWldTerrainRes::SetSkycube /
     * SetBackground); not in a `.scmskybox`. Empty when applied: the map's own stay.
     */
    std::string skycube;
    std::string background;

    bool operator==(const SkyboxState& other) const;
  };

  /**
   * FAForeverMapEditor's sky file (`.scmskybox`, JsonUtility's dump of its SkyboxData). Its MidRgbColor (the three
   * cumulus texture names, empty in every map FAFME reads) and Clouds7 (a float the game's reader doesn't have) are
   * written as zero and not read.
   */
  std::string SkyboxToScmskybox(const SkyboxState& sky);
  /**
   * A sky made for another map fitted to this one (FAF Studio's import): the dome centred on this map, its radius and
   * the planets' distance from the centre and size scaled by the ratio of the maps' sizes (the other map's taken as
   * twice its dome's centre), the dome's heights kept. Returns the ratio (1: nothing to do).
   */
  float RescaleSkybox(SkyboxState& sky, float mapWidth, float mapDepth);
  bool SkyboxFromScmskybox(const std::string& text, SkyboxState& sky, std::string& error);
} // namespace faf::editor
