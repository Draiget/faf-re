#pragma once

#include "editor/doc/EdLighting.h"
#include "editor/doc/EdSkybox.h"
#include "editor/doc/EdWater.h"

#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * A look (the consolidated design's Environment > Looks, after FAF Studio's library): a map's lighting, water and
   * sky, taken from another map or saved by the user, tried on the map without an undo step, then applied as one or
   * reverted.
   */
  struct Look
  {
    std::string name;
    LightingState lighting;
    WaterState water;
    SkyboxState sky;
    bool hasSky = false; // maps before format 0x3A keep no sky
    /** The environment cube lookups (name, cube texture), as the map lists them. */
    std::vector<std::pair<std::string, std::string>> cubes;
  };

  /** What of a look is put on the map. */
  enum LookSection : unsigned
  {
    kLookLighting = 1u, // sun, ambience, shadow, specular, bloom, fog
    kLookWater = 2u,    // the water's colours, reflections, sun and textures (not its levels)
    kLookWaves = 4u,    // the water's four normal maps: repeat, movement, textures
    kLookSky = 8u,      // the dome, its colours, planets and cirrus
    kLookAll = 15u,
  };

  /**
   * `from` with `to`'s chosen sections mixed in by `amount` (0 keeps `from`, 1 is `to`): numbers in between, names and
   * counts (textures, planets, segments) switching at one half. Water levels and on/off stay `from`'s.
   */
  [[nodiscard]] Look BlendLook(const Look& from, const Look& to, float amount, unsigned sections);

  /**
   * A map's look from its `.scmap` bytes, read as CWldTerrainRes::Load and the headless loader walk the file: the
   * environment lookups, lighting, water (CWaterShaderProperties::Load 0x008A03C0), and past the waves, texturing,
   * masks and terrain types, the sky (SkyDome::Load 0x00815FA0, from version 0x3A). False with `error` for a file it
   * can't follow; a file that ends before the sky gives the rest with `hasSky` false.
   */
  bool LookFromScmap(const std::string& bytes, Look& look, std::string& error);
} // namespace faf::editor
