#pragma once

#include <string>
#include <vector>

#include "editor/tools/EdDecalShape.h"

namespace moho
{
  class CWldTerrainDecal;
  class IDecalManager;
} // namespace moho

namespace faf::editor
{
  /** One decal's saved fields (what CWldTerrainDecal::DecalSave writes), for undo and for placing new ones. */
  struct DecalState
  {
    /** The decal's index in the map (-1 for a new decal: the manager gives it the next one). */
    int index = -1;
    /** EWldTerrainDecalType's number. */
    int type = 1;
    std::string names[2];
    float scale[3] = {1.0f, 1.0f, 1.0f};
    float position[3] = {0.0f, 0.0f, 0.0f};
    float orientation[3] = {0.0f, 0.0f, 0.0f};
    /** The far cutoff distance (0 or less: the decal works one out from its size, as the game does). */
    float cutoff = 0.0f;
    float nearCutoff = 0.0f;

    bool operator==(const DecalState& other) const;
  };

  DecalState CaptureDecal(const moho::CWldTerrainDecal& decal);
  /** Every decal of the map, in the manager's order. */
  std::vector<DecalState> CaptureDecals(moho::IDecalManager& manager);

  /**
   * Makes the manager's decals the snapshot's: a decal in both gets the snapshot's fields where they differ, one
   * missing is made again with its index, and one the snapshot doesn't have is destroyed.
   */
  void RestoreDecals(moho::IDecalManager& manager, const std::vector<DecalState>& decals);

  /** A new decal on the map with these fields (a fresh index); returns it. */
  moho::CWldTerrainDecal* AddDecal(moho::IDecalManager& manager, const DecalState& state);

  /** The decal with this index, or null. */
  moho::CWldTerrainDecal* FindDecal(moho::IDecalManager& manager, int index);

  /** A decal's footprint (its corner, size and heading). */
  DecalFootprint FootprintOf(const moho::CWldTerrainDecal& decal);

  /** A texture the decal browser offers. */
  struct DecalTexture
  {
    std::string path;
    /** The folder after /env/ ("Evergreen", "common"). */
    std::string biome;
    /** The file name without `.dds`. */
    std::string name;
    /** The type it is placed as (DecalTypeForTexture). */
    int type = 1;
    /**
     * An albedo texture's spec map when the data has one (`_albedo` to `_spec`): the game's maps put it in the same
     * decal's second name (SCMP_009: 284 of its 1,233 albedo decals; its 1,003 normal-map decals have none).
     */
    std::string pair;
  };

  /** Every `.dds` under a `decals` folder of /env the file system can see, by biome, then name. */
  std::vector<DecalTexture> ListDecalTextures();
} // namespace faf::editor
