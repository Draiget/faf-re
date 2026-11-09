#pragma once

#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * A decal's footprint as the game keeps it (CWldTerrainDecal): (x, z) is a corner, not the middle; the decal
   * runs `sizeX` along its heading `yaw` (radians, its orientation's y) and `sizeZ` across it.
   */
  struct DecalFootprint
  {
    float x = 0.0f;
    float z = 0.0f;
    float sizeX = 1.0f;
    float sizeZ = 1.0f;
    float yaw = 0.0f;
  };

  /** The footprint of a decal of this size and heading centred on (cx, cz). */
  DecalFootprint DecalAround(float cx, float cz, float sizeX, float sizeZ, float yaw);

  /** Its middle. */
  void DecalCentre(const DecalFootprint& decal, float& cx, float& cz);

  /** Its four corners in order, as CWldTerrainDecal::ComputeCorner (0x0089D9C0) gives (0,0), (1,0), (1,1), (0,1). */
  void DecalCorners(const DecalFootprint& decal, float (&x)[4], float (&z)[4]);

  /** Whether (x, z) is on it: the exact inverse of the corners above. */
  bool DecalContains(const DecalFootprint& decal, float x, float z);

  /**
   * The decal type a texture is placed as, from its file name, in EWldTerrainDecalType's numbers: a normal map
   * (`..._normals.dds`, `..._normal.dds`) as Normals (2), a glow map as Glow (6), anything else as Albedo (1).
   */
  int DecalTypeForTexture(const std::string& path);

  /**
   * A point on the uniform Catmull-Rom curve through `points` (the ends repeated), at `t` from 0 (the first point) to
   * points.size() - 1 (the last). The curve passes through every point.
   */
  std::pair<float, float> PathPoint(const std::vector<std::pair<float, float>>& points, float t);

  /**
   * Decals laid end to end along the curve through `points`: each `length` long along the curve and `width` across,
   * turned along it, the next starting `length * (1 - overlap)` further on, until the curve ends (the last one may
   * pass its end). Empty for fewer than two points.
   */
  std::vector<DecalFootprint> DecalsAlongPath(const std::vector<std::pair<float, float>>& points, float length, float width,
                                              float overlap);

  /** A short name for a decal type number ("albedo", "normals"...). */
  const char* DecalTypeName(int type);
} // namespace faf::editor
