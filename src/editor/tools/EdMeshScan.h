#pragma once

// The checks of a mesh terrain map that need its patches' vertices (FAF Studio's meshscan.lua, MESH_MAP_EDITOR_NEEDS.md
// section 3): normals, tangents and binormals of unit length, the tangent frame square, no NaN or infinity, no
// degenerate triangles (V3); the light mask coordinates (UV2) inside 0..1 for materials with light masks (V4); the
// mesh covering the playable rectangle (V10, vertical rays on a grid of at most `cells` along the longer side); the
// highest vertex in the playable rectangle plus a 32 unit margin (V15, what the manifest's mesh_high should say).
// Engine independent (tests/editor/MeshScanTests.cpp).

#include "editor/tools/EdMeshData.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  struct MeshScanFinding
  {
    char severity = 'W'; // E, W, I
    std::string code;    // V3, V4, V10, V15
    std::string text;
  };
  struct MeshScanResult
  {
    std::vector<MeshScanFinding> findings;
    float meshHigh = -10000.0f;
    float coverage = -1.0f; // percent of the playable rectangle the mesh covers (-1: not measured)
  };
  [[nodiscard]] MeshScanResult ScanMeshMap(const edmesh::MeshMap& map, bool coverage = true, int cells = 160);

  /** What the manifest checks compare it with: the open map, its scenario, and the files beside the manifest. */
  struct MeshManifestFacts
  {
    int mapSize = 0; // the height field's side (0: no map)
    bool havePlayable = false;
    float playable[4] = {0, 0, 0, 0}; // the map's playable area (AREA_1): x0 z0 x1 z1
    bool water = false;
    float waterLevel = 0.0f;
    float groundHighest = -1.0e9f; // the height field's highest point
    bool haveScenario = false;
    std::string terrainSystem; // the scenario's TerrainSystem
    std::string terrainMesh;   // the scenario's TerrainMesh
    std::string expectedMesh;  // /maps/<folder>/terrain/terrain.lua
    /** A file's bytes by its path in the game's files (empty: missing). */
    std::function<std::vector<std::uint8_t>(const std::string&)> read;
  };
  /**
   * FAF Studio's manifest checks (meshmap.lua Check): V18 lines not understood, V19 the scenario names the manifest,
   * V11 size, V9 the playable rectangle, V12 water, V15 the heights' order, V14 the ground over 250, V2 patches and
   * materials, V1 the patches' SCM files, V5 textures and water files there, V13 the water triangle files' sizes, V20
   * the totals.
   */
  [[nodiscard]] std::vector<MeshScanFinding>
  CheckMeshManifest(const edmesh::MeshMap& map, const MeshManifestFacts& facts);
} // namespace faf::editor
