#pragma once

// The checks of a mesh terrain map that need its patches' vertices (FAF Studio's meshscan.lua, MESH_MAP_EDITOR_NEEDS.md
// section 3): normals, tangents and binormals of unit length, the tangent frame square, no NaN or infinity, no
// degenerate triangles (V3); the light mask coordinates (UV2) inside 0..1 for materials with light masks (V4); the
// mesh covering the playable rectangle (V10, vertical rays on a grid of at most `cells` along the longer side); the
// highest vertex in the playable rectangle plus a 32 unit margin (V15, what the manifest's mesh_high should say).
// Engine independent (tests/editor/MeshScanTests.cpp).

#include "editor/tools/EdMeshData.h"

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
} // namespace faf::editor
