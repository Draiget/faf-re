// A mesh terrain map in the view (FAF Studio's meshview.lua and EdMeshTerrain): the scenario's TerrainSystem = 'mesh'
// names the manifest (TerrainMesh), its patches are read (EdMeshData), drawn shaded by their normals with the batcher
// (with their edges in the Both mode), checked (EdMeshScan), and things placed stand on the mesh while it is shown.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdScenarioInfo.h"
#include "editor/tools/EdMeshScan.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    constexpr float kReach = 40.0f; // a bridge deck isn't the ground of a cell, scenery isn't either
    constexpr std::size_t kMaxDrawnTriangles = 1500000;
  } // namespace

  std::string EdMapScene::LoadMeshTerrain()
  {
    mMeshMap.Clear();
    mMeshTris.clear();
    mMeshEdges.clear();
    std::string system;
    std::string manifest;
    const std::string& scenario = mDocument.Scenario();
    if (!ReadScenarioField(scenario, "TerrainSystem", system) || system != "mesh") {
      return "This map isn't a mesh terrain map (its scenario has no TerrainSystem = 'mesh').";
    }
    if (!ReadScenarioField(scenario, "TerrainMesh", manifest) || manifest.empty()) {
      manifest = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
    }
    if (!mMeshMap.Load(manifest)) {
      gpg::Warnf("editor: mesh terrain: %s", mMeshMap.error.c_str());
      return "The mesh terrain didn't load: " + mMeshMap.error;
    }
    // The triangles shaded by their normals against a light from above, once; the edges for the Both mode.
    std::size_t drawn = 0;
    for (const edmesh::Patch& p : mMeshMap.patches) {
      if (p.sky) {
        continue;
      }
      const std::size_t n = std::min<std::size_t>(p.vertexCount, p.vertices.size() / 68);
      const auto at = [&p](const std::size_t i, const std::size_t offset, float (&out)[3]) {
        std::memcpy(out, p.vertices.data() + i * 68 + offset, 12);
      };
      for (std::size_t t = 0; t + 2 < p.indices.size() && drawn < kMaxDrawnTriangles; t += 3) {
        moho::CD3DPrimBatcher::Vertex v[3]{};
        bool ok = true;
        for (int k = 0; k < 3; ++k) {
          const std::size_t i = p.indices[t + static_cast<std::size_t>(k)];
          if (i >= n) {
            ok = false;
            break;
          }
          float pos[3];
          float nrm[3];
          at(i, 0, pos);
          at(i, 12, nrm);
          const float light = std::clamp(0.35f + 0.65f * (nrm[1] * 0.8f + nrm[0] * 0.35f + nrm[2] * 0.2f), 0.15f, 1.0f);
          const auto c = static_cast<std::uint32_t>(std::clamp(light * 200.0f, 0.0f, 255.0f));
          v[k].mX = pos[0];
          v[k].mY = pos[1];
          v[k].mZ = pos[2];
          v[k].mColor = 0xFF000000u | (c << 16) | (c << 8) | static_cast<std::uint32_t>(c * 0.9f);
        }
        if (!ok) {
          continue;
        }
        mMeshTris.insert(mMeshTris.end(), v, v + 3);
        for (int k = 0; k < 3; ++k) {
          moho::CD3DPrimBatcher::Vertex a = v[k];
          moho::CD3DPrimBatcher::Vertex b = v[(k + 1) % 3];
          a.mColor = b.mColor = 0x6040E0FFu;
          mMeshEdges.push_back(a);
          mMeshEdges.push_back(b);
        }
        ++drawn;
      }
    }
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Mesh terrain %s: %zu patches, %u triangles%s",
      manifest.c_str(),
      mMeshMap.patches.size(),
      mMeshMap.TotalTriangles(),
      drawn < mMeshMap.TotalTriangles() ? " (the view draws the first 1.5 million)" : ""
    );
    gpg::Logf("editor: %s", text);
    return text;
  }

  std::vector<std::string> EdMapScene::CheckMeshTerrain()
  {
    std::vector<std::string> lines;
    for (const MeshScanFinding& f : ScanMeshMap(mMeshMap).findings) {
      lines.push_back(std::string(1, f.severity) + " " + f.code + ": " + f.text);
    }
    return lines;
  }

  float EdMapScene::PlacementHeight(
    const float x,
    const float z
  ) const
  {
    const float field = mMap != nullptr
      ? mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
        )
      : 0.0f;
    if (mMeshMode != 0 && mMeshMap.Loaded()) {
      float y = 0.0f;
      if (mMeshMap.HeightAt(x, z, field + kReach, y)) {
        return y;
      }
    }
    return field;
  }

  void EdMapScene::DrawMeshTerrain(
    moho::CD3DPrimBatcher& batcher
  )
  {
    if (mMeshMode == 0 || mMeshTris.empty()) {
      return;
    }
    // In pieces (the batcher takes a bounded count at a time).
    constexpr std::size_t kChunk = 6000;
    for (std::size_t at = 0; at < mMeshTris.size(); at += kChunk * 3) {
      const std::size_t count = std::min(kChunk, (mMeshTris.size() - at) / 3);
      batcher.DrawTriangles(mMeshTris.data() + at, static_cast<std::uint32_t>(count));
    }
    if (mMeshMode == 2) {
      for (std::size_t i = 0; i + 1 < mMeshEdges.size(); i += 2) {
        batcher.DrawLine(mMeshEdges[i], mMeshEdges[i + 1]);
      }
    }
  }
} // namespace faf::editor
