#include "editor/tools/EdMeshScan.h"

#include "editor/tools/EdMeshImport.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    constexpr float kMargin = kMeshHighMargin;
    constexpr std::size_t kStride = 68;

    bool Finite(
      const float v
    )
    {
      return std::isfinite(v) && v > -1e30f && v < 1e30f;
    }

    void Read(
      const std::vector<std::uint8_t>& bytes,
      const std::size_t vertex,
      const std::size_t offset,
      float* out,
      const int n
    )
    {
      std::memcpy(out, bytes.data() + vertex * kStride + offset, static_cast<std::size_t>(n) * 4);
    }

    float Length(
      const float* v
    )
    {
      return std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    }
  } // namespace

  MeshScanResult ScanMeshMap(
    const edmesh::MeshMap& map,
    const bool coverage,
    const int cells
  )
  {
    MeshScanResult r;
    const auto add = [&r](const char sev, const char* code, std::string text) {
      r.findings.push_back({sev, code, std::move(text)});
    };
    if (!map.Loaded()) {
      add(
        'E', "V0", "no mesh is loaded: " + (map.error.empty() ? std::string("the map names no manifest") : map.error)
      );
      return r;
    }
    const edmesh::Settings& s = map.settings;
    float px0 = s.playable[0], pz0 = s.playable[1], px1 = s.playable[2], pz1 = s.playable[3];
    if (px1 <= px0 || pz1 <= pz0) {
      px0 = 0.0f;
      pz0 = 0.0f;
      px1 = s.size;
      pz1 = s.size;
    }
    for (std::size_t pi = 0; pi < map.patches.size(); ++pi) {
      const edmesh::Patch& p = map.patches[pi];
      if (p.sky) {
        continue;
      }
      std::size_t badNumbers = 0, badLength = 0, badFrame = 0, badUv2 = 0, degenerate = 0;
      const bool lightMasks = p.material >= 0 && static_cast<std::size_t>(p.material) < map.materials.size() &&
        (!map.materials[static_cast<std::size_t>(p.material)].files[2].empty() ||
         !map.materials[static_cast<std::size_t>(p.material)].files[3].empty());
      const std::size_t n = std::min<std::size_t>(p.vertexCount, p.vertices.size() / kStride);
      for (std::size_t v = 0; v < n; ++v) {
        float pos[3], nrm[3], tan[3], bin[3], uv2[2];
        Read(p.vertices, v, 0, pos, 3);
        Read(p.vertices, v, 12, nrm, 3);
        Read(p.vertices, v, 24, tan, 3);
        Read(p.vertices, v, 36, bin, 3);
        Read(p.vertices, v, 56, uv2, 2);
        bool finite = true;
        for (const float* a : {pos, nrm, tan, bin}) {
          for (int k = 0; k < 3; ++k) {
            finite = finite && Finite(a[k]);
          }
        }
        if (!finite) {
          ++badNumbers;
          continue;
        }
        if (
          std::abs(Length(nrm) - 1.0f) > 0.02f || std::abs(Length(tan) - 1.0f) > 0.02f ||
          std::abs(Length(bin) - 1.0f) > 0.02f
        ) {
          ++badLength;
        }
        const float dnt = nrm[0] * tan[0] + nrm[1] * tan[1] + nrm[2] * tan[2];
        const float dnb = nrm[0] * bin[0] + nrm[1] * bin[1] + nrm[2] * bin[2];
        if (std::abs(dnt) > 0.05f || std::abs(dnb) > 0.05f) {
          ++badFrame;
        }
        if (lightMasks && (uv2[0] < -0.001f || uv2[0] > 1.001f || uv2[1] < -0.001f || uv2[1] > 1.001f)) {
          ++badUv2;
        }
        if (pos[0] >= px0 - kMargin && pos[0] <= px1 + kMargin && pos[2] >= pz0 - kMargin && pos[2] <= pz1 + kMargin) {
          r.meshHigh = std::max(r.meshHigh, pos[1]);
        }
      }
      for (std::size_t t = 0; t + 2 < p.indices.size(); t += 3) {
        float a[3], b[3], c[3];
        if (p.indices[t] >= n || p.indices[t + 1] >= n || p.indices[t + 2] >= n) {
          ++degenerate;
          continue;
        }
        Read(p.vertices, p.indices[t], 0, a, 3);
        Read(p.vertices, p.indices[t + 1], 0, b, 3);
        Read(p.vertices, p.indices[t + 2], 0, c, 3);
        const float e1[3] = {b[0] - a[0], b[1] - a[1], b[2] - a[2]};
        const float e2[3] = {c[0] - a[0], c[1] - a[1], c[2] - a[2]};
        const float cr[3] = {
          e1[1] * e2[2] - e1[2] * e2[1], e1[2] * e2[0] - e1[0] * e2[2], e1[0] * e2[1] - e1[1] * e2[0]
        };
        if (Length(cr) < 1e-8f) {
          ++degenerate;
        }
      }
      char text[240];
      if (badNumbers > 0) {
        (void)std::snprintf(text, sizeof(text), "%s: %zu vertices hold NaN or infinity", p.file.c_str(), badNumbers);
        add('E', "V3", text);
      }
      if (badLength > 0) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "%s: %zu vertices have a normal, tangent or binormal not of unit length",
          p.file.c_str(),
          badLength
        );
        add('W', "V3", text);
      }
      if (badFrame > 0) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "%s: %zu vertices have a tangent frame that isn't square to the normal",
          p.file.c_str(),
          badFrame
        );
        add('W', "V3", text);
      }
      if (degenerate > 0) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "%s: %zu degenerate triangles (no area, or a corner past the vertices)",
          p.file.c_str(),
          degenerate
        );
        add('W', "V3", text);
      }
      if (badUv2 > 0) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "%s: %zu vertices have light mask coordinates (UV2) outside 0..1 (clamped)",
          p.file.c_str(),
          badUv2
        );
        add('W', "V4", text);
      }
    }
    if (r.meshHigh > -9999.0f) {
      r.meshHigh += kMargin;
      char text[200];
      if (s.meshHigh > -9999.0f && std::abs(s.meshHigh - r.meshHigh) > 1.0f) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "the manifest's mesh_high is %.1f; the highest vertex plus the margin is %.1f",
          static_cast<double>(s.meshHigh),
          static_cast<double>(r.meshHigh)
        );
        add('W', "V15", text);
      } else {
        (void)std::snprintf(
          text,
          sizeof(text),
          "mesh_high %.1f (the highest vertex in the playable area plus %.0f)",
          static_cast<double>(r.meshHigh),
          static_cast<double>(kMargin)
        );
        add('I', "V15", text);
      }
    }
    if (coverage) {
      const float w = px1 - px0;
      const float h = pz1 - pz0;
      const float step = std::max(w, h) / static_cast<float>(std::max(8, cells));
      int hit = 0;
      int total = 0;
      for (float z = pz0 + step * 0.5f; z < pz1; z += step) {
        for (float x = px0 + step * 0.5f; x < px1; x += step) {
          ++total;
          float y = 0.0f;
          hit += map.HeightAt(x, z, 1e9f, y) ? 1 : 0;
        }
      }
      r.coverage = total > 0 ? 100.0f * static_cast<float>(hit) / static_cast<float>(total) : 0.0f;
      char text[160];
      (void)std::snprintf(
        text, sizeof(text), "the mesh covers %.1f%% of the playable rectangle", static_cast<double>(r.coverage)
      );
      add(r.coverage < 99.5f ? 'W' : 'I', "V10", text);
    }
    char text[160];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%zu patches, %u vertices, %u triangles",
      map.patches.size(),
      map.TotalVertices(),
      map.TotalTriangles()
    );
    add('I', "V0", text);
    return r;
  }
} // namespace faf::editor
