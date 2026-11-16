#include "editor/tools/EdMeshScan.h"

#include "editor/tools/EdMeshImport.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <tuple>
#include <utility>

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

  std::vector<MeshScanFinding> CheckMeshManifest(
    const edmesh::MeshMap& map,
    const MeshManifestFacts& facts
  )
  {
    std::vector<MeshScanFinding> list;
    const auto add = [&](const char severity, const char* code, std::string text) {
      list.push_back({severity, code, std::move(text)});
    };
    char line[400];
    const edmesh::Settings& s = map.settings;
    // V18: the dialect.
    for (const std::string& warning : map.warnings) {
      add('E', "V18", warning);
    }
    // V19: the scenario names the manifest.
    if (facts.haveScenario) {
      if (facts.terrainSystem != "mesh") {
        add('E', "V19", "ScenarioInfo.TerrainSystem is not 'mesh' (the game ignores the manifest)");
      }
      std::string mesh = facts.terrainMesh;
      std::string want = facts.expectedMesh;
      for (std::string* text : {&mesh, &want}) {
        std::transform(text->begin(), text->end(), text->begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
      }
      if (facts.terrainMesh.empty()) {
        add('E', "V19", "ScenarioInfo.TerrainMesh is missing");
      } else if (!want.empty() && mesh != want) {
        add('E', "V19", "TerrainMesh is " + facts.terrainMesh + ", the folder gives " + facts.expectedMesh);
      }
    }
    const bool given = [&] {
      for (const char* key : {"size"}) {
        if (s.given.contains(key)) {
          return true;
        }
      }
      return false;
    }();
    // V11: size.
    if (!given) {
      add('E', "V11", "size is missing");
    } else if (facts.mapSize > 0 && std::lround(s.size) != facts.mapSize) {
      (void)std::snprintf(
        line, sizeof(line), "size %.0f but the map is %d", static_cast<double>(s.size), facts.mapSize
      );
      add('E', "V11", line);
    }
    // V9: the playable rectangle.
    const float size = s.size > 0.0f ? s.size : static_cast<float>(facts.mapSize);
    const float* const p = s.playable;
    if (p[0] < 0.0f || p[1] < 0.0f || p[2] > size || p[3] > size) {
      add('E', "V9", "the playable rectangle leaves the map");
    }
    if (p[2] <= p[0] || p[3] <= p[1]) {
      add('E', "V9", "the playable rectangle is empty (x1 <= x0 or z1 <= z0)");
    }
    if (
      facts.havePlayable &&
      (std::fabs(facts.playable[0] - p[0]) > 0.5f || std::fabs(facts.playable[1] - p[1]) > 0.5f ||
       std::fabs(facts.playable[2] - p[2]) > 0.5f || std::fabs(facts.playable[3] - p[3]) > 0.5f)
    ) {
      (void)std::snprintf(
        line,
        sizeof(line),
        "playable rectangle %.0f,%.0f - %.0f,%.0f differs from AREA_1 %.0f,%.0f - %.0f,%.0f",
        static_cast<double>(p[0]),
        static_cast<double>(p[1]),
        static_cast<double>(p[2]),
        static_cast<double>(p[3]),
        static_cast<double>(facts.playable[0]),
        static_cast<double>(facts.playable[1]),
        static_cast<double>(facts.playable[2]),
        static_cast<double>(facts.playable[3])
      );
      add('E', "V9", line);
    }
    // V12: water against the map.
    const bool water = s.water > -9999.0f;
    if (water) {
      if (!facts.water) {
        add('E', "V12", "the manifest has water but the map has none");
      } else if (std::fabs(facts.waterLevel - s.water) > 0.01f) {
        (void)std::snprintf(
          line,
          sizeof(line),
          "water %.2f but the map's water elevation is %.2f",
          static_cast<double>(s.water),
          static_cast<double>(facts.waterLevel)
        );
        add('E', "V12", line);
      }
      if (s.given.contains("water_abyss") && s.waterAbyss >= s.water) {
        add('E', "V12", "water_abyss must be below water");
      }
    } else if (facts.water) {
      add('W', "V12", "the map has water but the manifest has no water level");
    }
    if (!water && (!s.waterMap.empty() || !s.waterBeyond.empty() || !s.waterInside.empty())) {
      add('E', "V12", "water files named without a water level");
    }
    // V15 (part): the heights in order.
    if (s.groundLow > -9999.0f && s.groundHigh > -9999.0f && s.groundLow > s.groundHigh) {
      add('W', "V15", "ground_low is above ground_high");
    }
    if (s.meshHigh > -9999.0f && s.groundHigh > -9999.0f && s.meshHigh < s.groundHigh) {
      add('W', "V15", "mesh_high is below ground_high");
    }
    // V14: the height field's highest point.
    if (facts.mapSize > 0 && facts.groundHighest > 250.0f) {
      (void)std::snprintf(
        line,
        sizeof(line),
        "the ground rises to %.0f (decals vanish beyond about 250)",
        static_cast<double>(facts.groundHighest)
      );
      add('W', "V14", line);
    }
    // The files beside the manifest.
    const auto inFolder = [&](const std::string& file) {
      if (file.empty() || file.front() == '/') {
        return file;
      }
      return map.dir + (map.dir.empty() || map.dir.back() == '/' ? "" : "/") + file;
    };
    const auto exists = [&](const std::string& file) {
      return facts.read && !facts.read(inFolder(file)).empty();
    };
    if (map.patches.empty()) {
      add('E', "V2", "the manifest names no patches (the game keeps the height field)");
    }
    std::vector<bool> used(map.materials.size(), false);
    std::size_t vertices = 0;
    for (const edmesh::Patch& patch : map.patches) {
      if (patch.material < 0 || patch.material >= static_cast<int>(map.materials.size())) {
        (void)std::snprintf(
          line,
          sizeof(line),
          "patch '%s' uses material %d (the manifest has %zu)",
          patch.file.c_str(),
          patch.material + 1,
          map.materials.size()
        );
        add('E', "V2", line);
      } else {
        used[static_cast<std::size_t>(patch.material)] = true;
      }
      if (facts.read) {
        const std::vector<std::uint8_t> bytes = facts.read(inFolder(patch.file));
        edmesh::Patch parsed;
        if (bytes.empty()) {
          add('E', "V1", patch.file + ": not found");
        } else if (const auto read = edmesh::ParseScm(bytes.data(), bytes.size(), parsed); !read) {
          add('E', "V1", patch.file + ": " + read.error());
        } else {
          vertices += parsed.vertexCount;
        }
      }
    }
    for (std::size_t m = 0; m < map.materials.size(); ++m) {
      const edmesh::Material& material = map.materials[m];
      if (!used[m]) {
        add('W', "V2", "material " + std::to_string(m + 1) + " '" + material.name + "' is not used by any patch");
      }
      static const char* const kSlotNames[edmesh::kSlots] = {
        "diffuse_a",
        "diffuse_b",
        "light_mask_0",
        "light_mask_1",
        "light_mask_2",
        "normal_a",
        "normal_b",
        "specular",
        "specular_b"
      };
      for (int k = 0; k < edmesh::kSlots && facts.read; ++k) {
        if (!material.files[k].empty() && !exists(material.files[k])) {
          add(
            'E',
            "V5",
            "texture '" + material.files[k] + "' (" + kSlotNames[k] + ", material " + std::to_string(m + 1) +
              ") not found"
          );
        }
      }
    }
    // The water files (V5, V13).
    if (facts.read) {
      const std::pair<const char*, const std::string*> files[] = {
        {"water_map", &s.waterMap},
        {"water_map_outer", &s.waterMapOuter},
        {"water_beyond", &s.waterBeyond},
        {"water_inside", &s.waterInside},
      };
      for (const auto& [key, file] : files) {
        if (!file->empty() && !exists(*file)) {
          add('E', "V5", std::string(key) + " '" + *file + "' not found");
        }
      }
      const std::tuple<const char*, const std::string*, float> triangles[] = {
        {"water_beyond", &s.waterBeyond, s.waterBeyondTriangles},
        {"water_inside", &s.waterInside, s.waterInsideTriangles},
      };
      for (const auto& [key, file, count] : triangles) {
        if (file->empty() || count < 0.0f) {
          continue;
        }
        const std::size_t bytes = facts.read(inFolder(*file)).size();
        const std::size_t want = static_cast<std::size_t>(std::lround(count)) * 24;
        if (bytes != 0 && bytes != want) {
          (void)std::snprintf(
            line,
            sizeof(line),
            "%s has %zu bytes, %.0f triangles need %zu",
            key,
            bytes,
            static_cast<double>(count),
            want
          );
          add('E', "V13", line);
        }
      }
    }
    // V20: the totals.
    (void)std::snprintf(
      line, sizeof(line), "%zu patches, %zu vertices, %zu materials", map.patches.size(), vertices, map.materials.size()
    );
    add('I', "V20", line);
    return list;
  }
} // namespace faf::editor
