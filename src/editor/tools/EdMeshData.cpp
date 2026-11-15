#include "editor/tools/EdMeshData.h"

#include <algorithm>
#include <functional>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace faf::editor
{
  namespace edmesh
  {
    namespace
    {
      // ---- manifest
      // -------------------------------------------------------------------------------------------------------------------

      bool Field(
        const std::string& line,
        const char* key,
        std::string& out
      )
      {
        const std::string needle = std::string(key) + " = ";
        std::size_t at = 0;
        while ((at = line.find(needle, at)) != std::string::npos) {
          const bool wordStart =
            at == 0 || !(std::isalnum(static_cast<unsigned char>(line[at - 1])) || line[at - 1] == '_');
          at += needle.size();
          if (!wordStart) {
            continue;
          }
          if (at < line.size() && line[at] == '\'') {
            const std::size_t end = line.find('\'', at + 1);
            if (end == std::string::npos) {
              return false;
            }
            out = line.substr(at + 1, end - at - 1);
          } else {
            std::size_t end = at;
            while (end < line.size() &&
                   (std::isdigit(static_cast<unsigned char>(line[end])) || line[end] == '.' || line[end] == '-')) {
              ++end;
            }
            out = line.substr(at, end - at);
          }
          return true;
        }
        return false;
      }

      template <class Fn>
      void ForEachLine(
        const std::vector<std::uint8_t>& file,
        Fn fn
      )
      {
        const char* p = reinterpret_cast<const char*>(file.data());
        const char* const end = p + file.size();
        while (p < end) {
          const char* eol = static_cast<const char*>(std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
          if (eol == nullptr) {
            eol = end;
          }
          fn(std::string(p, eol));
          p = eol + 1;
        }
      }

      bool ParseManifest(
        const std::vector<std::uint8_t>& file,
        MeshMap& map
      )
      {
        static const char* const kSlotNames[kSlots] = {
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
        Settings& s = map.settings;
        struct Number
        {
          const char* key;
          float* target;
        };
        const Number numbers[] = {
          {"water", &s.water},
          {"water_abyss", &s.waterAbyss},
          {"water_outer_min", &s.waterOuterMin},
          {"water_outer_span", &s.waterOuterSpan},
          {"water_beyond_triangles", &s.waterBeyondTriangles},
          {"water_inside_triangles", &s.waterInsideTriangles},
          {"ground_low", &s.groundLow},
          {"ground_high", &s.groundHigh},
          {"mesh_high", &s.meshHigh},
          {"playable_x0", &s.playable[0]},
          {"playable_z0", &s.playable[1]},
          {"playable_x1", &s.playable[2]},
          {"playable_z1", &s.playable[3]},
          {"water_tint", &s.waterTint},
          {"size", &s.size},
          {"haze", &s.haze},
          {"haze_span", &s.hazeSpan},
          {"void_r", &s.voidColor[0]},
          {"void_g", &s.voidColor[1]},
          {"void_b", &s.voidColor[2]},
          {"shadow_r", &s.shadowColor[0]},
          {"shadow_g", &s.shadowColor[1]},
          {"shadow_b", &s.shadowColor[2]},
          {"shadow_a", &s.shadowColor[3]},
          {"sun_x", &s.sunDirection[0]},
          {"sun_y", &s.sunDirection[1]},
          {"sun_z", &s.sunDirection[2]},
          {"sun_r", &s.sunColor[0]},
          {"sun_g", &s.sunColor[1]},
          {"sun_b", &s.sunColor[2]},
        };
        ForEachLine(file, [&](const std::string& line) {
          std::string value;
          if (Field(line, "mesh", value)) {
            Patch p;
            p.file = value;
            if (Field(line, "material", value)) {
              p.material = std::atoi(value.c_str()) - 1;
            }
            p.sky = Field(line, "sky", value) && value == "1";
            map.patches.push_back(std::move(p));
          } else if (Field(line, "water_map", value)) {
            s.waterMap = value;
          } else if (Field(line, "water_map_outer", value)) {
            s.waterMapOuter = value;
          } else if (Field(line, "water_beyond", value)) {
            s.waterBeyond = value;
          } else if (Field(line, "water_inside", value)) {
            s.waterInside = value;
          } else if (Field(line, "name", value)) {
            Material m;
            m.name = value;
            for (int k = 0; k < kSlots; ++k) {
              if (Field(line, kSlotNames[k], value)) {
                m.files[k] = value;
              }
            }
            m.blending = Field(line, "blending", value) && value == "1";
            m.glow = Field(line, "glow", value) && value == "1";
            m.additive = Field(line, "additive", value) && value == "1";
            m.highlight = Field(line, "highlight", value) && value == "1";
            if (Field(line, "alpha_test", value)) {
              m.alphaTest = static_cast<float>(std::atof(value.c_str()));
            }
            map.materials.push_back(std::move(m));
          } else {
            for (const Number& n : numbers) {
              if (Field(line, n.key, value)) {
                *n.target = static_cast<float>(std::atof(value.c_str()));
                if (n.target == &s.voidColor[0]) {
                  s.haveVoid = true;
                }
              }
            }
          }
        });
        if (s.waterAbyss >= s.water) {
          s.waterAbyss = s.water - 1.0f;
        }
        if (s.hazeSpan < 1.0f) {
          s.hazeSpan = 1.0f;
        }
        if (s.size < 1.0f) {
          s.size = 1024.0f;
        }
        if (s.playable[2] <= s.playable[0] || s.playable[3] <= s.playable[1]) {
          s.playable[0] = s.playable[1] = 0.0f;
          s.playable[2] = s.playable[3] = s.size;
        }
        return !map.patches.empty();
      }

      inline float Read32(
        const std::uint8_t* p
      )
      {
        float f;
        std::memcpy(&f, p, 4);
        return f;
      }

      inline std::uint32_t ReadU32(
        const std::uint8_t* p
      )
      {
        std::uint32_t v;
        std::memcpy(&v, p, 4);
        return v;
      }
    } // namespace

    // ---- file access
    // -----------------------------------------------------------------------------------------------------------------

    namespace
    {
      std::function<std::vector<std::uint8_t>(const std::string&)>& Reader()
      {
        static std::function<std::vector<std::uint8_t>(const std::string&)> reader;
        return reader;
      }
    } // namespace

    void SetMeshFileReader(
      std::function<std::vector<std::uint8_t>(const std::string&)> reader
    )
    {
      Reader() = std::move(reader);
    }

    std::vector<std::uint8_t> ReadVfs(
      const std::string& path
    )
    {
      return Reader() ? Reader()(path) : std::vector<std::uint8_t>{};
    }

    // ---- SCM v5
    // ---------------------------------------------------------------------------------------------------------------------

    bool ParseScm(
      const std::uint8_t* bytes,
      const std::size_t size,
      Patch& out,
      std::string& why
    )
    {
      if (size < 48 || std::memcmp(bytes, "MODL", 4) != 0) {
        why = "not an SCM file";
        return false;
      }
      const std::uint32_t version = ReadU32(bytes + 4);
      const std::uint32_t vertexOffset = ReadU32(bytes + 16), vertexCount = ReadU32(bytes + 24);
      const std::uint32_t indexOffset = ReadU32(bytes + 28), indexCount = ReadU32(bytes + 32);
      if (version != 5) {
        why = "SCM version " + std::to_string(version) + " (the mesh terrain reads version 5)";
        return false;
      }
      if (
        vertexCount == 0 || vertexCount > 65535 || indexCount % 3 != 0 ||
        static_cast<std::uint64_t>(vertexOffset) + vertexCount * 68ull > size ||
        static_cast<std::uint64_t>(indexOffset) + indexCount * 2ull > size
      ) {
        why = "unusable SCM header (vertex or index block outside the file, or more than 65,535 vertices)";
        return false;
      }
      out.vertexCount = vertexCount;
      out.triangleCount = indexCount / 3;
      out.vertices.assign(bytes + vertexOffset, bytes + vertexOffset + vertexCount * 68ull);
      out.indices.resize(indexCount);
      std::memcpy(out.indices.data(), bytes + indexOffset, indexCount * 2ull);
      for (std::uint16_t i : out.indices) {
        if (i >= vertexCount) {
          why = "an index points past the last vertex";
          return false;
        }
      }
      float lo[3] = {1e30f, 1e30f, 1e30f}, hi[3] = {-1e30f, -1e30f, -1e30f};
      for (std::uint32_t v = 0; v < vertexCount; ++v) {
        const std::uint8_t* p = out.vertices.data() + v * 68ull;
        for (int k = 0; k < 3; ++k) {
          const float x = Read32(p + k * 4);
          if (x < lo[k]) {
            lo[k] = x;
          }
          if (x > hi[k]) {
            hi[k] = x;
          }
        }
      }
      for (int k = 0; k < 3; ++k) {
        out.boundsMin[k] = lo[k];
        out.boundsMax[k] = hi[k];
      }
      return true;
    }

    // ---- MeshMap
    // --------------------------------------------------------------------------------------------------------------------

    void MeshMap::Clear()
    {
      manifestPath.clear();
      dir.clear();
      settings = Settings();
      materials.clear();
      patches.clear();
      error.clear();
      grid_ = Grid();
      gridBuilt_ = false;
    }

    std::string MeshMap::ManifestText() const
    {
      static const char* const kSlotNames[kSlots] = {
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
      const Settings& s = settings;
      std::string out = "-- mesh terrain manifest (FAF map editor): one entry a line\n";
      char line[256];
      const auto number = [&](const char* key, const float value, const bool keep) {
        if (keep) {
          (void)std::snprintf(line, sizeof(line), "%s = %g\n", key, static_cast<double>(value));
          out += line;
        }
      };
      const auto text = [&](const char* key, const std::string& value) {
        if (!value.empty()) {
          out += std::string(key) + " = '" + value + "'\n";
        }
      };
      number("size", s.size, true);
      number("playable_x0", s.playable[0], true);
      number("playable_z0", s.playable[1], true);
      number("playable_x1", s.playable[2], true);
      number("playable_z1", s.playable[3], true);
      number("water", s.water, s.water > -9999.0f);
      number("water_abyss", s.waterAbyss, s.water > -9999.0f);
      number("water_tint", s.waterTint, s.waterTint != 1.0f);
      number("haze", s.haze, s.haze > -9999.0f);
      number("haze_span", s.hazeSpan, s.haze > -9999.0f);
      number("ground_low", s.groundLow, s.groundLow > -9999.0f);
      number("ground_high", s.groundHigh, s.groundHigh > -9999.0f);
      number("mesh_high", s.meshHigh, s.meshHigh > -9999.0f);
      if (s.haveVoid) {
        number("void_r", s.voidColor[0], true);
        number("void_g", s.voidColor[1], true);
        number("void_b", s.voidColor[2], true);
      }
      text("water_map", s.waterMap);
      text("water_map_outer", s.waterMapOuter);
      text("water_beyond", s.waterBeyond);
      text("water_inside", s.waterInside);
      for (const Material& m : materials) {
        std::string entry = "name = '" + m.name + "'";
        for (int k = 0; k < kSlots; ++k) {
          if (!m.files[k].empty()) {
            entry += std::string(", ") + kSlotNames[k] + " = '" + m.files[k] + "'";
          }
        }
        entry += m.blending ? ", blending = 1" : "";
        entry += m.glow ? ", glow = 1" : "";
        entry += m.highlight ? ", highlight = 1" : "";
        entry += m.additive ? ", additive = 1" : "";
        if (m.alphaTest >= 0.0f) {
          (void)std::snprintf(line, sizeof(line), ", alpha_test = %g", static_cast<double>(m.alphaTest));
          entry += line;
        }
        out += entry + "\n";
      }
      for (const Patch& patch : patches) {
        out += "mesh = '" + patch.file + "', material = " + std::to_string(patch.material + 1) +
          (patch.sky ? ", sky = 1" : "") + "\n";
      }
      return out;
    }

    bool MeshMap::Load(
      const std::string& manifestVfsPath
    )
    {
      Clear();
      manifestPath = manifestVfsPath;
      const std::size_t slash = manifestVfsPath.rfind('/');
      dir = slash == std::string::npos ? std::string() : manifestVfsPath.substr(0, slash);
      const std::vector<std::uint8_t> file = ReadVfs(manifestVfsPath);
      if (file.empty()) {
        error = "manifest not found: " + manifestVfsPath;
        return false;
      }
      if (!ParseManifest(file, *this)) {
        error = "the manifest names no patches";
        patches.clear();
        return false;
      }
      for (Patch& p : patches) {
        const std::vector<std::uint8_t> scm = ReadVfs(dir + "/" + p.file);
        std::string why;
        if (scm.empty()) {
          error = "patch file missing: " + p.file;
          patches.clear();
          return false;
        }
        if (!ParseScm(scm.data(), scm.size(), p, why)) {
          error = p.file + ": " + why;
          patches.clear();
          return false;
        }
      }
      BuildGrid();
      return true;
    }

    std::uint32_t MeshMap::TotalVertices() const
    {
      std::uint32_t n = 0;
      for (const Patch& p : patches) {
        n += p.vertexCount;
      }
      return n;
    }

    std::uint32_t MeshMap::TotalTriangles() const
    {
      std::uint32_t n = 0;
      for (const Patch& p : patches) {
        n += p.triangleCount;
      }
      return n;
    }

    bool MeshMap::HeightRange(
      const float margin,
      float& low,
      float& high
    ) const
    {
      const float x0 = settings.playable[0] - margin, z0 = settings.playable[1] - margin;
      const float x1 = settings.playable[2] + margin, z1 = settings.playable[3] + margin;
      bool any = false;
      low = 1e30f;
      high = -1e30f;
      for (const Patch& p : patches) {
        if (p.sky) {
          continue;
        }
        for (std::uint32_t v = 0; v < p.vertexCount; ++v) {
          const std::uint8_t* d = p.vertices.data() + v * 68ull;
          const float x = Read32(d), y = Read32(d + 4), z = Read32(d + 8);
          if (x >= x0 && x <= x1 && z >= z0 && z <= z1) {
            low = std::min(low, y);
            high = std::max(high, y);
            any = true;
          }
        }
      }
      return any;
    }

    bool MeshMap::TriangleAt(
      const int patch,
      const int tri,
      float v[3][3]
    ) const
    {
      if (patch < 0 || patch >= static_cast<int>(patches.size())) {
        return false;
      }
      const Patch& p = patches[static_cast<std::size_t>(patch)];
      if (tri < 0 || static_cast<std::uint32_t>(tri) >= p.triangleCount) {
        return false;
      }
      for (int k = 0; k < 3; ++k) {
        const std::uint8_t* d = p.vertices.data() + p.indices[static_cast<std::size_t>(tri) * 3 + k] * 68ull;
        v[k][0] = Read32(d);
        v[k][1] = Read32(d + 4);
        v[k][2] = Read32(d + 8);
      }
      return true;
    }

    // ---- lookup grid
    // ----------------------------------------------------------------------------------------------------------------

    void MeshMap::BuildGrid()
    {
      grid_ = Grid();
      gridBuilt_ = false;
      if (patches.empty()) {
        return;
      }
      // the grid covers the map and a margin: scenery far outside is never picked
      const float margin = 64.0f;
      grid_.x0 = -margin;
      grid_.z0 = -margin;
      const float extent = settings.size + 2.0f * margin;
      const int maxCells = 512;
      grid_.cell = std::max(2.0f, extent / static_cast<float>(maxCells));
      grid_.nx = grid_.nz = std::max(1, static_cast<int>(std::ceil(extent / grid_.cell)));
      const std::size_t cells = static_cast<std::size_t>(grid_.nx) * static_cast<std::size_t>(grid_.nz);
      std::vector<std::uint32_t> count(cells + 1, 0);

      struct Ref
      {
        std::uint32_t patch, tri;
      };
      auto cellRange = [&](const float lo[2], const float hi[2], int& i0, int& i1, int& j0, int& j1) {
        i0 = std::max(0, static_cast<int>(std::floor((lo[0] - grid_.x0) / grid_.cell)));
        i1 = std::min(grid_.nx - 1, static_cast<int>(std::floor((hi[0] - grid_.x0) / grid_.cell)));
        j0 = std::max(0, static_cast<int>(std::floor((lo[1] - grid_.z0) / grid_.cell)));
        j1 = std::min(grid_.nz - 1, static_cast<int>(std::floor((hi[1] - grid_.z0) / grid_.cell)));
        return i0 <= i1 && j0 <= j1;
      };
      for (int pass = 0; pass < 2; ++pass) {
        std::vector<std::uint32_t> fill;
        if (pass == 1) {
          // prefix sums
          std::uint32_t sum = 0;
          for (std::size_t c = 0; c < cells; ++c) {
            const std::uint32_t n = count[c];
            count[c] = sum;
            sum += n;
          }
          count[cells] = sum;
          grid_.items.resize(sum);
          grid_.itemPatch.resize(sum);
          fill.assign(count.begin(), count.begin() + static_cast<std::ptrdiff_t>(cells));
        }
        for (std::size_t pi = 0; pi < patches.size(); ++pi) {
          const Patch& p = patches[pi];
          if (p.sky) {
            continue;
          }
          for (std::uint32_t t = 0; t < p.triangleCount; ++t) {
            float lo[2] = {1e30f, 1e30f}, hi[2] = {-1e30f, -1e30f};
            for (int k = 0; k < 3; ++k) {
              const std::uint8_t* d = p.vertices.data() + p.indices[static_cast<std::size_t>(t) * 3 + k] * 68ull;
              const float x = Read32(d), z = Read32(d + 8);
              lo[0] = std::min(lo[0], x);
              hi[0] = std::max(hi[0], x);
              lo[1] = std::min(lo[1], z);
              hi[1] = std::max(hi[1], z);
            }
            int i0, i1, j0, j1;
            if (!cellRange(lo, hi, i0, i1, j0, j1)) {
              continue;
            }
            for (int j = j0; j <= j1; ++j) {
              for (int i = i0; i <= i1; ++i) {
                const std::size_t c = static_cast<std::size_t>(j) * grid_.nx + i;
                if (pass == 0) {
                  ++count[c];
                } else {
                  const std::uint32_t at = fill[c]++;
                  grid_.items[at] = t;
                  grid_.itemPatch[at] = static_cast<std::uint32_t>(pi);
                }
              }
            }
          }
        }
      }
      grid_.start = std::move(count);
      gridBuilt_ = true;
    }

    // ---- queries
    // --------------------------------------------------------------------------------------------------------------------

    bool MeshMap::HeightAt(
      const float x,
      const float z,
      const float ceiling,
      float& y
    ) const
    {
      if (!gridBuilt_) {
        return false;
      }
      const int i = static_cast<int>(std::floor((x - grid_.x0) / grid_.cell));
      const int j = static_cast<int>(std::floor((z - grid_.z0) / grid_.cell));
      if (i < 0 || j < 0 || i >= grid_.nx || j >= grid_.nz) {
        return false;
      }
      const std::size_t c = static_cast<std::size_t>(j) * grid_.nx + i;
      bool found = false;
      float best = -1e30f;
      for (std::uint32_t k = grid_.start[c]; k < grid_.start[c + 1]; ++k) {
        float v[3][3];
        if (!TriangleAt(static_cast<int>(grid_.itemPatch[k]), static_cast<int>(grid_.items[k]), v)) {
          continue;
        }
        const float denom = (v[1][2] - v[2][2]) * (v[0][0] - v[2][0]) + (v[2][0] - v[1][0]) * (v[0][2] - v[2][2]);
        if (std::fabs(denom) < 1e-9f) {
          continue;
        }
        const float l1 = ((v[1][2] - v[2][2]) * (x - v[2][0]) + (v[2][0] - v[1][0]) * (z - v[2][2])) / denom;
        const float l2 = ((v[2][2] - v[0][2]) * (x - v[2][0]) + (v[0][0] - v[2][0]) * (z - v[2][2])) / denom;
        const float l3 = 1.0f - l1 - l2;
        if (l1 < -1e-5f || l2 < -1e-5f || l3 < -1e-5f) {
          continue;
        }
        const float h = l1 * v[0][1] + l2 * v[1][1] + l3 * v[2][1];
        if (h <= ceiling && h > best) {
          best = h;
          found = true;
        }
      }
      if (found) {
        y = best;
      }
      return found;
    }

    namespace
    {
      // Moeller-Trumbore, both sides; t in units of the (unit) direction
      bool RayTriangle(
        const float o[3],
        const float d[3],
        const float v[3][3],
        float& t,
        float& u,
        float& w
      )
      {
        const float e1[3] = {v[1][0] - v[0][0], v[1][1] - v[0][1], v[1][2] - v[0][2]};
        const float e2[3] = {v[2][0] - v[0][0], v[2][1] - v[0][1], v[2][2] - v[0][2]};
        const float p[3] = {d[1] * e2[2] - d[2] * e2[1], d[2] * e2[0] - d[0] * e2[2], d[0] * e2[1] - d[1] * e2[0]};
        const float det = e1[0] * p[0] + e1[1] * p[1] + e1[2] * p[2];
        if (std::fabs(det) < 1e-12f) {
          return false;
        }
        const float inv = 1.0f / det;
        const float s[3] = {o[0] - v[0][0], o[1] - v[0][1], o[2] - v[0][2]};
        u = (s[0] * p[0] + s[1] * p[1] + s[2] * p[2]) * inv;
        if (u < -1e-6f || u > 1.000001f) {
          return false;
        }
        const float q[3] = {s[1] * e1[2] - s[2] * e1[1], s[2] * e1[0] - s[0] * e1[2], s[0] * e1[1] - s[1] * e1[0]};
        w = (d[0] * q[0] + d[1] * q[1] + d[2] * q[2]) * inv;
        if (w < -1e-6f || u + w > 1.000001f) {
          return false;
        }
        t = (e2[0] * q[0] + e2[1] * q[1] + e2[2] * q[2]) * inv;
        return t > 0.0f;
      }
    } // namespace

    bool MeshMap::Raycast(
      const float origin[3],
      const float dir[3],
      const float maxDistance,
      RayHit& hit
    ) const
    {
      if (!gridBuilt_) {
        return false;
      }
      // clip the ray's xz projection to the grid
      const float gx0 = grid_.x0, gz0 = grid_.z0;
      const float gx1 = grid_.x0 + grid_.nx * grid_.cell, gz1 = grid_.z0 + grid_.nz * grid_.cell;
      float tEnter = 0.0f, tExit = maxDistance;
      const float lo[2] = {gx0, gz0}, hi[2] = {gx1, gz1};
      const float o2[2] = {origin[0], origin[2]}, d2[2] = {dir[0], dir[2]};
      for (int a = 0; a < 2; ++a) {
        if (std::fabs(d2[a]) < 1e-9f) {
          if (o2[a] < lo[a] || o2[a] > hi[a]) {
            return false;
          }
        } else {
          float t0 = (lo[a] - o2[a]) / d2[a], t1 = (hi[a] - o2[a]) / d2[a];
          if (t0 > t1) {
            std::swap(t0, t1);
          }
          tEnter = std::max(tEnter, t0);
          tExit = std::min(tExit, t1);
        }
      }
      if (tEnter > tExit) {
        return false;
      }
      const float px = origin[0] + dir[0] * (tEnter + 1e-4f), pz = origin[2] + dir[2] * (tEnter + 1e-4f);
      int i = std::min(grid_.nx - 1, std::max(0, static_cast<int>(std::floor((px - gx0) / grid_.cell))));
      int j = std::min(grid_.nz - 1, std::max(0, static_cast<int>(std::floor((pz - gz0) / grid_.cell))));
      const int stepI = d2[0] > 0 ? 1 : -1, stepJ = d2[1] > 0 ? 1 : -1;
      const float inf = std::numeric_limits<float>::max();
      float nextI = std::fabs(d2[0]) < 1e-9f ? inf : ((gx0 + (i + (stepI > 0 ? 1 : 0)) * grid_.cell) - o2[0]) / d2[0];
      float nextJ = std::fabs(d2[1]) < 1e-9f ? inf : ((gz0 + (j + (stepJ > 0 ? 1 : 0)) * grid_.cell) - o2[1]) / d2[1];
      const float deltaI = std::fabs(d2[0]) < 1e-9f ? inf : grid_.cell / std::fabs(d2[0]);
      const float deltaJ = std::fabs(d2[1]) < 1e-9f ? inf : grid_.cell / std::fabs(d2[1]);

      bool found = false;
      float bestT = maxDistance;
      for (;;) {
        const std::size_t c = static_cast<std::size_t>(j) * grid_.nx + i;
        for (std::uint32_t k = grid_.start[c]; k < grid_.start[c + 1]; ++k) {
          float v[3][3], t, u, w;
          if (!TriangleAt(static_cast<int>(grid_.itemPatch[k]), static_cast<int>(grid_.items[k]), v)) {
            continue;
          }
          if (RayTriangle(origin, dir, v, t, u, w) && t < bestT) {
            bestT = t;
            found = true;
            hit.t = t;
            hit.patch = static_cast<int>(grid_.itemPatch[k]);
            hit.triangle = static_cast<int>(grid_.items[k]);
            hit.material = patches[static_cast<std::size_t>(hit.patch)].material;
            for (int a = 0; a < 3; ++a) {
              hit.position[a] = origin[a] + dir[a] * t;
            }
            const float e1[3] = {v[1][0] - v[0][0], v[1][1] - v[0][1], v[1][2] - v[0][2]};
            const float e2[3] = {v[2][0] - v[0][0], v[2][1] - v[0][1], v[2][2] - v[0][2]};
            float n[3] = {e1[1] * e2[2] - e1[2] * e2[1], e1[2] * e2[0] - e1[0] * e2[2], e1[0] * e2[1] - e1[1] * e2[0]};
            const float len = std::sqrt(n[0] * n[0] + n[1] * n[1] + n[2] * n[2]);
            if (len > 1e-12f) {
              for (float& x : n) {
                x /= len;
              }
            }
            if (n[1] < 0.0f) { // face the sky: the editor places things on top
              for (float& x : n) {
                x = -x;
              }
            }
            std::memcpy(hit.normal, n, sizeof n);
          }
        }
        const float exitT = std::min(nextI, nextJ);
        if ((found && bestT <= exitT) || exitT > tExit) {
          break;
        }
        if (nextI < nextJ) {
          i += stepI;
          nextI += deltaI;
          if (i < 0 || i >= grid_.nx) {
            break;
          }
        } else {
          j += stepJ;
          nextJ += deltaJ;
          if (j < 0 || j >= grid_.nz) {
            break;
          }
        }
      }
      return found;
    }
  } // namespace edmesh
} // namespace faf::editor
