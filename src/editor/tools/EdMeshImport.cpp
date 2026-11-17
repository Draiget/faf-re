#include "editor/tools/EdMeshImport.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <set>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::uint32_t U32(
      const std::vector<std::uint8_t>& bytes,
      const std::size_t at
    )
    {
      std::uint32_t value = 0;
      std::memcpy(&value, bytes.data() + at, 4);
      return value;
    }

    [[nodiscard]] float F32(
      const std::vector<std::uint8_t>& bytes,
      const std::size_t at
    )
    {
      float value = 0.0f;
      std::memcpy(&value, bytes.data() + at, 4);
      return value;
    }
  } // namespace

  std::expected<ScmModel, std::string> ReadScm(
    const std::vector<std::uint8_t>& bytes
  )
  {
    ScmModel out;
    if (bytes.size() < 0x30 || std::memcmp(bytes.data(), "MODL", 4) != 0) {
      return std::unexpected("not an .scm file (no MODL header)");
    }
    out.version = static_cast<int>(U32(bytes, 0x04));
    if (out.version != 5) {
      return std::unexpected("an .scm of version " + std::to_string(out.version) + " (the game's are 5)");
    }
    out.bones = static_cast<int>(U32(bytes, 0x2C));
    const std::uint32_t vertexAt = U32(bytes, 0x10);
    const std::uint32_t vertexCount = U32(bytes, 0x18);
    const std::uint32_t indexAt = U32(bytes, 0x1C);
    const std::uint32_t indexCount = U32(bytes, 0x20);
    const std::uint32_t infoAt = U32(bytes, 0x24);
    const std::uint32_t infoSize = U32(bytes, 0x28);
    constexpr std::size_t kVertex = 0x44;
    if (
      static_cast<std::uint64_t>(vertexAt) + static_cast<std::uint64_t>(vertexCount) * kVertex > bytes.size() ||
      static_cast<std::uint64_t>(indexAt) + static_cast<std::uint64_t>(indexCount) * 2U > bytes.size()
    ) {
      return std::unexpected("the file is shorter than its header says");
    }
    for (std::uint32_t v = 0; v < vertexCount; ++v) {
      const std::size_t at = vertexAt + v * kVertex;
      out.positions.push_back({F32(bytes, at), F32(bytes, at + 4), F32(bytes, at + 8)});
      out.normals.push_back({F32(bytes, at + 12), F32(bytes, at + 16), F32(bytes, at + 20)});
      out.uvs.push_back({F32(bytes, at + 48), F32(bytes, at + 52)});
    }
    for (std::uint32_t i = 0; i < indexCount; ++i) {
      const std::size_t at = indexAt + i * 2U;
      const std::uint32_t index =
        static_cast<std::uint32_t>(bytes[at]) | (static_cast<std::uint32_t>(bytes[at + 1]) << 8);
      if (index >= vertexCount) {
        return std::unexpected(
          "a triangle names vertex " + std::to_string(index) + " of " + std::to_string(vertexCount)
        );
      }
      out.indexes.push_back(index);
    }
    if (infoSize > 0 && static_cast<std::uint64_t>(infoAt) + infoSize <= bytes.size()) {
      out.info.assign(reinterpret_cast<const char*>(bytes.data() + infoAt), infoSize);
      while (!out.info.empty() && out.info.back() == '\0') {
        out.info.pop_back();
      }
    }
    return out;
  }

  std::string ObjFromScm(
    const ScmModel& model,
    const float scale
  )
  {
    const float divide = scale != 0.0f ? scale : 1.0f;
    std::string out = "# from an .scm (the FAF map editor)\n";
    char line[160];
    for (const auto& p : model.positions) {
      (void)std::snprintf(line, sizeof(line), "v %.6g %.6g %.6g\n", p[0] / divide, p[1] / divide, p[2] / divide);
      out += line;
    }
    for (const auto& t : model.uvs) {
      (void)std::snprintf(line, sizeof(line), "vt %.6g %.6g\n", t[0], 1.0f - t[1]);
      out += line;
    }
    for (const auto& n : model.normals) {
      (void)std::snprintf(line, sizeof(line), "vn %.6g %.6g %.6g\n", n[0], n[1], n[2]);
      out += line;
    }
    for (std::size_t i = 0; i + 2 < model.indexes.size(); i += 3) {
      const std::uint32_t a = model.indexes[i] + 1;
      const std::uint32_t b = model.indexes[i + 1] + 1;
      const std::uint32_t c = model.indexes[i + 2] + 1;
      (void)std::snprintf(line, sizeof(line), "f %u/%u/%u %u/%u/%u %u/%u/%u\n", a, a, a, b, b, b, c, c, c);
      out += line;
    }
    return out;
  }

  ObjMesh TransformMesh(
    const ObjMesh& mesh,
    const MeshImportOptions& options
  )
  {
    ObjMesh out = mesh;
    if (options.zUp) {
      // Z up (Blender): (x, y, z) -> (x, z, -y), the same handedness.
      for (auto& p : out.positions) {
        p = {p[0], p[2], -p[1]};
      }
      for (auto& n : out.normals) {
        n = {n[0], n[2], -n[1]};
      }
    }
    for (auto& p : out.positions) {
      p[0] = p[0] * (options.flipX ? -options.scale : options.scale) + options.offset[0];
      p[1] = p[1] * options.scale + options.offset[1];
      p[2] = p[2] * (options.flipZ ? -options.scale : options.scale) + options.offset[2];
    }
    for (auto& n : out.normals) {
      n[0] = options.flipX ? -n[0] : n[0];
      n[2] = options.flipZ ? -n[2] : n[2];
    }
    // A single mirror turns the triangles inside out: their corners go the other way round (and the asked flip too).
    if ((options.flipX != options.flipZ) != options.flipWinding) {
      for (auto& triangle : out.triangles) {
        std::swap(triangle[1], triangle[2]);
      }
    }
    if (options.flipV) {
      for (auto& uv : out.uvs) {
        uv[1] = 1.0f - uv[1];
      }
    }
    // Normals (FAF Studio's File / auto, Smooth, Flat): smooth ones are each position's faces' normals weighted by
    // their area; auto keeps the file's and smooths only the corners without one; flat gives each triangle its own.
    if (options.normals == 2) {
      out.normals.clear();
      for (auto& triangle : out.triangles) {
        const auto& a = out.positions[static_cast<std::size_t>(triangle[0].position)];
        const auto& b = out.positions[static_cast<std::size_t>(triangle[1].position)];
        const auto& c = out.positions[static_cast<std::size_t>(triangle[2].position)];
        const std::array<float, 3> e1{b[0] - a[0], b[1] - a[1], b[2] - a[2]};
        const std::array<float, 3> e2{c[0] - a[0], c[1] - a[1], c[2] - a[2]};
        out.normals.push_back(
          {e1[1] * e2[2] - e1[2] * e2[1], e1[2] * e2[0] - e1[0] * e2[2], e1[0] * e2[1] - e1[1] * e2[0]}
        );
        for (ObjMesh::Corner& corner : triangle) {
          corner.normal = static_cast<int>(out.normals.size()) - 1;
        }
      }
    } else {
      bool missing = options.normals == 1;
      for (const auto& triangle : out.triangles) {
        for (const ObjMesh::Corner& corner : triangle) {
          missing = missing || corner.normal < 0 || corner.normal >= static_cast<int>(out.normals.size());
        }
      }
      if (missing) {
        std::vector<std::array<float, 3>> smooth(out.positions.size(), std::array<float, 3>{0, 0, 0});
        for (const auto& triangle : out.triangles) {
          const auto& a = out.positions[static_cast<std::size_t>(triangle[0].position)];
          const auto& b = out.positions[static_cast<std::size_t>(triangle[1].position)];
          const auto& c = out.positions[static_cast<std::size_t>(triangle[2].position)];
          const std::array<float, 3> e1{b[0] - a[0], b[1] - a[1], b[2] - a[2]};
          const std::array<float, 3> e2{c[0] - a[0], c[1] - a[1], c[2] - a[2]};
          const std::array<float, 3> n{
            e1[1] * e2[2] - e1[2] * e2[1], e1[2] * e2[0] - e1[0] * e2[2], e1[0] * e2[1] - e1[1] * e2[0]
          };
          for (const ObjMesh::Corner& corner : triangle) {
            for (int k = 0; k < 3; ++k) {
              smooth[static_cast<std::size_t>(corner.position)][static_cast<std::size_t>(k)] +=
                n[static_cast<std::size_t>(k)];
            }
          }
        }
        const int base = static_cast<int>(out.normals.size());
        out.normals.insert(out.normals.end(), smooth.begin(), smooth.end());
        for (auto& triangle : out.triangles) {
          for (ObjMesh::Corner& corner : triangle) {
            if (options.normals == 1 || corner.normal < 0 || corner.normal >= base) {
              corner.normal = base + corner.position;
            }
          }
        }
      }
    }
    if (out.uvs.empty() && options.uvRepeat > 0.0f) {
      // Texture coordinates from the ground plan: one per position.
      for (const auto& p : out.positions) {
        out.uvs.push_back({p[0] / options.uvRepeat, p[2] / options.uvRepeat});
      }
      for (auto& triangle : out.triangles) {
        for (ObjMesh::Corner& c : triangle) {
          c.uv = c.position;
        }
      }
    }
    return out;
  }

  std::vector<std::pair<std::string, ObjMesh>> SplitByMaterial(
    const ObjMesh& mesh,
    const int materialsBy
  )
  {
    // FAF Studio's "Materials by": the OBJ's usemtl names, its o / g groups, or one for all ("ground").
    const std::vector<int>& of = materialsBy == 0 ? mesh.triangleMaterial : mesh.triangleGroup;
    const std::vector<std::string>& names = materialsBy == 0 ? mesh.materials : mesh.groups;
    std::vector<std::pair<std::string, ObjMesh>> parts;
    std::map<int, std::size_t> partOf;
    for (std::size_t t = 0; t < mesh.triangles.size(); ++t) {
      const int which = materialsBy == 2 || t >= of.size() ? -1 : of[t];
      auto found = partOf.find(which);
      if (found == partOf.end()) {
        ObjMesh part;
        part.positions = mesh.positions;
        part.uvs = mesh.uvs;
        part.normals = mesh.normals;
        part.groups = mesh.groups;
        part.materials = mesh.materials;
        part.uv2Size = mesh.uv2Size;
        const std::string name =
          which >= 0 && which < static_cast<int>(names.size()) ? names[static_cast<std::size_t>(which)] : "ground";
        found = partOf.emplace(which, parts.size()).first;
        parts.emplace_back(name, std::move(part));
      }
      ObjMesh& part = parts[found->second].second;
      part.triangles.push_back(mesh.triangles[t]);
      part.triangleGroup.push_back(t < mesh.triangleGroup.size() ? mesh.triangleGroup[t] : -1);
      part.triangleMaterial.push_back(t < mesh.triangleMaterial.size() ? mesh.triangleMaterial[t] : -1);
    }
    return parts;
  }

  std::map<std::pair<int, int>, ObjMesh> SplitMesh(
    const ObjMesh& mesh,
    const MeshImportOptions& options
  )
  {
    // Square tiles, or one part for each o / g group (key: group + 1, 0).
    std::map<std::pair<int, int>, ObjMesh> parts;
    if (options.byGroup && !mesh.triangleGroup.empty()) {
      for (std::size_t t = 0; t < mesh.triangles.size(); ++t) {
        const int group = t < mesh.triangleGroup.size() ? mesh.triangleGroup[t] : -1;
        ObjMesh& part = parts[{group + 1, 0}];
        if (part.positions.empty()) {
          part.positions = mesh.positions;
          part.uvs = mesh.uvs;
          part.normals = mesh.normals;
        }
        part.triangles.push_back(mesh.triangles[t]);
      }
    } else {
      parts = SplitByTile(mesh, options.tile);
    }
    // A part with more corners than the limit is cut into pieces (key second: the piece's number + 1000 a step).
    const std::size_t limit = static_cast<std::size_t>(std::clamp(options.maxVertices, 3, 65535));
    std::map<std::pair<int, int>, ObjMesh> out;
    for (auto& [key, part] : parts) {
      int piece = 0;
      ObjMesh current;
      std::set<int> used;
      const auto flush = [&]() {
        if (!current.triangles.empty()) {
          out[{key.first, key.second + piece * 1000}] = std::move(current);
          ++piece;
        }
        current = ObjMesh{};
        used.clear();
      };
      for (const auto& triangle : part.triangles) {
        std::size_t extra = 0;
        for (const ObjMesh::Corner& c : triangle) {
          extra += !used.contains(c.position) ? 1 : 0;
        }
        if (used.size() + extra > limit) {
          flush();
        }
        if (current.positions.empty()) {
          current.positions = part.positions;
          current.uvs = part.uvs;
          current.normals = part.normals;
        }
        for (const ObjMesh::Corner& c : triangle) {
          used.insert(c.position);
        }
        current.triangles.push_back(triangle);
      }
      flush();
    }
    return out;
  }

  std::map<std::pair<int, int>, ObjMesh> SplitByTile(
    const ObjMesh& mesh,
    const float tile
  )
  {
    std::map<std::pair<int, int>, ObjMesh> out;
    const float size = tile > 0.0f ? tile : 256.0f;
    for (const auto& triangle : mesh.triangles) {
      float mx = 0.0f;
      float mz = 0.0f;
      for (const ObjMesh::Corner& corner : triangle) {
        mx += mesh.positions[static_cast<std::size_t>(corner.position)][0] / 3.0f;
        mz += mesh.positions[static_cast<std::size_t>(corner.position)][2] / 3.0f;
      }
      const std::pair<int, int> key{static_cast<int>(std::floor(mx / size)), static_cast<int>(std::floor(mz / size))};
      ObjMesh& part = out[key];
      if (part.positions.empty()) {
        part.positions = mesh.positions; // shared tables: ScmFromObj keeps only the corners used
        part.uvs = mesh.uvs;
        part.normals = mesh.normals;
      }
      part.triangles.push_back(triangle);
    }
    return out;
  }

  std::vector<std::array<float, 3>> MeshWire(
    const ObjMesh& mesh,
    const std::size_t maxLines
  )
  {
    std::vector<std::array<float, 3>> out;
    std::set<std::pair<int, int>> seen;
    for (const auto& triangle : mesh.triangles) {
      for (int e = 0; e < 3; ++e) {
        const int a = triangle[static_cast<std::size_t>(e)].position;
        const int b = triangle[static_cast<std::size_t>((e + 1) % 3)].position;
        if (!seen.insert({std::min(a, b), std::max(a, b)}).second) {
          continue;
        }
        if (out.size() / 2 >= maxLines) {
          return out;
        }
        out.push_back(mesh.positions[static_cast<std::size_t>(a)]);
        out.push_back(mesh.positions[static_cast<std::size_t>(b)]);
      }
    }
    return out;
  }

  std::string MeshManifest(
    const std::map<std::pair<int, int>, std::string>& files,
    const float tile
  )
  {
    char head[96];
    (void)std::snprintf(head, sizeof(head), "MeshTerrain = {\n    tile = %g,\n    tiles = {\n", tile);
    std::string out = head;
    for (const auto& [key, file] : files) {
      out += "        { " + std::to_string(key.first) + ", " + std::to_string(key.second) + ", '" + file + "' },\n";
    }
    out += "    },\n}\n";
    return out;
  }

  std::string MeshTerrainManifest(
    const std::map<std::pair<int, int>, std::string>& files,
    const float size,
    const float meshHigh
  )
  {
    // The line oriented dialect the mesh terrain reads (FAF Studio's EdMeshData ParseManifest): one entry a line.
    char line[160];
    std::string out = "-- mesh terrain manifest (FAF map editor): one entry a line\n";
    (void)std::snprintf(line, sizeof(line), "size = %g,\n", static_cast<double>(size));
    out += line;
    if (meshHigh > -9999.0f) {
      // The highest vertex plus the margin the mesh checks expect (V15).
      (void)std::snprintf(line, sizeof(line), "mesh_high = %g,\n", static_cast<double>(meshHigh + kMeshHighMargin));
      out += line;
    }
    out += "{ name = 'ground', diffuse_a = '' },\n";
    for (const auto& [key, file] : files) {
      out += "{ mesh = '" + file + "', material = 1 },\n";
    }
    return out;
  }
} // namespace faf::editor
