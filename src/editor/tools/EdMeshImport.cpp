#include "editor/tools/EdMeshImport.h"

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

  bool ReadScm(
    const std::vector<std::uint8_t>& bytes,
    ScmModel& out,
    std::string& error
  )
  {
    out = ScmModel{};
    if (bytes.size() < 0x30 || std::memcmp(bytes.data(), "MODL", 4) != 0) {
      error = "not an .scm file (no MODL header)";
      return false;
    }
    out.version = static_cast<int>(U32(bytes, 0x04));
    if (out.version != 5) {
      error = "an .scm of version " + std::to_string(out.version) + " (the game's are 5)";
      return false;
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
      error = "the file is shorter than its header says";
      return false;
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
        error = "a triangle names vertex " + std::to_string(index) + " of " + std::to_string(vertexCount);
        return false;
      }
      out.indexes.push_back(index);
    }
    if (infoSize > 0 && static_cast<std::uint64_t>(infoAt) + infoSize <= bytes.size()) {
      out.info.assign(reinterpret_cast<const char*>(bytes.data() + infoAt), infoSize);
      while (!out.info.empty() && out.info.back() == '\0') {
        out.info.pop_back();
      }
    }
    return true;
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
    for (auto& p : out.positions) {
      p[0] *= options.flipX ? -options.scale : options.scale;
      p[1] *= options.scale;
      p[2] *= options.flipZ ? -options.scale : options.scale;
    }
    for (auto& n : out.normals) {
      n[0] = options.flipX ? -n[0] : n[0];
      n[2] = options.flipZ ? -n[2] : n[2];
    }
    // A single mirror turns the triangles inside out: their corners go the other way round.
    if (options.flipX != options.flipZ) {
      for (auto& triangle : out.triangles) {
        std::swap(triangle[1], triangle[2]);
      }
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
} // namespace faf::editor
