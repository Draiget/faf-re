#include "editor/tools/EdScm.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <tuple>

namespace faf::editor
{
  std::expected<ObjMesh, std::string> ParseObj(
    const std::string& text
  )
  {
    ObjMesh out;
    std::istringstream lines(text);
    std::string line;
    int number = 0;
    int group = -1;    // -1: before any `o` / `g` line
    int material = -1; // -1: before any `usemtl` line
    const auto index = [](const std::string& part, const std::size_t count) {
      if (part.empty()) {
        return -1;
      }
      const int i = std::atoi(part.c_str());
      return i > 0 ? i - 1 : (i < 0 ? static_cast<int>(count) + i : -1);
    };
    while (std::getline(lines, line)) {
      ++number;
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      std::istringstream words(line);
      std::string kind;
      words >> kind;
      if (kind == "v") {
        std::array<float, 3> p{};
        words >> p[0] >> p[1] >> p[2];
        out.positions.push_back(p);
      } else if (kind == "vt") {
        std::array<float, 2> t{};
        words >> t[0] >> t[1];
        out.uvs.push_back(t);
      } else if (kind == "vn") {
        std::array<float, 3> n{};
        words >> n[0] >> n[1] >> n[2];
        out.normals.push_back(n);
      } else if (kind == "usemtl") {
        std::string name;
        std::getline(words >> std::ws, name);
        const auto found = std::find(out.materials.begin(), out.materials.end(), name);
        material = static_cast<int>(found - out.materials.begin());
        if (found == out.materials.end()) {
          out.materials.push_back(name);
        }
      } else if (kind == "o" || kind == "g") {
        std::string name;
        std::getline(words >> std::ws, name);
        if (name.empty()) {
          name = "default";
        }
        const auto found = std::find(out.groups.begin(), out.groups.end(), name);
        group = static_cast<int>(found - out.groups.begin());
        if (found == out.groups.end()) {
          out.groups.push_back(name);
        }
      } else if (kind == "f") {
        std::vector<ObjMesh::Corner> polygon;
        std::string word;
        while (words >> word) {
          ObjMesh::Corner corner;
          const std::size_t a = word.find('/');
          const std::size_t b = a == std::string::npos ? a : word.find('/', a + 1);
          corner.position = index(word.substr(0, a), out.positions.size());
          if (a != std::string::npos) {
            corner.uv =
              index(word.substr(a + 1, b == std::string::npos ? std::string::npos : b - a - 1), out.uvs.size());
          }
          if (b != std::string::npos) {
            corner.normal = index(word.substr(b + 1), out.normals.size());
          }
          if (corner.position < 0 || corner.position >= static_cast<int>(out.positions.size())) {
            return std::unexpected("line " + std::to_string(number) + ": a face names a vertex the file hasn't got");
          }
          polygon.push_back(corner);
        }
        for (std::size_t k = 2; k < polygon.size(); ++k) {
          out.triangles.push_back({polygon[0], polygon[k - 1], polygon[k]});
          out.triangleGroup.push_back(group);
          out.triangleMaterial.push_back(material);
        }
      }
    }
    if (out.triangles.empty()) {
      return std::unexpected("the file has no faces");
    }
    return out;
  }

  namespace
  {
    void Put32(
      std::vector<std::uint8_t>& out,
      const std::uint32_t value
    )
    {
      for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
      }
    }

    void PutFloat(
      std::vector<std::uint8_t>& out,
      const float value
    )
    {
      std::uint32_t word = 0;
      std::memcpy(&word, &value, 4);
      Put32(out, word);
    }

    void Set32(
      std::vector<std::uint8_t>& out,
      const std::size_t at,
      const std::uint32_t value
    )
    {
      for (int i = 0; i < 4; ++i) {
        out[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value >> (8 * i));
      }
    }

    /** 'X' up to four bytes before a 32-byte boundary, then the section's tag: its data starts on the boundary. */
    void Section(
      std::vector<std::uint8_t>& out,
      const char (&tag)[5]
    )
    {
      while ((out.size() + 4) % 32 != 0) {
        out.push_back('X');
      }
      out.insert(out.end(), tag, tag + 4);
    }

    std::array<float, 3> Normalized(
      std::array<float, 3> v
    )
    {
      const float length = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
      if (length > 1e-12f) {
        for (float& c : v) {
          c /= length;
        }
      }
      return v;
    }
  } // namespace

  void ScmBindPose(
    std::vector<ScmBone>& bones
  )
  {
    // Row-vector matrices (Direct3D): a bone's local transform is its rotation (the quaternion's matrix transposed) and
    // its position; the absolute one is local * parent's absolute; the file keeps the inverse of the absolute.
    struct Abs
    {
      float R[3][3];
      float t[3];
    };
    std::vector<Abs> abs(bones.size());
    for (std::size_t i = 0; i < bones.size(); ++i) {
      const ScmBone& b = bones[i];
      const float w = b.rot[0], x = b.rot[1], y = b.rot[2], z = b.rot[3];
      // The usual column matrix of the quaternion, transposed (row vectors).
      const float m[3][3] = {
        {1 - 2 * (y * y + z * z), 2 * (x * y + w * z), 2 * (x * z - w * y)},
        {2 * (x * y - w * z), 1 - 2 * (x * x + z * z), 2 * (y * z + w * x)},
        {2 * (x * z + w * y), 2 * (y * z - w * x), 1 - 2 * (x * x + y * y)},
      };
      Abs a{};
      if (b.parent >= 0 && static_cast<std::size_t>(b.parent) < i) {
        const Abs& p = abs[static_cast<std::size_t>(b.parent)];
        for (int r = 0; r < 3; ++r) {
          for (int c = 0; c < 3; ++c) {
            a.R[r][c] = m[r][0] * p.R[0][c] + m[r][1] * p.R[1][c] + m[r][2] * p.R[2][c];
          }
          a.t[r] = 0.0f;
        }
        for (int c = 0; c < 3; ++c) {
          a.t[c] = b.pos[0] * p.R[0][c] + b.pos[1] * p.R[1][c] + b.pos[2] * p.R[2][c] + p.t[c];
        }
      } else {
        for (int r = 0; r < 3; ++r) {
          for (int c = 0; c < 3; ++c) {
            a.R[r][c] = m[r][c];
          }
          a.t[r] = b.pos[static_cast<std::size_t>(r)];
        }
      }
      abs[i] = a;
      if (!b.hasRest) {
        ScmBone& out = bones[i];
        for (int r = 0; r < 3; ++r) {
          for (int c = 0; c < 3; ++c) {
            out.rest[static_cast<std::size_t>(r * 3 + c)] = a.R[c][r];
          }
        }
        for (int c = 0; c < 3; ++c) {
          out.rest[static_cast<std::size_t>(9 + c)] = -(a.t[0] * a.R[c][0] + a.t[1] * a.R[c][1] + a.t[2] * a.R[c][2]);
        }
        out.hasRest = true;
      }
    }
  }

  std::vector<std::array<float, 3>> ScmBonePositions(
    const std::vector<ScmBone>& bones
  )
  {
    // The rest pose's translation row inverted: the bone's place in the model.
    std::vector<ScmBone> copy = bones;
    ScmBindPose(copy);
    std::vector<std::array<float, 3>> out;
    for (const ScmBone& b : copy) {
      const auto& r = b.rest;
      // rest = [R^T | -t R^T]: t = -(row translation) * R
      const float tx = r[9], ty = r[10], tz = r[11];
      out.push_back({
        -(tx * r[0] + ty * r[1] + tz * r[2]),
        -(tx * r[3] + ty * r[4] + tz * r[5]),
        -(tx * r[6] + ty * r[7] + tz * r[8]),
      });
    }
    return out;
  }

  std::expected<std::vector<std::uint8_t>, std::string> ScmFromObj(
    const ObjMesh& mesh,
    const std::string& boneName,
    const float scale,
    const std::string& info
  )
  {
    ScmBone root;
    root.name = boneName;
    root.rest = {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0};
    root.hasRest = true;
    return ScmFromObjSkinned(mesh, {root}, {}, scale, info);
  }

  std::expected<std::vector<std::uint8_t>, std::string> ScmFromObjSkinned(
    const ObjMesh& mesh,
    const std::vector<ScmBone>& bonesIn,
    const std::vector<int>& positionBone,
    const float scale,
    const std::string& info
  )
  {
    if (bonesIn.empty()) {
      return std::unexpected("a model needs a bone");
    }
    std::vector<ScmBone> bones = bonesIn;
    ScmBindPose(bones);
    struct Vertex
    {
      std::array<float, 3> position{};
      std::array<float, 3> normal{};
      std::array<float, 3> tangent{};
      std::array<float, 3> binormal{};
      std::array<float, 2> uv{};
      int bone = 0;
    };
    // One vertex per distinct corner (position, uv, normal).
    std::map<std::tuple<int, int, int>, std::uint32_t> made;
    std::vector<Vertex> vertices;
    std::vector<std::uint32_t> indexes;
    for (const auto& triangle : mesh.triangles) {
      // A face's own normal, for corners the file gives none.
      const auto& a = mesh.positions[static_cast<std::size_t>(triangle[0].position)];
      const auto& b = mesh.positions[static_cast<std::size_t>(triangle[1].position)];
      const auto& c = mesh.positions[static_cast<std::size_t>(triangle[2].position)];
      const std::array<float, 3> e1{b[0] - a[0], b[1] - a[1], b[2] - a[2]};
      const std::array<float, 3> e2{c[0] - a[0], c[1] - a[1], c[2] - a[2]};
      const std::array<float, 3> face =
        Normalized({e1[1] * e2[2] - e1[2] * e2[1], e1[2] * e2[0] - e1[0] * e2[2], e1[0] * e2[1] - e1[1] * e2[0]});
      for (const ObjMesh::Corner& corner : triangle) {
        const auto key = std::make_tuple(corner.position, corner.uv, corner.normal);
        auto found = made.find(key);
        if (found == made.end()) {
          Vertex v;
          const auto& p = mesh.positions[static_cast<std::size_t>(corner.position)];
          v.position = {p[0] * scale, p[1] * scale, p[2] * scale};
          if (corner.uv >= 0 && corner.uv < static_cast<int>(mesh.uvs.size())) {
            const auto& t = mesh.uvs[static_cast<std::size_t>(corner.uv)];
            v.uv = {t[0], 1.0f - t[1]};
          }
          v.normal = corner.normal >= 0 && corner.normal < static_cast<int>(mesh.normals.size())
            ? Normalized(mesh.normals[static_cast<std::size_t>(corner.normal)])
            : face;
          if (corner.position >= 0 && static_cast<std::size_t>(corner.position) < positionBone.size()) {
            v.bone = std::clamp(
              positionBone[static_cast<std::size_t>(corner.position)], 0, static_cast<int>(bones.size()) - 1
            );
          }
          found = made.emplace(key, static_cast<std::uint32_t>(vertices.size())).first;
          vertices.push_back(v);
        }
        indexes.push_back(found->second);
      }
    }
    if (vertices.size() > 65535) {
      return std::unexpected(
        "the model has " + std::to_string(vertices.size()) + " vertices; a model takes 65535 at most"
      );
    }
    if (indexes.empty()) {
      return std::unexpected("the model has no triangles");
    }
    // Tangents and binormals from the texture coordinates (summed over the faces, then made square to the normal).
    std::vector<std::array<float, 3>> tangents(vertices.size(), std::array<float, 3>{0, 0, 0});
    std::vector<std::array<float, 3>> binormals(vertices.size(), std::array<float, 3>{0, 0, 0});
    for (std::size_t i = 0; i + 2 < indexes.size(); i += 3) {
      const Vertex& v0 = vertices[indexes[i]];
      const Vertex& v1 = vertices[indexes[i + 1]];
      const Vertex& v2 = vertices[indexes[i + 2]];
      const float x1 = v1.position[0] - v0.position[0], y1 = v1.position[1] - v0.position[1],
                  z1 = v1.position[2] - v0.position[2];
      const float x2 = v2.position[0] - v0.position[0], y2 = v2.position[1] - v0.position[1],
                  z2 = v2.position[2] - v0.position[2];
      const float s1 = v1.uv[0] - v0.uv[0], t1 = v1.uv[1] - v0.uv[1];
      const float s2 = v2.uv[0] - v0.uv[0], t2 = v2.uv[1] - v0.uv[1];
      const float d = s1 * t2 - s2 * t1;
      if (std::fabs(d) < 1e-12f) {
        continue;
      }
      const float r = 1.0f / d;
      const std::array<float, 3> t{(t2 * x1 - t1 * x2) * r, (t2 * y1 - t1 * y2) * r, (t2 * z1 - t1 * z2) * r};
      const std::array<float, 3> bn{(s1 * x2 - s2 * x1) * r, (s1 * y2 - s2 * y1) * r, (s1 * z2 - s2 * z1) * r};
      for (int k = 0; k < 3; ++k) {
        for (int c = 0; c < 3; ++c) {
          tangents[indexes[i + static_cast<std::size_t>(k)]][static_cast<std::size_t>(c)] +=
            t[static_cast<std::size_t>(c)];
          binormals[indexes[i + static_cast<std::size_t>(k)]][static_cast<std::size_t>(c)] +=
            bn[static_cast<std::size_t>(c)];
        }
      }
    }
    for (std::size_t i = 0; i < vertices.size(); ++i) {
      Vertex& v = vertices[i];
      const auto& n = v.normal;
      auto t = tangents[i];
      const float dot = n[0] * t[0] + n[1] * t[1] + n[2] * t[2];
      t = Normalized({t[0] - n[0] * dot, t[1] - n[1] * dot, t[2] - n[2] * dot});
      if (t[0] == 0.0f && t[1] == 0.0f && t[2] == 0.0f) {
        t = std::fabs(n[0]) < 0.9f ? Normalized({0.0f, -n[2], n[1]}) : Normalized({-n[2], 0.0f, n[0]});
      }
      v.tangent = t;
      // The binormal: normal x tangent, on the side the texture's v runs.
      std::array<float, 3> b{n[1] * t[2] - n[2] * t[1], n[2] * t[0] - n[0] * t[2], n[0] * t[1] - n[1] * t[0]};
      const auto& given = binormals[i];
      if (b[0] * given[0] + b[1] * given[1] + b[2] * given[2] < 0.0f) {
        b = {-b[0], -b[1], -b[2]};
      }
      v.binormal = b;
    }

    std::vector<std::uint8_t> out;
    // The header (SScmFile): offsets and counts filled in as the sections are written.
    out.insert(out.end(), {'M', 'O', 'D', 'L'});
    Put32(out, 5); // version
    for (int i = 0; i < 10; ++i) {
      Put32(out, 0);
    }
    Section(out, "NAME"); // the names from 0x40, one after another
    const std::size_t namesAt = out.size();
    std::vector<std::uint32_t> nameOffsets;
    for (const ScmBone& b : bones) {
      nameOffsets.push_back(static_cast<std::uint32_t>(out.size() - namesAt));
      out.insert(out.end(), b.name.begin(), b.name.end());
      out.push_back(0);
    }
    int used = 0;
    for (const Vertex& v : vertices) {
      used = std::max(used, v.bone);
    }
    Section(out, "SKEL");
    Set32(out, 0x08, static_cast<std::uint32_t>(out.size()));   // bone table
    Set32(out, 0x0C, static_cast<std::uint32_t>(used + 1));     // skinned bones
    Set32(out, 0x2C, static_cast<std::uint32_t>(bones.size())); // every bone
    for (std::size_t i = 0; i < bones.size(); ++i) {
      // The inverse bind pose as a 4x4 (rotation rows, then the translation row and 1), the position in the parent,
      // the rotation (w, x, y, z), the name's place in the names, the parent (-1: none), two words unused.
      const ScmBone& b = bones[i];
      const auto& r = b.rest;
      const float rows[16] = {r[0], r[1], r[2], 0, r[3], r[4], r[5], 0, r[6], r[7], r[8], 0, r[9], r[10], r[11], 1};
      for (const float value : rows) {
        PutFloat(out, value);
      }
      for (const float value : b.pos) {
        PutFloat(out, value);
      }
      for (const float value : b.rot) {
        PutFloat(out, value);
      }
      Put32(out, nameOffsets[i]);
      Put32(out, b.parent < 0 ? 0xFFFFFFFFu : static_cast<std::uint32_t>(b.parent));
      Put32(out, 0);
      Put32(out, 0);
    }
    Section(out, "VTXL");
    Set32(out, 0x10, static_cast<std::uint32_t>(out.size()));
    Set32(out, 0x18, static_cast<std::uint32_t>(vertices.size()));
    for (const Vertex& v : vertices) {
      for (const float c : v.position) {
        PutFloat(out, c);
      }
      for (const float c : v.normal) {
        PutFloat(out, c);
      }
      for (const float c : v.tangent) {
        PutFloat(out, c);
      }
      for (const float c : v.binormal) {
        PutFloat(out, c);
      }
      PutFloat(out, v.uv[0]);
      PutFloat(out, v.uv[1]);
      if (mesh.uv2Size > 0.0f) {
        // The second set over the map (FAF Studio's planar light mask coordinates).
        PutFloat(out, std::clamp(v.position[0] / mesh.uv2Size, 0.0f, 1.0f));
        PutFloat(out, std::clamp(v.position[2] / mesh.uv2Size, 0.0f, 1.0f));
      } else {
        PutFloat(out, v.uv[0]); // the second set: the same
        PutFloat(out, v.uv[1]);
      }
      Put32(out, static_cast<std::uint32_t>(v.bone)); // its bone (the first of four bytes)
    }
    Section(out, "TRIS");
    Set32(out, 0x1C, static_cast<std::uint32_t>(out.size()));
    Set32(out, 0x20, static_cast<std::uint32_t>(indexes.size()));
    for (const std::uint32_t i : indexes) {
      out.push_back(static_cast<std::uint8_t>(i));
      out.push_back(static_cast<std::uint8_t>(i >> 8));
    }
    Section(out, "INFO");
    Set32(out, 0x24, static_cast<std::uint32_t>(out.size()));
    Set32(out, 0x28, static_cast<std::uint32_t>(info.size() + 1));
    out.insert(out.end(), info.begin(), info.end());
    out.push_back(0);
    return out;
  }
} // namespace faf::editor
