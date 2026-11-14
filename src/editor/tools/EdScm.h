#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A Wavefront OBJ model as read: positions, texture coordinates, normals and triangles of their corners. */
  struct ObjMesh
  {
    std::vector<std::array<float, 3>> positions;
    std::vector<std::array<float, 2>> uvs;
    std::vector<std::array<float, 3>> normals;
    struct Corner
    {
      int position = -1; // 0-based; -1 none
      int uv = -1;
      int normal = -1;
    };
    std::vector<std::array<Corner, 3>> triangles;
  };

  /** Reads `v`, `vt`, `vn` and `f` lines (polygons fanned into triangles, negative indexes from the end). */
  bool ParseObj(const std::string& text, ObjMesh& out, std::string& error);

  /**
   * The model as a Supreme Commander `.scm` (version 5) the engine reads (moho::SScmFile): the 0x30-byte header, the
   * bone names from 0x40, one root bone (`boneName`, at rest at the origin), 0x44-byte vertices (position, normal,
   * tangent, binormal, two texture coordinates, bone 0), 16-bit indexes, an info text; each section after a 4-letter
   * tag (NAME, SKEL, VTXL, TRIS, INFO) at a 32-byte boundary, as the game's models are written. Positions times
   * `scale`; texture v turned over (OBJ counts from the bottom); normals made from the faces when the OBJ has none.
   * Empty with `error` over 65535 vertices or without triangles.
   */
  [[nodiscard]] std::vector<std::uint8_t> ScmFromObj(
    const ObjMesh& mesh,
    const std::string& boneName,
    float scale,
    const std::string& info,
    std::string& error
  );
} // namespace faf::editor
