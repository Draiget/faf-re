#pragma once

#include <array>
#include <cstdint>
#include <expected>
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
    /** The `o` / `g` names in file order, and each triangle's (an index into them; -1 before the first). */
    std::vector<std::string> groups;
    std::vector<int> triangleGroup;
    /** The `usemtl` names in file order, and each triangle's (-1 before the first). */
    std::vector<std::string> materials;
    std::vector<int> triangleMaterial;
    /**
     * The second texture coordinates (the light masks'): over the map, x and z / `uv2Size` (0..1), when above zero;
     * else the first set again.
     */
    float uv2Size = 0.0f;
  };

  /** Reads `v`, `vt`, `vn` and `f` lines (polygons fanned into triangles, negative indexes from the end). */
  [[nodiscard]] std::expected<ObjMesh, std::string> ParseObj(const std::string& text);

  /**
   * The model as a Supreme Commander `.scm` (version 5) the engine reads (moho::SScmFile): the 0x30-byte header, the
   * bone names from 0x40, one root bone (`boneName`, at rest at the origin), 0x44-byte vertices (position, normal,
   * tangent, binormal, two texture coordinates, bone 0), 16-bit indexes, an info text; each section after a 4-letter
   * tag (NAME, SKEL, VTXL, TRIS, INFO) at a 32-byte boundary, as the game's models are written. Positions times
   * `scale`; texture v turned over (OBJ counts from the bottom); normals made from the faces when the OBJ has none.
   * The error over 65535 vertices or without triangles.
   */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string>
  ScmFromObj(const ObjMesh& mesh, const std::string& boneName, float scale, const std::string& info);

  /** A bone of a skinned model: its parent (-1 the root, parents before children), its place and turn in the parent
   * (rotation w, x, y, z), and the inverse bind pose (3 rows of 3, then the translation row) when known. */
  struct ScmBone
  {
    std::string name;
    int parent = -1;
    std::array<float, 12> rest{};
    bool hasRest = false;
    std::array<float, 3> pos{};
    std::array<float, 4> rot{1.0f, 0.0f, 0.0f, 0.0f};
  };
  /** Fills the inverse bind pose of every bone that has none, from its position and rotation (parents first). */
  void ScmBindPose(std::vector<ScmBone>& bones);
  /** Where each bone is in the bind pose (model units). */
  [[nodiscard]] std::vector<std::array<float, 3>> ScmBonePositions(const std::vector<ScmBone>& bones);
  /** The same model with a skeleton: `positionBone[i]` is the bone of OBJ position i (missing: the root). */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> ScmFromObjSkinned(
    const ObjMesh& mesh,
    const std::vector<ScmBone>& bones,
    const std::vector<int>& positionBone,
    float scale,
    const std::string& info
  );
} // namespace faf::editor
