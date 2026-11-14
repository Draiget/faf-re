#pragma once

#include "editor/tools/EdScm.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /** A `.scm` model as read back (version 5, moho::SScmFile's layout): what the editor needs of it. */
  struct ScmModel
  {
    int version = 0;
    int bones = 0;
    std::vector<std::array<float, 3>> positions;
    std::vector<std::array<float, 3>> normals;
    std::vector<std::array<float, 2>> uvs;
    std::vector<std::uint32_t> indexes; // three a triangle
    std::string info;
  };

  /** Reads a `.scm` (FAF Studio's scm.lua, here in C++); false with `error` for a file that isn't one. */
  bool ReadScm(const std::vector<std::uint8_t>& bytes, ScmModel& out, std::string& error);

  /** The model as Wavefront OBJ text (texture v turned back over, as ScmFromObj turned it), positions divided by
   * `scale`. */
  [[nodiscard]] std::string ObjFromScm(const ScmModel& model, float scale);

  /**
   * Mesh terrain (FAF Studio's meshimport, kept as a preview: the game draws height fields only): an OBJ in map units
   * (after `scale`, X mirrored by `flipX`, Z by `flipZ`, Y up) cut into square tiles of `tile` units, each its own
   * mesh; a triangle goes to the tile its middle is in.
   */
  struct MeshImportOptions
  {
    float scale = 1.0f;
    bool flipX = false;
    bool flipZ = false;
    float tile = 256.0f;
  };
  [[nodiscard]] ObjMesh TransformMesh(const ObjMesh& mesh, const MeshImportOptions& options);
  [[nodiscard]] std::map<std::pair<int, int>, ObjMesh> SplitByTile(const ObjMesh& mesh, float tile);

  /** The triangles' edges as line pairs (each edge once), at most `maxLines`, for the view's wire preview. */
  [[nodiscard]] std::vector<std::array<float, 3>> MeshWire(const ObjMesh& mesh, std::size_t maxLines);

  /** The manifest the import writes beside the tiles: `MeshTerrain = { tile = 256, tiles = { {x, z, file}, ... } }`. */
  [[nodiscard]] std::string MeshManifest(const std::map<std::pair<int, int>, std::string>& files, float tile);
} // namespace faf::editor
