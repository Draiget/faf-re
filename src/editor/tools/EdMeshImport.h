#pragma once

#include "editor/tools/EdScm.h"

#include <array>
#include <cstdint>
#include <expected>
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

  /** Reads a `.scm` (FAF Studio's scm.lua, here in C++); the error for a file that isn't one. */
  [[nodiscard]] std::expected<ScmModel, std::string> ReadScm(const std::vector<std::uint8_t>& bytes);

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
    // FAF Studio's OBJ import options.
    bool zUp = false;            // the file's Z is up (Blender): Y and Z swapped
    float offset[3] = {0, 0, 0}; // added after the scale (map units)
    bool flipWinding = false;    // the triangles turned inside out
    bool flipV = false;          // the texture's v turned over
    int normals = 0;             // 0 the file's (smooth where it has none), 1 smooth, 2 flat (FAF Studio's)
    float uvRepeat = 0.0f;       // a file without texture coordinates: u, v = x, z / this (0: none)
    bool byGroup = false;        // one patch for each o / g group instead of square tiles
    int maxVertices = 65000;     // a patch is split before it has more corners than this
    // FAF Studio's import into the mesh terrain map.
    int materialsBy = 0;  // 0 the OBJ's materials (usemtl), 1 its o / g groups, 2 one material for all
    int lightMaskUv = 0;  // 0 over the map (x, z / the map's size), 1 the texture's coordinates
    bool replace = false; // the manifest's ground patches dropped first (sky patches stay)
  };
  /** The mesh cut by `materialsBy` into a part a material, each with its material's name (in first-use order). */
  [[nodiscard]] std::vector<std::pair<std::string, ObjMesh>> SplitByMaterial(const ObjMesh& mesh, int materialsBy);
  [[nodiscard]] ObjMesh TransformMesh(const ObjMesh& mesh, const MeshImportOptions& options);
  [[nodiscard]] std::map<std::pair<int, int>, ObjMesh> SplitByTile(const ObjMesh& mesh, float tile);
  /** The patches an import makes: tiles (or o / g groups), each cut again past `maxVertices` corners. */
  [[nodiscard]] std::map<std::pair<int, int>, ObjMesh> SplitMesh(const ObjMesh& mesh, const MeshImportOptions& options);

  /** The triangles' edges as line pairs (each edge once), at most `maxLines`, for the view's wire preview. */
  [[nodiscard]] std::vector<std::array<float, 3>> MeshWire(const ObjMesh& mesh, std::size_t maxLines);

  /** The manifest the import writes beside the tiles: `MeshTerrain = { tile = 256, tiles = { {x, z, file}, ... } }`. */
  [[nodiscard]] std::string MeshManifest(const std::map<std::pair<int, int>, std::string>& files, float tile);
  /**
   * The same tiles as a mesh terrain map's manifest (`terrain/terrain.lua`, FAF Studio's dialect: `size = ...`, one
   * material, `{ mesh = '<file>', material = 1 }` a line), which the editor's mesh terrain and Studio's both read.
   */
  [[nodiscard]] std::string
  MeshTerrainManifest(const std::map<std::pair<int, int>, std::string>& files, float size, float meshHigh);
  /**
   * How far above the highest vertex a mesh map's `mesh_high` sits (Studio's validator, check V15): the import writes
   * the highest vertex plus this, and the mesh checks expect it.
   */
  inline constexpr float kMeshHighMargin = 32.0f;
} // namespace faf::editor
