#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Editor addition: the CPU side of a mesh terrain map (docs/projects/editor/MESH_VIEW.md): the manifest
   * `terrain/terrain.lua`, its SCM v5 patches and the queries the editor needs against them (height under a point, ray
   * hit). No Direct3D in here; EdMeshDraw.cpp draws what this loads.
   *
   * The manifest dialect is the line oriented one the terrain mesh patch reads (automation/terrainmesh/meshterrain.cpp
   * `Field`, `LoadManifest`): one entry per line, `key = value` pairs, single quoted strings, numbers scanned as
   * `[0-9.-]`.
   */
  namespace edmesh
  {
    constexpr int kSlots = 9; // diffuse a, diffuse b, light mask 0..2, normal a, normal b, specular a, specular b

    struct Material
    {
      std::string name;
      std::string files[kSlots];
      bool blending = false;   // SC2's BLENDING: the two layers are mixed by light mask 1's alpha
      bool glow = false;       // the mask's green channel lights the ground itself
      bool highlight = false;  // SC2's sun highlight by the mask's blue channel
      bool additive = false;   // sky piece added onto what is behind it
      float alphaTest = -1.0f; // SC2's ALPHA_TEST reference (alpha * 255 must be above it), -1: none
    };

    struct Patch
    {
      std::string file;
      int material = 0; // 0 based; the manifest counts from 1
      bool sky = false;
      std::uint32_t vertexCount = 0;
      std::uint32_t triangleCount = 0;
      std::vector<std::uint8_t> vertices; // 68 bytes each: position, normal, tangent, binormal, uv1, uv2, 4 bone bytes
      std::vector<std::uint16_t> indices;
      float boundsMin[3] = {0, 0, 0};
      float boundsMax[3] = {0, 0, 0};
    };

    struct Settings
    {
      float size = 1024.0f;
      float playable[4] = {0, 0, 0, 0}; // x0 z0 x1 z1 (whole map when not given)
      float water = -10000.0f, waterAbyss = -10001.0f, waterTint = 1.0f;
      float haze = -10000.0f, hazeSpan = 100.0f;
      float voidColor[3] = {0, 0, 0};
      bool haveVoid = false;
      float shadowColor[4] = {0.40f, 0.40f, 0.45f, 1.0f};
      float sunDirection[4] = {0.0f, 1.0f, 0.0f, 0.0f};
      float sunColor[4] = {0, 0, 0, 0};
      float groundLow = -10000.0f, groundHigh = -10000.0f, meshHigh = -10000.0f;
      float waterOuterMin = 0.0f, waterOuterSpan = 0.0f;
      float waterBeyondTriangles = -1.0f, waterInsideTriangles = -1.0f;
      std::string waterMap, waterMapOuter, waterBeyond, waterInside;
      /** The keys the manifest gives (read from it, or set in the panel); Unset takes one out. */
      std::set<std::string> given;
    };

    /** One manifest setting (FAF Studio's meshmap.lua Keys): its decimals (-1 whole, -2 a file name), range, meaning.
     */
    struct SettingKey
    {
      const char* key;
      int decimals;
      float min;
      float max;
      const char* help;
    };
    /** Every manifest setting in the file's order. */
    [[nodiscard]] const std::vector<SettingKey>& SettingKeys();
    /** The number or file name a key holds (null for the other kind or an unknown key). */
    [[nodiscard]] float* SettingNumber(Settings& s, const std::string& key);
    [[nodiscard]] std::string* SettingText(Settings& s, const std::string& key);
    /** Whether the manifest writes the key (given, or a value away from its "none"). */
    [[nodiscard]] bool SettingSet(const Settings& s, const std::string& key);
    /**
     * Set: the key is given (a number at its "none" takes its lowest value, a file name Studio's default name).
     * Unset: it goes, back to the value a manifest without it has.
     */
    void SetSettingGiven(Settings& s, const std::string& key, bool given);

    struct RayHit
    {
      float t = 0.0f; // distance along the (unit) direction
      float position[3] = {0, 0, 0};
      float normal[3] = {0, 1, 0};
      int patch = -1;
      int triangle = -1;
      int material = -1;
    };

    class MeshMap
    {
    public:
      std::string manifestPath; // VFS path of terrain.lua
      std::string dir;          // VFS path of its folder
      Settings settings;
      std::vector<Material> materials;
      std::vector<Patch> patches;
      std::string error;                 // why the last Load failed
      std::vector<std::string> warnings; // lines the reader didn't understand (Studio's V18)

      /// Reads the manifest and every patch through the engine's virtual file system. False (and `error`) when it names
      /// no patch or a file is unusable.
      bool Load(const std::string& manifestVfsPath);
      /** The manifest as text (what Load reads back): the settings, one line a material, one line a patch. */
      [[nodiscard]] std::string ManifestText() const;
      void Clear();
      bool Loaded() const
      {
        return !patches.empty();
      }

      std::uint32_t TotalVertices() const;
      std::uint32_t TotalTriangles() const;

      /// Highest mesh surface under (x, z) that lies at or below `ceiling`; sky patches never count. False when nothing
      /// is there.
      bool HeightAt(float x, float z, float ceiling, float& y) const;
      /// Nearest hit of the ray (unit direction) with a non-sky patch.
      bool Raycast(const float origin[3], const float dir[3], float maxDistance, RayHit& hit) const;

      /// Lowest / highest vertex height of the non-sky patches inside the playable rectangle grown by `margin`.
      bool HeightRange(float margin, float& low, float& high) const;

      /// Builds the lookup grid again (after Load; cheap enough to call on demand).
      void BuildGrid();

    private:
      struct Grid
      {
        float x0 = 0, z0 = 0, cell = 8.0f;
        int nx = 0, nz = 0;
        std::vector<std::uint32_t> start; // nx * nz + 1
        std::vector<std::uint32_t> items; // (patch << 24 | triangle) is not enough for 600k triangles: two arrays
        std::vector<std::uint32_t> itemPatch;
      };
      Grid grid_;
      bool gridBuilt_ = false;
      bool TriangleAt(int patch, int tri, float v[3][3]) const;
    };

    /// Parses the SCM v5 file `bytes` into `out` (vertices, indices, bounds). Why not when it is not usable.
    [[nodiscard]] std::expected<void, std::string> ParseScm(const std::uint8_t* bytes, std::size_t size, Patch& out);

    /// Reads a file through the reader the app set (the game's virtual file system); empty when it is missing.
    std::vector<std::uint8_t> ReadVfs(const std::string& path);
    /// The reader ReadVfs uses (the editor gives it the game's virtual file system; the tests a folder).
    void SetMeshFileReader(std::function<std::vector<std::uint8_t>(const std::string&)> reader);
  } // namespace edmesh
} // namespace faf::editor
