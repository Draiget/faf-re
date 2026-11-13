#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The map-wide textures FAF's newer terrain shaders read from a layer slot whose size is above the map's (FAF
   * Studio's maptextures.lua): the map's normals, and its lighting (water depth, ambient occlusion, baked sun shadow).
   */
  enum class MapTextureKind : std::uint8_t
  {
    Normals,
    Lighting,
  };

  /** How a slot's texture packs the map-wide data. */
  enum class MapTexturePack : std::uint8_t
  {
    None,
    Normal7,  // the numbered shaders' slot 8 normal map: r, g, b = the normal's z, a = its x
    Info7,    // the numbered shaders' slot 8 albedo: r = water depth, g, b = occlusion, a = shadow
    Light301, // TerrainPBR / Terrain301's Upper albedo: r = x, g = z of the normal, b = water depth, a = shadow
  };

  /** Where a kind goes for a shader: the slot (0..9), whether its normal-map path (else its albedo), and the packing.
   */
  struct MapTextureTarget
  {
    int slot = -1;
    bool normalsPath = false;
    MapTexturePack pack = MapTexturePack::None;
    [[nodiscard]] bool Valid() const noexcept
    {
      return slot >= 0 && pack != MapTexturePack::None;
    }
  };
  [[nodiscard]] MapTextureTarget MapTextureTargetOf(const std::string& shader, MapTextureKind kind);

  /** What the lighting texture is made from: the sun, its softness, the occlusion, the sea. */
  struct MapTextureOptions
  {
    float azimuth = 315.0f; // degrees towards the sun, 0 = +x, 90 = +z (SunAnglesOf)
    float altitude = 40.0f;
    float soft = 1.0f;      // degrees: the sun's size, softening the shadow's edge
    int quality = 5;        // samples of the sun's disc: 1, 5 or 9
    float reach = 400.0f;   // units a shadow can be cast
    float occlusion = 0.5f; // 0..1
    float occlusionRadius = 40.0f;
    bool waterOn = true;
    float waterElevation = 25.0f;
    float abyss = 0.0f;
    float normalStrength = 1.0f;
  };

  /**
   * Makes the texture a target packs from the map's heights (`width` x `height` samples in game units, rows along z),
   * `size` pixels square over the whole map: `rgba` holds size * size * 4 values 0..1, rows along z. False with `error`
   * when an op fails.
   */
  bool MakeMapTexture(
    const std::vector<float>& heights,
    int width,
    int height,
    const MapTextureTarget& target,
    const MapTextureOptions& options,
    int size,
    std::vector<float>& rgba,
    std::string& error
  );

  /** The water's depth over the ground, 0 on land to 1 at the abyss (the lighting texture's red). */
  [[nodiscard]] float WaterDepthAt(float ground, const MapTextureOptions& options);
} // namespace faf::editor
