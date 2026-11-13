#pragma once

#include "editor/tools/EdGroundKind.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The map-wide textures FAF's terrain shaders read from a layer slot (FAF Studio's maptextures.lua): the map's
   * normals and its lighting (water depth, ambient occlusion, baked sun shadow) from the heights; its specular and its
   * macrotexture from the paint.
   */
  enum class MapTextureKind : std::uint8_t
  {
    Normals,
    Lighting,
    Specular,
    Macro,
  };
  inline constexpr int kMapTextureKinds = 4;

  /** How a slot's texture packs the map-wide data. */
  enum class MapTexturePack : std::uint8_t
  {
    None,
    Normal7,  // the numbered shaders' slot 8 normal map: r, g, b = the normal's z, a = its x
    Info7,    // the numbered shaders' slot 8 albedo: r = water depth, g, b = occlusion, a = shadow
    Light301, // TerrainPBR / Terrain301's Upper albedo: r = x, g = z of the normal, b = water depth, a = shadow
    Specular, // Terrain001 / 051's Upper albedo: rgb = the highlight's colour, a = its sharpness
    Macro,    // the Upper albedo of TTerrain, TTerrainXP(Ext), Terrain000 / 050: rgb = colour, a = how much
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

  /** What the specular and the macrotexture are made from: the share of the map each layer shows, its colour, its kind.
   */
  struct MapPaintLayer
  {
    bool textured = false;
    std::vector<float> visible; // 0..1 on the mask grid: what the layer shows (its weight, less the layers above)
    std::array<float, 3> colour{0.4f, 0.4f, 0.4f}; // its albedo's average colour
    GroundKind kind = GroundKind::Unknown;
  };
  struct MapPaint
  {
    int width = 0; // the mask grid, over the whole map
    int height = 0;
    std::array<MapPaintLayer, 9> layers; // 0 = the base layer, 1..8 the painted ones
  };

  /**
   * Fills `paint.layers[*].visible` from the masks (`texels`: the map's mask grid, byte k the weight of layer k + 1):
   * from the top painted layer down, each shows its weight times what the layers above leave free; the base layer shows
   * the rest. `painted`: the layers the shader blends (4, 7 or 8); `remapped`: RemappedStrata's bits. Layers that
   * aren't `textured` show nothing (their paint draws nothing).
   */
  void VisibleWeights(
    const std::uint64_t* texels,
    int width,
    int height,
    int painted,
    std::uint8_t remapped,
    MapPaint& paint
  );

  /** How the paint's textures are made (FAF Studio's MacroChannels / SpecularChannels). */
  struct MapPaintOptions
  {
    float contrast = 0.25f; // macro: lighter and darker in broad patches, this much either way
    float scale = 180.0f;   // macro: the patches' size, units
    int seed = 7;
    float cavity = 0.0f;    // macro: darker in cavities, 0..1
    float opacity = 0.35f;  // macro: how much it covers the ground
    float strength = 0.8f;  // specular: how strongly wet ground, snow and the waterline shine
    float sharpness = 1.0f; // specular
  };

  /**
   * Makes a paint-based texture (Specular or Macro packing) over the whole map, `size` pixels square, as MakeMapTexture
   * does. Macro: each pixel the colour the paint shows (each layer's average colour by what it shows), lighter and
   * darker in broad patches (a fractal noise) and darker in cavities, alpha the opacity. Specular: wet ground (1), snow
   * (0.6), plain rock (0.12) and the waterline (0.9) shine; rgb = 0.08 + shine * strength, alpha = 0.3 + 0.45 *
   * sharpness * shine.
   */
  bool MakePaintTexture(
    const std::vector<float>& heights,
    int width,
    int height,
    const MapPaint& paint,
    const MapTextureTarget& target,
    const MapTextureOptions& options,
    const MapPaintOptions& paintOptions,
    int size,
    std::vector<float>& rgba,
    std::string& error
  );
} // namespace faf::editor
