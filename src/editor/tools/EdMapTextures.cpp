#include "editor/tools/EdMapTextures.h"

#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdMaskBrush.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <memory>

namespace faf::editor
{
  namespace
  {
    /** "Terrain" and three digits, maybe a B: the numbered shaders (EdShaderSlots). */
    bool Numbered(
      const std::string& shader
    )
    {
      if (shader.rfind("Terrain", 0) != 0 || shader.size() < 10) {
        return false;
      }
      for (std::size_t i = 7; i < 10; ++i) {
        if (std::isdigit(static_cast<unsigned char>(shader[i])) == 0) {
          return false;
        }
      }
      return shader.size() == 10 || (shader.size() == 11 && shader[10] == 'B');
    }

    /** A field at world (x, z), bilinear, clamped at its edges. */
    float Sample(
      const field::Grid& grid,
      const float x,
      const float z
    )
    {
      const float gx = std::clamp((x - grid.ox) / grid.cell, 0.0f, static_cast<float>(grid.w - 1));
      const float gz = std::clamp((z - grid.oz) / grid.cell, 0.0f, static_cast<float>(grid.h - 1));
      const int x0 = static_cast<int>(gx);
      const int z0 = static_cast<int>(gz);
      const int x1 = std::min(x0 + 1, grid.w - 1);
      const int z1 = std::min(z0 + 1, grid.h - 1);
      const float fx = gx - static_cast<float>(x0);
      const float fz = gz - static_cast<float>(z0);
      const auto at = [&](const int i, const int j) {
        return grid.v[static_cast<std::size_t>(j) * static_cast<std::size_t>(grid.w) + static_cast<std::size_t>(i)];
      };
      const float top = at(x0, z0) + (at(x1, z0) - at(x0, z0)) * fx;
      const float bottom = at(x0, z1) + (at(x1, z1) - at(x0, z1)) * fx;
      return top + (bottom - top) * fz;
    }

    bool Op(
      const char* const name,
      field::OpArgs& args,
      field::Grid& out,
      std::string& error
    )
    {
      if (!field::RunOpCpu(name, args, out, error)) {
        error = std::string(name) + ": " + error;
        return false;
      }
      return true;
    }
  } // namespace

  MapTextureTarget MapTextureTargetOf(
    const std::string& shader,
    const MapTextureKind kind
  )
  {
    MapTextureTarget target;
    // The paint's textures go in the Upper layer's albedo (FAF Studio's shaders.lua MAPS: spec, ext, legacy).
    if (kind == MapTextureKind::Specular) {
      if (shader == "Terrain001" || shader == "Terrain051") {
        target.slot = 9;
        target.pack = MapTexturePack::Specular;
      }
      return target;
    }
    if (kind == MapTextureKind::Macro) {
      if (
        shader == "TTerrain" || shader == "TTerrainXP" || shader == "TTerrainGlow" || shader == "TTerrainXPExt" ||
        shader == "Terrain000" || shader == "Terrain050"
      ) {
        target.slot = 9;
        target.pack = MapTexturePack::Macro;
      }
      return target;
    }
    if (shader == "TerrainPBR" || shader == "Terrain301") {
      // One texture for both: the normal's x and z, the water depth, the shadow.
      target.slot = 9;
      target.pack = MapTexturePack::Light301;
      return target;
    }
    if (Numbered(shader) || shader == "TTerrainXPExt") {
      target.slot = 8;
      target.normalsPath = kind == MapTextureKind::Normals;
      target.pack = kind == MapTextureKind::Normals ? MapTexturePack::Normal7 : MapTexturePack::Info7;
    }
    return target;
  }

  float WaterDepthAt(
    const float ground,
    const MapTextureOptions& options
  )
  {
    if (!options.waterOn) {
      return 0.0f;
    }
    const float range = std::max(1.0f, options.waterElevation - options.abyss);
    return std::clamp((options.waterElevation - ground) / range, 0.0f, 1.0f);
  }

  bool MakeMapTexture(
    const std::vector<float>& heights,
    const int width,
    const int height,
    const MapTextureTarget& target,
    const MapTextureOptions& options,
    const int size,
    std::vector<float>& rgba,
    std::string& error
  )
  {
    if (
      !target.Valid() || width < 2 || height < 2 || size < 1 ||
      heights.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height)
    ) {
      error = "no heights or no map-wide slot for this shader";
      return false;
    }
    auto grid = std::make_shared<field::Grid>(width, height, 1.0f, 0.0f, 0.0f);
    grid->v = heights;
    const bool needNormals = target.pack == MapTexturePack::Normal7 || target.pack == MapTexturePack::Light301;
    const bool needLight = target.pack == MapTexturePack::Info7 || target.pack == MapTexturePack::Light301;

    // The normal as the engine's normal map has it (0..1), on the centres of the map squares.
    field::Grid nx;
    field::Grid nz;
    if (needNormals) {
      std::map<std::string, field::Grid> extra;
      field::OpArgs args;
      args.in["a"] = grid;
      args.p.num["span"] = 1.0;
      args.p.num["strength"] = options.normalStrength;
      args.p.num["shift"] = 0.5;
      args.extra = &extra;
      if (!Op("normal_map", args, nx, error)) {
        return false;
      }
      const auto z = extra.find("z");
      if (z == extra.end()) {
        error = "normal_map: no z";
        return false;
      }
      nz = std::move(z->second);
    }
    // The baked sun: the shadow averaged over samples of the sun's disc (soft edges), and the ambient occlusion.
    field::Grid lit;
    field::Grid occlusion;
    if (needLight) {
      std::vector<std::pair<float, float>> suns = {{options.azimuth, options.altitude}};
      if (options.quality >= 5 && options.soft > 0.0f) {
        for (const auto& [da, dl] :
             {std::pair{options.soft, 0.0f}, {-options.soft, 0.0f}, {0.0f, options.soft}, {0.0f, -options.soft}}) {
          suns.emplace_back(options.azimuth + da, std::clamp(options.altitude + dl, 1.0f, 89.0f));
        }
      }
      if (options.quality >= 9 && options.soft > 0.0f) {
        const float s = options.soft * 0.7f;
        for (const auto& [da, dl] : {std::pair{s, s}, {s, -s}, {-s, s}, {-s, -s}}) {
          suns.emplace_back(options.azimuth + da, std::clamp(options.altitude + dl, 1.0f, 89.0f));
        }
      }
      for (const auto& [az, alt] : suns) {
        field::OpArgs args;
        args.in["a"] = grid;
        args.p.str["mode"] = "shadow";
        args.p.num["azimuth"] = az;
        args.p.num["altitude"] = alt;
        args.p.num["shadow_len"] = options.reach;
        field::Grid shadow;
        if (!Op("hillshade", args, shadow, error)) {
          return false;
        }
        if (lit.v.empty()) {
          lit = std::move(shadow);
        } else {
          for (std::size_t i = 0; i < lit.v.size() && i < shadow.v.size(); ++i) {
            lit.v[i] += shadow.v[i];
          }
        }
      }
      // Shadow is 1 where cast: lit is 1 minus its average.
      for (float& v : lit.v) {
        v = 1.0f - v / static_cast<float>(suns.size());
      }
      if (options.occlusion > 0.0f) {
        field::OpArgs args;
        args.in["a"] = grid;
        args.p.str["mode"] = "cavity";
        args.p.num["radius"] = options.occlusionRadius;
        args.p.num["directions"] = 12;
        args.p.num["gain"] = 2;
        if (!Op("occlusion", args, occlusion, error)) {
          return false;
        }
        for (float& v : occlusion.v) {
          v = 1.0f - options.occlusion * v;
        }
      }
    }

    // Each pixel at the middle of its part of the map.
    rgba.assign(static_cast<std::size_t>(size) * static_cast<std::size_t>(size) * 4U, 0.0f);
    const float spanX = static_cast<float>(width - 1);
    const float spanZ = static_cast<float>(height - 1);
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        const float wx = (static_cast<float>(x) + 0.5f) / static_cast<float>(size) * spanX;
        const float wz = (static_cast<float>(y) + 0.5f) / static_cast<float>(size) * spanZ;
        float* const p = rgba.data() +
          (static_cast<std::size_t>(y) * static_cast<std::size_t>(size) + static_cast<std::size_t>(x)) * 4U;
        const float normalX = needNormals ? Sample(nx, wx, wz) : 0.5f;
        const float normalZ = needNormals ? Sample(nz, wx, wz) : 0.5f;
        const float shadow = needLight ? Sample(lit, wx, wz) : 1.0f;
        const float ao = needLight && !occlusion.v.empty() ? Sample(occlusion, wx, wz) : 1.0f;
        const float depth = needLight ? WaterDepthAt(Sample(*grid, wx, wz), options) : 0.0f;
        switch (target.pack) {
        case MapTexturePack::Normal7:
          p[0] = normalZ;
          p[1] = normalZ;
          p[2] = normalZ;
          p[3] = normalX;
          break;
        case MapTexturePack::Info7:
          p[0] = depth;
          p[1] = ao;
          p[2] = ao;
          p[3] = shadow;
          break;
        case MapTexturePack::Light301:
          p[0] = normalX;
          p[1] = normalZ;
          p[2] = depth;
          p[3] = shadow;
          break;
        case MapTexturePack::None:
        case MapTexturePack::Specular:
        case MapTexturePack::Macro:
          break;
        }
      }
    }
    return true;
  }

  void VisibleWeights(
    const std::uint64_t* const texels,
    const int width,
    const int height,
    const int painted,
    const std::uint8_t remapped,
    MapPaint& paint
  )
  {
    paint.width = width;
    paint.height = height;
    const std::size_t count = texels == nullptr || width < 1 || height < 1
      ? 0U
      : static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    for (MapPaintLayer& layer : paint.layers) {
      layer.visible.assign(count, 0.0f);
    }
    const int top = std::clamp(painted, 0, 8);
    for (std::size_t i = 0; i < count; ++i) {
      float free = 1.0f;
      for (int layer = top; layer >= 1; --layer) {
        MapPaintLayer& entry = paint.layers[static_cast<std::size_t>(layer)];
        if (!entry.textured) {
          continue;
        }
        const int byte = layer - 1;
        const float m = MaskWeight(MaskByte(texels[i], byte), (remapped & (1U << byte)) != 0) / 255.0f;
        entry.visible[i] = m * free;
        free *= 1.0f - m;
      }
      paint.layers[0].visible[i] = free;
    }
  }

  bool MakePaintTexture(
    const std::vector<float>& heights,
    const int width,
    const int height,
    const MapPaint& paint,
    const MapTextureTarget& target,
    const MapTextureOptions& options,
    const MapPaintOptions& paintOptions,
    const int size,
    std::vector<float>& rgba,
    std::string& error
  )
  {
    const bool macro = target.pack == MapTexturePack::Macro;
    if (
      (!macro && target.pack != MapTexturePack::Specular) || width < 2 || height < 2 || size < 1 ||
      heights.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height) || paint.width < 1 ||
      paint.height < 1
    ) {
      error = "no heights, no masks or no slot for this kind";
      return false;
    }
    auto grid = std::make_shared<field::Grid>(width, height, 1.0f, 0.0f, 0.0f);
    grid->v = heights;
    const float spanX = static_cast<float>(width - 1);
    const float spanZ = static_cast<float>(height - 1);
    // The masks as fields over the same world units as the heights.
    const float maskCell = spanX / static_cast<float>(paint.width);
    const auto maskField = [&](const std::vector<float>& values) {
      field::Grid f(paint.width, paint.height, maskCell, maskCell * 0.5f, maskCell * 0.5f);
      f.v = values;
      return f;
    };

    field::Grid noise;
    field::Grid cavity;
    std::array<field::Grid, 3> colour;
    field::Grid shine;
    if (macro) {
      // The colour the paint shows.
      for (int c = 0; c < 3; ++c) {
        std::vector<float> sum(static_cast<std::size_t>(paint.width) * static_cast<std::size_t>(paint.height), 0.0f);
        for (const MapPaintLayer& layer : paint.layers) {
          if (layer.visible.size() != sum.size()) {
            continue;
          }
          for (std::size_t i = 0; i < sum.size(); ++i) {
            sum[i] += layer.visible[i] * layer.colour[static_cast<std::size_t>(c)];
          }
        }
        colour[static_cast<std::size_t>(c)] = maskField(sum);
      }
      field::OpArgs args;
      args.in["like"] = grid;
      args.p.num["seed"] = paintOptions.seed;
      args.p.num["scale"] = paintOptions.scale;
      args.p.num["octaves"] = 5;
      if (!Op("fractal", args, noise, error)) {
        return false;
      }
      if (paintOptions.cavity > 0.0f) {
        field::OpArgs cavityArgs;
        cavityArgs.in["a"] = grid;
        cavityArgs.p.str["mode"] = "cavity";
        cavityArgs.p.num["radius"] = 30;
        cavityArgs.p.num["directions"] = 12;
        cavityArgs.p.num["gain"] = 2;
        if (!Op("occlusion", cavityArgs, cavity, error)) {
          return false;
        }
      }
    } else {
      // What shines: wet ground, snow, plain rock a little; the strongest wins.
      // The layers of one kind add up; the kinds take the strongest (FAF Studio's RoleWeights, then max).
      const std::size_t cells = static_cast<std::size_t>(paint.width) * static_cast<std::size_t>(paint.height);
      std::vector<float> sum(cells, 0.0f);
      for (const auto& [kind, k] :
           {std::pair{GroundKind::Wet, 1.0f}, {GroundKind::Snow, 0.6f}, {GroundKind::Rock, 0.12f}}) {
        std::vector<float> ofKind(cells, 0.0f);
        bool any = false;
        for (const MapPaintLayer& layer : paint.layers) {
          if (layer.kind != kind || layer.visible.size() != cells) {
            continue;
          }
          any = true;
          for (std::size_t i = 0; i < cells; ++i) {
            ofKind[i] += layer.visible[i];
          }
        }
        if (any) {
          for (std::size_t i = 0; i < cells; ++i) {
            sum[i] = std::max(sum[i], ofKind[i] * k);
          }
        }
      }
      shine = maskField(sum);
    }

    rgba.assign(static_cast<std::size_t>(size) * static_cast<std::size_t>(size) * 4U, 0.0f);
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        const float wx = (static_cast<float>(x) + 0.5f) / static_cast<float>(size) * spanX;
        const float wz = (static_cast<float>(y) + 0.5f) / static_cast<float>(size) * spanZ;
        float* const p = rgba.data() +
          (static_cast<std::size_t>(y) * static_cast<std::size_t>(size) + static_cast<std::size_t>(x)) * 4U;
        if (macro) {
          float k = 1.0f - paintOptions.contrast + 2.0f * paintOptions.contrast * Sample(noise, wx, wz);
          if (!cavity.v.empty()) {
            k *= 1.0f - paintOptions.cavity * Sample(cavity, wx, wz);
          }
          for (int c = 0; c < 3; ++c) {
            p[c] = std::clamp(Sample(colour[static_cast<std::size_t>(c)], wx, wz) * k, 0.0f, 1.0f);
          }
          p[3] = paintOptions.opacity;
          continue;
        }
        float s = Sample(shine, wx, wz);
        if (options.waterOn) {
          // The waterline: 1 within 2.5 units of the sea, fading over 3 more (the field library's `shore`).
          const float d = std::fabs(Sample(*grid, wx, wz) - options.waterElevation);
          const float t = std::clamp((5.5f - d) / 3.0f, 0.0f, 1.0f);
          const float band = d <= 2.5f ? 1.0f : t * t * (3.0f - 2.0f * t);
          s = std::max(s, band * 0.9f);
        }
        const float level = std::clamp(0.08f + s * paintOptions.strength, 0.0f, 1.0f);
        p[0] = level;
        p[1] = level;
        p[2] = level;
        p[3] = std::clamp(0.3f + 0.45f * paintOptions.sharpness * s, 0.0f, 1.0f);
      }
    }
    return true;
  }
} // namespace faf::editor
