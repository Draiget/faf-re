#include "editor/tools/EdAlphaGen.h"

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <memory>

namespace faf::editor
{
  namespace
  {
    constexpr float kRoughMin = 0.45f;
    constexpr float kRoughMax = 0.92f;
    constexpr float kRoughNeutral = 0.65f;
    constexpr float kRoughDetail = 0.30f;
    constexpr float kHeightSpread = 0.16f;
    constexpr std::size_t kCount = static_cast<std::size_t>(kAtlasTile) * kAtlasTile;

    void MeanSd(
      const std::vector<float>& list,
      float& mean,
      float& sd
    )
    {
      double sum = 0.0;
      for (const float v : list) {
        sum += v;
      }
      mean = static_cast<float>(sum / static_cast<double>(std::max<std::size_t>(1, list.size())));
      double sq = 0.0;
      for (const float v : list) {
        const double d = v - mean;
        sq += d * d;
      }
      sd = static_cast<float>(std::sqrt(sq / static_cast<double>(std::max<std::size_t>(1, list.size()))));
    }
  } // namespace

  void ApplyAtlasStyle(
    const std::string& style,
    AtlasSettings& s,
    float& splatSoft,
    float& splatContrast
  )
  {
    if (style == "default") {
      s = AtlasSettings{1.0f, 1.0f, 0.35f, 1.0f};
    } else if (style == "soft") {
      s = AtlasSettings{0.5f, 0.3f, 0.35f, 1.0f};
      splatSoft = 0.7f;
      splatContrast = 0.8f;
    } else if (style == "patchy") {
      s = AtlasSettings{2.0f, 2.0f, 0.35f, 1.0f};
      splatSoft = 0.3f;
      splatContrast = 1.5f;
    }
  }

  float KindRoughness(
    const GroundKind kind
  )
  {
    switch (kind) {
    case GroundKind::Grass:
      return 0.74f;
    case GroundKind::Dirt:
      return 0.80f;
    case GroundKind::Wet:
      return 0.48f;
    case GroundKind::Sand:
      return 0.82f;
    case GroundKind::Rock:
      return 0.88f;
    case GroundKind::DarkRock:
      return 0.90f;
    case GroundKind::HighRock:
      return 0.86f;
    case GroundKind::Snow:
      return 0.55f;
    default:
      return kRoughNeutral;
    }
  }

  float KindHeightStep(
    const GroundKind kind
  )
  {
    switch (kind) {
    case GroundKind::Rock:
      return 0.20f;
    case GroundKind::HighRock:
      return 0.24f;
    case GroundKind::DarkRock:
      return 0.16f;
    case GroundKind::Snow:
      return 0.10f;
    case GroundKind::Dirt:
      return -0.05f;
    case GroundKind::Grass:
      return -0.12f;
    case GroundKind::Wet:
      return -0.20f;
    default:
      return 0.0f;
    }
  }

  bool MakeAtlasTile(
    const std::vector<std::uint8_t>& albedo,
    const std::vector<std::uint8_t>& normal,
    const GroundKind kind,
    const AtlasSettings& o,
    AtlasTile& out,
    std::string& error
  )
  {
    if (albedo.size() != kCount * 4) {
      error = "the albedo isn't " + std::to_string(kAtlasTile) + " pixels square";
      return false;
    }
    const int n = kAtlasTile;
    std::vector<float> lum(kCount);
    for (std::size_t i = 0; i < kCount; ++i) {
      // B G R A
      lum[i] = (0.299f * albedo[i * 4 + 2] + 0.587f * albedo[i * 4 + 1] + 0.114f * albedo[i * 4]) / 255.0f;
    }
    const bool haveNormal = normal.size() == kCount * 4;
    std::vector<float> relief;
    if (haveNormal) {
      // The normal's slopes integrated into the height they describe (n = -grad h; the textures tile: periodic).
      auto dx = std::make_shared<field::Grid>(n, n, 1.0f, 0.0f, 0.0f);
      auto dz = std::make_shared<field::Grid>(n, n, 1.0f, 0.0f, 0.0f);
      for (std::size_t i = 0; i < kCount; ++i) {
        const float x = normal[i * 4 + 2] / 127.5f - 1.0f; // R
        const float y = normal[i * 4 + 1] / 127.5f - 1.0f; // G
        const float zz = std::max(0.04f, 1.0f - x * x - y * y);
        const float inv = 1.0f / std::sqrt(zz);
        dx->v[i] = -x * inv;
        dz->v[i] = -y * inv;
      }
      field::OpArgs args;
      args.in["dx"] = dx;
      args.in["dz"] = dz;
      args.p.num["periodic"] = 1.0;
      field::Grid h;
      std::string why;
      if (!field::RunOpCpu("height_from_gradient", args, h, why) || h.v.size() != kCount) {
        error = "the normal map's relief: " + why;
        return false;
      }
      relief = std::move(h.v);
    }
    float lm = 0.0f, ls = 0.0f, hm = 0.0f, hs = 0.0f;
    MeanSd(lum, lm, ls);
    if (haveNormal) {
      MeanSd(relief, hm, hs);
    }
    const float wc = haveNormal ? o.cavity : 0.0f;
    const float spread = kHeightSpread * o.spread;
    const float gl = ls > 0.002f ? spread / ls : 0.0f;
    const float gh = hs > 1.0e-6f ? spread / hs : 0.0f;
    const float bias = KindHeightStep(kind) * o.biasScale;
    const float baseRough = KindRoughness(kind);
    out.height.assign(kCount, 0.5f);
    out.rough.assign(kCount, baseRough);
    for (std::size_t i = 0; i < kCount; ++i) {
      const float l = (lum[i] - lm) * gl;
      const float c = haveNormal ? (relief[i] - hm) * gh : 0.0f;
      out.height[i] = std::clamp(0.5f + bias + (1.0f - wc) * l + wc * c, 0.05f, 0.95f);
      out.rough[i] = std::clamp(baseRough - kRoughDetail * o.roughDetail * l * 2.0f, kRoughMin, kRoughMax);
    }
    return true;
  }

  void PackAtlas(
    const std::array<const AtlasTile*, 8>& tiles,
    const std::array<GroundKind, 8>& kinds,
    const AtlasSettings& o,
    const int size,
    std::vector<float>& rgba
  )
  {
    const int s = std::max(8, size);
    const int half = s / 2;
    rgba.assign(static_cast<std::size_t>(s) * s * 4, 0.0f);
    for (int layer = 0; layer < 8; ++layer) {
      const int t = layer % 4;
      const int ox = (t % 2) * half;
      const int oz = (t / 2) * half;
      const std::size_t roughChannel = layer < 4 ? 0 : 2;
      const AtlasTile* tile = tiles[static_cast<std::size_t>(layer)];
      const float neutralHeight =
        std::clamp(0.5f + KindHeightStep(kinds[static_cast<std::size_t>(layer)]) * o.biasScale, 0.05f, 0.95f);
      for (int pz = 0; pz < half; ++pz) {
        // The picture twice in each direction: the tile's half holds it once.
        const int sz = (pz * 2 * kAtlasTile / half) % kAtlasTile;
        for (int px = 0; px < half; ++px) {
          const int sx = (px * 2 * kAtlasTile / half) % kAtlasTile;
          const std::size_t at = (static_cast<std::size_t>(oz + pz) * s + static_cast<std::size_t>(ox + px)) * 4;
          if (tile != nullptr && tile->rough.size() == kCount) {
            const std::size_t src = static_cast<std::size_t>(sz) * kAtlasTile + static_cast<std::size_t>(sx);
            rgba[at + roughChannel] = tile->rough[src];
            rgba[at + roughChannel + 1] = tile->height[src];
          } else {
            rgba[at + roughChannel] = kRoughNeutral;
            rgba[at + roughChannel + 1] = neutralHeight;
          }
        }
      }
    }
  }
  ShaderAlphaUse ShaderAlphaOf(
    const std::string_view shader
  )
  {
    std::string low(shader);
    for (char& c : low) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    ShaderAlphaUse use;
    if (low == "tterrain") {
      use.layers = LayerAlphaUse::Matte;
    } else if (low == "tterrainglow") {
      use.layers = LayerAlphaUse::Glow;
    } else if (low == "tterrainxp" || low == "tterrainxpext" || low == "terrain000" || low == "terrain050") {
      use.layers = LayerAlphaUse::Specularity;
    } else if (low == "terrain001" || low == "terrain051") {
      use.layers = LayerAlphaUse::Unused;
      use.baseOpacity = true;
    } else if (
      low.size() >= 10 && low.rfind("terrain", 0) == 0 && (low[7] == '1' || low[7] == '2') &&
      std::isdigit(static_cast<unsigned char>(low[8])) != 0 && std::isdigit(static_cast<unsigned char>(low[9])) != 0
    ) {
      // Terrain1xx / 2xx (a B at the end: biplanar): roughness and height from the atlas; the last digit 1 or 2 lays
      // the base texture over the map by its alpha.
      use.layers = LayerAlphaUse::Unused;
      use.baseOpacity = low[9] == '1' || low[9] == '2';
    } else if (low == "terrain301") {
      use.layers = LayerAlphaUse::Unused;
    }
    return use;
  }

  float KindSpecularity(
    const GroundKind kind
  )
  {
    switch (kind) {
    case GroundKind::Grass:
      return 0.18f;
    case GroundKind::Dirt:
      return 0.15f;
    case GroundKind::Wet:
      return 0.85f;
    case GroundKind::Sand:
      return 0.30f;
    case GroundKind::Rock:
      return 0.25f;
    case GroundKind::DarkRock:
      return 0.20f;
    case GroundKind::HighRock:
      return 0.30f;
    case GroundKind::Snow:
      return 0.70f;
    default:
      return 0.30f;
    }
  }

  void SetSpecularityAlpha(
    std::vector<std::uint8_t>& bgra,
    const GroundKind kind,
    const bool matte,
    const TextureAlphaMode mode,
    const float detail,
    const float amount
  )
  {
    const std::size_t n = bgra.size() / 4;
    if (n == 0 || mode == TextureAlphaMode::Off) {
      return;
    }
    const float base = KindSpecularity(kind);
    const float target = matte ? 1.0f - base : base;
    const auto store = [&](const std::size_t i, const float a) {
      bgra[i * 4 + 3] = static_cast<std::uint8_t>(std::lround(std::clamp(a, 0.02f, 0.98f) * 255.0f));
    };
    if (mode == TextureAlphaMode::Adjust) {
      const float w = std::clamp(amount, 0.0f, 1.0f);
      for (std::size_t i = 0; i < n; ++i) {
        store(i, bgra[i * 4 + 3] / 255.0f * (1.0f - w) + w * target);
      }
      return;
    }
    std::vector<float> lum(n);
    double sum = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
      lum[i] = (0.299f * bgra[i * 4 + 2] + 0.587f * bgra[i * 4 + 1] + 0.114f * bgra[i * 4]) / 255.0f;
      sum += lum[i];
    }
    const float mean = static_cast<float>(sum / static_cast<double>(n));
    const float scale = matte ? -detail : detail;
    for (std::size_t i = 0; i < n; ++i) {
      store(i, target + scale * (lum[i] - mean));
    }
  }

  void SetConstantAlpha(
    std::vector<std::uint8_t>& bgra,
    const float value
  )
  {
    const auto a = static_cast<std::uint8_t>(std::lround(std::clamp(value, 0.0f, 1.0f) * 255.0f));
    for (std::size_t i = 3; i < bgra.size(); i += 4) {
      bgra[i] = a;
    }
  }
} // namespace faf::editor
