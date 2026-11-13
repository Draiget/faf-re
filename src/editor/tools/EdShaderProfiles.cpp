#include "editor/tools/EdShaderProfiles.h"

#include "editor/tools/EdMaskBrush.h"

#include <cctype>

namespace faf::editor
{
  namespace
  {
    const char* const kXyz = "XYZ";
    const char* const kUnused = "not used";
    const char* const kSpec = "RGB, alpha = specularity";
    const char* const kRgb = "RGB (alpha not used)";
    const char* const kMatte = "RGB, alpha: specular amount = 1 - alpha";
    const char* const kNotDrawn = "not drawn";

    struct Cell
    {
      std::string albedo;
      std::string normal;
    };

    /** Base, layers 1-7 (`at[i]` overriding `painted` for layer i + 1), layer 8, Upper. */
    std::vector<ShaderLayerRow> Rows(
      const Cell& base,
      const Cell& painted,
      const Cell& layer8,
      const Cell& upper,
      const std::vector<std::pair<int, Cell>>& at = {}
    )
    {
      std::vector<ShaderLayerRow> rows;
      rows.push_back({"Base", base.albedo, base.normal});
      for (int i = 1; i <= 7; ++i) {
        Cell cell = painted;
        for (const auto& [layer, other] : at) {
          if (layer == i) {
            cell = other;
          }
        }
        rows.push_back({"Layer " + std::to_string(i), cell.albedo, cell.normal});
      }
      rows.push_back({"Layer 8", layer8.albedo, layer8.normal});
      rows.push_back({"Upper", upper.albedo, upper.normal});
      return rows;
    }

    const Cell kNone{kNotDrawn, kNotDrawn};
    const Cell kOverlay{"RGB, alpha = opacity (laid over everything)", kUnused};

    const char* const kLayoutOld =
      "Layers: Base, painted layers 1-4, Upper. Albedo RGB plus an alpha that sets the specular amount; normals XYZ.";
    const char* const kLayoutXp = "Layers: Base, painted layers 1-8, Upper. Albedo RGB plus alpha = specularity; "
                                  "normals XYZ. The Upper layer is an overlay whose alpha is its opacity.";
    const char* const kLayoutExt =
      "Layers: Base, painted layers 1-7 (the 8th is not painted), Upper. Albedo RGB plus alpha = specularity; normals "
      "XYZ. The Upper layer is a macrotexture (RGB) with its opacity in alpha. The map's own normal map and shadow map "
      "are used (the engine writes them).";
    const char* const kLayoutSpec =
      "Layers: Base, painted layers 1-7, Upper. Albedo RGB; normals XYZ. The Upper layer is the specular texture of "
      "the whole map: specular colour RGB and sharpness in alpha. The 8th layer's albedo alpha is read as the baked "
      "shadow.";
    const char* const kLayoutPbr =
      "Layers: Base, painted layers 1-7, Upper. Albedo RGB; normals XYZ. The roughness of every layer comes from the "
      "Upper layer, a small atlas texture, not from the albedo alpha. The mask of layer 8 is not painted: it is a "
      "roughness multiplier (128 = neutral).";
    const char* const kLayoutSplat =
      "Layers: Base, painted layers 1-7, Upper. Albedo RGB; normals XYZ. Roughness and the heights used for splatting "
      "come from the Upper layer, a small atlas texture. The mask of layer 8 is a roughness multiplier (128 = "
      "neutral). "
      "The normal tile sizes follow the albedo tile sizes (except on the base layer).";
    const char* const kNaming =
      "Naming: the first digit is the lighting (0 = the old specularity, 1 = PBR roughness, 2 = PBR roughness and "
      "height splatting); the middle digit 0 = the full mask range, 5 = only the upper half of it; a letter B at the "
      "end means biplanar mapping (steep ground is textured from the side).";
    const char* const kNoteAtlas =
      "Upper atlas: 2 x 2 tiles. The tile of the Base layer and layers 1-3 (top left, top right, bottom left, bottom "
      "right) hold their roughness in R and their height in G; layers 4-7 use the same tiles in B (roughness) and A "
      "(height). The shader reads only the middle half of a tile, so a tile holds its picture twice in each direction.";
    const char* const kNoteRough =
      "Layer 8 has no paint: its mask is a roughness multiplier (128 = neutral, lower = shinier, higher = rougher).";

    std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return out;
    }

    /** Terrain1xx / Terrain2xx, with or without B, from its name (FAF Studio's PbrInfo). */
    bool PbrProfile(
      const std::string& name,
      ShaderProfile& p
    )
    {
      const std::string low = Lower(name);
      const bool biplanar = low.size() == 11 && low[10] == 'b';
      if (
        (low.size() != 10 && !biplanar) || low.rfind("terrain", 0) != 0 || (low[7] != '1' && low[7] != '2') ||
        std::isdigit(static_cast<unsigned char>(low[8])) == 0 || std::isdigit(static_cast<unsigned char>(low[9])) == 0
      ) {
        return false;
      }
      const bool splat = low[7] == '2';
      const bool half = low[8] == '5';
      const char tail = low[9];
      const char* const macro = tail == '1'
        ? "the base layer's texture is blended over the map by its alpha as a macrotexture"
        : tail == '2' ? "the base layer's texture multiplies the map by its alpha as a macrotexture"
                      : nullptr;
      p.family = splat ? ShaderFamily::Splat : ShaderFamily::Pbr;
      p.known = true;
      p.painted = 7;
      p.summary = std::string(splat ? "Height splatting" : "PBR") + (biplanar ? ", biplanar" : "") +
        (half ? ", half mask range" : ", full mask range") + (macro != nullptr ? std::string("; ") + macro : "");
      p.instructions =
        std::string(
          splat ? "PBR lighting with height-based splatting: layers are mixed by comparing heights (from "
                  "the Upper atlas), so ground shows through rock and mud collects in dips. "
                : "PBR lighting (roughness from the Upper atlas) with UDN normal blending. "
        ) +
        (half ? "Only the upper half of the mask range counts. " : "Full mask range. ") +
        (biplanar ? "Biplanar mapping: layers 3 and 4 are textured only from the side (never from above, also on flat "
                    "ground), so cliffs are not stretched: put cliff textures on them and paint them on steep ground "
                    "only. The shader also always reads the map-wide normal map and water depth in layer 8. "
                  : "") +
        (macro != nullptr ? std::string("Macrotexture: ") + macro + "." : "") +
        (splat ? " The splatting's settings are the map's SpecularColor: r = how soft the transitions are (0.06 sharp, "
                 "1 plain blending), g = contrast of the heights, b and a = cosine and sine of the rotation of every "
                 "second layer (0.866 and 0.5 = 30 degrees). All four at 0, as in a map made for another shader, draw "
                 "those layers as flat colours."
               : "");
      p.layout = splat ? kLayoutSplat : kLayoutPbr;
      const Cell cliff{"RGB, mapped only from the side (cliffs)", "XYZ, mapped only from the side"};
      const Cell layer8 = biplanar
        ? Cell{"R = water depth (map-wide data, always read)", "A = terrain normal x, G = z (map-wide data, always read)"}
        : Cell{
            "map-wide data only when its tile size is above the map size (R water depth, G occlusion, A shadow)",
            "map-wide normal map when its tile size is above the map size"
          };
      p.rows = Rows(
        {macro != nullptr ? "RGB, alpha = macrotexture opacity" : kRgb, kXyz},
        {kRgb, kXyz},
        layer8,
        {splat ? "roughness and height atlas" : "roughness atlas", kUnused},
        biplanar ? std::vector<std::pair<int, Cell>>{{3, cliff}, {4, cliff}} : std::vector<std::pair<int, Cell>>{}
      );
      p.notes = {
        half ? "Masks use the half range: a byte up to 127 means none."
             : "Masks use the full range: the byte is the share of the layer.",
        kNoteRough,
        kNoteAtlas
      };
      if (splat) {
        p.notes.emplace_back(
          "The map's SpecularColor holds the splat settings: r = softness, g = height contrast, b / a = cos / sin of "
          "the rotation (0.2, 0.6, 0.866, 0.5 are good values). All zero gives flat colours."
        );
      }
      if (biplanar) {
        p.notes.emplace_back(
          "Layers 3 and 4 are textured only from the side, even on flat ground: use them for cliff textures and paint "
          "them on steep ground."
        );
      }
      return true;
    }
  } // namespace

  const char* ShaderFamilyName(
    const ShaderFamily family
  )
  {
    switch (family) {
    case ShaderFamily::Original:
      return "Original";
    case ShaderFamily::Extended:
      return "Extended (0xx)";
    case ShaderFamily::Pbr:
      return "PBR (1xx)";
    case ShaderFamily::Splat:
      return "PBR + height splatting (2xx)";
    default:
      return "Older / special";
    }
  }

  std::string MaskRangeText(
    const std::uint8_t remapped
  )
  {
    if (remapped == 0) {
      return "full range (the byte is the share of the layer)";
    }
    if (remapped == 0xFF) {
      return "half range (bytes up to 127 show nothing, 255 shows all)";
    }
    return "half range for layers 1-7, full range for layer 8";
  }

  ShaderProfile ShaderProfileOf(
    const std::string_view name
  )
  {
    ShaderProfile p;
    p.name = std::string(name);
    p.remapped = RemappedStrata(name);
    const std::string low = Lower(name);
    const auto set = [&](
                       const ShaderFamily family,
                       const char* const summary,
                       std::string instructions,
                       const char* const layout,
                       std::vector<ShaderLayerRow> rows,
                       std::vector<std::string> notes,
                       const int painted
                     ) {
      p.family = family;
      p.known = true;
      p.summary = summary;
      p.instructions = std::move(instructions);
      p.layout = layout;
      p.rows = std::move(rows);
      p.notes = std::move(notes);
      p.painted = painted;
    };
    const Cell matte{kMatte, kXyz};
    const Cell spec{kSpec, kXyz};
    const Cell extLayer8{"map-wide data when its tile size is below 1: R water depth, G occlusion, A shadow", kUnused};
    const Cell extUpper{"macrotexture RGB, alpha = opacity", kUnused};
    const Cell specBase{"RGB, alpha = macrotexture opacity (drawn over everything again)", kXyz};
    const Cell specLayer8{"map-wide data: alpha = baked shadow (always read)", kUnused};
    const Cell specUpper{"specular RGB, alpha = sharpness", kUnused};
    if (low == "tterrain") {
      set(
        ShaderFamily::Original,
        "The shader of the original Supreme Commander.",
        "Blends only the painted layers 1-4 over the base layer; layers 5-8 are not drawn. Choose it only for a map "
        "that has to look like the original game; use TTerrainXP for everything else. The alpha of the albedo textures "
        "works the other way round than in TTerrainXP: the specular amount is 1 - alpha.",
        kLayoutOld,
        Rows(matte, matte, kNone, kOverlay, {{5, kNone}, {6, kNone}, {7, kNone}}),
        {"Only layers 1-4 are blended; paint on layers 5-8 is not drawn."},
        4
      );
    } else if (low == "tterrainxp") {
      set(
        ShaderFamily::Original,
        "The Forged Alliance shader: the default of nearly every map.",
        "Blends all eight painted layers and the upper layer. Masks are read as saturate(2m - 1), so the paint brushes "
        "store half-range masks (the editor does it for you). Normals are blended by plain lerps on the masks as they "
        "are, so they follow the paint a little more broadly than the colours.",
        kLayoutXp,
        Rows(spec, spec, spec, kOverlay),
        {"Masks use the half range: a byte up to 127 means none, 255 means fully this layer."},
        8
      );
    } else if (low == "tterrainglow") {
      set(
        ShaderFamily::Original,
        "TTerrain where the alpha of the first painted layer is animated as a glow.",
        "Like TTerrain (painted layers 1-4) but the alpha of the first painted layer's texture is animated and used as "
        "a glow channel. Use it for lava or energy ground; give that layer an albedo whose alpha is the glow mask.",
        kLayoutOld,
        Rows(
          matte,
          matte,
          kNone,
          kOverlay,
          {{1, Cell{"RGB, alpha = glow mask (animated)", kXyz}}, {5, kNone}, {6, kNone}, {7, kNone}}
        ),
        {"Only layers 1-4 are blended; paint on layers 5-8 is not drawn."},
        4
      );
    } else if (low == "tterrainxpext") {
      set(
        ShaderFamily::Extended,
        "Drop-in replacement for TTerrainXP that adds the map-wide normals and shadows.",
        "Keeps the mask ranges of TTerrainXP (half range for the colours), so an existing map looks the same. Choose "
        "it "
        "to upgrade a TTerrainXP map without repainting.",
        kLayoutExt,
        Rows(spec, spec, extLayer8, extUpper),
        {"Layer 8 has no paint. Masks use the half range for the colours, like TTerrainXP."},
        7
      );
    } else if (low == "terrain000" || low == "terrain050") {
      const bool half = low == "terrain050";
      set(
        ShaderFamily::Extended,
        half ? "Like Terrain000, but only the upper half of the mask range counts."
             : "Like TTerrainXPExt, with the full mask range for albedo and normals.",
        std::string(
          half ? "Uses only the upper half of the mask range, which is what maps made for TTerrainXP store. Easiest "
                 "choice when converting an existing map."
               : "Both albedo and normals use the whole mask range (0-255). Paint layers normally; there is no "
                 "half-range conversion. Good for new maps that only need the extended shader."
        ) +
          "\n" + kNaming,
        kLayoutExt,
        Rows(spec, spec, extLayer8, extUpper),
        {half ? "Layer 8 has no paint. Masks use the half range: a byte up to 127 means none."
              : "Layer 8 has no paint. Masks use the full range: the byte is the share of the layer."},
        7
      );
    } else if (low == "terrain001" || low == "terrain051") {
      const bool half = low == "terrain051";
      set(
        ShaderFamily::Extended,
        half ? "Terrain001 with only the upper half of the mask range."
             : "UDN normal blending and a specularity texture on the upper layer.",
        std::string(
          "Normals are blended with UDN blending. The base layer's albedo is drawn first and blended over everything "
          "again by its alpha. The upper layer is not a macrotexture: its RGB is the specular colour and its alpha the "
          "specular sharpness, which gives fine control over the shine of the whole map."
        ) +
          (half ? " Only the upper half of the mask range counts (maps converted from TTerrainXP)." : "") + "\n" +
          kNaming,
        kLayoutSpec,
        Rows(specBase, Cell{kRgb, kXyz}, specLayer8, specUpper),
        {half ? "Layer 8 has no paint. Masks use the half range." : "Layer 8 has no paint. Masks use the full range."},
        7
      );
    } else if (low == "terrain301") {
      set(
        ShaderFamily::Older,
        "Height splatting, the first version (kept for old maps).",
        "The earlier form of the splatting of the 2xx shaders. Prefer Terrain200 / Terrain250 for new maps. It uses an "
        "older texture layout (the roughness atlas is in the normal map of layer 8, the water depth in the Upper "
        "layer), so the editor does not convert layers to or from it.",
        "Layers: Base, painted layers 1-7. The atlas for roughness and height is in the normal map of layer 8; layer "
        "8's albedo is a map-wide colour with its opacity in alpha; the Upper layer holds the water depth in its blue "
        "channel.",
        Rows(
          Cell{kRgb, kXyz},
          Cell{kRgb, kXyz},
          Cell{"map-wide colour RGB, alpha = opacity", "atlas: roughness in G and A, height in R and B"},
          Cell{"B = water depth", kUnused}
        ),
        {kNoteRough, "Masks use the half range."},
        7
      );
      p.convertible = false;
    } else if (!PbrProfile(p.name, p)) {
      p.family = ShaderFamily::Older;
      p.known = false;
      p.summary = "A terrain shader of this game version without a description here.";
      p.instructions =
        "This technique is in effects/terrain.fx but the editor has no notes about it. Read the comment above it in "
        "the shader file for its texture layout; the usual layers (base, painted layers, upper) apply.";
      p.convertible = false;
    }
    return p;
  }
} // namespace faf::editor
