#include "editor/tools/EdLayerConvert.h"

#include "editor/tools/EdShaderProfiles.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] bool Remapped(
      const std::uint8_t remapped,
      const int layer
    )
    {
      return (remapped & (1U << layer)) != 0;
    }

    /** Whether a layer's strongest byte holds paint in its range (half range: bytes up to 127 mean nothing). */
    [[nodiscard]] bool HasPaint(
      const int strongest,
      const bool remapped
    )
    {
      return remapped ? strongest > 127 : strongest > 0;
    }

    /** Whether a shader paints layer `layer` (0-7): its first `painted`. */
    [[nodiscard]] bool Paints(
      const ShaderProfile& profile,
      const int layer
    )
    {
      return layer < profile.painted;
    }
  } // namespace

  std::string LayerListText(
    const std::vector<int>& layers
  )
  {
    if (layers.empty()) {
      return "no layer";
    }
    if (layers.size() == 1) {
      return "layer " + std::to_string(layers[0] + 1);
    }
    std::vector<std::string> parts;
    for (std::size_t i = 0; i < layers.size();) {
      std::size_t j = i;
      while (j + 1 < layers.size() && layers[j + 1] == layers[j] + 1) {
        ++j;
      }
      if (j - i >= 2) {
        parts.push_back(std::to_string(layers[i] + 1) + "-" + std::to_string(layers[j] + 1));
        i = j + 1;
      } else {
        parts.push_back(std::to_string(layers[i] + 1));
        ++i;
      }
    }
    std::string text = "layers ";
    for (std::size_t k = 0; k < parts.size(); ++k) {
      text += (k == 0 ? "" : (k + 1 == parts.size() ? " and " : ", ")) + parts[k];
    }
    return text;
  }

  LayerPaint ReadLayerPaint(
    const std::uint64_t* const texels,
    const int maskWidth,
    const int maskHeight,
    const MaskTerrain& terrain,
    const std::uint8_t remapped,
    const std::array<bool, 8>& textured
  )
  {
    LayerPaint paint;
    paint.textured = textured;
    if (texels == nullptr || maskWidth < 1 || maskHeight < 1) {
      return paint;
    }
    std::array<double, 8> slopeSum{};
    std::array<double, 8> weightSum{};
    const float perTexel =
      terrain.width > 1 ? static_cast<float>(terrain.width - 1) / static_cast<float>(maskWidth) : 1.0f;
    const auto heightAt = [&](const int x, const int z) {
      const int cx = std::clamp(x, 0, terrain.width - 1);
      const int cz = std::clamp(z, 0, terrain.height - 1);
      return static_cast<float>(
               terrain.heights
                 [static_cast<std::size_t>(cz) * static_cast<std::size_t>(terrain.width) + static_cast<std::size_t>(cx)]
             ) /
        128.0f;
    };
    for (int z = 0; z < maskHeight; ++z) {
      for (int x = 0; x < maskWidth; ++x) {
        const std::uint64_t texel =
          texels[static_cast<std::size_t>(z) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(x)];
        float slope = 0.0f;
        if (terrain.heights != nullptr && terrain.width > 2) {
          const int sx = static_cast<int>((static_cast<float>(x) + 0.5f) * perTexel);
          const int sz = static_cast<int>((static_cast<float>(z) + 0.5f) * perTexel);
          const float gx = (heightAt(sx + 1, sz) - heightAt(sx - 1, sz)) * 0.5f;
          const float gz = (heightAt(sx, sz + 1) - heightAt(sx, sz - 1)) * 0.5f;
          slope = std::atan(std::hypot(gx, gz)) * 57.2957795f;
        }
        for (int layer = 0; layer < 8; ++layer) {
          const std::uint8_t byte = MaskByte(texel, layer);
          paint.strongest[static_cast<std::size_t>(layer)] =
            std::max(paint.strongest[static_cast<std::size_t>(layer)], static_cast<int>(byte));
          const float weight = MaskWeight(byte, Remapped(remapped, layer));
          if (weight > 0.0f) {
            slopeSum[static_cast<std::size_t>(layer)] += static_cast<double>(slope) * weight;
            weightSum[static_cast<std::size_t>(layer)] += weight;
          }
        }
      }
    }
    for (std::size_t layer = 0; layer < 8; ++layer) {
      paint.slopeDegrees[layer] =
        weightSum[layer] > 0.0 ? static_cast<float>(slopeSum[layer] / weightSum[layer]) : 0.0f;
    }
    return paint;
  }

  LayerConvertPlan PlanLayerConversion(
    const std::string& from,
    const std::string& to,
    const LayerPaint& paint,
    const LayerConvertOptions& options
  )
  {
    LayerConvertPlan plan;
    plan.from = from;
    plan.to = to;
    const ShaderProfile source = ShaderProfileOf(from);
    const ShaderProfile target = ShaderProfileOf(to);
    plan.fromRemapped = source.remapped;
    plan.toRemapped = target.remapped;
    plan.toPainted = target.painted;
    plan.toRoughLayer8 = target.family == ShaderFamily::Pbr || target.family == ShaderFamily::Splat;
    plan.toBiplanar = target.summary.find("biplanar") != std::string::npos;
    if (from == to) {
      plan.refused = "the map already uses " + to + ".";
      return plan;
    }
    if (!target.convertible) {
      plan.refused = to + ": the editor has no layer layout for it, so it doesn't convert to it.";
      return plan;
    }
    if (source.name == "Terrain301" || (!source.known && !from.empty())) {
      plan.refused = from + ": the editor has no layer layout for it, so it doesn't convert from it.";
      return plan;
    }

    // The layers with paint now (layers the source doesn't paint hold data or nothing).
    for (int layer = 0; layer < 8; ++layer) {
      if (
        Paints(source, layer) &&
        HasPaint(paint.strongest[static_cast<std::size_t>(layer)], Remapped(plan.fromRemapped, layer))
      ) {
        plan.painted.push_back(layer);
      }
    }
    for (const int layer : plan.painted) {
      if (!Paints(target, layer)) {
        plan.lost.push_back(layer);
      }
    }
    const auto holdsPaint = [&](const int layer) {
      return std::find(plan.painted.begin(), plan.painted.end(), layer) != plan.painted.end();
    };

    // The range.
    if (plan.fromRemapped != plan.toRemapped) {
      plan.lines.push_back(
        "The paint is re-encoded from the " + MaskRangeText(plan.fromRemapped) + " to the " +
        MaskRangeText(plan.toRemapped) + ", so it looks as it did."
      );
    } else {
      plan.lines.push_back("The masks keep their range (" + MaskRangeText(plan.toRemapped) + ").");
    }

    // Paint the target can't draw.
    std::array<int, 8>& arrangement = plan.arrangement;
    if (!plan.lost.empty()) {
      if (options.lost == LostLayers::Move) {
        // Free layers: the target paints them and they hold no paint; untextured ones first.
        std::vector<int> free;
        for (const bool wantUntextured : {true, false}) {
          for (int layer = 0; layer < target.painted; ++layer) {
            if (
              !holdsPaint(layer) && paint.textured[static_cast<std::size_t>(layer)] != wantUntextured &&
              std::find(free.begin(), free.end(), layer) == free.end()
            ) {
              free.push_back(layer);
            }
          }
        }
        std::vector<int> merged;
        for (std::size_t i = 0; i < plan.lost.size(); ++i) {
          const int layer = plan.lost[i];
          if (i < free.size()) {
            std::swap(arrangement[static_cast<std::size_t>(free[i])], arrangement[static_cast<std::size_t>(layer)]);
            plan.lines.push_back(
              "Layer " + std::to_string(layer + 1) + "'s paint and texture move to layer " +
              std::to_string(free[i] + 1) + ", which holds no paint (" + target.name + " doesn't draw layer " +
              std::to_string(layer + 1) + ")."
            );
          } else {
            merged.push_back(layer);
          }
        }
        if (!merged.empty()) {
          plan.warnings.push_back(
            "No free layer left for " + LayerListText(merged) + (merged.size() == 1 ? ": its" : ": their") +
            " paint joins layer " + std::to_string(target.painted) + "."
          );
        }
      } else if (options.lost == LostLayers::Merge) {
        plan.lines.push_back(
          "The paint of " + LayerListText(plan.lost) + " joins layer " + std::to_string(options.mergeInto + 1) +
          " (the stronger weight wins)."
        );
      } else {
        plan.warnings.push_back(
          "The paint of " + LayerListText(plan.lost) + " is dropped: " + target.name + " doesn't draw it."
        );
      }
    }

    // Biplanar targets draw layers 3 and 4 from the side: the cliff layers go there.
    if (plan.toBiplanar && options.arrange) {
      std::vector<int> cliffs;
      for (int j = 0; j < 7; ++j) {
        const int sourceLayer = arrangement[static_cast<std::size_t>(j)];
        if (
          holdsPaint(sourceLayer) && paint.slopeDegrees[static_cast<std::size_t>(sourceLayer)] >= kCliffSlopeDegrees
        ) {
          cliffs.push_back(j);
        }
      }
      std::sort(cliffs.begin(), cliffs.end(), [&](const int a, const int b) {
        return paint.slopeDegrees[static_cast<std::size_t>(arrangement[static_cast<std::size_t>(a)])] >
          paint.slopeDegrees[static_cast<std::size_t>(arrangement[static_cast<std::size_t>(b)])];
      });
      int place = 2;
      for (std::size_t i = 0; i < cliffs.size() && place <= 3; ++i) {
        const int slot = cliffs[i];
        if (slot != place) {
          const int was = arrangement[static_cast<std::size_t>(slot)];
          std::swap(arrangement[static_cast<std::size_t>(slot)], arrangement[static_cast<std::size_t>(place)]);
          plan.lines.push_back(
            "Layer " + std::to_string(was + 1) + " (paint on " +
            std::to_string(static_cast<int>(std::lround(paint.slopeDegrees[static_cast<std::size_t>(was)]))) +
            " degree slopes on average) moves to layer " + std::to_string(place + 1) + ", which " + target.name +
            " textures from the side."
          );
        }
        ++place;
      }
      if (cliffs.size() > 2) {
        plan.warnings.push_back("More than two layers are painted on steep ground; only two fit layers 3 and 4.");
      }
      for (int slot = 2; slot <= 3; ++slot) {
        const int now = arrangement[static_cast<std::size_t>(slot)];
        if (holdsPaint(now) && paint.slopeDegrees[static_cast<std::size_t>(now)] < kCliffSlopeDegrees) {
          plan.warnings.push_back(
            "Layer " + std::to_string(slot + 1) + " holds flat-ground paint, which " + target.name +
            " textures from the side only."
          );
        }
      }
    }

    // Layer 8's role.
    if (plan.toRoughLayer8) {
      plan.lines.push_back("Layer 8 becomes the roughness multiplier: set to neutral (128) everywhere.");
    } else if ((source.family == ShaderFamily::Pbr || source.family == ShaderFamily::Splat) && target.painted >= 8) {
      plan.lines.push_back("Layer 8 was a roughness multiplier: cleared, so it paints nothing.");
    }

    // What the masks can't fix: the textures.
    if (plan.toRoughLayer8) {
      plan.warnings.push_back(
        to +
        " takes every layer's roughness from the Upper layer (a roughness atlas) and ignores the albedo alpha: "
        "the textures are not converted here."
      );
    }
    if (target.family == ShaderFamily::Splat) {
      plan.warnings.push_back(
        "Set the splat settings in the lighting's SpecularColor (0.2, 0.6, 0.866, 0.5 are good values): all zero draws "
        "flat colours."
      );
    }
    if (plan.toBiplanar) {
      plan.warnings.push_back(
        to + " always reads the map-wide normal map and water depth in layer 8's textures: they are not made here."
      );
    }
    const bool fromMatte = source.name == "TTerrain" || source.name == "TTerrainGlow";
    const bool toMatte = target.name == "TTerrain" || target.name == "TTerrainGlow";
    if (fromMatte != toMatte && !plan.toRoughLayer8) {
      plan.warnings.push_back(
        "The albedo alpha is read the other way round (" +
        std::string(toMatte ? "specular = 1 - alpha" : "alpha = specularity") +
        "): the layers' textures need their alpha inverted."
      );
    }
    return plan;
  }

  std::size_t ConvertMasks(
    std::uint64_t* const texels,
    const std::size_t count,
    const LayerConvertPlan& plan,
    const LayerConvertOptions& options
  )
  {
    if (texels == nullptr || !plan.refused.empty()) {
      return 0;
    }
    const auto lostLayer = [&](const int layer) {
      return std::find(plan.lost.begin(), plan.lost.end(), layer) != plan.lost.end();
    };
    // Where the paint of lost layers goes when it isn't moved: the merge layer, or (Move without a free layer) the
    // target's last painted layer.
    std::vector<int> joining;
    int joinInto = -1;
    if (options.lost == LostLayers::Merge) {
      joining = plan.lost;
      joinInto = std::clamp(options.mergeInto, 0, std::max(0, plan.toPainted - 1));
    } else if (options.lost == LostLayers::Move) {
      for (const int layer : plan.lost) {
        const bool moved =
          std::find(plan.arrangement.begin(), plan.arrangement.begin() + std::min(8, plan.toPainted), layer) !=
          plan.arrangement.begin() + std::min(8, plan.toPainted);
        if (!moved) {
          joining.push_back(layer);
        }
      }
      joinInto = std::max(0, plan.toPainted - 1);
    }
    std::size_t changed = 0;
    for (std::size_t i = 0; i < count; ++i) {
      const std::uint64_t before = texels[i];
      std::array<float, 8> weight{};
      for (int layer = 0; layer < 8; ++layer) {
        weight[static_cast<std::size_t>(layer)] =
          MaskWeight(MaskByte(before, layer), Remapped(plan.fromRemapped, layer));
      }
      std::uint64_t after = 0;
      for (int slot = 0; slot < 8; ++slot) {
        const int source = plan.arrangement[static_cast<std::size_t>(slot)];
        const std::uint8_t sourceByte = MaskByte(before, source);
        std::uint8_t byte = 0;
        if (slot == 7 && plan.toRoughLayer8) {
          byte = 128; // the neutral roughness multiplier
        } else if (slot < plan.toPainted) {
          // A painted layer of the target: the source's weight, re-encoded when the ranges differ (exact otherwise).
          float w = lostLayer(source) && std::find(joining.begin(), joining.end(), source) != joining.end()
            ? 0.0f
            : weight[static_cast<std::size_t>(source)];
          if (slot == joinInto) {
            for (const int join : joining) {
              w = std::max(w, weight[static_cast<std::size_t>(join)]);
            }
          }
          if (options.lost == LostLayers::Drop && lostLayer(source)) {
            w = 0.0f;
          }
          const bool sameRange = Remapped(plan.fromRemapped, source) == Remapped(plan.toRemapped, slot);
          if (sameRange && w == weight[static_cast<std::size_t>(source)]) {
            byte = sourceByte; // exactly as it was
          } else if (w <= 0.0f) {
            byte = 0; // nothing painted: a plain zero, not the 127 a stroke leaves
          } else {
            byte = MaskStoredFor(w, Remapped(plan.toRemapped, slot), 0);
          }
        } else {
          // Not drawn by the target: the paint it couldn't place is gone (Merge / Drop), other bytes come along.
          byte = lostLayer(source) ? std::uint8_t{0} : sourceByte;
        }
        after = WithMaskByte(after, slot, byte);
      }
      if (after != before) {
        texels[i] = after;
        ++changed;
      }
    }
    return changed;
  }

  std::array<int, 8> LayerMoveArrangement(
    const int from,
    const int to
  )
  {
    std::vector<int> order = {0, 1, 2, 3, 4, 5, 6, 7};
    if (from >= 0 && from < 8 && to >= 0 && to < 8 && from != to) {
      order.erase(order.begin() + from);
      order.insert(order.begin() + to, from);
    }
    std::array<int, 8> arrangement{};
    for (std::size_t j = 0; j < 8; ++j) {
      arrangement[j] = order[j];
    }
    return arrangement;
  }

  std::size_t MoveLayerMasks(
    std::uint64_t* const texels,
    const std::size_t count,
    const std::array<int, 8>& arrangement,
    const std::uint8_t remapped
  )
  {
    if (texels == nullptr) {
      return 0;
    }
    std::size_t changed = 0;
    for (std::size_t i = 0; i < count; ++i) {
      const std::uint64_t before = texels[i];
      std::uint64_t after = 0;
      for (int place = 0; place < 8; ++place) {
        const int source = arrangement[static_cast<std::size_t>(place)];
        const std::uint8_t byte = MaskByte(before, source);
        // The same weight, stored as the new place reads it (a full-range layer moved onto a remapped one, or back).
        const std::uint8_t stored = Remapped(remapped, source) == Remapped(remapped, place)
          ? byte
          : MaskStoredFor(MaskWeight(byte, Remapped(remapped, source)), Remapped(remapped, place), 0);
        after = WithMaskByte(after, place, stored);
      }
      if (after != before) {
        texels[i] = after;
        ++changed;
      }
    }
    return changed;
  }
} // namespace faf::editor
