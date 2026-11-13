#pragma once

// Convert layers (FAF Studio's stratumconv.lua, the paint masks part): moves a map's paint from one terrain shader's
// format to another's: the mask bytes re-encoded for the target's range, the painted layers the target can't draw
// moved to a free layer, merged into one or dropped, layer 8 given its new role (the 1xx / 2xx shaders read it as a
// roughness multiplier: neutral 128), and for the biplanar shaders the layers painted on steep ground moved to layers
// 3 and 4 (which they draw from the side). The textures stay as they are (the report says what to look at). No engine
// types: tested on its own (tests/editor/LayerConvertTests.cpp).

#include "editor/tools/EdMaskBrush.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** What each painted layer (stratum 0-7) holds: its strongest byte and the mean slope of the ground under its paint.
   */
  struct LayerPaint
  {
    std::array<int, 8> strongest{};
    std::array<float, 8> slopeDegrees{};
    /** Whether layer i has a texture (the panel's slots 1-8). */
    std::array<bool, 8> textured{};
  };

  /** Per layer: the strongest byte, and the mean slope (degrees) of the texels it shows on, weighted by its weight. */
  [[nodiscard]] LayerPaint ReadLayerPaint(
    const std::uint64_t* texels,
    int maskWidth,
    int maskHeight,
    const MaskTerrain& terrain,
    std::uint8_t remapped,
    const std::array<bool, 8>& textured
  );

  /** What happens to the painted layers the target can't draw. */
  enum class LostLayers
  {
    /** Into layers the target paints that hold no paint, in order (merged into the last one when none is free). */
    Move,
    /** Their weight joins `mergeInto`'s (the stronger wins). */
    Merge,
    /** Their paint goes. */
    Drop,
  };

  struct LayerConvertOptions
  {
    LostLayers lost = LostLayers::Move;
    /** Merge: the layer (0-6) the lost paint joins. */
    int mergeInto = 0;
    /** Biplanar targets: move the steep-ground layers to layers 3 and 4. */
    bool arrange = true;
  };

  /** A layer painted on ground at least this steep on average counts as a cliff layer (FAF Studio's CLIFF_SLOPE). */
  inline constexpr float kCliffSlopeDegrees = 20.0f;

  struct LayerConvertPlan
  {
    std::string from;
    std::string to;
    /** Why it can't be done (empty when it can). */
    std::string refused;
    std::uint8_t fromRemapped = 0;
    std::uint8_t toRemapped = 0;
    int toPainted = 8;
    bool toRoughLayer8 = false; // the 1xx / 2xx shaders: layer 8's mask is a roughness multiplier
    bool toBiplanar = false;
    /** Painted layers (0-7) that hold paint now, and those of them the target can't draw. */
    std::vector<int> painted;
    std::vector<int> lost;
    /** Target layer j gets source layer arrangement[j] (paint and texture). */
    std::array<int, 8> arrangement{0, 1, 2, 3, 4, 5, 6, 7};
    /** What it does, and what needs a look afterwards, in words. */
    std::vector<std::string> lines;
    std::vector<std::string> warnings;
  };

  /** What converting the paint from shader `from` to `to` would do, with these options. */
  [[nodiscard]] LayerConvertPlan PlanLayerConversion(
    const std::string& from,
    const std::string& to,
    const LayerPaint& paint,
    const LayerConvertOptions& options
  );

  /** Converts the masks as `plan` says; returns how many texels changed. */
  std::size_t ConvertMasks(
    std::uint64_t* texels,
    std::size_t count,
    const LayerConvertPlan& plan,
    const LayerConvertOptions& options
  );

  /** "layer 3", "layers 5 and 8", "layers 1-7", "layers 1-3, 5 and 8" (indices 0-7 shown 1-8). */
  [[nodiscard]] std::string LayerListText(const std::vector<int>& layers);
} // namespace faf::editor
