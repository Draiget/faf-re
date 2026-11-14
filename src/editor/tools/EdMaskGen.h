#pragma once

#include "editor/terrain/EdFieldCore.h"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The mask generator (FAF Studio's maskgen.lua): a list of rules that makes a 0..1 mask over the whole map from the
   * terrain, on the field library. Source rules make a mask and combine it with what the rules above made; modifier
   * rules change the result so far. The panel writes the mask into a texture layer as one undo step.
   */
  struct MaskParamSpec
  {
    const char* key;
    const char* label;
    float min;
    float max;
    float step;
    const char* format;
    float fallback;
  };

  struct MaskRuleSpec
  {
    const char* id;
    const char* label;
    bool modifier = false;
    std::vector<MaskParamSpec> params;
  };

  /** Every rule type, sources first, in the panel's order. */
  [[nodiscard]] const std::vector<MaskRuleSpec>& MaskRuleCatalogue();
  [[nodiscard]] const MaskRuleSpec* MaskRuleSpecOf(const std::string& id);

  enum class MaskCombine : std::uint8_t
  {
    And, // the smaller
    Or,  // the larger
    Mul,
    Sub, // what is there, less this
    Add,
  };
  [[nodiscard]] const char* MaskCombineName(MaskCombine op) noexcept;

  struct MaskGenRule
  {
    std::string type;
    MaskCombine op = MaskCombine::And;
    bool invert = false;
    bool enabled = true;
    std::map<std::string, float> v; // a missing key reads its default
    [[nodiscard]] float Value(const char* key) const;
  };

  /** A rule of `type` with its defaults. */
  [[nodiscard]] MaskGenRule NewMaskRule(const std::string& type);
  /** "Slope  0.0 / 25.0 / 3.0": the label and its first three values. */
  [[nodiscard]] std::string DescribeMaskRule(const MaskGenRule& rule);

  /** What the rules read: the heights (cell 1 unit, sample (0, 0) at the map's corner), the sea, the paint. */
  struct MaskGenContext
  {
    std::shared_ptr<field::Grid> heights;
    float water = 0.0f;
    /** Layer k's weight 0..1 (as the shader reads it) at [k - 1], on the mask grid; null when not given. */
    std::array<std::shared_ptr<field::Grid>, 8> layers{};
    std::map<std::string, std::shared_ptr<field::Grid>> cache;
  };

  /** The layers' masks as fields: byte k of each texel is layer k + 1, read in the shader's range (`remapped`). */
  void MaskLayerFields(
    const std::uint64_t* texels,
    int width,
    int height,
    float mapSize,
    std::uint8_t remapped,
    MaskGenContext& context
  );

  /** Evaluates the rules top to bottom into `out` (on the heights' grid). False with `error` when none is on or an op
   * fails. */
  bool EvaluateMaskRules(
    MaskGenContext& context,
    const std::vector<MaskGenRule>& rules,
    field::Grid& out,
    std::string& error
  );

  /** How much the layers above `layer` leave free (1 - mask, multiplied over layers layer + 1 .. 8), on the heights'
   * grid. */
  bool FreeAboveLayer(MaskGenContext& context, int layer, field::Grid& out, std::string& error);

  struct MaskPreset
  {
    const char* id;
    const char* name;
  };
  /** The starting points (cliffs, beach, snow caps ...). */
  [[nodiscard]] const std::vector<MaskPreset>& MaskPresets();
  /** The rules of a preset; `heightLow` / `heightHigh` are the map's lowest and highest ground (snow caps). Empty when
   * the id is unknown. */
  [[nodiscard]] std::vector<MaskGenRule> MaskPresetRules(const std::string& id, float heightLow, float heightHigh);

  enum class MaskWriteMode : std::uint8_t
  {
    Replace,
    AddTo,        // the larger of the old and the new
    SubtractFrom, // the old times (1 - new)
  };

  /**
   * Writes `mask` (0..1, any grid over the map) into layer `layer` (1..8) of the texels (`width` x `height` over a map
   * `mapSize` units wide): sampled at each texel's middle, kept to what the layers above leave free when `takeAway`,
   * combined with the layer's weight by `mode`, blended by `strength`, and stored in the shader's range (`remapped`:
   * RemappedStrata's bits). Returns how many texels changed.
   */
  std::size_t WriteMaskLayer(
    std::uint64_t* texels,
    int width,
    int height,
    float mapSize,
    int layer,
    std::uint8_t remapped,
    const field::Grid& mask,
    MaskWriteMode mode,
    float strength,
    bool takeAway
  );

  /** A field sampled at world (x, z), bilinear, clamped at its edges. */
  [[nodiscard]] float SampleField(const field::Grid& grid, float x, float z);
} // namespace faf::editor
