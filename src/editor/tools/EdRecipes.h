#pragma once

#include "editor/tools/EdGroundKind.h"
#include "editor/tools/EdMaskGen.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Stratum recipes (FAF Studio's recipes.lua): the texture layers painted with the eight kinds of ground a landscape
   * is made of, from height, slope, curvature, water and noise rules built from the map's own numbers (height
   * percentiles of the land, never fixed heights). Which layer holds which kind comes from its texture (EdGroundKind),
   * not from its number. The kinds are resolved from the top of the priority list down (snow, high rock, dark rock,
   * rock, wet, sand, dirt, grass), so the visible weights add up to 1, and every layer gets the opacity that shows
   * exactly its weight: m = w / (what the layers above leave free).
   */
  struct RecipeKnobs
  {
    float cliff = 52.0f;  // cliff slope from (degrees)
    float rock = 34.0f;   // rock slope from (degrees)
    float snow = 0.08f;   // snow covers the top (share of the land)
    float high = 0.5f;    // high rock starts at (share of the height range)
    float beach = 3.0f;   // beach half width (units)
    float wet = 1.5f;     // wet strip half width (units)
    float dirt = 0.38f;   // dirt coverage (share of flat ground)
    float dark = 0.5f;    // dark rock in cavities
    float breakup = 0.5f; // edge breakup (noise)
    float patch = 50.0f;  // patch size (units)
    float crisp = 0.45f;  // edge crispness
    float fine = 0.35f;   // fine grain
    float mix = 0.55f;    // how much of a kind a second texture of it takes
    float soft = 0.0f;    // blend width between kinds (units)
    float seed = 1.0f;
    float wear = 0.12f; // erosion paint: worn rock (share of the ground)
    float sed = 0.22f;  // erosion paint: sediment (share of the ground)
    float chan = 0.07f; // erosion paint: drainage channels (share of the ground)
    float edge = 0.04f; // erosion paint: edge softness (share of a mask's range)
  };

  struct RecipeKnobInfo
  {
    float RecipeKnobs::* member;
    const char* label;
    float min;
    float max;
    const char* format;
  };
  [[nodiscard]] const std::vector<RecipeKnobInfo>& RecipeKnobList();
  /** The knobs' names as FAF Studio's graph files keep them, in RecipeKnobList's order ("cliff", "rock", ...). */
  [[nodiscard]] const std::vector<const char*>& RecipeKnobKeys();

  struct RecipeStyle
  {
    const char* id;
    const char* name;
    std::uint16_t off = 0; // kinds it doesn't paint (bit: GroundKind)
    bool altForce = false; // altitude counts on any map (alpine, arctic)
    bool drySand = false;  // sand in dry basins on a map without water (desert)
    bool relief = false;   // dirt on the floor of valleys (open valley)
    bool erosion = false;  // rock, dirt and wet ground read off the water's work (erosion paint)
  };
  [[nodiscard]] const std::vector<RecipeStyle>& RecipeStyles();
  /** The defaults with a style's own values on top. */
  [[nodiscard]] RecipeKnobs RecipeKnobsOf(int style);

  /** The map's numbers: the height range, the sea, and the land heights' percentiles (0..100). */
  struct RecipeStats
  {
    float hmin = 0.0f;
    float hmax = 100.0f;
    float water = 0.0f;
    bool hasWater = false;
    std::array<float, 101> pct{};
  };
  /** From the heights (any number of them): land = above the water when the map has water and at least 3 % is above
   * it. */
  [[nodiscard]] RecipeStats RecipeStatsOf(const std::vector<float>& heights, float water, bool waterOn);
  /** The height at land percentile p (0..1). */
  [[nodiscard]] float RecipeHeightAt(const RecipeStats& stats, float p);
  /** The 0..100 percentiles of values (a 1024-bin histogram); false when there are none. */
  bool RecipePercentiles(const std::vector<float>& values, std::array<float, 101>& out);

  /** Which layer holds which kind: byKind[kind] the layers (lowest first); base the base layer's kind. */
  struct RecipePlan
  {
    int cap = 8;           // the highest layer the shader paints
    bool biplanar = false; // layers 3 and 4 drawn from the side only (the B shaders)
    GroundKind base = GroundKind::Unknown;
    std::array<std::vector<int>, 9> byKind;
    std::vector<int> unknown; // textured layers of no known kind
    std::vector<int> beyond;  // textured layers the shader doesn't paint
    [[nodiscard]] bool Has(
      GroundKind kind
    ) const noexcept
    {
      return !byKind[static_cast<std::size_t>(kind)].empty();
    }
  };
  /** `kinds[layer]`: the kind of each layer's texture (Unknown: none or not used); layer 0 is the base. */
  [[nodiscard]] RecipePlan
  PlanRecipe(const std::array<GroundKind, 9>& kinds, const std::array<bool, 9>& textured, int cap, bool biplanar);

  struct RecipeRole
  {
    GroundKind kind = GroundKind::Unknown;
    std::vector<MaskGenRule> rules; // its selection; empty for the base kind (what the others leave)
    bool base = false;
    bool off = false; // not painted (the style, or nothing to paint on this map): its layers are cleared
  };
  /** The kinds bottom to top (grass, dirt, wet, sand, rock, dark rock, high rock, snow) and the priority (top first).
   */
  [[nodiscard]] const std::array<GroundKind, 8>& RecipeOrder();
  [[nodiscard]] const std::array<GroundKind, 8>& RecipePriority();
  [[nodiscard]] const char* RecipeKindLabel(GroundKind kind) noexcept;

  /**
   * The rules of every kind for this map, style and knobs. `context` gives the noise its grid: a noise's thresholds
   * come from the noise itself (its percentiles), so "dirt covers 38 %" means that on any map.
   */
  bool RecipeRoles(
    MaskGenContext& context,
    const RecipePlan& plan,
    const RecipeStats& stats,
    const RecipeKnobs& knobs,
    int style,
    std::vector<RecipeRole>& roles,
    std::string& error
  );

  /**
   * The visible weight of every layer of the plan (layer -> field on the heights' grid): each kind takes its selection
   * of what the kinds above it left; a kind with more layers gives the second and later ones soft noise patches of
   * its region. Kinds that are off get an empty weight, so their layers are cleared.
   */
  bool ResolveRecipe(
    MaskGenContext& context,
    const RecipePlan& plan,
    const std::vector<RecipeRole>& roles,
    const RecipeKnobs& knobs,
    int style,
    std::map<int, field::Grid>& target,
    std::string& error
  );

  /**
   * Erosion paint (FAF Studio's erosionpaint.lua): the paint read off what the water did, as a World Machine or Gaea
   * project paints its map. Three masks on the heights' grid, made from the heights (a solver-free stand-in): wear
   * (rockiness), deposit (topographic wetness on flat ground) and flow (drainage). Each is cut at a SHARE of the map
   * with an edge `edge` of its range wide, so it means the same on any map. Rock becomes the cliffs by slope plus the
   * worn ground, dirt the settled sediment on flat ground, wet ground the drainage network; their second layers take
   * bands of the same masks (the strongest wear, the thickest sediment, the channel core; a third rock the convex steep
   * ground; a second grass the ridge tops) instead of noise. Replaces `selection[kind]` for the kinds that have layers
   * and fills `variants[{kind, n}]`: the share of the kind's region its (n + 1)th layer takes.
   */
  /**
   * ResolveRecipe's two halves. The first: each kind's selection on the heights' grid (a kind with layers, not off,
   * not the base; on a B shader's side layers only steep ground) and, for erosion paint, the bands of the second
   * layers (`variants[{kind, n}]`). The second: the priority cascade (each kind takes its selection of what the kinds
   * above it left, the base the rest), every layer of a kind, the layers of `cleared` kinds emptied, the soft blend.
   */
  bool RecipeSelections(
    MaskGenContext& context,
    const RecipePlan& plan,
    const std::vector<RecipeRole>& roles,
    const RecipeKnobs& knobs,
    int style,
    std::array<std::vector<float>, 9>& selection,
    std::map<std::pair<int, int>, std::vector<float>>& variants,
    std::string& error
  );
  bool ResolveSelections(
    MaskGenContext& context,
    const RecipePlan& plan,
    const std::array<std::vector<float>, 9>& selection,
    const std::map<std::pair<int, int>, std::vector<float>>& variants,
    const std::array<bool, 9>& cleared,
    const RecipeKnobs& knobs,
    std::map<int, field::Grid>& target,
    std::string& error
  );

  bool RecipeErosionSelections(
    MaskGenContext& context,
    const RecipePlan& plan,
    const RecipeKnobs& knobs,
    std::array<std::vector<float>, 9>& selection,
    std::map<std::pair<int, int>, std::vector<float>>& variants,
    std::string& error
  );

  /** The value `share` (0..1) of the values lie above. */
  [[nodiscard]] float RecipeValueAbove(const std::vector<float>& values, float share);

  /**
   * Writes the visible weights into the masks: from the top layer down each gets the opacity that shows its weight (the
   * weight over what the layers above leave free), in the shader's range; a textured layer outside the recipe keeps its
   * mask and covers what lies under it. `shares[layer]` (0 = the base) is what each layer shows over the map. Returns
   * the texels changed.
   */
  std::size_t WriteRecipe(
    std::uint64_t* texels,
    int width,
    int height,
    float mapSize,
    std::uint8_t remapped,
    int cap,
    const std::array<bool, 9>& textured,
    const std::map<int, field::Grid>& target,
    std::array<float, 9>& shares
  );
} // namespace faf::editor
