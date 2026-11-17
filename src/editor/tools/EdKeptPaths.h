#pragma once

// Paths as lasting spline objects (FAF Studio's paths.lua, TERRAIN_GEN_DESIGN.md stage T4). A path is a Catmull-Rom or
// Bezier curve through control points; every point has a half width, a falloff, a height and a bank angle. A
// cross-section profile says how the ground follows the curve; the field library's path ops (terrain/EdFieldPath.cpp)
// turn curve and profile into a height change. A path is kept with the map (`<map>_paths.editor`), previewed on the
// real ground, applied (replacing its earlier result, one undo step), taken off again, or baked (its result frozen).
//
// Engine independent: the model, the sampling, the heights along the path, the grade report, the scatter plan, the
// build of a result through the field ops and the file text are tested on their own (tests/editor/KeptPathTests.cpp).

#include "editor/terrain/EdFieldCore.h"

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  enum class KeptPathMode : std::uint8_t
  {
    Carve,
    Raise,
    Level,
    Ramp,
    Road,
    River,
  };
  inline constexpr int kKeptPathModeCount = 6;
  [[nodiscard]] const char* KeptPathModeName(KeptPathMode mode) noexcept;
  [[nodiscard]] const char* KeptPathModeId(KeptPathMode mode) noexcept;
  [[nodiscard]] bool KeptPathModeFromId(const std::string& id, KeptPathMode& out);
  /** The label of the height field in the panel ("Depth (negative cuts)", "Height above the ground" ...). */
  [[nodiscard]] const char* KeptPathHeightLabel(KeptPathMode mode) noexcept;
  /** Offset modes add the points' heights to the ground; target modes blend the ground towards a height. */
  [[nodiscard]] bool KeptPathOffsetMode(KeptPathMode mode) noexcept;

  struct KeptPathPoint
  {
    float x = 0.0f;
    float z = 0.0f;
    /** The half width of the shaped section (units). */
    float w = 6.0f;
    /** The falloff beyond the half width (units). */
    float f = 4.0f;
    /** Offset modes: the height change; target modes: above the ground, or the height itself when `abs`; River: the
     * depth below the water. */
    float h = 0.0f;
    bool abs = false;
    /** Set by the editor when it pinned the point itself (the next added point may release it). */
    bool autoPin = false;
    /** Bank angle in degrees: the section tilts by tan(bank) times the signed distance. */
    float bank = 0.0f;
    /** Bezier handles (offsets from the point); empty: automatic. */
    bool hasHo = false;
    bool hasHi = false;
    float ho[2] = {0.0f, 0.0f};
    float hi[2] = {0.0f, 0.0f};
  };

  struct KeptPathProfile
  {
    /** x = |distance| / half width (0 the middle line), v = how much of the effect is there; x ascending. */
    std::vector<std::array<float, 2>> points;
    bool smooth = true;
    bool symmetric = true;
    std::string preset = "ramp";
  };

  struct KeptPathProfilePreset
  {
    const char* id;
    const char* label;
    bool smooth;
    std::vector<std::array<float, 2>> points;
  };
  [[nodiscard]] const std::vector<KeptPathProfilePreset>& KeptPathProfilePresets();
  [[nodiscard]] const KeptPathProfilePreset& KeptPathProfilePresetOf(const std::string& id);
  /** The profile at x (0..1): a monotone cubic through the points, or the polyline; constant outside them. */
  [[nodiscard]] float EvalKeptPathProfile(const KeptPathProfile& profile, float x);

  enum class KeptStrataKind : std::uint8_t
  {
    Core,  // inside the half width
    Bank,  // the falloff band
    Reach, // the whole reach
  };
  [[nodiscard]] const char* KeptStrataKindName(KeptStrataKind kind) noexcept;

  struct KeptPathStrata
  {
    int layer = 0; // 1..8; 0 off
    KeptStrataKind kind = KeptStrataKind::Core;
    float strength = 1.0f;
  };

  enum class KeptScatterSide : std::uint8_t
  {
    Both,
    Left,
    Right,
    Center,
  };
  [[nodiscard]] const char* KeptScatterSideName(KeptScatterSide side) noexcept;

  /** Props or decals laid along the path. */
  struct KeptPathScatter
  {
    bool on = false;
    /** A prop blueprint (props) or a texture (decals). */
    std::string what;
    float spacing = 6.0f;
    KeptScatterSide side = KeptScatterSide::Both;
    /** How far beyond the half width the sides lie. */
    float lateral = 1.0f;
    float jitter = 0.5f;
    float scaleMin = 0.8f;
    float scaleMax = 1.2f;
    /** Decals: their size (units) before the scale. */
    float size = 6.0f;
    int seed = 1;
  };

  struct KeptPath
  {
    std::string id;
    std::string name;
    bool bezier = false;
    KeptPathMode mode = KeptPathMode::Carve;
    bool closed = false;
    /** The path is copied by the map's symmetry. */
    bool sym = false;
    float strength = 1.0f;
    float tension = 1.0f;
    /** Grade limit (rise per run) and whether it is kept. */
    float grade = 0.75f;
    bool limitGrade = false;
    /** Unpinned points between two pinned ones lie on the line between them. */
    bool interp = true;
    /** Thermal passes over the banks. */
    int erosion = 0;
    /** The change spreads into the ground around by a blur of this width (units). */
    float blend = 0.0f;
    std::vector<KeptPathPoint> points;
    KeptPathProfile profile;
    std::array<KeptPathStrata, 2> strata{};
    KeptPathScatter props;
    KeptPathScatter decals;
    /** Made by the map skeleton generator (EdSkeleton): Generate replaces these, Apply all applies them. */
    bool skeleton = false;
  };

  /** A new path of `mode` (its profile preset, its height default). */
  [[nodiscard]] KeptPath NewKeptPath(KeptPathMode mode, bool bezier, const std::string& id);
  /** The mode's preset profile and default height. */
  void UseKeptPathPreset(KeptPath& path, const std::string& presetId);
  /** Switches the mode as Studio does: preset, heights reset or sign-flipped, pins. */
  void SetKeptPathMode(KeptPath& path, KeptPathMode mode, const std::function<float(float, float)>& ground);
  /** A new point after the last (its width, falloff and height from the last), pins as Studio's Pin. */
  void AddKeptPathPoint(KeptPath& path, float x, float z, const std::function<float(float, float)>& ground);
  /** A point inserted after control point `after`, its fields between its neighbours'. */
  void InsertKeptPathPoint(KeptPath& path, int after, float x, float z);
  /** Pins (or releases) a point: a pinned point aims at its own height, starting at the ground under it. */
  void PinKeptPathPoint(KeptPathPoint& point, bool on, const std::function<float(float, float)>& ground);

  /** All the paths of a map. */
  struct KeptPathSet
  {
    std::vector<KeptPath> paths;
    int nextId = 1;
    [[nodiscard]] KeptPath* Find(const std::string& id);
    [[nodiscard]] const KeptPath* Find(const std::string& id) const;
    /** A fresh id ("p<n>"). */
    std::string TakeId();
    bool operator==(const KeptPathSet& other) const;
  };

  /** The dense polyline of a curve. */
  struct KeptPathSamples
  {
    std::vector<float> x, z, w, f, bank, h, t, s;
    std::vector<int> seg;     // control point the segment starts at (0-based)
    std::vector<float> ctrlS; // arc length at every control point
    [[nodiscard]] std::size_t Count() const noexcept
    {
      return x.size();
    }
  };
  /** Out and in handle vectors of every control point. */
  void
  KeptPathHandles(const KeptPath& path, std::vector<std::array<float, 2>>& out, std::vector<std::array<float, 2>>& in);
  [[nodiscard]] KeptPathSamples SampleKeptPath(const KeptPath& path, float step);
  [[nodiscard]] float KeptPathLength(const KeptPath& path);

  /**
   * Target heights (target modes) or offsets (offset modes) along the samples: `ys`, `offs`. `ground(x, z)` is the
   * ground the path starts from; `water` the sea level (River).
   */
  void KeptPathHeights(
    const KeptPath& path,
    const KeptPathSamples& samples,
    const std::function<float(float, float)>& ground,
    float water,
    std::vector<float>& ys,
    std::vector<float>& offs
  );

  /** The planned grade along the path, over windows of about 3 units. */
  struct KeptPathReport
  {
    float max = 0.0f;
    float over = 0.0f;                        // share of the length above the limit
    std::vector<std::pair<int, int>> flagged; // sample ranges above the limit
    std::vector<float> ys;
    float worstX = 0.0f; // where the steepest grade starts
    float worstZ = 0.0f;
  };
  [[nodiscard]] KeptPathReport
  ReportKeptPath(const KeptPath& path, const std::function<float(float, float)>& ground, float water);

  /** One item laid along the path. */
  struct KeptPathItem
  {
    float x = 0.0f;
    float z = 0.0f;
    float heading = 0.0f;
    float scale = 1.0f;
  };
  [[nodiscard]] std::vector<KeptPathItem> KeptPathScatterPlan(const KeptPath& path, const KeptPathScatter& cfg);

  /** A symmetry image: f maps a point; `mirror` when it is a reflection. */
  struct KeptPathImage
  {
    std::function<void(float, float, float&, float&)> map;
    bool mirror = false;
  };
  /** The path moved through an image (positions, handles; a reflection flips the bank and an asymmetric profile). */
  [[nodiscard]] KeptPath KeptPathImageOf(const KeptPath& path, const KeptPathImage& image);

  /** What a path did to the map, kept while the map is open, so the next Apply replaces it and Unapply takes it off. */
  struct KeptPathResult
  {
    /** The heights' rectangle (samples, inclusive) and the change there in height words (new minus base). */
    int x0 = 0, z0 = 0, x1 = -1, z1 = -1;
    std::vector<std::int32_t> heightDelta;
    /** Per layer (1..8): the weight change (0..255 units, the shader's range) per mask texel, whole mask grid. */
    std::map<int, std::vector<float>> maskDelta;
    /** The props and decals it placed (blueprint or texture, position, heading, scale or size). */
    struct Placed
    {
      std::string what;
      float x = 0.0f, y = 0.0f, z = 0.0f;
      float heading = 0.0f;
      float scale = 1.0f;
    };
    std::vector<Placed> props;
    std::vector<Placed> decals;
    [[nodiscard]] bool Empty() const noexcept
    {
      return heightDelta.empty() && maskDelta.empty() && props.empty() && decals.empty();
    }
  };

  /** The inputs of a build: the map's heights (words, `width` x `height`), the sea, the symmetry images. */
  struct KeptPathGround
  {
    const std::uint16_t* words = nullptr;
    int width = 0;
    int height = 0;
    float water = 25.0f;
    std::vector<KeptPathImage> images;
  };

  /** A build: the new height words over the rectangle, the delta, the path masks for its strata (cell 1, rect). */
  struct KeptPathPlan
  {
    int x0 = 0, z0 = 0, x1 = -1, z1 = -1;
    std::vector<std::uint16_t> words;                          // the new heights in the rectangle
    std::vector<std::int32_t> delta;                           // new minus base
    std::vector<std::pair<KeptPathStrata, field::Grid>> masks; // 0..1 over the whole map (cell 1)
    float lowest = 0.0f;                                       // the largest cut (units, <= 0)
    float highest = 0.0f;                                      // the largest raise (units, >= 0)
    std::size_t changed = 0;
  };
  /**
   * Builds a path's result on `ground` with its earlier result `old` (null: none) taken off first: the shape ops of the
   * path and its images, the blend, the bank erosion, quantised to words. `wantMasks` also makes the strata masks.
   * The error when the path lies off the map or an op fails.
   */
  [[nodiscard]] std::expected<KeptPathPlan, std::string>
  BuildKeptPath(const KeptPath& path, const KeptPathGround& ground, const KeptPathResult* old, bool wantMasks);

  /**
   * Strata into the mask texels (`width` x `height` over a map `mapSize` units): the earlier result's weights taken
   * off, then each mask laid over the layer (weight += (255 - weight) * mask * strength). `remapped`: RemappedStrata's
   * bits. Returns the new deltas (per layer, whole grid) and how many texels changed.
   */
  std::map<int, std::vector<float>> ApplyKeptPathMasks(
    std::uint64_t* texels,
    int width,
    int height,
    float mapSize,
    std::uint8_t remapped,
    const std::vector<std::pair<KeptPathStrata, field::Grid>>& masks,
    const std::map<int, std::vector<float>>* oldDelta,
    std::size_t& changed
  );
  /** Takes a result's mask weights off again. Returns the texels changed. */
  std::size_t RemoveKeptPathMasks(
    std::uint64_t* texels,
    int width,
    int height,
    std::uint8_t remapped,
    const std::map<int, std::vector<float>>& delta
  );

  /** The file text (`<map>_paths.editor`, JSON) and back. */
  [[nodiscard]] std::string KeptPathsText(const KeptPathSet& set);
  [[nodiscard]] std::expected<KeptPathSet, std::string> ReadKeptPaths(const std::string& text);
} // namespace faf::editor
