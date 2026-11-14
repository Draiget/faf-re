#pragma once

#include "editor/terrain/EdFieldCore.h"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * The map layout (FAF Studio's layout.lua): a coarse drawing of the map in layers (hills, mountains, plateaus, water,
   * valleys, flat ground, bases and free masks) that is turned into heights, into the masks the graph's layout nodes
   * read and into start positions. Each layer is a grid of rw x rh square cells (0..1) over the map's playable area;
   * the generator spreads it over the map, softens it by the layer's soft edge and adds noise where its kind asks.
   */
  enum class LayoutKind
  {
    Hills,
    Mountains,
    Plateau,
    Water,
    Valley,
    Flat,
    Base,
    Mask,
  };

  struct LayoutParamDef
  {
    const char* key;
    const char* label;
    float min;
    float max;
    float step;
    const char* format;
    float value; // the default
  };

  struct LayoutKindInfo
  {
    LayoutKind kind;
    const char* id; // as saved: hills, mountains, plateau, water, valley, flat, base, mask
    const char* label;
    std::array<std::uint8_t, 3> color;
    const char* tip;
    std::vector<LayoutParamDef> params;
  };

  /** Every kind, in the panel's order. */
  [[nodiscard]] const std::vector<LayoutKindInfo>& LayoutKinds();
  [[nodiscard]] const LayoutKindInfo& LayoutKindOf(LayoutKind kind);
  bool LayoutKindFromId(const std::string& id, LayoutKind& kind);

  struct LayoutLayer
  {
    int id = 0;
    std::string name;
    LayoutKind kind = LayoutKind::Hills;
    bool visible = true;
    std::array<std::uint8_t, 3> color{};
    std::map<std::string, float> p;
    std::vector<float> data; // rw * rh cells, row by row
    /** The setting `key` (the kind's default when unset, 0 when the kind has none). */
    [[nodiscard]] float P(const std::string& key) const;
  };

  /** The drawing's grid: rw x rh cells of `cell` units, the corner at (ox, oz). */
  struct LayoutFrame
  {
    int rw = 0;
    int rh = 0;
    float cell = 1.0f;
    float ox = 0.0f;
    float oz = 0.0f;
  };

  /** A grid of `res` cells on the long side over the rectangle: square cells, centred on it. */
  [[nodiscard]] LayoutFrame LayoutFrameFor(int res, float x0, float z0, float x1, float z1);

  /** The copies of a world point under the editor's symmetry, the point itself first. */
  using LayoutImages = std::function<std::vector<std::pair<float, float>>(float x, float z)>;

  /** A stroke's undo record: the layer's cells before and after. */
  struct LayoutStroke
  {
    int layerId = 0;
    std::vector<float> before;
    std::vector<float> after;
  };

  /** How a picture becomes a layer (Studio's ImportImage): white is drawn, black is empty. */
  struct LayoutPictureOptions
  {
    bool invert = false;  // black is drawn
    bool stretch = false; // the picture's darkest value becomes 0 and its brightest 1 (heightmaps)
    bool hard = false;    // above one half: 1, else 0
    bool contain = false; // the whole picture inside the drawing with its aspect (else stretched over it)
    bool add = false;     // added to what is drawn (the larger value wins)
    bool flipX = false;
    bool flipZ = false;
  };

  /** A blob drawn on the Base layers: its centre in world units and its size in cells. */
  struct LayoutBase
  {
    float x = 0.0f;
    float z = 0.0f;
    int cells = 0;
  };

  class MapLayout
  {
  public:
    static constexpr int kMinRes = 32;
    static constexpr int kMaxRes = 512;
    static constexpr int kDefaultRes = 256;
    static constexpr int kMaxLayers = 16;

    MapLayout();

    /** A fresh drawing over the rectangle (the playable area) with a layer of each `kinds` (default: the first six). */
    void New(int res, float x0, float z0, float x1, float z1, const std::vector<LayoutKind>& kinds = DefaultKinds());
    [[nodiscard]] static std::vector<LayoutKind> DefaultKinds();

    [[nodiscard]] const LayoutFrame& Frame() const noexcept
    {
      return mFrame;
    }
    [[nodiscard]] int Res() const noexcept
    {
      return mRes;
    }
    [[nodiscard]] std::vector<LayoutLayer>& Layers() noexcept
    {
      return mLayers;
    }
    [[nodiscard]] const std::vector<LayoutLayer>& Layers() const noexcept
    {
      return mLayers;
    }
    [[nodiscard]] LayoutLayer* Layer(int i);
    [[nodiscard]] const LayoutLayer* Layer(int i) const;
    [[nodiscard]] LayoutLayer* LayerById(int id);

    // The generator's settings.
    float base = 25.0f;  // ground height (units)
    float water = 20.0f; // water level (units)
    int seed = 1;
    float weather = 0.0f; // 0..1: droplet erosion on top (gullies)
    /** The markers the start and resource generator placed last (name and place): the next Place replaces those
     * still there. */
    struct Generated
    {
      std::string name;
      float x = 0.0f;
      float z = 0.0f;
    };
    std::vector<Generated> generated;
    int selected = 0;
    /** Goes up on every change: views and the graph's layout nodes compare it. */
    std::uint64_t revision = 1;
    void Touch() noexcept
    {
      ++revision;
    }

    /** The editor's symmetry for strokes (none: a stroke paints only where it is). */
    void SetImages(
      LayoutImages images
    )
    {
      mImages = std::move(images);
    }
    /** The copies of a canvas point under the symmetry (canvas cells), the point itself first. */
    [[nodiscard]] std::vector<std::pair<float, float>> BrushImages(
      const float cx,
      const float cz
    ) const
    {
      return CellImages(cx, cz);
    }

    void ToWorld(float cx, float cz, float& x, float& z) const;
    void ToCell(float x, float z, float& cx, float& cz) const;

    /** A layer of `kind` at the top of the list (a second one of a kind is numbered); its index, -1 when full. */
    int AddLayer(LayoutKind kind, const std::string& name = {});
    bool RemoveLayer(int i);
    /** Moves layer i up (dir 1: applied later) or down (dir -1). */
    bool MoveLayer(int i, int dir);

    // Painting (canvas cells; every tool paints the symmetry's copies too). A stroke wraps them for undo.
    bool BeginStroke(int i);
    /** False when nothing changed (no undo step then). */
    bool EndStroke(LayoutStroke& out);
    /** Puts a layer's cells back (undo / redo of a stroke). */
    bool SetCells(int layerId, const std::vector<float>& data);
    void Dab(int i, float cx, float cz, float r, float hardness, float strength, bool erase);
    void Line(int i, float x0, float z0, float x1, float z1, float r, float hardness, float strength, bool erase);
    int FillRect(int i, float x0, float z0, float x1, float z1, float strength, bool erase);
    int FillEllipse(int i, float x0, float z0, float x1, float z1, float strength, bool erase);
    int FillPolygon(int i, const std::vector<std::pair<float, float>>& points, float strength, bool erase);
    void Fill(int i, float value);
    void Smooth(int i);
    void Invert(int i);
    /**
     * A picture (`grey` 0..1, `w` x `h`, rows along z) fitted over the drawing as layer i's cells (bilinear, values in
     * 1/255 steps); how many cells changed, -1 for no such layer or an empty picture. Wrap it in a stroke for undo.
     */
    int ImportPicture(int i, const std::vector<float>& grey, int w, int h, const LayoutPictureOptions& options);

    /** Is anything drawn? */
    [[nodiscard]] bool Drawn() const;
    /** True when the drawing doesn't cover the rectangle (the playable area changed, another map). */
    [[nodiscard]] bool Stale(float x0, float z0, float x1, float z1) const;
    /** Fits the drawing to the rectangle at `res` cells: every layer resampled by world position. False: no change. */
    bool Refit(int res, float x0, float z0, float x1, float z1);

    /** The blobs drawn on visible Base layers (cells of at least one half joined by their sides, 3 or more), the
     * biggest first. */
    [[nodiscard]] std::vector<LayoutBase> BaseCentres() const;

    /** The canvas picture: rw x rh RGBA, the visible layers over a dark ground; `only` >= 0 dims the others. */
    void Pixels(std::vector<std::uint8_t>& rgba, int only = -1) const;

    /** Starting drawings: duel, four, river, islands. Replaces the drawing; `symmetry` gets the one it is drawn in
     * (rot2, mirror_xz, mirror_x). False for an unknown id. */
    bool ApplyTemplate(const std::string& id, std::string& symmetry);
    struct TemplateInfo
    {
      const char* id;
      const char* label;
      const char* symmetry;
      const char* tip;
    };
    [[nodiscard]] static const std::vector<TemplateInfo>& Templates();

    /** The drawing as JSON (cells run-length coded in 1/255 steps); "" when nothing is drawn and no marker was
     * generated. */
    [[nodiscard]] std::string Save() const;
    bool Load(const std::string& text, std::string& error);

  private:
    LayoutLayer MakeLayer(LayoutKind kind, const std::string& name);
    [[nodiscard]] std::vector<std::pair<float, float>> CellImages(float cx, float cz) const;
    template <typename Inside>
    int FillWhere(int i, float x0, float z0, float x1, float z1, Inside inside, float strength, bool erase);

    int mRes = kDefaultRes;
    LayoutFrame mFrame;
    std::vector<LayoutLayer> mLayers;
    int mNextId = 1;
    LayoutImages mImages;
    bool mStroking = false;
    LayoutStroke mStroke;
  };

  struct LayoutBuildOptions
  {
    /** The symmetrize op's mode for the result ("" or "none": as built), about (cx, cz). */
    std::string symmetry;
    float cx = 0.0f;
    float cz = 0.0f;
    int turns = 3; // rotn: the number of turns
    /** 0..1: droplet erosion over the result before the symmetry (Studio's weathering: gullies). */
    float weather = 0.0f;
  };

  /**
   * The layout's heights on the grid of `like`, and (when `masks` is given) the softened mask of every layer. Layers
   * apply from the first to the last; clamped to 0..400.
   */
  bool BuildLayout(
    const MapLayout& layout,
    const field::Grid& like,
    const LayoutBuildOptions& options,
    field::Grid& height,
    std::vector<field::Grid>* masks,
    std::string& error
  );

  /** Layer i's mask on the grid of `like`: softened by its kind's soft edge, or plain. */
  bool LayoutLayerMask(
    const MapLayout& layout,
    const field::Grid& like,
    int i,
    bool soft,
    field::Grid& out,
    std::string& error
  );

  /** Whether layer i has cells above `level` (a water layer above 0.3 sets the water level). */
  [[nodiscard]] bool LayoutLayerHas(const LayoutLayer& layer, float level);
} // namespace faf::editor
