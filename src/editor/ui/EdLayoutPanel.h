#pragma once

#include "editor/tools/EdLayoutMarkers.h"
#include "editor/tools/EdMapLayout.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdDocument;

  /**
   * The Layout workspace's drawing (the consolidated design's Terrain > Layout canvas; FAF Studio's layout panels):
   * Layout layers (templates, the resolution, the list of layers, the selected one's settings, the generator's
   * ground and water heights and seed, Generate terrain) and Layout canvas (the tools over the drawing of the playable
   * area: brush, eraser, line, rectangle, ellipse and lasso, under the editor's symmetry; right button erases). Every
   * stroke and change is an undo step of the map; Generate terrain writes the heights (and the water level when a
   * Water layer has paint) as one step.
   */
  class EdLayoutPanel
  {
  public:
    explicit EdLayoutPanel(EdDocument& document);
    ~EdLayoutPanel();
    EdLayoutPanel(const EdLayoutPanel&) = delete;
    EdLayoutPanel& operator=(const EdLayoutPanel&) = delete;

    void DrawLayersPanel(bool& open, bool mapOpen);
    void DrawCanvasPanel(bool& open, bool mapOpen);
    /**
     * Starts and resources (Studio's start and resource generator): where the starts come from, what lies around
     * each, the rules; Preview shows the plan on the canvas, Place markers writes it as one undo step.
     */
    void DrawStartsPanel(bool& open, bool mapOpen);

    [[nodiscard]] LayoutMarkerSettings& MarkerSettings() noexcept
    {
      return mMarkers;
    }
    /** Preview or Place was pressed (the app plans against the map, and places). */
    [[nodiscard]] bool TakePlanAsk() noexcept
    {
      const bool asked = mPlanAsked;
      mPlanAsked = false;
      return asked;
    }
    [[nodiscard]] bool TakePlaceAsk() noexcept
    {
      const bool asked = mPlaceAsked;
      mPlaceAsked = false;
      return asked;
    }
    void AskPlace() noexcept
    {
      mPlaceAsked = true;
    }
    void AskPlan() noexcept
    {
      mPlanAsked = true;
    }
    /** The plan shown on the canvas (none: nothing shown), and what the last plan or placing gave. */
    void SetPlan(
      std::optional<LayoutMarkerPlan> plan,
      std::string status
    )
    {
      mPlan = std::move(plan);
      mStartsStatus = std::move(status);
    }

    /** Generate terrain was pressed (the app builds the heights and writes them). */
    [[nodiscard]] bool TakeGenerateAsk() noexcept
    {
      const bool asked = mGenerateAsked;
      mGenerateAsked = false;
      return asked;
    }
    void AskGenerate() noexcept
    {
      mGenerateAsked = true;
    }
    /** A template's symmetry for the app to set as the editor's ("" none). */
    [[nodiscard]] bool TakeSymmetryAsk(
      std::string& symmetry
    )
    {
      if (mSymmetryAsk.empty()) {
        return false;
      }
      symmetry = std::move(mSymmetryAsk);
      mSymmetryAsk.clear();
      return true;
    }
    void SetStatus(
      std::string status
    )
    {
      mStatus = std::move(status);
    }
    /** The copies of a point under a symmetry by its op name (rot2, mirror_xz, mirror_x): a template draws its
     * master part under its own symmetry. */
    void SetImagesFor(
      std::function<LayoutImages(const std::string&)> imagesFor
    )
    {
      mImagesFor = std::move(imagesFor);
    }
    /** A template applied (test runs, `/layouttest`); the drawing's state as one undo step. */
    bool ApplyTemplate(const std::string& id);

    enum class Tool : std::uint8_t
    {
      Brush,
      Eraser,
      Line,
      Rect,
      Ellipse,
      Lasso,
    };

  private:
    void Changed(MapLayout before);
    void BeginChange();
    void EndChange(bool edited);
    void UpdateImage();
    void DrawCanvas();
    void PaintAt(float cx, float cz, bool erase);

    EdDocument& mDocument;
    Tool mTool = Tool::Brush;
    float mSize = 8.0f; // brush radius in cells
    float mHardness = 0.6f;
    float mStrength = 1.0f;
    bool mGenerateAsked = false;
    std::string mSymmetryAsk;
    std::string mStatus;
    std::optional<MapLayout> mEditBefore; // a setting being dragged: the drawing before it
    // The stroke or shape being drawn.
    bool mStroking = false;
    bool mErasing = false;
    float mLastX = 0.0f;
    float mLastZ = 0.0f;
    float mStartX = 0.0f;
    float mStartZ = 0.0f;
    std::vector<std::pair<float, float>> mLasso;
    // The drawing's picture.
    std::uint64_t mImage = 0;
    std::uint64_t mImageRevision = 0;
    int mImageSelected = -1;
    std::vector<std::uint64_t> mRetired;
    std::function<LayoutImages(const std::string&)> mImagesFor;
    LayoutMarkerSettings mMarkers;
    std::optional<LayoutMarkerPlan> mPlan;
    std::string mStartsStatus;
    bool mPlanAsked = false;
    bool mPlaceAsked = false;
  };
} // namespace faf::editor
