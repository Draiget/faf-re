#pragma once

#include "editor/graph/EdNodeGraph.h"

#include <cstdint>
#include <functional>
#include <set>
#include <string>

struct ImVec2;

namespace faf::editor
{
  /**
   * Draws a node graph and edits it, as UE4's material graph does: nodes with a coloured header by category, typed
   * pins, curved links; the wheel zooms at the mouse, the right or middle button drags the view, a right click (or a
   * link dropped on nothing) opens the palette there; the left button selects (Ctrl toggles, a box from empty space),
   * drags nodes, and drags from a pin to link (from a linked input it picks the link up); Alt+click on a pin cuts its
   * links; Delete removes, Ctrl+D duplicates, F frames the selection (or everything).
   */
  class EdNodeCanvas
  {
  public:
    /** The image a node shows under its pins (0: none). */
    using ThumbnailFn = std::function<std::uint64_t(const GraphNode&)>;
    /** A short warning a node shows in its header's tooltip and as a red outline (empty: none). */
    using WarningFn = std::function<std::string(const GraphNode&)>;

    void SetThumbnails(ThumbnailFn fn) { mThumbnail = std::move(fn); }
    void SetWarnings(WarningFn fn) { mWarning = std::move(fn); }

    /** Draws into the rest of the current window; true while the graph changed this frame. */
    bool Draw(NodeGraph& graph);

    [[nodiscard]] const std::set<int>& Selection() const noexcept { return mSelection; }
    void Select(int id);
    /** Adds a node of the type at the canvas's centre (the palette panel's double-click or drop). */
    int AddAtCentre(NodeGraph& graph, const std::string& type);
    /** Frames everything at the next frame. */
    void FrameAll() noexcept { mFrameNext = true; }
    /** A palette panel's item being dragged is dropped here: the payload's id. */
    static constexpr const char* kPalettePayload = "FAF_GRAPH_NODE";

  private:
    enum class Drag : std::uint8_t
    {
      None,
      Pan,
      Move,
      Box,
      Link,
    };

    struct PinHit
    {
      int node = 0;
      int pin = -1;
      bool output = false;
    };

    void DrawPalettePopup(NodeGraph& graph);
    bool PaletteList(NodeGraph& graph, const char* filter, float x, float y);
    void Frame(const NodeGraph& graph, bool selectionOnly);

    ThumbnailFn mThumbnail;
    WarningFn mWarning;
    std::set<int> mSelection;
    float mPanX = 40.0f;
    float mPanY = 200.0f;
    float mZoom = 1.0f;
    float mCanvasX = 0.0f;
    float mCanvasY = 0.0f;
    float mCanvasW = 0.0f;
    float mCanvasH = 0.0f;
    bool mFrameNext = true;
    Drag mDrag = Drag::None;
    float mDragStartX = 0.0f;
    float mDragStartY = 0.0f;
    bool mRightMoved = false;
    PinHit mLinkFrom;
    // The palette popup: where it opened (graph units) and the pin a new node links to.
    float mPopupX = 0.0f;
    float mPopupY = 0.0f;
    PinHit mPopupPin;
    char mPopupFilter[64] = {};
    bool mPopupFocus = false;
  };

  /** A category's header colour (ImU32). */
  std::uint32_t NodeCategoryColor(const std::string& category);
} // namespace faf::editor
