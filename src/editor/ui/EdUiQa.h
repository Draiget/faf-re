#pragma once

// The editor's own QA runs (FAF Studio's clicksweep.lua and layoutcheck.lua), on Dear ImGui's item hooks
// (cmake/deps/imgui/faf_imgui_hooks.h: every item's box, a widget's label):
//
//   click sweep   presses every button of every panel once (ImGui's mouse, never the real cursor; a popup that
//                 opens is closed with Escape), skipping buttons whose labels say they delete, close, save, upload or
//                 quit; the log lists what it pressed.
//   layout check  at several UI scales, every labelled control of every panel must lie inside its panel across
//                 (rows may scroll) and must not cover another control; the log lists what doesn't.
//
// Both walk the panels (`panels`): what is shown first, then each panel in turn, shown through `showPanel` for the
// check and put back as it was after. The judgements are pure functions; the runner feeds ImGui's mouse.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  struct QaItem
  {
    std::uint32_t id = 0;
    std::string window;
    std::string label;
    int flags = 0; // ImGuiItemStatusFlags
    float x0 = 0, y0 = 0, x1 = 0, y1 = 0;
    // The window's box and whether it can scroll sideways.
    float wx0 = 0, wy0 = 0, wx1 = 0, wy1 = 0;
    bool scrollX = false;
    /** The window's own title bar or dock tab (a press there can drag the panel out into a window of its own). */
    bool title = false;
  };

  /** Whether a control is a plain button the sweep may press (not a checkbox, input, tree node; no risky label). */
  [[nodiscard]] bool QaSweepable(const QaItem& item);

  struct QaLayoutProblem
  {
    std::string window;
    std::string text;
  };
  /**
   * The layout judgement over one frame's items (titles and tabs left out). `slack`: how far a control may reach past
   * the panel's side (ImGui's list rows reach half the item spacing into the window's padding by design).
   */
  [[nodiscard]] std::vector<QaLayoutProblem> QaLayoutProblems(const std::vector<QaItem>& items, float slack = 1.0f);

  class EdUiQa
  {
  public:
    enum class Kind
    {
      ClickSweep,
      LayoutCheck,
    };
    /** Starts a run after `wait` frames. The layout check sets each UI scale through `setScale` and puts it back. */
    void Start(Kind kind, int wait);
    [[nodiscard]] bool Running() const noexcept
    {
      return mState != State::Off && mState != State::Done;
    }
    [[nodiscard]] bool Done() const noexcept
    {
      return mState == State::Done;
    }
    std::function<void(float)> setScale;
    std::function<float()> getScale;
    /** The panels' window names; `showPanel(name, on)` shows or hides one and says whether it was shown. */
    std::function<std::vector<std::string>()> panels;
    std::function<bool(const std::string& window, bool on)> showPanel;
    /** Before ImGui::NewFrame: the mouse (and Escape) the run feeds this frame. */
    void BeforeNewFrame();
    /** After ImGui::NewFrame: the panel being checked brought in front (a docked tab behind another draws nothing). */
    void DuringFrame();
    /** After ImGui::Render: the frame's items read, the run's next step. */
    void AfterRender();
    /** What the last run found, in lines. */
    [[nodiscard]] const std::vector<std::string>& Report() const noexcept
    {
      return mReport;
    }

  private:
    enum class State
    {
      Off,
      Waiting,
      Running,
      Done,
    };
    void Finish();
    /** The next panel of the walk shown (the one before put back); false when the walk is over. */
    bool NextPanel();
    /** Whether an item belongs to the panel being checked ("" while the first, as-shown pass runs: every window). */
    [[nodiscard]] bool InPanel(const QaItem& item) const;
    void CollectTargets();
    std::vector<std::string> mPanels;
    std::size_t mPanelAt = 0;
    bool mPanelWas = false;
    bool mPanelOpen = false; // mPanels[mPanelAt - 1] was shown by the walk
    bool mCollect = false;
    std::string mFocus;             // the panel to bring in front while it settles
    std::vector<std::string> mSeen; // window + label of every button collected
    int mGone = 0;                  // buttons that went away before their press
    Kind mKind = Kind::ClickSweep;
    State mState = State::Off;
    int mWait = 0;
    std::vector<QaItem> mTargets;
    std::size_t mNext = 0;
    int mPhase = 0; // sweep: 0 move + press, 1 release, 2 settle
    std::vector<std::string> mPressed;
    int mSkipped = 0;
    std::vector<float> mScales;
    std::size_t mScaleAt = 0;
    float mScaleBefore = 1.0f;
    int mSettle = 0;
    std::vector<std::string> mReport;
    std::vector<QaLayoutProblem> mProblems;
  };
} // namespace faf::editor
