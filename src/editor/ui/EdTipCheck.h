#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The tooltip coverage check (FAF Studio's tipcheck, `/tipcheck`): the mouse is moved over every panel on a grid,
   * one point a frame (ImGui's mouse, never the real cursor), with the hover delays at zero; each control the mouse
   * hovered is counted with whether a tooltip showed while it did. The log lists the controls without one.
   */
  struct TipRect
  {
    std::string window;
    float x = 0.0f;
    float y = 0.0f;
    float width = 0.0f;
    float height = 0.0f;
  };

  struct TipPoint
  {
    std::string window;
    float x = 0.0f;
    float y = 0.0f;
  };

  /** Pure: the grid points over each rectangle, `step` apart, half a step in from its edges. */
  [[nodiscard]] std::vector<TipPoint> TipCheckPoints(const std::vector<TipRect>& rects, float step);

  /** Pure: what the check saw per control (by ImGui id): hovered where, and whether any hover showed a tooltip. */
  class TipTally
  {
  public:
    struct Control
    {
      std::uint32_t id = 0;
      std::string window;
      float x = 0.0f;
      float y = 0.0f;
      bool tooltip = false;
    };

    void Record(std::uint32_t id, const std::string& window, float x, float y, bool tooltip);
    [[nodiscard]] const std::vector<Control>& Controls() const noexcept
    {
      return mControls;
    }
    [[nodiscard]] int WithTooltip() const noexcept;
    [[nodiscard]] std::vector<Control> Missing() const;

  private:
    std::vector<Control> mControls;
  };

  /** The check in a run: start, a point before each frame, the result after it. */
  class EdTipCheck
  {
  public:
    void Start(int framesToWait);
    [[nodiscard]] bool Running() const noexcept
    {
      return mState != State::Off && mState != State::Done;
    }
    [[nodiscard]] bool Done() const noexcept
    {
      return mState == State::Done;
    }
    /** Before ImGui::NewFrame: the next point fed as ImGui's mouse. */
    void BeforeNewFrame();
    /** After ImGui::Render: what this frame's point hovered; the summary in the log when the last point is done. */
    void AfterRender();

  private:
    enum class State
    {
      Off,
      Waiting,
      Walking,
      Done
    };
    State mState = State::Off;
    int mWait = 0;
    std::vector<TipPoint> mPoints;
    std::size_t mNext = 0;
    bool mFed = false;
    TipTally mTally;
    float mSavedDelays[3] = {};
  };
} // namespace faf::editor
