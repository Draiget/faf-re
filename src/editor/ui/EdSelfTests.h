#pragma once

// Self tests inside the live editor (FAF Studio's selftest_*.lua and selftest_perfbudget.lua): checks that run against
// the open map through the editor's own operations and undo (each leaves the map as it found it), one a frame, and a
// frame-time budget measured over a number of frames. The app registers the tests (EdApp.cpp); Help > Self tests shows
// them, `/selftests` runs them all and logs the result.

#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdSelfTests
  {
  public:
    /** A test: "" when it passed, else what went wrong; "skip: <why>" when it couldn't run here. */
    struct Test
    {
      std::string name;
      std::function<std::string()> run;
      std::string result;
      bool ran = false;
    };
    void Add(const std::string& name, std::function<std::string()> run);
    /** Runs every test, one a frame, then the frame budget (`frames` frames: mean and worst against the budget). */
    void RunAll(int budgetFrames = 120);
    /** Each frame: the next test, or a frame of the budget. */
    void Frame(float frameSeconds);
    void Draw(bool& open);
    [[nodiscard]] bool Running() const noexcept
    {
      return mNext >= 0;
    }
    [[nodiscard]] bool Finished() const noexcept
    {
      return mFinished;
    }
    [[nodiscard]] int Failed() const noexcept;
    /** The last click sweep's or layout check's lines (EdUiQa), shown under the tests; and asks for them. */
    std::vector<std::string> qaReport;
    bool askClickSweep = false;
    bool askLayoutCheck = false;
    /** The stress the budget is measured under (Studio's perfstress: thousands of markers), put on before and taken off
     * after; set by the app. */
    std::function<void()> stressOn;
    std::function<void()> stressOff;
    /** The budget: mean and worst frame (ms) the editor should stay under. */
    float meanBudgetMs = 33.0f;
    float worstBudgetMs = 150.0f;

  private:
    void Summary();
    std::vector<Test> mTests;
    int mNext = -1;
    int mBudgetFrames = 0;
    int mBudgetLeft = 0;
    std::vector<float> mFrameMs;
    std::string mBudgetResult;
    bool mFinished = false;
  };
} // namespace faf::editor
