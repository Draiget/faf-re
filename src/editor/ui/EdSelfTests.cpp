#include "editor/ui/EdSelfTests.h"

#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <numeric>

namespace faf::editor
{
  void EdSelfTests::Add(
    const std::string& name,
    std::function<std::string()> run
  )
  {
    mTests.push_back({name, std::move(run), {}, false});
  }

  void EdSelfTests::RunAll(
    const int budgetFrames
  )
  {
    for (Test& t : mTests) {
      t.ran = false;
      t.result.clear();
    }
    mNext = 0;
    mBudgetFrames = budgetFrames;
    mBudgetLeft = 0;
    mFrameMs.clear();
    mBudgetResult.clear();
    mFinished = false;
    gpg::Logf("editor: self tests: %zu tests and a %d-frame budget", mTests.size(), budgetFrames);
  }

  int EdSelfTests::Failed() const noexcept
  {
    int failed = 0;
    for (const Test& t : mTests) {
      failed += t.ran && !t.result.empty() && !t.result.starts_with("skip:") ? 1 : 0;
    }
    return failed;
  }

  void EdSelfTests::Frame(
    const float frameSeconds
  )
  {
    if (mNext < 0) {
      return;
    }
    if (static_cast<std::size_t>(mNext) < mTests.size()) {
      Test& t = mTests[static_cast<std::size_t>(mNext)];
      try {
        t.result = t.run ? t.run() : std::string("no test");
      } catch (const std::exception& e) {
        t.result = std::string("threw: ") + e.what();
      } catch (...) {
        t.result = "threw";
      }
      t.ran = true;
      gpg::Logf("editor: self test %s: %s", t.name.c_str(), t.result.empty() ? "passed" : t.result.c_str());
      ++mNext;
      if (static_cast<std::size_t>(mNext) == mTests.size()) {
        mBudgetLeft = mBudgetFrames + 10; // the first frames after the tests settle
        if (stressOn) {
          stressOn();
        }
      }
      return;
    }
    if (mBudgetLeft > 0) {
      if (mBudgetLeft <= mBudgetFrames) {
        mFrameMs.push_back(frameSeconds * 1000.0f);
      }
      --mBudgetLeft;
      if (mBudgetLeft > 0) {
        return;
      }
      if (stressOff) {
        stressOff();
      }
    }
    if (!mFrameMs.empty()) {
      const float mean = std::accumulate(mFrameMs.begin(), mFrameMs.end(), 0.0f) / static_cast<float>(mFrameMs.size());
      const float worst = *std::max_element(mFrameMs.begin(), mFrameMs.end());
      char text[200];
      (void)std::snprintf(
        text,
        sizeof(text),
        "frames: mean %.1f ms (budget %.0f), worst %.1f ms (budget %.0f) over %zu frames%s",
        static_cast<double>(mean),
        static_cast<double>(meanBudgetMs),
        static_cast<double>(worst),
        static_cast<double>(worstBudgetMs),
        mFrameMs.size(),
        mean <= meanBudgetMs && worst <= worstBudgetMs ? "" : ": OVER BUDGET"
      );
      mBudgetResult = text;
    }
    mNext = -1;
    mFinished = true;
    Summary();
  }

  void EdSelfTests::Summary()
  {
    int passed = 0;
    int skipped = 0;
    for (const Test& t : mTests) {
      passed += t.ran && t.result.empty() ? 1 : 0;
      skipped += t.ran && t.result.starts_with("skip:") ? 1 : 0;
    }
    gpg::Logf(
      "editor: self tests: %d passed, %d failed, %d skipped; %s", passed, Failed(), skipped, mBudgetResult.c_str()
    );
  }

  void EdSelfTests::Draw(
    bool& open
  )
  {
    ImGui::SetNextWindowSize(ImVec2(Em(420.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Self tests###SelfTests"), &open)) {
      ImGui::End();
      return;
    }
    ImGui::TextWrapped(
      "Checks that run inside the editor on the open map, through its own operations and undo (each leaves the map as "
      "it found it), then the frame time against a budget. The log has the details."
    );
    ImGui::BeginDisabled(Running());
    if (PrimaryButton("Run them all")) {
      RunAll();
    }
    ImGui::EndDisabled();
    if (Running()) {
      ImGui::SameLine();
      ImGui::TextDisabled("running...");
    }
    for (const Test& t : mTests) {
      const ImU32 colour = !t.ran       ? IM_COL32(160, 160, 160, 255)
        : t.result.empty()              ? IM_COL32(110, 220, 120, 255)
        : t.result.starts_with("skip:") ? IM_COL32(200, 200, 120, 255)
                                        : IM_COL32(255, 110, 100, 255);
      ImGui::PushStyleColor(ImGuiCol_Text, colour);
      ImGui::TextWrapped(
        "%s  %s%s",
        !t.ran                            ? "-"
          : t.result.empty()              ? "ok"
          : t.result.starts_with("skip:") ? "skip"
                                          : "FAIL",
        t.name.c_str(),
        t.result.empty() ? "" : (": " + t.result).c_str()
      );
      ImGui::PopStyleColor();
    }
    if (!mBudgetResult.empty()) {
      ImGui::TextWrapped("%s", mBudgetResult.c_str());
    }
    ImGui::SeparatorText("The panels themselves");
    if (ImGui::Button("Click sweep")) {
      askClickSweep = true;
    }
    EdSetItemTooltip(
      "Presses every plain button of every shown panel once (not ones that delete, save, apply or quit)"
    );
    ImGui::SameLine();
    if (ImGui::Button("Layout check")) {
      askLayoutCheck = true;
    }
    EdSetItemTooltip("At 100, 125, 150 and 200 %: every control inside its panel across, none covering another");
    for (const std::string& line : qaReport) {
      ImGui::TextWrapped("%s", line.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
