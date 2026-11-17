#include "editor/ui/EdPerf.h"

#include <algorithm>
#include <cstdio>
#include <utility>
#include <vector>

namespace faf::editor
{
  EdPerf& EdPerf::Get()
  {
    static EdPerf perf;
    return perf;
  }

  void EdPerf::SetOn(
    const bool on
  )
  {
    mOn = on;
    mSections.clear();
    mElapsed = 0.0;
    mFrames = 0;
  }

  void EdPerf::Add(
    const std::string& section,
    const double ms
  )
  {
    if (!mOn) {
      return;
    }
    Section& s = mSections[section];
    s.total += ms;
    s.thisFrame += ms;
  }

  bool EdPerf::EndFrame(
    const double frameSeconds,
    std::string& report,
    const double period
  )
  {
    if (!mOn) {
      return false;
    }
    for (auto& [name, s] : mSections) {
      s.worst = std::max(s.worst, s.thisFrame);
      s.thisFrame = 0.0;
    }
    mElapsed += frameSeconds;
    ++mFrames;
    if (mElapsed < period || mFrames == 0) {
      return false;
    }
    std::vector<std::pair<std::string, Section>> sorted(mSections.begin(), mSections.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
      return a.second.total > b.second.total;
    });
    char line[200];
    (void)std::snprintf(
      line,
      sizeof(line),
      "Performance over %.1f s, %d frames (%.1f fps, %.1f ms a frame):",
      mElapsed,
      mFrames,
      mFrames / mElapsed,
      mElapsed * 1000.0 / mFrames
    );
    report = line;
    for (const auto& [name, s] : sorted) {
      (void)std::snprintf(line, sizeof(line), " %s %.2f ms (slowest %.1f);", name.c_str(), s.total / mFrames, s.worst);
      report += line;
    }
    if (!sorted.empty()) {
      report.pop_back();
    }
    mSections.clear();
    mElapsed = 0.0;
    mFrames = 0;
    return true;
  }

  EdPerf::Scope::Scope(
    const char* const section
  )
  {
    if (EdPerf::Get().On()) {
      mSection = section;
      mStart = std::chrono::steady_clock::now();
    }
  }

  EdPerf::Scope::~Scope()
  {
    if (mSection != nullptr) {
      EdPerf::Get().Add(
        mSection, std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - mStart).count()
      );
    }
  }
} // namespace faf::editor
