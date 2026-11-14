#include "editor/EdLog.h"

#include <cstring>
#include "editor/ui/EdControls.h"

#include <cstdio>

#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    constexpr std::size_t kMaxLines = 5000U;
  }

  EdLog::EdLog()
    : gpg::LogTarget(true)
  {}

  EdLog::~EdLog()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mTimesFile != nullptr) {
      std::fclose(mTimesFile);
      mTimesFile = nullptr;
    }
  }

  void EdLog::WriteTimesTo(
    const std::string& path
  )
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mTimesFile != nullptr) {
      std::fclose(mTimesFile);
    }
    mTimesFile = std::fopen(path.c_str(), "w");
  }

  std::vector<std::string> EdLog::Warnings() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::string> out;
    for (const Line& line : mLines) {
      if (line.level == gpg::LogSeverity::Warn) {
        out.push_back(line.text);
      }
    }
    return out;
  }

  void EdLog::SetFilter(
    const std::string& text
  )
  {
    (void)std::snprintf(mFilter, sizeof(mFilter), "%s", text.c_str());
  }

  void EdLog::OnMessage(
    const gpg::LogSeverity level,
    const fa::string& message,
    const fa::vector<fa::string>& context,
    const int previousDepth
  )
  {
    (void)context;
    (void)previousDepth;
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - mStart).count();
    const std::lock_guard<std::mutex> lock(mMutex);
    mLines.push_back(Line{level, std::string(message.c_str()), seconds});
    if (mTimesFile != nullptr) {
      std::fprintf(mTimesFile, "%9.3f %s\n", seconds, message.c_str());
      std::fflush(mTimesFile);
    }
    if (mLines.size() > kMaxLines) {
      mLines.pop_front();
    }
    static constexpr char kTrace[] = "EDMISSION trace ";
    if (std::strncmp(message.c_str(), kTrace, sizeof(kTrace) - 1) == 0 && mMissionTrace.size() < 5000) {
      mMissionTrace.emplace_back(message.c_str() + sizeof(kTrace) - 1);
    }
    if (level == gpg::LogSeverity::Warn) {
      ++mWarnings;
      if (mCapturing && mCaptured.size() < 500) {
        mCaptured.emplace_back(message.c_str());
      }
    }
  }

  void EdLog::BeginCapture()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCaptured.clear();
    mCapturing = true;
  }

  std::vector<std::string> EdLog::EndCapture()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCapturing = false;
    return std::move(mCaptured);
  }

  int EdLog::WarningCount() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mWarnings;
  }

  void EdLog::Draw()
  {
    ImGui::SetNextItemWidth(-560.0f);
    ImGui::InputTextWithHint("##filter", "Filter", mFilter, sizeof(mFilter));
    ImGui::SameLine();
    ImGui::Checkbox("Info", &mShowInfo);
    ImGui::SameLine();
    ImGui::Checkbox("Warnings", &mShowWarnings);
    ImGui::SameLine();
    ImGui::Checkbox("Debug", &mShowDebug);
    ImGui::SameLine();
    if (ImGui::Button("Copy")) {
      // The lines shown (filter and levels), as text.
      const std::lock_guard<std::mutex> lock(mMutex);
      std::string text;
      for (const Line& line : mLines) {
        if (Shown(line)) {
          text += line.text + "\n";
        }
      }
      ImGui::SetClipboardText(text.c_str());
    }
    if (ImGui::IsItemHovered()) {
      EdSetTooltip("The lines shown, to the clipboard");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Times", &mShowTimes);
    if (ImGui::IsItemHovered()) {
      EdSetTooltip("Each line's time, in seconds since the editor started");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Follow", &mAutoScroll);
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
      const std::lock_guard<std::mutex> lock(mMutex);
      mLines.clear();
    }
    ImGui::Separator();

    if (ImGui::BeginChild("##lines", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar)) {
      const std::lock_guard<std::mutex> lock(mMutex);
      for (const Line& line : mLines) {
        if (!Shown(line)) {
          continue;
        }
        if (mShowTimes) {
          ImGui::TextDisabled("%9.3f", line.seconds);
          ImGui::SameLine();
        }
        if (line.level == gpg::LogSeverity::Warn) {
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%s", line.text.c_str());
        } else if (line.level == gpg::LogSeverity::Debug) {
          ImGui::TextDisabled("%s", line.text.c_str());
        } else {
          ImGui::TextUnformatted(line.text.c_str());
        }
      }
      if (mAutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
      }
    }
    ImGui::EndChild();
  }
  bool EdLog::Shown(
    const Line& line
  ) const
  {
    if (mFilter[0] != '\0' && line.text.find(mFilter) == std::string::npos) {
      return false;
    }
    switch (line.level) {
    case gpg::LogSeverity::Warn:
      return mShowWarnings;
    case gpg::LogSeverity::Debug:
      return mShowDebug;
    default:
      return mShowInfo;
    }
  }

  std::vector<std::string> EdLog::TakeMissionTrace()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::string> out;
    out.swap(mMissionTrace);
    return out;
  }
} // namespace faf::editor
