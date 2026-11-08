#include "editor/EdLog.h"

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

  void EdLog::OnMessage(
    const gpg::LogSeverity level,
    const fa::string& message,
    const fa::vector<fa::string>& context,
    const int previousDepth
  )
  {
    (void)context;
    (void)previousDepth;
    const std::lock_guard<std::mutex> lock(mMutex);
    mLines.push_back(Line{level, std::string(message.c_str())});
    if (mLines.size() > kMaxLines) {
      mLines.pop_front();
    }
    if (level == gpg::LogSeverity::Warn) {
      ++mWarnings;
    }
  }

  int EdLog::WarningCount() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mWarnings;
  }

  void EdLog::Draw()
  {
    ImGui::SetNextItemWidth(-200.0f);
    ImGui::InputTextWithHint("##filter", "Filter", mFilter, sizeof(mFilter));
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
      const bool filtered = mFilter[0] != '\0';
      for (const Line& line : mLines) {
        if (filtered && line.text.find(mFilter) == std::string::npos) {
          continue;
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
} // namespace faf::editor
