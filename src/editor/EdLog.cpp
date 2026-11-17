#include "editor/EdLog.h"

#include <cstring>
#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"

#include <algorithm>

#include <cstdio>
#include <print>

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

  std::vector<std::string> EdLog::Tail(
    const std::size_t count
  ) const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::string> out;
    const std::size_t first = mLines.size() > count ? mLines.size() - count : 0;
    for (std::size_t i = first; i < mLines.size(); ++i) {
      const Line& line = mLines[i];
      const char* const level = line.level == gpg::LogSeverity::Warn ? "warning"
        : line.level == gpg::LogSeverity::Info                       ? "info"
                                                                     : "debug";
      char head[48];
      (void)std::snprintf(head, sizeof(head), "%9.2f %s: ", line.seconds, level);
      out.push_back(head + line.text);
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
    // The Run panel's state line, once a second during a test play: kept apart, not shown.
    static constexpr char kLive[] = "EDMISSION live ";
    if (std::strncmp(message.c_str(), kLive, sizeof(kLive) - 1) == 0) {
      mMissionLive = message.c_str() + sizeof(kLive) - 1;
      return;
    }
    // The Unit lab's Test in game: the unit under test, once a second.
    static constexpr char kUnitTest[] = "EDUNITTEST live ";
    if (std::strncmp(message.c_str(), kUnitTest, sizeof(kUnitTest) - 1) == 0) {
      mUnitTestLive = message.c_str() + sizeof(kUnitTest) - 1;
      return;
    }
    // Its notes (which builder builds it, none does, no second army): kept for the panel and shown.
    static constexpr char kUnitTestNote[] = "EDUNITTEST note ";
    if (std::strncmp(message.c_str(), kUnitTestNote, sizeof(kUnitTestNote) - 1) == 0) {
      mUnitTestNote = message.c_str() + sizeof(kUnitTestNote) - 1;
    }
    mLines.push_back(Line{level, std::string(message.c_str()), seconds});
    if (mTimesFile != nullptr) {
      std::println(mTimesFile, "{:9.3f} {}", seconds, message.c_str());
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
    // The filter takes what the controls after it leave (at least 12 em); they wrap when the panel is narrower.
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float controls = CheckboxWidth("Info") + CheckboxWidth("Warnings") + CheckboxWidth("Debug") +
      ButtonWidth("Copy") + CheckboxWidth("Times") + CheckboxWidth("Follow") + ButtonWidth("Clear") + spacing * 7.0f;
    ImGui::SetNextItemWidth(std::max(Em(12.0f), ImGui::GetContentRegionAvail().x - controls));
    ImGui::InputTextWithHint("##filter", "Filter", mFilter, sizeof(mFilter));
    SameLineIfFits(CheckboxWidth("Info"));
    ImGui::Checkbox("Info", &mShowInfo);
    SameLineIfFits(CheckboxWidth("Warnings"));
    ImGui::Checkbox("Warnings", &mShowWarnings);
    SameLineIfFits(CheckboxWidth("Debug"));
    ImGui::Checkbox("Debug", &mShowDebug);
    SameLineIfFits(ButtonWidth("Copy"));
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
    SameLineIfFits(CheckboxWidth("Times"));
    ImGui::Checkbox("Times", &mShowTimes);
    if (ImGui::IsItemHovered()) {
      EdSetTooltip("Each line's time, in seconds since the editor started");
    }
    SameLineIfFits(CheckboxWidth("Follow"));
    ImGui::Checkbox("Follow", &mAutoScroll);
    SameLineIfFits(ButtonWidth("Clear"));
    if (ImGui::Button("Clear")) {
      const std::lock_guard<std::mutex> lock(mMutex);
      mLines.clear();
    }
    ImGui::Separator();

    const float footer = ImGui::GetFrameHeightWithSpacing();
    if (
      ImGui::BeginChild("##lines", ImVec2(0.0f, -footer), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar)
    ) {
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
    // The console line: Enter runs it, Up and Down walk the history.
    ImGui::SetNextItemWidth(-1.0f);
    if (
      ImGui::InputTextWithHint(
        "##console",
        "Lua (=expr prints it; sim <code> runs in the sim; con <command> the engine's console)",
        mCommand,
        sizeof(mCommand),
        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory,
        &EdLog::HistoryCallback,
        this
      )
    ) {
      std::string line = mCommand;
      if (!line.empty()) {
        mCommands.push_back(line);
        if (mHistory.empty() || mHistory.back() != line) {
          mHistory.push_back(line);
          if (mHistory.size() > 50) {
            mHistory.erase(mHistory.begin());
          }
        }
      }
      mCommand[0] = '\0';
      mHistoryAt = -1;
      ImGui::SetKeyboardFocusHere(-1); // stays in the line for the next one
    }
  }

  int EdLog::HistoryCallback(
    ImGuiInputTextCallbackData* const data
  )
  {
    auto* const log = static_cast<EdLog*>(data->UserData);
    if (log == nullptr || log->mHistory.empty()) {
      return 0;
    }
    const int count = static_cast<int>(log->mHistory.size());
    if (data->EventKey == ImGuiKey_UpArrow) {
      log->mHistoryAt = log->mHistoryAt < 0 ? count - 1 : std::max(0, log->mHistoryAt - 1);
    } else if (data->EventKey == ImGuiKey_DownArrow) {
      log->mHistoryAt = log->mHistoryAt < 0 || log->mHistoryAt + 1 >= count ? -1 : log->mHistoryAt + 1;
    }
    data->DeleteChars(0, data->BufTextLen);
    if (log->mHistoryAt >= 0) {
      data->InsertChars(0, log->mHistory[static_cast<std::size_t>(log->mHistoryAt)].c_str());
    }
    return 0;
  }
  bool EdLog::Shown(
    const Line& line
  ) const
  {
    if (mFilter[0] != '\0' && !line.text.contains(mFilter)) {
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

  bool EdLog::TakeUnitTestNote(
    std::string& out
  )
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mUnitTestNote.empty()) {
      return false;
    }
    out.swap(mUnitTestNote);
    mUnitTestNote.clear();
    return true;
  }

  bool EdLog::TakeUnitTestLive(
    std::string& out
  )
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mUnitTestLive.empty()) {
      return false;
    }
    out.swap(mUnitTestLive);
    mUnitTestLive.clear();
    return true;
  }

  bool EdLog::TakeMissionLive(
    std::string& out
  )
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mMissionLive.empty()) {
      return false;
    }
    out.swap(mMissionLive);
    mMissionLive.clear();
    return true;
  }

  std::vector<std::string> EdLog::TakeMissionTrace()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::string> out;
    out.swap(mMissionTrace);
    return out;
  }
} // namespace faf::editor
