#include "moho/app/AppPrivate.h"
#include "legacy/thread/Mutex.h"

#include "imgui.h"

namespace
{
  constexpr std::size_t kMaxCommittedLogLines = 10000;
  constexpr std::uint32_t kCustomFilterCategoryBit = 1u << 4;
  constexpr std::uint32_t kWarningCategoryValue = 2u;
  constexpr std::uint32_t kErrorCategoryValue = 3u;
  constexpr std::size_t kReplayIndentWidth = 4u;
  constexpr const char* kLogCategoryPreferenceKeys[] = {
    "Options.Log.Debug",
    "Options.Log.Info",
    "Options.Log.Warn",
    "Options.Log.Error",
    "Options.Log.Custom",
  };
  constexpr bool kLogCategoryPreferenceDefaults[] = {
    false,
    true,
    true,
    true,
    true,
  };
  constexpr const char* kLogFilterPreferenceKey = "Options.Log.Filter";
  constexpr const char* kLogFilterPreferenceDefault = "*DEBUG:";
  constexpr const char* kLogWindowXPreferenceKey = "Windows.Log.x";
  constexpr const char* kLogWindowYPreferenceKey = "Windows.Log.y";
  constexpr const char* kLogWindowWidthPreferenceKey = "Windows.Log.width";
  constexpr const char* kLogWindowHeightPreferenceKey = "Windows.Log.height";
  constexpr std::int32_t kLogWindowGeometryFallback = -1;

  constexpr std::int32_t kLogWindowDefaultWidth = 640;
  constexpr std::int32_t kLogWindowDefaultHeight = 480;

  // The colour each category's lines are written in (TextAttr colours in the binary); the
  // replayed context lines use the Info colour. Info was black on the rich edit's white; the
  // window is dark now, so Info is light grey.
  [[nodiscard]] ImVec4 TextColourForCategory(
    const std::uint32_t category
  )
  {
    switch (category) {
    case 0u:
      return ImVec4(0x80 / 255.0f, 0x80 / 255.0f, 0x80 / 255.0f, 1.0f);
    case kWarningCategoryValue:
      return ImVec4(0xF7 / 255.0f, 0xA1 / 255.0f, 0x00 / 255.0f, 1.0f);
    case kErrorCategoryValue:
      return ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
    default:
      return ImVec4(0.86f, 0.86f, 0.86f, 1.0f);
    }
  }

  [[nodiscard]] std::string Utf8Of(
    const std::wstring& text
  )
  {
    return gpg::STR_WideToUtf8(text.c_str()).c_str();
  }
} // namespace

/**
 * Address: 0x004F73B0 (FUN_004F73B0)
 *
 * What it does:
 * Constructs one wide stream/buffer helper used by log-window text formatting.
 */
moho::WWinLogTextBuilder::WWinLogTextBuilder() = default;

/**
 * Address: 0x004F74D0 (FUN_004F74D0)
 *
 * What it does:
 * Finalizes stream state and returns the accumulated wide text.
 */
const std::wstring& moho::WWinLogTextBuilder::Finalize() const noexcept
{
  return mText;
}

void moho::WWinLogTextBuilder::Clear() noexcept
{
  mText.clear();
  mFieldWidth = 0;
  mFillCodePoint = L' ';
  mLeftAlign = false;
}

/**
 * Address: 0x004F98F0 (FUN_004F98F0)
 *
 * What it does:
 * Emits one code-point with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteCodePoint(
  const wchar_t codePoint
)
{
  const std::wstring oneCodePoint(1, codePoint);
  WriteWideText(oneCodePoint);
}

/**
 * Address: 0x004F9B80 (FUN_004F9B80)
 *
 * What it does:
 * Emits one wide string with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteWideText(
  const std::wstring& text
)
{
  const std::size_t paddingCount = mFieldWidth > text.size() ? mFieldWidth - text.size() : 0;
  if (!mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mText += text;

  if (mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mFieldWidth = 0;
}

/**
 * Address: 0x004FA000 (FUN_004FA000)
 *
 * What it does:
 * Emits one UTF-8 fragment by widening it then appending with width behavior.
 */
void moho::WWinLogTextBuilder::WriteUtf8Text(
  const fa::string& text
)
{
  WriteWideText(gpg::STR_Utf8ToWide(text.c_str()));
}

/**
 * Address: 0x004FA2C0 (FUN_004FA2C0)
 *
 * What it does:
 * Emits one decoded wide code-point.
 */
void moho::WWinLogTextBuilder::WriteDecodedCodePoint(
  const wchar_t codePoint
)
{
  WriteCodePoint(codePoint);
}

/**
 * Address: 0x004F5AB0 (FUN_004F5AB0)
 *
 * What it does:
 * Emits one run of space code-points.
 */
void moho::WWinLogTextBuilder::WriteSpaces(
  std::size_t count
)
{
  while (count > 0) {
    WriteCodePoint(L' ');
    --count;
  }
}

bool moho::CWinLogLine::IsReplayEntry() const noexcept
{
  return isReplayEntry != 0u;
}

const wchar_t* moho::CWinLogLine::SeverityPrefix() const noexcept
{
  switch (categoryMask) {
  case 0u:
    return L"DEBUG: ";
  case kWarningCategoryValue:
    return L"WARNING: ";
  case kErrorCategoryValue:
    return L"ERROR: ";
  default:
    return L"INFO: ";
  }
}

/**
 * Address: 0x004F38F0 (FUN_004F38F0, ??0CWinLogTarget@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes the global log-target owner and auto-registers it with gpg logging.
 */
moho::CWinLogTarget::CWinLogTarget()
  : gpg::LogTarget(true)
{}

/**
 * Address: 0x004F39B0 (FUN_004F39B0)
 * Mangled deleting-dtor thunk: 0x004F3990 (FUN_004F3990)
 *
 * What it does:
 * Releases pending/committed vectors and tears down base log-target registration.
 */
moho::CWinLogTarget::~CWinLogTarget() = default;

/**
 * Address: 0x004F6F40 (FUN_004F6F40)
 *
 * What it does:
 * Appends one line record to the pending queue.
 */
void moho::CWinLogTarget::AppendPendingLine(
  const CWinLogLine& line
)
{
  mPendingLines.push_back(line);
}

/**
 * Address: 0x004F6F10 (FUN_004F6F10)
 *
 * What it does:
 * Returns committed line count.
 */
std::size_t moho::CWinLogTarget::CommittedLineCount() const
{
  return mCommittedLines.size();
}

const fa::vector<moho::CWinLogLine>& moho::CWinLogTarget::CommittedLines() const
{
  return mCommittedLines;
}

/**
 * Address: 0x004F6FD0 (FUN_004F6FD0)
 *
 * What it does:
 * Replaces committed-line storage with a copy of `nextCommittedLines`.
 */
void moho::CWinLogTarget::ReplaceCommittedLines(
  const fa::vector<CWinLogLine>& nextCommittedLines
)
{
  mCommittedLines = nextCommittedLines;
}

void moho::CWinLogTarget::ResetCommittedLinesFromReplayBuffer(
  const fa::vector<fa::string>& replayLines
)
{
  fa::mutex::scoped_lock scopedLock(lock);

  fa::vector<CWinLogLine> rebuiltLines;
  rebuiltLines.reserve(replayLines.size());
  for (std::size_t index = 0; index < replayLines.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = 1;
    replayLine.text = replayLines[index];
    rebuiltLines.push_back(replayLine);
  }

  ReplaceCommittedLines(rebuiltLines);
}

/**
 * Address: 0x004F6A50 (FUN_004F6A50)
 *
 * What it does:
 * Merges pending lines into committed history and enforces the 10,000 line
 * cap.
 */
void moho::CWinLogTarget::MergePendingLines()
{
  fa::mutex::scoped_lock scopedLock(lock);

  const std::size_t pendingCount = mPendingLines.size();
  const std::size_t committedCount = mCommittedLines.size();
  if (committedCount + pendingCount > kMaxCommittedLogLines) {
    const std::size_t dropCount = (std::min)(committedCount, pendingCount);
    if (dropCount != 0) {
      mCommittedLines.erase(mCommittedLines.begin(), mCommittedLines.begin() + dropCount);
    }
  }

  mCommittedLines.insert(mCommittedLines.end(), mPendingLines.begin(), mPendingLines.end());
  mPendingLines.clear();
}

/**
 * Address: 0x004F6860 (FUN_004F6860)
 *
 * gpg::LogSeverity level, fa::string const &, fa::vector<fa::string> const &, int
 *
 * What it does:
 * Queues replay/context lines plus the current line into the pending log queue.
 */
void moho::CWinLogTarget::OnMessage(
  const gpg::LogSeverity level,
  const fa::string& message,
  const fa::vector<fa::string>& context,
  const int previousDepth
)
{
  fa::mutex::scoped_lock scopedLock(lock);

  std::size_t replayStart = 0;
  if (previousDepth > 0) {
    replayStart = static_cast<std::size_t>(previousDepth);
  }
  if (replayStart > context.size()) {
    replayStart = context.size();
  }

  const std::uint32_t categoryMask = static_cast<std::uint32_t>(level);
  for (std::size_t index = replayStart; index < context.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = categoryMask;
    replayLine.text = context[index];
    AppendPendingLine(replayLine);
  }

  CWinLogLine messageLine{};
  messageLine.isReplayEntry = 0;
  messageLine.sequenceIndex = static_cast<std::uint32_t>(context.size());
  messageLine.categoryMask = categoryMask;
  messageLine.text = message;
  AppendPendingLine(messageLine);

  // Any thread may log, so the window is told rather than called: the binary posted a
  // CLogAdditionEvent while it still held the lock (0x004F6A06 .. 0x004F6A2D), and the GUI thread
  // ran OnTargetPendingLinesChanged for it. The window merges on the main thread every frame.
  if (dialog != nullptr) {
    dialog->NotePendingLines();
  }
}

/**
 * Address: 0x004F4270 (FUN_004F4270)
 *
 * What it does:
 * Creates the "Moho Log" window. The check boxes and the filter start from the preferences, the
 * window from its saved geometry (Windows.Log.*), and the output is filled from the target's
 * committed lines.
 */
moho::WWinLogWindow::WWinLogWindow()
  : platform::tools::ToolWindow("Moho Log", kLogWindowDefaultWidth, kLogWindowDefaultHeight)
  , mOwnerTarget(&sLogWindowTarget)
{
  IUserPrefs* const preferences = USER_GetPreferences();
  for (std::size_t index = 0; index < mCategoryChecks.size(); ++index) {
    mCategoryChecks[index] =
      preferences->GetBoolean(fa::string(kLogCategoryPreferenceKeys[index]), kLogCategoryPreferenceDefaults[index]);
  }
  const fa::string filter =
    preferences->GetString(fa::string(kLogFilterPreferenceKey), fa::string(kLogFilterPreferenceDefault));
  std::snprintf(mFilterEdit.data(), mFilterEdit.size(), "%s", filter.c_str());

  mSavedHeight = preferences->GetInteger(fa::string(kLogWindowHeightPreferenceKey), kLogWindowGeometryFallback);
  mSavedWidth = preferences->GetInteger(fa::string(kLogWindowWidthPreferenceKey), kLogWindowGeometryFallback);
  mSavedY = preferences->GetInteger(fa::string(kLogWindowYPreferenceKey), kLogWindowGeometryFallback);
  mSavedX = preferences->GetInteger(fa::string(kLogWindowXPreferenceKey), kLogWindowGeometryFallback);
  SetBounds(mSavedX, mSavedY, mSavedWidth, mSavedHeight);

  RebuildVisibleLinesFromControls();
}

/**
 * Address: 0x004F5380 (FUN_004F5380)
 *
 * What it does:
 * Detaches from the log target.
 */
moho::WWinLogWindow::~WWinLogWindow()
{
  DetachFromTarget();
}

/**
 * Address: 0x004F6760 (FUN_004F6760)
 *
 * What it does:
 * Clears `mOwnerTarget->dialog` under the target lock.
 */
void moho::WWinLogWindow::DetachFromTarget()
{
  fa::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
  if (mOwnerTarget->dialog == this) {
    mOwnerTarget->dialog = nullptr;
  }
}

/**
 * Address: 0x004F5590 (FUN_004F5590)
 *
 * What it does:
 * Stores each category check box and the filter text in the preferences, after the visible
 * lines were rebuilt from them.
 */
void moho::WWinLogWindow::SaveControls()
{
  IUserPrefs* const preferences = USER_GetPreferences();
  for (std::size_t index = 0; index < mCategoryChecks.size(); ++index) {
    preferences->SetBoolean(fa::string(kLogCategoryPreferenceKeys[index]), mCategoryChecks[index]);
  }
  preferences->SetString(fa::string(kLogFilterPreferenceKey), mFilterText);
}

/**
 * Address: 0x004F6640 (FUN_004F6640, OnSize) and 0x004F6520 (FUN_004F6520, OnMove)
 *
 * What it does:
 * Stores the window's position in `Windows.Log.x` / `Windows.Log.y` and its size in
 * `Windows.Log.width` / `Windows.Log.height` when they change.
 */
void moho::WWinLogWindow::SaveGeometry()
{
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;
  if (!IsShown() || !GetBounds(x, y, width, height)) {
    return;
  }
  IUserPrefs* const preferences = USER_GetPreferences();
  if (x != mSavedX || y != mSavedY) {
    mSavedX = x;
    mSavedY = y;
    preferences->SetInteger(fa::string(kLogWindowXPreferenceKey), x);
    preferences->SetInteger(fa::string(kLogWindowYPreferenceKey), y);
  }
  if (width != mSavedWidth || height != mSavedHeight) {
    mSavedWidth = width;
    mSavedHeight = height;
    preferences->SetInteger(fa::string(kLogWindowWidthPreferenceKey), width);
    preferences->SetInteger(fa::string(kLogWindowHeightPreferenceKey), height);
  }
}

/**
 * Address: 0x004F5440 (FUN_004F5440)
 *
 * What it does:
 * Clears the output and resets the target's committed lines to the buffered replay context.
 */
void moho::WWinLogWindow::Clear()
{
  mOutput.clear();
  mFirstVisibleLine = 0;
  mOwnerTarget->ResetCommittedLinesFromReplayBuffer(mBufferedLines);
}

void moho::WWinLogWindow::AppendOutput(
  const std::uint32_t styleCategory,
  const std::wstring& text
)
{
  // One entry per line, for drawing only what is in view.
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find(L'\n', start);
    if (end == std::wstring::npos) {
      end = text.size();
    }
    mOutput.push_back(OutputLine{styleCategory, Utf8Of(text.substr(start, end - start))});
    start = end + 1;
  }
  // The target keeps 10,000 lines; the output keeps twice that before dropping its oldest.
  if (mOutput.size() > 2u * kMaxCommittedLogLines) {
    mOutput.erase(mOutput.begin(), mOutput.begin() + static_cast<std::ptrdiff_t>(kMaxCommittedLogLines / 2u));
  }
  mScrollToEnd = true;
}
bool moho::WWinLogWindow::ShouldDisplayCommittedLine(
  const CWinLogLine& line
) const
{
  if (line.categoryMask < 32) {
    const std::uint32_t categoryBit = 1u << line.categoryMask;
    if ((mEnabledCategoriesMask & categoryBit) != 0u) {
      return true;
    }
  }

  if ((mEnabledCategoriesMask & kCustomFilterCategoryBit) == 0u) {
    return false;
  }

  const fa::string loweredLineText = gpg::STR_ToLower(line.text.c_str());
  return std::strstr(loweredLineText.c_str(), mFilterText.c_str()) != nullptr;
}

std::wstring moho::WWinLogWindow::BuildReplayFlushText(
  const std::size_t startIndex
) const
{
  WWinLogTextBuilder replayBuilder{};
  for (std::size_t index = startIndex; index < mBufferedLines.size(); ++index) {
    replayBuilder.WriteSpaces(index * kReplayIndentWidth);
    replayBuilder.WriteUtf8Text(mBufferedLines[index]);
    replayBuilder.WriteCodePoint(L'\n');
  }

  return replayBuilder.Finalize();
}

std::wstring moho::WWinLogWindow::BuildFormattedCommittedLineText(
  const CWinLogLine& line
) const
{
  WWinLogTextBuilder lineBuilder{};
  const std::wstring severityPrefix(line.SeverityPrefix());
  lineBuilder.WriteWideText(severityPrefix);

  const std::size_t continuationIndent = mBufferedLines.size() * kReplayIndentWidth + severityPrefix.size();
  bool continuationLine = false;
  wchar_t decodedCodePoint = 0;
  const char* cursor = gpg::STR_DecodeUtf8Char(line.text.c_str(), decodedCodePoint);
  while (decodedCodePoint != 0) {
    if (continuationLine) {
      lineBuilder.WriteSpaces(continuationIndent);
      continuationLine = false;
    }

    lineBuilder.WriteDecodedCodePoint(decodedCodePoint);
    if (decodedCodePoint == L'\n') {
      continuationLine = true;
    }

    cursor = gpg::STR_DecodeUtf8Char(cursor, decodedCodePoint);
  }

  if (!continuationLine) {
    lineBuilder.WriteCodePoint(L'\n');
  }

  return lineBuilder.Finalize();
}

/**
 * Address: 0x004F5840 (FUN_004F5840)
 *
 * What it does:
 * Reads the category mask and the lower-cased filter back from the controls,
 * then refills the output from every committed line with the control hidden
 * (if it was shown), and scrolls it to the end.
 */
void moho::WWinLogWindow::RebuildVisibleLinesFromControls()
{
  mEnabledCategoriesMask = 0;
  for (std::size_t index = 0; index < mCategoryChecks.size(); ++index) {
    if (mCategoryChecks[index]) {
      mEnabledCategoriesMask |= (1u << index);
    }
  }

  mFilterText = gpg::STR_ToLower(mFilterEdit.data());

  mOutput.clear();
  mFirstVisibleLine = 0;
  mBufferedLines.clear();

  fa::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
  const fa::vector<CWinLogLine>& committedLines = mOwnerTarget->CommittedLines();
  for (std::size_t index = 0; index < committedLines.size(); ++index) {
    AppendCommittedLine(committedLines[index]);
  }

  // The binary scrolled the output to its end (SB_THUMBTRACK, 0x004F5A4F .. 0x004F5A79).
  mScrollToEnd = true;
}

/**
 * Address: 0x004F5AE0 (FUN_004F5AE0)
 *
 * What it does:
 * Applies one committed line against category/filter visibility and appends
 * replay/text output with preserved indentation behavior.
 */
void moho::WWinLogWindow::AppendCommittedLine(
  const CWinLogLine& line
)
{
  while (mBufferedLines.size() > line.sequenceIndex) {
    mBufferedLines.pop_back();
  }

  if (mFirstVisibleLine > mBufferedLines.size()) {
    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
  }

  if (line.IsReplayEntry()) {
    if (line.isReplayEntry == 1u) {
      mBufferedLines.push_back(line.text);
    }
    return;
  }

  if (!ShouldDisplayCommittedLine(line)) {
    return;
  }

  if (mFirstVisibleLine < mBufferedLines.size()) {
    const std::wstring replayText = BuildReplayFlushText(mFirstVisibleLine);

    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
    if (!replayText.empty()) {
      AppendOutput(1u, replayText);
    }
  }

  AppendOutput(line.categoryMask, BuildFormattedCommittedLineText(line));

  if (line.categoryMask >= kWarningCategoryValue && moho::CFG_GetArgOption("/edit", 0, nullptr)) {
    Show(true);
  }
}

/**
 * Address: 0x004F6470 (FUN_004F6470)
 *
 * What it does:
 * Merges pending lines into committed history, then appends just the lines the
 * merge added to the visible output.
 *
 * The count is sampled before the merge (`0x004F647C..0x004F64A4`) and the
 * loop at `0x004F64C0` walks `[previousCount, CommittedLineCount())` one entry
 * at a time through `AppendCommittedLine` (0x004F5AE0), re-reading the count
 * each iteration. It does NOT rebuild the whole visible list: doing that
 * cleared the output control and replayed every committed line on every single
 * log message, which is quadratic once the 10,000-line cap is reached.
 */
void moho::WWinLogWindow::OnTargetPendingLinesChanged()
{
  CWinLogTarget* const target = mOwnerTarget;
  std::size_t index = target->CommittedLineCount();
  target->MergePendingLines();
  fa::mutex::scoped_lock scopedLock(target->lock);
  while (index < target->CommittedLineCount()) {
    AppendCommittedLine(target->CommittedLines()[index]);
    ++index;
  }
}

void moho::WWinLogWindow::Tick()
{
  bool pending = false;
  {
    fa::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
    pending = mLinesPending;
    mLinesPending = false;
  }
  if (pending) {
    OnTargetPendingLinesChanged();
  }
  SaveGeometry();
}

void moho::WWinLogWindow::Draw()
{
  // The "Show" box: the five categories and the custom filter (controls 900 .. 905).
  static const char* const kCategoryLabels[] = {"Debug", "Info", "Warn", "Error", "Custom"};
  bool changed = false;
  ImGui::TextUnformatted("Show");
  ImGui::SameLine();
  for (std::size_t index = 0; index < mCategoryChecks.size(); ++index) {
    changed |= ImGui::Checkbox(kCategoryLabels[index], &mCategoryChecks[index]);
    ImGui::SameLine();
  }
  ImGui::SetNextItemWidth(-1.0f);
  changed |= ImGui::InputText("##filter", mFilterEdit.data(), mFilterEdit.size());
  if (changed) {
    RebuildVisibleLinesFromControls();
    SaveControls();
  }

  // The Clear button (906).
  if (ImGui::Button("Clear")) {
    Clear();
  }
  ImGui::SameLine();
  if (ImGui::Button("Copy")) {
    std::string all;
    for (const OutputLine& line : mOutput) {
      all += line.utf8;
      all += '\n';
    }
    ImGui::SetClipboardText(all.c_str());
  }

  // The output: read-only, coloured by category, following new lines while at its end.
  if (
    ImGui::BeginChild("##output", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar)
  ) {
    const bool atEnd = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(mOutput.size()));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const OutputLine& line = mOutput[static_cast<std::size_t>(row)];
        ImGui::PushStyleColor(ImGuiCol_Text, TextColourForCategory(line.styleCategory));
        ImGui::TextUnformatted(line.utf8.c_str(), line.utf8.c_str() + line.utf8.size());
        ImGui::PopStyleColor();
      }
    }
    if (mScrollToEnd && (atEnd || mOutput.empty())) {
      ImGui::SetScrollHereY(1.0f);
    }
    mScrollToEnd = false;
  }
  ImGui::EndChild();
}
