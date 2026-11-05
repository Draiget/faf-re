#include "moho/app/WxPrivate.h"

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
  constexpr std::int32_t kLogWindowSetSizeFlags = 3;

  // The colour each category's lines are written in; the replayed context
  // lines use the Info colour.
  [[nodiscard]] wxTextAttr DefaultTextStyleForCategory(const std::uint32_t category)
  {
    switch (category) {
    case 0u:
      return wxTextAttr(wxColour(0x80, 0x80, 0x80));
    case kWarningCategoryValue:
      return wxTextAttr(wxColour(0xF7, 0xA1, 0x00));
    case kErrorCategoryValue:
      return wxTextAttr(wxColour(0xFF, 0x00, 0x00));
    default:
      return wxTextAttr(wxColour(0x00, 0x00, 0x00));
    }
  }
}


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

void moho::WWinLogTextBuilder::SetFieldWidth(
  const std::size_t width
) noexcept
{
  mFieldWidth = width;
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
 * Address: 0x004F9DF0 (FUN_004F9DF0)
 *
 * What it does:
 * Emits one wide-string literal with width/padding behavior.
 */
void moho::WWinLogTextBuilder::WriteWideLiteral(
  const wchar_t* const text
)
{
  WriteWideText(text != nullptr ? std::wstring(text) : std::wstring{});
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

bool moho::CWinLogLine::IsMessageEntry() const noexcept
{
  return !IsReplayEntry();
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
 * Address: 0x00BC7310 (FUN_00BC7310, static initialiser)
 *
 * What it does:
 * Numbers the log-addition event type from wxNewEventType (0x00978FD0).
 */
DEFINE_EVENT_TYPE(moho::EVT_LOG_ADDITION)

/**
 * Address: 0x004F37F0 (FUN_004F37F0)
 *
 * What it does:
 * Allocates and copy-clones one `CLogAdditionEvent` object.
 */
wxEvent* moho::CLogAdditionEvent::Clone() const
{
  return new CLogAdditionEvent(*this);
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

void moho::CWinLogTarget::SnapshotCommittedLines(
  fa::vector<CWinLogLine>* const outLines
)
{
  if (outLines == nullptr) {
    return;
  }

  boost::mutex::scoped_lock scopedLock(lock);
  *outLines = mCommittedLines;
}

void moho::CWinLogTarget::ResetCommittedLinesFromReplayBuffer(
  const fa::vector<fa::string>& replayLines
)
{
  boost::mutex::scoped_lock scopedLock(lock);

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
  boost::mutex::scoped_lock scopedLock(lock);

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
  boost::mutex::scoped_lock scopedLock(lock);

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

  // Any thread may log, so the dialog is told through its event queue rather
  // than called: AddPendingEvent clones the event and the GUI thread runs
  // OnTargetPendingLinesChanged when it next processes pending events. The
  // binary posts while it still holds the lock (0x004F6A06 .. 0x004F6A2D).
  if (dialog != nullptr) {
    CLogAdditionEvent event;
    dialog->AddPendingEvent(event);
  }
}

BEGIN_EVENT_TABLE(moho::WWinLogWindow, wxDialog)
  EVT_LOG_ADDITION_EVENT(moho::WWinLogWindow::OnTargetPendingLinesChanged)
  EVT_CHECKBOX(900, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_CHECKBOX(901, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_CHECKBOX(902, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_CHECKBOX(903, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_CHECKBOX(904, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_TEXT(905, moho::WWinLogWindow::OnFilterOrCategoryControlsChanged)
  EVT_BUTTON(906, moho::WWinLogWindow::OnClear)
  EVT_SIZE(moho::WWinLogWindow::OnSize)
  EVT_MOVE(moho::WWinLogWindow::OnMove)
END_EVENT_TABLE()

/**
 * Address: 0x004F4270 (FUN_004F4270)
 *
 * What it does:
 * Creates the "Moho Log" dialog and lays it out: a "Show" box holding the five
 * category check boxes (900-904) and the filter text (905) above a Clear
 * button (906) and the read-only rich output text. The check boxes and filter
 * start from the preferences, the window from its saved geometry, and the
 * output is filled from the target's committed lines before the initialising
 * flag drops.
 */
moho::WWinLogWindow::WWinLogWindow()
  : WWinManagedDialog(
      nullptr,
      -1,
      wxT("Moho Log"),
      wxDefaultPosition,
      wxDefaultSize,
      wxCAPTION | wxSYSTEM_MENU | wxRESIZE_BORDER,
      wxT("MohoDialogBox")
    )
  , mIsInitializingControls(true)
  , mOwnerTarget(&sLogWindowTarget)
  , mOutputTextControl(nullptr)
  , mFilterTextControl(nullptr)
  , mEnabledCategoriesMask(0)
  , mFirstVisibleLine(0)
{
  IUserPrefs* const preferences = USER_GetPreferences();

  wxBoxSizer* const topSizer = new wxBoxSizer(wxVERTICAL);
  wxStaticBoxSizer* const showSizer = new wxStaticBoxSizer(new wxStaticBox(this, -1, wxT("Show")), wxHORIZONTAL);

  mDebugCategoryCheckBox = new wxCheckBox(this, 900, wxT("Debug"));
  mInfoCategoryCheckBox = new wxCheckBox(this, 901, wxT("Info"));
  mWarnCategoryCheckBox = new wxCheckBox(this, 902, wxT("Warn"));
  mErrorCategoryCheckBox = new wxCheckBox(this, 903, wxT("Error"));
  mCustomCategoryCheckBox = new wxCheckBox(this, 904, wxT("Custom"));
  mFilterTextControl = new wxTextCtrl(this, 905, wxEmptyString);

  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    checkBoxes[index]->SetValue(
      preferences->GetBoolean(fa::string(kLogCategoryPreferenceKeys[index]), kLogCategoryPreferenceDefaults[index])
    );
  }

  mFilterText = preferences->GetString(fa::string(kLogFilterPreferenceKey), fa::string(kLogFilterPreferenceDefault));
  mFilterTextControl->SetValue(gpg::STR_Utf8ToWide(mFilterText.c_str()).c_str());

  for (wxCheckBox* const checkBox : checkBoxes) {
    showSizer->Add(checkBox);
  }
  showSizer->Add(mFilterTextControl, 1, wxALIGN_CENTER_VERTICAL);

  mOutputTextControl = new wxTextCtrl(
    this,
    -1,
    wxEmptyString,
    wxDefaultPosition,
    wxSize(384, 512),
    wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH | wxHSCROLL
  );

  topSizer->Add(showSizer, 0, wxEXPAND);
  topSizer->Add(new wxButton(this, 906, wxT("Clear")), 0, wxALIGN_BOTTOM);
  topSizer->Add(mOutputTextControl, 1, wxEXPAND);

  SetAutoLayout(true);
  SetSizer(topSizer);
  topSizer->SetSizeHints(this);
  topSizer->Fit(this);

  const std::int32_t height =
    preferences->GetInteger(fa::string(kLogWindowHeightPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t width =
    preferences->GetInteger(fa::string(kLogWindowWidthPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t y = preferences->GetInteger(fa::string(kLogWindowYPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t x = preferences->GetInteger(fa::string(kLogWindowXPreferenceKey), kLogWindowGeometryFallback);
  SetSize(x, y, width, height, kLogWindowSetSizeFlags);

  RebuildVisibleLinesFromControls();
  mIsInitializingControls = false;
}

/**
 * Address: 0x004F5380 (FUN_004F5380)
 *
 * What it does:
 * Detaches from the log target. The buffered lines, the filter text and
 * ~WWinManagedDialog (0x004F40A0) follow as member and base destruction.
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
  boost::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
  mOwnerTarget->dialog = nullptr;
}

std::array<wxCheckBox*, 5> moho::WWinLogWindow::CategoryCheckBoxes() noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

std::array<const wxCheckBox*, 5> moho::WWinLogWindow::CategoryCheckBoxes() const noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

/**
 * Address: 0x004F5590 (FUN_004F5590)
 *
 * What it does:
 * Once the controls are built, rebuilds the visible lines and stores each
 * category check box and the filter text back into the preferences.
 */
void moho::WWinLogWindow::OnFilterOrCategoryControlsChanged(wxCommandEvent& event)
{
  (void)event;
  if (mIsInitializingControls) {
    return;
  }

  RebuildVisibleLinesFromControls();

  IUserPrefs* const preferences = USER_GetPreferences();
  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    preferences->SetBoolean(fa::string(kLogCategoryPreferenceKeys[index]), checkBoxes[index]->GetValue());
  }
  preferences->SetString(fa::string(kLogFilterPreferenceKey), mFilterText);
}

/**
 * Address: 0x004F6640 (FUN_004F6640)
 *
 * What it does:
 * wxTopLevelWindowBase::OnSize (0x0098CFD0) lays the single child out; then,
 * once the controls are built, the window's size is stored in
 * `Windows.Log.width` / `Windows.Log.height`.
 */
void moho::WWinLogWindow::OnSize(wxSizeEvent& event)
{
  wxDialog::OnSize(event);
  if (mIsInitializingControls) {
    return;
  }

  IUserPrefs* const preferences = USER_GetPreferences();
  preferences->SetInteger(fa::string(kLogWindowWidthPreferenceKey), GetSize().x);
  preferences->SetInteger(fa::string(kLogWindowHeightPreferenceKey), GetSize().y);
}

/**
 * Address: 0x004F6520 (FUN_004F6520)
 *
 * What it does:
 * Once the controls are built, stores the window's position in
 * `Windows.Log.x` / `Windows.Log.y`.
 */
void moho::WWinLogWindow::OnMove(wxMoveEvent& event)
{
  (void)event;
  if (mIsInitializingControls) {
    return;
  }

  IUserPrefs* const preferences = USER_GetPreferences();
  preferences->SetInteger(fa::string(kLogWindowXPreferenceKey), GetPosition().x);
  preferences->SetInteger(fa::string(kLogWindowYPreferenceKey), GetPosition().y);
}

/**
 * Address: 0x004F5440 (FUN_004F5440)
 *
 * What it does:
 * Clears the output and resets the target's committed lines to the buffered
 * replay context.
 */
void moho::WWinLogWindow::OnClear(wxCommandEvent& event)
{
  (void)event;
  mOutputTextControl->Clear();
  mPendingOutput.clear();
  mFirstVisibleLine = 0;
  mOwnerTarget->ResetCommittedLinesFromReplayBuffer(mBufferedLines);
}

bool moho::WWinLogWindow::Show(const bool show)
{
  if (show) {
    FlushPendingOutput();
  }
  return WWinManagedDialog::Show(show);
}

void moho::WWinLogWindow::AppendOutput(const std::uint32_t styleCategory, const std::wstring& text)
{
  if (!mPendingOutput.empty() && mPendingOutput.back().styleCategory == styleCategory) {
    mPendingOutput.back().text += text;
  } else {
    mPendingOutput.push_back(PendingOutputRun{styleCategory, text});
  }
}

void moho::WWinLogWindow::FlushPendingOutput()
{
  for (const PendingOutputRun& run : mPendingOutput) {
    mOutputTextControl->SetDefaultStyle(DefaultTextStyleForCategory(run.styleCategory));
    mOutputTextControl->AppendText(run.text.c_str());
  }
  mPendingOutput.clear();
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
  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    if (checkBoxes[index]->GetValue()) {
      mEnabledCategoriesMask |= (1u << index);
    }
  }

  mFilterText = gpg::STR_ToLower(gpg::STR_WideToUtf8(mFilterTextControl->GetValue().c_str()).c_str());

  const bool outputShown = mOutputTextControl->IsShown();
  if (outputShown) {
    mOutputTextControl->Show(false);
  }
  mOutputTextControl->Clear();
  mPendingOutput.clear();
  mFirstVisibleLine = 0;
  mBufferedLines.clear();

  const fa::vector<CWinLogLine>& committedLines = mOwnerTarget->CommittedLines();
  for (std::size_t index = 0; index < committedLines.size(); ++index) {
    AppendCommittedLine(committedLines[index]);
  }
  if (IsShown()) {
    FlushPendingOutput(); // engine change: queued by AppendCommittedLine, see AppendOutput
  }

  if (outputShown) {
    mOutputTextControl->Show(true);
  }

  // The binary scrolls through the edit control directly: SB_THUMBTRACK to
  // the last position (0x004F5A4F .. 0x004F5A79).
  ::SendMessageW(
    reinterpret_cast<HWND>(static_cast<std::uintptr_t>(mOutputTextControl->GetHWND())),
    WM_VSCROLL,
    MAKEWPARAM(SB_THUMBTRACK, static_cast<WORD>(mOutputTextControl->GetLastPosition())),
    0
  );
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

  // Engine change: the binary sets the default style and appends to the output control here;
  // the text is queued instead and written while the dialog is shown (`AppendOutput`).
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
void moho::WWinLogWindow::OnTargetPendingLinesChanged(
  CLogAdditionEvent& event
)
{
  (void)event;
  CWinLogTarget* const target = mOwnerTarget;
  std::size_t index = target->CommittedLineCount();
  target->MergePendingLines();
  while (index < target->CommittedLineCount()) {
    AppendCommittedLine(target->CommittedLines()[index]);
    ++index;
  }
  if (IsShown()) {
    FlushPendingOutput(); // engine change: queued by AppendCommittedLine, see AppendOutput
  }
}
