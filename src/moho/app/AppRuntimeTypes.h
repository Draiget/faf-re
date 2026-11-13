#pragma once

#include <cstdarg>
#include <array>
#include <functional>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "legacy/thread/Mutex.h"
#include <memory>
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakObject.h"
#include "moho/misc/WeakPtr.h"

/**
 * The retail binary linked the 2.4.2 window library; the engine classes below derive from the application
 * shell's window-library-shaped classes (src/platform/shell, SDL3 underneath, issue #407), as their RTTI
 * records name the window library's (`??_R2...` base-class arrays in dumps/rtti_dump_all.hpp).
 */
#include "platform/shell/Shell.h"
#include "platform/sdl/ToolWindow.h"
#include "platform/shell/Shell.h"

/**
 * The game's main frame (RTTI `.?AVWSupComFrame@@`: WSupComFrame > wxFrame,
 * vftable 0x00E4F434, 162 slots - the same count as wxFrame's, so it adds no
 * virtuals of its own). Three flag bytes follow the 0x178-byte wxFrame.
 *
 * Its event table is the standard DECLARE/BEGIN_EVENT_TABLE pair: the table
 * at 0x00DFE4EC = {base 0x00D56F70 (wxFrame::sm_eventTable), rows 0x00F5BB4C}
 * holds {-1, -1, 0x008CDAA0 OnCloseWindow, 0, &wxEVT_CLOSE_WINDOW} and
 * {-1, -1, 0x008CDAD0 OnMove, 0, &wxEVT_MOVE}; GetEventTable (0x008CE090) is
 * the `mov eax, offset sm_eventTable` the macro generates. The deleting
 * destructor at 0x008CE060 is the compiler's.
 */
class WSupComFrame : public ShellFrame
{
public:
  /**
   * Address: 0x008CD8C0 (FUN_008CD8C0)
   * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
   *
   * What it does:
   * Creates the native frame (`wxFrame(nullptr, -1, title, pos, size, style,
   * wxFrameNameStr)` at 0x008CD92E), clears the three flag bytes, applies the
   * wnd_MinDrag* size hints and puts the IDI_WIN_FAICON icon on it.
   */
  WSupComFrame(const char* title, const ShellPoint& position, const ShellSize& size, long style);

  /**
   * Address: 0x008CE050 (FUN_008CE050)
   *
   * What it does:
   * Returns the WM_ACTIVATEAPP-derived active flag MSWWindowProc records.
   * Inline: nothing in the image calls the out-of-line copy.
   */
  [[nodiscard]] bool IsApplicationActive() const
  {
    return mIsApplicationActive != 0;
  }

  /**
   * Address: 0x008CDAA0 (FUN_008CDAA0, WSupComFrame::OnCloseWindow)
   *
   * What it does:
   * If the frame is iconized, exits the wx main loop; otherwise requests the
   * Moho escape dialog.
   */
  void OnCloseWindow(ShellCloseEvent& event);

  /**
   * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
   *
   * What it does:
   * Persists current top-level frame position lanes into user preferences
   * while the main frame is windowed and not device-locked.
   */
  void OnMove(ShellMoveEvent& event);

  /**
   * The retail frame's window procedure (WSupComFrame::MSWWindowProc, 0x008CDD40, and
   * MSWDefWindowProc, 0x008CDCD0) on the shell's events: a finished size change re-sizes the
   * viewport and the device and is saved to the preferences, as WM_SIZE (maximized, restored)
   * and WM_EXITSIZEMOVE after SC_SIZE were.
   */
  void OnSize(ShellSizeEvent& event);

#if FAFRE_PLATFORM_POSIX
  /**
   * Engine addition: OnSize on POSIX only marks the size as pending; the main loop calls this
   * between frames, and the device follows once the size has stopped changing for 150 ms. A bind
   * the device refused is tried again after another wait, up to 10 times.
   */
  static void ApplyPendingResize();
#endif

  /**
   * OnSize's work: follows the client size with the viewport and the device when it differs from
   * the device's head, and saves the size and maximized state. False when the device didn't take
   * the size (only POSIX acts on it).
   */
  bool FollowClientSize();

  /**
   * WM_ACTIVATEAPP in WSupComFrame::MSWWindowProc (0x008CDD40): records the active flag and
   * clips the cursor to the window (lock_fullscreen_cursor_to_window) or frees it.
   */
  void OnActivate(ShellActivateEvent& event);

  /**
   * WM_SYSCOMMAND in WSupComFrame::MSWWindowProc (0x008CDD40): the system-menu items
   * CScApp's AppendLuaDebuggerSystemMenu (0x008D42E0) adds, 1 the log window and 2 the Lua
   * debugger.
   */
  void OnSystemCommand(int command) override;

  std::uint8_t mUnknown178;
  std::uint8_t mPendingMaximizeSync;
  std::uint8_t mPersistedMaximizeSync;
  std::uint8_t mIsApplicationActive;

  DECLARE_EVENT_TABLE()
};

namespace moho
{
  class CWinLogTarget;
  class WWinLogWindow;
  class WWinLogTextBuilder;
  struct CWinLogLine;

  /**
   * Wide text-builder helper used by `WWinLogWindow` replay/message formatting.
   *
   * Evidence:
   * - ctor/finalize: `FUN_004F73B0` / `FUN_004F74D0`
   * - write helpers:
   *   - `FUN_004F98F0` one code-point emission with stream width/reset
   *   - `FUN_004F9B80` wide-string emission with stream width/reset
   *   - `FUN_004F9DF0` wide-literal emission with stream width/reset
   *   - `FUN_004FA000` narrow-to-wide emission with stream width/reset
   *   - `FUN_004FA2C0` one decoded code-point emission
   * - spacing helper family: `FUN_004F5AB0`.
   *
   * The real 0x004F73B0 constructs a `std::wostringstream`-family object (the
   * real class held a full iostream stack: `wstringbuf` over `wstreambuf`,
   * each with their own construction machinery), which is why the binary's
   * call tree from that address reaches `std::locale::locale`,
   * `std::_Lockit`, `std::wstreambuf::basic_streambuf` (0x004F8820),
   * `std::wstreambuf::_Init` (0x004F95E0), `std::basic_stringbuf<wchar_t>::
   * basic_stringbuf` (0x004F83C0) and `::_Tidy` (0x004F8550) beneath it, plus
   * three more of the same iostream-internals family found on a later pass:
   * `std::basic_ios<wchar_t>::setstate`-shaped state update (0x004F8720,
   * touches `std::ios_base::_Mystate` and dispatches a virtual `rdbuf()`
   * check), its `std::basic_ostream<wchar_t>::sentry::~sentry`-shaped RAII
   * caller (0x004F8660, checks `std::uncaught_exception()` then conditionally
   * `std::_Mutex::_Unlock`s the stream's lock), and a sibling call site of
   * the former (0x004F6B60). This recovery replaces the whole iostream stack
   * with a plain `std::wstring mText` member -- same "keep behaviour, not
   * exact function count" modernization already applied to
   * `gpg::core::TssPtr` for `boost::thread_specific_ptr<ContextStack>`
   * (`Tss.h`) -- so none of those addresses have a corresponding call here
   * by design; the default ctor and implicit destructor below are their
   * modern equivalent. `WriteCodePoint`/`WriteWideText`/etc. below (0x004F98F0
   * and siblings) are `recovered`, not `skip`, because they DO have a modern
   * equivalent doing the same observable job -- only the stream-state/lock
   * plumbing beneath them has none.
   */
  class WWinLogTextBuilder
  {
  public:
    /**
     * Address: 0x004F73B0 (FUN_004F73B0)
     *
     * What it does:
     * Constructs one wide stream/buffer builder used by log-window formatting.
     */
    WWinLogTextBuilder();

    /**
     * Address: 0x004F74D0 (FUN_004F74D0)
     *
     * What it does:
     * Finalizes current stream state and returns the accumulated wide text.
     */
    [[nodiscard]] const std::wstring& Finalize() const noexcept;

    /**
     * Address: 0x004F98F0 (FUN_004F98F0)
     *
     * What it does:
     * Emits one wide code-point and clears transient field width.
     */
    void WriteCodePoint(wchar_t codePoint);

    /**
     * Address: 0x004F9B80 (FUN_004F9B80)
     *
     * What it does:
     * Emits one wide string and clears transient field width.
     */
    void WriteWideText(const std::wstring& text);

    /**
     * Address: 0x004FA000 (FUN_004FA000)
     *
     * What it does:
     * Emits one UTF-8/narrow text fragment as widened output.
     */
    void WriteUtf8Text(const fa::string& text);

    /**
     * Address: 0x004FA2C0 (FUN_004FA2C0)
     *
     * What it does:
     * Emits one decoded wide code-point and clears transient field width.
     */
    void WriteDecodedCodePoint(wchar_t codePoint);

    /**
     * Address: 0x004F5AB0 (FUN_004F5AB0)
     *
     * What it does:
     * Emits `count` space code-points.
     */
    void WriteSpaces(std::size_t count);

    void Clear() noexcept;

  private:
    std::wstring mText{};
    std::size_t mFieldWidth = 0;
    wchar_t mFillCodePoint = L' ';
    bool mLeftAlign = false;
  };

  /**
   * Runtime line-entry record used by `CWinLogTarget` vectors.
   *
   * Evidence:
   * - `FUN_004F6860` / `FUN_004F6F40` construct and append one `0x28`-byte
   *   record with `[isReplay,index,category,text]`.
   */
  struct CWinLogLine
  {
    std::uint32_t isReplayEntry = 0;
    std::uint32_t sequenceIndex = 0;
    std::uint32_t categoryMask = 0;
    fa::string text;

    [[nodiscard]] bool IsReplayEntry() const noexcept;
    [[nodiscard]] const wchar_t* SeverityPrefix() const noexcept;
  };

  static_assert(offsetof(CWinLogLine, isReplayEntry) == 0x0, "moho::CWinLogLine::isReplayEntry offset must be 0x0");
  static_assert(offsetof(CWinLogLine, sequenceIndex) == 0x4, "moho::CWinLogLine::sequenceIndex offset must be 0x4");
  static_assert(offsetof(CWinLogLine, categoryMask) == 0x8, "moho::CWinLogLine::categoryMask offset must be 0x8");
  static_assert(offsetof(CWinLogLine, text) == 0xC, "moho::CWinLogLine::text offset must be 0xC");
  static_assert(sizeof(CWinLogLine) == 0x28, "moho::CWinLogLine size must be 0x28");

  /**
   * Runtime owner for the global log-window target (`sLogWindowTarget`).
   *
   * Evidence:
   * - `FUN_004F38F0` (`CWinLogTarget` ctor) initializes:
   *   - dialog pointer at `+0x8`
   *   - committed line vector lanes at `+0x10/+0x14/+0x18`
   *   - lock at `+0x1C`
   *   - pending line vector lanes at `+0x28/+0x2C/+0x30`.
   * - `FUN_004F6A50` / `FUN_004F6860` append/merge pending lines into the
   *   committed line set under the same lock.
   */
  class CWinLogTarget : public gpg::LogTarget
  {
  public:
    /**
     * Address: 0x004F38F0 (FUN_004F38F0, ??0CWinLogTarget@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the global log-target owner and auto-registers it with gpg logging.
     */
    CWinLogTarget();

    /**
     * Address: 0x004F39B0 (FUN_004F39B0)
     * Mangled deleting-dtor thunk: 0x004F3990 (FUN_004F3990)
     *
     * What it does:
     * Releases pending/committed vectors and tears down base log-target registration.
     */
    ~CWinLogTarget() override;

    /**
     * Address: 0x004F6860 (FUN_004F6860)
     *
     * gpg::LogSeverity level, fa::string const &, fa::vector<fa::string> const &, int
     *
     * What it does:
     * Queues replay/context lines plus the current line into the pending log queue.
     */
    void OnMessage(
      gpg::LogSeverity level,
      const fa::string& message,
      const fa::vector<fa::string>& context,
      int previousDepth
    ) override;

    /**
     * Address: 0x004F6A50 (FUN_004F6A50)
     *
     * What it does:
     * Merges pending lines into committed history and enforces the 10,000 line cap.
     */
    void MergePendingLines();

    /**
     * Address: 0x004F6F10 (FUN_004F6F10)
     *
     * What it does:
     * Returns committed line count.
     */
    [[nodiscard]] std::size_t CommittedLineCount() const;
    [[nodiscard]] const fa::vector<CWinLogLine>& CommittedLines() const;
    void ResetCommittedLinesFromReplayBuffer(const fa::vector<fa::string>& replayLines);

    WWinLogWindow* dialog = nullptr;
    fa::vector<CWinLogLine> mCommittedLines;
    fa::mutex lock{};
    fa::vector<CWinLogLine> mPendingLines;

  private:
    /**
     * Address: 0x004F6FD0 (FUN_004F6FD0)
     *
     * What it does:
     * Replaces committed-line storage with a copy of `nextCommittedLines`.
     */
    void ReplaceCommittedLines(const fa::vector<CWinLogLine>& nextCommittedLines);

    /**
     * Address: 0x004F6F40 (FUN_004F6F40)
     *
     * What it does:
     * Appends one line record into the pending queue.
     */
    void AppendPendingLine(const CWinLogLine& line);
  };

  static_assert(offsetof(CWinLogTarget, dialog) == 0x8, "moho::CWinLogTarget::dialog offset must be 0x8");
  static_assert(
    offsetof(CWinLogTarget, mCommittedLines) == 0xC,
    "moho::CWinLogTarget::mCommittedLines offset must be 0xC"
  );
  static_assert(offsetof(CWinLogTarget, lock) == 0x1C, "moho::CWinLogTarget::lock offset must be 0x1C");
  static_assert(
    offsetof(CWinLogTarget, mPendingLines) == 0x24,
    "moho::CWinLogTarget::mPendingLines offset must be 0x24"
  );
  static_assert(sizeof(CWinLogTarget) == 0x34, "moho::CWinLogTarget size must be 0x34");

  /**
   * The log window (RTTI `.?AVWWinLogWindow@Moho@@`, 0x004F4270), a wx dialog in the binary: the
   * "Show" box with the Debug, Info, Warn, Error and Custom check boxes and the custom filter, a
   * Clear button and the output, coloured by category. Dear ImGui in a window of its own since
   * issue #412 (platform/sdl/ToolWindow.h); its options (`Options.Log.*`) and geometry
   * (`Windows.Log.*`) are the same preferences, its history the target's 10,000 lines.
   */
  class WWinLogWindow final : public platform::tools::ToolWindow
  {
  public:
    /**
     * Address: 0x004F4270 (FUN_004F4270)
     *
     * What it does:
     * Creates the "Moho Log" window, reads the check boxes, the filter and the geometry from
     * the preferences and fills the output from the target's committed lines.
     */
    WWinLogWindow();

    /**
     * Address: 0x004F5380 (FUN_004F5380)
     *
     * What it does:
     * Detaches from the log target.
     */
    ~WWinLogWindow() override;

    /**
     * Address: 0x004F6760 (FUN_004F6760)
     *
     * What it does:
     * Clears `mOwnerTarget->dialog` under the target lock.
     */
    void DetachFromTarget();

    /**
     * Address: 0x004F5840 (FUN_004F5840)
     *
     * What it does:
     * Reads the category mask and the lower-cased filter, then refills the output from every
     * committed line and scrolls to the end.
     */
    void RebuildVisibleLinesFromControls();

    /**
     * Address: 0x004F5AE0 (FUN_004F5AE0)
     *
     * What it does:
     * Applies one committed line against the category and filter and appends it, after the
     * context lines it follows, to the output.
     */
    void AppendCommittedLine(const CWinLogLine& line);

    [[nodiscard]] bool ShouldDisplayCommittedLine(const CWinLogLine& line) const;
    [[nodiscard]] std::wstring BuildReplayFlushText(std::size_t startIndex) const;
    [[nodiscard]] std::wstring BuildFormattedCommittedLineText(const CWinLogLine& line) const;

    /**
     * Address: 0x004F6470 (FUN_004F6470)
     *
     * What it does:
     * Merges the target's pending lines and appends the ones the merge added. The binary ran it
     * for the CLogAdditionEvent CWinLogTarget::OnMessage posted; the target now raises a flag
     * any thread may set, and the window merges on the main thread every frame.
     */
    void OnTargetPendingLinesChanged();

    // CWinLogTarget::OnMessage, under the target's lock: lines are waiting.
    void NotePendingLines() noexcept
    {
      mLinesPending = true;
    }

    /**
     * Address: 0x004F5440 (FUN_004F5440)
     *
     * What it does:
     * Clears the output and resets the target's committed lines to the buffered context.
     */
    void Clear();

  protected:
    void Tick() override;
    void Draw() override;

  private:
    struct OutputLine
    {
      std::uint32_t styleCategory;
      std::string utf8;
    };

    void AppendOutput(std::uint32_t styleCategory, const std::wstring& text);
    void SaveControls();
    void SaveGeometry();

    CWinLogTarget* mOwnerTarget = nullptr;
    std::uint32_t mEnabledCategoriesMask = 0;
    fa::string mFilterText;
    std::array<bool, 5> mCategoryChecks{};
    std::array<char, 256> mFilterEdit{};
    fa::vector<fa::string> mBufferedLines;
    std::uint32_t mFirstVisibleLine = 0;
    std::vector<OutputLine> mOutput;
    bool mScrollToEnd = true;
    bool mLinesPending = false;
    int mSavedX = -1;
    int mSavedY = -1;
    int mSavedWidth = -1;
    int mSavedHeight = -1;
  };

  /**
   * The input box (RTTI `.?AVWWxInputBox@Moho@@`, 0x004FC040 in the binary, a wx dialog): a
   * label, an edit box and OK / Cancel. Dear ImGui since issue #412.
   */
  class WInputBox final : public platform::tools::ToolWindow
  {
  public:
    WInputBox(const char* dialogTitle, const char* defaultValue, const char* labelText);

    // Dialog::ShowModal: true for OK, with the text in `result`.
    [[nodiscard]] bool RunModal(fa::string* result);

  protected:
    void Draw() override;
    void OnCloseRequested() override;

  private:
    std::string mLabel;
    std::array<char, 1024> mText{};
    bool mDone = false;
    bool mAccepted = false;
    bool mFocusText = true;
  };

  /**
   * Address: 0x004FC870 (FUN_004FC870, WxInputBox)
   *
   * What it does:
   * Runs one modal input box; true when the user pressed OK.
   */
  [[nodiscard]] bool
  InputBox(const char* dialogTitle, const char* defaultValue, const char* labelText, fa::string* resultString);

  /**
   * Address: 0x004FC900 (FUN_004FC900, ?CON_WxInputBox@Moho@@YAXPAX@Z)
   *
   * What it does:
   * The `InputBox` console command (`WxInputBox` in the binary): asks "What?" with the default
   * "default" and prints the answer or "Canceled".
   */
  void CON_InputBox(const fa::vector<fa::string>& args);

  // Engine addition (issue #412): runs the window system and the developer windows until `done`.
  void WINX_RunModal(const std::function<bool()>& done);

  // The one log target (0x010A9BA0): WWinLogWindow's constructor binds to it,
  // and WINX_PrecreateLogWindow publishes the window through its `dialog`.
  extern CWinLogTarget sLogWindowTarget;

  /**
   * The engine's application object. RTTI: MohoApp > wxApp > wxAppBase >
   * wxEvtHandler > wxObject, vftable 0x00E0C184 with wxApp's 42 slots.
   *
   * wx creates it: IMPLEMENT_APP_NO_MAIN(MohoApp) registers `wxCreateApp`
   * (0x004F1E90 - checks wxBuildOptions, then `new MohoApp`) as the app
   * initializer from a static constructor, and `wxEntry` - which
   * `WIN_AppExecute` (0x004F20B0) calls with enterLoop = false - runs it after
   * `wxApp::Initialize`. MohoApp's constructor (0x004F1F10) and destructor are
   * the compiler's; the argv release at 0x00992070 is wxApp::~wxApp.
   *
   * WIN_AppExecute then pumps the loop itself, so the keep-going flag that
   * wxApp::MainLoop would own is driven through the two members below.
   */
  class MohoApp : public ShellApp
  {
  public:
    /**
     * Address: 0x004F1E50 (FUN_004F1E50, Moho::MohoApp::OnInit)
     * Mangled: ?OnInit@MohoApp@Moho@@UAE_NXZ
     *
     * What it does:
     * Returns startup success for the app bootstrap lane.
     */
    bool OnInit() override;

    /**
     * Address: 0x004F1E80 (FUN_004F1E80, Moho::MohoApp::ExitMainLoop)
     * Mangled: ?ExitMainLoop@MohoApp@Moho@@UAEXXZ
     *
     * What it does:
     * Clears the loop-keepalive flag so wx main-loop pumping exits.
     */
    void ExitMainLoop() override;

    /**
     * Address: 0x004F1E70 (FUN_004F1E70)
     *
     * What it does:
     * Returns wxApp::m_keepGoing (+0x5C), the flag ExitMainLoop clears. Inline:
     * nothing in the image calls the out-of-line copy.
     */
    [[nodiscard]] bool KeepGoing() const
    {
      return m_keepGoing != 0;
    }

    /**
     * Address: 0x004F1E60 (FUN_004F1E60)
     *
     * What it does:
     * Sets wxApp::m_keepGoing, the flag KeepGoing reads. Inline: nothing in
     * the image calls the out-of-line copy.
     */
    void SetKeepGoing()
    {
      m_keepGoing = TRUE;
    }
  };

  // The main frame (0x010A63B8): WIN_OkBox parents its message box on it,
  // and CScApp::CreateAppFrame sets it to the WSupComFrame.
  extern ShellWindow* sMainWindow;
} // namespace moho

// GetApp(), from the IMPLEMENT_APP_NO_MAIN(moho::MohoApp) in WinApp.cpp.
DECLARE_APP(
  moho::MohoApp
)
