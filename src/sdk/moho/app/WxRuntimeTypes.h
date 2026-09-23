#pragma once

#include <cstdarg>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "boost/mutex.h"
#include "boost/shared_ptr.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"

/**
 * wxWidgets 2.4.2 is linked, not recovered: `wxmswu.lib` is the library the
 * shipped binary was built against (sizes and vtable lengths of every class
 * the engine derives from match the binary - see platform/WxWidgets.h). The
 * engine classes below derive from the real wx classes, exactly as their
 * RTTI records (`??_R2...` base-class arrays in dumps/rtti_dump_all.hpp).
 */
#include "platform/WxWidgets.h"
#include <wx/wx.h>
#include <wx/bmpbuttn.h>
#include <wx/dcclient.h>
#include <wx/ffile.h>
#include <wx/file.h>
#include <wx/filename.h>
#include <wx/image.h>
#include <wx/layout.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <wx/splash.h>
#include <wx/stream.h>
#include <wx/treectrl.h>
#include <wx/wfstream.h>

// The binary agrees with wx/gdicmn.h: wxWindow::Refresh (0x00968350) reads a
// wxRect as {x, y, width, height}, and wxApp::Initialize (0x009927E0)
// allocates the colour database with operator new(0x1C).
static_assert(sizeof(wxPoint) == 0x8, "wxPoint size must be 0x8");
static_assert(sizeof(wxSize) == 0x8, "wxSize size must be 0x8");
static_assert(sizeof(wxRect) == 0x10, "wxRect size must be 0x10");
static_assert(sizeof(wxColourDatabase) == 0x1C, "wxColourDatabase size must be 0x1C");

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
class WSupComFrame : public wxFrame
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
  WSupComFrame(const char* title, const wxPoint& position, const wxSize& size, long style);

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
  void OnCloseWindow(wxCloseEvent& event);

  /**
   * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
   *
   * What it does:
   * Persists current top-level frame position lanes into user preferences
   * while the main frame is windowed and not device-locked.
   */
  void OnMove(wxMoveEvent& event);

  /**
   * Address: 0x008CDCD0 (FUN_008CDCD0, WSupComFrame::MSWDefWindowProc)
   *
   * What it does:
   * Handles SupCom system-command defaults, including pending-maximize sync
   * priming and Alt-menu suppression, then forwards other lanes to base wx
   * default window-proc dispatch.
   */
  long MSWDefWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam) override;

  /**
   * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
   * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
   *
   * What it does:
   * Handles SupCom frame resize/maximize/app-activation/system-command
   * routing, updates persisted window prefs, and forwards unhandled messages
   * to base frame dispatch.
   */
  long MSWWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam) override;

  std::uint8_t mUnknown178;
  std::uint8_t mPendingMaximizeSync;
  std::uint8_t mPersistedMaximizeSync;
  std::uint8_t mIsApplicationActive;

  DECLARE_EVENT_TABLE()
};

static_assert(
  offsetof(WSupComFrame, mPendingMaximizeSync) == 0x179,
  "WSupComFrame::mPendingMaximizeSync offset must be 0x179"
);
static_assert(
  offsetof(WSupComFrame, mPersistedMaximizeSync) == 0x17A,
  "WSupComFrame::mPersistedMaximizeSync offset must be 0x17A"
);
static_assert(
  offsetof(WSupComFrame, mIsApplicationActive) == 0x17B,
  "WSupComFrame::mIsApplicationActive offset must be 0x17B"
);
static_assert(sizeof(WSupComFrame) == 0x17C, "WSupComFrame size must be 0x17C");

namespace moho
{
  struct ManagedWindowSlot;
  class WWinManagedDialog;
  class CWinLogTarget;
  class WWinLogWindow;
  class WWinLogTextBuilder;
  struct CWinLogLine;

  /**
   * The event type CLogAdditionEvent carries (0x010A9BF0), numbered by
   * wxNewEventType in its static initialiser (0x00BC7310) like any
   * DEFINE_EVENT_TYPE.
   */
  extern const wxEventType EVT_LOG_ADDITION;

  /**
   * The event `CWinLogTarget::OnMessage` posts to the log dialog.
   *
   * RTTI: CLogAdditionEvent > wxEvent > wxObject, vftable 0x00E0C9F0 with
   * wxEvent's 5 slots: slot 0 is wxEvent's inline GetClassInfo (0x004B4310,
   * returning wxEvent::sm_classwxEvent) - this class declares no class info -
   * then the compiler's deleting destructor (0x004F3850) and Clone.
   * OnMessage (0x004F6860) builds one on the stack and hands it to
   * `wxEvtHandler::AddPendingEvent`, which clones it into the queue.
   */
  class CLogAdditionEvent final : public wxEvent
  {
  public:
    CLogAdditionEvent()
      : wxEvent(0, EVT_LOG_ADDITION)
    {}

    /**
     * Address: 0x004F37F0 (FUN_004F37F0)
     *
     * What it does:
     * Allocates and copy-clones one `CLogAdditionEvent` object (0x20 bytes).
     */
    wxEvent* Clone() const override;
  };

  static_assert(sizeof(CLogAdditionEvent) == 0x20, "moho::CLogAdditionEvent size must be 0x20");

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
     * Address: 0x004F9DF0 (FUN_004F9DF0)
     *
     * What it does:
     * Emits one wide literal and clears transient field width.
     */
    void WriteWideLiteral(const wchar_t* text);

    /**
     * Address: 0x004FA000 (FUN_004FA000)
     *
     * What it does:
     * Emits one UTF-8/narrow text fragment as widened output.
     */
    void WriteUtf8Text(const msvc8::string& text);

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

    void SetFieldWidth(std::size_t width) noexcept;
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
    msvc8::string text;

    [[nodiscard]] bool IsReplayEntry() const noexcept;
    [[nodiscard]] bool IsMessageEntry() const noexcept;
    [[nodiscard]] const wchar_t* SeverityPrefix() const noexcept;
  };

  static_assert(
    offsetof(CWinLogLine, isReplayEntry) == 0x0,
    "moho::CWinLogLine::isReplayEntry offset must be 0x0"
  );
  static_assert(
    offsetof(CWinLogLine, sequenceIndex) == 0x4,
    "moho::CWinLogLine::sequenceIndex offset must be 0x4"
  );
  static_assert(
    offsetof(CWinLogLine, categoryMask) == 0x8,
    "moho::CWinLogLine::categoryMask offset must be 0x8"
  );
  static_assert(
    offsetof(CWinLogLine, text) == 0xC,
    "moho::CWinLogLine::text offset must be 0xC"
  );
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
     * gpg::LogSeverity level, msvc8::string const &, msvc8::vector<msvc8::string> const &, int
     *
     * What it does:
     * Queues replay/context lines plus the current line into the pending log queue.
     */
    void OnMessage(
      gpg::LogSeverity level,
      const msvc8::string& message,
      const msvc8::vector<msvc8::string>& context,
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
    [[nodiscard]] const msvc8::vector<CWinLogLine>& CommittedLines() const;
    void SnapshotCommittedLines(msvc8::vector<CWinLogLine>* outLines);
    void ResetCommittedLinesFromReplayBuffer(const msvc8::vector<msvc8::string>& replayLines);

    WWinLogWindow* dialog = nullptr;
    msvc8::vector<CWinLogLine> mCommittedLines;
    boost::mutex lock{};
    msvc8::vector<CWinLogLine> mPendingLines;

  private:
    /**
     * Address: 0x004F6FD0 (FUN_004F6FD0)
     *
     * What it does:
     * Replaces committed-line storage with a copy of `nextCommittedLines`.
     */
    void ReplaceCommittedLines(const msvc8::vector<CWinLogLine>& nextCommittedLines);

    /**
     * Address: 0x004F6F40 (FUN_004F6F40)
     *
     * What it does:
     * Appends one line record into the pending queue.
     */
    void AppendPendingLine(const CWinLogLine& line);
  };

  static_assert(
    offsetof(CWinLogTarget, dialog) == 0x8,
    "moho::CWinLogTarget::dialog offset must be 0x8"
  );
  static_assert(
    offsetof(CWinLogTarget, mCommittedLines) == 0xC,
    "moho::CWinLogTarget::mCommittedLines offset must be 0xC"
  );
  static_assert(
    offsetof(CWinLogTarget, lock) == 0x1C,
    "moho::CWinLogTarget::lock offset must be 0x1C"
  );
  static_assert(
    offsetof(CWinLogTarget, mPendingLines) == 0x24,
    "moho::CWinLogTarget::mPendingLines offset must be 0x24"
  );
  static_assert(sizeof(CWinLogTarget) == 0x34, "moho::CWinLogTarget size must be 0x34");

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
  class MohoApp : public wxApp
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

  class WCurveEditorPanel;

  /**
   * One vertical column of the curve envelope: a time on the horizontal axis
   * plus the value/tangent pair that gives the band its height there.
   */
  struct CurveEnvelopeColumn
  {
    float mTime = 0.0f;
    float mValue = 0.0f;
    float mTangent = 0.0f;
  };

  /** Envelope edge selectors taken by `ProjectCurvePointToScreen`. */
  inline constexpr std::int32_t kCurveEnvelopeUpperEdge = 0;
  inline constexpr std::int32_t kCurveEnvelopeCurveValue = 1;
  inline constexpr std::int32_t kCurveEnvelopeLowerEdge = 2;

  /**
   * Runtime emitter curve sample set is `moho::SEfxCurve` (see
   * `moho/effects/rendering/SEfxCurve.h`); this is the wx widget that edits
   * one such curve interactively.
   *
   * Layout/behavior evidence: constructed by `Moho::WCurveEditor::WCurveEditor`
   * (0x00661330), whose only caller is `Moho::WCurveEditorPanel::WCurveEditorPanel`
   * (0x0066276B). Every field offset below is proven by that constructor's
   * disassembly (0x006613FA-0x0066142F for the view-range quartet,
   * 0x0066140C for `mOwnerPanel`) and by the behavior methods below, which
   * were recovered against this same layout in `moho/app/WEmitterWx.cpp`
   * (originally under the working name `WEmitterCurveEditor` before this
   * pass connected them to the real mangled symbol `??0WCurveEditor@Moho@@QAE@@Z`).
   */
  class WCurveEditor : public wxControl
  {
  public:
    /**
     * Cursor into `mCurve.mKeys` naming the key the user currently has
     * selected. Seeded to `mCurve.mKeys.begin()` by the constructor
     * (0x00661470) and by FUN_00661A90 (0x00661B37); "no selection" is
     * expressed as `mSelectedKey == mCurve.mKeys.end()`.
     */
    Wm3::Vector3f* mSelectedKey;
    std::uint8_t mReserved134To137[0x4];
    SEfxCurve mCurve;

    /**
     * Time-axis pixels-per-unit, recomputed by the paint handler
     * (FUN_006621F0) as `clientWidth / (mViewTimeMax - mViewTimeMin)`.
     */
    float mViewTimeScale;

    /**
     * Value-axis units-per-pixel scale. Recomputed by the resize handler
     * (FUN_006621F0 stores the value span here, then divides the time span by
     * it) and used as the divisor that converts pixel / wheel deltas into
     * curve-value deltas (FUN_006617A0, FUN_00661820, FUN_00661900,
     * FUN_00661A90 all divide by `[this+0x174]`).
     */
    float mViewValueScale;

    /** Client size cached by the paint handler (FUN_006621F0). */
    std::int32_t mClientWidth;
    std::int32_t mClientHeight;

    /**
     * Visible view rectangle over the curve, stored interleaved as
     * (timeMin, valueMin, timeMax, valueMax). Proven by the `WCurveEditor`
     * constructor at 0x006613FA-0x0066142F, which seeds `[0x180] = 0.0f`,
     * `[0x188] = arg8`, `[0x184] = argC`, `[0x18C] = arg10`; and by the span
     * arithmetic in FUN_006621F0 (`[0x188]-[0x180]` paired with
     * `[0x18C]-[0x184]`).
     */
    float mViewTimeMin;
    float mViewValueMin;
    float mViewTimeMax;
    float mViewValueMax;
    /** Set once the widget has captured the mouse for a drag (FUN_00661820). */
    std::uint8_t mMouseCaptured;
    std::uint8_t mCurveDirty;
    std::uint8_t mReserved192To193[0x2];

    /** Caption painted at the widget's top-left corner. */
    wxString mCaption;

    /** Script key this curve is written out under (FUN_00661580). */
    wxString mScriptName;

    /** Panel that owns this editor; refreshed after a curve assignment. */
    WCurveEditorPanel* mOwnerPanel;

    /** Cursor position cached on button-down (FUN_00661820). */
    std::int32_t mLastMouseX;
    std::int32_t mLastMouseY;

    /** Which button is driving the current drag: 1 = left, 2 = middle. */
    std::int32_t mActiveDragButton;

    /**
     * Unconfirmed trailing lane: `operator new(0x1B0)` (the allocation size
     * for this type at 0x006626FF) is four bytes past `mActiveDragButton`,
     * but no recovered method reads/writes anything past it yet. Kept as a
     * named, sized placeholder per CLAUDE.md's typed-placeholder rule rather
     * than guessed at.
     */
    std::uint8_t mReserved1ACTo1AF[0x4];

    /**
     * Address: 0x00661330 (FUN_00661330, Moho::WCurveEditor::WCurveEditor)
     * Mangled: ??0WCurveEditor@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::WCurveEditor *__thiscall Moho::WCurveEditor::WCurveEditor(
     *   WSupComFrame *parent@<ecx>, Moho::WCurveEditor *this, int id,
     *   float viewTimeMax, float viewValueMin, float viewValueMax,
     *   float initialKeyValue, float initialKeyTangent);
     * (IDA's own `this`/`a2` labels are swapped from real C++ ABI - `a2` on
     * the stack is the actual constructed object; the `ecx` param is the
     * parent window, confirmed by the caller passing itself as the first
     * argument and by `[edi+19Ch] = ecx` seeding `mOwnerPanel`.)
     *
     * What it does:
     * Builds one wx child control named `wxControlNameStr` ("control") over
     * `parent`, installs this type's vtable, default-constructs `mCurve`
     * (zero keys, inline `fastvector_n<Vector3f,2>` storage - the
     * `[edi+148h..154h]` writes the decompiler shows are exactly that
     * default construction, not something this constructor does by hand),
     * seeds the visible view rectangle to
     * `(0, viewValueMin, viewTimeMax, viewValueMax)`, rescales the (still
     * empty) curve to `[0, viewTimeMax]`, inserts one initial key at
     * `(viewTimeMax * 0.5, initialKeyValue, initialKeyTangent)`, selects that
     * key, and shows the control.
     */
    WCurveEditor(
      WCurveEditorPanel* parent,
      std::int32_t id,
      float viewTimeMax,
      float viewValueMin,
      float viewValueMax,
      float initialKeyValue,
      float initialKeyTangent
    );

    void ResetCurveXRange(float rangeMax) noexcept;

    /**
     * Address: 0x006617A0 (FUN_006617A0)
     *
     * What it does:
     * `wxEventTableEntry` mouse-wheel sink at 0x00F59D44: zooms the value axis
     * about its centre, rejecting zooms that would collapse the visible span
     * below 0.1f, then raises the curve-changed notification.
     */
    void ZoomValueAxisByWheel(wxMouseEvent& wheelEvent);

    /**
     * Address: 0x00662570 (FUN_00662570, nullsub_1719)
     *
     * What it does:
     * Nothing (`ret 4`). The last row of the event table binds it to
     * wxEVT_ENTER_WINDOW, so entering the control is swallowed.
     */
    void IgnoreEvent(wxMouseEvent& event);

    /**
     * Address: 0x00661A50 (FUN_00661A50)
     *
     * What it does:
     * Ends a drag (left or middle button up): clears the drag button and, if
     * the mouse was captured, releases it and posts the curve-changed command;
     * then repaints.
     */
    void OnMouseUp(wxMouseEvent& event);

    /**
     * Address: 0x00661900 (FUN_00661900)
     *
     * What it does:
     * Drags the selected key: with the left button it follows the cursor,
     * clamped to the view and between its neighbours; with the middle button
     * the vertical motion widens or narrows its tangent (never below 0). Any
     * drag posts the curve-changed command and repaints; the cursor position
     * is always remembered for the next move.
     */
    void OnMouseMove(wxMouseEvent& event);

    /**
     * Address: 0x00661100 (FUN_00661100)
     *
     * What it does:
     * Clears the dirty flag and posts a `wxEVT_COMMAND_BUTTON_CLICKED`
     * command event carrying this editor's window id, so the owning panel
     * learns the curve changed.
     */
    void PostCurveChangedCommand();

    /**
     * Address: 0x006614B0 (FUN_006614B0)
     *
     * What it does:
     * Moves the selected key to `(time, value, tangent)`, clamping the time
     * into the visible time range and against the neighbouring keys (to keep
     * keys sorted by time) and the value into the visible value range.
     */
    void MoveSelectedKeyTo(float time, float value, float tangent);

    /**
     * Address: 0x00661B90 (FUN_00661B90)
     *
     * What it does:
     * Paints one span of the curve's tangent envelope between the given key
     * and its neighbour (clamped to the visible time range at either end),
     * then draws the curve line across that span.
     */
    void DrawKeyEnvelopeSpan(wxDC& dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x00662180 (FUN_00662180)
     *
     * What it does:
     * Draws one key's 5x5 grab handle, cyan when selected and red otherwise.
     */
    void DrawKeyHandle(wxDC& dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x006621F0 (FUN_006621F0)
     *
     * What it does:
     * `wxEventTableEntry` paint sink: caches the client size, derives the view
     * scales, and paints the envelope spans, key handles and axis labels.
     */
    void OnPaint(wxPaintEvent& event);

    /**
     * Address: 0x00661820 (FUN_00661820)
     *
     * What it does:
     * Button-down sink: caches the cursor, selects the nearest key, records the
     * drag button, captures the mouse and repaints.
     */
    void OnMouseDown(wxMouseEvent& mouseEvent);

    /**
     * Address: 0x00661A90 (FUN_00661A90)
     *
     * What it does:
     * Key-editing sink: a plain click inserts a key at the cursor, a
     * control-click deletes the nearest one (never the last).
     */
    void OnCurveKeyEdit(wxMouseEvent& mouseEvent);

    /**
     * Address: 0x006612A0 (FUN_006612A0)
     *
     * What it does:
     * Projects one curve point to widget space. `edge` selects the upper
     * envelope edge (`value + tangent/2`), the curve value itself, or the
     * lower edge (`value - tangent/2`).
     */
    [[nodiscard]] wxPoint ProjectCurvePointToScreen(
      std::int32_t edge,
      const CurveEnvelopeColumn& column
    ) const noexcept;

    /**
     * Address: 0x00669E40 (FUN_00669E40)
     *
     * What it does:
     * Replaces the edited curve wholesale, drops the now-dangling selection,
     * notifies, and refreshes the owning panel's fields.
     */
    void AssignCurve(const SEfxCurve& source);

    /**
     * Address: 0x00661580 (FUN_00661580)
     *
     * What it does:
     * Formats this curve as a Lua table (`XRange` plus one `{x,y,z}` line per
     * key). See the body note: the retail exporter discards the text.
     */
    void FormatCurveScript() const;

    void MarkCurveClean() noexcept;
    [[nodiscard]] const SEfxCurve& Curve() const noexcept;

    // GetEventTable (0x00662660) and the table itself come from this macro.
    DECLARE_EVENT_TABLE()
  };
  static_assert(offsetof(WCurveEditor, mCurve) == 0x138, "WCurveEditor::mCurve offset must be 0x138");
  static_assert(
    offsetof(WCurveEditor, mViewTimeScale) == 0x170,
    "WCurveEditor::mViewTimeScale offset must be 0x170"
  );
  static_assert(
    offsetof(WCurveEditor, mViewValueScale) == 0x174,
    "WCurveEditor::mViewValueScale offset must be 0x174"
  );
  static_assert(
    offsetof(WCurveEditor, mClientWidth) == 0x178,
    "WCurveEditor::mClientWidth offset must be 0x178"
  );
  static_assert(
    offsetof(WCurveEditor, mClientHeight) == 0x17C,
    "WCurveEditor::mClientHeight offset must be 0x17C"
  );
  static_assert(
    offsetof(WCurveEditor, mViewTimeMin) == 0x180,
    "WCurveEditor::mViewTimeMin offset must be 0x180"
  );
  static_assert(
    offsetof(WCurveEditor, mViewValueMin) == 0x184,
    "WCurveEditor::mViewValueMin offset must be 0x184"
  );
  static_assert(
    offsetof(WCurveEditor, mViewTimeMax) == 0x188,
    "WCurveEditor::mViewTimeMax offset must be 0x188"
  );
  static_assert(
    offsetof(WCurveEditor, mViewValueMax) == 0x18C,
    "WCurveEditor::mViewValueMax offset must be 0x18C"
  );
  static_assert(
    offsetof(WCurveEditor, mCurveDirty) == 0x191,
    "WCurveEditor::mCurveDirty offset must be 0x191"
  );
  static_assert(offsetof(WCurveEditor, mOwnerPanel) == 0x19C, "WCurveEditor::mOwnerPanel offset must be 0x19C");
  static_assert(sizeof(WCurveEditor) == 0x1B0, "WCurveEditor size must be 0x1B0");

  /**
   * One `WCurveEditor` plus five numeric fields (key time/value/tangent,
   * visible value range) that mirror the selected key and let it be edited by
   * hand.
   *
   * RTTI: WCurveEditorPanel > wxPanel, with wxPanel's 132 vtable slots; its
   * own fields start at sizeof(wxPanel) = 0x134. The constructor (0x00662680)
   * proves every offset: 0x006626FF-0x0066271D zero the five text-control
   * pointers and the live flag, 0x0066277B writes the editor, 0x006633DD sets
   * the live flag. The destructors are the compiler's (0x00663870 is the
   * deleting one; 0x009AE6D0, which IDA attributed to this class, lies in the
   * wx library block). GetEventTable (0x006638A0) comes from
   * DECLARE_EVENT_TABLE below.
   */
  class WCurveEditorPanel : public wxPanel
  {
  public:
    WCurveEditor* mCurveEditor; // +0x134

    /**
     * The five numeric fields the panel keeps in sync with the editor. Their
     * wx command ids are consecutive from 622 (0x26E), which is how
     * FUN_00663650 selects between them.
     */
    wxTextCtrl* mKeyTimeText;      // +0x138, id 622
    wxTextCtrl* mKeyValueText;     // +0x13C, id 623
    wxTextCtrl* mKeyTangentText;   // +0x140, id 624
    wxTextCtrl* mViewValueMinText; // +0x144, id 625
    wxTextCtrl* mViewValueMaxText; // +0x148, id 626

    /** Set once the panel's fields are bound; commits are ignored until then. */
    std::uint8_t mFieldsLive;      // +0x14C

    /**
     * Address: 0x00662680 (FUN_00662680, Moho::WCurveEditorPanel::WCurveEditorPanel)
     * Mangled: ??0WCurveEditorPanel@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::WCurveEditorPanel *__stdcall Moho::WCurveEditorPanel::WCurveEditorPanel(
     *   Moho::WCurveEditorPanel *this, DWORD parent, int childId,
     *   float viewTimeMax, float viewValueMin, float viewValueMax,
     *   float initialKeyValue, float initialKeyTangent);
     * (IDA's `__stdcall`/all-stack-args shape is a decompiler artifact of a
     * plain `__thiscall` ctor; `this` arrives in ECX as usual.)
     *
     * What it does:
     * Builds a wx child panel named `wxPanelNameStr` over `parent` (the panel
     * itself does not use `childId` - that value is forwarded on unchanged as
     * the nested `WCurveEditor`'s window id, matching the binary exactly),
     * installs this type's vtable, allocates and constructs one
     * `WCurveEditor` (0x1B0 bytes) with the five range/key arguments, then
     * lays out a vertical sizer holding, for each of the five fields in turn:
     * a static label plus a text control seeded from the editor's current
     * key/range value and given the field's fixed command id (622-626).
     * Finally the editor itself is added to the sizer, which becomes this
     * panel's sizer, and the panel is marked as having its fields live.
     */
    WCurveEditorPanel(
      wxWindow* parent,
      std::int32_t childId,
      float viewTimeMax,
      float viewValueMin,
      float viewValueMax,
      float initialKeyValue,
      float initialKeyTangent
    );

    /**
     * Address: 0x00663650 (FUN_00663650)
     *
     * What it does:
     * `wxEventTableEntry` sink shared by all five numeric fields: re-reads the
     * committed text, applies it to the selected key or the visible value
     * range, and mirrors the parsed value back into the field.
     */
    void OnCurveFieldCommitted(wxCommandEvent& commandEvent);

    /**
     * Address: 0x00663400 (FUN_00663400)
     *
     * What it does:
     * Pushes the editor's current key and view-range values back out into the
     * five numeric fields, formatted as `%f`.
     */
    void RefreshFieldsFromCurve();

    DECLARE_EVENT_TABLE()
  };
  static_assert(offsetof(WCurveEditorPanel, mCurveEditor) == 0x134, "WCurveEditorPanel::mCurveEditor offset must be 0x134");
  static_assert(
    offsetof(WCurveEditorPanel, mKeyTimeText) == 0x138,
    "WCurveEditorPanel::mKeyTimeText offset must be 0x138"
  );
  static_assert(
    offsetof(WCurveEditorPanel, mViewValueMaxText) == 0x148,
    "WCurveEditorPanel::mViewValueMaxText offset must be 0x148"
  );
  static_assert(
    offsetof(WCurveEditorPanel, mFieldsLive) == 0x14C,
    "WCurveEditorPanel::mFieldsLive offset must be 0x14C"
  );
  static_assert(sizeof(WCurveEditorPanel) == 0x150, "WCurveEditorPanel size must be 0x150");

  /**
   * A panel that tiles a bitmap across itself on erase-background.
   *
   * RTTI: WBitmapPanel > wxPanel, wxPanel's 132 vtable slots; the constructor
   * (0x004FBCC0) stores the bitmap right after the 0x134-byte wxPanel.
   * GetEventTable (0x004FBCB0) comes from DECLARE_EVENT_TABLE below.
   */
  class WBitmapPanel : public wxPanel
  {
  public:
    /**
     * Address: 0x004FBCC0 (FUN_004FBCC0, ??0WBitmapPanel@Moho@@QAE@PAVwxWindow@@PAVwxBitmap@@@Z)
     * Mangled: ??0WBitmapPanel@Moho@@QAE@PAVwxWindow@@PAVwxBitmap@@@Z
     *
     * What it does:
     * Creates the panel under `parentWindow` and keeps `bitmap` for painting.
     */
    WBitmapPanel(wxWindow* parentWindow, wxBitmap* bitmap);

    /**
     * Address: 0x004FBD90 (FUN_004FBD90, ?OnEraseBackground@WBitmapPanel@Moho@@IAEXAAVwxEraseEvent@@@Z)
     * Mangled: ?OnEraseBackground@WBitmapPanel@Moho@@IAEXAAVwxEraseEvent@@@Z
     *
     * What it does:
     * Tiles the bound bitmap across the panel client span during erase
     * background, or skips the event when there is nothing to draw.
     */
    void OnEraseBackground(wxEraseEvent& eraseEvent);

    wxBitmap* mBitmap; // +0x134

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(WBitmapPanel, mBitmap) == 0x134, "moho::WBitmapPanel::mBitmap offset must be 0x134");

  /**
   * A bitmap button that toggles.
   *
   * RTTI: WBitmapCheckBox > wxBitmapButton, vftable 0x00E0CE74 with
   * wxBitmapButton's 142 slots (the dump's 143rd entry, 0x004B004F, is the
   * dword after the table - no function starts there). The checked byte sits
   * right after the 0x168-byte wxBitmapButton. GetEventTable (0x004FBE20)
   * comes from DECLARE_EVENT_TABLE below.
   */
  class WBitmapCheckBox : public wxBitmapButton
  {
  public:
    /**
     * Address: 0x004FBE30 (FUN_004FBE30, ??0WBitmapCheckBox@Moho@@QAE@PAVwxWindow@@HABVwxBitmap@@@Z)
     * Mangled: ??0WBitmapCheckBox@Moho@@QAE@PAVwxWindow@@HABVwxBitmap@@@Z
     *
     * What it does:
     * Runs `wxBitmapButton`'s constructor with the default button name and
     * clears the checked byte.
     */
    WBitmapCheckBox(wxWindow* parentWindow, int controlId, const wxBitmap& bitmap);

    /**
     * Address: 0x004FBF10 (FUN_004FBF10, ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ)
     * Mangled: ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ
     *
     * What it does:
     * Returns whether the button is checked.
     */
    [[nodiscard]] bool IsChecked();

    /**
     * Address: 0x004FBF20 (FUN_004FBF20, ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z)
     * Mangled: ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z
     *
     * What it does:
     * Stores the new state; when it actually flips, lets the button pick its
     * bitmap again (OnSetBitmap, vtable +0x228) and repaints (Refresh, +0xF0).
     */
    void SetChecked(bool checked);

    /**
     * Address: 0x004FC010 (FUN_004FC010)
     *
     * What it does:
     * Toggles the checked state on left-button-up and skips the event on.
     */
    void OnLeftUp(wxMouseEvent& event);

    std::uint8_t mIsChecked; // +0x168

    DECLARE_EVENT_TABLE()
  };

  static_assert(
    offsetof(WBitmapCheckBox, mIsChecked) == 0x168,
    "moho::WBitmapCheckBox::mIsChecked offset must be 0x168"
  );

  /**
   * The modal input box behind the `WxInputBox` console helper.
   *
   * RTTI: WWxInputBox > wxDialog, wxDialog's 145 vtable slots
   * (vftable 0x00E0D12C). The text control and the caller's result string sit
   * right after the 0x170-byte wxDialog - in that order: the constructor
   * stores the control at +0x170 (0x004FC3E3) and the string at +0x174
   * (0x004FC15F). Its one override (0x004FC7B0, vtable +0xDC) is
   * wxWindowBase::TransferDataFromWindow - the hook wxDialog::OnOK runs before
   * EndModal(wxID_OK) - which reads the control through wxTextCtrl::GetValue
   * (+0x218).
   */
  class WWxInputBox : public wxDialog
  {
  public:
    wxTextCtrl* mTextCtrl;         // +0x170
    msvc8::string* mResultString;  // +0x174

    /**
     * Address: 0x004FC040 (FUN_004FC040, ??0WWxInputBox@Moho@@QAE@PBDPBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@msvc8@@00PAV40@@Z)
     *
     * What it does:
     * Creates the dialog (wxDEFAULT_DIALOG_STYLE, the title widened from
     * UTF-8) and lays it out: the label, the text control seeded with the
     * default value, and OK/Cancel below them, at least 500 wide.
     */
    WWxInputBox(
      const char* dialogTitle,
      const char* defaultValue,
      const char* labelText,
      msvc8::string* resultString
    );

    /**
     * Address: 0x004FC7B0 (FUN_004FC7B0, vtable +0xDC)
     *
     * What it does:
     * UTF-8 encodes the text control's value into the caller's result string
     * and returns true, so wxDialog::OnOK goes on to EndModal(wxID_OK).
     */
    bool TransferDataFromWindow() override;

    // No event table of its own: vtable slot 6 is wxDialog::GetEventTable
    // (0x0098B230), the same as the base's.
  };

  static_assert(offsetof(WWxInputBox, mTextCtrl) == 0x170, "moho::WWxInputBox::mTextCtrl offset must be 0x170");
  static_assert(
    offsetof(WWxInputBox, mResultString) == 0x174,
    "moho::WWxInputBox::mResultString offset must be 0x174"
  );
  static_assert(sizeof(WWxInputBox) == 0x178, "moho::WWxInputBox size must be 0x178");

  /**
   * Address: 0x004FC870 (FUN_004FC870, ?WxInputBox@Moho@@YA_NPBD0PAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@msvc8@@@Z)
   *
   * What it does:
   * Helper that allocates one heap-resident `WWxInputBox`, runs the modal
   * loop via the dialog's `ShowModal` virtual (slot +0x04 of the dialog
   * vtable, returns `wxID_OK = 5100` on accept), copies the entered text
   * into `resultString` via the OnOK override above, then destroys the
   * dialog. Returns `true` when the user accepted (wxID_OK) and `false`
   * for cancel / window-close.
   */
  [[nodiscard]] bool WxInputBox(
    const char* dialogTitle,
    const char* defaultValue,
    const char* labelText,
    msvc8::string* resultString
  );

  /**
   * Address: 0x004FC900 (FUN_004FC900, ?CON_WxInputBox@Moho@@YAXPAX@Z)
   *
   * What it does:
   * Console-command callback that opens an interactive `WxInputBox` with
   * fixed test prompts and prints either the entered text or a "Canceled"
   * message. Registered as the `WxInputBox` startup console command by
   * `register_CConFunc_WxInputBox`.
   */
  void CON_WxInputBox(const msvc8::vector<msvc8::string>& args);

  /**
   * Entry stored in the legacy `managedWindows` / `managedFrames` vectors.
   *
   * The first field points to the owning window's head-link slot
   * (`WWinManaged*::mManagedSlotsHead`), and the second field chains all
   * slots associated with the owner.
   */
  struct ManagedWindowSlot
  {
    ManagedWindowSlot** ownerHeadLink = nullptr;
    ManagedWindowSlot* nextInOwnerChain = nullptr;

    /**
     * Address family:
     * - 0x004F7210 (FUN_004F7210)
     * - 0x004F72D0 (FUN_004F72D0)
     *
     * What it does:
     * Detaches this slot from its owner-managed slot chain.
     *
     * Behavior is shared by constructor unwind + explicit owner-unlink paths.
     */
    void UnlinkFromOwner() noexcept;

    /**
     * Address context:
     * - 0x004F40A0 (dialog dtor core)
     * - 0x004F4230 (frame dtor core)
     *
     * What it does:
     * Clears both slot links to the inert state.
     */
    void Clear() noexcept;
  };

  static_assert(sizeof(ManagedWindowSlot) == 0x8, "moho::ManagedWindowSlot size must be 0x8");
  static_assert(
    offsetof(ManagedWindowSlot, ownerHeadLink) == 0x0,
    "moho::ManagedWindowSlot::ownerHeadLink offset must be 0x0"
  );
  static_assert(
    offsetof(ManagedWindowSlot, nextInOwnerChain) == 0x4,
    "moho::ManagedWindowSlot::nextInOwnerChain offset must be 0x4"
  );

  /**
   * A dialog the engine keeps a weak slot for in `managedWindows`, so WINX_Exit
   * can destroy whatever is still open.
   *
   * RTTI: WWinManagedDialog > wxDialog, vftable 0x00E0C51C. Slot 0 is
   * wxDialog's inline GetClassInfo and slot 6 wxDialog::GetEventTable
   * (0x0098B230): no class info or event table of its own. The one member
   * sits right after the 0x170-byte wxDialog; it is the head of the weak-link
   * chain the `managedWindows` slots hang off (a WeakObject, which the slot
   * code below still spells out by hand).
   */
  class WWinManagedDialog : public wxDialog
  {
  public:
    /**
     * Address: 0x004F3F50 (FUN_004F3F50)
     *
     * What it does:
     * `wxDialog(parent, id, title, position, size, style, name)`, then files
     * this dialog in the first free `managedWindows` slot, or a new one. The
     * one caller, WWinLogWindow, passes (null, -1, wxDefaultPosition,
     * wxDefaultSize, wxCAPTION | wxSYSTEM_MENU | wxRESIZE_BORDER).
     */
    WWinManagedDialog(
      wxWindow* parent,
      wxWindowID id,
      const wxString& title,
      const wxPoint& position,
      const wxSize& size,
      long style,
      const wxString& name
    );

    /**
     * Address: 0x004F40A0 (FUN_004F40A0)
     *
     * What it does:
     * Unlinks every managed slot still pointing at this dialog, then
     * ~wxDialog. The deleting destructor (0x004F4080) is the compiler's.
     */
    ~WWinManagedDialog() override;

    static WWinManagedDialog* FromManagedSlotHeadLink(ManagedWindowSlot** ownerHeadLink) noexcept;
    static ManagedWindowSlot** NullManagedSlotHeadLinkSentinel() noexcept;

    /**
     * Address: 0x004F7070 (FUN_004F7070)
     *
     * What it does:
     * Returns the current number of dialog-managed registry slots.
     */
    static std::size_t ManagedSlotCount();

    /**
     * Address: 0x004F70A0 (FUN_004F70A0)
     *
     * What it does:
     * Appends one dialog-managed registry slot and links it to `ownerHeadLink`,
     * preserving slot-chain ownership links across vector growth.
     */
    static void AppendManagedSlotForOwner(ManagedWindowSlot** ownerHeadLink);

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);

  private:
    void RegisterManagedOwnerSlot();
    void ReleaseManagedOwnerSlots();

  public:
    ManagedWindowSlot* mManagedSlotsHead; // +0x170
  };

  static_assert(sizeof(wxDialog) == 0x170, "wxDialog size must be 0x170");
  static_assert(
    offsetof(WWinManagedDialog, mManagedSlotsHead) == 0x170,
    "moho::WWinManagedDialog::mManagedSlotsHead offset must be 0x170"
  );
  static_assert(sizeof(WWinManagedDialog) == 0x174, "moho::WWinManagedDialog size must be 0x174");

  /**
   * The "Moho Log" dialog: the console log with its category and filter
   * controls.
   *
   * RTTI: WWinLogWindow > WWinManagedDialog, vftable 0x00E0CA14. Slot 6 is
   * its GetEventTable (0x004F38E0), table 0x00DFF4A8 = {&wxDialog::
   * sm_eventTable, rows 0x00F59720}: the log-addition event, the five
   * category check boxes (900-904) and the filter text (905) to the rebuild,
   * the Clear button (906), size and move.
   *
   * The constructor (0x004F4270) also builds the dialog's sizers and
   * controls and stores them in the pointers below; that part is not
   * recovered, so the control pointers stay null and the handlers skip them.
   */
  class WWinLogWindow : public WWinManagedDialog
  {
  public:
    /**
     * Address: 0x004F4270 (FUN_004F4270)
     *
     * What it does:
     * Creates the dialog as "Moho Log" (name "MohoDialogBox"), seeds the
     * members, restores the category, filter and geometry preferences, and
     * clears the initialising flag.
     */
    WWinLogWindow();

    /**
     * Address: 0x004F5380 (FUN_004F5380)
     *
     * What it does:
     * Detaches from the log target; the members and ~WWinManagedDialog do the
     * rest. The deleting destructor (0x004F5360) is the compiler's.
     */
    ~WWinLogWindow() override;

    [[nodiscard]] std::array<wxCheckBox*, 5> CategoryCheckBoxes() noexcept;
    [[nodiscard]] std::array<const wxCheckBox*, 5> CategoryCheckBoxes() const noexcept;

    /**
     * Address: 0x004F5840 (FUN_004F5840)
     *
     * What it does:
     * Rebuilds enabled category/filter state from controls and replays matching
     * committed target lines into output.
     */
    void RebuildVisibleLinesFromControls();

    /**
     * Address: 0x004F5AE0 (FUN_004F5AE0)
     *
     * What it does:
     * Applies one committed line against filter/category state and appends it to
     * output and replay buffer state.
     */
    void AppendCommittedLine(const CWinLogLine& line);

    /**
     * Address: 0x004F6760 (FUN_004F6760)
     *
     * What it does:
     * Clears `mOwnerTarget->dialog` under the target lock.
     */
    void DetachFromTarget();

    [[nodiscard]] bool ShouldDisplayCommittedLine(const CWinLogLine& line) const;
    [[nodiscard]] std::wstring BuildReplayFlushText(std::size_t startIndex) const;
    [[nodiscard]] std::wstring BuildFormattedCommittedLineText(const CWinLogLine& line) const;

    /**
     * Address: 0x004F6470 (FUN_004F6470)
     *
     * What it does:
     * Merges the target's pending lines and appends just the ones the merge
     * added. Bound to the log-addition event CWinLogTarget::OnMessage posts.
     */
    void OnTargetPendingLinesChanged(CLogAdditionEvent& event);

    /**
     * Address: 0x004F5590 (FUN_004F5590)
     *
     * What it does:
     * Once the controls are built, rebuilds the visible lines from them and
     * stores the category and filter state back into the preferences. Bound to
     * the category check boxes (900-904) and the filter text (905).
     */
    void OnFilterOrCategoryControlsChanged(wxCommandEvent& event);

    /**
     * Address: 0x004F5440 (FUN_004F5440)
     *
     * What it does:
     * Clears the output and rebuilds the target's committed lines from the
     * buffered replay text. Bound to the Clear button (906).
     */
    void OnClear(wxCommandEvent& event);

    /**
     * Address: 0x004F6640 (FUN_004F6640)
     *
     * What it does:
     * Lays the single child out over the client area, then - once the
     * controls are built - stores the window's size in `Windows.Log.width` and
     * `Windows.Log.height`.
     */
    void OnSize(wxSizeEvent& event);

    /**
     * Address: 0x004F6520 (FUN_004F6520)
     *
     * What it does:
     * Once the controls are built, stores the window's position in
     * `Windows.Log.x` and `Windows.Log.y`.
     */
    void OnMove(wxMoveEvent& event);

    bool mIsInitializingControls;                // +0x174
    CWinLogTarget* mOwnerTarget;                 // +0x178
    wxTextCtrl* mOutputTextControl;              // +0x17C
    wxTextCtrl* mFilterTextControl;              // +0x180
    std::uint32_t mEnabledCategoriesMask;        // +0x184
    msvc8::string mFilterText;                   // +0x188
    wxCheckBox* mDebugCategoryCheckBox;          // +0x1A4
    wxCheckBox* mInfoCategoryCheckBox;           // +0x1A8
    wxCheckBox* mWarnCategoryCheckBox;           // +0x1AC
    wxCheckBox* mErrorCategoryCheckBox;          // +0x1B0
    wxCheckBox* mCustomCategoryCheckBox;         // +0x1B4
    msvc8::vector<msvc8::string> mBufferedLines; // +0x1B8
    std::uint32_t mFirstVisibleLine;             // +0x1C8

    DECLARE_EVENT_TABLE()
  };

  static_assert(
    offsetof(WWinLogWindow, mIsInitializingControls) == 0x174,
    "moho::WWinLogWindow::mIsInitializingControls offset must be 0x174"
  );
  static_assert(offsetof(WWinLogWindow, mOwnerTarget) == 0x178, "moho::WWinLogWindow::mOwnerTarget offset must be 0x178");
  static_assert(
    offsetof(WWinLogWindow, mOutputTextControl) == 0x17C,
    "moho::WWinLogWindow::mOutputTextControl offset must be 0x17C"
  );
  static_assert(
    offsetof(WWinLogWindow, mFilterTextControl) == 0x180,
    "moho::WWinLogWindow::mFilterTextControl offset must be 0x180"
  );
  static_assert(
    offsetof(WWinLogWindow, mEnabledCategoriesMask) == 0x184,
    "moho::WWinLogWindow::mEnabledCategoriesMask offset must be 0x184"
  );
  static_assert(offsetof(WWinLogWindow, mFilterText) == 0x188, "moho::WWinLogWindow::mFilterText offset must be 0x188");
  static_assert(
    offsetof(WWinLogWindow, mDebugCategoryCheckBox) == 0x1A4,
    "moho::WWinLogWindow::mDebugCategoryCheckBox offset must be 0x1A4"
  );
  static_assert(
    offsetof(WWinLogWindow, mCustomCategoryCheckBox) == 0x1B4,
    "moho::WWinLogWindow::mCustomCategoryCheckBox offset must be 0x1B4"
  );
  static_assert(
    offsetof(WWinLogWindow, mBufferedLines) == 0x1B8,
    "moho::WWinLogWindow::mBufferedLines offset must be 0x1B8"
  );
  static_assert(
    offsetof(WWinLogWindow, mFirstVisibleLine) == 0x1C8,
    "moho::WWinLogWindow::mFirstVisibleLine offset must be 0x1C8"
  );
  static_assert(sizeof(WWinLogWindow) == 0x1CC, "moho::WWinLogWindow size must be 0x1CC");

  /**
   * A frame the engine keeps a weak slot for in `managedFrames`, so WINX_Exit
   * can destroy whatever is still open.
   *
   * RTTI: WWinManagedFrame > wxFrame, vftable 0x00E0C764. Slot 0 is
   * wxFrame's inline GetClassInfo and slot 6 wxFrame::GetEventTable
   * (0x0099E7A0). The one member sits right after the 0x178-byte wxFrame.
   */
  class WWinManagedFrame : public wxFrame
  {
  public:
    /**
     * Address: 0x004F40E0 (FUN_004F40E0)
     * Mangled: ??0WWinManagedFrame@Moho@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
     *
     * What it does:
     * `wxFrame(parent, id, title, position, size, style, name)`, then files
     * this frame in the first free `managedFrames` slot, or a new one. The
     * binary's one caller passes (null, -1, wxDefaultPosition,
     * wxDEFAULT_FRAME_STYLE), which LTCG folded into the body.
     */
    WWinManagedFrame(
      wxWindow* parent,
      wxWindowID id,
      const wxString& title,
      const wxPoint& position,
      const wxSize& size,
      long style,
      const wxString& name
    );

    /**
     * Address: 0x004F4230 (FUN_004F4230)
     *
     * What it does:
     * Unlinks every managed slot still pointing at this frame, then ~wxFrame.
     * The deleting destructor (0x004F4210) is the compiler's.
     */
    ~WWinManagedFrame() override;

    static WWinManagedFrame* FromManagedSlotHeadLink(ManagedWindowSlot** ownerHeadLink) noexcept;
    static ManagedWindowSlot** NullManagedSlotHeadLinkSentinel() noexcept;

    /**
     * Address: 0x004F7140 (FUN_004F7140)
     *
     * What it does:
     * Returns the current number of frame-managed registry slots.
     */
    static std::size_t ManagedSlotCount();

    /**
     * Address: 0x004F7170 (FUN_004F7170)
     *
     * What it does:
     * Appends one frame-managed registry slot and links it to `ownerHeadLink`,
     * preserving slot-chain ownership links across vector growth.
     */
    static void AppendManagedSlotForOwner(ManagedWindowSlot** ownerHeadLink);

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);

  private:
    void RegisterManagedOwnerSlot();
    void ReleaseManagedOwnerSlots();

  public:
    ManagedWindowSlot* mManagedSlotsHead; // +0x178
  };

  static_assert(
    offsetof(WWinManagedFrame, mManagedSlotsHead) == 0x178,
    "moho::WWinManagedFrame::mManagedSlotsHead offset must be 0x178"
  );
  static_assert(sizeof(WWinManagedFrame) == 0x17C, "moho::WWinManagedFrame size must be 0x17C");

  // 0x010A9B94 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedWindows;
  // 0x010A9BD8 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedFrames;

  // The main frame (0x010A63B8): WIN_OkBox parents its message box on it,
  // and CScApp::CreateAppFrame sets it to the WSupComFrame.
  extern wxWindow* sMainWindow;
} // namespace moho

// wxGetApp(), from the IMPLEMENT_APP_NO_MAIN(moho::MohoApp) in WinApp.cpp.
DECLARE_APP(moho::MohoApp)
