#pragma once

#include <cstdarg>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "boost/mutex.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"

/**
 * wxWidgets 2.4.2, as the shipped binary linked it.
 *
 * `dependencies/wxWindows-2.4.2` is the same wxWidgets the engine was built
 * against, and `lib/wxmsw.lib` is a build of it. That was verified against the
 * binary rather than assumed: for every wx function this project had also
 * reimplemented and for which an address is on record, the field offsets the
 * shipped code touches and the ones the library's own code touches are the
 * same set - `wxWindowBase::Show` (0x00963660) flips bit 1 of the byte at
 * +0xCC in both, `GetMinWidth`/`GetMinHeight` read +0x4C/+0x50 in both,
 * `SetWindowStyleFlag` writes +0xD0, `SetExtraStyle` +0xD4, `SetThemeEnabled`
 * +0xDC, `AddChild` walks the child list at +0x30. The headers agree with the
 * sizes too: `sizeof(wxFrame)` is 0x178 here, and `WSupComFrame` - which
 * derives from it and adds three bytes - is 0x17C in the binary.
 *
 * So these types do not need recovering; they need linking. Declaring our own
 * versions of them produced two definitions of the same mangled names, and
 * which one the linker picked per COMDAT was arbitrary - the source of a
 * string of window bugs. The rule from here is: if `wxmsw.lib` defines it, we
 * include the real header and let the library provide the body.
 */
#include <wx/defs.h>
#include <wx/object.h>
#include <wx/stream.h>
#include <wx/file.h>
#include <wx/ffile.h>
#include <wx/wfstream.h>
#include <wx/filename.h>
#include <wx/string.h>

struct _RTL_CRITICAL_SECTION;

/**
 * Minimal recovered wx runtime types used by app/sim loop code.
 *
 * These declarations keep recovered dependencies centralized so loop/shutdown
 * code can use typed members instead of local ad-hoc overlay structs.
 */

struct wxPoint
{
  std::int32_t x = 0;
  std::int32_t y = 0;
};

static_assert(sizeof(wxPoint) == 0x8, "wxPoint size must be 0x8");

struct wxSize
{
  std::int32_t x = 0;
  std::int32_t y = 0;
};

static_assert(sizeof(wxSize) == 0x8, "wxSize size must be 0x8");

/**
 * Origin plus extent, in the order wxWindow::Refresh (0x00968350) reads them:
 * `x` at +0x00, `y` at +0x04, `width` at +0x08 and `height` at +0x0C, which it
 * turns into a Win32 RECT as {x, y, x + width, y + height}.
 */
struct wxRect
{
  std::int32_t x = 0;
  std::int32_t y = 0;
  std::int32_t width = 0;
  std::int32_t height = 0;
};

static_assert(sizeof(wxRect) == 0x10, "wxRect size must be 0x10");

struct WxDisplaySizePairRuntime
{
  std::int32_t widthPixels = 0;
  std::int32_t heightPixels = 0;
};

static_assert(sizeof(WxDisplaySizePairRuntime) == 0x8, "WxDisplaySizePairRuntime size must be 0x8");

struct WxDisplayTransformRuntimeView
{
  std::uint8_t reserved00_0B[0x0C]{};
  std::int32_t xBaseOffset = 0;     // +0x0C
  std::int32_t yBaseOffset = 0;     // +0x10
  std::int32_t xInputOrigin = 0;    // +0x14
  std::int32_t yInputOrigin = 0;    // +0x18
  std::uint8_t reserved1C_1F[0x04]{};
  double xScaleNumerator = 0.0;     // +0x20
  double yScaleNumerator = 0.0;     // +0x28
  double xScaleMiddle = 0.0;        // +0x30
  double yScaleMiddle = 0.0;        // +0x38
  double xScaleDenominator = 0.0;   // +0x40
  double yScaleDenominator = 0.0;   // +0x48
  std::int32_t xStep = 0;           // +0x50
  std::int32_t yStep = 0;           // +0x54
};

static_assert(sizeof(WxDisplayTransformRuntimeView) == 0x58, "WxDisplayTransformRuntimeView size must be 0x58");
static_assert(
  offsetof(WxDisplayTransformRuntimeView, xBaseOffset) == 0x0C,
  "WxDisplayTransformRuntimeView::xBaseOffset offset must be 0x0C"
);
static_assert(
  offsetof(WxDisplayTransformRuntimeView, yBaseOffset) == 0x10,
  "WxDisplayTransformRuntimeView::yBaseOffset offset must be 0x10"
);
static_assert(
  offsetof(WxDisplayTransformRuntimeView, xScaleNumerator) == 0x20,
  "WxDisplayTransformRuntimeView::xScaleNumerator offset must be 0x20"
);
static_assert(
  offsetof(WxDisplayTransformRuntimeView, yScaleNumerator) == 0x28,
  "WxDisplayTransformRuntimeView::yScaleNumerator offset must be 0x28"
);
static_assert(offsetof(WxDisplayTransformRuntimeView, xStep) == 0x50, "WxDisplayTransformRuntimeView::xStep offset must be 0x50");
static_assert(offsetof(WxDisplayTransformRuntimeView, yStep) == 0x54, "WxDisplayTransformRuntimeView::yStep offset must be 0x54");

struct WxAnonymousPipeHandles
{
  void* readHandle = nullptr;
  void* writeHandle = nullptr;
};

static_assert(sizeof(WxAnonymousPipeHandles) == 0x8, "WxAnonymousPipeHandles size must be 0x8");

struct wxStringRuntime;
struct wxColourRuntime;
class wxEventRuntime;
class wxMoveEventRuntime;
class wxEraseEventRuntime;
class wxCloseEventRuntime;
class wxCommandEventRuntime;
class wxCursor;
class wxBitmap;
class wxBrush;

/**
 * The two stock brushes `WD3DViewport::DrawBackgroundImage` (0x00430A60)
 * selects: `wxBLACK_BRUSH` (a `wxBrush*`) to fill with, and `&wxNullBrush` to
 * put back afterwards. Both live in `wxmsw.lib` as
 * `?wxBLACK_BRUSH@@3PAVwxBrush@@A` / `?wxNullBrush@@3VwxBrush@@A` and are
 * built by `wxInitializeStockObjects`, which `wxApp::Initialize` (0x009927E0)
 * runs.
 *
 * They have to be the real wx objects: `wxDC::SetBrush` takes a `wxBrush&`
 * and ref-counts it, so handing it a raw GDI `HBRUSH` from
 * `GetStockObject(BLACK_BRUSH)` - which is what stood here - made
 * `wxObject::Ref` write through a stock-object handle as if it were an
 * object pointer.
 */
extern wxBrush* wxBLACK_BRUSH;
extern wxBrush wxNullBrush;

/**
 * The named-colour table the stock objects are built from.
 *
 * `wxApp::Initialize` (0x009927E0) does `operator new(0x1Cu)` followed by
 * `wxColourDatabase::wxColourDatabase(db, 2)` and publishes the result in
 * `wxTheColourDatabase`, immediately before calling
 * `wxInitializeStockObjects` - which goes straight to
 * `wxColour::InitFromName` and would read through a null table otherwise.
 *
 * Only the size and the constructor are modelled: 0x1C from that allocation,
 * and `??0wxColourDatabase@@QAE@H@Z` from `wxmsw.lib`, which is where the
 * body stays. Nothing here needs its fields.
 */
class wxColourDatabase
{
public:
  explicit wxColourDatabase(int type);

private:
  std::uint8_t mStorage[0x1C]{};
};

static_assert(sizeof(wxColourDatabase) == 0x1C, "wxColourDatabase size must be 0x1C");

extern wxColourDatabase* wxTheColourDatabase;

/**
 * Builds the wx stock pens, brushes, fonts and cursors.
 * `?wxInitializeStockObjects@@YAXXZ` in `wxmsw.lib`; `wxApp::Initialize`
 * (0x009927E0) is what calls it in the binary.
 */
void wxInitializeStockObjects();
struct wxMouseEventRuntime;
class wxBitmapListRuntime;
struct WxThreadSuspendControllerRuntime;

struct WxThreadNativeHandleRuntime
{
  void* nativeThreadHandle = nullptr;
  std::uint32_t suspendStateFlag = 0;
};

static_assert(sizeof(WxThreadNativeHandleRuntime) == 0x8, "WxThreadNativeHandleRuntime size must be 0x8");

/**
 * Address: 0x009ACE50 (FUN_009ACE50, wxENTER_CRIT_SECT)
 *
 * What it does:
 * Enters one Win32 critical-section lane.
 */
void wxENTER_CRIT_SECT(_RTL_CRITICAL_SECTION* criticalSection);

/**
 * Address: 0x009ACE60 (FUN_009ACE60, wxLEAVE_CRIT_SECT)
 *
 * What it does:
 * Leaves one Win32 critical-section lane.
 */
void wxLEAVE_CRIT_SECT(_RTL_CRITICAL_SECTION* criticalSection);

/**
 * Address: 0x009AD330 (FUN_009AD330, wxThread::IsMain)
 *
 * What it does:
 * Returns whether the current Win32 thread matches the stored wx main-thread id.
 */
[[nodiscard]] bool wxThreadIsMain();

/**
 * Address: 0x009AD660 (FUN_009AD660, wxGuiOwnedByMainThread)
 *
 * What it does:
 * Returns the wx GUI-ownership flag managed by the GUI mutex helpers.
 */
[[nodiscard]] bool wxGuiOwnedByMainThread();

/**
 * Address: 0x009AD670 (FUN_009AD670, wxWakeUpMainThread)
 *
 * What it does:
 * Posts one wake-up message (`WM_NULL`) to the stored wx main-thread id.
 */
[[nodiscard]] bool wxWakeUpMainThread();

/**
 * Address: 0x009AD210 (FUN_009AD210)
 *
 * What it does:
 * Suspends one native thread handle and stores the post-suspend runtime flag
 * lane used by wx thread-control helpers.
 */
[[nodiscard]] bool wxThreadSuspendNativeHandle(WxThreadNativeHandleRuntime* threadRuntime);

/**
 * Address: 0x009AD270 (FUN_009AD270)
 *
 * What it does:
 * Resumes one native thread handle and updates the runtime suspend-state flag
 * lane to match original wx thread-control semantics.
 */
[[nodiscard]] bool wxThreadResumeNativeHandle(WxThreadNativeHandleRuntime* threadRuntime);

/**
 * Address: 0x009AD8D0 (FUN_009AD8D0)
 *
 * What it does:
 * Enters the thread-controller critical section, suspends the owned native
 * handle lane, and returns `0` or wx thread misc-error `5`.
 */
[[nodiscard]] int wxThreadSuspendNativeHandleGuarded(WxThreadSuspendControllerRuntime* controller);

/**
 * Address: 0x009AD940 (FUN_009AD940)
 *
 * What it does:
 * Enters the thread-controller critical section, resumes the owned native
 * handle lane, and returns `0` or wx thread misc-error `5`.
 */
[[nodiscard]] int wxThreadResumeNativeHandleGuarded(WxThreadSuspendControllerRuntime* controller);

/**
 * Address: 0x009674D0 (FUN_009674D0, wxIsShiftDown)
 *
 * What it does:
 * Returns whether the Win32 Shift key is currently pressed.
 */
[[nodiscard]] bool wxIsShiftDown();

/**
 * Address: 0x009674F0 (FUN_009674F0, wxIsCtrlDown)
 *
 * What it does:
 * Returns whether the Win32 Control key is currently pressed.
 */
[[nodiscard]] bool wxIsCtrlDown();

/**
 * Address: 0x009ADC20 (FUN_009ADC20, wxMutexGuiLeave)
 *
 * What it does:
 * Releases GUI ownership for the calling lane and unlocks wx GUI/waiting
 * critical sections with the original runtime ordering.
 */
void wxMutexGuiLeave();

/**
 * Address: 0x009ADC70 (FUN_009ADC70, wxMutexGuiLeaveOrEnter)
 *
 * What it does:
 * Reconciles GUI ownership against waiting-thread state, leaving or entering
 * the wx GUI critical section as required by the original runtime contract.
 */
void wxMutexGuiLeaveOrEnter();

/**
 * Address: 0x009C7540 (FUN_009C7540, wxGetOsVersion)
 *
 * What it does:
 * Caches Win32 platform-id and major/minor version lanes and returns the wx
 * OS-family enum value.
 */
int wxGetOsVersion(int* majorVsn, int* minorVsn);

/**
 * Address: 0x009C8260 (FUN_009C8260)
 *
 * What it does:
 * Builds one localized human-readable Windows version string using
 * `GetVersionExW` platform and CSD lanes.
 */
[[nodiscard]] wxStringRuntime wxGetOsDescription();

/**
 * Address: 0x009BFA70 (FUN_009BFA70)
 *
 * What it does:
 * Formats one `"windows-<ACP>"` encoding label into `outEncodingName`.
 */
wxStringRuntime* wxBuildWindowsCodePageEncodingName(wxStringRuntime* outEncodingName);

/**
 * Address: 0x009BF3E0 (FUN_009BF3E0)
 *
 * What it does:
 * Builds one locale message-catalog path chain under `LC_MESSAGES` into
 * `outPath` from `(localeName, localeDirectory)` lanes.
 */
wxStringRuntime* wxBuildLocaleMessagesCatalogPath(
  wxStringRuntime* outPath,
  const wchar_t* localeName,
  const wchar_t* localeDirectory
);

/**
 * Address: 0x009C8A40 (FUN_009C8A40)
 *
 * What it does:
 * Captures current DC text/background colors, applies runtime override lanes
 * when active, and records whether capture succeeded.
 */
void* wxCaptureAndApplyDcColourStateRuntime(
  void* outStateScopeRuntime,
  void* dcRuntime
) noexcept;

/**
 * Address: 0x00962900 (FUN_00962900, wxLogDebug)
 *
 * What it does:
 * Preserves the wx debug-log call lane as a deliberate no-op.
 */
void wxLogDebug(...);

/**
 * Address: 0x009BB840 (FUN_009BB840)
 *
 * What it does:
 * Enables wx URL default-proxy mode when `HTTP_PROXY` is present.
 */
bool wxURLInitializeDefaultProxyFromEnvironment();

/**
 * Address: 0x009F2500 (FUN_009F2500)
 *
 * What it does:
 * Builds one timer-event payload from timer runtime lanes and dispatches it to
 * the bound event-handler lane.
 */
void wxDispatchTimerOwnerEvent(void* timerRuntime);

/**
 * Address: 0x009F2C40 (FUN_009F2C40)
 *
 * What it does:
 * Constructs one screen-DC runtime lane from window-DC base state, binds the
 * screen vtable tag, acquires the desktop DC, and sets transparent background
 * drawing mode.
 */
void* wxConstructScreenDCRuntime(void* screenDcRuntime) noexcept;

/**
 * Address: 0x009F2CA0 (FUN_009F2CA0)
 *
 * What it does:
 * Allocates one `0x118`-byte screen-DC runtime object and runs
 * `wxConstructScreenDCRuntime`; returns null when allocation fails.
 */
[[nodiscard]] void* wxAllocateScreenDCRuntime() noexcept;

/**
 * Address: 0x00A148E0 (FUN_00A148E0)
 *
 * What it does:
 * Builds one process-event payload, dispatches it through the source runtime,
 * and deletes the source lane when the event is unhandled.
 */
void wxDispatchProcessEventOrDelete(void* processEventSourceRuntime, int eventParam0, int eventParam1);

/**
 * Address: 0x00A38080 (FUN_00A38080)
 *
 * What it does:
 * Reserves one `WM_USER..WM_USER+0x3FF` socket-dispatch slot for the given
 * registration and stores the reserved message id into that registration.
 */
bool wxSocketAssignDispatchMessageSlot(void* socketRegistrationRuntime);

/**
 * Address: 0x00A118C0 (FUN_00A118C0)
 *
 * What it does:
 * Ensures the wx socket runtime lane is initialized, using first-call init
 * semantics with rollback on initialization failure.
 */
bool wxEnsureSocketRuntimeInitialized();

/**
 * Address: 0x00A28090 (FUN_00A28090, sub_A28090)
 *
 * What it does:
 * Allocates one socket-dispatch hash-table state block, initializes a
 * threshold-sized zeroed bucket lane, and stores it as the secondary runtime
 * socket-dispatch table.
 */
[[nodiscard]] std::uint32_t* wxSocketAllocateSecondaryDispatchHashTable();

/**
 * Address: 0x00A2DF10 (FUN_00A2DF10)
 *
 * What it does:
 * Constructs one `wxSocketEvent` payload by seeding base `wxEvent` lanes and
 * binding the socket-event dispatch vtable lane.
 */
void* wxConstructSocketEventRuntime(void* socketEventRuntime, std::int32_t eventId);

/**
 * Address: 0x00A2FF50 (FUN_00A2FF50)
 *
 * What it does:
 * Performs one socket writable-lane probe and writes runtime state `8`
 * (timeout) when the probe times out.
 */
int wxSocketWaitWritableRuntime(void* socketProbeRuntime);

/**
 * Address: 0x009ACEA0 (FUN_009ACEA0)
 *
 * What it does:
 * Closes one native Win32 handle lane when present.
 */
void* wxCloseNativeHandleIfPresentRuntime(void* nativeHandleStorage) noexcept;

/**
 * Address: 0x009ACF50 (FUN_009ACF50)
 *
 * What it does:
 * Closes one native Win32 handle lane when present (alternate call lane).
 */
void* wxCloseNativeHandleIfPresentRuntimeAlias(void* nativeHandleStorage) noexcept;

/**
 * Address: 0x00A27620 (FUN_00A27620)
 *
 * What it does:
 * Releases one loaded module handle lane and clears it to null.
 */
void* wxFreeLoadedModuleIfPresentRuntime(void* moduleHandleStorage) noexcept;

/**
 * Address: 0x009ED790 (FUN_009ED790)
 *
 * What it does:
 * Writes the vertical scroll thumb position through `SetScrollInfo` using the
 * runtime window handle lane.
 */
int wxSetVerticalScrollThumbPositionRuntime(void* scrollOwnerRuntime, int thumbPosition);

/**
 * Address: 0x004F4080 (FUN_004F4080)
 *
 * What it does:
 * Runs the managed-dialog destructor core and conditionally deletes the owning
 * object storage when `deleteFlags & 1`.
 */
void* wxDeleteManagedDialogRuntimeWithFlag(void* managedDialogRuntime, std::uint8_t deleteFlags) noexcept;

/**
 * Address: 0x004F4210 (FUN_004F4210)
 *
 * What it does:
 * Runs the managed-frame destructor core and conditionally deletes the owning
 * object storage when `deleteFlags & 1`.
 */
void* wxDeleteManagedFrameRuntimeWithFlag(void* managedFrameRuntime, std::uint8_t deleteFlags) noexcept;

/**
 * Address: 0x004F1570 (FUN_004F1570)
 *
 * What it does:
 * Rebinds one `wxObjectRefData` runtime payload to its base vtable lane
 * without deleting object storage.
 */
void* wxDestroyObjectRefDataNoDelete(void* objectRefDataRuntime) noexcept;

/**
 * Address: 0x004F1580 (FUN_004F1580)
 *
 * What it does:
 * Scalar deleting-dtor slot stored in `wxObjectRefData::vftable`. Rebinds the
 * payload to the base `wxObjectRefData` vtable lane (no virtual chained
 * teardown — wxObjectRefData adds no destructible state on its own) and, when
 * the low bit of `deleteFlags` is set, releases the object storage via
 * `operator delete`. Returns the same payload pointer.
 */
void* wxDeleteObjectRefDataBaseScalarRuntime(void* objectRefDataRuntime, std::uint8_t deleteFlags) noexcept;

/**
 * Address: 0x004F1630 (FUN_004F1630)
 *
 * What it does:
 * Implements the deleting-dtor thunk lane for one `wxObjectRefData` runtime
 * payload.
 */
void* wxDeleteObjectRefDataWithFlag(void* objectRefDataRuntime, std::uint8_t deleteFlags) noexcept;

/**
 * Address: 0x004F16D0 (FUN_004F16D0)
 *
 * What it does:
 * Alias construction lane for one `wxObjectRefData` runtime payload.
 */
void* wxConstructObjectRefDataBaseRuntimeAlias(void* objectRefDataRuntime) noexcept;

/**
 * Address: 0x004F1710 (FUN_004F1710)
 *
 * What it does:
 * Runs the base-construction lane for one `wxObjectRefData` runtime payload.
 */
void* wxConstructObjectRefDataBaseRuntime(void* objectRefDataRuntime) noexcept;

/**
 * Address: 0x004F17F0 (FUN_004F17F0)
 *
 * What it does:
 * Alias lane that forwards one wx-object base-teardown transition into the
 * shared vtable-reset/unref helper.
 */
void* wxConstructWxObjectBaseRuntimeAlias(void* objectRuntime) noexcept;

/**
 * Address: 0x004F19C0 (FUN_004F19C0)
 *
 * What it does:
 * Allocates one icon-refdata payload lane and initializes its shared wx GDI
 * refdata state.
 */
[[nodiscard]] void* wxAllocateIconRefDataRuntime() noexcept;

/**
 * Address: 0x00A017D0 (FUN_00A017D0)
 *
 * What it does:
 * Destroys the owned client-data payload lane inside one tree-item-indirect
 * data object and rebases the object to `wxClientData` runtime state.
 */
void* wxTreeItemIndirectDataDestroyNoDelete(void* treeItemIndirectDataRuntime) noexcept;

/**
 * Address: 0x009FB510 (FUN_009FB510)
 *
 * What it does:
 * Reads one status-bar pane text lane from the native HWND and stores it in
 * `outText`; invalid pane indices return an empty string.
 */
wxStringRuntime* wxGetStatusBarPaneText(
  const void* statusBarRuntime,
  wxStringRuntime* outText,
  std::int32_t paneIndex
);

/**
 * Address: 0x009690F0 (FUN_009690F0, wxWindow::HandleActivate)
 *
 * What it does:
 * Builds one activation event for `windowRuntime` and dispatches it through
 * the current event-handler lane.
 */
bool wxHandleWindowActivationEvent(
  void* windowRuntime,
  unsigned short activationState,
  bool minimized,
  unsigned int activatedNativeHandle
);

/**
 * Address: 0x009FBE70 (FUN_009FBE70)
 *
 * What it does:
 * Returns the currently active child window for one MDI parent runtime, or
 * `nullptr` when no child is active.
 */
void* wxFindActiveMdiChildWindow(const void* mdiParentRuntime);

/**
 * Address: 0x009FC010 (FUN_009FC010)
 *
 * What it does:
 * Forwards parent activation handling to base window activation, then
 * dispatches one activate event to the current active MDI child when present.
 */
bool wxHandleMdiParentActivation(
  void* mdiParentRuntime,
  unsigned short activationState,
  bool minimized,
  unsigned int activatedNativeHandle
);

/**
 * Address: 0x009FC740 (FUN_009FC740)
 *
 * What it does:
 * Synchronizes the MDI client extended-style border lane with the active
 * child maximize state and optionally reports client rect.
 */
bool wxSyncMdiClientEdgeStyle(
  void* mdiChildRuntime,
  void* outClientRect
);

/**
 * Address: 0x0099F260 (FUN_0099F260)
 *
 * What it does:
 * Routes one frame command through control HWND forwarding, popup-menu command
 * handling (for notification lanes `0/1`), then dispatches menu-selected
 * fallback events.
 */
bool wxHandleFrameCommandWithPopupMenu(
  void* frameRuntime,
  unsigned int commandId,
  unsigned short notificationCode,
  int controlHandle
);

/**
 * Address: 0x009A90D0 (FUN_009A90D0)
 *
 * What it does:
 * Builds and dispatches one `wxEVT_COMMAND_MENU_SELECTED` event for
 * `frameRuntime`, synchronizing checked/radio menu-item state lanes when the
 * resolved item is checkable.
 */
bool wxDispatchMenuSelectionCommandEvent(
  void* frameRuntime,
  unsigned short commandId
);

/**
 * Address: 0x009FC610 (FUN_009FC610)
 *
 * What it does:
 * Routes one frame command through control HWND forwarding, popup-menu command
 * handling, and menu-item lookup fallback before emitting menu-selected
 * command events.
 */
bool wxHandleFrameMenuCommand(
  void* frameRuntime,
  unsigned int commandId,
  unsigned short notificationCode,
  int controlHandle
);

/**
 * Address: 0x009FD0E0 (FUN_009FD0E0)
 *
 * What it does:
 * Handles one MDI parent command lane including built-in window-arrangement
 * commands, child activation by id range, and frame/menu fallback command
 * routing.
 */
bool wxHandleMdiParentMenuCommand(
  void* mdiParentRuntime,
  unsigned int commandId,
  unsigned short notificationCode,
  int controlHandle
);

/**
 * Address: 0x009FC6C0 (FUN_009FC6C0)
 *
 * What it does:
 * Forwards one child-frame `WM_GETMINMAXINFO` lane through default window
 * proc handling, then applies client-size override lanes into the incoming
 * `MINMAXINFO` payload when size hints are finite.
 */
bool wxHandleMdiChildGetMinMaxInfo(
  void* mdiChildRuntime,
  void* minMaxInfoRuntime
);

/**
 * Address: 0x009FCD30 (FUN_009FCD30)
 *
 * What it does:
 * Unpacks one `WM_MDIACTIVATE` lane into fixed activate-state `1`, activated
 * native handle, and deactivated native handle outputs.
 */
unsigned int* wxUnpackMdiActivateMessage(
  unsigned int deactivatedNativeHandle,
  unsigned int activatedNativeHandle,
  unsigned short* outActivationState,
  unsigned int* outActivatedNativeHandle,
  unsigned int* outDeactivatedNativeHandle
);

/**
 * Address: 0x009FD2A0 (FUN_009FD2A0)
 *
 * What it does:
 * Applies one MDI child activation transition, synchronizes parent
 * active-child/menu-routing lanes, updates MDI client menus, and dispatches
 * one activate event for the child runtime.
 */
bool wxHandleMdiChildActivationChange(
  void* mdiChildRuntime,
  unsigned short activationState,
  unsigned int activatedNativeHandle,
  unsigned int deactivatedNativeHandle
);

/**
 * Address: 0x009FD3D0 (FUN_009FD3D0)
 *
 * What it does:
 * Handles one child-frame `WM_WINDOWPOSCHANGING` lane by optionally
 * recalculating `WINDOWPOS` geometry from client-edge sync and maximizing
 * style, then updating parent MDI-client presentation lanes.
 */
bool wxHandleMdiChildWindowPosChanging(
  void* mdiChildRuntime,
  void* windowPosRuntime
);

/**
 * Address: 0x009FD5F0 (FUN_009FD5F0)
 *
 * What it does:
 * Routes one MDI parent frame window-proc lane for create/activate/command/
 * menu-select messages and forwards unhandled cases to base frame window-proc
 * behavior.
 */
long wxHandleMdiParentWindowProc(
  void* mdiParentRuntime,
  unsigned int message,
  unsigned int wParam,
  long lParam
);

/**
 * Address: 0x009FD810 (FUN_009FD810)
 *
 * What it does:
 * Routes one MDI child frame window-proc lane for command, activation,
 * minmax, and window-pos messages, and forwards unhandled cases to base frame
 * window-proc behavior.
 */
long wxHandleMdiChildWindowProc(
  void* mdiChildRuntime,
  unsigned int message,
  unsigned int wParam,
  long lParam
);

/**
 * Address: 0x009FC0F0 (FUN_009FC0F0)
 *
 * What it does:
 * Forwards one parent-frame default window-proc lane through `DefFrameProcW`
 * using the parent and MDI-client native handles.
 */
long wxMdiParentDefFrameWindowProc(
  void* mdiParentRuntime,
  unsigned int message,
  unsigned int wParam,
  long lParam
);

/**
 * Address: 0x009FC130 (FUN_009FC130)
 *
 * What it does:
 * Tries active-child and base-frame message translation, then falls back to
 * `TranslateMDISysAccel` for MDI key lanes.
 */
bool wxMdiParentTranslateMessage(
  void* mdiParentRuntime,
  void* nativeMessage
);

/**
 * Address: 0x009FC1A0 (FUN_009FC1A0)
 *
 * What it does:
 * Sets the post-construction runtime flag lane for one MDI child frame.
 */
void wxMdiChildMarkConstructed(void* mdiChildRuntime);

/**
 * Address: 0x009FC1B0 (FUN_009FC1B0)
 *
 * What it does:
 * Creates one MDI child native window from title/position/size/style lanes,
 * associates the created HWND with the child runtime, and tracks it as
 * modeless.
 */
bool wxMdiChildCreateWindow(
  void* mdiChildRuntime,
  void* mdiParentRuntime,
  std::int32_t windowId,
  const wxStringRuntime& title,
  const wxPoint& position,
  const wxSize& size,
  long style,
  const wxStringRuntime& name
);

/**
 * Address: 0x009FC500 (FUN_009FC500)
 *
 * What it does:
 * Resolves one child window origin from screen coordinates into MDI-client
 * client coordinates and writes `outX/outY`.
 */
long wxMdiChildGetClientOrigin(
  const void* mdiChildRuntime,
  long* outX,
  long* outY
);

/**
 * Address: 0x009FC560 (FUN_009FC560)
 *
 * What it does:
 * Returns the preferred MDI child-frame icon handle, falling back to the
 * default icon handle when no standard icon is configured.
 */
void* wxGetMdiChildFrameIconHandle();

/**
 * Address: 0x009FC570 (FUN_009FC570)
 *
 * What it does:
 * Sends one maximize or restore command (`WM_MDIMAXIMIZE`/`WM_MDIRESTORE`)
 * for the child through the parent MDI-client window.
 */
long wxMdiChildSendMaximizeCommand(
  void* mdiChildRuntime,
  bool maximize
);

/**
 * Address: 0x009FC5B0 (FUN_009FC5B0)
 *
 * What it does:
 * Sends one `WM_MDIRESTORE` lane for the child through the parent MDI-client
 * window.
 */
long wxMdiChildRestoreWindow(
  void* mdiChildRuntime
);

/**
 * Address: 0x009FC5E0 (FUN_009FC5E0)
 *
 * What it does:
 * Sends one `WM_MDIACTIVATE` lane for the child through the parent MDI-client
 * window.
 */
long wxMdiChildActivateWindow(
  void* mdiChildRuntime
);

/**
 * Address: 0x009FC710 (FUN_009FC710)
 *
 * What it does:
 * Forwards one child-frame default window-proc lane through
 * `DefMDIChildProcW`.
 */
long wxMdiChildDefFrameWindowProc(
  void* mdiChildRuntime,
  unsigned int message,
  unsigned int wParam,
  long lParam
);

/**
 * Address: 0x009FCD50 (FUN_009FCD50)
 *
 * What it does:
 * Runs non-deleting MDI parent-frame teardown and applies deleting-dtor thunk
 * semantics when `deleteFlags & 1`.
 */
void* wxDestroyMdiParentFrameWithDeleteFlag(
  void* mdiParentRuntime,
  std::uint8_t deleteFlags
) noexcept;

/**
 * Address: 0x009FCDB0 (FUN_009FCDB0)
 *
 * What it does:
 * Returns the static class-info table lane for wx MDI child frame RTTI.
 */
void* wxGetMdiChildFrameClassInfo() noexcept;

/**
 * Address: 0x009FCDE0 (FUN_009FCDE0)
 *
 * What it does:
 * Returns the static class-info table lane for wx MDI client-window RTTI.
 */
void* wxGetMdiClientWindowClassInfo() noexcept;

/**
 * Address: 0x009FCE00 (FUN_009FCE00)
 *
 * What it does:
 * Applies wx-window deleting-dtor thunk semantics for one MDI client-window
 * runtime lane.
 */
void* wxDestroyMdiClientWindowWithDeleteFlag(
  void* mdiClientRuntime,
  std::uint8_t deleteFlags
) noexcept;

/**
 * Address: 0x0099F680 (FUN_0099F680)
 *
 * What it does:
 * Initializes one frame runtime lane by running frame-base constructor/init
 * state transitions used by frame-derived constructors.
 */
void* wxConstructFrameRuntimeBase(
  void* frameRuntime
);

/**
 * Address: 0x009FB720 (FUN_009FB720)
 *
 * What it does:
 * Initializes one MDI parent-frame runtime lane from frame-base state and
 * seeds MDI parent pointers/flags.
 */
void* wxConstructMdiParentFrameRuntime(
  void* mdiParentRuntime
);

/**
 * Address: 0x009FCE20 (FUN_009FCE20)
 *
 * What it does:
 * Allocates and constructs one MDI parent-frame runtime object.
 */
void* wxAllocateAndConstructMdiParentFrameRuntime();

/**
 * Address: 0x009FCE90 (FUN_009FCE90)
 *
 * What it does:
 * Allocates and constructs one MDI child-frame runtime object.
 */
void* wxAllocateAndConstructMdiChildFrameRuntime();

/**
 * Address: 0x00962910 (FUN_00962910, wxLogTrace)
 *
 * What it does:
 * Preserves the wx trace-log call lane as a deliberate no-op.
 */
void wxLogTrace(...);

/**
 * Address: 0x00966E60 (FUN_00966E60, nullsub_3482)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackH();

/**
 * Address: 0x00966E70 (FUN_00966E70, nullsub_3483)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackI();

/**
 * Address: 0x00967010 (FUN_00967010, nullsub_3484)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1G(std::int32_t reservedArg0);

/**
 * Address: 0x00983420 (FUN_00983420, nullsub_3491)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1H(std::int32_t reservedArg0);

/**
 * Address: 0x00978200 (FUN_00978200, nullsub_3488)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackA();

/**
 * Address: 0x00999B70 (FUN_00999B70, nullsub_3495)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1(std::int32_t reservedArg0);

/**
 * Address: 0x009A8EE0 (FUN_009A8EE0, nullsub_3496)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackB();

/**
 * Address: 0x009AD4F0 (FUN_009AD4F0, nullsub_3501)
 *
 * What it does:
 * Preserves one `wxThread` vtable virtual lane as an intentional no-op.
 */
void wxThreadNoOpVirtualSlot();

/**
 * Address: 0x009C5EE0 (FUN_009C5EE0, nullsub_3505)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2A(std::int32_t reservedArg0, std::int32_t reservedArg1);

/**
 * Address: 0x009C5EF0 (FUN_009C5EF0, nullsub_3506)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2B(std::int32_t reservedArg0, std::int32_t reservedArg1);

/**
 * Address: 0x009C5F00 (FUN_009C5F00, nullsub_3507)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1B(std::int32_t reservedArg0);

/**
 * Address: 0x009C88E0 (FUN_009C88E0, nullsub_3509)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackC();

/**
 * Address: 0x009C88F0 (FUN_009C88F0, nullsub_3510)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackD();

/**
 * Address: 0x009C8900 (FUN_009C8900, nullsub_3511)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackE();

/**
 * Address: 0x009C9DE0 (FUN_009C9DE0, nullsub_3512)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackJ();

/**
 * Address: 0x009C9DF0 (FUN_009C9DF0, nullsub_3513)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackK();

/**
 * Address: 0x009C9E00 (FUN_009C9E00, nullsub_3514)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackL();

/**
 * Address: 0x009D2F00 (FUN_009D2F00, nullsub_3515)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackM();

/**
 * Address: 0x00A06BF0 (FUN_00A06BF0, nullsub_3517)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1C(std::int32_t reservedArg0);

/**
 * Address: 0x00A07DD0 (FUN_00A07DD0, nullsub_3518)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2C(std::int32_t reservedArg0, std::int32_t reservedArg1);

/**
 * Address: 0x00A0B3F0 (FUN_00A0B3F0, nullsub_3519)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1D(std::int32_t reservedArg0);

/**
 * Address: 0x00A0DC40 (FUN_00A0DC40, nullsub_3520)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackF();

/**
 * Address: 0x00A0E400 (FUN_00A0E400, nullsub_3521)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1I(std::int32_t reservedArg0);

/**
 * Address: 0x00A0E410 (FUN_00A0E410, nullsub_3522)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1J(std::int32_t reservedArg0);

/**
 * Address: 0x00A18DB0 (FUN_00A18DB0, nullsub_3523)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackG();

/**
 * Address: 0x00A20780 (FUN_00A20780, nullsub_8)
 *
 * What it does:
 * Preserves one runtime function-pointer dispatch lane as an intentional
 * no-op.
 */
void wxNoOpRuntimeDispatchSlot();

/**
 * Address: 0x00A13300 (FUN_00A13300)
 *
 * What it does:
 * Creates one inheritable anonymous pipe pair and stores read/write handles in
 * `pipeHandles`.
 */
[[nodiscard]] bool wxCreateAnonymousPipe(WxAnonymousPipeHandles* pipeHandles);

/**
 * Address: 0x009DE1E0 (FUN_009DE1E0)
 *
 * What it does:
 * Copies one filesystem file lane with Win32 `CopyFileW` overwrite semantics
 * and logs localized system errors on failure.
 */
[[nodiscard]] bool wxCopyFileRuntime(const wchar_t* sourcePath, const wchar_t* destinationPath, bool overwrite);

/**
 * Address: 0x009DE270 (FUN_009DE270)
 *
 * What it does:
 * Creates one filesystem directory lane and logs a localized system error if
 * creation fails.
 */
[[nodiscard]] bool wxCreateDirectoryRuntime(const wchar_t* directoryPath);

/**
 * Address: 0x009DDED0 (FUN_009DDED0)
 *
 * What it does:
 * Removes the trailing `.<ext>` lane from `pathText` when one extension
 * separator is present past the first code unit.
 */
void wxRemoveFileExtensionInPlace(wxStringRuntime* pathText);

/**
 * Address: 0x009DE3D0 (FUN_009DE3D0)
 *
 * What it does:
 * Builds one temporary-file path from `prefixText`, stores it in
 * `outFileName`, and returns whether the resulting output lane is non-empty.
 */
[[nodiscard]] bool wxCreateTempFileNameFromPrefix(const wxStringRuntime* prefixText, wxStringRuntime* outFileName);

/**
 * Address: 0x00A27140 (FUN_00A27140, nullsub_3525)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1F(std::int32_t reservedArg0);

/**
 * Address: 0x00A37F30 (FUN_00A37F30, nullsub_3526)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1E(std::int32_t reservedArg0);

/**
 * Address: 0x00A312A0 (FUN_00A312A0, sub_A312A0)
 *
 * What it does:
 * Formats one DDE error-code lane into a human-readable wx string payload.
 */
wxStringRuntime* wxFormatDdeErrorString(wxStringRuntime* outText, unsigned int ddeErrorCode);

/**
 * Address: 0x00962120 (FUN_00962120, wxString::Format)
 *
 * What it does:
 * Static `wxString::Format`: seeds `outValue` to the shared empty string then
 * formats the varargs into it. The retail signature returns `wxString` by
 * value, so the result comes back through the hidden first parameter.
 */
wxStringRuntime* wxStringFormat(wxStringRuntime* outValue, const wchar_t* formatText, ...);

/**
 * Address: 0x00968990 (FUN_00968990, wxYieldForCommandsOnly)
 *
 * What it does:
 * Pumps only `WM_COMMAND` messages from the thread queue and reposts quit
 * state when a `WM_QUIT` lane is encountered.
 */
void wxYieldForCommandsOnly();

/**
 * Address: 0x00992B90 (FUN_00992B90, wxEntryStart)
 *
 * What it does:
 * Runs the wx app initialization lane used by `wxEntry` startup.
 */
[[nodiscard]] bool wxEntryStart();

/**
 * Address: 0x00992020 (FUN_00992020, wxEntryInitGui)
 *
 * What it does:
 * Calls the wx app's `OnInitGui` virtual lane and forwards its success flag.
 */
[[nodiscard]] bool wxEntryInitGui();

/**
 * Address: 0x00991F80 (FUN_00991F80)
 *
 * What it does:
 * Unregisters wx canvas/MDI window classes from the process instance and
 * returns true only when every unregister call succeeds.
 */
[[nodiscard]] bool wxUnregisterWindowClasses();

/**
 * Address: 0x00992FE0 (FUN_00992FE0, wxEntryCleanup)
 *
 * What it does:
 * Runs the wx app cleanup lane used by `wxEntry` shutdown.
 */
void wxEntryCleanup();

/**
 * Address: 0x009BCDD0 (FUN_009BCDD0, wxDeleteStockLists)
 *
 * What it does:
 * Destroys global wx stock brush/pen/font/bitmap list singletons and resets
 * their runtime pointers.
 */
void wxDeleteStockLists();

/**
 * Address: 0x009C4860 (FUN_009C4860, wxSafeShowMessage)
 *
 * What it does:
 * Formats one fatal-log message into the wx runtime buffer lane and shows a
 * modal Win32 error message box titled `"Fatal Error"`.
 */
int wxSafeShowMessage(const wchar_t* formatText, va_list argList);

/**
 * Address: 0x009C4940 (FUN_009C4940, wxVLogFatalError)
 *
 * What it does:
 * Routes one variadic fatal-log message through `wxSafeShowMessage` and then
 * terminates the process via `abort()`.
 */
[[noreturn]] void wxVLogFatalError(wchar_t* formatText, ...);

/**
 * Address: 0x009C7BB0 (FUN_009C7BB0, wxBeginBusyCursor)
 *
 * What it does:
 * Increments busy-cursor nesting depth and, on first entry, swaps the active
 * Win32 cursor to the provided wx cursor handle (or null cursor when refdata
 * is absent), while saving the previous cursor lane.
 */
void wxBeginBusyCursor(wxCursor* cursor);

/**
 * Address: 0x009C7C00 (FUN_009C7C00, wxEndBusyCursor)
 *
 * What it does:
 * Decrements busy-cursor nesting depth and, on final release, restores the
 * previously saved Win32 cursor lane.
 */
HCURSOR wxEndBusyCursor();

/**
 * Address: 0x009C7D70 (FUN_009C7D70, wxColourDisplay)
 *
 * What it does:
 * Caches and returns whether the current display device reports color output.
 */
BOOL wxColourDisplay();

/**
 * Address: 0x009BCE40 (FUN_009BCE40, wxBitmapListInit)
 *
 * What it does:
 * Runs the stock wx bitmap-list constructor lane used by the global list
 * initializers.
 */
[[nodiscard]] wxBitmapListRuntime* wxBitmapListInit(wxBitmapListRuntime* object) noexcept;

/**
 * Address: 0x00976400 (FUN_00976400, wxCreateDIB)
 *
 * What it does:
 * Allocates one palette-backed DIB header block, seeds its metadata, and
 * converts the palette entries into bitmap color-table order for the caller.
 */
bool wxCreateDIB(
  std::int32_t xSize,
  std::int32_t ySize,
  std::int32_t bitsPerPixel,
  HPALETTE hpal,
  LPBITMAPINFO* lpDIBHeader
);

/**
 * Address: 0x009764C0 (FUN_009764C0, wxFreeDIB)
 *
 * What it does:
 * Releases one DIB header block previously allocated by `wxCreateDIB()`.
 */
void wxFreeDIB(void* ptr);

/**
 * Address: 0x009ECA00 (FUN_009ECA00)
 *
 * What it does:
 * Builds one Win32 palette/bitmap pair from global DIB memory and writes both
 * output handles when bitmap creation succeeds.
 */
bool wxCreateBitmapFromGlobalDib(
  HDC deviceContext,
  HGLOBAL dibGlobalHandle,
  HPALETTE* outPalette,
  HBITMAP* outBitmap
);

/**
 * Address: 0x009C6900 (FUN_009C6900, wxRGBToColour)
 *
 * What it does:
 * Initializes one `wxColourRuntime` from packed `0x00BBGGRR` RGB bytes and
 * returns the output pointer.
 */
wxColourRuntime* wxRGBToColour(wxColourRuntime* outColour, std::uint32_t packedRgb);

namespace wx
{
  /**
   * Address: 0x009CD1D0 (FUN_009CD1D0, wx::copystring)
   *
   * What it does:
   * Allocates and returns one heap-owned wide-string copy, treating `nullptr`
   * as an empty string source.
   */
  [[nodiscard]] wchar_t* copystring(const wchar_t* text);
}

/**
 * Address: 0x009CD480 (FUN_009CD480)
 *
 * What it does:
 * Formats one byte into uppercase two-digit UTF-16 hex and stores it in
 * `outText`.
 */
wxStringRuntime* wxBuildUpperHexByteStringRuntime(wxStringRuntime* outText, int byteValue);

// One row of a wx event table: which event type, which id or id range, and the
// handler to call. Layout read off wxEvtHandler::SearchEventTable (0x00979900):
// the stride is 0x14 (lea esi*5 scaled by 4 at 0x00979976) and m_fn at +8
// terminates the table when null.
struct wxEventTableEntry
{
  std::int32_t m_id;               // +0x00 single id, or range start
  std::int32_t m_lastId;           // +0x04 range end; -1 when not a range
  void* m_fn;                      // +0x08 handler; null ends the table
  void* m_callbackUserData;        // +0x0C copied onto the event before dispatch
  const std::int32_t* m_eventType; // +0x10 by pointer, so ids can be assigned at startup
};
static_assert(offsetof(wxEventTableEntry, m_id) == 0x00, "wxEventTableEntry::m_id offset must be 0x00");
static_assert(offsetof(wxEventTableEntry, m_lastId) == 0x04, "wxEventTableEntry::m_lastId offset must be 0x04");
static_assert(offsetof(wxEventTableEntry, m_fn) == 0x08, "wxEventTableEntry::m_fn offset must be 0x08");
static_assert(
  offsetof(wxEventTableEntry, m_callbackUserData) == 0x0C,
  "wxEventTableEntry::m_callbackUserData offset must be 0x0C"
);
static_assert(offsetof(wxEventTableEntry, m_eventType) == 0x10, "wxEventTableEntry::m_eventType offset must be 0x10");
static_assert(sizeof(wxEventTableEntry) == 0x14, "wxEventTableEntry size must be 0x14");

// A class's event table, chained to its base class's.
struct wxEventTable
{
  const wxEventTable* baseTable;    // +0x00
  const wxEventTableEntry* entries; // +0x04
};
static_assert(offsetof(wxEventTable, baseTable) == 0x00, "wxEventTable::baseTable offset must be 0x00");
static_assert(offsetof(wxEventTable, entries) == 0x04, "wxEventTable::entries offset must be 0x04");
static_assert(sizeof(wxEventTable) == 0x08, "wxEventTable size must be 0x08");

/**
 * A region - an arbitrary shape, used here for the part of a window that
 * needs repainting.
 *
 * Same shared-handle shape as wxPalette and wxCursor: the native handle lives
 * in reference data so copies name one region rather than duplicating it.
 * Offsets from the constructor at 0x0097BB30, which allocates twelve bytes of
 * reference data, sets its count to one and stores the handle at +0x08.
 */
struct wxRegionRefDataRuntime
{
  void* mVTable = nullptr;      // +0x00
  std::int32_t mRefCount = 0;   // +0x04
  void* mNativeRegion = nullptr; // +0x08
};

static_assert(
  offsetof(wxRegionRefDataRuntime, mNativeRegion) == 0x08,
  "wxRegionRefDataRuntime::mNativeRegion offset must be 0x08"
);

struct wxRegionRuntime
{
  void* mVTable = nullptr;                    // +0x00
  wxRegionRefDataRuntime* mRefData = nullptr; // +0x04
  std::uint8_t mReserved08[0x4]{};            // +0x08

  [[nodiscard]] void* GetNativeRegion() const noexcept
  {
    return mRefData != nullptr ? mRefData->mNativeRegion : nullptr;
  }
};

static_assert(offsetof(wxRegionRuntime, mRefData) == 0x04, "wxRegionRuntime::mRefData offset must be 0x04");
static_assert(sizeof(wxRegionRuntime) == 0xC, "wxRegionRuntime size must be 0xC");

/**
 * A logical palette.
 *
 * The native handle lives in the shared reference data rather than in the
 * object, so copies of a palette share one HPALETTE. Offsets are off
 * wxWindow::HandleQueryNewPalette (0x00969A20), which reads the reference
 * data at +0x04 and the handle at +0x08 within it - the decompiler renders
 * that second step as an array subscript and gets the offset wrong.
 */
struct wxPaletteRefDataRuntime
{
  void* mVTable = nullptr;        // +0x00
  std::int32_t mRefCount = 0;     // +0x04
  void* mNativePalette = nullptr; // +0x08
};

static_assert(
  offsetof(wxPaletteRefDataRuntime, mNativePalette) == 0x08,
  "wxPaletteRefDataRuntime::mNativePalette offset must be 0x08"
);

struct wxPaletteRuntime
{
  void* mVTable = nullptr;                    // +0x00
  wxPaletteRefDataRuntime* mRefData = nullptr; // +0x04
  std::uint8_t mReserved08[0x4]{};            // +0x08

  /**
   * Address: swaps the handle the reference data holds and hands back what
   * was there, which is how the select/realize pair keeps hold of the palette
   * it displaced.
   */
  void* ExchangeNativePalette(void* nativePalette) noexcept;

  [[nodiscard]] void* GetNativePalette() const noexcept
  {
    return mRefData != nullptr ? mRefData->mNativePalette : nullptr;
  }

  // Whether this names a real palette - reference data with a handle in it.
  [[nodiscard]] bool Ok() const noexcept
  {
    return mRefData != nullptr && mRefData->mNativePalette != nullptr;
  }
};

static_assert(offsetof(wxPaletteRuntime, mRefData) == 0x04, "wxPaletteRuntime::mRefData offset must be 0x04");
static_assert(sizeof(wxPaletteRuntime) == 0xC, "wxPaletteRuntime size must be 0xC");

class wxHashTableRuntime;


class wxWindowBase;

/**
 * The application-global source of context-sensitive help.
 *
 * Mangled: ?ms_helpProvider@wxHelpProvider@@0PAV1@A (0x00FB29D4)
 *
 * What it does:
 * wxWindows never creates a provider on demand - an application installs one
 * or there is none - which is why every user of it tests the global first.
 * Set and Get are inline statics rather than virtuals, so they take no vtable
 * slot; that is why the binary reads the global directly at each of its nine
 * reference sites instead of calling an accessor.
 *
 * The slot order below is the binary's and has to stay: OnHelp (0x00964100)
 * dispatches through virtual +4, the second slot, which is where declaring
 * GetHelp first and ShowHelp second puts it. The destructor is declared last,
 * as wxWindows declares it, so it takes the final slot rather than the first.
 */
class wxHelpProvider
{
public:
  static wxHelpProvider* Set(wxHelpProvider* const helpProvider)
  {
    wxHelpProvider* const previous = ms_helpProvider;
    ms_helpProvider = helpProvider;
    return previous;
  }

  [[nodiscard]] static wxHelpProvider* Get() { return ms_helpProvider; }

  virtual wxStringRuntime GetHelp(const wxWindowBase* window) = 0;
  virtual bool ShowHelp(wxWindowBase* window) = 0;
  virtual void AddHelp(wxWindowBase* window, const wxStringRuntime& text);
  virtual void AddHelp(int id, const wxStringRuntime& text);
  virtual void RemoveHelp(wxWindowBase* window);
  virtual ~wxHelpProvider();

private:
  static wxHelpProvider* ms_helpProvider;
};

class wxWindowBase
{
public:
  /**
   * Address: 0x0042B770 (FUN_0042B770)
   * Mangled: ?GetClassInfo@wxWindowBase@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxWindowBase runtime RTTI checks.
   */
  virtual void* GetClassInfo() const;
  virtual void DeleteObject() {}
  virtual void* CreateRefData() const { return nullptr; }
  virtual void* CloneRefData(const void* sourceRefData) const
  {
    (void)sourceRefData;
    return nullptr;
  }
  /**
   * Address: 0x0097AF30 (FUN_0097AF30)
   * Mangled: ?ProcessEvent@wxEvtHandler@@UAE_NAAVwxEvent@@@Z
   *
   * What it does:
   * Offers an event to everything that could handle it, in wx's order: dynamic
   * bindings, this class's static event table and every base-class table behind
   * it, the next handler in the chain, then the application object.
   */
  virtual bool ProcessEvent(void* event);

  /**
   * What it does:
   * The handler events are offered to: this window, unless another handler has
   * been pushed in front of it.
   */
  [[nodiscard]] wxWindowBase* GetEventHandler();

  /**
   * Address: 0x00964100 (FUN_00964100)
   * Mangled: ?OnHelp@wxWindowBase@@IAEXAAVwxHelpEvent@@@Z
   *
   * IDA signature:
   * int __thiscall wxWindowBase::OnHelp(wxWindowBase *this, int event);
   *
   * What it does:
   * Offers the help request to the installed help provider, and skips the
   * event when there is no provider or the provider had nothing to show, so
   * that a parent window still gets its turn.
   */
  void OnHelp(wxEventRuntime& helpEvent);

  /**
   * Address: 0x00979900 (FUN_00979900)
   * Mangled: ?SearchEventTable@wxEvtHandler@@UAE_NAAUwxEventTable@@AAVwxEvent@@@Z
   *
   * What it does:
   * Looks for a handler in one table, matching on event type and id range.
   */
  virtual bool SearchEventTable(void* eventTable, void* event);

  /**
   * Address: 0x00964A50 (FUN_00964A50)
   * Mangled: ?GetEventTable@wxWindowBase@@MBEPBUwxEventTable@@XZ
   *
   * What it does:
   * Hands back the table at the root of every window's chain.
   */
  [[nodiscard]] virtual const void* GetEventTable() const;

  /**
   * Address: 0x00964A10 (FUN_00964A10)
   * Mangled: ?OnInitDialog@wxWindowBase@@IAEXAAVwxInitDialogEvent@@@Z
   *
   * IDA signature:
   * void __thiscall wxWindowBase::OnInitDialog(wxWindowBase *this, wxInitDialogEvent *event);
   *
   * What it does:
   * Pushes the values behind a dialog into the controls showing them, which is
   * what makes a dialog come up filled in.
   */
  void OnInitDialog(wxEventRuntime& initDialogEvent);

  /**
   * Address: 0x00964960 (FUN_00964960)
   * Mangled: ?OnSysColourChanged@wxWindowBase@@IAEXAAVwxSysColourChangedEvent@@@Z
   *
   * IDA signature:
   * void __thiscall wxWindowBase::OnSysColourChanged(wxWindowBase *this,
   *                                                  wxSysColourChangedEvent *event);
   *
   * What it does:
   * Passes a system-colour change down to every child that is not a top-level
   * window in its own right.
   */
  void OnSysColourChanged(wxEventRuntime& sysColourChangedEvent);

  static wxEventTable sm_eventTable;
  virtual void DoSetClientObject(void* clientObject) { (void)clientObject; }
  virtual void* DoGetClientObject() const { return nullptr; }
  virtual void DoSetClientData(void* clientData) { (void)clientData; }
  virtual void* DoGetClientData() const { return nullptr; }

  /**
   * Address: 0x00963210
   * Mangled: ?Destroy@wxWindowBase@@UAE_NXZ
   */
  virtual bool Destroy() { return false; }

  /**
   * Address: 0x00963220 (FUN_00963220)
   * Mangled: ?Close@wxWindowBase@@QAE_N_N@Z
   *
   * IDA signature:
   * char __thiscall wxWindowBase::Close(wxWindowBase *this, bool force);
   *
   * What it does:
   * Asks the window to close by raising wxEVT_CLOSE_WINDOW at its event
   * handler, and reports whether the close should go ahead. `force` suppresses
   * the handler's right to veto. Raising the event is all this does - actually
   * destroying the window is the handler's business.
   */
  bool Close(bool force = false);
  /**
   * Address: 0x0042B3E0 (FUN_0042B3E0)
   * Mangled: ?SetTitle@wxWindowBase@@UAEXPBG@Z
   *
   * What it does:
   * Base implementation accepts but ignores title updates.
   */
  virtual void SetTitle(const wxStringRuntime& title);

  /**
   * Address: 0x0042B3F0 (FUN_0042B3F0)
   * Mangled: ?GetTitle@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Returns an empty runtime wx string for base windows.
   */
  [[nodiscard]] virtual wxStringRuntime GetTitle() const;
  /**
   * Address: 0x0042B420 (FUN_0042B420)
   * Mangled: ?SetLabel@wxWindowBase@@UAEXABVwxString@@@Z
   *
   * What it does:
   * Forwards label updates to `SetTitle`.
   */
  virtual void SetLabel(const wxStringRuntime& label);

  /**
   * Address: 0x0042B430 (FUN_0042B430)
   * Mangled: ?GetLabel@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Forwards label reads to `GetTitle`.
   */
  [[nodiscard]] virtual wxStringRuntime GetLabel() const;

  /**
   * Address: 0x0042B450 (FUN_0042B450)
   * Mangled: ?SetName@wxWindowBase@@UAEXABVwxString@@@Z
   *
   * What it does:
   * Stores one runtime window-name value.
   */
  virtual void SetName(const wxStringRuntime& name);

  /**
   * Address: 0x0042B460 (FUN_0042B460)
   * Mangled: ?GetName@wxWindowBase@@UBE?AVwxString@@XZ
   *
   * What it does:
   * Returns the current runtime window-name value.
   */
  [[nodiscard]] virtual wxStringRuntime GetName() const;

  /**
   * Address: 0x00967200 (FUN_00967200)
   * Mangled: ?GetBackgroundColour@wxWindowBase@@QBE?AVwxColour@@XZ
   *
   * What it does:
   * Returns one copy of the current window background-colour runtime lane.
   */
  [[nodiscard]] wxColourRuntime GetBackgroundColour() const;

  virtual void Raise() {}
  virtual void Lower() {}
  /**
   * Address: 0x00963540 (FUN_00963540)
   * Mangled: ?GetClientAreaOrigin@wxWindowBase@@UBE?AVwxPoint@@XZ
   *
   * What it does:
   * Returns the default client-area origin `(0, 0)` for base window lanes.
   */
  [[nodiscard]] virtual wxPoint GetClientAreaOrigin() const;
  virtual void Fit() {}
  virtual void FitInside() {}
  /**
   * Address: 0x00963560
   * Mangled: ?SetSizeHints@wxWindowBase@@UAEXHHHHHH@Z
   */
  virtual void SetSizeHints(
    std::int32_t minWidth,
    std::int32_t minHeight,
    std::int32_t maxWidth,
    std::int32_t maxHeight,
    std::int32_t incWidth,
    std::int32_t incHeight
  )
  {
    (void)minWidth;
    (void)minHeight;
    (void)maxWidth;
    (void)maxHeight;
    (void)incWidth;
    (void)incHeight;
  }
  virtual void SetVirtualSizeHints(
    std::int32_t minWidth, std::int32_t minHeight, std::int32_t maxWidth, std::int32_t maxHeight
  )
  {
    (void)minWidth;
    (void)minHeight;
    (void)maxWidth;
    (void)maxHeight;
  }
  /**
   * Address: 0x0042B4F0 (FUN_0042B4F0)
   * Mangled: ?GetMinWidth@wxWindowBase@@UBEHXZ
   */
  [[nodiscard]] virtual std::int32_t GetMinWidth() const;

  /**
   * Address: 0x0042B500 (FUN_0042B500)
   * Mangled: ?GetMinHeight@wxWindowBase@@UBEHXZ
   */
  [[nodiscard]] virtual std::int32_t GetMinHeight() const;

  /**
   * Address: 0x0042B510 (FUN_0042B510)
   * Mangled: ?GetMaxSize@wxWindowBase@@UBE?AVwxSize@@XZ
   */
  [[nodiscard]] virtual wxSize GetMaxSize() const;
  virtual void DoSetVirtualSize(std::int32_t width, std::int32_t height)
  {
    (void)width;
    (void)height;
  }
  virtual wxSize DoGetVirtualSize() const { return wxSize{}; }

  /**
   * Address: 0x0042B4A0 (FUN_0042B4A0)
   *
   * What it does:
   * Returns client size by forwarding to `DoGetClientSize`.
   */
  [[nodiscard]] wxSize GetClientSize() const;

  /**
   * Address: 0x0042B4D0 (FUN_0042B4D0)
   *
   * What it does:
   * Returns best size by forwarding to `DoGetBestSize`.
   */
  [[nodiscard]] wxSize GetBestSize() const;

  /**
   * Address: 0x0042B530 (FUN_0042B530)
   * Mangled: ?GetBestVirtualSize@wxWindowBase@@UBE?AVwxSize@@XZ
   */
  [[nodiscard]] virtual wxSize GetBestVirtualSize() const;

  /**
   * Address: 0x00963660 (FUN_00963660)
   * Mangled: ?Show@wxWindowBase@@UAE_N_N@Z
   *
   * What it does:
   * Toggles the base visibility bit in window runtime state and reports
   * whether the visibility lane changed.
   */
  virtual bool Show(bool show);

  /**
   * Address: 0x009636A0 (FUN_009636A0)
   * Mangled: ?Enable@wxWindowBase@@UAE_N_N@Z
   *
   * What it does:
   * Toggles the base enabled bit in window runtime state and reports whether
   * the enabled lane changed.
   */
  virtual bool Enable(bool enable);
  /**
   * Address: 0x0042B5B0 (FUN_0042B5B0)
   * Mangled: ?SetWindowStyleFlag@wxWindowBase@@UAEXJ@Z
   */
  virtual void SetWindowStyleFlag(long style);

  /**
   * Address: 0x0042B5C0 (FUN_0042B5C0)
   * Mangled: ?GetWindowStyleFlag@wxWindowBase@@UBEJXZ
   */
  [[nodiscard]] virtual long GetWindowStyleFlag() const;

  /**
   * Address: 0x0042B5F0 (FUN_0042B5F0)
   * Mangled: ?IsRetained@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool IsRetained() const;

  /**
   * Address: 0x0042B600 (FUN_0042B600)
   * Mangled: ?SetExtraStyle@wxWindowBase@@UAEXJ@Z
   */
  virtual void SetExtraStyle(long style);
  virtual void MakeModal(bool modal) { (void)modal; }
  /**
   * Address: 0x0042B610 (FUN_0042B610)
   * Mangled: ?SetThemeEnabled@wxWindowBase@@UAEX_N@Z
   */
  virtual void SetThemeEnabled(bool enabled);

  /**
   * Address: 0x0042B620 (FUN_0042B620)
   * Mangled: ?GetThemeEnabled@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool GetThemeEnabled() const;

  /**
   * Address: 0x00967650 (FUN_00967650, wxWindow::SetFocus)
   * Mangled: ?SetFocus@wxWindow@@UAEXXZ
   *
   * What it does:
   * Hands the Win32 keyboard focus to this window's own HWND.
   */
  virtual void SetFocus();
  /**
   * Address: 0x0042B630 (FUN_0042B630)
   * Mangled: ?SetFocusFromKbd@wxWindowBase@@UAEXXZ
   */
  virtual void SetFocusFromKbd();

  /**
   * Address: 0x0042B640 (FUN_0042B640)
   * Mangled: ?AcceptsFocus@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool AcceptsFocus() const;

  /**
   * Address: 0x0042B660 (FUN_0042B660)
   * Mangled: ?AcceptsFocusFromKeyboard@wxWindowBase@@UBE_NXZ
   */
  [[nodiscard]] virtual bool AcceptsFocusFromKeyboard() const;

  /**
   * Address: 0x0042B670 (FUN_0042B670)
   * Mangled: ?GetDefaultItem@wxWindowBase@@UBEPAVwxWindow@@XZ
   */
  [[nodiscard]] virtual void* GetDefaultItem() const;
  /**
   * Address: 0x0042B680 (FUN_0042B680)
   * Mangled: ?SetDefaultItem@wxWindowBase@@UAEPAVwxWindow@@PAV2@@Z
   */
  virtual void* SetDefaultItem(void* defaultItem);

  /**
   * Address: 0x0042B690 (FUN_0042B690)
   * Mangled: ?SetTmpDefaultItem@wxWindowBase@@UAEXPAVwxWindow@@@Z
   */
  virtual void SetTmpDefaultItem(void* defaultItem);
  virtual bool IsTopLevel() const { return false; }
  virtual bool Reparent(wxWindowBase* parent)
  {
    (void)parent;
    return false;
  }
  /**
   * Address: 0x009636F0 (FUN_009636F0)
   * Mangled: ?AddChild@wxWindowBase@@UAEXPAV1@@Z
   *
   * IDA signature:
   * wxObjectListNode *__thiscall wxWindowBase::AddChild(wxWindowBase *this, wxWindowBase *child);
   *
   * What it does:
   * Takes a window into this one's child list and points it back at its new
   * parent. Both halves had been missing, so the hierarchy had no downward
   * links at all.
   */
  virtual void AddChild(wxWindowBase* child);

  /**
   * Address: 0x00963710 (FUN_00963710)
   * Mangled: ?RemoveChild@wxWindowBase@@UAEXPAV1@@Z
   *
   * IDA signature:
   * char __thiscall wxWindowBase::RemoveChild(wxWindowBase *this, wxWindowBase *child);
   *
   * What it does:
   * Drops a window from this one's child list and orphans it.
   */
  virtual void RemoveChild(wxWindowBase* child);

  /**
   * The windows parented to this one, in the order they were added.
   */
  [[nodiscard]] std::span<wxWindowBase* const> GetChildren() const;
  virtual void SetValidator(const void* validator) { (void)validator; }
  virtual void* GetValidator() { return nullptr; }
  virtual bool Validate() { return false; }
  virtual bool TransferDataToWindow() { return false; }
  virtual bool TransferDataFromWindow() { return false; }
  virtual void InitDialog() {}
  virtual void SetAcceleratorTable(const void* acceleratorTable) { (void)acceleratorTable; }
  virtual void WarpPointer(std::int32_t x, std::int32_t y)
  {
    (void)x;
    (void)y;
  }
  /**
   * Address: 0x0042B6E0 (FUN_0042B6E0)
   * Mangled: ?HasCapture@wxWindowBase@@UBE_NXZ
   */
  virtual bool HasCapture() const;

  /**
   * What it does:
   * Returns the current runtime capture owner window, when tracked.
   */
  [[nodiscard]] static wxWindowBase* GetCapture();

  /**
   * Address: 0x0096C050 (FUN_0096C050)
   * Mangled: ?FindFocus@wxWindowBase@@SAPAVwxWindow@@XZ
   *
   * What it does:
   * The window that currently has the keyboard focus, or nothing when the
   * focused window is not one of ours.
   */
  [[nodiscard]] static wxWindowBase* FindFocus();

  /**
   * Address: 0x00977C90 (FUN_00977C90)
   * Mangled: ?IsKindOf@wxObject@@QBE_NPBVwxClassInfo@@@Z
   *
   * What it does:
   * Whether this object is the class being asked about, or something derived
   * from it.
   */
  [[nodiscard]] bool IsKindOf(const wxClassInfo* info) const;

  /**
   * Address: 0x009654A0 (FUN_009654A0)
   * Mangled: ?UpdateWindowUI@wxWindowBase@@UAEXXZ
   *
   * What it does:
   * Asks whatever is watching this window how it should currently look, and
   * applies whichever of enabled, text and checked it was told about.
   */
  virtual void UpdateWindowUI();


  /**
   * Address: 0x00964CA0 (FUN_00964CA0)
   * Mangled: ?CaptureMouse@wxWindowBase@@QAEXXZ
   *
   * What it does:
   * Releases any previously captured window, pushes that window onto the
   * capture-history lane, then requests capture for this window.
   */
  void CaptureMouse();

  /**
   * Address: 0x00968350 (FUN_00968350)
   * Mangled: ?Refresh@wxWindow@@UAEX_NPBVwxRect@@@Z
   *
   * IDA signature:
   * BOOL __thiscall wxWindow::Refresh(wxWindow *this, bool a2,
   *                                   const struct wxRect *a3);
   *
   * What it does:
   * Marks this window's area as needing a repaint. A null `updateRect`
   * invalidates the whole client area; otherwise only the given rectangle is
   * invalidated. `eraseBackground` decides whether Windows also raises
   * WM_ERASEBKGND for the invalidated region.
   *
   * This is the engine's frame trigger: CScApp::Main calls
   * CD3DDevice::Refresh once per frame, which lands here on the viewport, and
   * the resulting WM_PAINT is the only thing that ever reaches
   * WD3DViewport::OnPaint -> CD3DDevice::Paint.
   */
  virtual void Refresh(bool eraseBackground, const wxRect* updateRect);
  /**
   * Address: 0x0042B700 (FUN_0042B700)
   */
  virtual void Update();
  virtual void Clear() {}
  /**
   * Address: 0x0042B710 (FUN_0042B710)
   */
  virtual void Freeze();
  /**
   * Address: 0x0042B720 (FUN_0042B720)
   */
  virtual void Thaw();
  /**
   * Address: 0x0042B730 (FUN_0042B730)
   * Mangled: ?PrepareDC@wxWindowBase@@UAEXAAVwxDC@@@Z
   */
  virtual void PrepareDC(void* deviceContext);
  virtual bool SetBackgroundColour(const void* colour)
  {
    (void)colour;
    return false;
  }
  virtual bool SetForegroundColour(const void* colour)
  {
    (void)colour;
    return false;
  }
  virtual bool SetCursor(const void* cursor)
  {
    (void)cursor;
    return false;
  }
  virtual bool SetFont(const void* font)
  {
    (void)font;
    return false;
  }
  virtual std::int32_t GetCharHeight() const { return 0; }
  virtual std::int32_t GetCharWidth() const { return 0; }
  virtual void GetTextExtent(
    const void* text,
    std::int32_t* outWidth,
    std::int32_t* outHeight,
    std::int32_t* outDescent,
    std::int32_t* outExternalLeading,
    const void* font
  ) const
  {
    (void)text;
    (void)font;
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
    if (outDescent != nullptr) {
      *outDescent = 0;
    }
    if (outExternalLeading != nullptr) {
      *outExternalLeading = 0;
    }
  }
  virtual void SetScrollbar(
    std::int32_t orientation,
    std::int32_t position,
    std::int32_t thumbSize,
    std::int32_t range,
    bool refresh
  )
  {
    (void)orientation;
    (void)position;
    (void)thumbSize;
    (void)range;
    (void)refresh;
  }
  virtual void SetScrollPos(std::int32_t orientation, std::int32_t position, bool refresh)
  {
    (void)orientation;
    (void)position;
    (void)refresh;
  }
  virtual std::int32_t GetScrollPos(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual std::int32_t GetScrollThumb(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual std::int32_t GetScrollRange(std::int32_t orientation) const
  {
    (void)orientation;
    return 0;
  }
  virtual void ScrollWindow(std::int32_t dx, std::int32_t dy, const void* rect)
  {
    (void)dx;
    (void)dy;
    (void)rect;
  }
  /**
   * Address: 0x0042B740 (FUN_0042B740)
   */
  virtual bool ScrollLines(std::int32_t lines);
  /**
   * Address: 0x0042B750 (FUN_0042B750)
   */
  virtual bool ScrollPages(std::int32_t pages);
  virtual void SetDropTarget(void* dropTarget);
  /**
   * Address: 0x0042B760 (FUN_0042B760)
   * Mangled: ?GetDropTarget@wxWindowBase@@UBEPAVwxDropTarget@@XZ
   */
  virtual void* GetDropTarget() const;
  virtual void SetConstraintSizes(bool recurse) { (void)recurse; }
  virtual bool LayoutPhase1(std::int32_t* flags)
  {
    (void)flags;
    return false;
  }
  virtual bool LayoutPhase2(std::int32_t* flags)
  {
    (void)flags;
    return false;
  }
  virtual bool DoPhase(std::int32_t phase)
  {
    (void)phase;
    return false;
  }
  virtual void SetSizeConstraint(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height)
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }
  virtual void MoveConstraint(std::int32_t x, std::int32_t y)
  {
    (void)x;
    (void)y;
  }
  virtual void GetSizeConstraint(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual void GetClientSizeConstraint(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual void GetPositionConstraint(std::int32_t* outX, std::int32_t* outY) const
  {
    if (outX != nullptr) {
      *outX = 0;
    }
    if (outY != nullptr) {
      *outY = 0;
    }
  }
  virtual bool Layout() { return false; }
  /**
   * Address: 0x0042B820 (FUN_0042B820)
   * Mangled: ?GetHandle@wxWindow@@UBEKXZ
   *
   * What it does:
   * Returns the native window handle, which the binary keeps in
   * wxWindow::m_hWnd at +0x108.
   */
  [[nodiscard]] virtual unsigned long GetHandle() const;

  /**
   * Address: 0x00963190 (FUN_00963190)
   * Mangled: ?CreateBase@wxWindowBase@@IAE_NPAVwxWindow@@HABVwxPoint@@ABVwxSize@@JABVwxValidator@@ABVwxString@@@Z
   *
   * What it does:
   * Fills in the platform-independent window state shared by every wx window:
   * id, name, style, parent, and the inheritable extra-style flag.
   */
  bool CreateBase(
    wxWindowBase* parent,
    std::int32_t id,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );
  virtual std::int32_t GetDefaultBorder() const { return 0; }
  virtual void DoClientToScreen(std::int32_t* x, std::int32_t* y) const
  {
    (void)x;
    (void)y;
  }
  virtual void DoScreenToClient(std::int32_t* x, std::int32_t* y) const
  {
    (void)x;
    (void)y;
  }
  virtual std::int32_t DoHitTest(std::int32_t x, std::int32_t y) const
  {
    (void)x;
    (void)y;
    return 0;
  }
  virtual void DoCaptureMouse() {}
  /**
   * Address: 0x00967930 (FUN_00967930)
   * Mangled: ?DoReleaseMouse@wxWindow@@MAEXXZ
   *
   * What it does:
   * Releases the current Win32 mouse capture lane.
   */
  virtual void DoReleaseMouse();
  virtual void DoGetPosition(std::int32_t* x, std::int32_t* y) const
  {
    if (x != nullptr) {
      *x = 0;
    }
    if (y != nullptr) {
      *y = 0;
    }
  }
  virtual void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }

  /**
   * Address: 0x0042B6B0 / 0x0098D180 family
   * Mangled (window/frame overrides):
   * - ?DoGetClientSize@wxWindow@@MBEXPAH0@Z
   * - ?DoGetClientSize@wxFrame@@MBEXPAH0@Z
   */
  virtual void DoGetClientSize(std::int32_t* outWidth, std::int32_t* outHeight) const
  {
    if (outWidth != nullptr) {
      *outWidth = 0;
    }
    if (outHeight != nullptr) {
      *outHeight = 0;
    }
  }
  virtual wxSize DoGetBestSize() const { return wxSize{}; }
  virtual void DoSetSize(
    std::int32_t x,
    std::int32_t y,
    std::int32_t width,
    std::int32_t height,
    std::int32_t sizeFlags
  )
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)sizeFlags;
  }

  /**
   * Address: 0x0042B6A0 / 0x0098D110 family
   * Mangled (window/frame overrides):
   * - ?DoSetClientSize@wxWindow@@MAEXHH@Z
   * - ?DoSetClientSize@wxFrame@@MAEXHH@Z
   */
  virtual void DoSetClientSize(std::int32_t width, std::int32_t height)
  {
    (void)width;
    (void)height;
  }
};

class wxWindowMswRuntime : public wxWindowBase
{
public:
  /**
   * Address: 0x00965730 (FUN_00965730, wxWindowBase::~wxWindowBase)
   * Mangled: ??1wxWindowBase@@UAE@XZ
   *
   * What it does:
   * Takes the window back out of the two lists that hold bare pointers to it,
   * which is the first thing the binary's destructor does:
   *
   *   wxList::DeleteObject(&wxPendingDelete, this);
   *   wxList::DeleteObject(&wxTopLevelWindows, this);
   *
   * Nothing else may hold a raw pointer to a window past its lifetime - both
   * lists are walked long after, wxTopLevelWindows by the idle pump on the way
   * out of the main loop.
   *
   * This is the wxWindowBase destructor's work, but it lives here because
   * wxWindowBase models the binary's vtable slot-for-slot (its deleting-dtor
   * slot is `DeleteObject`) and giving it a real C++ destructor would insert a
   * slot that the binary does not have. Every window teardown path in this
   * tree runs ~wxWindowMswRuntime, so the effect is the same.
   *
   * Deliberately non-virtual, for the same reason.
   */
  ~wxWindowMswRuntime();

  /**
   * Address: 0x009678C0 (FUN_009678C0)
   * Mangled: ?SetTitle@wxWindow@@UAEXPBG@Z
   *
   * IDA signature:
   * BOOL __thiscall wxWindow::SetTitle(wxWindow *this, LPCWSTR *a2);
   *
   * What it does:
   * Pushes the title straight onto the native window; wxWindowBase's version
   * (0x0042B3E0) accepts and ignores it because a plain wxWindowBase has no
   * handle to push it to.
   */
  void SetTitle(const wxStringRuntime& title) override;

  /**
   * Address: 0x00968640 (FUN_00968640)
   * Mangled: ?DoMoveWindow@wxWindow@@MAEXHHHH@Z
   *
   * IDA signature:
   * BOOL __thiscall wxWindow::DoMoveWindow(HWND *this, int X, int Y,
   *                                        int nWidth, int nHeight);
   *
   * What it does:
   * Moves and resizes the native window, clamping negative extents to zero
   * and repainting. The binary reads the handle as `*(this + 66)`, i.e.
   * +0x108 - which is exactly `sizeof(wxWindowBase)`, so it is wxWindowMSW's
   * first member.
   */
  virtual void DoMoveWindow(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height);

  /**
   * Address: 0x009684C0 (FUN_009684C0)
   * Mangled: ?DoGetClientSize@wxWindow@@MBEXPAH0@Z
   *
   * What it does:
   * Reports the native client rectangle's extent. wxFrame's override
   * (0x0099E990) subtracts the client-area origin and a shown status bar's
   * height on top of this; the SupCom frame has neither, so it reduces to
   * this body.
   */
  void DoGetClientSize(std::int32_t* outWidth, std::int32_t* outHeight) const override;

  /**
   * Address: 0x009687B0 (FUN_009687B0)
   * Mangled: ?DoSetClientSize@wxWindow@@MAEXHH@Z
   *
   * What it does:
   * Grows the window until its client area matches the requested size, by
   * adding the current window/client difference and moving. It iterates up to
   * four times because the first move can change the non-client metrics
   * (a scrollbar appearing or disappearing), and stops early once the client
   * rectangle already matches. -1 means "leave this axis alone".
   */
  void DoSetClientSize(std::int32_t width, std::int32_t height) override;

  /**
   * Address: 0x00968500 (FUN_00968500)
   * Mangled: ?DoGetPosition@wxWindow@@MBEXPAH0@Z
   *
   * IDA signature:
   * int *__thiscall wxWindow::DoGetPosition(wxWindow *this, int *a2, int *a3);
   *
   * What it does:
   * Reports where the window sits. A top-level window reports its screen
   * position; a child reports its position in the parent's client area, so the
   * screen point is mapped through the parent and the parent's client-area
   * origin is subtracted.
   */
  void DoGetPosition(std::int32_t* x, std::int32_t* y) const override;

  /**
   * Address: 0x00968480 (FUN_00968480)
   * Mangled: ?DoGetSize@wxWindow@@MBEXPAH0@Z
   *
   * IDA signature:
   * int *__thiscall wxWindow::DoGetSize(wxWindow *this, int *a2, int *a3);
   *
   * What it does:
   * Reports the outer (window rectangle) extent, non-client area included.
   */
  void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const override;

  /**
   * Address: 0x00968680 (FUN_00968680)
   * Mangled: ?DoSetSize@wxWindow@@MAEXHHHHH@Z
   *
   * IDA signature:
   * int __thiscall wxWindow::DoSetSize(wxWindow *this, int a2, int a3, int a4,
   *                                    int a5, int a6);
   *
   * What it does:
   * Resolves the -1 "leave this alone" placeholders against the window's
   * current geometry - or against its best size when the matching wxSIZE_AUTO_*
   * flag is set - and moves the window. Returns without touching the window
   * when the requested rectangle already matches the current one.
   */
  void DoSetSize(
    std::int32_t x,
    std::int32_t y,
    std::int32_t width,
    std::int32_t height,
    std::int32_t sizeFlags
  ) override;

  virtual void DoSetToolTip(void* tooltip) { (void)tooltip; }
  virtual bool DoPopupMenu(void* menu, std::int32_t x, std::int32_t y)
  {
    (void)menu;
    (void)x;
    (void)y;
    return false;
  }
  /**
   * Address: 0x00964840 (FUN_00964840)
   * Mangled: ?AdjustForParentClientOrigin@wxWindowBase@@UBEXAAH0H@Z
   *
   * IDA signature:
   * int *__thiscall wxWindowBase::AdjustForParentClientOrigin(
   *     wxWindowBase *this, int *a2, int *a3, char a4);
   *
   * What it does:
   * Shifts a child's requested position by the parent's client-area origin, so
   * a caller can ask for a position in client coordinates. Top-level windows,
   * parentless windows, and callers passing wxSIZE_NO_ADJUSTMENTS are left
   * alone.
   *
   * The binary declares this on wxWindowBase; it is kept here because the only
   * caller in this reconstruction is wxWindow::DoSetSize just below.
   */
  virtual void AdjustForParentClientOrigin(std::int32_t& x, std::int32_t& y, std::int32_t sizeFlags) const;
  virtual void DragAcceptFiles(bool accept) { (void)accept; }
  virtual bool LoadNativeDialogByName(void* parent, const void* dialogName)
  {
    (void)parent;
    (void)dialogName;
    return false;
  }
  virtual bool LoadNativeDialogById(void* parent, std::int32_t& dialogId)
  {
    (void)parent;
    (void)dialogId;
    return false;
  }
  /**
   * Address: 0x0042B830 (FUN_0042B830)
   * Mangled: ?ContainsHWND@wxWindow@@UBE_NK@Z
   *
   * What it does:
   * Base implementation reports the queried native handle as not contained.
   */
  virtual bool ContainsHWND(unsigned long nativeHandle) const;

  /**
   * Address: 0x0042B840 (FUN_0042B840)
   * Mangled: ?GetClassInfo@wxWindow@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxWindow runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;
  /**
   * Address: 0x00967570 (FUN_00967570)
   * Mangled: ?GetEventTable@wxWindow@@MBEPBUwxEventTable@@XZ
   *
   * What it does:
   * Returns the static event-table lane for wx window runtime dispatch.
   */
  [[nodiscard]] const void* GetEventTable() const override;
  /**
   * Address: 0x00967EB0 (FUN_00967EB0)
   * Mangled: ?MSWGetStyle@wxWindow@@UBEKJPAK@Z
   *
   * What it does:
   * Translates one wx style-bit lane into Win32 style and extended-style
   * masks, including 3D-control and top-level adjustments.
   */
  [[nodiscard]] unsigned long MSWGetStyle(long style, unsigned long* extendedStyle) const;
  /**
   * Address: 0x00968CF0 (FUN_00968CF0)
   * Mangled: ?MSWGetParent@wxWindow@@UBEKXZ
   *
   * What it does:
   * The handle CreateWindowEx should parent this window to.
   */
  [[nodiscard]] virtual unsigned long MSWGetParent() const;

  /**
   * Address: 0x0096DE00 (FUN_0096DE00, wxWindowMSW::Create)
   *
   * What it does:
   * Creates an ordinary child window: common state, parent's child list, then
   * the native window.
   */
  bool Create(
    wxWindowBase* parent,
    std::int32_t id,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x0096DC20 (FUN_0096DC20, wxWindow::MSWCreate)
   *
   * What it does:
   * The one place wx calls ::CreateWindowExW, then subclasses the result.
   */
  bool MSWCreate(
    const wchar_t* windowClassName,
    const wchar_t* title,
    const wxPoint& position,
    const wxSize& size,
    unsigned long style,
    unsigned long extendedStyle
  );

  /**
   * Address: 0x0096DBC0 (FUN_0096DBC0, wxWindowMSW::SubclassWin)
   *
   * What it does:
   * Points an existing HWND at the wx window procedure.
   */
  void SubclassWin(unsigned long nativeHandle);

  /**
   * Address: 0x0096C090 (FUN_0096C090, wxWindowMSW::UnsubclassWin)
   *
   * What it does:
   * Undoes SubclassWin: drops the handle association and, if this window
   * displaced someone else's window procedure, puts theirs back.
   */
  void UnsubclassWin();

  /**
   * Address: 0x0096BF40 (FUN_0096BF40, wxWindow::~wxWindow), tail at 0x0096BF78
   *
   * What it does:
   * The destructor's native teardown: destroys the window and drops its
   * handle association, in that order - the association has to outlive
   * ::DestroyWindow because the window procedure still runs during it.
   */
  void DestroyNativeWindow();

  /**
   * Address: 0x0096A100 (FUN_0096A100)
   * Mangled: ?HandleMove@wxWindow@@IAE_NHH@Z
   */
  bool HandleMove(std::int32_t x, std::int32_t y);

  /**
   * Address: 0x0096A1B0 (FUN_0096A1B0)
   * Mangled: ?HandleSize@wxWindow@@IAE_NHHI@Z
   */
  bool HandleSize(std::int32_t width, std::int32_t height, unsigned int flags);

  /**
   * Address: 0x009693D0 (FUN_009693D0)
   * Mangled: ?HandleShow@wxWindow@@IAE_N_NH@Z
   */
  bool HandleShow(bool show, std::int32_t status);

  /**
   * Address: 0x0096A270 (FUN_0096A270)
   * Mangled: ?HandleGetMinMaxInfo@wxWindow@@IAE_NPAX@Z
   */
  bool HandleGetMinMaxInfo(void* minMaxInfo);

  /**
   * Address: 0x00969DF0 (FUN_00969DF0)
   * Mangled: ?HandleEraseBkgnd@wxWindow@@IAE_NPAX@Z
   *
   * IDA signature:
   * bool __thiscall wxWindow::HandleEraseBkgnd(wxWindow *this, HDC hdc);
   *
   * What it does:
   * Turns WM_ERASEBKGND into wxEVT_ERASE_BACKGROUND, wrapping the handle the
   * message supplied in a borrowed device context so a handler can draw
   * through it.
   */
  bool HandleEraseBkgnd(void* nativeDeviceContext);

  /**
   * Address: 0x009696F0 (FUN_009696F0)
   * Mangled: ?HandleDisplayChange@wxWindow@@IAE_NXZ
   *
   * What it does:
   * Raises wxEVT_DISPLAY_CHANGED so a window can react to the screen
   * resolution or colour depth changing under it.
   */
  bool HandleDisplayChange();

  /**
   * Address: 0x00969660 (FUN_00969660)
   * Mangled: ?HandleSysColorChange@wxWindow@@IAE_NXZ
   *
   * What it does:
   * Raises wxEVT_SYS_COLOUR_CHANGED when Windows says the system colours
   * moved. This is the message side; OnSysColourChanged is what receives it.
   */
  bool HandleSysColorChange();

  /**
   * Address: 0x00969A20 (FUN_00969A20)
   * Mangled: ?HandleQueryNewPalette@wxWindow@@IAE_NXZ
   *
   * What it does:
   * Takes the foreground palette when this window is being activated.
   */
  /**
   * Address: 0x0096A760 (FUN_0096A760)
   * Mangled: ?HandleJoystickEvent@wxWindow@@IAE_NIHHI@Z
   *
   * What it does:
   * Turns one of the eight joystick messages into the matching wx joystick
   * event.
   */
  bool HandleJoystickEvent(unsigned int message, std::int32_t x, std::int32_t y, unsigned int flags);

  /**
   * Address: 0x00969500 (FUN_00969500)
   * Mangled: ?HandleSetCursor@wxWindow@@IAE_NPAXGI@Z
   *
   * What it does:
   * Chooses the cursor for a pointer sitting over this window's client area.
   */
  /**
   * Address: 0x0096B4E0 (FUN_0096B4E0)
   * Mangled: ?TranslateKbdEventToMouse@wxWindow@@IAEXPAH00@Z
   *
   * What it does:
   * Describes the pointer as though the right button had just been pressed
   * there, so a keyboard request for a context menu can be delivered as a
   * click.
   */
  void TranslateKbdEventToMouse(std::int32_t* x, std::int32_t* y, unsigned int* flags) const;

  /**
   * Address: 0x0096C100 (FUN_0096C100)
   * Mangled: ?OnIdle@wxWindow@@IAEXAAVwxIdleEvent@@@Z
   *
   * What it does:
   * Notices the pointer having left this window - Windows sends nothing when
   * it does - and refreshes whatever the window shows.
   */
  void OnIdle(wxEventRuntime& idleEvent);

  /**
   * Address: 0x00969780 (FUN_00969780)
   * Mangled: ?HandleCtlColor@wxWindow@@IAE_NPAPAXPAX@Z
   *
   * What it does:
   * Answers a control asking its parent what colour to draw itself in.
   */
  bool HandleCtlColor(
    void** brushOut,
    void* deviceContext,
    void* controlHandle,
    unsigned int controlType,
    unsigned int message,
    unsigned int wParam,
    long lParam
  );

  /**
   * Address: 0x00969CA0 (FUN_00969CA0)
   * Mangled: ?HandlePaint@wxWindow@@IAE_NXZ
   *
   * What it does:
   * Records which part of the window needs redrawing and asks for it to be
   * painted.
   */
  bool HandlePaint();

  bool HandleSetCursor(unsigned int hitTestCode);

  bool HandleQueryNewPalette();

  /**
   * Address: 0x00969810 (FUN_00969810)
   * Mangled: ?HandlePaletteChanged@wxWindow@@IAE_NPAX@Z
   *
   * What it does:
   * Re-realises this window's palette after some other window changed the
   * system one.
   */
  bool HandlePaletteChanged(void* changedWindow);

  /**
   * The nearest window up the chain - this one included - that carries a
   * palette of its own, or nothing if none does.
   */
  [[nodiscard]] wxWindowMswRuntime* GetAncestorWithCustomPalette();

  /**
   * Address: 0x009C89D0 (FUN_009C89D0)
   * Mangled: ?GetPalette@wxWindowBase@@QBE?AVwxPalette@@XZ
   *
   * What it does:
   * This window's palette; a copy names the same handle.
   */
  [[nodiscard]] wxPaletteRuntime GetPalette() const;

  /**
   * Address: 0x00969FD0 (FUN_00969FD0)
   *
   * What it does:
   * Raises wxEVT_ICONIZE saying the window was minimised.
   */
  bool HandleMinimize();

  /**
   * Address: 0x0096A070 (FUN_0096A070)
   *
   * What it does:
   * Raises wxEVT_MAXIMIZE.
   */
  bool HandleMaximize();

  /**
   * Address: 0x0096A2D0 (FUN_0096A2D0)
   * Mangled: ?HandleSysCommand@wxWindow@@IAE_NIJ@Z
   *
   * What it does:
   * Picks out the two system-menu commands wx cares about, minimise and
   * maximise, and lets everything else alone.
   */
  bool HandleSysCommand(unsigned int wParam, long lParam);

  /**
   * Address: 0x00968D10 (FUN_00968D10)
   * Mangled: ?HandleNotify@wxWindow@@IAE_NHJPAJ@Z
   *
   * What it does:
   * Hands a common-control notification to the control it came from.
   */
  bool HandleNotify(std::int32_t controlId, long notification, long* result);

  /**
   * Address: 0x00969470 (FUN_00969470)
   * Mangled: ?HandleInitDialog@wxWindow@@IAE_NPAX@Z
   *
   * What it does:
   * Raises wxEVT_INIT_DIALOG so a dialog fills its controls in before it is
   * shown.
   */
  bool HandleInitDialog(void* focusWindow);

  /**
   * Address: 0x00968DC0 (FUN_00968DC0)
   * Mangled: ?HandleQueryEndSession@wxWindow@@IAE_NJPA_N@Z
   *
   * What it does:
   * Answers Windows asking whether the session may end, by offering the
   * application a chance to object.
   */
  static bool HandleQueryEndSession(long logOff, bool* mayEnd);

  /**
   * Address: 0x00968E90 (FUN_00968E90)
   * Mangled: ?HandleEndSession@wxWindow@@IAE_N_NJ@Z
   *
   * What it does:
   * Tells the application the session really is ending, once, through the
   * main window.
   */
  bool HandleEndSession(bool endSession, long logOff);

  /**
   * Address: 0x0096A450 (FUN_0096A450)
   * Mangled: ?HandleMouseEvent@wxWindow@@IAE_NIHHI@Z
   *
   * IDA signature:
   * bool __thiscall wxWindow::HandleMouseEvent(wxWindow *this, UINT msg,
   *                                            int x, int y, WXUINT flags);
   *
   * What it does:
   * Turns one of the ten mouse messages into the matching wx mouse event and
   * offers it to this window's handler.
   */
  bool HandleMouseEvent(unsigned int message, std::int32_t x, std::int32_t y, unsigned int flags);

  /**
   * Address: 0x0096A580 (FUN_0096A580)
   * Mangled: ?HandleMouseMove@wxWindow@@IAE_NHHI@Z
   *
   * IDA signature:
   * bool __thiscall wxWindow::HandleMouseMove(wxWindow *this, int x, int y, WXUINT flags);
   *
   * What it does:
   * Notices the pointer arriving over this window and raises an enter event
   * once, then reports the motion itself.
   */
  bool HandleMouseMove(std::int32_t x, std::int32_t y, unsigned int flags);

  /**
   * Address: 0x0096A660 (FUN_0096A660)
   * Mangled: ?HandleMouseWheel@wxWindow@@IAE_NIJ@Z
   *
   * IDA signature:
   * bool __thiscall wxWindow::HandleMouseWheel(wxWindow *this, WXWPARAM wParam, WXLPARAM lParam);
   *
   * What it does:
   * Raises a wheel event carrying how far the wheel turned and how far the
   * system says one notch should scroll.
   */
  bool HandleMouseWheel(unsigned int wParam, long lParam);

  /**
   * Address: 0x00968180 (FUN_00968180)
   *
   * IDA signature:
   * bool __thiscall wxWindow::IsMouseInWindow(wxWindow *this);
   *
   * What it does:
   * Whether the pointer is over this window or anything nested inside it.
   */
  [[nodiscard]] bool IsMouseInWindow() const;

  /**
   * Address: 0x00969F40 (FUN_00969F40)
   * Mangled: ?OnEraseBackground@wxWindow@@IAEXAAVwxEraseEvent@@@Z
   *
   * IDA signature:
   * void __thiscall wxWindow::OnEraseBackground(wxWindow *this, wxEraseEvent *event);
   *
   * What it does:
   * Fills the whole client area with the window's background colour. The row
   * that binds this is the first one in wxWindow's event table, so it is what
   * every window's background comes from unless a derived class claims
   * wxEVT_ERASE_BACKGROUND for itself, the way the viewport does.
   */
  void OnEraseBackground(wxEraseEventRuntime& eraseEvent);

  /**
   * Address: 0x00969B80 (FUN_00969B80)
   * Mangled: ?OnSysColourChanged@wxWindow@@IAEXAAVwxSysColourChangedEvent@@@Z
   *
   * IDA signature:
   * void __thiscall wxWindow::OnSysColourChanged(wxWindow *this,
   *                                              wxSysColourChangedEvent *event);
   *
   * What it does:
   * Tells every child window the system colours moved, and takes the new
   * defaults for any colour the caller never overrode.
   */
  void OnSysColourChanged(wxEventRuntime& sysColourChangedEvent);

  /**
   * Address: 0x009691A0 (FUN_009691A0)
   * Mangled: ?HandleSetFocus@wxWindow@@IAE_NPAX@Z
   */
  bool HandleSetFocus(unsigned long windowLosingFocus);

  /**
   * Address: 0x009692D0 (FUN_009692D0)
   * Mangled: ?HandleKillFocus@wxWindow@@IAE_NPAX@Z
   */
  bool HandleKillFocus(unsigned long windowGainingFocus);

  /**
   * Address: 0x00968F70 (FUN_00968F70)
   * Mangled: ?HandleCreate@wxWindow@@IAE_NPAUtagCREATESTRUCTW@@PA_N@Z
   */
  bool HandleCreate(void* createStruct, bool* mayCreate);

  /**
   * Address: 0x00969050 (FUN_00969050)
   * Mangled: ?HandleDestroy@wxWindow@@IAE_NXZ
   */
  bool HandleDestroy();

  /**
   * What it does:
   * The parent window, or null at the top of the chain.
   */
  [[nodiscard]] wxWindowBase* GetParentWindow() const;
  /**
   * Address: 0x009675F0 (FUN_009675F0)
   * Mangled: ?MSWCommand@wxWindow@@UAE_NIG@Z
   *
   * What it does:
   * Base window runtime does not consume Win32 command notifications.
   */
  virtual bool MSWCommand(unsigned int commandId, unsigned short notificationCode);

  /**
   * Address: 0x00969800 (FUN_00969800, wxWindow vtable slot 130)
   * Mangled: ?OnCtlColor@wxWindow@@MAEPAXPAX0IIIJ@Z
   *
   * What it does:
   * The brush a window wants a control drawn with. The base answers with
   * none, leaving the control its default colours.
   */
  virtual void* OnCtlColor(
    void* deviceContext,
    void* controlHandle,
    unsigned int controlType,
    unsigned int message,
    unsigned int wParam,
    long lParam
  );


  /**
   * Address: 0x00968B10 (FUN_00968B10, wxWindow::UnpackCommand)
   *
   * What it does:
   * Splits packed command-message params into command id, notification code,
   * and control handle lanes.
   */
  static unsigned short UnpackCommand(
    unsigned int packedWord,
    int controlHandle,
    unsigned short* outCommandId,
    unsigned int* outControlHandle,
    unsigned short* outNotificationCode
  );

  /**
   * Address: 0x00968B40 (FUN_00968B40, wxWindow::UnpackActivate)
   *
   * What it does:
   * Splits activation packed word into state/minimized lanes and forwards the
   * HWND parameter.
   */
  static unsigned int* UnpackActivate(
    int packedWord,
    int nativeWindowHandle,
    unsigned short* outState,
    unsigned short* outMinimized,
    unsigned int* outNativeWindowHandle
  );

  /**
   * Address: 0x00968B70 (FUN_00968B70, wxWindow::UnpackScroll)
   *
   * What it does:
   * Splits scroll packed word into position/request lanes and forwards the
   * scroll-bar HWND parameter.
   */
  static unsigned int* UnpackScroll(
    int packedWord,
    int scrollBarHandle,
    unsigned short* outRequest,
    unsigned short* outPosition,
    unsigned int* outScrollBarHandle
  );

  /**
   * Address: 0x00968BA0 (FUN_00968BA0, wxWindow::UnpackCtlColor)
   *
   * What it does:
   * Emits fixed control-colour id lane (`3`) and forwards `wParam/lParam`
   * into caller-provided output lanes.
   */
  static unsigned int* UnpackCtlColor(
    int wParam,
    int lParam,
    unsigned short* outControlId,
    unsigned int* outWParam,
    unsigned int* outLParam
  );

  /**
   * Address: 0x0097D080 (FUN_0097D080)
   * Mangled: ?CreateWindowFromHWND@wxWindow@@UAEPAV1@PAV1@K@Z
   *
   * What it does:
   * Adapts one native Win32 HWND into the closest recovered wx runtime
   * control wrapper and adopts HWND-derived attributes.
   */
  virtual void* CreateWindowFromHWND(void* parent, unsigned long nativeHandle);
  /**
   * Address: 0x0097CCC0 (FUN_0097CCC0)
   * Mangled: ?AdoptAttributesFromHWND@wxWindow@@UAEXXZ
   *
   * What it does:
   * Reads native Win32 scroll-style bits from the attached HWND and mirrors
   * them into the wx window-style lane.
   */
  virtual void AdoptAttributesFromHWND();
  /**
   * Address: 0x00969970 (FUN_00969970)
   *
   * What it does:
   * Dispatches one mouse-capture-changed event to this window's current
   * event-handler lane, resolving the previous native capture owner handle
   * into a runtime wx window pointer.
   */
  bool HandleCaptureChanged(int nativeHandle);
  /**
   * Address: 0x0096C5F0 (FUN_0096C5F0)
   * Mangled: ?HandleDropFiles@wxWindow@@MAE_NPAUHDROP__@@@Z
   *
   * What it does:
   * Converts one Win32 HDROP payload into a runtime drop-files event and
   * dispatches it through the current window event-handler lane.
   */
  bool HandleDropFiles(void* hDrop);
  virtual void SetupColours() {}
  virtual bool MSWOnScroll(
    std::int32_t orientation, unsigned short command, unsigned short position, unsigned long controlHandle
  )
  {
    (void)orientation;
    (void)command;
    (void)position;
    (void)controlHandle;
    return false;
  }
  virtual bool MSWOnNotify(std::int32_t controlId, long notificationCode, long* result)
  {
    (void)controlId;
    (void)notificationCode;
    (void)result;
    return false;
  }
  virtual bool MSWOnDrawItem(std::int32_t controlId, void** drawItemStruct)
  {
    (void)controlId;
    (void)drawItemStruct;
    return false;
  }
  virtual bool MSWOnMeasureItem(std::int32_t controlId, void** measureItemStruct)
  {
    (void)controlId;
    (void)measureItemStruct;
    return false;
  }
  /**
   * Address: 0x0096D110 (FUN_0096D110)
   * Mangled: ?MSWWindowProc@wxWindow@@UAEJIIJ@Z
   *
   * What it does:
   * The wx side of the window procedure. Every message wx does not handle
   * itself ends up at MSWDefWindowProc, which is what this base does for all
   * of them - the per-message handling in the binary's 571-instruction version
   * is not recovered yet, and returning 0 instead of defaulting would abort
   * window creation at WM_NCCREATE.
   */
  virtual long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam);

  /**
   * Address: 0x00968A90 (FUN_00968A90)
   * Mangled: ?MSWDefWindowProc@wxWindow@@UAEJIIJ@Z
   *
   * What it does:
   * Default message handling: the window procedure this window replaced when
   * it subclassed an existing HWND, or the system default when wx created the
   * window itself.
   */
  virtual long MSWDefWindowProc(unsigned int message, unsigned int wParam, long lParam);
  /**
   * Address: 0x00968B00 (FUN_00968B00)
   * Mangled: ?MSWShouldPreProcessMessage@wxWindow@@UAE_NPAPAX@Z
   *
   * What it does:
   * Base window runtime requests pre-processing for incoming native messages.
   */
  virtual bool MSWShouldPreProcessMessage(void** message);
  virtual bool MSWProcessMessage(void** message)
  {
    (void)message;
    return false;
  }
  virtual bool MSWTranslateMessage(void** message)
  {
    (void)message;
    return false;
  }
  /**
   * Address: 0x00968C60 (FUN_00968C60)
   * Mangled: ?MSWDestroyWindow@wxWindow@@UAEXXZ
   *
   * What it does:
   * Base implementation performs no additional HWND teardown work.
   */
  virtual void MSWDestroyWindow();
  /**
   * Address: 0x00969800 (FUN_00969800)
   * Mangled: ?OnCtlColor@wxWindow@@UAEKKKIIIJ@Z
   *
   * What it does:
   * Base window runtime does not provide a control-colour brush override.
   */
  virtual unsigned long OnCtlColor(
    unsigned long hdc,
    unsigned long hwnd,
    unsigned int nCtlColor,
    unsigned int message,
    unsigned int controlId,
    long result
  );

  static wxEventTable sm_eventTable;
};

static_assert(sizeof(wxWindowMswRuntime) == 0x4, "wxWindowMswRuntime size must be 0x4");

class wxControlRuntime : public wxWindowMswRuntime
{
public:
  // Registers itself with wxClassInfo so a kind-of test can recognise it.
  static wxClassInfo sm_classInfo;

  /**
   * Address: 0x004A3830 (FUN_004A3830)
   * Mangled: ?Command@wxControl@@UAEXAAVwxCommandEvent@@@Z
   *
   * What it does:
   * Forwards one command-event dispatch into `ProcessCommand`.
   */
  virtual void Command(void* commandEvent);

  virtual void ControlSlot131() {}

  /**
   * Address: 0x004A3840 (FUN_004A3840)
   * Mangled: ?MSWOnDraw@wxControl@@UAE_NPAPAX@Z
   *
   * What it does:
   * Base implementation reports that no owner-draw handling was performed.
   */
  virtual bool MSWOnDraw(void** drawStruct);

  /**
   * Address: 0x004A3850 (FUN_004A3850)
   * Mangled: ?MSWOnMeasure@wxControl@@UAE_NPAPAX@Z
   *
   * What it does:
   * Base implementation reports that no owner-measure handling was performed.
   */
  virtual bool MSWOnMeasure(void** measureStruct);

protected:
  virtual void ProcessCommand(void* commandEvent)
  {
    (void)commandEvent;
  }
};

static_assert(sizeof(wxControlRuntime) == 0x4, "wxControlRuntime size must be 0x4");

struct wxStringRuntime
{
  wchar_t* m_pchData = nullptr;

  [[nodiscard]] const wchar_t* c_str() const noexcept;
  [[nodiscard]] msvc8::string ToUtf8() const;
  [[nodiscard]] msvc8::string ToUtf8Lower() const;
  /**
   * Address: 0x0095FFD0 (FUN_0095FFD0, func_wstrFind)
   *
   * What it does:
   * Finds one wide-character lane from the left or right and returns its
   * zero-based index, or `-1` when absent.
   */
  [[nodiscard]] std::int32_t FindCharacterIndex(wchar_t needle, bool findFromRight) const noexcept;

  /**
   * Address: 0x009621C0 (FUN_009621C0, wxString::Matches)
   *
   * What it does:
   * Matches this text lane against one wildcard mask (`*`/`?`) using the
   * original wx backtracking semantics.
   */
  [[nodiscard]] bool Matches(const wchar_t* wildcardMask) const noexcept;

  /**
   * Address: 0x009610B0 (FUN_009610B0, wxString::Empty)
   *
   * What it does:
   * Truncates one wx string to `newLength` when the target is shorter than the
   * current length and copy-on-write ownership checks pass.
   */
  wxStringRuntime* Empty(std::uint32_t newLength);

  /**
   * Address: 0x00960F20 (FUN_00960F20)
   *
   * What it does:
   * Ensures copy-on-write ownership, then lowercases this string in place.
   */
  wxStringRuntime* LowerInPlace();

  /**
   * Address: 0x00960FA0 (FUN_00960FA0)
   *
   * What it does:
   * Trims ASCII-space characters from either the left or right edge of this
   * string, after ensuring unique writable ownership.
   */
  wxStringRuntime* TrimInPlace(bool fromRight);

  /**
   * Address: 0x009620B0 (FUN_009620B0, wxString::Pad)
   *
   * What it does:
   * Builds one temporary pad-string lane of `padCount` copies of `padChar`,
   * then appends or prepends it to this string according to `appendToRight`.
   */
  wxStringRuntime* PadInPlace(std::size_t padCount, wchar_t padChar, bool appendToRight);

  /**
   * Address: 0x00960090 (FUN_00960090, wxString::ToULong)
   *
   * What it does:
   * Parses this wide-string text as an unsigned long using the active CRT
   * locale, writing the parsed value into `*outValue` and returning `true`
   * only when the full string was consumed (no trailing garbage) and the
   * string was non-empty.
   */
  [[nodiscard]] bool ToULong(unsigned long* outValue, std::int32_t base) const noexcept;

  /**
   * Address: 0x00961E70 (FUN_00961E70, wxString::BeforeLast)
   *
   * What it does:
   * Writes into `outPrefix` the prefix of this string up to (but not
   * including) the last occurrence of `separator`. If `separator` is not
   * found, or is at index `0`, `outPrefix` is cleared to empty. Returns
   * `outPrefix` (the result sink) so callers can chain.
   */
  wxStringRuntime* BeforeLast(wxStringRuntime* outPrefix, wchar_t separator) const noexcept;

  [[nodiscard]] static wxStringRuntime Borrow(const wchar_t* text) noexcept;
};

static_assert(sizeof(wxStringRuntime) == 0x4, "wxStringRuntime size must be 0x4");

struct wxBuildOptionsRuntime
{
  std::int32_t versionMajor = 0;  // +0x00
  std::int32_t versionMinor = 0;  // +0x04
  std::uint8_t debugBuild = 0;    // +0x08
  std::uint8_t reserved09_0B[0x3]{};
};

static_assert(offsetof(wxBuildOptionsRuntime, versionMajor) == 0x00, "wxBuildOptionsRuntime::versionMajor offset must be 0x00");
static_assert(offsetof(wxBuildOptionsRuntime, versionMinor) == 0x04, "wxBuildOptionsRuntime::versionMinor offset must be 0x04");
static_assert(offsetof(wxBuildOptionsRuntime, debugBuild) == 0x08, "wxBuildOptionsRuntime::debugBuild offset must be 0x08");
static_assert(sizeof(wxBuildOptionsRuntime) == 0x0C, "wxBuildOptionsRuntime size must be 0x0C");

/**
 * Address: 0x009AAB90 (FUN_009AAB90)
 * Mangled: wxCheckBuildOptions
 *
 * What it does:
 * Validates application build-options against the embedded wx runtime's
 * expected major/minor/debug tuple and fatals on mismatch.
 */
bool wxCheckBuildOptions(const wxBuildOptionsRuntime* buildOptions);

/**
 * Minimal recovered `wxNativeFontInfo` runtime projection.
 *
 * Layout matches Win32 `LOGFONTW` storage lanes used by wx font parsing code.
 */
class wxNativeFontInfoRuntime
{
public:
  /**
   * Address: 0x0096E1D0 (FUN_0096E1D0, wxNativeFontInfo::wxNativeFontInfo)
   * Mangled: ??0wxNativeFontInfo@@QAE@@Z
   *
   * What it does:
   * Constructs one native-font descriptor and seeds default weight/charset
   * lanes.
   */
  wxNativeFontInfoRuntime();

  /**
   * Address: 0x0096E460 (FUN_0096E460)
   *
   * What it does:
   * Parses one legacy semicolon-delimited native-font descriptor into LOGFONT
   * scalar/byte/facename lanes.
   */
  [[nodiscard]] bool ParseLegacySemicolonDescriptor(const wxStringRuntime& descriptor);

  /**
   * Address: 0x0097EEF0 (FUN_0097EEF0, wxNativeFontInfo::FromString)
   * Mangled: ?FromString@wxNativeFontInfo@@QAE_NABVwxString@@@Z
   *
   * What it does:
   * Resets this descriptor, tokenizes one textual font description, then
   * applies point-size/style/weight/underline/charset/facename lanes.
   */
  [[nodiscard]] bool FromString(const wxStringRuntime& description);

  void Init() noexcept;

  /**
   * Address: 0x0096E360 (FUN_0096E360, wxNativeFontInfo::SetPointSize)
   *
   * What it does:
   * Converts one point-size value into LOGFONT logical height using
   * `LOGPIXELSY`.
   */
  void SetPointSize(std::int32_t pointSize) noexcept;

  /**
   * Address: 0x0096E1E0 (FUN_0096E1E0, wxFont::GetPointSize helper lane)
   *
   * What it does:
   * Converts this LOGFONT logical height into point size using display
   * vertical DPI (`LOGPIXELSY`).
   */
  [[nodiscard]] std::int32_t GetPointSize() const noexcept;

  /**
   * Address: 0x0096E350 (FUN_0096E350, wxNativeFontInfo::GetEncoding helper lane)
   *
   * What it does:
   * Maps the stored Win32 charset byte into one wx encoding-id lane.
   */
  [[nodiscard]] std::int32_t GetEncoding() const noexcept;

  /**
   * Address: 0x0096E230 (FUN_0096E230, wxFont::GetStyle helper lane)
   *
   * What it does:
   * Returns wx style token `93` when the italic flag lane is set, otherwise
   * returns normal style token `90`.
   */
  [[nodiscard]] std::int32_t GetStyle() const noexcept;

  /**
   * Address: 0x0096E240 (FUN_0096E240, wxFont::GetWeight helper lane)
   *
   * What it does:
   * Maps LOGFONT weight lane to wx weight token (`91`, `90`, `92`) using the
   * original threshold split (`<=300`, `301..599`, `>=600`).
   */
  [[nodiscard]] std::int32_t GetWeight() const noexcept;

  /**
   * Address: 0x0096E270 (FUN_0096E270, wxFont::GetUnderline helper lane)
   *
   * What it does:
   * Returns whether the underline byte lane is non-zero.
   */
  [[nodiscard]] bool GetUnderlined() const noexcept;

  /**
   * Address: 0x0096E3E0 (FUN_0096E3E0, wxNativeFontInfo::SetWeight)
   *
   * What it does:
   * Maps wx font-weight tokens (`90/91/92`) to Win32 LOGFONT weights
   * (`400/300/700`) and defaults unknown tokens to normal weight (`400`).
   */
  void SetWeight(std::int32_t weight) noexcept;

  /**
   * Address: 0x0096E3B0 (FUN_0096E3B0)
   *
   * What it does:
   * Updates the LOGFONT italic/style flag lane from wx style-token values.
   */
  void SetStyle(std::int32_t style) noexcept;

  /**
   * Address: 0x0096E420 (FUN_0096E420)
   *
   * What it does:
   * Stores the LOGFONT underline flag lane.
   */
  void SetUnderlined(bool underlined) noexcept;
  void SetFaceName(const wxStringRuntime& faceName) noexcept;

  /**
   * Address: 0x0096E430 (FUN_0096E430)
   *
   * What it does:
   * Copies one temporary UTF-16 facename lane into this `LOGFONTW` face-name
   * buffer and releases the temporary wx-string ownership lane.
   */
  void CopyFaceNameFromBufferAndReleaseTemp(wchar_t* temporaryFaceNameBuffer) noexcept;

  void SetEncoding(std::int32_t encoding) noexcept;

public:
  std::int32_t mHeight = 0;
  std::int32_t mWidth = 0;
  std::int32_t mEscapement = 0;
  std::int32_t mOrientation = 0;
  std::int32_t mWeight = 0;
  std::uint8_t mItalic = 0;
  std::uint8_t mUnderline = 0;
  std::uint8_t mStrikeOut = 0;
  std::uint8_t mCharSet = 0;
  std::uint8_t mOutPrecision = 0;
  std::uint8_t mClipPrecision = 0;
  std::uint8_t mQuality = 0;
  std::uint8_t mPitchAndFamily = 0;
  wchar_t mFaceName[32]{};
};

static_assert(offsetof(wxNativeFontInfoRuntime, mWeight) == 0x10, "wxNativeFontInfoRuntime::mWeight offset must be 0x10");
static_assert(
  offsetof(wxNativeFontInfoRuntime, mFaceName) == 0x1C,
  "wxNativeFontInfoRuntime::mFaceName offset must be 0x1C"
);
static_assert(sizeof(wxNativeFontInfoRuntime) == 0x5C, "wxNativeFontInfoRuntime size must be 0x5C");

/**
 * Address: 0x0097F440 (FUN_0097F440, wxFontBase::SetNativeFontInfo)
 * Mangled: ?SetNativeFontInfo@wxFontBase@@QAEXABVwxString@@@Z
 *
 * What it does:
 * Parses one textual native-font descriptor and forwards the parsed
 * `wxNativeFontInfo` payload into the font object's virtual native-info lane.
 */
void WX_FontBaseSetNativeFontInfoFromString(void* fontObject, const wxStringRuntime& description);












/**
 * Address: 0x009F46E0 (FUN_009F46E0)
 * Mangled: ?wxGetVolumeString@@YA?AVwxString@@ABV1@W4wxPathFormat@@@Z
 *
 * What it does:
 * Formats one volume-prefix lane for `wxFileName::SplitPath_0` prepend usage.
 */
[[nodiscard]] wxStringRuntime wxGetVolumeString(const wxStringRuntime& volume, const wchar_t* formatHint);

/**
 * Address: 0x009DF260 (FUN_009DF260)
 *
 * What it does:
 * Splits one path and writes `name[.ext]` into `outFileName`.
 */
wxStringRuntime* wxBuildFileNameFromPath(
  wxStringRuntime* outFileName,
  const wxStringRuntime* sourcePath
);

/**
 * Address: 0x009DFC90 (FUN_009DFC90)
 *
 * What it does:
 * Returns one pointer into `pathText` at the beginning of the filename lane.
 */
[[nodiscard]] const wchar_t* wxFindFileNameStartInPath(const wchar_t* pathText);

/**
 * Address: 0x009EA000 (FUN_009EA000)
 *
 * What it does:
 * Reads the first 9 bytes from `inputStream`, seeks back by 9, and returns
 * `true` only when they match the XPM header literal `/ * XPM * /`.
 */
[[nodiscard]] bool wxInputStreamHasXpmSignature(wxInputStream* inputStream);

/**
 * Address: 0x00975620 (FUN_00975620)
 *
 * What it does:
 * Reads the first 4 bytes from `inputStream`, seeks back by 4, and returns
 * `true` only when they match the PNG file signature prefix.
 */
[[nodiscard]] bool wxInputStreamHasPngSignature(wxInputStream* inputStream);

/**
 * Address: 0x009CE620 (FUN_009CE620)
 *
 * What it does:
 * Builds one current-user text lane from wx profile/user environment sources,
 * falling back to `"Unknown User"` when no source resolves.
 */
wxStringRuntime* wxBuildCurrentUserNameOrUnknownRuntime(wxStringRuntime* outText);

/**
 * Address: 0x009CE6B0 (FUN_009CE6B0)
 *
 * What it does:
 * Builds one local computer-name text lane using `GetComputerNameW`, or an
 * empty string when name resolution fails.
 */
wxStringRuntime* wxBuildCurrentComputerNameStringRuntime(wxStringRuntime* outText);

/**
 * Address: 0x009CEAE0 (FUN_009CEAE0)
 *
 * What it does:
 * Writes `username@hostname` into `outText` when both lanes resolve;
 * otherwise writes an empty string.
 */
wxStringRuntime* wxBuildCurrentUserAtHostStringRuntime(wxStringRuntime* outText);

/**
 * Address: 0x009CEBF0 (FUN_009CEBF0)
 *
 * What it does:
 * Builds `username@hostname` text and copies it into `outBuffer` when
 * non-empty; returns `true` when text was copied.
 */
[[nodiscard]] bool wxCopyCurrentUserAtHostStringToBuffer(wchar_t* outBuffer, int maxChars);

/**
 * Address: 0x009F8590 (FUN_009F8590)
 *
 * What it does:
 * Copies the leading identifier token from `sourceText` into `outText`,
 * stopping at the first code unit that is neither alnum nor listed in
 * `additionalAllowedChars`.
 */
wxStringRuntime* wxExtractLeadingIdentifierToken(
  wxStringRuntime* outText,
  const wchar_t* sourceText,
  const wchar_t* additionalAllowedChars
);

/**
 * Address: 0x00A1AEC0 (FUN_00A1AEC0)
 *
 * What it does:
 * Resolves the user config-home path into `outText`, ensures writable string
 * ownership, and appends one trailing `'\\'` when missing.
 */
wxStringRuntime* wxBuildUserConfigRootPath(wxStringRuntime* outText);


/**
 * The drawing state every device context carries: pens, brushes, fonts,
 * colours, the mapping mode and the scale/origin pair, plus the bounding box
 * the drawing primitives accumulate.
 *
 * Those fields have not been mapped yet - what is pinned is the size, because
 * wxDC's own first field sits at +0xE8 (`mov [esi+0E8h], edi` in the wxDC
 * constructor at 0x009CA490), so everything below it belongs here.
 */
class wxDCBase
{
public:
  wxDCBase();

  /**
   * The vtable shape, not a behaviour recovery.
   *
   * `wxmsw.lib` supplies `??_7wxDC@@6B@` and `??_7wxDCTemp@@6B@`, so the
   * vtable actually installed in every device context we construct is the
   * library's - the real wxWidgets 2.4.2 one, which is what the shipped
   * binary used too. Our call sites therefore have to index it with the
   * library's slot numbers, and the only way to make the compiler emit those
   * numbers is to declare the same virtuals in the same order.
   *
   * The order is transcribed from `wxDCBase` in the in-repo
   * `dependencies/wxWindows-2.4.2/include/wx/dc.h`, on top of the four slots
   * wxObject contributes (GetClassInfo, the deleting destructor,
   * CreateRefData, CloneRefData - the shape this project already read off the
   * WSupComFrame vtable). `SetColourMap` is left out because it sits behind
   * `WXWIN_COMPATIBILITY`, which the shipped build had off.
   *
   * That reproduces the three offsets the disassembly of
   * `WD3DViewport::DrawBackgroundImage` (0x00430A60) dispatches through
   * exactly: SetBrush at +0x3C, DoDrawRectangle at +0xC4, DoGetSize at +0xE8.
   * Before this the class declared one virtual of its own, so `SetBrush`
   * compiled to slot 1 - the library's deleting destructor - and erasing the
   * background deleted the borrowed DC and faulted in `free`.
   *
   * The bodies below are never entered: virtual dispatch goes through the
   * library's vtable, and the linker discards the duplicate we emit. They
   * exist so the slots line up, the same way the byte arrays in this class
   * exist so the fields line up.
   */
  virtual void* GetClassInfo() const { return nullptr; } // slot 0 (+0x00)
  virtual ~wxDCBase() = default;                         // slot 1 (+0x04)
  virtual void* CreateRefData() const { return nullptr; } // slot 2 (+0x08)
  virtual void* CloneRefData(const void*) const { return nullptr; } // slot 3 (+0x0C)

  virtual void BeginDrawing() {} // slot 4 (+0x10)
  virtual void EndDrawing() {} // slot 5 (+0x14)
  virtual void DrawObject() {} // slot 6 (+0x18)
  virtual void DrawLabel() {} // slot 7 (+0x1C)
  virtual void Clear() {} // slot 8 (+0x20)
  virtual void StartDoc() {} // slot 9 (+0x24)
  virtual void EndDoc() {} // slot 10 (+0x28)
  virtual void StartPage() {} // slot 11 (+0x2C)
  virtual void EndPage() {} // slot 12 (+0x30)
  virtual void SetFont() {} // slot 13 (+0x34)
  virtual void SetPen() {} // slot 14 (+0x38)
  // slot 15 (+0x3C)
  virtual void SetBrush(const void* brush) noexcept;
  virtual void SetBackground() {} // slot 16 (+0x40)
  virtual void SetBackgroundMode() {} // slot 17 (+0x44)
  virtual void SetPalette() {} // slot 18 (+0x48)
  virtual void DestroyClippingRegion() {} // slot 19 (+0x4C)
  virtual void GetCharHeight() {} // slot 20 (+0x50)
  virtual void GetCharWidth() {} // slot 21 (+0x54)
  virtual void GetMultiLineTextExtent() {} // slot 22 (+0x58)
  virtual void CanDrawBitmap() {} // slot 23 (+0x5C)
  virtual void CanGetTextExtent() {} // slot 24 (+0x60)
  virtual void GetDepth() {} // slot 25 (+0x64)
  virtual void GetPPI() {} // slot 26 (+0x68)
  virtual void Ok() {} // slot 27 (+0x6C)
  virtual void SetTextForeground() {} // slot 28 (+0x70)
  virtual void SetTextBackground() {} // slot 29 (+0x74)
  virtual void SetMapMode() {} // slot 30 (+0x78)
  virtual void GetUserScale() {} // slot 31 (+0x7C)
  virtual void SetUserScale() {} // slot 32 (+0x80)
  virtual void GetLogicalScale() {} // slot 33 (+0x84)
  virtual void SetLogicalScale() {} // slot 34 (+0x88)
  virtual void SetLogicalOrigin() {} // slot 35 (+0x8C)
  virtual void SetDeviceOrigin() {} // slot 36 (+0x90)
  virtual void SetAxisOrientation() {} // slot 37 (+0x94)
  virtual void SetLogicalFunction() {} // slot 38 (+0x98)
  virtual void SetOptimization() {} // slot 39 (+0x9C)
  virtual void GetOptimization() {} // slot 40 (+0xA0)
  virtual void CalcBoundingBox() {} // slot 41 (+0xA4)
  virtual void DoFloodFill() {} // slot 42 (+0xA8)
  virtual void DoGetPixel() {} // slot 43 (+0xAC)
  virtual void DoDrawPoint() {} // slot 44 (+0xB0)
  virtual void DoDrawLine() {} // slot 45 (+0xB4)
  virtual void DoDrawArc() {} // slot 46 (+0xB8)
  virtual void DoDrawCheckMark() {} // slot 47 (+0xBC)
  virtual void DoDrawEllipticArc() {} // slot 48 (+0xC0)
  // slot 49 (+0xC4)
  virtual void DoDrawRectangle(
    std::int32_t x,
    std::int32_t y,
    std::int32_t width,
    std::int32_t height
  ) noexcept;
  virtual void DoDrawRoundedRectangle() {} // slot 50 (+0xC8)
  virtual void DoDrawEllipse() {} // slot 51 (+0xCC)
  virtual void DoCrossHair() {} // slot 52 (+0xD0)
  virtual void DoDrawIcon() {} // slot 53 (+0xD4)
  virtual void DoDrawBitmap() {} // slot 54 (+0xD8)
  virtual void DoDrawText() {} // slot 55 (+0xDC)
  virtual void DoDrawRotatedText() {} // slot 56 (+0xE0)
  virtual void DoBlit() {} // slot 57 (+0xE4)
  // slot 58 (+0xE8)
  virtual void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const noexcept;
  virtual void DoGetSizeMM() {} // slot 59 (+0xEC)
  virtual void DoDrawLines() {} // slot 60 (+0xF0)
  virtual void DoDrawPolygon() {} // slot 61 (+0xF4)
  virtual void DoSetClippingRegionAsRegion() {} // slot 62 (+0xF8)
  virtual void DoSetClippingRegion() {} // slot 63 (+0xFC)
  virtual void DoGetClippingRegion() {} // slot 64 (+0x100)
  virtual void DoGetClippingBox() {} // slot 65 (+0x104)
  virtual void DoGetLogicalOrigin() {} // slot 66 (+0x108)
  virtual void DoGetDeviceOrigin() {} // slot 67 (+0x10C)
  virtual void DoGetTextExtent() {} // slot 68 (+0x110)
  virtual void DoDrawSpline() {} // slot 69 (+0x114)

  void* m_refData = nullptr;                 // +0x04, from wxObject
  std::uint8_t m_flags = 0;                  // +0x08 bit 1: the DC is usable
  std::uint8_t mDrawingState[0xCB]{};        // +0x09, not yet mapped
  // The palette a context draws through, borrowed from whichever window up
  // the chain owns one. Offsets from wxDC::InitializePalette (0x009CAAA0),
  // which writes the flag at +0xE0 and takes a reference on the palette at
  // +0xD4.
  wxPaletteRuntime m_palette{};              // +0xD4
  std::uint8_t m_hasCustomPalette = 0;       // +0xE0
  std::uint8_t mPaddingE1[0x7]{};            // +0xE1
};

static_assert(offsetof(wxDCBase, m_refData) == 0x04, "wxDCBase::m_refData offset must be 0x04");
static_assert(offsetof(wxDCBase, m_flags) == 0x08, "wxDCBase::m_flags offset must be 0x08");
static_assert(offsetof(wxDCBase, m_palette) == 0xD4, "wxDCBase::m_palette offset must be 0xD4");
static_assert(
  offsetof(wxDCBase, m_hasCustomPalette) == 0xE0,
  "wxDCBase::m_hasCustomPalette offset must be 0xE0"
);
static_assert(sizeof(wxDCBase) == 0xE8, "wxDCBase size must be 0xE8");

/**
 * A Win32 device context.
 *
 * Offsets are read off the constructor at 0x009CA490, which writes every one
 * of them; the decompiler lists them in a different order than the stores
 * happen, so the disassembly is what they come from.
 *
 * The total size is not asserted: the fields run to +0x114 and the deepest
 * stack frame holding one by value (HandleEraseBkgnd at 0x00969DF0, `wxDC dc`
 * at ebp-0x124) bounds it below 0x120, which is not tight enough to pin.
 */
class wxDC : public wxDCBase
{
public:
  /**
   * Address: 0x009CA490 (FUN_009CA490)
   * Mangled: ??0wxDC@@QAE@@Z
   *
   * IDA signature:
   * wxDC *__thiscall wxDC::wxDC(wxDC *this);
   *
   * What it does:
   * Clears the selected-object backups and the native handle, and hands the
   * DC to nobody - it owns neither the handle nor a canvas until something
   * assigns them.
   */
  wxDC();
  ~wxDC() override = default;

  [[nodiscard]] void* GetNativeHandle() const noexcept { return m_hDC; }

  // Drops a handle this context never owned, so destroying it cannot take the
  // lender's handle down too.
  void ForgetNativeHandle() noexcept
  {
    m_bOwnsDC &= static_cast<std::uint8_t>(~1u);
    m_hDC = nullptr;
  }

  /**
   * The three drawing calls WD3DViewport::DrawBackgroundImage (0x00430A60)
   * dispatches through, at vtable slots +0x3C, +0xE8 and +0xC4 - the same
   * +0xC4 for DoDrawRectangle that the curve editor's vtable view asserts.
   */
  void SetBrush(const void* brush) noexcept override;
  void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const noexcept override;
  void DoDrawRectangle(
    std::int32_t x,
    std::int32_t y,
    std::int32_t width,
    std::int32_t height
  ) noexcept override;

  /**
   * Address: 0x009CAAA0 (FUN_009CAAA0)
   * Mangled: ?InitializePalette@wxDC@@IAEXXZ
   *
   * IDA signature:
   * void __thiscall wxDC::InitializePalette(wxDC *this);
   *
   * What it does:
   * Adopts the palette of the nearest ancestor that has a custom one, and
   * selects it into the context - but only on a palettised display.
   */
  void InitializePalette();

  /**
   * Address: 0x009C9900 (FUN_009C9900)
   * Mangled: ?DoSelectPalette@wxDC@@MAEX_N@Z
   *
   * What it does:
   * Selects this context's palette, optionally realising it.
   */
  virtual void DoSelectPalette(bool realize);

  void* m_canvas = nullptr;                  // +0xE8 the window being drawn on
  void* m_selectedBitmap = nullptr;          // +0xEC wxBitmap, 0xC bytes
  std::uint8_t mSelectedBitmapRest[0x8]{};   // +0xF0
  std::uint8_t m_bOwnsDC = 0;                // +0xF8 bit 0: destroy m_hDC with the DC
  std::uint8_t mPaddingF9[0x3]{};            // +0xF9
  void* m_hDC = nullptr;                     // +0xFC
  void* m_oldBitmap = nullptr;               // +0x100
  void* m_oldPen = nullptr;                  // +0x104
  void* m_oldBrush = nullptr;                // +0x108
  void* m_oldFont = nullptr;                 // +0x10C
  void* m_oldPalette = nullptr;              // +0x110
};

static_assert(offsetof(wxDC, m_canvas) == 0xE8, "wxDC::m_canvas offset must be 0xE8");
static_assert(offsetof(wxDC, m_selectedBitmap) == 0xEC, "wxDC::m_selectedBitmap offset must be 0xEC");
static_assert(offsetof(wxDC, m_bOwnsDC) == 0xF8, "wxDC::m_bOwnsDC offset must be 0xF8");
static_assert(offsetof(wxDC, m_hDC) == 0xFC, "wxDC::m_hDC offset must be 0xFC");
static_assert(offsetof(wxDC, m_oldBitmap) == 0x100, "wxDC::m_oldBitmap offset must be 0x100");
static_assert(offsetof(wxDC, m_oldPen) == 0x104, "wxDC::m_oldPen offset must be 0x104");
static_assert(offsetof(wxDC, m_oldBrush) == 0x108, "wxDC::m_oldBrush offset must be 0x108");
static_assert(offsetof(wxDC, m_oldFont) == 0x10C, "wxDC::m_oldFont offset must be 0x10C");
static_assert(offsetof(wxDC, m_oldPalette) == 0x110, "wxDC::m_oldPalette offset must be 0x110");

/**
 * A device context borrowed from somewhere else.
 *
 * The handle belongs to whoever supplied it - m_bOwnsDC stays clear - so
 * destroying one of these must not destroy the DC. The binary builds these
 * inline by constructing a wxDC and overwriting its vtable pointer, which is
 * exactly what a wxDCTemp constructor compiles to.
 */
class wxDCTemp : public wxDC
{
public:
  wxDCTemp(void* nativeDeviceContext, wxWindowBase* canvas) noexcept;
  ~wxDCTemp() override = default;

  /**
   * Address: 0x009CA520 (FUN_009CA520)
   * Mangled: ?SelectOldObjects@wxDCTemp@@IAEXPAX@Z
   *
   * IDA signature:
   * void __thiscall wxDCTemp::SelectOldObjects(wxDC *this, HDC hdc);
   *
   * What it does:
   * Puts back every GDI object this context displaced, in the order the
   * binary does, and forgets the backups so a second call is harmless.
   */
  void SelectOldObjects(void* nativeDeviceContext) noexcept;
};

class wxMemoryDC : public wxDC
{
public:
  /**
   * Address: 0x009D45B0 (FUN_009D45B0)
   * Mangled: ??0wxMemoryDC@@QAE@@Z
   *
   * What it does:
   * Initializes one memory-DC lane, creates a compatible native DC handle,
   * then applies default brush/pen/background draw state.
   */
  wxMemoryDC();

  /**
   * Address: 0x009D4430 (FUN_009D4430)
   * Mangled: ?CreateCompatible@wxMemoryDC@@QAE_NPAVwxDC@@@Z
   */
  bool CreateCompatible(wxDC* sourceDc);

  /**
   * Address: 0x009D43F0 (FUN_009D43F0)
   * Mangled: ?Init@wxMemoryDC@@AAEXXZ
   */
  void Init();

private:
  void SetBrush(void* brushToken);
  void SetPen(void* penToken);
};

/**
 * Minimal recovered `wxClientData` runtime object.
 */
class wxClientDataRuntime
{
public:
  /**
   * Address: 0x004A3690 (FUN_004A3690)
   * Mangled: ??0wxClientData@@QAE@@Z
   *
   * What it does:
   * Constructs one `wxClientData` runtime lane.
   */
  wxClientDataRuntime();

  virtual ~wxClientDataRuntime() = default;

  /**
   * Address: 0x004A36A0 (FUN_004A36A0)
   *
   * What it does:
   * Rebinds this object to the `wxClientData` runtime vtable lane.
   */
  void ResetRuntimeVTable() noexcept;

  /**
   * Address: 0x004A36B0 (FUN_004A36B0)
   *
   * What it does:
   * Implements the deleting-dtor thunk lane for `wxClientData`.
   */
  static wxClientDataRuntime* DeleteWithFlag(wxClientDataRuntime* object, std::uint8_t deleteFlags) noexcept;
};

static_assert(sizeof(wxClientDataRuntime) == 0x4, "wxClientDataRuntime size must be 0x4");

/**
 * Minimal recovered `wxSizer` client-data container subobject used by sizer
 * `wxClientDataContainer` vtable lanes.
 */
class wxSizerClientDataRuntime
{
public:
  static constexpr std::uint32_t kClientPayloadObject = 1;
  static constexpr std::uint32_t kClientPayloadData = 2;

  /**
   * Address: 0x009F34B0 (FUN_009F34B0, wxSizer::DoSetClientObject)
   *
   * What it does:
   * Deletes the previous client-object payload (when present), then stores one
   * new client-object lane and marks payload type as object-backed.
   */
  virtual void DoSetClientObject(void* clientObject);

  /**
   * Address: 0x009F34F0 (FUN_009F34F0, wxSizer::DoGetClientObject)
   *
   * What it does:
   * Returns the stored client payload pointer lane.
   */
  [[nodiscard]] virtual void* DoGetClientObject() const;

  /**
   * Address: 0x009F3500 (FUN_009F3500, wxSizer::DoSetClientData)
   *
   * What it does:
   * Stores one raw client-data payload pointer and marks payload type as raw
   * client-data.
   */
  virtual void DoSetClientData(void* clientData);

  /**
   * Address: 0x009F3520 (FUN_009F3520, wxSizer::DoGetClientData)
   *
   * What it does:
   * Returns the stored client payload pointer lane.
   */
  [[nodiscard]] virtual void* DoGetClientData() const;

public:
  void* mClientPayload = nullptr;           // +0x04
  std::uint32_t mClientPayloadType = 0;     // +0x08
};

static_assert(
  offsetof(wxSizerClientDataRuntime, mClientPayload) == 0x4,
  "wxSizerClientDataRuntime::mClientPayload offset must be 0x4"
);
static_assert(
  offsetof(wxSizerClientDataRuntime, mClientPayloadType) == 0x8,
  "wxSizerClientDataRuntime::mClientPayloadType offset must be 0x8"
);
static_assert(sizeof(wxSizerClientDataRuntime) == 0xC, "wxSizerClientDataRuntime size must be 0xC");

/**
 * Minimal recovered `wxImageHandler` runtime layout used by image codec startup
 * lanes and handler registration.
 */
class wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x0042B870 (FUN_0042B870)
   * Mangled: ??0wxImageHandler@@QAE@@Z
   *
   * What it does:
   * Initializes name/extension/mime string lanes and sets type to invalid.
   */
  wxImageHandlerRuntime();

  /**
   * Address: 0x0042B8F0 (FUN_0042B8F0)
   * Mangled: ?GetClassInfo@wxImageHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxImageHandler runtime RTTI checks.
   */
  [[nodiscard]] virtual void* GetClassInfo() const;

  /**
   * Address: 0x0042B920 (FUN_0042B920)
   *
   * What it does:
   * Releases runtime string lanes and clears shared ref-data ownership.
   */
  virtual ~wxImageHandlerRuntime();

  /**
   * Address: 0x00971420 (FUN_00971420)
   *
   * What it does:
   * Copies the shared extension string lane into `outValue`, falling back to
   * `wxEmptyString` when the lane is empty.
   */
  wxStringRuntime* CopyExtensionOrEmpty(wxStringRuntime* outValue) const;

  /**
   * Address: 0x00971460 (FUN_00971460)
   *
   * What it does:
   * Copies the shared MIME string lane into `outValue`, falling back to
   * `wxEmptyString` when the lane is empty.
   */
  wxStringRuntime* CopyMimeOrEmpty(wxStringRuntime* outValue) const;

protected:
  void SetDescriptor(
    const wchar_t* name, const wchar_t* extension, const wchar_t* mimeType, std::int32_t bitmapType
  ) noexcept;

private:
  static void ReleaseSharedWxString(wxStringRuntime& value) noexcept;

public:
  void* mRefData = nullptr;
  wxStringRuntime mName{};
  wxStringRuntime mExtension{};
  wxStringRuntime mMime{};
  std::int32_t mType = 0;
};

static_assert(offsetof(wxImageHandlerRuntime, mRefData) == 0x4, "wxImageHandlerRuntime::mRefData offset must be 0x4");
static_assert(offsetof(wxImageHandlerRuntime, mName) == 0x8, "wxImageHandlerRuntime::mName offset must be 0x8");
static_assert(
  offsetof(wxImageHandlerRuntime, mExtension) == 0xC,
  "wxImageHandlerRuntime::mExtension offset must be 0xC"
);
static_assert(offsetof(wxImageHandlerRuntime, mMime) == 0x10, "wxImageHandlerRuntime::mMime offset must be 0x10");
static_assert(offsetof(wxImageHandlerRuntime, mType) == 0x14, "wxImageHandlerRuntime::mType offset must be 0x14");
static_assert(sizeof(wxImageHandlerRuntime) == 0x18, "wxImageHandlerRuntime size must be 0x18");

class wxPngHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x0042B9E0 (FUN_0042B9E0)
   * Mangled: ??0wxPNGHandler@@QAE@XZ
   *
   * What it does:
   * Initializes the PNG handler descriptor (name, extension, mime, bitmap type).
   */
  wxPngHandlerRuntime();

  /**
   * Address: 0x0042BA50 (FUN_0042BA50)
   * Mangled: ?GetClassInfo@wxPNGHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxPNGHandler runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x0042BA60 (FUN_0042BA60)
   *
   * What it does:
   * Deleting-dtor thunk lane for `wxPNGHandler`; no extra teardown beyond base.
   */
  ~wxPngHandlerRuntime() override;
};

static_assert(sizeof(wxPngHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxPngHandlerRuntime size must stay 0x18");

class wxBmpHandlerRuntime : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x00970250 (FUN_00970250, ??0wxBMPHandler@@QAE@XZ)
   * Mangled: ??0wxBMPHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one BMP handler descriptor lane (`"Windows bitmap file"`,
   * extension `"bmp"`, mime `"image/x-bmp"`, bitmap type `1`).
   */
  wxBmpHandlerRuntime();

  /**
   * Address: 0x009702D0 (FUN_009702D0)
   * Mangled: ?GetClassInfo@wxBMPHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxBMPHandler runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x009715F0 (FUN_009715F0)
   *
   * What it does:
   * Deleting-dtor thunk lane for `wxBMPHandler`; no extra teardown beyond base.
   */
  ~wxBmpHandlerRuntime() override;
};

static_assert(sizeof(wxBmpHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxBmpHandlerRuntime size must stay 0x18");

class wxXpmHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x009702F0 (FUN_009702F0, ??0wxXPMHandler@@QAE@XZ)
   * Mangled: ??0wxXPMHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one XPM handler descriptor lane (`"XPM file"`, extension
   * `"xpm"`, mime `"image/xpm"`, bitmap type `9`).
   */
  wxXpmHandlerRuntime();

  /**
   * Address: 0x00970370 (FUN_00970370)
   * Mangled: ?GetClassInfo@wxXPMHandler@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for wxXPMHandler runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x00971610 (FUN_00971610)
   *
   * What it does:
   * Deleting-dtor thunk lane for `wxXPMHandler`; no extra teardown beyond base.
   */
  ~wxXpmHandlerRuntime() override;
};

static_assert(sizeof(wxXpmHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxXpmHandlerRuntime size must stay 0x18");

class wxIcoHandlerRuntime : public wxBmpHandlerRuntime
{
public:
  /**
   * Address: 0x009D7E10 (FUN_009D7E10, ??0wxICOHandler@@QAE@XZ)
   * Mangled: ??0wxICOHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one ICO handler descriptor lane (`"Windows icon file"`,
   * extension `"ico"`, mime `"image/x-ico"`, bitmap type `3`).
   */
  wxIcoHandlerRuntime();
};

static_assert(sizeof(wxIcoHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxIcoHandlerRuntime size must stay 0x18");

class wxCurHandlerRuntime : public wxIcoHandlerRuntime
{
public:
  /**
   * Address: 0x009D7EB0 (FUN_009D7EB0, ??0wxCURHandler@@QAE@XZ)
   * Mangled: ??0wxCURHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one CUR handler descriptor lane (`"Windows cursor file"`,
   * extension `"cur"`, mime `"image/x-cur"`, bitmap type `5`).
   */
  wxCurHandlerRuntime();
};

static_assert(sizeof(wxCurHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxCurHandlerRuntime size must stay 0x18");

class wxAniHandlerRuntime final : public wxCurHandlerRuntime
{
public:
  /**
   * Address: 0x009D7F50 (FUN_009D7F50, ??0wxANIHandler@@QAE@XZ)
   * Mangled: ??0wxANIHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one ANI handler descriptor lane (`"Windows animated cursor file"`,
   * extension `"ani"`, mime `"image/x-ani"`, bitmap type `27`).
   */
  wxAniHandlerRuntime();
};

static_assert(sizeof(wxAniHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxAniHandlerRuntime size must stay 0x18");

class wxBmpFileHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x009AB120 (FUN_009AB120, ??0wxBMPFileHandler@@QAE@XZ)
   * Mangled: ??0wxBMPFileHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one BMP image-handler descriptor lane (`"Windows bitmap file"`,
   * extension `"bmp"`, bitmap type `1`) while preserving empty MIME lane
   * semantics from the base image-handler runtime constructor.
   */
  wxBmpFileHandlerRuntime();

  /**
   * Address: 0x009AB070 (FUN_009AB070)
   *
   * What it does:
   * Copies the shared handler display-name lane into `outValue`, or
   * `wxEmptyString` when no name is stored.
   */
  wxStringRuntime* CopyNameOrEmpty(wxStringRuntime* outValue) const;

  /**
   * Address: 0x009AB0B0 (FUN_009AB0B0)
   *
   * What it does:
   * Copies the shared handler extension lane into `outValue`, or
   * `wxEmptyString` when no extension is stored.
   */
  wxStringRuntime* CopyExtensionOrEmpty(wxStringRuntime* outValue) const;
};

static_assert(sizeof(wxBmpFileHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxBmpFileHandlerRuntime size must stay 0x18");

class wxBmpResourceHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x009AB240 (FUN_009AB240, ??0wxBMPResourceHandler@@QAE@XZ)
   * Mangled: ??0wxBMPResourceHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one BMP-resource handler descriptor lane
   * (`"Windows bitmap resource"`, empty extension, bitmap type `2`) using
   * `wxImageHandler` runtime storage.
   */
  wxBmpResourceHandlerRuntime();
};

static_assert(
  sizeof(wxBmpResourceHandlerRuntime) == sizeof(wxImageHandlerRuntime),
  "wxBmpResourceHandlerRuntime size must stay 0x18"
);

class wxIcoFileHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x009AB450 (FUN_009AB450, ??0wxICOFileHandler@@QAE@XZ)
   * Mangled: ??0wxICOFileHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one ICO-file handler descriptor lane (`"ICO icon file"`,
   * extension `"ico"`, bitmap type `3`) using wxImageHandler runtime storage.
   */
  wxIcoFileHandlerRuntime();
};

static_assert(sizeof(wxIcoFileHandlerRuntime) == sizeof(wxImageHandlerRuntime), "wxIcoFileHandlerRuntime size must stay 0x18");

class wxIcoResourceHandlerRuntime final : public wxImageHandlerRuntime
{
public:
  /**
   * Address: 0x009AB570 (FUN_009AB570, ??0wxICOResourceHandler@@QAE@XZ)
   * Mangled: ??0wxICOResourceHandler@@QAE@XZ
   *
   * What it does:
   * Initializes one ICO-resource handler descriptor lane (`"ICO resource"`,
   * extension `"ico"`, bitmap type `4`) using wxImageHandler runtime storage.
   */
  wxIcoResourceHandlerRuntime();
};

static_assert(
  sizeof(wxIcoResourceHandlerRuntime) == sizeof(wxImageHandlerRuntime),
  "wxIcoResourceHandlerRuntime size must stay 0x18"
);

/**
 * Minimal recovered `wxImage` runtime object lane.
 *
 * Keeps the wx ref-data pointer lane at `+0x4` and recovers the Create(width,
 * height) path used by image decode/load callsites.
 */
class wxImageRuntime
{
public:
  /**
   * Address: 0x00971670 (FUN_00971670)
   *
   * What it does:
   * Constructs one image runtime lane, clears shared ref-data ownership, and
   * allocates pixel storage via `Create(width, height)`.
   */
  wxImageRuntime(std::int32_t width, std::int32_t height);

  /**
   * Address: 0x00970540 (FUN_00970540)
   *
   * What it does:
   * Initializes one image object and shares ref-data ownership from `clone`.
   */
  wxImageRuntime(const wxImageRuntime& clone);

  virtual ~wxImageRuntime();

  /**
   * Address: 0x00970600 (FUN_00970600)
   * Mangled: ?Create@wxImage@@QAEXHH@Z
   *
   * What it does:
   * Releases existing image ref-data, allocates fresh ref-data storage, then
   * allocates/zeroes 24-bit RGB pixel storage for the requested dimensions.
   */
  void Create(std::int32_t width, std::int32_t height);

  /**
   * Address: 0x00972340 (FUN_00972340, wxImage::GetRed helper lane)
   *
   * What it does:
   * Returns the red byte at pixel `(x, y)` when this image and coordinates are
   * valid; otherwise returns `0`.
   */
  [[nodiscard]] std::uint8_t GetRed(std::int32_t x, std::int32_t y) const noexcept;

  /**
   * Address: 0x00972390 (FUN_00972390, wxImage::GetGreen helper lane)
   *
   * What it does:
   * Returns the green byte at pixel `(x, y)` when this image and coordinates
   * are valid; otherwise returns `0`.
   */
  [[nodiscard]] std::uint8_t GetGreen(std::int32_t x, std::int32_t y) const noexcept;

  /**
   * Address: 0x009723E0 (FUN_009723E0, wxImage::GetBlue helper lane)
   *
   * What it does:
   * Returns the blue byte at pixel `(x, y)` when this image and coordinates are
   * valid; otherwise returns `0`.
   */
  [[nodiscard]] std::uint8_t GetBlue(std::int32_t x, std::int32_t y) const noexcept;

  /**
   * Address: 0x009722D0 (FUN_009722D0)
   *
   * What it does:
   * Writes one RGB pixel lane at `(x, y)` when image ref-data and coordinates
   * are valid.
   */
  void SetRgb(
    std::int32_t x,
    std::int32_t y,
    std::uint8_t red,
    std::uint8_t green,
    std::uint8_t blue
  ) noexcept;

  /**
   * Address: 0x00970C10 (FUN_00970C10)
   *
   * What it does:
   * Returns whether this image owns valid ref-data and has one option entry
   * matching `optionName`.
   */
  [[nodiscard]] bool HasOption(const wxStringRuntime& optionName) const noexcept;

  /**
   * Address: 0x00972490 (FUN_00972490)
   *
   * What it does:
   * Looks up one image-option value by key and writes either the shared option
   * text lane or `wxEmptyString` into `outValue`.
   */
  wxStringRuntime* GetOptionValueOrEmpty(
    wxStringRuntime* outValue,
    const wchar_t* optionName
  ) const;

private:
  void ReleaseRefData() noexcept;

public:
  void* mRefData = nullptr;
};

static_assert(offsetof(wxImageRuntime, mRefData) == 0x4, "wxImageRuntime::mRefData offset must be 0x4");
static_assert(sizeof(wxImageRuntime) == 0x8, "wxImageRuntime size must be 0x8");

/**
 * A colour.
 *
 * The byte order is the binary's, not a convenient one: red, then blue, then
 * green. Two independent routes agree on it - wxWindow::OnEraseBackground
 * (0x00969F40) reads the window's background colour at +0x8D/+0x8E/+0x8F, and
 * wxWindow::OnSysColourChanged (0x00969B80) writes that same colour as the
 * object at window+0x80, which puts red at +0x0D within it.
 *
 * The packed lane is what GDI is handed, and it is a PALETTERGB rather than an
 * RGB - the 0x02000000 asks for the nearest entry in the logical palette.
 */
struct wxColourRuntime
{
  std::uint8_t mReserved00To07[0x08]{}; // +0x00 wxObject head, not mapped
  std::uint32_t mPackedNativeColour = 0; // +0x08 PALETTERGB(red, green, blue)
  std::uint8_t mIsInit = 0;              // +0x0C
  std::uint8_t mRed = 0;                 // +0x0D
  std::uint8_t mBlue = 0;                // +0x0E
  std::uint8_t mGreen = 0;               // +0x0F

  [[nodiscard]] static wxColourRuntime FromRgb(
    std::uint8_t red, std::uint8_t green, std::uint8_t blue
  ) noexcept;
  [[nodiscard]] static const wxColourRuntime& Null() noexcept;

  [[nodiscard]] std::uint8_t Red() const noexcept { return mRed; }
  [[nodiscard]] std::uint8_t Green() const noexcept { return mGreen; }
  [[nodiscard]] std::uint8_t Blue() const noexcept { return mBlue; }
  [[nodiscard]] bool IsSet() const noexcept { return mIsInit != 0; }
};

static_assert(
  offsetof(wxColourRuntime, mPackedNativeColour) == 0x08,
  "wxColourRuntime::mPackedNativeColour offset must be 0x08"
);
static_assert(offsetof(wxColourRuntime, mIsInit) == 0x0C, "wxColourRuntime::mIsInit offset must be 0x0C");
static_assert(offsetof(wxColourRuntime, mRed) == 0x0D, "wxColourRuntime::mRed offset must be 0x0D");
static_assert(offsetof(wxColourRuntime, mBlue) == 0x0E, "wxColourRuntime::mBlue offset must be 0x0E");
static_assert(offsetof(wxColourRuntime, mGreen) == 0x0F, "wxColourRuntime::mGreen offset must be 0x0F");
static_assert(sizeof(wxColourRuntime) == 0x10, "wxColourRuntime size must be 0x10");


/**
 * A mouse cursor.
 *
 * Like the palette, the native handle lives in shared reference data so copies
 * name one HCURSOR. Offsets are off wxWindow::HandleSetCursor (0x00969500),
 * which reads the reference data at +0x04 and the handle at +0x14 within it;
 * wxCursor::Ok (0x004FB7B0) tests the same pair.
 */
struct wxCursorRefDataRuntime
{
  std::uint8_t mReserved00To13[0x14]{}; // +0x00, not mapped
  void* mNativeCursor = nullptr;        // +0x14
};

static_assert(
  offsetof(wxCursorRefDataRuntime, mNativeCursor) == 0x14,
  "wxCursorRefDataRuntime::mNativeCursor offset must be 0x14"
);

struct wxCursorRuntime
{
  void* mVTable = nullptr;                    // +0x00
  wxCursorRefDataRuntime* mRefData = nullptr; // +0x04
  std::uint8_t mReserved08[0x4]{};            // +0x08

  /**
   * Address: 0x004FB7B0 (FUN_004FB7B0)
   *
   * What it does:
   * Whether this cursor names a real one - reference data with a handle in it.
   */
  [[nodiscard]] bool Ok() const noexcept
  {
    return mRefData != nullptr && mRefData->mNativeCursor != nullptr;
  }

  [[nodiscard]] void* GetNativeCursor() const noexcept
  {
    return mRefData != nullptr ? mRefData->mNativeCursor : nullptr;
  }
};

static_assert(offsetof(wxCursorRuntime, mRefData) == 0x04, "wxCursorRuntime::mRefData offset must be 0x04");
static_assert(sizeof(wxCursorRuntime) == 0xC, "wxCursorRuntime size must be 0xC");

struct wxFontRuntime
{
  std::uint8_t mStorage[0xC]{};

  [[nodiscard]] static const wxFontRuntime& Null() noexcept;
};

static_assert(sizeof(wxFontRuntime) == 0xC, "wxFontRuntime size must be 0xC");

/**
 * Text style object used by `WWinLogWindow` output-color paths.
 *
 * Evidence:
 * - `FUN_004F36A0` constructs:
 *   - foreground `wxColour` at `+0x00`
 *   - background `wxColour` at `+0x10`
 *   - font `wxFont` at `+0x20`
 * - `FUN_004F63B0` destroys the same lanes in reverse order.
 */
struct wxTextAttrRuntime
{
  /**
   * Address: 0x0099A130 (FUN_0099A130, ??0wxTextAttr@@QAE@@Z)
   *
   * What it does:
   * Default-initializes foreground/background colour lanes and font lane for
   * one text-style payload.
   */
  wxTextAttrRuntime();

  /**
   * Address: 0x004F36A0 (FUN_004F36A0)
   *
   * What it does:
   * Initializes text-style lanes from foreground/background/font values.
   */
  wxTextAttrRuntime(
    const wxColourRuntime& foreground, const wxColourRuntime& background, const wxFontRuntime& font
  );

  /**
   * Address: 0x004F63B0 (FUN_004F63B0)
   *
   * What it does:
   * Tears down style lanes in reverse subobject order.
   */
  ~wxTextAttrRuntime();

  wxColourRuntime mForegroundColour{};
  wxColourRuntime mBackgroundColour{};
  wxFontRuntime mFont{};
};

static_assert(
  offsetof(wxTextAttrRuntime, mForegroundColour) == 0x0,
  "wxTextAttrRuntime::mForegroundColour offset must be 0x0"
);
static_assert(
  offsetof(wxTextAttrRuntime, mBackgroundColour) == 0x10,
  "wxTextAttrRuntime::mBackgroundColour offset must be 0x10"
);
static_assert(offsetof(wxTextAttrRuntime, mFont) == 0x20, "wxTextAttrRuntime::mFont offset must be 0x20");
static_assert(sizeof(wxTextAttrRuntime) == 0x2C, "wxTextAttrRuntime size must be 0x2C");

enum wxListKeyTypeRuntime : std::int32_t
{
  wxKEY_NONE_RUNTIME = 0,
  wxKEY_INTEGER_RUNTIME = 1,
  wxKEY_STRING_RUNTIME = 2,
};

struct wxListKeyRuntime
{
  wxListKeyTypeRuntime mKeyType = wxKEY_NONE_RUNTIME;
  union
  {
    std::uintptr_t integer;
    const wchar_t* string;
  } mKey{};
};

static_assert(offsetof(wxListKeyRuntime, mKeyType) == 0x0, "wxListKeyRuntime::mKeyType offset must be 0x0");
static_assert(offsetof(wxListKeyRuntime, mKey) == 0x4, "wxListKeyRuntime::mKey offset must be 0x4");
static_assert(sizeof(wxListKeyRuntime) == 0x8, "wxListKeyRuntime size must be 0x8");

/**
 * Recovered `wxNodeBase` runtime projection.
 */
class wxNodeBaseRuntime
{
public:
  virtual ~wxNodeBaseRuntime() = default;

  std::uintptr_t mKeyStorage = 0;
  void* mValue = nullptr;
  wxNodeBaseRuntime* mNext = nullptr;
  wxNodeBaseRuntime* mPrevious = nullptr;
  void* mListOwner = nullptr;
};

static_assert(offsetof(wxNodeBaseRuntime, mKeyStorage) == 0x4, "wxNodeBaseRuntime::mKeyStorage offset must be 0x4");
static_assert(offsetof(wxNodeBaseRuntime, mValue) == 0x8, "wxNodeBaseRuntime::mValue offset must be 0x8");
static_assert(offsetof(wxNodeBaseRuntime, mNext) == 0xC, "wxNodeBaseRuntime::mNext offset must be 0xC");
static_assert(offsetof(wxNodeBaseRuntime, mPrevious) == 0x10, "wxNodeBaseRuntime::mPrevious offset must be 0x10");
static_assert(offsetof(wxNodeBaseRuntime, mListOwner) == 0x14, "wxNodeBaseRuntime::mListOwner offset must be 0x14");
static_assert(sizeof(wxNodeBaseRuntime) == 0x18, "wxNodeBaseRuntime size must be 0x18");

/**
 * Address: 0x00978190 (FUN_00978190, func_wxNodeBaseInit)
 *
 * What it does:
 * Initializes one `wxNodeBase` node with key/data/owner lanes and links it
 * between optional neighboring nodes.
 */
wxNodeBaseRuntime* wxNodeBaseInit(
  wxNodeBaseRuntime* node,
  void* listOwner,
  wxNodeBaseRuntime* previous,
  wxNodeBaseRuntime* next,
  void* value,
  const wxListKeyRuntime* key
);

/**
 * Recovered `wxListItemAttr` runtime projection.
 *
 * Evidence:
 * - `FUN_00980B70` destroys two `wxColour` lanes at `+0x00/+0x10` and one
 *   `wxFont` lane at `+0x20`.
 */
struct wxListItemAttrRuntime
{
  /**
   * Address: 0x009834F0 (FUN_009834F0)
   *
   * What it does:
   * Constructs one list-item-attribute payload by default-constructing text
   * colour, background colour, and font member lanes.
   */
  wxListItemAttrRuntime();

  /**
   * Address: 0x00987E70 (FUN_00987E70)
   *
   * What it does:
   * Copy-constructs one `wxListItemAttrRuntime` by invoking the subobject copy
   * constructors for the two `wxColour` lanes and the `wxFont` lane in source
   * order; SEH unwind guards tear down already-built lanes on exception.
   */
  wxListItemAttrRuntime(const wxListItemAttrRuntime& other);

  wxColourRuntime mTextColour{};
  wxColourRuntime mBackgroundColour{};
  wxFontRuntime mFont{};
};

static_assert(
  offsetof(wxListItemAttrRuntime, mTextColour) == 0x0,
  "wxListItemAttrRuntime::mTextColour offset must be 0x0"
);
static_assert(
  offsetof(wxListItemAttrRuntime, mBackgroundColour) == 0x10,
  "wxListItemAttrRuntime::mBackgroundColour offset must be 0x10"
);
static_assert(
  offsetof(wxListItemAttrRuntime, mFont) == 0x20,
  "wxListItemAttrRuntime::mFont offset must be 0x20"
);
static_assert(sizeof(wxListItemAttrRuntime) == 0x2C, "wxListItemAttrRuntime size must be 0x2C");

/**
 * Recovered `wxListItem` runtime object used by `wxListCtrl` get/set-item
 * paths.
 *
 * Evidence:
 * - `FUN_00987D00` destroys optional attribute storage from `+0x30`.
 * - `FUN_00987D00` releases the shared `wxString` payload at `+0x1C`.
 * - `FUN_009880E0` (`wxListEvent::~wxListEvent`) destroys embedded list-item
 *   payloads.
 */
class wxListItemRuntime
{
public:
  wxListItemRuntime();

  /**
   * Address: 0x00987EE0 (FUN_00987EE0, ??0wxListItem@@QAE@ABV0@@Z)
   * Mangled: ??0wxListItem@@QAE@ABV0@@Z
   *
   * What it does:
   * Copies one list-item payload lane, retaining shared string ownership and
   * deep-copying optional attribute storage when present.
   */
  wxListItemRuntime(const wxListItemRuntime& source);

  /**
   * Address: 0x00987D00 (FUN_00987D00, ??1wxListItem@@QAE@@Z)
   * Mangled: ??1wxListItem@@QAE@@Z
   *
   * What it does:
   * Releases optional list-item attribute storage, releases shared string
   * payload ownership, and clears base wxObject ref-data ownership lanes.
   */
  virtual ~wxListItemRuntime();

  /**
   * Address: 0x0099C000 (FUN_0099C000)
   *
   * What it does:
   * Lazily allocates and constructs this list-item's optional attribute
   * payload lane.
   */
  [[nodiscard]] wxListItemAttrRuntime* EnsureAttributeStorage();

  void* mRefData = nullptr;
  std::int32_t mMask = 0;
  std::int32_t mItemId = 0;
  std::int32_t mColumn = 0;
  std::int32_t mState = 0;
  std::int32_t mStateMask = 0;
  wxStringRuntime mText = wxStringRuntime::Borrow(L"");
  std::int32_t mImage = -1;
  long mData = 0;
  std::int32_t mWidth = -1;
  std::int32_t mFormat = 0;
  wxListItemAttrRuntime* mAttr = nullptr;
};

static_assert(
  offsetof(wxListItemRuntime, mRefData) == 0x4,
  "wxListItemRuntime::mRefData offset must be 0x4"
);
static_assert(
  offsetof(wxListItemRuntime, mText) == 0x1C,
  "wxListItemRuntime::mText offset must be 0x1C"
);
static_assert(
  offsetof(wxListItemRuntime, mAttr) == 0x30,
  "wxListItemRuntime::mAttr offset must be 0x30"
);
static_assert(sizeof(wxListItemRuntime) == 0x34, "wxListItemRuntime size must be 0x34");

class wxListCtrlRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x0099C480 (FUN_0099C480, xListCtrl::GetItem)
   *
   * What it does:
   * Populates one `wxListItem` payload lane for the requested row.
   */
  [[nodiscard]] virtual bool GetItem(wxListItemRuntime* item);

  /**
   * Address: 0x0099D120 (FUN_0099D120, wxListCtrl::GetItemData)
   *
   * What it does:
   * Requests one list row through `GetItem` and returns the row user-data lane
   * when available.
   */
  [[nodiscard]] long GetItemData(std::int32_t itemId);

  /**
   * Address: 0x0099D5A0 (FUN_0099D5A0, wxListCtrl::FindItem)
   *
   * What it does:
   * Scans forward from `startItem + 1` and returns the first row whose
   * user-data lane equals `itemData`, or `-1` when no row matches.
   */
  [[nodiscard]] long FindItem(std::int32_t startItem, long itemData);

  /**
   * Address: 0x0099B520 (FUN_0099B520, wxListCtrl::EnsureVisible)
   *
   * What it does:
   * Requests native list-view scrolling so row `itemId` becomes visible.
   */
  [[nodiscard]] bool EnsureVisible(std::int32_t itemId) const;

  /**
   * Address: 0x0099C440 (FUN_0099C440, wxListCtrl::SetColumn)
   *
   * What it does:
   * Converts one `wxListItem` column descriptor into a Win32 `LVCOLUMNW`
   * payload and sends `LVM_SETCOLUMNW` for the requested column index.
   */
  [[nodiscard]] bool SetColumn(std::uint32_t columnIndex, const wxListItemRuntime& item);
};

class wxCheckBoxRuntime : public wxControlRuntime
{
public:
  // Registers itself with wxClassInfo so a kind-of test can recognise it.
  static wxClassInfo sm_classInfo;

  /**
   * Address: 0x009ACBE0 (slot 134 in `wxCheckBox`)
   * Mangled: ?SetValue@wxCheckBox@@UAEX_N@Z
   */
  virtual void SetValue(bool checked)
  {
    (void)checked;
  }

  /**
   * Address: 0x009ACC00 (slot 135 in `wxCheckBox`)
   * Mangled: ?GetValue@wxCheckBox@@UBE_NXZ
   */
  [[nodiscard]] virtual bool GetValue() const { return false; }
};

static_assert(sizeof(wxCheckBoxRuntime) == 0x4, "wxCheckBoxRuntime size must be 0x4");

class wxTextCtrlRuntime : public wxControlRuntime
{
public:
  // Registers itself with wxClassInfo so a kind-of test can recognise it.
  static wxClassInfo sm_classInfo;

  /**
   * Address: 0x00993670 (FUN_00993670)
   * Mangled: ?AdoptAttributesFromHWND@wxTextCtrl@@UAEXXZ
   *
   * What it does:
   * Extends base HWND style adoption with text-control specific style flags and
   * RichEdit version probing from class name.
   */
  void AdoptAttributesFromHWND() override;

  /**
   * Address: 0x00994510 (FUN_00994510)
   * Mangled: ?OnCtlColor@wxTextCtrl@@UAEKKKIIIJ@Z
   *
   * What it does:
   * Applies text-control background/foreground paint lanes for one ctl-color
   * request and returns the brush handle to use.
   */
  unsigned long OnCtlColor(
    unsigned long hdc,
    unsigned long hwnd,
    unsigned int nCtlColor,
    unsigned int message,
    unsigned int controlId,
    long result
  ) override;

  /**
   * Address: 0x009938A0 (slot 134 in `wxTextCtrl`)
   * Mangled: ?GetValue@wxTextCtrl@@UBE?AVwxString@@XZ
   */
  [[nodiscard]] virtual wxStringRuntime GetValue() const { return wxStringRuntime{}; }

  /**
   * Address: 0x009962A0 (slot 135 in `wxTextCtrl`)
   * Mangled: ?SetValue@wxTextCtrl@@UAEXABVwxString@@@Z
   */
  virtual void SetValue(const wxStringRuntime& value) { (void)value; }

  virtual void TextCtrlSlot136() {}
  virtual void TextCtrlSlot137() {}
  virtual void TextCtrlSlot138() {}
  virtual void TextCtrlSlot139() {}
  virtual void TextCtrlSlot140() {}
  virtual void TextCtrlSlot141() {}
  virtual void TextCtrlSlot142() {}
  virtual void TextCtrlSlot143() {}
  virtual void TextCtrlSlot144() {}
  virtual void TextCtrlSlot145() {}
  virtual void TextCtrlSlot146() {}
  virtual void TextCtrlSlot147() {}
  virtual void TextCtrlSlot148() {}
  virtual void TextCtrlSlot149() {}
  virtual void TextCtrlSlot150() {}

  /**
   * Address: 0x009938D0 (slot 151 in `wxTextCtrl`)
   * Mangled: ?AppendText@wxTextCtrl@@UAEXABVwxString@@@Z
   */
  virtual void AppendText(const wxStringRuntime& text) { (void)text; }

  virtual void TextCtrlSlot152() {}
  virtual void TextCtrlSlot153() {}

  /**
   * Address: 0x009954C0 (slot 154 in `wxTextCtrl`)
   * Mangled: ?SetDefaultStyle@wxTextCtrl@@UAE_NABVwxTextAttr@@@Z
   */
  [[nodiscard]] virtual bool SetDefaultStyle(const wxTextAttrRuntime& style)
  {
    (void)style;
    return false;
  }

  virtual void TextCtrlSlot155() {}
  virtual void TextCtrlSlot156() {}
  virtual void TextCtrlSlot157() {}

  /**
   * Address: 0x00993F90 (slot 158 in `wxTextCtrl`)
   * Mangled: ?ShowPosition@wxTextCtrl@@UAEXJ@Z
   */
  virtual void ShowPosition(std::int32_t position) { (void)position; }

  virtual void TextCtrlSlot159() {}
  virtual void TextCtrlSlot160() {}
  virtual void TextCtrlSlot161() {}
  virtual void TextCtrlSlot162() {}
  virtual void TextCtrlSlot163() {}
  virtual void TextCtrlSlot164() {}
  virtual void TextCtrlSlot165() {}
  virtual void TextCtrlSlot166() {}
  virtual void TextCtrlSlot167() {}
  virtual void TextCtrlSlot168() {}
  virtual void TextCtrlSlot169() {}
  virtual void TextCtrlSlot170() {}
  virtual void TextCtrlSlot171() {}

  /**
   * Address: 0x00995F30 (slot 172 in `wxTextCtrl`)
   * Mangled: ?GetLastPosition@wxTextCtrl@@UBEJXZ
   */
  [[nodiscard]] virtual std::int32_t GetLastPosition() const { return 0; }

  virtual void TextCtrlSlot173() {}
  virtual void TextCtrlSlot174() {}
  virtual void TextCtrlSlot175() {}

  [[nodiscard]] msvc8::string GetValueUtf8() const;
  [[nodiscard]] msvc8::string GetValueUtf8Lower() const;
  void SetValueUtf8(const msvc8::string& value);
  void AppendUtf8(const msvc8::string& text);
  void AppendWide(const std::wstring& text);
  void ScrollToLastPosition();
};

static_assert(sizeof(wxTextCtrlRuntime) == 0x4, "wxTextCtrlRuntime size must be 0x4");

/**
 * One loaded icon.
 *
 * The binary keeps this behind a ref-counted wxGDIImageRefData: width at
 * +0x08, height at +0x0C, depth at +0x10 and the HICON at +0x14. That is the
 * layout wxICOResourceHandler::Load (0x009ABE80) writes and the one
 * wxIconBundle::GetIcon (0x009F2FE0), wxIcon::Ok (0x004FB7B0),
 * wxIcon::GetWidth (0x004FB7D0) and wxIcon::GetHeight (0x004FB7E0) read back.
 *
 * This tree does not lay wx objects out to match the binary - wxWindowBase
 * already keeps its state in a map beside the object - so the three fields the
 * icon path actually uses are held directly and the binary offsets are
 * recorded here rather than asserted. Nothing reads them by offset.
 */
class wxIcon
{
public:
  wxIcon() = default;

  /**
   * Address: 0x009AA610 (FUN_009AA610)
   * Mangled: ??0wxIcon@@QAE@ABVwxString@@HHH@Z
   *
   * IDA signature:
   * wxIcon *__thiscall wxIcon::wxIcon(wxIcon *this, int a2, int a3, int a4,
   *                                   int a5);
   *
   * What it does:
   * Starts empty and immediately loads: this is the form
   * WSupComFrame's constructor uses, as
   * wxIcon(L"IDI_WIN_FAICON", wxBITMAP_TYPE_ICO_RESOURCE, -1, -1).
   */
  wxIcon(
    const wchar_t* resourceName,
    std::int32_t bitmapType,
    std::int32_t desiredWidth = -1,
    std::int32_t desiredHeight = -1
  );

  /**
   * Address: 0x009AA540 (FUN_009AA540)
   *
   * What it does:
   * Drops whatever was loaded, finds the handler registered for this bitmap
   * type, and lets it load. No handler for the type means no icon.
   */
  bool LoadFile(
    const wchar_t* resourceName,
    std::int32_t bitmapType,
    std::int32_t desiredWidth,
    std::int32_t desiredHeight
  );

  /** Address: 0x004FB7B0 (FUN_004FB7B0) - refData present and its handle set. */
  [[nodiscard]] bool Ok() const noexcept { return mNativeIcon != 0UL; }

  /** Address: 0x004FB7D0 (FUN_004FB7D0) - refData +0x08. */
  [[nodiscard]] std::int32_t GetWidth() const noexcept { return mWidth; }

  /** Address: 0x004FB7E0 (FUN_004FB7E0) - refData +0x0C. */
  [[nodiscard]] std::int32_t GetHeight() const noexcept { return mHeight; }

  /** refData +0x14. */
  [[nodiscard]] unsigned long GetNativeIcon() const noexcept { return mNativeIcon; }

  /**
   * What it does:
   * Takes ownership lanes from a handler that has just loaded one - the
   * assignment wxICOResourceHandler::Load makes to refData +0x08/+0x0C/+0x14.
   */
  void AdoptNativeIcon(unsigned long nativeIcon, std::int32_t width, std::int32_t height) noexcept;

private:
  std::int32_t mWidth = 0;        // wxGDIImageRefData +0x08
  std::int32_t mHeight = 0;       // wxGDIImageRefData +0x0C
  unsigned long mNativeIcon = 0;  // wxGDIImageRefData +0x14
};

/**
 * The set of sizes one icon is available in. A frame keeps one so it can
 * answer both halves of WM_SETICON from whatever the application supplied.
 */
class wxIconBundle
{
public:
  wxIconBundle() = default;

  /**
   * Address: 0x0098BEC0 (FUN_0098BEC0)
   *
   * What it does:
   * The single-icon bundle wxTopLevelWindowMSW::SetIcon builds before handing
   * the work to SetIcons.
   */
  explicit wxIconBundle(const wxIcon& icon);

  /**
   * Address: 0x009F3220 (FUN_009F3220)
   *
   * What it does:
   * Adds an icon, replacing whichever entry already has the same width and
   * height rather than letting a size appear twice.
   */
  void AddIcon(const wxIcon& icon);

  /**
   * Address: 0x009F2FE0 (FUN_009F2FE0)
   *
   * What it does:
   * Picks the icon for a requested size: an exact match if the bundle has one,
   * otherwise the one matching the system icon metric, otherwise the first.
   * An empty bundle answers with an empty icon.
   */
  [[nodiscard]] wxIcon GetIcon(std::int32_t width, std::int32_t height) const;

  [[nodiscard]] bool IsEmpty() const noexcept { return mIcons.empty(); }

private:
  msvc8::vector<wxIcon> mIcons;
};

class wxTopLevelWindowRuntime : public wxWindowMswRuntime
{
public:
  /**
   * Address: 0x004A3710 (FUN_004A3710)
   * Mangled: ??0wxTopLevelWindowMSW@@QAE@@Z
   *
   * What it does:
   * Constructs one top-level-window runtime base lane and resets fullscreen
   * state bookkeeping.
   */
  wxTopLevelWindowRuntime();

  /**
   * Address: 0x0098C280 (FUN_0098C280, wxTopLevelWindowMSW::Show)
   * Mangled: ?Show@wxTopLevelWindowMSW@@UAE_N_N@Z
   *
   * What it does:
   * Applies base visibility toggle and promotes this window (or parent on
   * hide) in Z-order when a native handle lane is available.
   */
  bool Show(bool show) override;

  /**
   * Address: 0x0098CAB0 (FUN_0098CAB0, wxTopLevelWindowMSW::MSWGetParent)
   * Mangled: ?MSWGetParent@wxTopLevelWindowMSW@@UBEKXZ
   *
   * What it does:
   * Picks the owner window for ::CreateWindowExW. Null for an ordinary frame -
   * an owned top-level window is pinned above its owner and gets no taskbar
   * button of its own. The hidden module window is returned only for a
   * wxFRAME_NO_TASKBAR frame, where suppressing that button is the point.
   */
  [[nodiscard]] unsigned long MSWGetParent() const override;

  /**
   * Address: 0x0098C050 (FUN_0098C050)
   * Mangled: ?MSWGetStyle@wxTopLevelWindowMSW@@MBEKJPAK@Z
   *
   * What it does:
   * Translates a top-level window's wx style into the Win32 style pair. Unlike
   * the child-window version this decides the frame furniture - caption,
   * sizing border, min/max boxes, system menu - and the initial minimised or
   * maximised state.
   */
  [[nodiscard]] unsigned long MSWGetStyle(long style, unsigned long* extendedStyle) const;

  /**
   * Address: 0x0098C160 (FUN_0098C160, wxTopLevelWindowMSW::CreateFrame)
   *
   * What it does:
   * Creates the native window behind a frame, with the styles this class
   * computes rather than the child-window ones.
   */
  bool CreateFrame(const wchar_t* title, const wxPoint& position, const wxSize& size);

  /**
   * Address: 0x0098CD30 (FUN_0098CD30, wxTopLevelWindow::Create)
   *
   * What it does:
   * Creates a top-level window: common state, registration in the top-level
   * window list, then the native frame.
   */
  bool Create(
    wxWindowBase* parent,
    std::int32_t id,
    const wchar_t* title,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x0098C760 (FUN_0098C760)
   *
   * What it does:
   * Enables or disables the native system-menu Close command, then redraws the
   * menu bar when the command-state update succeeds.
   */
  bool SetSystemCloseMenuItemEnabled(bool enabled);

  /**
   * Address: 0x0098C390 (FUN_0098C390, wxTopLevelWindowMSW::Maximize)
   * Mangled: ?Maximize@wxTopLevelWindowMSW@@UAEX_N@Z
   *
   * What it does:
   * Maximises or restores the frame when it is already on screen; otherwise
   * parks the request in `maximizeOnShow` for the next `Show(true)` to apply.
   */
  virtual void Maximize(bool maximize);

  virtual void Restore() {}

  /**
   * Address: 0x0098C3E0 (FUN_0098C3E0, wxTopLevelWindowMSW::Iconize)
   * Mangled: ?Iconize@wxTopLevelWindowMSW@@UAEX_N@Z
   *
   * What it does:
   * Minimises or restores the frame through `DoShowWindow`.
   */
  virtual void Iconize(bool iconize);

  /**
   * Address: 0x0098C400 (FUN_0098C400)
   * Mangled: ?IsIconized@wxTopLevelWindowMSW@@UBE_NXZ
   *
   * IDA signature:
   * bool __thiscall wxTopLevelWindowMSW::IsIconized(wxTopLevelWindowMSW *this);
   *
   * What it does:
   * Asks Windows whether the frame is minimised and caches the answer in
   * `m_iconized`. The state is read from the window, never from a flag this
   * process wrote - a minimise the user performed with the caption button
   * has to be observable too.
   */
  [[nodiscard]] virtual bool IsIconized() const;

  /**
   * Address: 0x0098C3C0 (FUN_0098C3C0)
   * Mangled: ?IsMaximized@wxTopLevelWindowMSW@@UBE_NXZ
   *
   * IDA signature:
   * BOOL __thiscall wxTopLevelWindowMSW::IsMaximized(wxTopLevelWindowMSW *this);
   *
   * What it does:
   * Asks Windows whether the frame is maximised.
   */
  [[nodiscard]] virtual bool IsMaximized() const;
  /**
   * Address: 0x0098C640 (FUN_0098C640)
   * Mangled: ?SetIcon@wxTopLevelWindowMSW@@UAEXABVwxIcon@@@Z
   *
   * IDA signature:
   * int __thiscall wxTopLevelWindowMSW::SetIcon(wxTopLevelWindowMSW *this,
   *                                             const struct wxIcon *a2);
   *
   * What it does:
   * Wraps the icon in a one-entry bundle and hands it to SetIcons, which is
   * the only thing that talks to the window.
   */
  virtual void SetIcon(const wxIcon& icon);

  /**
   * Address: 0x0098C6B0 (FUN_0098C6B0)
   * Mangled: ?SetIcons@wxTopLevelWindowMSW@@UAEXABVwxIconBundle@@@Z
   *
   * IDA signature:
   * wxObjectRefData *__thiscall wxTopLevelWindowMSW::SetIcons(
   *     wxTopLevelWindowMSW *this, wxArrayDCInfo *arg0);
   *
   * What it does:
   * Keeps the bundle, then sets the small and large window icons from it -
   * but only from an entry that is *exactly* 16x16 and 32x32 respectively.
   * The frame's own icon is loaded at the default size, so in practice only
   * the large one is set and Windows scales the caption icon down from it.
   */
  virtual void SetIcons(const wxIconBundle& icons);

  /**
   * Address: 0x0098BFA0 (FUN_0098BFA0)
   *
   * What it does:
   * The bundle's answer for "no particular size", which is how the frame's
   * icon is asked for when something needs one and does not care.
   */
  [[nodiscard]] virtual wxIcon GetIcon() const;
  virtual bool ShowFullScreen(bool show, long style)
  {
    (void)show;
    (void)style;
    return false;
  }

  /**
   * Address: 0x0098C250 (FUN_0098C250, wxTopLevelWindowMSW::DoShowWindow)
   *
   * IDA signature:
   * BOOL __thiscall wxTopLevelWindowMSW::DoShowWindow(int this, int nCmdShow);
   *
   * What it does:
   * Hands `nCmdShow` to `::ShowWindow` for this frame's native handle and
   * records whether the command minimised it. Every visibility change in this
   * class goes through here - Show, Maximize, Iconize and Restore all funnel
   * into it, and it is the only place the native window is actually shown.
   */
  bool DoShowWindow(std::int32_t showCommand);

  /**
   * Address: 0x004A3770 (FUN_004A3770)
   * Mangled: ?IsFullScreen@wxTopLevelWindowMSW@@UBE_NXZ
   *
   * What it does:
   * Returns one cached fullscreen-visible flag.
   */
  [[nodiscard]] bool IsFullScreen() const;

  /**
   * Address: 0x004A3700 (FUN_004A3700)
   * Mangled: ?IsOneOfBars@wxTopLevelWindowBase@@MBE_NPBVwxWindow@@@Z
   *
   * What it does:
   * Base implementation reports the queried window as not one of frame bars.
   */
  [[nodiscard]] virtual bool IsOneOfBars(const void* window) const;

  /**
   * Address: 0x004A36F0 (FUN_004A36F0)
   * Mangled: ?IsTopLevel@wxTopLevelWindowBase@@UBE_NXZ
   *
   * What it does:
   * Reports this runtime lane as a top-level wx window.
   */
  [[nodiscard]] bool IsTopLevel() const override;

  /**
   * Address: 0x0098C8C0 (FUN_0098C8C0)
   * Mangled: ?OnActivate@wxTopLevelWindowMSW@@IAEXAAVwxActivateEvent@@@Z
   *
   * What it does:
   * Remembers which child had the focus when the window is deactivated, and
   * puts it back when the window is activated again.
   */
  void OnActivate(wxEventRuntime& activateEvent);

  /**
   * Address: 0x0098C900 (FUN_0098C900)
   * Mangled: ?GetEventTable@wxTopLevelWindowMSW@@MBEPBUwxEventTable@@XZ
   */
  [[nodiscard]] const void* GetEventTable() const override;

  static wxEventTable sm_eventTable;

  /**
   * Address: 0x0099F4B0 (FUN_0099F4B0)
   * Mangled: ?MSWWindowProc@wxFrame@@UAEJIIJ@Z
   *
   * IDA signature:
   * wxWindow *__thiscall wxFrame::MSWWindowProc(wxWindow *this,
   *     enum_AllMessages message, HWND hWnd, unsigned int a5);
   *
   * What it does:
   * Translates the messages a frame answers for into wx events, and hands
   * everything else to wxWindow::MSWWindowProc.
   *
   * This is wxFrame's slot. The binary's chain is
   * WSupComFrame -> wxFrame -> wxWindow; this tree has no wxFrame class
   * between the top-level window and the SupCom frame, so the row lives here,
   * which is exactly where WSupComFrame::MSWWindowProc already forwards.
   *
   * Only WM_CLOSE is translated so far. The binary's switch also covers
   * WM_MENUSELECT, WM_ENTERMENULOOP/WM_EXITMENULOOP, WM_COMMAND, WM_SIZE,
   * WM_PAINT and WM_QUERYDRAGICON; those want the menu-event, frame-layout and
   * icon-bundle machinery and are still to come. Until then they fall through
   * exactly as an unhandled message should.
   */
  long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

  /**
   * Address: 0x0099F410 (FUN_0099F410)
   *
   * What it does:
   * Raises wxEVT_MENU_OPEN / wxEVT_MENU_CLOSE at the window's event handler
   * for the WM_ENTERMENULOOP / WM_EXITMENULOOP bookends, and reports whether
   * the handler took the event.
   */
  bool DoSendMenuOpenCloseEvent(std::int32_t eventType, bool isPopup);

  /**
   * Address: 0x0099F0A0 (FUN_0099F0A0)
   * Mangled: ?HandlePaint@wxFrame@@IAE_NXZ
   *
   * What it does:
   * Answers WM_PAINT. A frame that is not minimised paints through
   * wxWindow; a minimised one draws its icon centred in the client area.
   */
  bool HandlePaint();

  /**
   * Address: 0x0099F040 (FUN_0099F040)
   * Mangled: ?GetDefaultIcon@wxFrame@@MBEKXZ
   *
   * What it does:
   * The icon a frame falls back to when its own bundle has nothing
   * usable: the standard frame icon, or the default one when unset.
   */
  [[nodiscard]] virtual unsigned long GetDefaultIcon() const;

  /**
   * Address: 0x004A3780 (FUN_004A3780)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for top-level-window runtime
   * lanes.
   */
  static wxTopLevelWindowRuntime* DeleteWithFlag(wxTopLevelWindowRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  /**
   * Address: 0x004A36E0 (FUN_004A36E0)
   *
   * What it does:
   * Resets one top-level-window runtime flag lane.
   */
  void ResetTopLevelFlag34() noexcept;
};

static_assert(sizeof(wxWindowBase) == 0x4, "wxWindowBase size must be 0x4");
static_assert(sizeof(wxTopLevelWindowRuntime) == 0x4, "wxTopLevelWindowRuntime size must be 0x4");

/**
 * Minimal recovered `wxTopLevelWindow` runtime lane used for shared class-info
 * ownership.
 */
class wxTopLevelWindowRootRuntime : public wxTopLevelWindowRuntime
{
public:
  /**
   * Address: 0x004A37A0 (FUN_004A37A0)
   * Mangled: ??0wxTopLevelWindow@@QAE@@Z
   *
   * What it does:
   * Constructs one `wxTopLevelWindow` runtime layer and reapplies base
   * top-level init.
   */
  wxTopLevelWindowRootRuntime();

  /**
   * Address: 0x004A3800 (FUN_004A3800)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for `wxTopLevelWindow`.
   */
  static wxTopLevelWindowRootRuntime* DeleteWithFlag(
    wxTopLevelWindowRootRuntime* object,
    std::uint8_t deleteFlags
  ) noexcept;

  /**
   * Address: 0x004A3820 (FUN_004A3820)
   *
   * What it does:
   * Runs the non-deleting top-level-window teardown thunk.
   */
  static wxTopLevelWindowRootRuntime* DestroyWithoutDelete(wxTopLevelWindowRootRuntime* object) noexcept;

  static wxClassInfo sm_classInfo;
};

static_assert(sizeof(wxTopLevelWindowRootRuntime) == 0x4, "wxTopLevelWindowRootRuntime size must be 0x4");

/**
 * Address: 0x004A37F0 (FUN_004A37F0)
 * Mangled: ?GetClassInfo@wxFrameBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the shared class-info lane used by frame/dialog/top-level
 * `GetClassInfo` slot-0 entries.
 */
[[nodiscard]] wxClassInfo* WX_FrameBaseGetClassInfo() noexcept;

/**
 * Address: 0x009C7EF0 (FUN_009C7EF0, wxGetWindowId)
 *
 * What it does:
 * Returns one Win32 window-id lane (`GWL_ID`) from the provided native HWND.
 */
[[nodiscard]] long wxGetWindowId(void* nativeWindow) noexcept;

/**
 * Address: 0x009C7E10 (FUN_009C7E10)
 *
 * What it does:
 * Reads primary-display width/height (in pixels) from Win32 device caps and
 * writes them into optional output lanes.
 */
int wxGetDisplaySize(int* widthPixels, int* heightPixels) noexcept;

/**
 * Address: 0x009BCEF0 (FUN_009BCEF0)
 *
 * What it does:
 * Reads one display size pair from `wxGetDisplaySize` and writes both lanes
 * to the caller-provided pair view.
 */
WxDisplaySizePairRuntime* wxGetDisplaySizePair(WxDisplaySizePairRuntime* outSize) noexcept;

/**
 * Address: 0x009CA040 (FUN_009CA040)
 *
 * What it does:
 * Converts one X-axis input delta into the display-transform bucket lane.
 */
int wxDisplayTransformScaleX(const WxDisplayTransformRuntimeView* transform, int deltaX) noexcept;

/**
 * Address: 0x009CA060 (FUN_009CA060)
 *
 * What it does:
 * Converts one Y-axis input delta into the display-transform bucket lane.
 */
int wxDisplayTransformScaleY(const WxDisplayTransformRuntimeView* transform, int deltaY) noexcept;

/**
 * Address: 0x009CADB0 (FUN_009CADB0)
 *
 * What it does:
 * Projects one X-axis input coordinate into runtime output space.
 */
int wxDisplayTransformProjectX(const WxDisplayTransformRuntimeView* transform, int inputX) noexcept;

/**
 * Address: 0x009CADD0 (FUN_009CADD0)
 *
 * What it does:
 * Projects one Y-axis input coordinate into runtime output space.
 */
int wxDisplayTransformProjectY(const WxDisplayTransformRuntimeView* transform, int inputY) noexcept;

/**
 * Address: 0x0099E8A0 (FUN_0099E8A0)
 *
 * What it does:
 * Runs non-deleting frame-runtime teardown for frame-derived windows.
 */
[[nodiscard]] wxTopLevelWindowRuntime* WX_FrameDestroyWithoutDelete(wxTopLevelWindowRuntime* frame) noexcept;

class wxLogWindowRuntime;

/**
 * Minimal recovered `wxLogFrame` runtime projection.
 */
class wxLogFrameRuntime : public wxTopLevelWindowRuntime
{
public:
  /**
   * Address: 0x00A0AB50 (FUN_00A0AB50, wxLogFrame::wxLogFrame)
   * Mangled: ??0wxLogFrame@@QAE@PAVwxFrame@@PAVwxLogWindow@@PBD@Z
   *
   * What it does:
   * Builds one log-output frame lane, creates the embedded multiline text
   * control, and seeds menu/status metadata used by wx log-window plumbing.
   */
  wxLogFrameRuntime(
    wxTopLevelWindowRuntime* parentFrame,
    wxLogWindowRuntime* ownerLogWindow,
    const wchar_t* titleText
  );

  /**
   * Address: 0x00A0B160 (FUN_00A0B160, wxLogFrame::dtr)
   *
   * What it does:
   * Runs non-deleting log-frame teardown, detaches the owner log-window frame
   * lane, and forwards to shared frame destruction.
   */
  ~wxLogFrameRuntime();

  [[nodiscard]] wxTextCtrlRuntime* TextCtrl() const noexcept;

public:
  std::uint8_t mUnknown004To177[0x174]{};
  wxTextCtrlRuntime* mTextControl = nullptr;          // +0x178
  wxLogWindowRuntime* mOwnerLogWindow = nullptr;      // +0x17C
};

static_assert(
  offsetof(wxLogFrameRuntime, mTextControl) == 0x178,
  "wxLogFrameRuntime::mTextControl offset must be 0x178"
);
static_assert(
  offsetof(wxLogFrameRuntime, mOwnerLogWindow) == 0x17C,
  "wxLogFrameRuntime::mOwnerLogWindow offset must be 0x17C"
);
static_assert(sizeof(wxLogFrameRuntime) == 0x180, "wxLogFrameRuntime size must be 0x180");

/**
 * Minimal recovered `wxLogWindow` runtime projection.
 */
class wxLogWindowRuntime
{
public:
  /**
   * Address: 0x00A0BC80 (FUN_00A0BC80, wxLogWindow::wxLogWindow)
   * Mangled: ??0wxLogWindow@@QAE@PAVwxFrame@@PBD_N2@Z
   *
   * What it does:
   * Builds one log-window owner lane, allocates the backing log frame, and
   * optionally shows that frame immediately.
   */
  wxLogWindowRuntime(
    wxTopLevelWindowRuntime* parentFrame,
    const wchar_t* titleText,
    bool showAtStartup,
    bool passToOldLog
  );

  [[nodiscard]] wxLogFrameRuntime* GetFrame() const noexcept;

  /**
   * Address: 0x00A0B420 (FUN_00A0B420, wxLogWindow::dtr)
   *
   * What it does:
   * Runs non-deleting log-window teardown by deleting the owned log frame
   * lane, then destroying chained log sinks.
   */
  virtual ~wxLogWindowRuntime();

public:
  std::uint8_t mUnknown04To0F[0x0C]{};
  std::uint8_t mPassToOldLog = 0; // +0x10
  std::uint8_t mPadding11To13[0x3]{};
  wxLogFrameRuntime* mFrame = nullptr; // +0x14
};

static_assert(
  offsetof(wxLogWindowRuntime, mPassToOldLog) == 0x10,
  "wxLogWindowRuntime::mPassToOldLog offset must be 0x10"
);
static_assert(offsetof(wxLogWindowRuntime, mFrame) == 0x14, "wxLogWindowRuntime::mFrame offset must be 0x14");
static_assert(sizeof(wxLogWindowRuntime) == 0x18, "wxLogWindowRuntime size must be 0x18");

/**
 * Minimal recovered runtime projection for `wxControlContainer`.
 */
struct wxControlContainerRuntime
{
  std::uint8_t mAcceptsFocusRecursion = 0;
  std::uint8_t mPadding01To03[0x3]{};

  void Initialize(bool acceptsFocusRecursion) noexcept;
};

static_assert(
  sizeof(wxControlContainerRuntime) == 0x4,
  "wxControlContainerRuntime size must be 0x4"
);

/**
 * Minimal recovered `wxDialogBase` runtime view.
 */
class wxDialogBaseRuntime : public wxTopLevelWindowRootRuntime
{
public:
  /**
   * Address: 0x004A3860 (FUN_004A3860)
   * Mangled: ??0wxDialogBase@@QAE@@Z
   *
   * What it does:
   * Builds one dialog-base runtime lane, initializes control-container
   * storage, then runs dialog-base init.
   */
  wxDialogBaseRuntime();

  /**
   * Address: 0x004A38C0 (FUN_004A38C0)
   *
   * What it does:
   * Runs non-deleting teardown for dialog-base runtime lanes.
   */
  static wxDialogBaseRuntime* DestroyWithoutDelete(wxDialogBaseRuntime* object) noexcept;

  /**
   * Address: 0x004A38D0 (FUN_004A38D0)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for dialog-base runtime lanes.
   */
  static wxDialogBaseRuntime* DeleteWithFlag(wxDialogBaseRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  void InitRuntime() noexcept;

public:
  std::uint8_t mUnknown004To157[0x154]{};
  wxControlContainerRuntime mControlContainer{};
};

static_assert(
  offsetof(wxDialogBaseRuntime, mControlContainer) == 0x158,
  "wxDialogBaseRuntime::mControlContainer offset must be 0x158"
);

/**
 * Minimal recovered `wxDialog` runtime view.
 */
class wxDialogRuntime : public wxDialogBaseRuntime
{
public:
  /**
   * Address: 0x0098B870 (FUN_0098B870)
   * Mangled: ??0wxDialog@@QAE@XZ
   *
   * What it does:
   * Builds one dialog runtime lane and runs default dialog init state setup.
   */
  wxDialogRuntime();

  /**
   * Address: 0x004A3900 (FUN_004A3900)
   * Mangled: ??0wxDialog@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
   *
   * What it does:
   * Builds one dialog runtime lane, then applies create/init arguments.
   */
  wxDialogRuntime(
    void* parentWindow,
    std::int32_t windowId,
    const wxStringRuntime& title,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x004A3970 (FUN_004A3970)
   * Mangled: ?GetClassInfo@wxDialog@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for dialog runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;
  /**
   * Address: 0x0098B230 (FUN_0098B230)
   * Mangled: ?GetEventTable@wxDialog@@MBEPBUwxEventTable@@XZ
   *
   * What it does:
   * Returns the static event-table lane for dialog runtime dispatch.
   */
  [[nodiscard]] const void* GetEventTable() const override;

  /**
   * Address: 0x004A3980 (FUN_004A3980)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for dialog runtime lanes.
   */
  static wxDialogRuntime* DeleteWithFlag(wxDialogRuntime* object, std::uint8_t deleteFlags) noexcept;

  /**
   * Address: unknown (wxDialog::ShowModal)
   *
   * What it does:
   * Runs the dialog modal loop and returns the result code.
   */
  virtual std::int32_t ShowModal();

  /**
   * Address: 0x0098B700 (FUN_0098B700)
   *
   * What it does:
   * Handles one dialog OK command lane: validates, transfers dialog data from
   * window controls, then dispatches command id `5100`.
   */
  std::int32_t OnOkCommand(wxCommandEventRuntime& event);

  /**
   * Address: 0x0098B740 (FUN_0098B740)
   *
   * What it does:
   * Handles one dialog Apply command lane: validates and then transfers dialog
   * data from window controls.
   */
  std::int32_t OnApplyCommand(wxCommandEventRuntime& event);

  static wxClassInfo sm_classInfo;
  static wxEventTable sm_eventTable;

  std::uint8_t mUnknown15CTo16F[0x14]{};
};

static_assert(sizeof(wxDialogRuntime) == 0x170, "wxDialogRuntime size must be 0x170");

/**
 * Minimal recovered `wxMessageDialog` runtime view. wxWidgets-2.4.2's MSW
 * `wxMessageDialog` does not build a real native dialog window: it only
 * stores the caption/message/style/parent lanes and defers everything to
 * `::MessageBoxW` from `ShowModal`.
 */
class wxMessageDialogRuntime : public wxDialogRuntime
{
public:
  /**
   * Address: 0x009B39B0 (FUN_009B39B0)
   *
   * IDA signature:
   * int __thiscall sub_9B39B0(int this, int a2, wxString *a3, wxString *a4, int a5, int a6);
   *
   * What it does:
   * Runs the base `wxDialog` default constructor, binds the
   * `wxMessageDialog` vtable, then copies the shared message/caption text
   * lanes and stores the raw style/parent lanes. `pos` is accepted but
   * unused, matching the retail body.
   */
  wxMessageDialogRuntime(
    void* parentWindow,
    const wxStringRuntime& message,
    const wxStringRuntime& caption,
    std::int32_t style
  );

  /**
   * Address: 0x009B3A70 (FUN_009B3A70)
   *
   * What it does:
   * Pumps any pending event loop once when no top window is up yet,
   * resolves an owner `HWND` (falling back through
   * `wxResolveTopLevelOwnerWindow`), decodes the wx style bits into a raw
   * `::MessageBoxW` style word, and maps the Win32 result back to
   * `wxID_OK`/`wxID_YES`/`wxID_NO`/`wxID_CANCEL`.
   */
  std::int32_t ShowModal() override;

  /**
   * Address: 0x009A2340 (FUN_009A2340)
   *
   * What it does:
   * Releases the shared message/caption string lanes, then runs the shared
   * non-deleting dialog teardown lane. Deliberately non-virtual, matching
   * this tree's established convention for the whole wxWindow/wxDialog
   * hierarchy (see `wxWindowMswRuntime::~wxWindowMswRuntime`): the binary's
   * real vtable has no destructor slot here, only a deleting-dtor thunk
   * elsewhere, so giving this a virtual destructor would insert an ABI slot
   * the binary does not have.
   */
  ~wxMessageDialogRuntime();

  wxStringRuntime mCaption{};      // +0x170
  wxStringRuntime mMessage{};      // +0x174
  std::int32_t mDialogStyle = 0;   // +0x178
  void* mParent = nullptr;         // +0x17C
};

static_assert(offsetof(wxMessageDialogRuntime, mCaption) == 0x170, "wxMessageDialogRuntime::mCaption offset must be 0x170");
static_assert(offsetof(wxMessageDialogRuntime, mMessage) == 0x174, "wxMessageDialogRuntime::mMessage offset must be 0x174");
static_assert(offsetof(wxMessageDialogRuntime, mDialogStyle) == 0x178, "wxMessageDialogRuntime::mDialogStyle offset must be 0x178");
static_assert(offsetof(wxMessageDialogRuntime, mParent) == 0x17C, "wxMessageDialogRuntime::mParent offset must be 0x17C");
static_assert(sizeof(wxMessageDialogRuntime) == 0x180, "wxMessageDialogRuntime size must be 0x180");

/**
 * Address: 0x009CDF50 (FUN_009CDF50, wxMessageBox)
 *
 * What it does:
 * Builds one transient `wxMessageDialogRuntime` at `wxDefaultPosition`, runs
 * its modal loop, and maps the wx dialog result id back to the
 * `wxOK`/`wxYES`/`wxNO`/`wxCANCEL` button-style return codes.
 */
int wxMessageBox(
  const wxStringRuntime& message,
  const wxStringRuntime& caption,
  std::int32_t style,
  void* parent
);

/**
 * Minimal recovered `wxTreeItemId` runtime value wrapper.
 */
struct wxTreeItemIdRuntime
{
  /**
   * Address: 0x004A39A0 (FUN_004A39A0)
   *
   * What it does:
   * Clears this item-id to the null value.
   */
  void Reset() noexcept;

  /**
   * Address: 0x004A39B0 (FUN_004A39B0)
   *
   * What it does:
   * Reports whether this item-id currently references a valid node.
   */
  [[nodiscard]] bool IsValid() const noexcept;

  /**
   * Address: 0x00A02970 (FUN_00A02970)
   *
   * What it does:
   * Returns true when this tree-item id wraps a non-null node handle.
   */
  [[nodiscard]] bool IsOk() const noexcept;

  void* mNode = nullptr;
};

static_assert(sizeof(wxTreeItemIdRuntime) == 0x4, "wxTreeItemIdRuntime size must be 0x4");

/**
 * Minimal recovered `wxTreeItemData` runtime payload lane.
 */
class wxTreeItemDataRuntime : public wxClientDataRuntime
{
public:
  /**
   * Address: 0x004A39C0 (FUN_004A39C0)
   *
   * What it does:
   * Constructs one tree-item payload lane with null item data.
   */
  wxTreeItemDataRuntime();

  /**
   * Address: 0x004A39D0 (FUN_004A39D0)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-item payload lanes.
   */
  static wxTreeItemDataRuntime* DeleteWithFlag(wxTreeItemDataRuntime* object, std::uint8_t deleteFlags) noexcept;

protected:
  /**
   * Address: 0x004A39F0 (FUN_004A39F0)
   *
   * What it does:
   * Rebinds this object to the `wxClientData` base vtable lane.
   */
  void ResetClientDataBaseVTable() noexcept;

public:
  void* mPayload = nullptr;
};

static_assert(offsetof(wxTreeItemDataRuntime, mPayload) == 0x4, "wxTreeItemDataRuntime::mPayload offset must be 0x4");
static_assert(sizeof(wxTreeItemDataRuntime) == 0x8, "wxTreeItemDataRuntime size must be 0x8");

/**
 * Minimal recovered `wxTreeListColumnInfo` runtime projection.
 */
class wxTreeListColumnInfoRuntime
{
public:
  /**
   * Address: 0x004A3A30 (FUN_004A3A30)
   *
   * What it does:
   * Initializes one tree-list column descriptor from title/width/align and
   * owner lane arguments.
   */
  wxTreeListColumnInfoRuntime(
    const wxStringRuntime& title,
    std::int32_t width,
    void* ownerTreeControl,
    std::uint8_t shown,
    std::uint8_t alignment,
    std::int32_t userData
  );

  /**
   * Address: 0x004A3AC0 (FUN_004A3AC0)
   *
   * What it does:
   * Runs non-deleting teardown for one tree-list column descriptor lane.
   */
  void DestroyWithoutDelete() noexcept;

  /**
   * Address: 0x004A3B30 (FUN_004A3B30)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-list column descriptors.
   */
  static wxTreeListColumnInfoRuntime* DeleteWithFlag(
    wxTreeListColumnInfoRuntime* object,
    std::uint8_t deleteFlags
  ) noexcept;

  virtual ~wxTreeListColumnInfoRuntime() = default;

  void* mRefData = nullptr;
  std::uint8_t mShown = 0;
  std::uint8_t mAlignment = 0;
  std::uint8_t mPadding0A = 0;
  std::uint8_t mPadding0B = 0;
  std::int32_t mUserData = 0;
  wxStringRuntime mText{};
  std::int32_t mWidth = -1;
  std::int32_t mImageIndex = -1;
  void* mOwnerTreeControl = nullptr;
};

static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mRefData) == 0x4,
  "wxTreeListColumnInfoRuntime::mRefData offset must be 0x4"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mText) == 0x10,
  "wxTreeListColumnInfoRuntime::mText offset must be 0x10"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mWidth) == 0x14,
  "wxTreeListColumnInfoRuntime::mWidth offset must be 0x14"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mImageIndex) == 0x18,
  "wxTreeListColumnInfoRuntime::mImageIndex offset must be 0x18"
);
static_assert(
  offsetof(wxTreeListColumnInfoRuntime, mOwnerTreeControl) == 0x1C,
  "wxTreeListColumnInfoRuntime::mOwnerTreeControl offset must be 0x1C"
);
static_assert(sizeof(wxTreeListColumnInfoRuntime) == 0x20, "wxTreeListColumnInfoRuntime size must be 0x20");

/**
 * Minimal recovered `wxTreeListCtrl` runtime projection.
 */
class wxTreeListCtrlRuntime : public wxControlRuntime
{
public:
  /**
   * Address: 0x004A3B50 (FUN_004A3B50)
   * Mangled: ??0wxTreeListCtrl@@QAE@PAVwxWindow@@HABVwxPoint@@ABVwxSize@@JABVwxValidator@@ABVwxString@@@Z
   *
   * What it does:
   * Initializes one tree-list control runtime lane with parent/style/name
   * creation arguments.
   */
  wxTreeListCtrlRuntime(
    wxWindowBase* parentWindow,
    std::int32_t windowId,
    const wxPoint& position,
    const wxSize& size,
    long style,
    const wxStringRuntime& name
  );

  /**
   * Address: 0x004A3BD0 (FUN_004A3BD0)
   *
   * What it does:
   * Runs non-deleting teardown for one tree-list control runtime lane.
   */
  static wxTreeListCtrlRuntime* DestroyWithoutDelete(wxTreeListCtrlRuntime* object) noexcept;

  /**
   * Address: 0x004A3BE0 (FUN_004A3BE0)
   * Mangled: ?AddColumn@wxTreeListCtrl@@QAEXABVwxString@@I_NW4wxTreeListColumnAlign@@@Z
   *
   * What it does:
   * Appends one tree-list column descriptor to this control.
   */
  void AddColumn(const wxStringRuntime& title, std::uint32_t width, bool shown, std::uint8_t alignment = 0);

  /**
   * Address: 0x004A3C50 (FUN_004A3C50)
   * Mangled: ?GetWindowStyleFlag@wxTreeListCtrl@@UBEJXZ
   *
   * What it does:
   * Returns the cached window-style flags for this tree-list control.
   */
  [[nodiscard]] long GetWindowStyleFlag() const override;

  /**
   * Address: 0x004A3C70 (FUN_004A3C70)
   * Mangled: ?GetClassInfo@wxTreeListCtrl@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns the static class-info lane for tree-list runtime RTTI checks.
   */
  [[nodiscard]] void* GetClassInfo() const override;

  /**
   * Address: 0x00982B20 (FUN_00982B20)
   * Mangled: ?GetEventTable@wxTreeListCtrl@@MBEPBUwxEventTable@@XZ
   *
   * What it does:
   * Returns the static event-table lane for tree-list control runtime dispatch.
   */
  [[nodiscard]] const void* GetEventTable() const override;

  /**
   * Address: 0x004A3C80 (FUN_004A3C80)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for tree-list control runtime
   * lanes.
   */
  static wxTreeListCtrlRuntime* DeleteWithFlag(wxTreeListCtrlRuntime* object, std::uint8_t deleteFlags) noexcept;

  [[nodiscard]] wxTreeItemIdRuntime AddRoot(const wxStringRuntime& text);
  [[nodiscard]] wxTreeItemIdRuntime AppendItem(const wxTreeItemIdRuntime& parentItem, const wxStringRuntime& text);
  void Expand(const wxTreeItemIdRuntime& item) noexcept;
  void Collapse(const wxTreeItemIdRuntime& item) noexcept;
  [[nodiscard]] bool IsExpanded(const wxTreeItemIdRuntime& item) const noexcept;
  [[nodiscard]] bool HasChildren(const wxTreeItemIdRuntime& item) const noexcept;
  void SortChildren(const wxTreeItemIdRuntime& item);
  void SetItemData(const wxTreeItemIdRuntime& item, wxTreeItemDataRuntime* itemData);
  [[nodiscard]] wxTreeItemDataRuntime* GetItemData(const wxTreeItemIdRuntime& item) const noexcept;
  void SetItemHasChildren(const wxTreeItemIdRuntime& item, bool hasChildren) noexcept;
  void SetItemText(const wxTreeItemIdRuntime& item, std::uint32_t column, const wxStringRuntime& text);

  static wxClassInfo sm_classInfo;
  static wxEventTable sm_eventTable;

  std::uint8_t mUnknown04To13F[0x13C]{};
};

static_assert(sizeof(wxTreeListCtrlRuntime) == 0x140, "wxTreeListCtrlRuntime size must be 0x140");

class wxApp
{
public:
  enum ExitOnFrameDeleteMode : std::int32_t
  {
    kExitOnFrameDeleteLater = -1,
    kExitOnFrameDeleteNo = 0,
    kExitOnFrameDeleteYes = 1,
  };

  virtual void* GetClassInfo() const;
  virtual void DeleteObject();
  virtual void* CreateRefData() const;
  virtual void* CloneRefData(const void* sourceRefData) const;
  virtual bool ProcessEvent(void* event);
  virtual bool SearchEventTable(void* eventTable, void* event);
  virtual const void* GetEventTable() const;
  virtual void DoSetClientObject(void* clientObject);
  virtual void* DoGetClientObject() const;
  virtual void DoSetClientData(void* clientData);
  virtual void* DoGetClientData() const;
  virtual bool OnInit() = 0;
  virtual bool OnInitGui();
  virtual int OnRun();

  /**
   * Address: 0x009AA860
   * Mangled: ?OnExit@wxAppBase@@UAEHXZ
   */
  virtual int OnExit();

  virtual void OnFatalException();
  virtual int MainLoop();
  virtual void ExitMainLoop();
  virtual bool Initialized();

  /**
   * Address: 0x00992230
   * Mangled: ?Pending@wxApp@@UAE_NXZ
   */
  virtual bool Pending();

  /**
   * Address: 0x00992250
   * Mangled: ?Dispatch@wxApp@@UAEXXZ
   */
  virtual void Dispatch();

  /**
   * Address: 0x009923C0
   * Mangled: ?Yield@wxApp@@UAE_N_N@Z
   */
#ifdef Yield
#undef Yield
#endif
  virtual bool Yield(bool onlyIfNeeded);

  /**
   * Address: 0x00992190
   * Mangled: ?ProcessIdle@wxApp@@UAE_NXZ
   */
  virtual bool ProcessIdle();
  virtual bool IsActive() const;
  virtual wxWindowBase* GetTopWindow() const;
  virtual void OnInitCmdLine(void* cmdLineParser);
  virtual bool OnCmdLineParsed(void* cmdLineParser);
  virtual bool OnCmdLineHelp(void* cmdLineParser);
  virtual bool OnCmdLineError(void* cmdLineParser);
  virtual void* CreateLogTarget();
  virtual void* CreateMessageOutput();
  virtual void* GetStdIcon(std::int32_t iconId) const;
  virtual void* GetDisplayMode() const;
  virtual bool SetDisplayMode(const void* displayMode);
  virtual void SetPrintMode(std::int32_t mode);
  virtual void SetActive(bool isActive, wxWindowBase* topWindow);
  virtual std::int32_t FilterEvent(void* event);
  virtual void ProcessPendingEvents();
  virtual std::int32_t GetPrintMode() const;

  /**
   * Address: 0x00993100 (FUN_00993100)
   * Mangled: ?DoMessage@wxApp@@UAE_NXZ
   *
   * What it does:
   * Pumps one Win32 message for the wx app loop, dispatching immediately on
   * the GUI owner thread and deferring cross-thread deliveries.
   */
  virtual bool DoMessage();
  virtual void DoMessage(void** message);
  virtual bool ProcessMessage(void** message);

  /**
   * Address: 0x009927E0 (FUN_009927E0)
   * Mangled: ?Initialize@wxApp@@SA_NXZ
   *
   * What it does:
   * Runs process-wide wx app initialization and returns success.
   */
  static bool Initialize();

  /**
   * Import thunk address: 0x00992E10
   * Mangled: __imp_?CleanUp@wxApp@@SAXXZ
   */
  static void CleanUp();

  // wxEvtHandler + wxAppConsole unknown/shared runtime lanes.
  std::uint8_t mUnknown04To27[0x24];
  std::uint8_t m_wantDebugOutput = 0;
  std::uint8_t mUnknown29To2B[0x3];

  std::int32_t argc = 0;
  char** argv = nullptr;

  // Declaration order from `wxAppBase` in the vendored
  // `include/wx/app.h` - `wxString m_vendorName, m_appName, m_className;` -
  // which is the order the binary has, because the binary links this library.
  // These three had been labelled one slot apart: m_className on +0x34 and the
  // other two pushed down, so GetAppName() would have handed back the vendor
  // string. Nothing in the recovered tree reads them yet, so this is a naming
  // correction rather than a behaviour change.
  wxStringRuntime m_vendorName{};
  wxStringRuntime m_appName{};
  wxStringRuntime m_className{};

  wxWindowBase* m_topWindow = nullptr;
  std::int32_t m_exitOnFrameDelete = kExitOnFrameDeleteLater;
  std::uint8_t m_useBestVisual = 0;
  std::uint8_t m_isActive = 0;
  std::uint8_t mUnknown4A = 0;
  std::uint8_t mUnknown4B = 0;

  std::uint8_t mUnknown4CTo4F[0x4];
  std::int32_t m_printMode = 0;
  std::uint8_t m_auto3D = 0;
  std::uint8_t mUnknown55To5B[0x7];
  std::uint8_t m_keepGoing = 0;
};

static_assert(
  offsetof(wxApp, m_wantDebugOutput) == 0x28,
  "wxApp::m_wantDebugOutput offset must be 0x28"
);
static_assert(
  offsetof(wxApp, argc) == 0x2C,
  "wxApp::argc offset must be 0x2C"
);
static_assert(
  offsetof(wxApp, argv) == 0x30,
  "wxApp::argv offset must be 0x30"
);
static_assert(
  offsetof(wxApp, m_vendorName) == 0x34,
  "wxApp::m_vendorName offset must be 0x34"
);
static_assert(
  offsetof(wxApp, m_appName) == 0x38,
  "wxApp::m_appName offset must be 0x38"
);
static_assert(
  offsetof(wxApp, m_className) == 0x3C,
  "wxApp::m_className offset must be 0x3C"
);
static_assert(
  offsetof(wxApp, m_topWindow) == 0x40,
  "wxApp::m_topWindow offset must be 0x40"
);
static_assert(
  offsetof(wxApp, m_exitOnFrameDelete) == 0x44,
  "wxApp::m_exitOnFrameDelete offset must be 0x44"
);
static_assert(
  offsetof(wxApp, m_useBestVisual) == 0x48,
  "wxApp::m_useBestVisual offset must be 0x48"
);
static_assert(
  offsetof(wxApp, m_isActive) == 0x49,
  "wxApp::m_isActive offset must be 0x49"
);
static_assert(
  offsetof(wxApp, m_printMode) == 0x50,
  "wxApp::m_printMode offset must be 0x50"
);
static_assert(
  offsetof(wxApp, m_auto3D) == 0x54,
  "wxApp::m_auto3D offset must be 0x54"
);
static_assert(
  offsetof(wxApp, m_keepGoing) == 0x5C,
  "wxApp::m_keepGoing offset must be 0x5C"
);

// wx global owned by wxWidgets runtime.
extern wxApp* wxTheApp;

/**
 * Recovered WSupComFrame runtime view used by CScApp keyboard-suppression
 * gating.
 *
 * Evidence:
 * - FUN_008CDF00 style window proc path in decomp/ForgedAlliance.exe.c:
 *   `*(bool *)((int)this + 0x17b) = (wParam != 0)` on message 0x1C
 *   (WM_ACTIVATEAPP).
 * - FUN_008CE1D0 checks `(supcomFrame + 0x17b) != 0`.
 *
 * Full complete-object size is not asserted yet because only the tail flag
 * lanes are currently validated by direct behavior evidence.
 */
class WSupComFrame : public wxTopLevelWindowRuntime
{
public:
  /**
   * Address: 0x008CE060 (FUN_008CE060, WSupComFrame::dtr)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for SupCom frame runtime lanes.
   */
  static WSupComFrame* DeleteWithFlag(WSupComFrame* object, std::uint8_t deleteFlags) noexcept;

  /**
   * Address: 0x008CE090 (FUN_008CE090)
   * Mangled: ?GetEventTable@WSupComFrame@@MBEPBUwxEventTable@@XZ
   *
   * What it does:
   * Hands back this class's event table, which claims wxEVT_CLOSE_WINDOW and
   * wxEVT_MOVE and chains the rest to wxFrame's.
   *
   * Table at 0x00DFE4EC = {base 0x00D56F70, rows 0x00F5BB4C}; the two rows are
   * {-1, -1, 0x008CDAA0 OnCloseWindow, 0, &0x00F8F40C wxEVT_CLOSE_WINDOW} and
   * {-1, -1, 0x008CDAD0 OnMove, 0, &0x00F8F48C wxEVT_MOVE}. This is one of the
   * four slots WSupComFrame actually overrides.
   */
  [[nodiscard]] const void* GetEventTable() const override;

  static wxEventTable sm_eventTable;

  /**
   * Address: 0x008CDAA0 (FUN_008CDAA0, WSupComFrame::OnCloseWindow)
   *
   * What it does:
   * If the frame is iconized, exits the wx main loop; otherwise requests the
   * Moho escape dialog.
   */
  void OnCloseWindow(wxCloseEventRuntime& event);

  /**
   * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
   *
   * What it does:
   * Persists current top-level frame position lanes into user preferences
   * while the main frame is windowed and not device-locked.
   */
  void OnMove(wxMoveEventRuntime& event);

  /**
   * Address: 0x008CDCD0 (FUN_008CDCD0, WSupComFrame::MSWDefWindowProc)
   *
   * What it does:
   * Handles SupCom system-command defaults, including pending-maximize sync
   * priming and Alt-menu suppression, then forwards other lanes to base wx
   * default window-proc dispatch.
   */
  long MSWDefWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

  /**
   * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
   * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
   *
   * What it does:
   * Handles SupCom frame resize/maximize/app-activation/system-command
   * routing, updates persisted window prefs, and forwards unhandled messages
   * to base frame dispatch.
   */
  long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

  std::uint8_t mUnknown004To178[0x175];
  std::uint8_t mPendingMaximizeSync;
  std::uint8_t mPersistedMaximizeSync;
  std::uint8_t mIsApplicationActive;
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

/**
 * Recovered wxEvent runtime layout shared by log-window event payloads.
 *
 * Evidence:
 * - `FUN_00978FF0` initializes runtime lanes:
 *   - type at `+0xC`
 *   - id at `+0x14`
 *   - bool flags at `+0x1C/+0x1D`
 * - `FUN_00979050` copy-clones all lanes `+0x8..+0x1D`.
 * - `FUN_00979020` is the deleting-dtor thunk family used by wxEvent-derived
 *   payloads.
 */
class wxEventRuntime
{
public:
  /**
   * Address: 0x00978FF0 (FUN_00978FF0, ??0wxEvent@@QAE@@Z)
   *
   * What it does:
   * Initializes core wxEvent runtime lanes (`type`, `id`, object/ref pointers,
   * timestamp, skip flag, callback user-data, and command-event flag).
   */
  explicit wxEventRuntime(std::int32_t eventId = 0, std::int32_t eventType = 0);

  virtual void* GetClassInfo() const { return nullptr; }
  virtual void DeleteObject() {}
  virtual void* CreateRefData() const { return nullptr; }
  virtual void* CloneRefData(const void* sourceRefData) const
  {
    (void)sourceRefData;
    return nullptr;
  }
  virtual wxEventRuntime* Clone() const = 0;

  void* mRefData = nullptr;
  void* mEventObject = nullptr;
  std::int32_t mEventType = 0;
  std::int32_t mEventTimestamp = 0;
  std::int32_t mEventId = 0;
  void* mCallbackUserData = nullptr;
  std::uint8_t mSkipped = 0;
  std::uint8_t mIsCommandEvent = 0;
  std::uint8_t mReserved1E = 0;
  std::uint8_t mReserved1F = 0;
};

static_assert(offsetof(wxEventRuntime, mRefData) == 0x4, "wxEventRuntime::mRefData offset must be 0x4");
static_assert(offsetof(wxEventRuntime, mEventObject) == 0x8, "wxEventRuntime::mEventObject offset must be 0x8");
static_assert(offsetof(wxEventRuntime, mEventType) == 0xC, "wxEventRuntime::mEventType offset must be 0xC");
static_assert(offsetof(wxEventRuntime, mEventTimestamp) == 0x10, "wxEventRuntime::mEventTimestamp offset must be 0x10");
static_assert(offsetof(wxEventRuntime, mEventId) == 0x14, "wxEventRuntime::mEventId offset must be 0x14");
static_assert(
  offsetof(wxEventRuntime, mCallbackUserData) == 0x18,
  "wxEventRuntime::mCallbackUserData offset must be 0x18"
);
static_assert(offsetof(wxEventRuntime, mSkipped) == 0x1C, "wxEventRuntime::mSkipped offset must be 0x1C");
static_assert(
  offsetof(wxEventRuntime, mIsCommandEvent) == 0x1D,
  "wxEventRuntime::mIsCommandEvent offset must be 0x1D"
);
static_assert(sizeof(wxEventRuntime) == 0x20, "wxEventRuntime size must be 0x20");

/**
 * Minimal recovered `wxEraseEvent` runtime projection.
 *
 * Evidence:
 * - `FUN_0097A2D0` constructor lane materializes a 0x24-byte erase-event
 *   payload with one device-context lane at `+0x20`.
 */
class wxEraseEventRuntime : public wxEventRuntime
{
public:
  explicit wxEraseEventRuntime(std::int32_t eventId = 0, std::int32_t eventType = 0)
    : wxEventRuntime(eventId, eventType)
  {}

  wxEraseEventRuntime* Clone() const override { return nullptr; }

  wxDC* mDeviceContext = nullptr; // +0x20
};

/**
 * Minimal recovered `wxPaintEvent` runtime projection.
 *
 * Evidence:
 * - wxPaintEvent adds no payload of its own, so it is the bare 0x20-byte
 *   wxEvent base; the erase event next to it is what carries a DC.
 */
class wxPaintEventRuntime : public wxEventRuntime
{
public:
  explicit wxPaintEventRuntime(std::int32_t eventId = 0, std::int32_t eventType = 0)
    : wxEventRuntime(eventId, eventType)
  {}

  wxPaintEventRuntime* Clone() const override { return nullptr; }
};

static_assert(sizeof(wxPaintEventRuntime) == 0x20, "wxPaintEventRuntime size must be 0x20");

static_assert(offsetof(wxEraseEventRuntime, mDeviceContext) == 0x20, "wxEraseEventRuntime::mDeviceContext offset must be 0x20");
static_assert(sizeof(wxEraseEventRuntime) == 0x24, "wxEraseEventRuntime size must be 0x24");

/**
 * Minimal recovered `wxCommandEvent` runtime projection.
 *
 * Evidence:
 * - `FUN_00979090` constructor writes one `wxString` lane at `+0x20` and
 *   clears command/client payload lanes (`+0x24..+0x30`).
 * - `FUN_006609B0` releases shared `mCommandString` storage then runs the
 *   `wxEvent::UnRef` tail.
 */
class wxCommandEventRuntime : public wxEventRuntime
{
public:
  /**
   * Address: 0x00979090 (FUN_00979090, ??0wxCommandEvent@@QAE@@Z)
   *
   * What it does:
   * Initializes command-event payload lanes and marks this event as a command
   * event.
   */
  explicit wxCommandEventRuntime(std::int32_t commandType = 0, std::int32_t eventId = 0);

  /**
   * Address: 0x00964DC0 (FUN_00964DC0, ??0wxCommandEvent@@QAE@ABV0@@Z)
   *
   * What it does:
   * Copies one command-event payload including shared command-string lane and
   * command/client payload fields.
   */
  wxCommandEventRuntime(const wxCommandEventRuntime& source);

  /**
   * Address: 0x006609B0 (FUN_006609B0, ??1wxCommandEvent@@QAE@@Z)
   *
   * What it does:
   * Releases one shared command-string payload and clears wxEvent ref-data
   * ownership via the base unref tail.
   */
  ~wxCommandEventRuntime();

  /**
   * Address: synthetic (runtime clone helper)
   *
   * What it does:
   * Clones one command-event payload including command/client lanes.
   */
  wxCommandEventRuntime* Clone() const override;

  /**
   * Address: 0x009956A0 (FUN_009956A0)
   *
   * What it does:
   * Copies the shared command-string payload lane into `outValue`, falling
   * back to `wxEmptyString` when the command text is empty.
   */
  wxStringRuntime* CopyCommandStringOrEmpty(wxStringRuntime* outValue) const;

  wxStringRuntime mCommandString{};
  std::int32_t mCommandInt = 0;
  std::int32_t mExtraLong = 0;
  void* mClientData = nullptr;
  wxClientDataRuntime* mClientObject = nullptr;
};

static_assert(
  offsetof(wxCommandEventRuntime, mCommandString) == 0x20,
  "wxCommandEventRuntime::mCommandString offset must be 0x20"
);
static_assert(
  offsetof(wxCommandEventRuntime, mCommandInt) == 0x24,
  "wxCommandEventRuntime::mCommandInt offset must be 0x24"
);
static_assert(
  offsetof(wxCommandEventRuntime, mExtraLong) == 0x28,
  "wxCommandEventRuntime::mExtraLong offset must be 0x28"
);
static_assert(
  offsetof(wxCommandEventRuntime, mClientData) == 0x2C,
  "wxCommandEventRuntime::mClientData offset must be 0x2C"
);
static_assert(
  offsetof(wxCommandEventRuntime, mClientObject) == 0x30,
  "wxCommandEventRuntime::mClientObject offset must be 0x30"
);
static_assert(sizeof(wxCommandEventRuntime) == 0x34, "wxCommandEventRuntime size must be 0x34");

/**
 * Minimal recovered `wxTreeEvent` runtime projection.
 */
class wxTreeEventRuntime : public wxEventRuntime
{
public:
  /**
   * Address: 0x004A3A00 (FUN_004A3A00)
   *
   * What it does:
   * Copies the primary tree-item-id lane into `outItem`.
   */
  void GetItem(wxTreeItemIdRuntime* outItem) const noexcept;

  /**
   * Address: 0x004A3A10 (FUN_004A3A10)
   *
   * What it does:
   * Returns the label storage lane for this tree event.
   */
  [[nodiscard]] wxStringRuntime* GetLabelStorage() noexcept;

  /**
   * Address: 0x004A3A20 (FUN_004A3A20)
   *
   * What it does:
   * Returns the edit-cancelled flag lane for this tree event.
   */
  [[nodiscard]] bool IsEditCancelled() const noexcept;

  std::uint8_t mUnknown20To73[0x54]{};
  wxTreeItemIdRuntime mItem{};
  wxTreeItemIdRuntime mPreviousItem{};
  wxPoint mDragPoint{};
  wxStringRuntime mLabel{};
  std::uint8_t mEditCancelled = 0;
};

static_assert(offsetof(wxTreeEventRuntime, mItem) == 0x74, "wxTreeEventRuntime::mItem offset must be 0x74");
static_assert(offsetof(wxTreeEventRuntime, mLabel) == 0x84, "wxTreeEventRuntime::mLabel offset must be 0x84");
static_assert(
  offsetof(wxTreeEventRuntime, mEditCancelled) == 0x88,
  "wxTreeEventRuntime::mEditCancelled offset must be 0x88"
);

namespace moho
{
  struct ManagedWindowSlot;
  struct WWinManagedDialog;
  class IUserPrefs;
  class CWinLogTarget;
  struct WWinLogWindow;
  class WWinLogTextBuilder;
  struct CWinLogLine;

  /**
   * Runtime wxEvent-derived payload used by `CWinLogTarget::OnMessage` when
   * notifying the log dialog.
   *
   * Evidence:
   * - `FUN_004F6860` stack-constructs one event and assigns
   *   `CLogAdditionEvent` vftable before dispatch to the dialog handler.
   * - `FUN_004F37F0` allocates one `0x20`-byte clone object.
   */
  class CLogAdditionEvent final : public wxEventRuntime
  {
  public:
    /**
     * Address: 0x004F38E0 (FUN_004F38E0)
     *
     * What it does:
     * Returns the static wx class-info lane for this event payload type.
     */
    [[nodiscard]] void* GetClassInfo() const override;

    /**
     * Address: 0x004F3850 (FUN_004F3850)
     *
     * What it does:
     * Deleting-dtor entry for this event payload type.
     */
    void DeleteObject() override;

    /**
     * Address: 0x004F37F0 (FUN_004F37F0)
     *
     * What it does:
     * Allocates and copy-clones one `CLogAdditionEvent` object.
     */
    CLogAdditionEvent* Clone() const override;
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
   * Runtime splash-screen base used by WinMain startup/shutdown paths.
   *
   * Evidence:
   * - `WINX_ExitSplash` (`0x004F3F30`) dispatches the deleting-dtor slot with
   *   flag `1` then clears the global pointer.
   */
  struct SplashScreenRuntime
  {
    virtual void GetClassInfo() = 0;
    virtual void DeleteObject(std::uint32_t flags) = 0;
  };

  /**
   * Address dependency: 0x004F3CE0 (FUN_004F3CE0, WINX_InitSplash)
   *
   * What it does:
   * Initializes one-time PNG splash handler state used before splash bitmap
   * load attempts.
   */
  bool WX_EnsureSplashPngHandler();

  /**
   * Address dependency: 0x004F3CE0 (FUN_004F3CE0, WINX_InitSplash)
   *
   * What it does:
   * Creates one splash runtime object from a UTF-8 file path and target splash
   * size when the image path can be resolved.
   */
  [[nodiscard]] SplashScreenRuntime* WX_CreateSplashScreen(const char* filename, const wxSize& size);

  /**
   * Returns the runtime-assigned `wxEVT_MOTION` event-type lane backed by
   * `gWxEvtMotionRuntimeType` (binary `0x00F8F460`). Initializes lazily on
   * first use just like the original wx startup path.
   */
  [[nodiscard]] std::int32_t WX_GetWxEvtMotionType();

  /**
   * Returns the runtime-assigned `wxEVT_MOUSEWHEEL` event-type lane backed by
   * `gWxEvtMouseWheelRuntimeType` (binary `0x00F8F4B0`). Initializes lazily on
   * first use just like the original wx startup path.
   */
  [[nodiscard]] std::int32_t WX_GetWxEvtMouseWheelType();

  /**
   * The runtime-assigned `wxEVT_LEFT_DOWN` / `wxEVT_MIDDLE_DOWN` lanes.
   *
   * These exist because the wx 2.4.2 header constants (1100 / 1110) are not
   * what this build raises: every event type is handed out by wxNewEventType()
   * during startup. Code outside this translation unit must ask for the id
   * rather than declaring `extern const std::int32_t wxEVT_LEFT_DOWN`, which
   * binds to the vendored library's own global and compares against a
   * different number.
   */
  [[nodiscard]] std::int32_t WX_GetWxEvtLeftDownType();
  [[nodiscard]] std::int32_t WX_GetWxEvtMiddleDownType();

  /**
   * Which family of wx event a runtime event type belongs to.
   *
   * Event types are not compile-time constants in this build - `wxNewEventType`
   * hands them out in static-initialisation order - so a handler outside this
   * translation unit cannot compare against `wxEVT_*` names. This classifies a
   * type against the same globals the event tables use, which is what lets the
   * MAUI event mapper pick a sink without the whole `gWxEvt*` block becoming
   * public.
   */
  enum class WxEventFamily
  {
    Other,
    Mouse,
    KeyDown,
    KeyUp,
    Char,
  };

  [[nodiscard]] WxEventFamily WX_ClassifyEventType(std::int32_t eventType);

  /**
   * Hook consulted by `wxWindowBase::ProcessEvent` before its own event tables.
   *
   * `WX_PushEventHandler` records handlers per window in the UI layer, and wx
   * semantics are that a pushed handler sees the event first. The wx layer must
   * not know what a MAUI event mapper is, so the UI layer installs the walk
   * through this hook instead. Returns true when a pushed handler consumed the
   * event.
   */
  using WxPushedEventHandlerDispatchFn = bool (*)(wxWindowBase* window, void* event);

  void WX_SetPushedEventHandlerDispatch(WxPushedEventHandlerDispatchFn dispatch);

  /** Runs the installed hook, if any. Returns false when none is installed. */
  [[nodiscard]] bool WX_InvokePushedEventHandlerDispatch(wxWindowBase* window, void* event);

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
} // namespace moho

/**
 * Address: 0x008CD8C0 (FUN_008CD8C0)
 * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
 *
 * What it does:
 * Allocates/constructs one SupCom frame shell with startup style/size lanes.
 */
[[nodiscard]] WSupComFrame* WX_CreateSupComFrame(
  const char* title, const wxPoint& position, const wxSize& size, std::int32_t style
);

namespace moho
{
  class CD3DPrimBatcher;
  class IRenderWorldView;
  class TerrainCommon;
  class IWldTerrainRes;

  /**
   * Runtime app shell owning SupCom wx startup loop lanes.
   *
   * Evidence:
   * - `FUN_004F1E50` returns constant success for `OnInit`.
   * - `FUN_004F1E80` clears `wxApp::m_keepGoing` (`+0x5C`) to stop the main
   *   loop.
   */
  /**
   * Creates the single application object and publishes it as wxTheApp.
   * Must run before WIN_AppExecute enters its message loop.
   */
  void WX_EnsureApplicationObject();

  struct MohoApp : wxApp
  {
    /**
     * Address: 0x004F1F10 (FUN_004F1F10, Moho::MohoApp::MohoApp)
     * Mangled: ??0MohoApp@Moho@@QAE@@Z
     *
     * What it does:
     * Constructs one `MohoApp` shell over `wxApp` base runtime state.
     */
    MohoApp();

    /**
     * Address: 0x00992070 (FUN_00992070, Moho::MohoApp::~MohoApp)
     * Mangled: ??1MohoApp@Moho@@QAE@@Z
     *
     * What it does:
     * Runs non-deleting app teardown by releasing argv element storage and the
     * argv pointer array before base wxApp destruction.
     */
    ~MohoApp();

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
     * Address: 0x007FA110 (FUN_007FA110, sub_7FA110)
     *
     * What it does:
     * Shuts down D3D runtime state and clears global main-window/viewport
     * owner lanes during app exit.
     */
    int OnExit() override;
  };

  struct WEmitterTextControl;
  struct WCurveEditorPanel;

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
  struct WCurveEditor : wxControlRuntime
  {
    std::uint8_t mReserved004To027[0x24]{};

    /** wx window id, used as the command id of the curve-changed event. */
    std::int32_t mWindowId = 0;
    std::uint8_t mReserved02CTo12F[0x104]{};

    /**
     * Cursor into `mCurve.mKeys` naming the key the user currently has
     * selected. Seeded to `mCurve.mKeys.begin()` by the constructor
     * (0x00661470) and by FUN_00661A90 (0x00661B37); "no selection" is
     * expressed as `mSelectedKey == mCurve.mKeys.end()`.
     */
    Wm3::Vector3f* mSelectedKey = nullptr;
    std::uint8_t mReserved134To137[0x4]{};
    SEfxCurve mCurve;

    /**
     * Time-axis pixels-per-unit, recomputed by the paint handler
     * (FUN_006621F0) as `clientWidth / (mViewTimeMax - mViewTimeMin)`.
     */
    float mViewTimeScale = 0.0f;

    /**
     * Value-axis units-per-pixel scale. Recomputed by the resize handler
     * (FUN_006621F0 stores the value span here, then divides the time span by
     * it) and used as the divisor that converts pixel / wheel deltas into
     * curve-value deltas (FUN_006617A0, FUN_00661820, FUN_00661900,
     * FUN_00661A90 all divide by `[this+0x174]`).
     */
    float mViewValueScale = 0.0f;

    /** Client size cached by the paint handler (FUN_006621F0). */
    std::int32_t mClientWidth = 0;
    std::int32_t mClientHeight = 0;

    /**
     * Visible view rectangle over the curve, stored interleaved as
     * (timeMin, valueMin, timeMax, valueMax). Proven by the `WCurveEditor`
     * constructor at 0x006613FA-0x0066142F, which seeds `[0x180] = 0.0f`,
     * `[0x188] = arg8`, `[0x184] = argC`, `[0x18C] = arg10`; and by the span
     * arithmetic in FUN_006621F0 (`[0x188]-[0x180]` paired with
     * `[0x18C]-[0x184]`).
     */
    float mViewTimeMin = 0.0f;
    float mViewValueMin = 0.0f;
    float mViewTimeMax = 0.0f;
    float mViewValueMax = 0.0f;
    /** Set once the widget has captured the mouse for a drag (FUN_00661820). */
    std::uint8_t mMouseCaptured = 0;
    std::uint8_t mCurveDirty = 0;
    std::uint8_t mReserved192To193[0x2]{};

    /** Caption painted at the widget's top-left corner. */
    wxStringRuntime mCaption;

    /** Script key this curve is written out under (FUN_00661580). */
    wxStringRuntime mScriptName;

    /** Panel that owns this editor; refreshed after a curve assignment. */
    WCurveEditorPanel* mOwnerPanel = nullptr;

    /** Cursor position cached on button-down (FUN_00661820). */
    std::int32_t mLastMouseX = 0;
    std::int32_t mLastMouseY = 0;

    /** Which button is driving the current drag: 1 = left, 2 = middle. */
    std::int32_t mActiveDragButton = 0;

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
      wxWindowBase* parent,
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
    void ZoomValueAxisByWheel(const wxEventRuntime& wheelEvent) noexcept;

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
    void DrawKeyEnvelopeSpan(void* dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x00662180 (FUN_00662180)
     *
     * What it does:
     * Draws one key's 5x5 grab handle, cyan when selected and red otherwise.
     */
    void DrawKeyHandle(void* dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x006621F0 (FUN_006621F0)
     *
     * What it does:
     * `wxEventTableEntry` paint sink: caches the client size, derives the view
     * scales, and paints the envelope spans, key handles and axis labels.
     */
    void OnPaint();

    /**
     * Address: 0x00661820 (FUN_00661820)
     *
     * What it does:
     * Button-down sink: caches the cursor, selects the nearest key, records the
     * drag button, captures the mouse and repaints.
     */
    void OnMouseDown(wxEventRuntime& mouseEvent);

    /**
     * Address: 0x00661A90 (FUN_00661A90)
     *
     * What it does:
     * Key-editing sink: a plain click inserts a key at the cursor, a
     * control-click deletes the nearest one (never the last).
     */
    void OnCurveKeyEdit(wxEventRuntime& mouseEvent);

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

    /**
     * Address: 0x00662660 (FUN_00662660, ?GetEventTable@WCurveEditor@Moho@@MBEPBUwxEventTable@@XZ)
     * Mangled: ?GetEventTable@WCurveEditor@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this curve-editor control type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    static wxEventTable sm_eventTable;
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
   * Recovered curve-editor panel runtime owner: one `WCurveEditor` plus five
   * numeric fields (key time/value/tangent, visible value range) that mirror
   * the selected key and let it be edited by hand.
   *
   * Evidence:
   * - `FUN_009AE6D0` is the non-deleting destructor lane.
   * - `FUN_00663870` and duplicate thunks run deleting-dtor semantics.
   * - `FUN_006638A0` returns this type's static event-table lane.
   * - `Moho::WCurveEditorPanel::WCurveEditorPanel` (0x00662680) proves every
   *   field offset below (0x006626FF-0x0066271D zero-inits all five text
   *   control pointers plus the live-fields flag; 0x0066277B writes `editor`;
   *   0x006633DD sets the live-fields flag at the end of construction).
   */
  struct WCurveEditorPanel : wxWindowMswRuntime
  {
    /**
     * Address: 0x009AE6D0 (FUN_009AE6D0, ??1WCurveEditorPanel@Moho@@QAE@@Z)
     * Mangled: ??1WCurveEditorPanel@Moho@@QAE@@Z
     *
     * What it does:
     * Runs non-deleting curve-editor panel teardown and forwards into base
     * window destruction.
     */
    ~WCurveEditorPanel();

    /**
     * Address: 0x00663870 (FUN_00663870, Moho::WCurveEditorPanel::dtr)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for this panel runtime.
     */
    WCurveEditorPanel* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x006638A0 (FUN_006638A0, ?GetEventTable@WCurveEditorPanel@Moho@@MBEPBUwxEventTable@@XZ)
     * Mangled: ?GetEventTable@WCurveEditorPanel@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this curve-editor panel type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    static wxEventTable sm_eventTable;

    std::uint8_t mReserved000To133[0x130]{};
    WCurveEditor* mCurveEditor = nullptr;      // +0x134

    /**
     * The five numeric fields the panel keeps in sync with the editor. Their
     * wx command ids are consecutive from 622 (0x26E), which is how
     * FUN_00663650 selects between them.
     */
    WEmitterTextControl* mKeyTimeText = nullptr;      // +0x138, id 622
    WEmitterTextControl* mKeyValueText = nullptr;     // +0x13C, id 623
    WEmitterTextControl* mKeyTangentText = nullptr;   // +0x140, id 624
    WEmitterTextControl* mViewValueMinText = nullptr; // +0x144, id 625
    WEmitterTextControl* mViewValueMaxText = nullptr; // +0x148, id 626

    /** Set once the panel's fields are bound; commits are ignored until then. */
    std::uint8_t mFieldsLive = 0;                     // +0x14C

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
      wxWindowBase* parent,
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
    void OnCurveFieldCommitted(wxEventRuntime& commandEvent);

    /**
     * Address: 0x00663400 (FUN_00663400)
     *
     * What it does:
     * Pushes the editor's current key and view-range values back out into the
     * five numeric fields, formatted as `%f`.
     */
    void RefreshFieldsFromCurve();
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
   * Recovered bitmap-backed panel control runtime.
   *
   * Evidence:
   * - ctor `FUN_004FBCC0` stores panel image lane at `+0x134`.
   * - `FUN_004FBCB0` returns this type's static event-table lane.
   */
  struct WBitmapPanel : wxWindowMswRuntime
  {
    std::uint8_t mUnknown04To133[0x130]{};
    void* mBitmapLane = nullptr; // +0x134

    /**
     * Address: 0x004FBCC0 (FUN_004FBCC0, ??0WBitmapPanel@Moho@@QAE@PAVwxWindow@@PAVwxBitmap@@@Z)
     * Mangled: ??0WBitmapPanel@Moho@@QAE@PAVwxWindow@@PAVwxBitmap@@@Z
     *
     * What it does:
     * Stores one bitmap lane used by this panel runtime wrapper.
     */
    WBitmapPanel(wxWindowBase* parentWindow, wxBitmap* bitmap);

    /**
     * Address: 0x004FBCB0 (FUN_004FBCB0, ?GetEventTable@WBitmapPanel@Moho@@MBEPBUwxEventTable@@XZ)
     * Mangled: ?GetEventTable@WBitmapPanel@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this bitmap-panel runtime type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004FBD90 (FUN_004FBD90, ?OnEraseBackground@WBitmapPanel@Moho@@IAEXAAVwxEraseEvent@@@Z)
     * Mangled: ?OnEraseBackground@WBitmapPanel@Moho@@IAEXAAVwxEraseEvent@@@Z
     *
     * What it does:
     * Tiles the bound bitmap across the panel client span during erase
     * background, or marks the erase event as skipped when bitmap lanes are
     * unavailable.
     */
    void OnEraseBackground(wxEraseEventRuntime& eraseEvent);

    static wxEventTable sm_eventTable;
  };

  static_assert(offsetof(WBitmapPanel, mBitmapLane) == 0x134, "moho::WBitmapPanel::mBitmapLane offset must be 0x134");

  /**
   * Recovered bitmap check-box control runtime.
   *
   * Evidence:
   * - ctor `FUN_004FBE30` initializes checked state lane at `+0x168`.
   * - `FUN_004FBE20` returns this type's static event-table lane.
   */
  struct WBitmapCheckBox : wxWindowMswRuntime
  {
    std::uint8_t mUnknown04To167[0x164]{};
    std::uint8_t mIsChecked = 0; // +0x168

    /**
     * Address: 0x004FBE30 (FUN_004FBE30, ??0WBitmapCheckBox@Moho@@QAE@PAVwxWindow@@HABVwxBitmap@@@Z)
     * Mangled: ??0WBitmapCheckBox@Moho@@QAE@PAVwxWindow@@HABVwxBitmap@@@Z
     *
     * What it does:
     * Constructs one bitmap-check-box control by delegating to
     * `wxBitmapButton`'s constructor with the default button-name string,
     * rebinds the vtable lane to `??_7WBitmapCheckBox@Moho@@6B@`, and clears
     * the checked-state byte.
     */
    WBitmapCheckBox(wxWindowBase* parentWindow, int controlId, const wxBitmap& bitmap);

    /**
     * Address: 0x004FBE20 (FUN_004FBE20, ?GetEventTable@WBitmapCheckBox@Moho@@MBEPBUwxEventTable@@XZ)
     * Mangled: ?GetEventTable@WBitmapCheckBox@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this bitmap-check-box runtime
     * type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004FBF10 (FUN_004FBF10, ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ)
     * Mangled: ?IsChecked@WBitmapCheckBox@Moho@@QAE_NXZ
     *
     * What it does:
     * Returns whether the check-box checked-state lane is non-zero.
     */
    [[nodiscard]] bool IsChecked();

    /**
     * Address: 0x004FBF20 (FUN_004FBF20, ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z)
     * Mangled: ?SetChecked@WBitmapCheckBox@Moho@@QAEX_N@Z
     *
     * What it does:
     * Updates the checked-state byte; when it actually flips, refreshes the
     * stored bitmap-button bitmap via the wx vtable slot at +0x228, then
     * re-evaluates the parent bitmap-button repaint slot at +0xF0.
     */
    void SetChecked(bool checked);

    static wxEventTable sm_eventTable;
  };

  static_assert(
    offsetof(WBitmapCheckBox, mIsChecked) == 0x168,
    "moho::WBitmapCheckBox::mIsChecked offset must be 0x168"
  );

  class wxTextCtrl;

  /**
   * Recovered modal input-box dialog runtime used by the `WxInputBox`
   * console helper. Inherits the wx dialog runtime and adds a result-string
   * pointer plus the in-dialog text-control pointer; the OnOK virtual
   * override copies the text-control contents into the caller-owned result
   * buffer.
   *
   * Evidence:
   * - ctor `FUN_004FC040` writes vtable lane, stores caller-supplied result
   *   string at +0x170, and the constructed `wxTextCtrl*` at +0x174.
   * - OnOK virtual override `FUN_004FC7B0` sits at vtable slot +0xDC of
   *   `??_7WWxInputBox@Moho@@6B@` and reads the control's current value
   *   via the wx text-control vtable slot at +0x218.
   */
  struct WWxInputBox : wxTopLevelWindowRuntime
  {
    std::uint8_t mUnknown04To16F[0x170 - 0x04]{};
    msvc8::string* mResultString = nullptr; // +0x170
    wxTextCtrl* mTextCtrl = nullptr;        // +0x174

    /**
     * Address: 0x004FC040 (FUN_004FC040, ??0WWxInputBox@Moho@@QAE@PBDPBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@msvc8@@00PAV40@@Z)
     *
     * What it does:
     * Builds the modal input-box dialog: creates the wxDialog frame with
     * the caller-supplied title, then arranges a static-text label, a
     * text-control seeded with the default value, and OK/Cancel buttons
     * inside vertical/horizontal box sizers. Stores the caller's result
     * string pointer so the OnOK override can write the final value.
     */
    WWxInputBox(
      const char* dialogTitle,
      const char* defaultValue,
      const char* labelText,
      msvc8::string* resultString
    );

    /**
     * Address: 0x004FC7B0 (FUN_004FC7B0,
     *   `WWxInputBox` vtable slot +0xDC override — modal-OK transfer hook).
     *
     * What it does:
     * Wx OnOK-style override: reads the text-control's current wide-string
     * value, UTF-8 encodes it into the caller-supplied result string, and
     * returns `true` so the modal dialog closes with ID_OK.
     */
    [[nodiscard]] bool TransferDataFromTextControl();

    static wxEventTable sm_eventTable;
  };

  static_assert(
    offsetof(WWxInputBox, mResultString) == 0x170,
    "moho::WWxInputBox::mResultString offset must be 0x170"
  );
  static_assert(
    offsetof(WWxInputBox, mTextCtrl) == 0x174,
    "moho::WWxInputBox::mTextCtrl offset must be 0x174"
  );

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
  void CON_WxInputBox(void* commandArgs);

  // Main owner window used by WinMain lifecycle paths (`WIN_OkBox`,
  // crash handling, and startup viewport bootstrap).
  //
  // Evidence:
  // - `FUN_004F2800` (`WIN_OkBox`) resolves owner with `sMainWindow->GetHandle()`.
  // - startup frame/bootstrap passes `WSupComFrame` through this global.
  //
  // Keep this typed as the shared wx window base to avoid duplicating ad-hoc
  // runtime-view overlays for each caller.

  /**
   * Runtime viewport base used by startup/device and UI manager bindings.
   *
   * Evidence:
   * - `CScApp::CreateAppFrame` (0x008CF8C0) reads `viewport->m_parent`
   *   before calling `GetHandle()` on both parent and viewport.
   */
  struct WPreviewImageRuntime;

  struct WRenViewport : wxWindowMswRuntime
  {
    std::uint8_t mUnknown04To0C[0x08];
    std::int32_t mRenderState0C = -1;
    std::uint8_t mUnknown10To1D[0x0D];
    std::uint8_t mEnabled = 0;
    std::uint8_t mUnknown1ETo2B[0x0E];
    wxWindowBase* m_parent;

    /**
     * Address: 0x007F6690 (FUN_007F6690, ?GetEventTable@WRenViewport@Moho@@MBEPBUwxEventTable@@XZ)
     * Mangled: ?GetEventTable@WRenViewport@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this viewport runtime type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x007F6600 (FUN_007F6600, ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ)
     * Mangled: ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ
     *
     * What it does:
     * Returns the viewport debug-canvas primary batcher lane.
     */
    [[nodiscard]] virtual CD3DPrimBatcher* GetPrimBatcher() const;

    /**
     * Address: 0x00453AA0 (FUN_00453AA0, sub_453AA0)
     *
     * What it does:
     * Resets `mRenderState0C` to `-1` as part of the viewport's
     * per-frame render prep; callers live in the render-camera
     * outline path (`RenderCameraOutline` at 0x007F98A0).
     */
    void ResetRenderState0C() noexcept;

    /**
     * Address: 0x007F9E60 (FUN_007F9E60, ?AddWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@HH@Z)
     *
     * What it does:
     * Inserts one world-view lane sorted by depth and creates one terrain
     * renderer instance bound to the active world-map terrain resource.
     */
    void AddWorldView(IRenderWorldView* worldView, int head, int depth);

    /**
     * Address: 0x007FA090 (FUN_007FA090, ?RemoveWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@@Z)
     *
     * What it does:
     * Removes the first matching world-view entry from the viewport world-view
     * vector lane.
     */
    void RemoveWorldView(IRenderWorldView* worldView);

    /**
     * Address: 0x007F90D0 (FUN_007F90D0, Moho::WRenViewport::Render)
     *
     * What it does:
     * Binds one active head, selects matching world-view entries, and drives
     * the terrain/mesh/effects/water render-pass sequence for that frame.
     *
     * Notes:
     * - `worldViewInfoVector` is currently an opaque runtime lane in this SDK
     *   recovery pass; the render path uses the recovered embedded world-view
     *   vector stored on `WRenViewport`.
     */
    void Render(int head, void* worldViewInfoVector);

    /**
     * Address: 0x007F7B30 (FUN_007F7B30)
     * Mangled: ?D3DWindowOnDeviceRender@WRenViewport@Moho@@UAEXXZ
     *
     * What it does:
     * Drives one engine frame: resets the per-frame render stat counters, ticks
     * each registered world view, advances the global mesh interpolant, then
     * runs `Render` once per configured head. Re-entrant paints are dropped.
     *
     * Notes:
     * - In the binary this is `WRenViewport`'s override of the empty
     *   `WD3DViewport::D3DWindowOnDeviceRender` slot that `CD3DDevice::Paint`
     *   dispatches. This tree models the inheritance inverted, so the body
     *   lives here as a plain member and the `WD3DViewport` slot forwards.
     */
    void RenderAllHeads();

    /**
     * Address: 0x007F6B60 (FUN_007F6B60)
     * Mangled: ?D3DWindowOnDeviceInit@WRenViewport@Moho@@UAEX_N@Z
     *
     * IDA signature:
     * int __thiscall Moho::WRenViewport::D3DWindowOnDeviceInit(
     *     Moho::WRenViewport *this, bool a2);
     *
     * What it does:
     * Builds every device-dependent resource this viewport renders through:
     * the texture and primitive batchers, the debug font, each sub-renderer's
     * own resources, the shared dynamic texture sheet, and - per head - the
     * bloom renderer, the two offscreen colour targets and the depth stencil.
     *
     * `createBatchers` separates the two entry paths. `CD3DDevice::SetRenViewport`
     * (0x0042DC10) passes true when the viewport is first bound and the
     * batchers do not exist yet; `CD3DDevice::InitContext` (0x0042E1E0) passes
     * false when an existing device context is rebound, keeping the batchers
     * that are already there. Everything after that gate runs either way, and
     * the per-head resources are each guarded so a rebind only fills the slots
     * that were released.
     *
     * Notes:
     * - In the binary this is `WRenViewport`'s override of the empty
     *   `WD3DViewport::D3DWindowOnDeviceInit` slot. This tree models the
     *   inheritance inverted, so the body lives here and the slot forwards,
     *   exactly as for `RenderAllHeads`.
     */
    void InitDeviceResources(bool createBatchers);

    /**
     * Address: 0x007F70F0 (FUN_007F70F0,
     * ?D3DWindowOnDeviceExit@WRenViewport@Moho@@UAEX_N@Z)
     *
     * IDA signature:
     * int __thiscall Moho::WRenViewport::D3DWindowOnDeviceExit(
     *     Moho::WRenViewport *this, bool a2);
     *
     * What it does:
     * The exact inverse of `InitDeviceResources`: drops every device-dependent
     * resource the viewport holds so none of them survives into
     * `IDirect3DDevice9::Reset`. D3D9 fails a reset outright while any
     * default-pool surface is still referenced, so a missed release here does
     * not leak quietly - it takes the resize path down.
     *
     * `fullShutdown` separates the two entry paths, mirroring
     * `createBatchers`. `CD3DDevice::InitContext` (0x0042E1E0) passes false to
     * rebind an existing context: the batchers are kept and the mesh renderer
     * is only `Reset`. `CD3DDevice::Destroy` (0x0042E750) passes true at app
     * shutdown: the batchers go too, the map-imager border is cleared and the
     * mesh renderer is fully `Shutdown`. Everything after that gate runs either
     * way.
     *
     * Notes:
     * - In the binary this is `WRenViewport`'s override of the empty
     *   `WD3DViewport::D3DWindowOnDeviceExit` slot (vtable slot 133,
     *   0x00E405BC+0x214). This tree models the inheritance inverted, so the
     *   body lives here and the slot forwards, exactly as for
     *   `InitDeviceResources` and `RenderAllHeads`.
     */
    void ReleaseDeviceResources(bool fullShutdown);

    /**
     * Address: 0x007F6610 (FUN_007F6610, ?OnMouseEnter@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z)
     *
     * What it does:
     * When GAL device runtime is ready, focuses the primary head window handle
     * so mouse-enter viewport transitions keep keyboard input ownership in sync.
     */
    void OnMouseEnter(wxMouseEventRuntime& mouseEvent);

    /**
     * Address: 0x007F6640 (FUN_007F6640, ?OnMouseLeave@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z)
     *
     * What it does:
     * When GAL device runtime is ready and a secondary head exists, focuses
     * that secondary head window during mouse-leave transitions.
     */
    void OnMouseLeave(wxMouseEventRuntime& mouseEvent);

    /**
     * Address: 0x007F65D0 (FUN_007F65D0, ?GetPreviewImage@WRenViewport@Moho@@UAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained preview-image shared-pointer lane from viewport
     * runtime storage.
     */
    [[nodiscard]] virtual WPreviewImageRuntime GetPreviewImage() const;

    /**
     * Address: 0x007F7FC0 (FUN_007F7FC0, ?TransformTerrainNormals@WRenViewport@Moho@@AAEXXZ)
     * Mangled: ?TransformTerrainNormals@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * Builds one full-screen terrain-normal basis frame for the active head
     * by binding terrain normal targets and drawing the cached `CRenFrame`
     * pass.
     */
    void TransformTerrainNormals();

    /**
     * Address: 0x007F81C0 (FUN_007F81C0, ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
     * Mangled: ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     *
     * What it does:
     * Binds the active viewport head and draws terrain normal-composite lanes
     * for the current frame, then renders the terrain skirt pass.
     */
    void RenderCompositeTerrain(TerrainCommon* terrain);

    /**
     * Address: 0x007F80C0 (FUN_007F80C0)
     * Mangled: ?Render@SkyDome@Moho@@QAEXHMABVGeomCamera3@2@ABV?$vector@UCumulusVertex@SkyDome@Moho@@V?$allocator@UCumulusVertex@SkyDome@Moho@@@std@@@std@@@Z
     *
     * IDA signature:
     * void __thiscall Moho::SkyDome::Render(WRenViewport *this);
     *
     * What it does:
     * Binds the sky render target and viewport rectangle for the active head,
     * resolves the active terrain's SkyDome, ensures its render resources exist,
     * then dispatches the atmosphere, decal, cirrus, and cumulus passes for the
     * active world-view camera.
     *
     * The PDB attributes FUN_007F80C0 to ?Render@SkyDome@Moho@@..., but the
     * compiled body's `this` is a WRenViewport (it reads WRenViewport fields
     * mHead@+0x320, mScreenPos@+0x308, mScreenSize@+0x310, mCam@+0x219C, all
     * beyond SkyDome's 0x224 size). The symbol is a genuine misattribution, so
     * the body is modeled here as a WRenViewport member.
     */
    void RenderSkyDome();

    /**
     * Address: 0x007F8350 (FUN_007F8350, ?RenderWaterMask@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
     * Mangled: ?RenderWaterMask@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     *
     * What it does:
     * Binds water-mask render state for the active viewport head and dispatches
     * the terrain water-mask pass for the current simulation frame.
     */
    void RenderWaterMask(TerrainCommon* terrain);

    /**
     * Address: 0x007F83F0 (FUN_007F83F0, ?RenderCopyForRefraction@WRenViewport@Moho@@AAEXXZ)
     * Mangled: ?RenderCopyForRefraction@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * Copies the active writer-lock render target into the retained
     * refraction background slot, optionally clamped to the local viewport
     * rectangle lanes.
     */
    void RenderCopyForRefraction(bool clampToViewportRect);

    /**
     * Address: 0x007F8290 (FUN_007F8290, Moho::WRenViewport::RenderMeshes)
     *
     * What it does:
     * Sets the render target, viewport, and color-write state for one viewport
     * mesh pass, then dispatches either skeleton-debug rendering or the normal
     * mesh batch renderer depending on `ren_ShowSkeletons`.
     */
    void RenderMeshes(int meshFlags, bool mirrored);

    /**
     * Address: 0x007F8560 (FUN_007F8560, Moho::WRenViewport::RenderEffects)
     *
     * What it does:
     * Binds the viewport render target and viewport lanes for the active head,
     * configures color writes for FX, then renders world-particle effects.
     */
    void RenderEffects(bool renderWaterSurface);

    /**
     * Address: 0x007F8600 (FUN_007F8600, ?RenderRefractingEffects@WRenViewport@Moho@@AAEXXZ)
     * Mangled: ?RenderRefractingEffects@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * When FX are enabled and graphics fidelity is medium or higher, copies the
     * active writer-lock into the refraction slot, rebinds the active head's
     * render target and local viewport, configures color-only writes, then
     * forwards the retained refraction background texture pointer to
     * `CWorldParticles::RenderRefractingEffects` for the current frame.
     */
    void RenderRefractingEffects();

    /**
     * Address: 0x007F86F0 (FUN_007F86F0, ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
     * Mangled: ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     *
     * What it does:
     * Binds the active viewport head to the water render target, restores the
     * viewport rectangle, and forwards the current frame lanes to terrain
     * water rendering.
     */
    void RenderWater(TerrainCommon* terrain);

    /**
     * Address: 0x007F7DF0 (FUN_007F7DF0, ?RenderReflections@WRenViewport@Moho@@AAEXXZ)
     *
     * What it does:
     * Binds reflection render-target/depth lanes for the active head slot and,
     * when enabled, renders reflection meshes through `MeshRenderer`.
     */
    void RenderReflections();

    /**
     * Address: 0x007F7ED0 (FUN_007F7ED0, ?SetViewportToFullScreen@WRenViewport@Moho@@AAEXXZ)
     *
     * What it does:
     * Applies a full-head viewport rectangle (`(0,0)` to `mFullScreen`) to the
     * active D3D device viewport state.
     */
    void SetViewportToFullScreen();

    /**
     * Address: 0x007F7EA0 (FUN_007F7EA0, ?SetViewportToLocalScreen@WRenViewport@Moho@@AAEXXZ)
     *
     * What it does:
     * Applies this viewport's cached local-screen rectangle to the active D3D
     * device viewport state.
     */
    void SetViewportToLocalScreen();

    /**
     * Address: 0x007F87F0 (FUN_007F87F0, ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ)
     * Mangled: ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * Refreshes full-head screen dimensions and per-camera local viewport
     * rectangle lanes used by render passes.
     */
    void UpdateRenderViewportCoordinates();

    /**
     * Address: 0x007F8A30 (FUN_007F8A30, ?FogOn@WRenViewport@Moho@@AAEXM@Z)
     * Mangled: ?FogOn@WRenViewport@Moho@@AAEXM@Z
     *
     * What it does:
     * Enables distance fog and derives start/end/color lanes from terrain fog
     * settings plus one caller-provided distance offset multiplier.
     */
    void FogOn(float offsetMultiplier);

    /**
     * Address: 0x007F8B70 (FUN_007F8B70, ?FogOff@WRenViewport@Moho@@AAEXXZ)
     * Mangled: ?FogOff@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * Disables fog in the active GAL D3D9 pipeline state and restores default
     * fog range lanes (`0.0f` to `1.0f`) with zero fog color.
     */
    void FogOff();

    /**
     * Address: 0x007F7F10 (FUN_007F7F10, ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
     * Mangled: ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     *
     * What it does:
     * Binds the terrain-normal render target and viewport lanes for the
     * active head, then renders terrain normals when terrain debugging is
     * enabled.
     */
    void RenderTerrainNormals(TerrainCommon* terrain);

    static wxEventTable sm_eventTable;
  };

  static_assert(offsetof(WRenViewport, mRenderState0C) == 0x0C, "moho::WRenViewport::mRenderState0C offset must be 0x0C");
  static_assert(offsetof(WRenViewport, mEnabled) == 0x1D, "moho::WRenViewport::mEnabled offset must be 0x1D");
  static_assert(offsetof(WRenViewport, m_parent) == 0x2C, "moho::WRenViewport::m_parent offset must be 0x2C");

  // There is one device context, not two: this used to be a second, unrelated
  // stand-in with a do-nothing DoDrawRectangle, so the viewport background it
  // was asked to paint never appeared.
  using wxDCRuntime = ::wxDC;

  /**
   * Mangled: ??0wxPaintDC@@QAE@PAVwxWindow@@@Z / ??1wxPaintDC@@UAE@XZ
   *
   * wxPaintDC's whole job is the BeginPaint/EndPaint pair. wx answers WM_PAINT
   * from its event table and never lets the message reach DefWindowProc, so
   * this destructor is the only thing that validates the update region. With
   * the pair missing, the region stayed dirty, Windows regenerated WM_PAINT
   * immediately, and wxApp::Pending() never went false - the main loop in
   * WIN_AppExecute spun on Dispatch() and never reached ProcessIdle() or
   * app->Main().
   *
   * wx caches these per window so nested wxPaintDCs on one window share a
   * single BeginPaint; the engine only ever builds one at a time (the paint
   * handlers each construct exactly one on the stack), so the count is kept
   * here rather than in a process-wide cache.
   */
  struct wxPaintDCRuntime : ::wxDC
  {
    explicit wxPaintDCRuntime(wxWindowBase* ownerWindow) noexcept;
    ~wxPaintDCRuntime() override;

  private:
    PAINTSTRUCT mPaintStruct{};
    bool mOwnsPaint = false;
  };

  struct WPreviewImageRuntime
  {
    void* lane0 = nullptr;
    void* lane1 = nullptr;
  };

  static_assert(sizeof(WPreviewImageRuntime) == 0x8, "moho::WPreviewImageRuntime size must be 0x8");

  struct WD3DViewport : WRenViewport
  {
    /**
     * Address: 0x00430980 (FUN_00430980)
     * Mangled:
     * ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
     *
     * What it does:
     * Initializes viewport runtime ownership from parent/title/size startup
     * lanes and clears retained D3D-device reference storage.
     */
    WD3DViewport(wxWindowBase* parentWindow, const char* title, const wxPoint& position, const wxSize& size);

    /**
     * Address: 0x00430970 (FUN_00430970)
     * Mangled: ?GetEventTable@WD3DViewport@Moho@@MBEPBUwxEventTable@@XZ
     *
     * What it does:
     * Returns the static event-table lane for this viewport runtime type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x0042BA90 (FUN_0042BA90)
     * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
     *
     * What it does:
     * Releases one held D3D-device reference before base window teardown.
     */
    virtual ~WD3DViewport();

    /**
     * Address: 0x0042BAF0 (FUN_0042BAF0)
     *
     * The binary's `WD3DViewport` body is a bare `retn`; the real work is
     * `WRenViewport`'s override (0x007F6B60), which this tree reaches by
     * forwarding because the inheritance is modelled inverted.
     */
    virtual void D3DWindowOnDeviceInit(bool createBatchers);

    /**
     * Address: 0x0042BB00 (FUN_0042BB00)
     */
    virtual void D3DWindowOnDeviceRender();

    /**
     * Address: 0x0042BB10 (FUN_0042BB10)
     *
     * The binary's `WD3DViewport` body is a bare `retn`; the real work is
     * `WRenViewport`'s override (0x007F70F0), which this tree reaches by
     * forwarding because the inheritance is modelled inverted.
     */
    virtual void D3DWindowOnDeviceExit(bool fullShutdown);

    /**
     * Address: 0x0042BB20 (FUN_0042BB20)
     */
    virtual void RenderPreviewImage();

    /**
     * Address: 0x0042BB30 (FUN_0042BB30)
     */
    [[nodiscard]] WPreviewImageRuntime GetPreviewImage() const override;

    /**
     * Address: 0x0042BB50 (FUN_0042BB50)
     */
    [[nodiscard]] CD3DPrimBatcher* GetPrimBatcher() const override;

    /**
     * Address: 0x00430AC0
     * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
     *
     * What it does:
     * Builds one paint-DC for this viewport, then either paints via active
     * D3D device path or draws fallback background.
     */
    void OnPaint(wxPaintEventRuntime& paintEvent);

    /**
     * Address: 0x00430A60 (FUN_00430A60)
     * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
     *
     * What it does:
     * Draws a solid black background over the viewport DC extents.
     */
    void DrawBackgroundImage(wxDCRuntime& deviceContext);

    /**
     * Address: 0x00430B70 (FUN_00430B70)
     *
     * IDA signature:
     * void __stdcall sub_430B70(int event);
     *
     * What it does:
     * Paints the viewport background on WM_ERASEBKGND, but only while the D3D
     * device is absent or has asked for the background to be drawn - once the
     * device is presenting, erasing underneath it would only flicker. Bound as
     * the second row of this class's event table; `this` goes unused, which is
     * why the decompiler shows it as a free __stdcall function.
     */
    void OnEraseBackground(wxEraseEventRuntime& eraseEvent);

    /**
     * Address: 0x00430B90 (FUN_00430B90)
     * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
     *
     * What it does:
     * Handles cursor message routing for D3D cursor ownership and forwards
     * unhandled messages to base wx window dispatch.
     */
    long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

    static wxEventTable sm_eventTable;
    void* mD3DDevice = nullptr;
  };

  /**
   * Address: 0x007FA230
   * Mangled:
   * ?REN_CreateGameViewport@Moho@@YAPAVWD3DViewport@1@PAVwxWindow@@VStrArg@gpg@@ABV?$IVector2@H@Wm3@@_N@Z
   */
  [[nodiscard]] WD3DViewport* REN_CreateGameViewport(
    wxWindowBase* parentWindow, const char* title, const wxSize& size, bool hasSecondHead
  );

  /**
   * Address: 0x007F6530 (FUN_007F6530, Moho::REN_ShowSkeletons)
   *
   * What it does:
   * Toggles the skeleton-visualization render flag and forwards the same bool
   * lane into the active sim-driver sync-filter option hook when present.
   */
  void REN_ShowSkeletons();

  /**
   * Address: 0x007FA170 (FUN_007FA170, ?REN_GetTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
   *
   * What it does:
   * Returns the active world-map terrain resource when one map is currently
   * bound; otherwise returns null.
   */
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  // 0x010A6428 in FA.
  extern WRenViewport* ren_Viewport;

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
   * Runtime sub-layout used by `WINX_Exit` owner recovery.
   *
   * `mManagedSlotsHead` is the owner anchor used by `managedWindows`.
   */
  struct WWinManagedDialog : wxWindowBase
  {
    std::uint8_t mUnknown04To16F[0x16C];
    ManagedWindowSlot* mManagedSlotsHead = nullptr;

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

    /**
     * Address: 0x004F3F50 (FUN_004F3F50, WWinManagedDialog ctor tail)
     *
     * What it does:
     * Registers this dialog's owner-chain head in `managedWindows`.
     */
    void RegisterManagedOwnerSlot();

    /**
     * Address: 0x004F40A0 (FUN_004F40A0, WWinManagedDialog dtor core)
     *
     * What it does:
     * Unlinks and clears all slots currently chained under this dialog owner.
     */
    void ReleaseManagedOwnerSlots();

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);
  };

  static_assert(
    offsetof(WWinManagedDialog, mManagedSlotsHead) == 0x170,
    "moho::WWinManagedDialog::mManagedSlotsHead offset must be 0x170"
  );
  static_assert(sizeof(WWinManagedDialog) == 0x174, "moho::WWinManagedDialog size must be 0x174");

  /**
   * Runtime owner for the precreated log dialog object.
   *
   * Evidence:
   * - constructor body `FUN_004F4270` builds this object on top of
   *   `WWinManagedDialog` and wires all downstream controls/lanes.
   * - dtor body `FUN_004F5380` detaches from target, tears down local
   *   string/vector lanes, and releases managed-owner slots.
   */
  struct WWinLogWindow : WWinManagedDialog
  {
    std::uint8_t mIsInitializingControls = 0;
    std::uint8_t mUnknown175To177[0x3];
    CWinLogTarget* mOwnerTarget = nullptr;
    wxTextCtrlRuntime* mOutputTextControl = nullptr;
    wxTextCtrlRuntime* mFilterTextControl = nullptr;
    std::uint32_t mEnabledCategoriesMask = 0;
    msvc8::string mFilterText;
    wxCheckBoxRuntime* mDebugCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mInfoCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mWarnCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mErrorCategoryCheckBox = nullptr;
    wxCheckBoxRuntime* mCustomCategoryCheckBox = nullptr;
    msvc8::vector<msvc8::string> mBufferedLines;
    std::uint32_t mFirstVisibleLine = 0;

    /**
     * Address: 0x004F4270 (FUN_004F4270)
     *
     * What it does:
     * Constructs one managed log-window object and seeds downstream control
     * state lanes.
     */
    WWinLogWindow();

    /**
     * Address: 0x004F5380 (FUN_004F5380)
     * Mangled deleting-dtor thunk: 0x004F5360 (FUN_004F5360)
     *
     * What it does:
     * Detaches from the log-target owner, releases local lane storage, and
     * unlinks managed-owner slots.
     */
    ~WWinLogWindow();

    /**
     * Binds this window instance to one `CWinLogTarget` owner.
     *
     * Used by `WINX_PrecreateLogWindow` publication paths.
     */
    void SetOwnerTarget(CWinLogTarget* ownerTarget) noexcept;

    [[nodiscard]] std::array<wxCheckBoxRuntime*, 5> CategoryCheckBoxes() noexcept;
    [[nodiscard]] std::array<const wxCheckBoxRuntime*, 5> CategoryCheckBoxes() const noexcept;

    /**
     * Address: 0x004F5440 (FUN_004F5440)
     *
     * What it does:
     * Clears output and repopulates committed target lines from buffered replay
     * text entries.
     */
    void ResetCommittedLinesFromBuffer();

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

    void OnTargetPendingLinesChanged();

    /**
     * Address: 0x004F6470 (FUN_004F6470)
     *
     * What it does:
     * Merges pending target lines and refreshes visible output when committed
     * line count changed.
     */
    void OnTargetPendingLinesChanged(const CLogAdditionEvent& event);

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
     * Address: 0x004F5590 (FUN_004F5590)
     *
     * What it does:
     * Rebuilds the visible-line view from controls (filter + category checkbox
     * state) and then persists the new category checkbox states + filter text
     * back into user preferences. Bound into the WWinLogWindow wxEventTable as
     * a category/filter command handler.
     */
    void OnFilterOrCategoryControlsChanged();

    /**
     * Address: 0x004F6640 (FUN_004F6640)
     *
     * What it does:
     * Forwards to the standard wx top-level resize-single-child layout, then,
     * once initial control setup is complete, persists the current window
     * width/height into the `Windows.Log.{width,height}` preferences. Bound
     * into the WWinLogWindow wxEventTable as the wxEVT_SIZE handler.
     */
    void OnSizePersistGeometry(wxEventRuntime& event);

    /**
     * What it does:
     * Synthetic invocation entry that fires `OnFilterOrCategoryControlsChanged`
     * via the static wxEventTable binding block. Used by host code that needs
     * to re-fire the handler after programmatic control changes.
     */
    void FireFilterOrCategoryChangedFromBindings();

    /**
     * What it does:
     * Synthetic invocation entry that fires `OnSizePersistGeometry` via the
     * static wxEventTable binding block. Used by host code that needs to
     * re-fire the size handler after a programmatic geometry change.
     */
    void FireSizePersistGeometryFromBindings(wxEventRuntime& event);

  private:
    void InitializeFromUserPreferences();
    void RestoreCategoryStateFromPreferences(IUserPrefs* preferences);
    void RestoreFilterFromPreferences(IUserPrefs* preferences);
    void RestoreGeometryFromPreferences(IUserPrefs* preferences);
    void PersistCategoryStateAndFilterToPreferences(IUserPrefs* preferences);
  };

  static_assert(
    offsetof(WWinLogWindow, mOwnerTarget) == 0x178,
    "moho::WWinLogWindow::mOwnerTarget offset must be 0x178"
  );
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
  static_assert(
    offsetof(WWinLogWindow, mFilterText) == 0x188,
    "moho::WWinLogWindow::mFilterText offset must be 0x188"
  );
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
   * Runtime sub-layout used by `WINX_Exit` owner recovery.
   *
   * `mManagedSlotsHead` is the owner anchor used by `managedFrames`.
   */
  struct WWinManagedFrame : wxWindowBase
  {
    std::uint8_t mUnknown04To177[0x174];
    ManagedWindowSlot* mManagedSlotsHead = nullptr;

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

    /**
     * Address: 0x004F40E0 (FUN_004F40E0, WWinManagedFrame ctor tail)
     *
     * What it does:
     * Registers this frame's owner-chain head in `managedFrames`.
     */
    void RegisterManagedOwnerSlot();

    /**
     * Address: 0x004F4230 (FUN_004F4230, WWinManagedFrame dtor core)
     *
     * What it does:
     * Unlinks and clears all slots currently chained under this frame owner.
     */
    void ReleaseManagedOwnerSlots();

    static void DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots);
  };

  static_assert(
    offsetof(WWinManagedFrame, mManagedSlotsHead) == 0x178,
    "moho::WWinManagedFrame::mManagedSlotsHead offset must be 0x178"
  );
  static_assert(sizeof(WWinManagedFrame) == 0x17C, "moho::WWinManagedFrame size must be 0x17C");

  // Compatibility aliases while older call sites transition to owning names.
  using WWinManagedDialogRuntime = WWinManagedDialog;
  using WWinManagedFrameRuntime = WWinManagedFrame;

  // 0x010A9B94 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedWindows;
  // 0x010A9BD8 family in FA.
  extern msvc8::vector<ManagedWindowSlot> managedFrames;
  // 0x010A63B8 in FA.
  extern wxWindowBase* sMainWindow;
} // namespace moho
