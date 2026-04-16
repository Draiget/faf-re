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
class wxMoveEventRuntime;
class wxCloseEventRuntime;
class wxCommandEventRuntime;
class wxCursor;
class wxBitmap;
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
  virtual bool ProcessEvent(void* event)
  {
    (void)event;
    return false;
  }
  virtual bool SearchEventTable(void* eventTable, void* event)
  {
    (void)eventTable;
    (void)event;
    return false;
  }
  virtual const void* GetEventTable() const { return nullptr; }
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
   * Address: 0x00967650
   * Mangled: ?SetFocus@wxWindow@@UAEXXZ
   */
  virtual void SetFocus() {}
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
  virtual void AddChild(wxWindowBase* child) { (void)child; }
  virtual void RemoveChild(wxWindowBase* child) { (void)child; }
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
   * Address: 0x00964CA0 (FUN_00964CA0)
   * Mangled: ?CaptureMouse@wxWindowBase@@QAEXXZ
   *
   * What it does:
   * Releases any previously captured window, pushes that window onto the
   * capture-history lane, then requests capture for this window.
   */
  void CaptureMouse();

  virtual void Refresh(bool eraseBackground, const void* updateRect)
  {
    (void)eraseBackground;
    (void)updateRect;
  }
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
   * Address: 0x0042B820
   * Mangled: ?GetHandle@wxWindow@@UBEKXZ
   */
  virtual unsigned long GetHandle() const { return 0; }
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
  virtual void DoMoveWindow(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height)
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }
  virtual void DoSetToolTip(void* tooltip) { (void)tooltip; }
  virtual bool DoPopupMenu(void* menu, std::int32_t x, std::int32_t y)
  {
    (void)menu;
    (void)x;
    (void)y;
    return false;
  }
  virtual void AdjustForParentClientOrigin(std::int32_t& x, std::int32_t& y, std::int32_t sizeFlags) const
  {
    (void)x;
    (void)y;
    (void)sizeFlags;
  }
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
  virtual unsigned long MSWGetParent() const { return 0; }
  /**
   * Address: 0x009675F0 (FUN_009675F0)
   * Mangled: ?MSWCommand@wxWindow@@UAE_NIG@Z
   *
   * What it does:
   * Base window runtime does not consume Win32 command notifications.
   */
  virtual bool MSWCommand(unsigned int commandId, unsigned short notificationCode);

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
  virtual long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam)
  {
    (void)message;
    (void)wParam;
    (void)lParam;
    return 0;
  }
  virtual long MSWDefWindowProc(unsigned int message, unsigned int wParam, long lParam)
  {
    (void)message;
    (void)wParam;
    (void)lParam;
    return 0;
  }
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

  static void* sm_eventTable[1];
};

static_assert(sizeof(wxWindowMswRuntime) == 0x4, "wxWindowMswRuntime size must be 0x4");

class wxControlRuntime : public wxWindowMswRuntime
{
public:
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
 * Minimal recovered `wxStreamBase` lane used by input stream constructors.
 */
class wxStreamBase
{
public:
  /**
   * Address: 0x009DCEE0 (FUN_009DCEE0)
   * Mangled: ??0wxStreamBase@@QAE@@Z
   *
   * What it does:
   * Initializes one stream-base runtime lane and binds the base vtable.
   */
  wxStreamBase();
  virtual ~wxStreamBase() = default;

protected:
  std::uint8_t mStatusLane[0x8]{};
};

static_assert(sizeof(wxStreamBase) == 0xC, "wxStreamBase size must be 0xC");

class wxInputStream : public wxStreamBase
{
public:
  /**
   * Address: 0x009DCF40 (FUN_009DCF40)
   * Mangled: ??0wxInputStream@@QAE@@Z
   *
   * What it does:
   * Initializes pushback-lane counters to zero and binds the input-stream
   * runtime vtable.
   */
  wxInputStream();
  ~wxInputStream() override = default;

  /**
   * Address: 0x009DD0F0 (FUN_009DD0F0)
   *
   * What it does:
   * Reads one byte from the stream backend and returns the resulting character
   * lane.
   */
  char GetC();

public:
  std::int32_t m_wback = 0;
  std::int32_t m_wbackcur = 0;
  std::int32_t m_wbacksize = 0;
};

static_assert(offsetof(wxInputStream, m_wback) == 0xC, "wxInputStream::m_wback offset must be 0xC");
static_assert(offsetof(wxInputStream, m_wbackcur) == 0x10, "wxInputStream::m_wbackcur offset must be 0x10");
static_assert(offsetof(wxInputStream, m_wbacksize) == 0x14, "wxInputStream::m_wbacksize offset must be 0x14");
static_assert(sizeof(wxInputStream) == 0x18, "wxInputStream size must be 0x18");

class wxOutputStream : public wxStreamBase
{
public:
  /**
   * Address: 0x009DD2B0 (FUN_009DD2B0)
   * Mangled: ??0wxOutputStream@@QAE@@Z
   *
   * What it does:
   * Initializes one output-stream runtime lane and binds the derived vtable.
   */
  wxOutputStream();
  ~wxOutputStream() override = default;
};

static_assert(sizeof(wxOutputStream) == 0xC, "wxOutputStream size must be 0xC");

/**
 * Minimal recovered `wxFile` lane used by `wxFileInputStream`.
 */
class wxFile
{
public:
  enum OpenMode : std::int32_t
  {
    OpenRead = 0,
    OpenWrite = 1,
    OpenReadWrite = 2,
    OpenWriteAppend = 3,
    OpenWriteExcl = 4,
  };

  /**
   * Address: 0x00A12870 (FUN_00A12870)
   * Mangled: ??0wxFile@@QAE@PBGW4OpenMode@0@@Z
   *
   * What it does:
   * Initializes one file lane and attempts to open the requested wide path.
   */
  wxFile(const wchar_t* fileName, OpenMode mode);
  ~wxFile();

  /**
   * Address: 0x00A11F50 (FUN_00A11F50)
   * Mangled: ?Exists@wxFile@@SA_NPB_W@Z
   *
   * What it does:
   * Probes one wide path and reports whether it exists as a non-directory file.
   */
  static bool Exists(const wchar_t* fileName);

  /**
   * Address: 0x00A12020 (FUN_00A12020)
   * Mangled: ?Attach@wxFile@@QAE_NXZ
   *
   * What it does:
   * Closes the current file descriptor lane when open and resets it to `-1`.
   */
  bool Attach();

  /**
   * Address: 0x00A12080 (FUN_00A12080)
   * Mangled: ?Read@wxFile@@QAEJPAXJ@Z
   *
   * What it does:
   * Reads up to `bytesToRead` bytes from the open descriptor into `buffer`,
   * logging a localized system error when `_read()` fails.
   */
  long Read(void* buffer, long bytesToRead);

  /**
   * Address: 0x00A120F0 (FUN_00A120F0)
   * Mangled: ?Write@wxFile@@QAEJPBXJ@Z
   *
   * What it does:
   * Writes up to `bytesToWrite` bytes from `buffer` to the open descriptor and
   * sets the wx file error lane when `_write()` fails.
   */
  long Write(const void* buffer, long bytesToWrite);

  /**
   * Address: 0x00A12150 (FUN_00A12150)
   * Mangled: ?Flush@wxFile@@QAE_NXZ
   *
   * What it does:
   * Commits one descriptor lane to storage (`_commit`) when open, logging a
   * localized system error on failure.
   */
  bool Flush();

  /**
   * Address: 0x00A12290 (FUN_00A12290)
   * Mangled: ?Length@wxFile@@QBEJXZ
   *
   * What it does:
   * Returns the current byte length of the open descriptor and logs a
   * localized system error when length resolution fails.
   */
  [[nodiscard]] long Length() const;

  /**
   * Address: 0x00A12230 (FUN_00A12230)
   * Mangled: ?Tell@wxFile@@QBEJXZ
   *
   * What it does:
   * Returns the current seek position for the open descriptor.
   */
  [[nodiscard]] long Tell() const;

  /**
   * Address: 0x00A121B0 (FUN_00A121B0)
   * Mangled: ?Seek@wxFile@@QAEJJW4wxSeekMode@@@Z
   *
   * What it does:
   * Applies one descriptor seek operation with start/current/end origin
   * semantics and returns the resulting position.
   */
  long Seek(long distanceToMove, int seekMode);

  /**
   * Address: 0x00A12600 (FUN_00A12600)
   *
   * What it does:
   * Creates/opens one writable descriptor for `fileName` using either
   * overwrite (`_O_TRUNC`) or exclusive-create (`_O_EXCL`) semantics.
   */
  bool Create(const wchar_t* fileName, bool overwrite, std::int32_t permissions);

  /**
   * Address: 0x00A12690 (FUN_00A12690)
   * Mangled: ?Open@wxFile@@QAE_NPB_WW4OpenMode@1@H@Z
   *
   * What it does:
   * Opens one wide path with mode-specific CRT flags and rebinds `m_fd` to
   * the new descriptor on success.
   */
  bool Open(const wchar_t* fileName, OpenMode mode, std::int32_t permissions);

public:
  std::int32_t m_fd = -1;
  std::uint8_t m_error = 0;
  std::uint8_t mPadding05[0x3]{};
};

static_assert(offsetof(wxFile, m_fd) == 0x0, "wxFile::m_fd offset must be 0x0");
static_assert(offsetof(wxFile, m_error) == 0x4, "wxFile::m_error offset must be 0x4");
static_assert(sizeof(wxFile) == 0x8, "wxFile size must be 0x8");

class wxFileInputStream : public wxInputStream
{
public:
  /**
   * Address: 0x009DBAF0 (FUN_009DBAF0)
   * Mangled: ??0wxFileInputStream@@QAE@@Z
   *
   * What it does:
   * Builds one file-backed input stream by constructing/opening `m_file` from
   * the provided wide path and marking stream-owned file destruction.
   */
  explicit wxFileInputStream(const wxStringRuntime& fileName);
  ~wxFileInputStream() override;

  /**
   * Address: 0x009DBCD0 (FUN_009DBCD0)
   *
   * What it does:
   * Returns the current input-stream file-position lane by delegating to the
   * wrapped `wxFile` descriptor.
   */
  [[nodiscard]] long OnSysTell() const;

  /**
   * Address: 0x009DBCC0 (FUN_009DBCC0)
   *
   * What it does:
   * Repositions the wrapped `wxFile` descriptor lane using wx seek-mode
   * semantics.
   */
  long OnSysSeek(long distanceToMove, int seekMode);

public:
  wxFile* m_file = nullptr;
  std::uint8_t m_file_destroy = 0;
  std::uint8_t mPadding1D[0x3]{};
};

static_assert(offsetof(wxFileInputStream, m_file) == 0x18, "wxFileInputStream::m_file offset must be 0x18");
static_assert(
  offsetof(wxFileInputStream, m_file_destroy) == 0x1C,
  "wxFileInputStream::m_file_destroy offset must be 0x1C"
);
static_assert(sizeof(wxFileInputStream) == 0x20, "wxFileInputStream size must be 0x20");

/**
 * Minimal recovered `wxFFile` lane used by wx stream/file wrappers.
 */
class wxFFile
{
public:
  /**
   * Address: 0x00999A00 (FUN_00999A00)
   *
   * What it does:
   * Closes the active file lane and releases shared ownership of the
   * associated wx filename string payload.
   */
  ~wxFFile();

  /**
   * Address: 0x009FAB40 (FUN_009FAB40)
   * Mangled: ?Read@wxFFile@@QAEIPAXI@Z
   *
   * What it does:
   * Reads up to `byteCount` bytes from the current `FILE*` and logs a
   * localized read error when `ferror()` reports failure.
   */
  unsigned int Read(void* buffer, unsigned int byteCount);

  /**
   * Address: 0x009FABD0 (FUN_009FABD0)
   * Mangled: ?Write@wxFFile@@QAEIPBXI@Z
   *
   * What it does:
   * Writes up to `byteCount` bytes from `buffer` into the current `FILE*` lane
   * and logs a localized system error on short write.
   */
  unsigned int Write(const void* buffer, unsigned int byteCount);

  /**
   * Address: 0x00999960 (FUN_00999960)
   *
   * What it does:
   * Converts one wx UTF-16 text lane into narrow text and writes the full
   * byte span; returns `true` only when all bytes are written.
   */
  bool Write(const wxStringRuntime& text);

  /**
   * Address: 0x009FAAE0 (FUN_009FAAE0)
   *
   * What it does:
   * Closes the active `FILE*` lane and logs a localized system error when
   * `fclose()` fails.
   */
  bool Close();

  /**
   * Address: 0x009FAC50 (FUN_009FAC50)
   * Mangled: ?Flush@wxFFile@@QAE_NXZ
   *
   * What it does:
   * Flushes the active `FILE*` lane with `fflush()` and logs a localized
   * system error when the flush fails.
   */
  bool Flush();

  /**
   * Address: 0x009FACB0 (FUN_009FACB0, sub_9FACB0)
   *
   * What it does:
   * Repositions the active `FILE*` lane using wx seek-mode semantics and logs
   * one localized error on seek failure.
   */
  bool Seek(long distanceToMove, int seekMode);

  /**
   * Address: 0x009FAD40 (FUN_009FAD40)
   * Mangled: ?Tell@wxFFile@@QBEIXZ
   *
   * What it does:
   * Returns the current file-position lane (`ftell`) and logs a localized
   * system error when position lookup fails.
   */
  [[nodiscard]] unsigned int Tell() const;

  /**
   * Address: 0x009FAE20 (FUN_009FAE20, sub_9FAE20)
   *
   * What it does:
   * Computes one file-length lane by seeking to end, reading the end position,
   * and restoring the original cursor lane.
   */
  [[nodiscard]] int Length();

public:
  FILE* m_file = nullptr;
  wxStringRuntime m_name;
};

static_assert(offsetof(wxFFile, m_file) == 0x0, "wxFFile::m_file offset must be 0x0");
static_assert(offsetof(wxFFile, m_name) == 0x4, "wxFFile::m_name offset must be 0x4");
static_assert(sizeof(wxFFile) == 0x8, "wxFFile size must be 0x8");

/**
 * Minimal recovered `wxTempFile` lane that stores source/temp names and one
 * embedded `wxFile` descriptor wrapper.
 */
class wxTempFile
{
public:
  /**
   * Address: 0x00A127D0 (FUN_00A127D0)
   * Mangled: ??1wxTempFile@@QAE@XZ
   *
   * What it does:
   * Runs temp-file teardown by discarding an open temp descriptor, closing the
   * embedded file lane, and releasing both owned wxString path lanes.
   */
  ~wxTempFile();

  /**
   * Address: 0x00A12580 (FUN_00A12580)
   * Mangled: ?Discard@wxTempFile@@QAEXXZ
   *
   * What it does:
   * Closes the embedded temp descriptor and removes the temp file path,
   * logging a localized error when removal fails.
   */
  void Discard();

public:
  wxStringRuntime m_originalPath;
  wxStringRuntime m_tempPath;
  wxFile m_file;
};

static_assert(offsetof(wxTempFile, m_originalPath) == 0x0, "wxTempFile::m_originalPath offset must be 0x0");
static_assert(offsetof(wxTempFile, m_tempPath) == 0x4, "wxTempFile::m_tempPath offset must be 0x4");
static_assert(offsetof(wxTempFile, m_file) == 0x8, "wxTempFile::m_file offset must be 0x8");
static_assert(sizeof(wxTempFile) == 0x10, "wxTempFile size must be 0x10");

/**
 * Minimal recovered output-stream runtime lane that owns a `wxFile*` pointer.
 */
class wxFileOutputStream
{
public:
  /**
   * Address: 0x009DBCE0 (FUN_009DBCE0)
   *
   * What it does:
   * Initializes one file-backed output stream by constructing/opening `m_file`
   * from the provided wide path and marking stream-owned file destruction.
   */
  explicit wxFileOutputStream(const wxStringRuntime& fileName);

  /**
   * Address: 0x009DBDD0 (FUN_009DBDD0)
   *
   * What it does:
   * Initializes one file-backed output stream from an already-open file
   * descriptor lane and marks stream-owned `wxFile` destruction.
   */
  explicit wxFileOutputStream(int fileDescriptor);

  /**
   * Address: 0x009DBE90 (FUN_009DBE90)
   * Mangled: ?Sync@wxFileOutputStream@@UAEXXZ
   *
   * What it does:
   * Executes the wx file-flush hook lane then synchronizes the underlying
   * `wxFile` descriptor with `wxFile::Flush()`.
   */
  void Sync();

  /**
   * Address: 0x009DBE70 (FUN_009DBE70)
   * Mangled: ?OnSysTell@wxFileOutputStream@@MBEJXZ
   *
   * What it does:
   * Returns the current output-stream file position by delegating to the
   * wrapped `wxFile` lane.
   */
  [[nodiscard]] long OnSysTell() const;

  /**
   * Address: 0x009DBE80 (FUN_009DBE80)
   * Mangled: ?OnSysSeek@wxFileOutputStream@@MAEJJW4wxSeekMode@@@Z
   *
   * What it does:
   * Repositions the wrapped `wxFile` lane using wx seek-mode semantics.
   */
  long OnSysSeek(long distanceToMove, int seekMode);

public:
  std::uint8_t m_streamRuntime00[0x0C]{};
  wxFile* m_file = nullptr;
  std::uint8_t m_ownsFile = 0;
  std::uint8_t mPadding11[0x3]{};
};

static_assert(offsetof(wxFileOutputStream, m_file) == 0x0C, "wxFileOutputStream::m_file offset must be 0x0C");
static_assert(offsetof(wxFileOutputStream, m_ownsFile) == 0x10, "wxFileOutputStream::m_ownsFile offset must be 0x10");
static_assert(sizeof(wxFileOutputStream) == 0x14, "wxFileOutputStream size must be 0x14");

/**
 * Minimal recovered output-stream runtime lane that owns a `wxFFile*` pointer.
 */
class wxFFileOutputStream
{
public:
  /**
   * Address: 0x009DC2C0 (FUN_009DC2C0)
   * Mangled: ?Sync@wxFFileOutputStream@@UAEXXZ
   *
   * What it does:
   * Executes the wx file-flush hook lane then synchronizes the underlying
   * `wxFFile` stream with `wxFFile::Flush()`.
   */
  void Sync();

public:
  std::uint8_t m_streamRuntime00[0x0C]{};
  wxFFile* m_file = nullptr;
  std::uint8_t m_ownsFile = 0;
  std::uint8_t mPadding11[0x3]{};
};

static_assert(offsetof(wxFFileOutputStream, m_file) == 0x0C, "wxFFileOutputStream::m_file offset must be 0x0C");
static_assert(offsetof(wxFFileOutputStream, m_ownsFile) == 0x10, "wxFFileOutputStream::m_ownsFile offset must be 0x10");
static_assert(sizeof(wxFFileOutputStream) == 0x14, "wxFFileOutputStream size must be 0x14");

class wxFileName
{
public:
  static void SplitPath(
    const wxStringRuntime& input,
    wxStringRuntime* volume,
    wxStringRuntime* path,
    wxStringRuntime* name,
    wxStringRuntime* ext,
    const wchar_t* formatHint
  );

  /**
   * Address: 0x009F5820 (FUN_009F5820)
   * Mangled: ?SplitPath_0@wxFileName@@SAXABVwxString@@PAV2@00PA_W@Z
   *
   * What it does:
   * Splits a path into path/name/ext lanes and then prepends the normalized
   * volume-prefix lane onto the path output lane when present.
   */
  static void SplitPath_0(
    const wxStringRuntime& input,
    wxStringRuntime* path,
    wxStringRuntime* name,
    wxStringRuntime* ext,
    const wchar_t* formatHint
  );
};

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

class wxDCBase
{
public:
  wxDCBase();
  virtual ~wxDCBase() = default;
};

class wxDC : public wxDCBase
{
public:
  /**
   * Address: 0x009CA490 (FUN_009CA490)
   * Mangled: ??0wxDC@@QAE@@Z
   *
   * What it does:
   * Initializes base device-context lanes and clears selected object / native
   * handle state.
   */
  wxDC();
  ~wxDC() override = default;

  [[nodiscard]] void* GetNativeHandle() const noexcept { return m_hDC; }

protected:
  void* m_selectedBitmap = nullptr;
  std::uint8_t m_bOwnsDC = 0;
  std::uint8_t m_flags = 0;
  std::uint8_t mPadding0A[0x2]{};
  void* m_canvas = nullptr;
  void* m_oldBitmap = nullptr;
  void* m_oldPen = nullptr;
  void* m_oldBrush = nullptr;
  void* m_oldFont = nullptr;
  void* m_oldPalette = nullptr;
  void* m_hDC = nullptr;
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

struct wxColourRuntime
{
  std::uint8_t mStorage[0x10]{};

  [[nodiscard]] static wxColourRuntime FromRgb(
    std::uint8_t red, std::uint8_t green, std::uint8_t blue
  ) noexcept;
  [[nodiscard]] static const wxColourRuntime& Null() noexcept;
};

static_assert(sizeof(wxColourRuntime) == 0x10, "wxColourRuntime size must be 0x10");

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
   * Address: 0x0098C9B0 (FUN_0098C9B0, wxTopLevelWindowMSW::MSWGetParent)
   * Mangled: ?MSWGetParent@wxTopLevelWindowMSW@@UBEKXZ
   *
   * What it does:
   * Lazily registers and creates the hidden Win32 parent window used by
   * top-level wx windows, then returns its native handle lane.
   */
  [[nodiscard]] unsigned long MSWGetParent() const override;

  /**
   * Address: 0x0098C760 (FUN_0098C760)
   *
   * What it does:
   * Enables or disables the native system-menu Close command, then redraws the
   * menu bar when the command-state update succeeds.
   */
  bool SetSystemCloseMenuItemEnabled(bool enabled);

  /**
   * Address: 0x0098C1E0 family
   * Mangled: ?Maximize@wxTopLevelWindowMSW@@UAEX_N@Z
   */
  virtual void Maximize(bool maximize) { (void)maximize; }
  virtual void Restore() {}
  virtual void Iconize(bool iconize) { (void)iconize; }
  virtual bool IsMaximized() const { return false; }
  virtual bool IsIconized() const { return false; }
  virtual void SetIcon(const void* icon) { (void)icon; }
  virtual void SetIcons(const void* iconBundle) { (void)iconBundle; }
  virtual bool ShowFullScreen(bool show, long style)
  {
    (void)show;
    (void)style;
    return false;
  }

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

  static void* sm_classInfo[1];
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
[[nodiscard]] void** WX_FrameBaseGetClassInfo() noexcept;

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

  static void* sm_classInfo[1];
  static void* sm_eventTable[1];

  std::uint8_t mUnknown15CTo16F[0x14]{};
};

static_assert(sizeof(wxDialogRuntime) == 0x170, "wxDialogRuntime size must be 0x170");

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

  static void* sm_classInfo[1];
  static void* sm_eventTable[1];

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

  virtual void* GetClassInfo() const = 0;
  virtual void DeleteObject() = 0;
  virtual void* CreateRefData() const = 0;
  virtual void* CloneRefData(const void* sourceRefData) const = 0;
  virtual bool ProcessEvent(void* event) = 0;
  virtual bool SearchEventTable(void* eventTable, void* event) = 0;
  virtual const void* GetEventTable() const = 0;
  virtual void DoSetClientObject(void* clientObject) = 0;
  virtual void* DoGetClientObject() const = 0;
  virtual void DoSetClientData(void* clientData) = 0;
  virtual void* DoGetClientData() const = 0;
  virtual bool OnInit() = 0;
  virtual bool OnInitGui() = 0;
  virtual int OnRun() = 0;

  /**
   * Address: 0x009AA860
   * Mangled: ?OnExit@wxAppBase@@UAEHXZ
   */
  virtual int OnExit();

  virtual void OnFatalException() = 0;
  virtual int MainLoop() = 0;
  virtual void ExitMainLoop() = 0;
  virtual bool Initialized() = 0;

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
  virtual bool Yield(bool onlyIfNeeded) = 0;

  /**
   * Address: 0x00992190
   * Mangled: ?ProcessIdle@wxApp@@UAE_NXZ
   */
  virtual bool ProcessIdle();
  virtual bool IsActive() const = 0;
  virtual wxWindowBase* GetTopWindow() const = 0;
  virtual void OnInitCmdLine(void* cmdLineParser) = 0;
  virtual bool OnCmdLineParsed(void* cmdLineParser) = 0;
  virtual bool OnCmdLineHelp(void* cmdLineParser) = 0;
  virtual bool OnCmdLineError(void* cmdLineParser) = 0;
  virtual void* CreateLogTarget() = 0;
  virtual void* CreateMessageOutput() = 0;
  virtual void* GetStdIcon(std::int32_t iconId) const = 0;
  virtual void* GetDisplayMode() const = 0;
  virtual bool SetDisplayMode(const void* displayMode) = 0;
  virtual void SetPrintMode(std::int32_t mode) = 0;
  virtual void SetActive(bool isActive, wxWindowBase* topWindow) = 0;
  virtual std::int32_t FilterEvent(void* event) = 0;
  virtual void ProcessPendingEvents() = 0;
  virtual std::int32_t GetPrintMode() const = 0;

  /**
   * Address: 0x00993100 (FUN_00993100)
   * Mangled: ?DoMessage@wxApp@@UAE_NXZ
   *
   * What it does:
   * Pumps one Win32 message for the wx app loop, dispatching immediately on
   * the GUI owner thread and deferring cross-thread deliveries.
   */
  virtual bool DoMessage();
  virtual void DoMessage(void** message) = 0;
  virtual bool ProcessMessage(void** message) = 0;

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

  wxStringRuntime m_className{};
  wxStringRuntime m_vendorName{};
  wxStringRuntime m_appName{};

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
  offsetof(wxApp, m_className) == 0x34,
  "wxApp::m_className offset must be 0x34"
);
static_assert(
  offsetof(wxApp, m_vendorName) == 0x38,
  "wxApp::m_vendorName offset must be 0x38"
);
static_assert(
  offsetof(wxApp, m_appName) == 0x3C,
  "wxApp::m_appName offset must be 0x3C"
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
  wxEraseEventRuntime* Clone() const override { return nullptr; }

  void* mDeviceContext = nullptr; // +0x20
};

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

  /**
   * Recovered curve-editor panel runtime owner.
   *
   * Evidence:
   * - `FUN_009AE6D0` is the non-deleting destructor lane.
   * - `FUN_00663870` and duplicate thunks run deleting-dtor semantics.
   * - `FUN_006638A0` returns this type's static event-table lane.
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

    static void* sm_eventTable[1];
  };

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

    static void* sm_eventTable[1];
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

    static void* sm_eventTable[1];
  };

  static_assert(
    offsetof(WBitmapCheckBox, mIsChecked) == 0x168,
    "moho::WBitmapCheckBox::mIsChecked offset must be 0x168"
  );

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

    static void* sm_eventTable[1];
  };

  static_assert(offsetof(WRenViewport, mRenderState0C) == 0x0C, "moho::WRenViewport::mRenderState0C offset must be 0x0C");
  static_assert(offsetof(WRenViewport, mEnabled) == 0x1D, "moho::WRenViewport::mEnabled offset must be 0x1D");
  static_assert(offsetof(WRenViewport, m_parent) == 0x2C, "moho::WRenViewport::m_parent offset must be 0x2C");

  struct wxPaintEventRuntime
  {
    std::uint8_t mStorage[0x24];
  };

  static_assert(sizeof(wxPaintEventRuntime) == 0x24, "moho::wxPaintEventRuntime size must be 0x24");

  struct wxDCRuntime
  {
    explicit wxDCRuntime(wxWindowBase* ownerWindow) noexcept;

    void SetBrush(const void* brushToken) noexcept;
    void DoGetSize(std::int32_t* outWidth, std::int32_t* outHeight) const noexcept;
    void DoDrawRectangle(std::int32_t x, std::int32_t y, std::int32_t width, std::int32_t height) noexcept;

  private:
    wxWindowBase* mOwnerWindow = nullptr;
    const void* mActiveBrush = nullptr;
  };

  struct wxPaintDCRuntime : wxDCRuntime
  {
    explicit wxPaintDCRuntime(wxWindowBase* ownerWindow) noexcept;
    ~wxPaintDCRuntime();
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
     */
    virtual void D3DWindowOnDeviceInit();

    /**
     * Address: 0x0042BB00 (FUN_0042BB00)
     */
    virtual void D3DWindowOnDeviceRender();

    /**
     * Address: 0x0042BB10 (FUN_0042BB10)
     */
    virtual void D3DWindowOnDeviceExit();

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
     * Address: 0x00430B90 (FUN_00430B90)
     * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
     *
     * What it does:
     * Handles cursor message routing for D3D cursor ownership and forwards
     * unhandled messages to base wx window dispatch.
     */
    long MSWWindowProc(unsigned int message, unsigned int wParam, long lParam) override;

    static void* sm_eventTable[1];
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

  private:
    void InitializeFromUserPreferences();
    void RestoreCategoryStateFromPreferences(IUserPrefs* preferences);
    void RestoreFilterFromPreferences(IUserPrefs* preferences);
    void RestoreGeometryFromPreferences(IUserPrefs* preferences);
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
