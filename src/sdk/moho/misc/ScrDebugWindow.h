#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/ScrSourceCtrl.h"

namespace moho
{
  class ScrWatchCtrl;

  struct wxAccelTableEntryRuntime
  {
    std::uint32_t flags = 0;
    std::uint32_t keyCode = 0;
    std::uint32_t commandId = 0;
    void* commandTarget = nullptr;
  };

  static_assert(sizeof(wxAccelTableEntryRuntime) == 0x10, "wxAccelTableEntryRuntime size must be 0x10");

  class ScrDebugWindow : public wxTopLevelWindowRuntime
  {
  public:
    /**
     * Address: 0x004BEB70 (FUN_004BEB70)
     *
     * What it does:
     * Runs non-deleting teardown for one script-debug window instance,
     * releasing recent-file list and selected-path storage before frame-base
     * destruction.
     */
    static ScrDebugWindow* DestroyWithoutDelete(ScrDebugWindow* object) noexcept;

    /**
     * Address: 0x004BEB40 (FUN_004BEB40)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for one script-debug window.
     */
    static ScrDebugWindow* DeleteWithFlag(ScrDebugWindow* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x004BEBE0 (FUN_004BEBE0)
     *
     * msvc8::string const &
     *
     * What it does:
     * Opens or selects one mounted source path in the source-page control and
     * appends it to recent debug source files when not already listed.
     */
    bool OpenMountedSourcePathAndTrackRecent(const msvc8::string& mountedSourcePath);

    /**
     * Address: 0x004BC100 (FUN_004BC100)
     *
     * What it does:
     * Returns this debug-window event-table lane.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004BECF0 (FUN_004BECF0)
     *
     * void *
     *
     * What it does:
     * Opens/focuses paused source location, rebuilds call-stack + watch lanes,
     * and disables viewport render while script execution is paused.
     */
    void OnScriptPauseEvent(void* pauseEvent);

    /**
     * Address: 0x004BF750 (FUN_004BF750)
     *
     * void *
     *
     * What it does:
     * Focuses the call-stack-selected activation source location and rebuilds
     * local watch lanes for that activation level.
     */
    void OnCallStackSelectionChanged(void* listEvent);

    /**
     * Address: 0x004BF630 (FUN_004BF630)
     *
     * void *
     *
     * IDA signature:
     * Moho::WRenViewport *__thiscall sub_4BF630(int this, int a2)
     *
     * What it does:
     * Clears active source-line execution markers across all open source pages,
     * clears watch rows, then performs one script-debug step.
     */
    void OnStepCommand(void* commandEvent);

    /**
     * Address: 0x004BF690 (FUN_004BF690)
     *
     * void *
     *
     * IDA signature:
     * Moho::WRenViewport *__thiscall sub_4BF690(int this, int a2)
     *
     * What it does:
     * Clears active source-line execution markers across all open source pages,
     * clears watch rows, then resumes script-debug execution.
     */
    void OnResumeCommand(void* commandEvent);

    /**
     * Address: 0x004BF6F0 (FUN_004BF6F0)
     *
     * void *
     *
     * IDA signature:
     * void __stdcall sub_4BF6F0(int a1)
     *
     * What it does:
     * Marks all source-line breakpoint indicators as enabled and enables all
     * persisted global script breakpoints.
     */
    void OnEnableAllBreakpointsCommand(void* commandEvent);

    /**
     * Address: 0x004BF710 (FUN_004BF710)
     *
     * void *
     *
     * IDA signature:
     * void __stdcall sub_4BF710(int a1)
     *
     * What it does:
     * Marks all source-line breakpoint indicators as disabled and disables all
     * persisted global script breakpoints.
     */
    void OnDisableAllBreakpointsCommand(void* commandEvent);

    /**
     * Address: 0x004BF960 (FUN_004BF960)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BF960(_BYTE *this, int a2)
     *
     * What it does:
     * Persists the vertical splitter sash position while startup control wiring
     * is complete.
     */
    void OnVerticalSashPositionChanged(void* splitterEvent);

    /**
     * Address: 0x004BFA00 (FUN_004BFA00)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BFA00(_BYTE *this, int a2)
     *
     * What it does:
     * Persists the horizontal splitter sash position while startup control
     * wiring is complete.
     */
    void OnHorizontalSashPositionChanged(void* splitterEvent);

    /**
     * Address: 0x004BFAA0 (FUN_004BFAA0)
     *
     * void *
     *
     * IDA signature:
     * void __userpurge sub_4BFAA0(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
     *
     * What it does:
     * Persists call-stack column widths (source/block/line) to user
     * preferences while startup control wiring is complete.
     */
    void OnCallStackColumnsResized(void* commandEvent);

    /**
     * Address: 0x004BFC00 (FUN_004BFC00)
     *
     * void *
     *
     * IDA signature:
     * void __userpurge sub_4BFC00(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
     *
     * What it does:
     * Persists local-watch column widths (name/type/value) to user preferences
     * while startup control wiring is complete.
     */
    void OnLocalWatchColumnsResized(void* commandEvent);

    /**
     * Address: 0x004BFD60 (FUN_004BFD60)
     *
     * void *
     *
     * IDA signature:
     * void __userpurge sub_4BFD60(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
     *
     * What it does:
     * Persists global-watch column widths (name/type/value) to user
     * preferences while startup control wiring is complete.
     */
    void OnGlobalWatchColumnsResized(void* commandEvent);

    /**
     * Address: 0x004BF120 (FUN_004BF120)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BF120(_DWORD *this, int a2)
     *
     * What it does:
     * Removes the currently selected source page, removes one matching recent
     * source-file entry, and persists the updated recent-file list.
     */
    void OnRemoveCurrentSourceCommand(void* commandEvent);

    /**
     * Address: 0x004BF220 (FUN_004BF220)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BF220(_DWORD *this, int a2)
     *
     * What it does:
     * Repeatedly removes selected source pages until no source remains selected,
     * erasing matching recent-file entries and persisting each update.
     */
    void OnRemoveAllSourcePagesCommand(void* commandEvent);

    /**
     * Address: 0x004BF400 (FUN_004BF400)
     *
     * void *
     *
     * IDA signature:
     * int __thiscall sub_4BF400(_DWORD *this, int a2)
     *
     * What it does:
     * Shows the goto-line dialog and focuses the requested source line on the
     * currently selected source page.
     */
    void OnGotoLineCommand(void* commandEvent);

    /**
     * Address: 0x004BF4C0 (FUN_004BF4C0)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BF4C0(int this, int a2)
     *
     * What it does:
     * Copies selected-source text into window state and focuses the first
     * matching source line in the currently selected source page.
     */
    void OnSelectedSourcePathChanged(void* commandEvent);

    /**
     * Address: 0x004BF840 (FUN_004BF840)
     *
     * void *
     *
     * IDA signature:
     * void __thiscall sub_4BF840(int this, int a2)
     *
     * What it does:
     * Reads the currently activated source path from the source-tree owner
     * control, converts it to mounted-path form, and opens/tracks that source.
     */
    void OnSourceTreeItemActivated(void* commandEvent);

    /**
     * Address: 0x004BFEC0 (FUN_004BFEC0)
     *
     * void *
     *
     * IDA signature:
     * void __userpurge sub_4BFEC0(_BYTE *a1@<ecx>, int a2@<esi>, int a3)
     *
     * What it does:
     * Persists debug-window X/Y position lanes while startup control wiring is
     * complete.
     */
    void OnWindowMoved(void* commandEvent);

    static void* sm_eventTable[1];

    std::uint8_t mUnknown004To177[0x174]{};
    std::uint8_t mIsInitializingControls = 0; // +0x178
    std::uint8_t mUnknown179To17F[0x7]{};
    void* mSourcePathOwnerControl = nullptr;  // +0x180
    ScrSourceCtrl* mSourceControl = nullptr;  // +0x184
    void* mCallStackControl = nullptr;        // +0x188
    ScrWatchCtrl* mLocalWatchControl = nullptr;   // +0x18C
    ScrWatchCtrl* mGlobalWatchControl = nullptr;  // +0x190
    msvc8::string mSelectedSourcePath{};
    void* mSelectedSourceControl = nullptr;   // +0x1B0
    msvc8::list<msvc8::string> mRecentSourceFiles{};
  };

  /**
   * Address: 0x004BEB60 (FUN_004BEB60)
   *
   * What it does:
   * Clears one accelerator-entry runtime lane before constructor wiring.
   */
  void ResetAccelTableEntry(wxAccelTableEntryRuntime& entry) noexcept;
} // namespace moho

static_assert(sizeof(moho::ScrDebugWindow) == 0x1C0, "ScrDebugWindow size must be 0x1C0");
static_assert(
  offsetof(moho::ScrDebugWindow, mUnknown004To177) == 0x4,
  "ScrDebugWindow::mUnknown004To177 offset must be 0x4"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mIsInitializingControls) == 0x178,
  "ScrDebugWindow::mIsInitializingControls offset must be 0x178"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mUnknown179To17F) == 0x179,
  "ScrDebugWindow::mUnknown179To17F offset must be 0x179"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mSourcePathOwnerControl) == 0x180,
  "ScrDebugWindow::mSourcePathOwnerControl offset must be 0x180"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mSourceControl) == 0x184,
  "ScrDebugWindow::mSourceControl offset must be 0x184"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mCallStackControl) == 0x188,
  "ScrDebugWindow::mCallStackControl offset must be 0x188"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mLocalWatchControl) == 0x18C,
  "ScrDebugWindow::mLocalWatchControl offset must be 0x18C"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mGlobalWatchControl) == 0x190,
  "ScrDebugWindow::mGlobalWatchControl offset must be 0x190"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mSelectedSourcePath) == 0x194,
  "ScrDebugWindow::mSelectedSourcePath offset must be 0x194"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mSelectedSourceControl) == 0x1B0,
  "ScrDebugWindow::mSelectedSourceControl offset must be 0x1B0"
);
static_assert(
  offsetof(moho::ScrDebugWindow, mRecentSourceFiles) == 0x1B4,
  "ScrDebugWindow::mRecentSourceFiles offset must be 0x1B4"
);
