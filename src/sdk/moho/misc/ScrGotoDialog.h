#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/app/WxRuntimeTypes.h"

namespace moho
{
  class ScrGotoDialog : public wxDialogRuntime
  {
  public:
    /**
     * Address: 0x004BBEA0 (FUN_004BBEA0)
     *
     * What it does:
     * Runs non-deleting teardown for one script goto dialog instance.
     */
    static ScrGotoDialog* DestroyWithoutDelete(ScrGotoDialog* object) noexcept;

    /**
     * Address: 0x004BC0C0 (FUN_004BC0C0)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for one script goto dialog.
     */
    static ScrGotoDialog* DeleteWithFlag(ScrGotoDialog* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x004BC0F0 (FUN_004BC0F0)
     *
     * What it does:
     * Returns this dialog runtime event-table lane.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004BBEB0 (FUN_004BBEB0)
     *
     * What it does:
     * Persists goto-dialog window position to user preferences after move
     * handling when startup initialization has completed.
     */
    void PersistWindowPositionToPreferences();

    /**
     * Address: 0x004BBFF0 (FUN_004BBFF0)
     *
     * What it does:
     * Reads goto-line text input and converts it to an integer line index.
     */
    [[nodiscard]] int ParseRequestedLineNumber() const;

    static void* sm_eventTable[1];

    std::uint8_t mIsInitializing = 0;
    std::uint8_t mPadding171To173[0x3]{};
    wxTextCtrlRuntime* mLineTextControl = nullptr;
    std::uint8_t mUnknown178To183[0xC]{};
  };

  static_assert(
    offsetof(ScrGotoDialog, mIsInitializing) == 0x170,
    "ScrGotoDialog::mIsInitializing offset must be 0x170"
  );
  static_assert(
    offsetof(ScrGotoDialog, mLineTextControl) == 0x174,
    "ScrGotoDialog::mLineTextControl offset must be 0x174"
  );
  static_assert(sizeof(ScrGotoDialog) == 0x184, "ScrGotoDialog size must be 0x184");
} // namespace moho

