#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/app/WxRuntimeTypes.h"

namespace moho
{
  struct ScrSourcePageRuntimeLane;

  struct wxArrayPtrVoidRuntime
  {
    ScrSourcePageRuntimeLane** mItemsBegin = nullptr;
    ScrSourcePageRuntimeLane** mItemsEnd = nullptr;
    ScrSourcePageRuntimeLane** mItemsHeapBuffer = nullptr;
  };

  static_assert(sizeof(wxArrayPtrVoidRuntime) == 0xC, "wxArrayPtrVoidRuntime size must be 0xC");

  class ScrSourceCtrl : public wxControlRuntime
  {
  public:
    /**
     * Address: 0x004C3500 (FUN_004C3500)
     *
     * wxWindow *
     *
     * What it does:
     * Initializes one script-source notebook control runtime and clears the
     * open-page pointer lanes used by script debugger source tabs.
     */
    explicit ScrSourceCtrl(wxWindowBase* parentWindow);

    /**
     * Address: 0x004C35B0 (FUN_004C35B0)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for one script-source control.
     */
    static ScrSourceCtrl* DeleteWithFlag(ScrSourceCtrl* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x004C3610 (FUN_004C3610)
     *
     * What it does:
     * Runs non-deleting notebook-base teardown for one script-source control.
     */
    ~ScrSourceCtrl();

  private:
    static void InitializeNotebookBaseRuntime(ScrSourceCtrl& object, wxWindowBase* parentWindow) noexcept;

  public:
    std::uint8_t mUnknown004To12F[0x12C]{};
    wxArrayPtrVoidRuntime mNotebookPageStorage{};               // +0x130
    ScrSourcePageRuntimeLane* mCurrentPageWindow = nullptr;     // +0x13C
    std::uint8_t mDestroyCurrentPageWindow = 0;                 // +0x140
    std::uint8_t mUnknown141To143[0x3]{};
    std::int32_t mSelectedPageIndex = -1;                       // +0x144
    std::uint32_t mUnknown148 = 0;                              // +0x148
    ScrSourcePageRuntimeLane** mPagesBegin = nullptr;           // +0x14C
    ScrSourcePageRuntimeLane** mPagesEnd = nullptr;             // +0x150
    ScrSourcePageRuntimeLane** mPagesCapacity = nullptr;        // +0x154
  };

  static_assert(offsetof(ScrSourceCtrl, mNotebookPageStorage) == 0x130, "ScrSourceCtrl::mNotebookPageStorage offset must be 0x130");
  static_assert(offsetof(ScrSourceCtrl, mCurrentPageWindow) == 0x13C, "ScrSourceCtrl::mCurrentPageWindow offset must be 0x13C");
  static_assert(
    offsetof(ScrSourceCtrl, mDestroyCurrentPageWindow) == 0x140,
    "ScrSourceCtrl::mDestroyCurrentPageWindow offset must be 0x140"
  );
  static_assert(
    offsetof(ScrSourceCtrl, mSelectedPageIndex) == 0x144,
    "ScrSourceCtrl::mSelectedPageIndex offset must be 0x144"
  );
  static_assert(offsetof(ScrSourceCtrl, mUnknown148) == 0x148, "ScrSourceCtrl::mUnknown148 offset must be 0x148");
  static_assert(offsetof(ScrSourceCtrl, mPagesBegin) == 0x14C, "ScrSourceCtrl::mPagesBegin offset must be 0x14C");
  static_assert(offsetof(ScrSourceCtrl, mPagesEnd) == 0x150, "ScrSourceCtrl::mPagesEnd offset must be 0x150");
  static_assert(offsetof(ScrSourceCtrl, mPagesCapacity) == 0x154, "ScrSourceCtrl::mPagesCapacity offset must be 0x154");
  static_assert(sizeof(ScrSourceCtrl) == 0x158, "ScrSourceCtrl size must be 0x158");
} // namespace moho
