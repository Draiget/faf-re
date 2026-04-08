#include "moho/misc/ScrSourceCtrl.h"

#include "moho/misc/ScrFileCtrl.h"

namespace
{
  [[nodiscard]] moho::ScrFileCtrl* AsScrFileCtrl(moho::ScrSourcePageRuntimeLane* const pageWindow) noexcept
  {
    return reinterpret_cast<moho::ScrFileCtrl*>(pageWindow);
  }
} // namespace

void moho::ScrSourceCtrl::InitializeNotebookBaseRuntime(
  ScrSourceCtrl& object,
  wxWindowBase* const parentWindow
) noexcept
{
  (void)parentWindow;
  object.mNotebookPageStorage.mItemsBegin = nullptr;
  object.mNotebookPageStorage.mItemsEnd = nullptr;
  object.mNotebookPageStorage.mItemsHeapBuffer = nullptr;
  object.mCurrentPageWindow = nullptr;
  object.mDestroyCurrentPageWindow = 0;
  object.mSelectedPageIndex = -1;
  object.mUnknown148 = 0;
}

/**
 * Address: 0x004C3500 (FUN_004C3500)
 *
 * wxWindow *
 *
 * What it does:
 * Initializes one script-source notebook control runtime and clears the
 * open-page pointer lanes used by script debugger source tabs.
 */
moho::ScrSourceCtrl::ScrSourceCtrl(wxWindowBase* const parentWindow)
{
  InitializeNotebookBaseRuntime(*this, parentWindow);
  mPagesBegin = nullptr;
  mPagesEnd = nullptr;
  mPagesCapacity = nullptr;
}

/**
 * Address: 0x004C3610 (FUN_004C3610)
 *
 * What it does:
 * Runs non-deleting notebook-base teardown for one script-source control.
 */
moho::ScrSourceCtrl::~ScrSourceCtrl()
{
  if (mDestroyCurrentPageWindow != 0 && mCurrentPageWindow != nullptr) {
    (void)ScrFileCtrl::DeleteWithFlag(AsScrFileCtrl(mCurrentPageWindow), 1u);
    mCurrentPageWindow = nullptr;
  }

  if (mNotebookPageStorage.mItemsHeapBuffer != nullptr) {
    operator delete(mNotebookPageStorage.mItemsHeapBuffer);
    mNotebookPageStorage.mItemsHeapBuffer = nullptr;
  }
}

/**
 * Address: 0x004C35B0 (FUN_004C35B0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for one script-source control.
 */
moho::ScrSourceCtrl* moho::ScrSourceCtrl::DeleteWithFlag(
  ScrSourceCtrl* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  if (object->mPagesBegin != nullptr) {
    operator delete(object->mPagesBegin);
  }

  object->mPagesBegin = nullptr;
  object->mPagesEnd = nullptr;
  object->mPagesCapacity = nullptr;

  object->~ScrSourceCtrl();

  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }

  return object;
}
