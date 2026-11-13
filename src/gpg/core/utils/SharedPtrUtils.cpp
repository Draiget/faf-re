#include "SharedPtrUtils.h"

namespace gpg
{
  namespace
  {
    [[noreturn]] void ThrowBadPointerForNullPushBack()
    {
      throw BadPointer();
    }
  } // namespace

  /**
   * Address: 0x004DBBC0 (FUN_004DBBC0)
   *
   * What it does:
   * Validates one ptr-container `push_back` input pointer and throws
   * `gpg::BadPointer` (retail: `boost::bad_pointer`) when the pointer is null.
   */
  void EnsurePtrContainerPushBackInputNotNull(
    const void* const inputPointer
  )
  {
    if (inputPointer == nullptr) {
      ThrowBadPointerForNullPushBack();
    }
  }
} // namespace gpg
