#include "BoostWrappers.h"

#include <boost/ptr_container/exception.hpp>

namespace boost
{
  namespace
  {
    [[noreturn]] void ThrowBadPointerForNullPushBack()
    {
      throw bad_pointer();
    }
  } // namespace

  /**
   * Address: 0x004DBBC0 (FUN_004DBBC0)
   *
   * What it does:
   * Validates one ptr-container `push_back` input pointer and throws
   * `boost::bad_pointer` when the pointer is null.
   */
  void EnsurePtrContainerPushBackInputNotNull(
    const void* const inputPointer
  )
  {
    if (inputPointer == nullptr) {
      ThrowBadPointerForNullPushBack();
    }
  }
} // namespace boost
