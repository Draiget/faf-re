#include "CountedObject.h"

#include <intrin.h>

namespace moho
{
  /**
   * Address: 0x004228E0 (FUN_004228E0, scalar deleting destructor thunk)
   * Mangled: ??_GCountedObject@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Resets this object's vtable to `CountedObject` and optionally deletes `this`.
   */
  CountedObject::~CountedObject() = default;

  void CountedObject::AddReference() noexcept
  {
    ++mRefCount;
  }

  void CountedObject::AddReferenceAtomic() noexcept
  {
    (void)_InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&mRefCount), 1);
  }

  [[nodiscard]] bool CountedObject::ReleaseReference() noexcept
  {
    --mRefCount;
    if (mRefCount != 0) {
      return false;
    }

    delete this;
    return true;
  }

  [[nodiscard]] bool CountedObject::ReleaseReferenceAtomic() noexcept
  {
    const long previous = _InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&mRefCount), -1);
    if (previous != 1) {
      return false;
    }

    delete this;
    return true;
  }
} // namespace moho
