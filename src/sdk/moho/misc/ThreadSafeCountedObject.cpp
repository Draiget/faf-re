#include "moho/misc/ThreadSafeCountedObject.h"

namespace moho
{
  /**
   * Address: 0x0048EC40 (FUN_0048EC40, scalar deleting destructor thunk)
   * Mangled: ??_GThreadSafeCountedObject@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Resets this object's vtable to `ThreadSafeCountedObject` and optionally
   * deletes `this`.
   */
  ThreadSafeCountedObject::~ThreadSafeCountedObject() = default;
} // namespace moho

