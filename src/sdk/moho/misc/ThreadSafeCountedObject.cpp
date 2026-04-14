#include "moho/misc/ThreadSafeCountedObject.h"

namespace moho
{
  /**
   * Address: 0x0048EC20 (FUN_0048EC20, ThreadSafeCountedObject dtor body)
   * Address: 0x0048EC40 (FUN_0048EC40, scalar deleting destructor thunk,
   *                      ??_GThreadSafeCountedObject@Moho@@UAEPAXI@Z)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0048EC20 and a separate scalar-deleting thunk at 0x0048EC40.
   */
  ThreadSafeCountedObject::~ThreadSafeCountedObject() = default;
} // namespace moho

