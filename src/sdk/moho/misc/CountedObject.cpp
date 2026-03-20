#include "CountedObject.h"

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
} // namespace moho
