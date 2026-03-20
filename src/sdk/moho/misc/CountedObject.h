#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class CountedObject
  {
  public:
    /**
     * Address: 0x004228E0 (FUN_004228E0, scalar deleting destructor thunk)
     * Mangled: ??_GCountedObject@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Resets this object's vtable to `CountedObject` and optionally deletes `this`.
     */
    virtual ~CountedObject();

  protected:
    CountedObject() = default;

  public:
    // Intrusive reference counter used by `CountedPtr<T>`-style ownership paths.
    std::int32_t mRefCount; // +0x04
  };

  static_assert(offsetof(CountedObject, mRefCount) == 0x04, "CountedObject::mRefCount offset must be 0x04");
  static_assert(sizeof(CountedObject) == 0x08, "CountedObject size must be 0x08");
} // namespace moho
