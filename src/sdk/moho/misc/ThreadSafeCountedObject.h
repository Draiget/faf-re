#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class ThreadSafeCountedObject
  {
  public:
    /**
     * Address: 0x0048EC40 (FUN_0048EC40, scalar deleting destructor thunk)
     * Mangled: ??_GThreadSafeCountedObject@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Resets this object's vtable to `ThreadSafeCountedObject` and optionally
     * deletes `this`.
     */
    virtual ~ThreadSafeCountedObject();

  protected:
    ThreadSafeCountedObject() = default;

  public:
    // Intrusive reference counter lane (thread-safe owners use interlocked ops).
    std::int32_t mRefCount; // +0x04
  };

  static_assert(
    offsetof(ThreadSafeCountedObject, mRefCount) == 0x04,
    "ThreadSafeCountedObject::mRefCount offset must be 0x04"
  );
  static_assert(sizeof(ThreadSafeCountedObject) == 0x08, "ThreadSafeCountedObject size must be 0x08");
} // namespace moho

