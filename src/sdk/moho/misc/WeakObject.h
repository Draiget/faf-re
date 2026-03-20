#pragma once
#include <cstdint>

namespace moho
{
  class WeakObject
  {
  public:
    // Head link slot for intrusive weak-guard / weak-pointer chains.
    // WeakPtr<T>::ownerLinkSlot points to this slot in owner objects.
    uint32_t weakLinkHead_;
  };
  static_assert(sizeof(WeakObject) == 4, "WeakObject must be 4 bytes");
} // namespace moho
