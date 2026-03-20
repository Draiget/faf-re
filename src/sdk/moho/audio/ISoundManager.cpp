#include "ISoundManager.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x00760A70 (FUN_00760A70)
   *
   * std::uint8_t deleteFlags
   *
   * IDA signature:
   * _DWORD *__thiscall sub_760A70(_DWORD *this, char deleteFlags);
   *
   * What it does:
   * Implements deleting-style virtual teardown for interface pointers.
   */
  ISoundManager* ISoundManager::Destroy(const std::uint8_t flags)
  {
    if ((flags & 1u) != 0u) {
      operator delete(this);
    }
    return this;
  }
} // namespace moho
