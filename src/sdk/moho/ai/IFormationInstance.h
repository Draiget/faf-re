#pragma once

#include <cstdint>

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Minimal formation-instance interface view used by transport/runtime callers.
   *
   * Address ownership:
   * - `CAiFormationInstance` slot-0 implementation: 0x0059BD60 (`FUN_0059BD60`)
   *
   * What it does:
   * Invokes instance destructor and optionally frees storage when bit0 of
   * `deleteFlags` is set.
   */
  class IFormationInstance
  {
  public:
    inline static gpg::RType* sType = nullptr;

    virtual void operator_delete(std::int32_t deleteFlags) = 0;
  };

  static_assert(sizeof(IFormationInstance) == 0x04, "IFormationInstance size must be 0x04");
} // namespace moho
