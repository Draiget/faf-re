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
    inline static gpg::RType* sPointerType = nullptr;

    /**
     * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `IFormationInstance*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    virtual void operator_delete(std::int32_t deleteFlags) = 0;
  };

  static_assert(sizeof(IFormationInstance) == 0x04, "IFormationInstance size must be 0x04");
} // namespace moho
