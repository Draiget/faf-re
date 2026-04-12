#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Recovered enum from binary AddEnums evidence at FUN_0055AF30.
   * Used by SSTITarget command targeting (entity vs position vs none).
   */
  enum class ESTITargetType : std::int32_t
  {
    None = 0,
    Entity = 1,
    Position = 2,
  };

  /**
   * VFTABLE: from `Moho::ESTITargetTypeTypeInfo::vftable`
   *
   * Reflection type-info for the `ESTITargetType` enum. Registers itself in
   * the gpg pre-RType map under `typeid(ESTITargetType)` and exposes named
   * enum values via `AddEnums`.
   */
  class ESTITargetTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055AE70 (FUN_0055AE70, sub_55AE70)
     *
     * What it does:
     * Calls `gpg::REnumType::REnumType()`, registers `this` under
     * `typeid(ESTITargetType)`, and installs the type-info vtable.
     */
    ESTITargetTypeTypeInfo();

    /**
     * Address: 0x0055AF00 (FUN_0055AF00, scalar deleting thunk)
     */
    ~ESTITargetTypeTypeInfo() override;

    /**
     * Address: 0x0055AEF0 (FUN_0055AEF0, GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055AED0 (FUN_0055AED0, Init)
     *
     * What it does:
     * Sets `mSize = sizeof(ESTITargetType)`, registers all enum values via
     * `AddEnums`, then finalizes.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055AF30 (FUN_0055AF30, AddEnums)
     *
     * What it does:
     * Sets prefix `STITARGET_` and registers `None`, `Entity`, and
     * `Position` enum values.
     */
    static void AddEnums(gpg::REnumType* enumType);
  };

  static_assert(sizeof(ESTITargetTypeTypeInfo) == 0x78, "ESTITargetTypeTypeInfo size must be 0x78");

  /**
   * Address: from register_ESTITargetType in BC* range
   */
  void register_ESTITargetTypeTypeInfoStartup();
} // namespace moho
