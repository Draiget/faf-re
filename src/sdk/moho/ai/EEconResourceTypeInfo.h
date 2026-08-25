#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EEconResource : std::int32_t
  {
    ECON_ENERGY = 0,
    ECON_MASS = 1,
  };

  static_assert(sizeof(EEconResource) == 0x4, "EEconResource size must be 0x4");

  class EEconResourceTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00563980 (FUN_00563980, Moho::EEconResourceTypeInfo::EEconResourceTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EEconResource` with the reflection registry.
     */
    EEconResourceTypeInfo();

    /**
     * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
     */
    ~EEconResourceTypeInfo() override;

    /**
     * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EEconResource,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EEconResource@Moho@@H@gpg'`):
   * `FUN_00BCA810` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at a lower address in the same instantiation family.
   */
  using EEconResourcePrimitiveSerializer = gpg::PrimitiveSerHelper<EEconResource, int>;

  static_assert(sizeof(EEconResourceTypeInfo) == 0x78, "EEconResourceTypeInfo size must be 0x78");

  /**
   * Address: 0x00563980 (FUN_00563980, static-init lane)
   *
   * IDA signature:
   * gpg::REnumType *sub_563980();
   *
   * What it does:
   * Constructs the static `EEconResourceTypeInfo` descriptor (`stru_10ACEF8`
   * in the binary) in place and returns it; construction preregisters
   * `EEconResource` with the reflection registry. Called from the CRT
   * static-initializer array via FUN_00BCA7F0.
   */
  [[nodiscard]] gpg::REnumType* preregister_EEconResourceTypeInfo();
} // namespace moho
