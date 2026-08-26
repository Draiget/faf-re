#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/command/SSTICommandIssueData.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E17A04
   * COL:  0x00E6BB78
   */
  class EUnitCommandTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005520B0 (FUN_005520B0, Moho::EUnitCommandTypeTypeInfo::EUnitCommandTypeTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EUnitCommandType` with the reflection registry.
     */
    EUnitCommandTypeTypeInfo();

    /**
     * Address: 0x00552140 (FUN_00552140, Moho::EUnitCommandTypeTypeInfo::dtr)
     */
    ~EUnitCommandTypeTypeInfo() override;

    /**
     * Address: 0x00552130 (FUN_00552130, Moho::EUnitCommandTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00552110 (FUN_00552110, Moho::EUnitCommandTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00552170 (FUN_00552170, Moho::EUnitCommandTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EUnitCommandTypeTypeInfo) == 0x78, "EUnitCommandTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EUnitCommandType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EUnitCommandType@Moho@@H@gpg'`):
   * `FUN_00BC9C40` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). See the per-instantiation address list on
   * `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF4960` (atexit target
   * pushed by the real ctor above); `FUN_005524F0`/`FUN_00552520` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneF` and its two reset thunks; removed in
   * favor of this citation.
   */
  using EUnitCommandTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EUnitCommandType, int>;

  /**
   * Address: 0x00BC9C20 (FUN_00BC9C20, sub_BC9C20)
   *
   * What it does:
   * Constructs the static `EUnitCommandTypeTypeInfo` descriptor in place --
   * construction preregisters `EUnitCommandType` with the reflection
   * registry -- and installs its atexit teardown. This is an independent
   * `__xc_a` static-initializer entry, separate from (and not coupled to)
   * `EUnitCommandTypePrimitiveSerializer`'s own independent initializer
   * (`FUN_00BC9C40`); the two must not be constructed from one shared
   * bootstrap.
   */
  int register_EUnitCommandTypeTypeInfo();
} // namespace moho

