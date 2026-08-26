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

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESTITargetType,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESTITargetType@Moho@@H@gpg'`):
   * `FUN_00BCA2B0` (real, `__xc_a`-reachable). Unlike `EAlliance`/
   * `EImpactType`, this instantiation has no dead low-address duplicate
   * ctor in `vtable_writers` -- only the one real emission.
   *
   * `FUN_00BCA2B0` was previously mis-tagged `external_dependency` ("OS/CRT/
   * library dependency") in the progress DB; raw asm shows it is plainly
   * engine code -- constructs our own `gpg::SerHelperBase` base, writes our
   * own `PrimitiveSerHelper<ESTITargetType,int>` vtable, and installs
   * `sub_55B310`/`sub_55B330` (this instantiation's Deserialize/Serialize)
   * as callback fields, the same shape as every other confirmed real ctor
   * in this family.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF50E0` (atexit target
   * pushed by the real ctor above); `FUN_0055AF80`/`FUN_0055AFB0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneG` and its two reset thunks; removed in
   * favor of this citation.
   */
  using ESTITargetTypePrimitiveSerializer = gpg::PrimitiveSerHelper<ESTITargetType, int>;

  static_assert(sizeof(ESTITargetTypeTypeInfo) == 0x78, "ESTITargetTypeTypeInfo size must be 0x78");

  /**
   * Address: from register_ESTITargetType in BC* range
   */
  void register_ESTITargetTypeTypeInfoStartup();
} // namespace moho
