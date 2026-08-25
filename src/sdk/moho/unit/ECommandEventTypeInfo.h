#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  /**
   * Address: 0x006E7D60 (FUN_006E7D60, Moho::ECommandEventTypeInfo::ECommandEventTypeInfo)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ECommandEvent`.
   */
  class ECommandEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006E7D60 (FUN_006E7D60, Moho::ECommandEventTypeInfo::ECommandEventTypeInfo)
     *
     * What it does:
     * Constructs and preregisters `ECommandEvent` enum RTTI.
     */
    ECommandEventTypeInfo();

    ~ECommandEventTypeInfo() override;

    /**
     * Address: 0x006E7D60 (FUN_006E7D60, vftable lane)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E7D60 (FUN_006E7D60, vftable lane)
     */
    void Init() override;
  };

  static_assert(sizeof(ECommandEventTypeInfo) == 0x78, "ECommandEventTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ECommandEvent,int>
   *
   * Investigated per RTTI: `ECommandEvent` has vtable_writer entries for
   * BOTH `?$PrimitiveSerHelper@W4ECommandEvent@Moho@@H@gpg` (two ctor
   * writers) and `?$SerSaveLoadHelper@W4ECommandEvent@Moho@@@gpg` (one ctor
   * writer). Only ONE of the three is `__xc_a`-reachable:
   *   - `FUN_00BD8EF0` (`PrimitiveSerHelper<ECommandEvent,int>` ctor):
   *     `incoming_xrefs=1`, `reachable via ctor_static depth 0` -- REAL.
   *   - `FUN_006E9730` (`PrimitiveSerHelper<ECommandEvent,int>` ctor, same
   *     vtable as above): `incoming_xrefs=0`, unreachable -- dead duplicate
   *     (same low-address/high-address shape as every other
   *     `PrimitiveSerHelper<T,int>` instantiation; a prior recovery pass
   *     wrongly labeled THIS address "the real, distinct ctor").
   *   - `FUN_006EA770` (`SerSaveLoadHelper<ECommandEvent>` ctor):
   *     `incoming_xrefs=0`, unreachable -- dead sibling-writer, same
   *     "shares a global's storage address but is itself unreachable" shape
   *     already documented for ELayer/EVisibilityMode/ESquadClass in
   *     `gpg::PrimitiveSerHelper<T,IntType>`'s Reflection.h class comment.
   * `Init()` confirmed at `FUN_006E9760` via the RTTI vftable dump
   * (`vftable@0xE2E968` slot 0) -- a THIRD address, previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ECommandEvent")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x006EA730/0x006EA750 already matched this
   * template's generic bodies exactly (no fabricated null-check needed).
   */
  using ECommandEventPrimitiveSerializer = gpg::PrimitiveSerHelper<ECommandEvent, int>;

  /**
   * Address: 0x006E7D60 (FUN_006E7D60, sub_6E7D60)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is registered and schedules teardown.
   */
  int register_ECommandEventTypeInfo();
} // namespace moho
