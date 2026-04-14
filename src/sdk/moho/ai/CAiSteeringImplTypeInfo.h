#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E118
   * COL:  0x00E74DB4
   */
  class CAiSteeringImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D21E0 (FUN_005D21E0, ??0CAiSteeringImplTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CAiSteeringImpl` RTTI so lookup resolves to this type
     * helper.
     */
    CAiSteeringImplTypeInfo();

    /**
     * Address: 0x005D22A0 (FUN_005D22A0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiSteeringImplTypeInfo() override;

    /**
     * Address: 0x005D2290 (FUN_005D2290, ?GetName@CAiSteeringImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D2240 (FUN_005D2240, ?Init@CAiSteeringImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;

    /**
     * Address: 0x005D4310 (FUN_005D4310, Moho::CAiSteeringImplTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CAiSteeringImpl` in caller storage and returns
     * a typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);
  };

  /**
   * Address: 0x00BCE480 (FUN_00BCE480, register_CAiSteeringImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiSteeringImplTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_CAiSteeringImplTypeInfo();

  static_assert(sizeof(CAiSteeringImplTypeInfo) == 0x64, "CAiSteeringImplTypeInfo size must be 0x64");
} // namespace moho
