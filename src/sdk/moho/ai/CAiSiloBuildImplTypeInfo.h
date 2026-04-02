#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DE08
   * COL:  0x00E7493C
   */
  class CAiSiloBuildImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005CF700 (FUN_005CF700, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiSiloBuildImplTypeInfo() override;

    /**
     * Address: 0x005CF6F0 (FUN_005CF6F0, ?GetName@CAiSiloBuildImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005CF6D0 (FUN_005CF6D0, ?Init@CAiSiloBuildImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCE090 (FUN_00BCE090, register_SSiloBuildInfoTypeInfo)
   *
   * What it does:
   * Registers `SSiloBuildInfo` RTTI type-info and installs process-exit
   * cleanup for its static storage.
   */
  int register_SSiloBuildInfoTypeInfo();

  /**
   * Address: 0x00BCE0F0 (FUN_00BCE0F0, register_CAiSiloBuildImplTypeInfo)
   *
   * What it does:
   * Registers `CAiSiloBuildImpl` RTTI type-info and installs process-exit
   * cleanup for its static storage.
   */
  int register_CAiSiloBuildImplTypeInfo();

  /**
   * Address: 0x00BCE190 (FUN_00BCE190, register_ESiloTypeListTypeInfo)
   *
   * What it does:
   * Registers reflected `std::list<ESiloType>` type-info and installs
   * process-exit cleanup for its static storage.
   */
  int register_ESiloTypeListTypeInfo();

  static_assert(sizeof(CAiSiloBuildImplTypeInfo) == 0x64, "CAiSiloBuildImplTypeInfo size must be 0x64");
} // namespace moho
