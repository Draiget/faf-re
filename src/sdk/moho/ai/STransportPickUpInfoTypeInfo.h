#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F348
   */
  class STransportPickUpInfoTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E4520 (FUN_005E4520, ??0STransportPickUpInfoTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `STransportPickUpInfo` RTTI so lookup resolves to this
     * type helper.
     */
    STransportPickUpInfoTypeInfo();

    /**
     * Address: 0x005E45B0 (FUN_005E45B0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~STransportPickUpInfoTypeInfo() override;

    /**
     * Address: 0x005E45A0 (FUN_005E45A0, STransportPickUpInfoTypeInfo::GetName)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E4580 (FUN_005E4580, STransportPickUpInfoTypeInfo::Init)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCEE30 (FUN_00BCEE30, register_STransportPickUpInfoTypeInfo)
   *
   * What it does:
   * Registers `STransportPickUpInfo` type-info and installs process-exit
   * cleanup.
   */
  int register_STransportPickUpInfoTypeInfo();

  static_assert(sizeof(STransportPickUpInfoTypeInfo) == 0x64, "STransportPickUpInfoTypeInfo size must be 0x64");
} // namespace moho
