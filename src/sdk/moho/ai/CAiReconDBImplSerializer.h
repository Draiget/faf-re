#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA74
   * COL:  0x00E73E34
   */
  class SReconKeyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005BFE20 (FUN_005BFE20, Moho::SReconKeyTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors and runs scalar-delete thunk lane.
     */
    ~SReconKeyTypeInfo() override;

    /**
     * Address: 0x005BFE10 (FUN_005BFE10, Moho::SReconKeyTypeInfo::GetName)
     *
     * What it does:
     * Returns reflection type name for `SReconKey`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005BFDF0 (FUN_005BFDF0, Moho::SReconKeyTypeInfo::Init)
     *
     * What it does:
     * Sets reflection payload size and finalizes `gpg::RType` init path.
     */
    void Init() override;
  };

  static_assert(sizeof(SReconKeyTypeInfo) == 0x64, "SReconKeyTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCDD20 (FUN_00BCDD20, register_SReconKeyTypeInfo)
   *
   * What it does:
   * Preregisters `SReconKey` RTTI.
   */
  void register_SReconKeyTypeInfo();

} // namespace moho
