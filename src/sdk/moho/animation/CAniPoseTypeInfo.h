#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: evidence from FUN_0054AD70
   */
  class CAniPoseTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0054AD70 (FUN_0054AD70, ??0CAniPoseTypeInfo@Moho@@QAE@XZ)
     *
     * What it does:
     * Preregisters `CAniPose` RTTI for this type-info helper.
     */
    CAniPoseTypeInfo();

    /**
     * Address: 0x0054AE30 (FUN_0054AE30, scalar deleting thunk)
     */
    ~CAniPoseTypeInfo() override;

    /**
     * Address: 0x0054AE20 (FUN_0054AE20, ?GetName@CAniPoseTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0054ADD0 (FUN_0054ADD0, ?Init@CAniPoseTypeInfo@Moho@@UAEXXZ)
     *
     * What it does:
     * Sets size = 0x90, installs ref-management function pointers (NewRef, CtrRef,
     * CpyRef, MovRef, Delete, Destruct), then finalizes.
     */
    void Init() override;
  };

  static_assert(sizeof(CAniPoseTypeInfo) == 0x64, "CAniPoseTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC9940 (FUN_00BC9940, register_CAniPoseTypeInfo)
   *
   * What it does:
   * Ensures startup construction of `CAniPoseTypeInfo` and installs process-exit cleanup.
   */
  void register_CAniPoseTypeInfoStartup();
} // namespace moho
