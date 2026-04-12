#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: evidence from FUN_00585CD0
   */
  class SMassInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00585CD0 (FUN_00585CD0, ??0SMassInfoTypeInfo@Moho@@QAE@XZ)
     *
     * What it does:
     * Preregisters `SMassInfo` RTTI for this type-info helper.
     */
    SMassInfoTypeInfo();

    /**
     * Address: 0x00585D60 (FUN_00585D60, scalar deleting thunk)
     */
    ~SMassInfoTypeInfo() override;

    /**
     * Address: 0x00585D50 (FUN_00585D50, ?GetName@SMassInfoTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00585D30 (FUN_00585D30, ?Init@SMassInfoTypeInfo@Moho@@UAEXXZ)
     *
     * What it does:
     * Sets size = 0x0C and finalizes.
     */
    void Init() override;
  };

  static_assert(sizeof(SMassInfoTypeInfo) == 0x64, "SMassInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCB6E0 (FUN_00BCB6E0, register_SMassInfoTypeInfo)
   *
   * What it does:
   * Ensures startup construction of `SMassInfoTypeInfo` and installs process-exit cleanup.
   */
  void register_SMassInfoTypeInfoStartup();
} // namespace moho
