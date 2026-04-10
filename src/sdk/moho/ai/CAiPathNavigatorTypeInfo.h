#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C6B4
   * COL:  0x00E72488
   */
  class CAiPathNavigatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005AFA70 (FUN_005AFA70, ??0CAiPathNavigatorTypeInfo@Moho@@QAE@XZ)
     *
     * What it does:
     * Preregisters `CAiPathNavigator` RTTI for this type-info helper.
     */
    CAiPathNavigatorTypeInfo();

    /**
     * Address: 0x005AFB30 (FUN_005AFB30, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiPathNavigatorTypeInfo() override;

    /**
     * Address: 0x005AFB20 (FUN_005AFB20, ?GetName@CAiPathNavigatorTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AFAD0 (FUN_005AFAD0, ?Init@CAiPathNavigatorTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiPathNavigatorTypeInfo) == 0x64, "CAiPathNavigatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCD020 (FUN_00BCD020, register_CAiPathNavigatorTypeInfo)
   *
   * What it does:
   * Constructs the recovered `CAiPathNavigatorTypeInfo` startup owner and
   * installs process-exit cleanup.
   */
  void register_CAiPathNavigatorTypeInfo();
} // namespace moho
