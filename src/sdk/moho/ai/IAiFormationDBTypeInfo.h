#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class IAiFormationDBTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059C3D0 (FUN_0059C3D0, ctor)
     *
     * What it does:
     * Preregisters `IAiFormationDB` RTTI so lookup resolves to this type helper.
     */
    IAiFormationDBTypeInfo();

    /**
     * Address: 0x0059C460 (FUN_0059C460, scalar deleting thunk)
     */
    ~IAiFormationDBTypeInfo() override;

    /**
     * Address: 0x0059C450 (FUN_0059C450, ?GetName@IAiFormationDBTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059C430 (FUN_0059C430, ?Init@IAiFormationDBTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };

  static_assert(sizeof(IAiFormationDBTypeInfo) == 0x64, "IAiFormationDBTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC190 (FUN_00BCC190)
   *
   * What it does:
   * Constructs startup-owned `IAiFormationDBTypeInfo` storage and installs
   * process-exit cleanup.
   */
  int register_IAiFormationDBTypeInfo();
} // namespace moho
