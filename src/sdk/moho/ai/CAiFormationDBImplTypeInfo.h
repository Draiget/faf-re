#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiFormationDBImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059C5C0 (FUN_0059C5C0, scalar deleting thunk)
     */
    ~CAiFormationDBImplTypeInfo() override;

    /**
     * Address: 0x0059C5B0 (FUN_0059C5B0, ?GetName@CAiFormationDBImplTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059C570 (FUN_0059C570, ?Init@CAiFormationDBImplTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };

  static_assert(sizeof(CAiFormationDBImplTypeInfo) == 0x64, "CAiFormationDBImplTypeInfo size must be 0x64");
} // namespace moho
