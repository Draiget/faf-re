#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class IAiAttackerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D5BA0 (FUN_005D5BA0, scalar deleting thunk)
     */
    ~IAiAttackerTypeInfo() override;

    /**
     * Address: 0x005D5B90 (FUN_005D5B90, ?GetName@IAiAttackerTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D5B70 (FUN_005D5B70, ?Init@IAiAttackerTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };

  static_assert(sizeof(IAiAttackerTypeInfo) == 0x64, "IAiAttackerTypeInfo size must be 0x64");
} // namespace moho
