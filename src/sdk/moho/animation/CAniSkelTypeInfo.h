#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniSkelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00549FF0 (FUN_00549FF0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAniSkelTypeInfo() override;

    /**
     * Address: 0x00549FE0 (FUN_00549FE0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00549FC0 (FUN_00549FC0)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAniSkel` (`sizeof = 0x2C`).
     */
    void Init() override;
  };

  static_assert(sizeof(CAniSkelTypeInfo) == 0x64, "CAniSkelTypeInfo size must be 0x64");
} // namespace moho
