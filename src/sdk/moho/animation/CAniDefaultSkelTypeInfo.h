#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0054A9C0 (FUN_0054A9C0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAniDefaultSkelTypeInfo() override;

    /**
     * Address: 0x0054A9B0 (FUN_0054A9B0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0054A990 (FUN_0054A990)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAniDefaultSkel` and registers
     * `CAniSkel` as base metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(CAniDefaultSkelTypeInfo) == 0x64, "CAniDefaultSkelTypeInfo size must be 0x64");
} // namespace moho
