#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMersenneTwisterTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0040EC70 (FUN_0040EC70, Moho::CMersenneTwisterTypeInfo::CMersenneTwisterTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `CMersenneTwister`.
     */
    CMersenneTwisterTypeInfo();

    /**
     * Address: 0x0040ED00 (FUN_0040ED00, deleting dtor lane)
     * Slot: 2
     */
    ~CMersenneTwisterTypeInfo() override;

    /**
     * Address: 0x0040ECF0 (FUN_0040ECF0, Moho::CMersenneTwisterTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0040ECD0 (FUN_0040ECD0, Moho::CMersenneTwisterTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected CMersenneTwister size metadata and finalizes the descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(CMersenneTwisterTypeInfo) == 0x64, "CMersenneTwisterTypeInfo size must be 0x64");
} // namespace moho
