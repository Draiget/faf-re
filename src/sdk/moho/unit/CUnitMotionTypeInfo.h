#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMotionTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006B7830 (FUN_006B7830, gpg::RType::~RType thunk owner)
     *
     * What it does:
     * Scalar deleting destructor thunk for CUnitMotionTypeInfo.
     */
    ~CUnitMotionTypeInfo() override;

    /**
     * Address: 0x006B7820 (FUN_006B7820, Moho::CUnitMotionTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CUnitMotion.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006B7800 (FUN_006B7800, Moho::CUnitMotionTypeInfo::Init)
     *
     * What it does:
     * Sets CUnitMotion size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(CUnitMotionTypeInfo) == 0x64, "CUnitMotionTypeInfo size must be 0x64");
} // namespace moho
