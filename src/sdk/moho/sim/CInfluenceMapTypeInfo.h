#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CInfluenceMapTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00717520 (FUN_00717520, Moho::CInfluenceMapTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CInfluenceMapTypeInfo.
     */
    ~CInfluenceMapTypeInfo() override;

    /**
     * Address: 0x00717510 (FUN_00717510, Moho::CInfluenceMapTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CInfluenceMap.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007174F0 (FUN_007174F0, Moho::CInfluenceMapTypeInfo::Init)
     *
     * What it does:
     * Sets CInfluenceMap size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(CInfluenceMapTypeInfo) == 0x64, "CInfluenceMapTypeInfo size must be 0x64");
} // namespace moho
