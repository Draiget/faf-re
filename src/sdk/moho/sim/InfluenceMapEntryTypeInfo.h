#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class InfluenceMapEntryTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00717840 (FUN_00717840, Moho::InfluenceMapEntryTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for InfluenceMapEntryTypeInfo.
     */
    ~InfluenceMapEntryTypeInfo() override;

    /**
     * Address: 0x00717830 (FUN_00717830, Moho::InfluenceMapEntryTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for InfluenceMapEntry.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00717810 (FUN_00717810, Moho::InfluenceMapEntryTypeInfo::Init)
     *
     * What it does:
     * Sets InfluenceMapEntry size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(InfluenceMapEntryTypeInfo) == 0x64, "InfluenceMapEntryTypeInfo size must be 0x64");
} // namespace moho
