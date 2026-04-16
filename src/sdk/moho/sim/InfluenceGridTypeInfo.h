#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class InfluenceGridTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00717BB0 (FUN_00717BB0, Moho::InfluenceGridTypeInfo::InfluenceGridTypeInfo)
     *
     * What it does:
     * Preregisters `InfluenceGrid` reflection metadata at startup.
     */
    InfluenceGridTypeInfo();

    /**
     * Address: 0x00717C40 (FUN_00717C40, Moho::InfluenceGridTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for InfluenceGridTypeInfo.
     */
    ~InfluenceGridTypeInfo() override;

    /**
     * Address: 0x00717C30 (FUN_00717C30, Moho::InfluenceGridTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for InfluenceGrid.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00717C10 (FUN_00717C10, Moho::InfluenceGridTypeInfo::Init)
     *
     * What it does:
     * Sets InfluenceGrid size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(InfluenceGridTypeInfo) == 0x64, "InfluenceGridTypeInfo size must be 0x64");
} // namespace moho
