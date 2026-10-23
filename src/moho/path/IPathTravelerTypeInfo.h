#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class IPathTravelerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0076D5F0 (FUN_0076D5F0, Moho::IPathTravelerTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for IPathTravelerTypeInfo.
     */
    ~IPathTravelerTypeInfo() override;

    /**
     * Address: 0x0076D5E0 (FUN_0076D5E0, Moho::IPathTravelerTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for IPathTraveler.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0076D5C0 (FUN_0076D5C0, Moho::IPathTravelerTypeInfo::Init)
     *
     * What it does:
     * Sets IPathTraveler size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(IPathTravelerTypeInfo) == 0x64, "IPathTravelerTypeInfo size must be 0x64");
} // namespace moho
