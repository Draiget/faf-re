#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CRandomStreamTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0040F070 (FUN_0040F070, Moho::CRandomStreamTypeInfo::CRandomStreamTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `CRandomStream`.
     */
    CRandomStreamTypeInfo();

    /**
     * Address: 0x0040F120 (FUN_0040F120, deleting dtor lane)
     * Slot: 2
     */
    ~CRandomStreamTypeInfo() override;

    /**
     * Address: 0x0040F110 (FUN_0040F110, Moho::CRandomStreamTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0040F0D0 (FUN_0040F0D0, Moho::CRandomStreamTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected CRandomStream size metadata and installs object lifecycle callbacks.
     */
    void Init() override;
  };

  static_assert(sizeof(CRandomStreamTypeInfo) == 0x64, "CRandomStreamTypeInfo size must be 0x64");
} // namespace moho
