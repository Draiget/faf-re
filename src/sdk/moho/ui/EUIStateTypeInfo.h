#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Owns reflected metadata for the `EUIState` enum.
   */
  class EUIStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0083CBA0 (FUN_0083CBA0, Moho::EUIStateTypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EUIState` enum metadata.
     */
    EUIStateTypeInfo();

    /**
     * Address: 0x0083CC30 (FUN_0083CC30, Moho::EUIStateTypeInfo::dtr)
     *
     * What it does:
     * Releases the reflected `EUIState` enum descriptor.
     */
    ~EUIStateTypeInfo() override;

    /**
     * Address: 0x0083CC20 (FUN_0083CC20, Moho::EUIStateTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EUIState`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0083CC00 (FUN_0083CC00, Moho::EUIStateTypeInfo::Init)
     *
     * What it does:
     * Sets enum width, registers enum entries, and finalizes the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0083CC60 (FUN_0083CC60, Moho::EUIStateTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `UIS_` enum name/value map in reflected metadata.
     */
    void AddEnums();
  };

  static_assert(sizeof(EUIStateTypeInfo) == 0x78, "EUIStateTypeInfo size must be 0x78");
} // namespace moho
