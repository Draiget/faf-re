#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EVisibilityMode : std::int32_t
  {
    VIZMODE_Never = 1,
    VIZMODE_Always = 2,
    VIZMODE_Intel = 4,
  };

  static_assert(sizeof(EVisibilityMode) == 0x04, "EVisibilityMode size must be 0x04");

  class EVisibilityModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0050A190 (FUN_0050A190, Moho::EVisibilityModeTypeInfo::dtr)
     */
    ~EVisibilityModeTypeInfo() override;

    /**
     * Address: 0x0050A0D0 (FUN_0050A0D0, Moho::EVisibilityModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A160 (FUN_0050A160, Moho::EVisibilityModeTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050A1C0 (FUN_0050A1C0, Moho::EVisibilityModeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EVisibilityModeTypeInfo) == 0x78, "EVisibilityModeTypeInfo size must be 0x78");


  /**
   * Address: 0x0050A100 (FUN_0050A100, preregister_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `EVisibilityMode`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EVisibilityModeTypeInfo();

  /**
   * Address: 0x00BC7AD0 (FUN_00BC7AD0, register_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Runs `EVisibilityMode` typeinfo preregistration.
   */
  void register_EVisibilityModeTypeInfo();
} // namespace moho

