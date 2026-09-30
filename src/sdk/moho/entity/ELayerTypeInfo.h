#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Entity.h"

namespace moho
{
  class ELayerTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0050BA80 (FUN_0050BA80, Moho::ELayerTypeInfo::dtr)
     */
    ~ELayerTypeInfo() override;

    /**
     * Address: 0x0050BA70 (FUN_0050BA70, Moho::ELayerTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BA50 (FUN_0050BA50, Moho::ELayerTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050BAB0 (FUN_0050BAB0, Moho::ELayerTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ELayerTypeInfo) == 0x78, "ELayerTypeInfo size must be 0x78");


  /**
   * Address: 0x0050B9F0 (FUN_0050B9F0, preregister_ELayerTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for `ELayer`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ELayerTypeInfo();

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   *
   * What it does:
   * Runs `ELayer` typeinfo preregistration.
   */
  void register_ELayerTypeInfo();
} // namespace moho
