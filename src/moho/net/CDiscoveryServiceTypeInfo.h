#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CDiscoveryServiceTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007BF500 (FUN_007BF500, Moho::CDiscoveryServiceTypeInfo::CDiscoveryServiceTypeInfo)
     */
    CDiscoveryServiceTypeInfo();

    /**
     * Address: 0x007BF5A0 (FUN_007BF5A0, scalar deleting thunk)
     */
    ~CDiscoveryServiceTypeInfo() override;

    /**
     * Address: 0x007BF590 (FUN_007BF590, Moho::CDiscoveryServiceTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007BF560 (FUN_007BF560, Moho::CDiscoveryServiceTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CDiscoveryServiceTypeInfo) == 0x64, "CDiscoveryServiceTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDFD90 (FUN_00BDFD90, register_CDiscoveryServiceTypeInfo)
   */
  void register_CDiscoveryServiceTypeInfoStartup();
} // namespace moho
