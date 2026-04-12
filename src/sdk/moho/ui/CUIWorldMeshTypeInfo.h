#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUIWorldMeshTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0086B090 (Moho::CUIWorldMeshTypeInfo::CUIWorldMeshTypeInfo)
     */
    CUIWorldMeshTypeInfo();

    /**
     * Address: 0x0086B130 (scalar deleting thunk)
     */
    ~CUIWorldMeshTypeInfo() override;

    /**
     * Address: 0x0086B120 (Moho::CUIWorldMeshTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0086B0F0 (Moho::CUIWorldMeshTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CUIWorldMeshTypeInfo) == 0x64, "CUIWorldMeshTypeInfo size must be 0x64");

  /**
   * Address: 0x00BE64C0 (register_CUIWorldMeshTypeInfo)
   */
  void register_CUIWorldMeshTypeInfoStartup();
} // namespace moho
