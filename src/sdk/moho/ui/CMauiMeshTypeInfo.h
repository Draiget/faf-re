#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiMeshTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0079DC60 (FUN_0079DC60, Moho::CMauiMeshTypeInfo::CMauiMeshTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiMesh` descriptor.
     */
    CMauiMeshTypeInfo();

    /**
     * Address: 0x0079DD00 (FUN_0079DD00, Moho::CMauiMeshTypeInfo::dtr)
     */
    ~CMauiMeshTypeInfo() override;

    /**
     * Address: 0x0079DCF0 (FUN_0079DCF0, Moho::CMauiMeshTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0079DCC0 (FUN_0079DCC0, Moho::CMauiMeshTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiMeshTypeInfoStartup();
} // namespace moho
