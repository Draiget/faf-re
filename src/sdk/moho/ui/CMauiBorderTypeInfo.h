#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiBorderTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007848C0 (FUN_007848C0, Moho::CMauiBorderTypeInfo::CMauiBorderTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiBorder` descriptor.
     */
    CMauiBorderTypeInfo();

    /**
     * Address: 0x00784960 (FUN_00784960, Moho::CMauiBorderTypeInfo::dtr)
     */
    ~CMauiBorderTypeInfo() override;

    /**
     * Address: 0x00784950 (FUN_00784950, Moho::CMauiBorderTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00784920 (FUN_00784920, Moho::CMauiBorderTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiBorderTypeInfoStartup();
} // namespace moho
