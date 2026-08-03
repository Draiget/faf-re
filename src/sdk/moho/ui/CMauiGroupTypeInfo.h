#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiGroupTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00797130 (FUN_00797130, Moho::CMauiGroupTypeInfo::CMauiGroupTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiGroup` descriptor.
     */
    CMauiGroupTypeInfo();

    /**
     * Address: 0x007971D0 (FUN_007971D0, Moho::CMauiGroupTypeInfo::dtr)
     */
    ~CMauiGroupTypeInfo() override;

    /**
     * Address: 0x007971C0 (FUN_007971C0, Moho::CMauiGroupTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00797190 (FUN_00797190, Moho::CMauiGroupTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiGroupTypeInfoStartup();
} // namespace moho
