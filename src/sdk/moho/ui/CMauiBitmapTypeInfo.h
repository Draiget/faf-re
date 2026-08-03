#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiBitmapTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0077F800 (FUN_0077F800, Moho::CMauiBitmapTypeInfo::CMauiBitmapTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiBitmap` descriptor.
     */
    CMauiBitmapTypeInfo();

    /**
     * Address: 0x0077F8A0 (FUN_0077F8A0, Moho::CMauiBitmapTypeInfo::dtr)
     */
    ~CMauiBitmapTypeInfo() override;

    /**
     * Address: 0x0077F890 (FUN_0077F890, Moho::CMauiBitmapTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0077F860 (FUN_0077F860, Moho::CMauiBitmapTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiBitmapTypeInfoStartup();
} // namespace moho
