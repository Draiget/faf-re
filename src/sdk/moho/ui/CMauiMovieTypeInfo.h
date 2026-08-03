#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiMovieTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0079ECD0 (FUN_0079ECD0, Moho::CMauiMovieTypeInfo::CMauiMovieTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiMovie` descriptor.
     */
    CMauiMovieTypeInfo();

    /**
     * Address: 0x0079ED70 (FUN_0079ED70, Moho::CMauiMovieTypeInfo::dtr)
     */
    ~CMauiMovieTypeInfo() override;

    /**
     * Address: 0x0079ED60 (FUN_0079ED60, Moho::CMauiMovieTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0079ED30 (FUN_0079ED30, Moho::CMauiMovieTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiMovieTypeInfoStartup();
} // namespace moho
