#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiCursorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0078CA00 (FUN_0078CA00, Moho::CMauiCursorTypeInfo::CMauiCursorTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiCursor` descriptor.
     */
    CMauiCursorTypeInfo();

    /**
     * Address: 0x0078CAA0 (FUN_0078CAA0, Moho::CMauiCursorTypeInfo::dtr)
     */
    ~CMauiCursorTypeInfo() override;

    /**
     * Address: 0x0078CA90 (FUN_0078CA90, Moho::CMauiCursorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0078CA60 (FUN_0078CA60, Moho::CMauiCursorTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiCursorTypeInfoStartup();
} // namespace moho
