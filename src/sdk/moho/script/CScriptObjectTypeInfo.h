#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E09280
   * COL: 0x00E63358
   */
  class CScriptObjectTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004C6EC0 (FUN_004C6EC0, Moho::CScriptObjectTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CScriptObjectTypeInfo.
     */
    ~CScriptObjectTypeInfo() override;

    /**
     * Address: 0x004C6EB0 (FUN_004C6EB0, Moho::CScriptObjectTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CScriptObject.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004C6E80 (FUN_004C6E80, Moho::CScriptObjectTypeInfo::Init)
     *
     * What it does:
     * Sets CScriptObject object size metadata, registers RObject as reflection
     * base at offset 0, and finalizes type initialization.
     */
    void Init() override;
  };

  static_assert(sizeof(CScriptObjectTypeInfo) == 0x64, "CScriptObjectTypeInfo size must be 0x64");
} // namespace moho
