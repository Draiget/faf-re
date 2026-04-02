#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3ED88
   * COL: 0x00E97078
   */
  class CLobbyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x007C0820 (FUN_007C0820, Moho::CLobbyTypeInfo::CLobbyTypeInfo)
     *
     * What it does:
     * Constructs `CLobby` reflection type-info and preregisters RTTI mapping.
     */
    CLobbyTypeInfo();

    /**
     * Address: 0x007C08C0 (FUN_007C08C0, Moho::CLobbyTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CLobbyTypeInfo.
     */
    ~CLobbyTypeInfo() override;

    /**
     * Address: 0x007C08B0 (FUN_007C08B0, Moho::CLobbyTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CLobby.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007C0880 (FUN_007C0880, Moho::CLobbyTypeInfo::Init)
     *
     * What it does:
     * Sets CLobby object size metadata, registers CScriptObject as reflection
     * base at offset 0, and finalizes type initialization.
     */
    void Init() override;
  };

  static_assert(sizeof(CLobbyTypeInfo) == 0x64, "CLobbyTypeInfo size must be 0x64");
} // namespace moho
