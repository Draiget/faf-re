#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E028D8
   * COL: 0x00E5EDE0
   */
  class ID3DTextureSheetTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0043D490 (FUN_0043D490, Moho::ID3DTextureSheetTypeInfo::ID3DTextureSheetTypeInfo)
     *
     * What it does:
     * Initializes RTTI base state and preregisters `ID3DTextureSheet` metadata.
     */
    ID3DTextureSheetTypeInfo();

    /**
     * Address: 0x0043D520 (FUN_0043D520, Moho::ID3DTextureSheetTypeInfo::dtr)
     * Slot: 2
     */
    ~ID3DTextureSheetTypeInfo() override;

    /**
     * Address: 0x0043D510 (FUN_0043D510, Moho::ID3DTextureSheetTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `ID3DTextureSheet`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0043D4F0 (FUN_0043D4F0, Moho::ID3DTextureSheetTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets object-size metadata for `ID3DTextureSheet` and finalizes base
     * reflection initialization.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC41D0 (FUN_00BC41D0, register_ID3DTextureSheetTypeInfo)
   *
   * What it does:
   * Constructs the process-global `ID3DTextureSheetTypeInfo` slot and
   * registers process-exit teardown for that slot.
   */
  void register_ID3DTextureSheetTypeInfo();

  /**
   * Address: 0x00BEF250 (FUN_00BEF250, cleanup_ID3DTextureSheetTypeInfo)
   *
   * What it does:
   * Destroys the process-global `ID3DTextureSheetTypeInfo` slot when
   * startup registration constructed it.
   */
  void cleanup_ID3DTextureSheetTypeInfo();

  static_assert(sizeof(ID3DTextureSheetTypeInfo) == 0x64, "ID3DTextureSheetTypeInfo size must be 0x64");
} // namespace moho
