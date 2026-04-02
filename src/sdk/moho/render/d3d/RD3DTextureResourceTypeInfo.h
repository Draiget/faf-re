#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E02908
   * COL: 0x00E5EE1C
   */
  class RD3DTextureResourceTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0043D5D0 (FUN_0043D5D0, Moho::RD3DTextureResourceTypeInfo::RD3DTextureResourceTypeInfo)
     *
     * What it does:
     * Initializes RTTI base state and preregisters `RD3DTextureResource` metadata.
     */
    RD3DTextureResourceTypeInfo();

    /**
     * Address: 0x0043D660 (FUN_0043D660, Moho::RD3DTextureResourceTypeInfo::dtr)
     * Slot: 2
     */
    ~RD3DTextureResourceTypeInfo() override;

    /**
     * Address: 0x0043D650 (FUN_0043D650, Moho::RD3DTextureResourceTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `RD3DTextureResource`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0043D630 (FUN_0043D630, Moho::RD3DTextureResourceTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes `RD3DTextureResource` reflection metadata and registers
     * `ID3DTextureSheet` as base metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x004454B0 (FUN_004454B0, Moho::RD3DTextureResourceTypeInfo::AddBase_ID3DTextureSheet)
     *
     * What it does:
     * Registers `ID3DTextureSheet` as reflection base metadata at offset `0`.
     */
    static void AddBase_ID3DTextureSheet(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC41F0 (FUN_00BC41F0, register_RD3DTextureResourceTypeInfo)
   *
   * What it does:
   * Constructs the process-global `RD3DTextureResourceTypeInfo` slot and
   * registers process-exit teardown for that slot.
   */
  void register_RD3DTextureResourceTypeInfo();

  /**
   * Address: 0x00BEF2B0 (FUN_00BEF2B0, cleanup_RD3DTextureResourceTypeInfo)
   *
   * What it does:
   * Destroys the process-global `RD3DTextureResourceTypeInfo` slot when
   * startup registration constructed it.
   */
  void cleanup_RD3DTextureResourceTypeInfo();

  static_assert(sizeof(RD3DTextureResourceTypeInfo) == 0x64, "RD3DTextureResourceTypeInfo size must be 0x64");
} // namespace moho
