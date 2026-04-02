#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E35A10
   * COL: 0x00E8F2B0
   */
  class ISoundManagerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00760A90 (FUN_00760A90, Moho::ISoundManagerTypeInfo::ISoundManagerTypeInfo)
     * Slot: constructor
     *
     * What it does:
     * Constructs and preregisters `ISoundManager` reflection type metadata.
     */
    ISoundManagerTypeInfo();

    /**
     * Address: 0x00760B20 (FUN_00760B20, Moho::ISoundManagerTypeInfo::dtr)
     * Slot: 2
     */
    ~ISoundManagerTypeInfo() override;

    /**
     * Address: 0x00760B10 (FUN_00760B10, Moho::ISoundManagerTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `ISoundManager`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00760AF0 (FUN_00760AF0, Moho::ISoundManagerTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `ISoundManager` (`sizeof = 0x04`).
     */
    void Init() override;
  };

  /**
   * Address: 0x00C01470 (FUN_00C01470, cleanup_ISoundManagerTypeInfo)
   *
   * What it does:
   * Releases process-exit `ISoundManagerTypeInfo` field/base vector storage.
   */
  void cleanup_ISoundManagerTypeInfo();

  /**
   * Address: 0x00BDC4A0 (FUN_00BDC4A0, register_ISoundManagerTypeInfo)
   *
   * What it does:
   * Forces `ISoundManagerTypeInfo` startup construction and installs `atexit`
   * cleanup.
   */
  int register_ISoundManagerTypeInfo();

  static_assert(sizeof(ISoundManagerTypeInfo) == 0x64, "ISoundManagerTypeInfo size must be 0x64");
} // namespace moho
