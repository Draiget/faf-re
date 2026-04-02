#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E35A6C
   * COL: 0x00E8F168
   */
  class CSimSoundManagerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00760F40 (FUN_00760F40, Moho::CSimSoundManagerTypeInfo::CSimSoundManagerTypeInfo)
     * Slot: constructor
     *
     * What it does:
     * Constructs and preregisters `CSimSoundManager` reflection type metadata.
     */
    CSimSoundManagerTypeInfo();

    /**
     * Address: 0x00760FD0 (FUN_00760FD0, Moho::CSimSoundManagerTypeInfo::dtr)
     * Slot: 2
     */
    ~CSimSoundManagerTypeInfo() override;

    /**
     * Address: 0x00760FC0 (FUN_00760FC0, Moho::CSimSoundManagerTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `CSimSoundManager`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00760FA0 (FUN_00760FA0, Moho::CSimSoundManagerTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CSimSoundManager` (`sizeof = 0x720`)
     * and registers `ISoundManager` as base metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00762390 (FUN_00762390, Moho::CSimSoundManagerTypeInfo::AddBase_ISoundManager)
     *
     * What it does:
     * Registers `ISoundManager` as reflection base at subobject offset `0`.
     */
    static void AddBase_ISoundManager(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00C01500 (FUN_00C01500, cleanup_CSimSoundManagerTypeInfo)
   *
   * What it does:
   * Releases process-exit `CSimSoundManagerTypeInfo` field/base vector storage.
   */
  void cleanup_CSimSoundManagerTypeInfo();

  /**
   * Address: 0x00BDC500 (FUN_00BDC500, register_CSimSoundManagerTypeInfo)
   *
   * What it does:
   * Forces `CSimSoundManagerTypeInfo` startup construction and installs
   * `atexit` cleanup.
   */
  int register_CSimSoundManagerTypeInfo();

  static_assert(sizeof(CSimSoundManagerTypeInfo) == 0x64, "CSimSoundManagerTypeInfo size must be 0x64");
} // namespace moho
