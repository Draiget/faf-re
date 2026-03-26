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

  static_assert(sizeof(CSimSoundManagerTypeInfo) == 0x64, "CSimSoundManagerTypeInfo size must be 0x64");
} // namespace moho

