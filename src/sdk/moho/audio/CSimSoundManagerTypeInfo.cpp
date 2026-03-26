#include "moho/audio/CSimSoundManagerTypeInfo.h"

#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"

namespace moho
{
  /**
   * Address: 0x00760FD0 (FUN_00760FD0, Moho::CSimSoundManagerTypeInfo::dtr)
   */
  CSimSoundManagerTypeInfo::~CSimSoundManagerTypeInfo() = default;

  /**
   * Address: 0x00760FC0 (FUN_00760FC0, Moho::CSimSoundManagerTypeInfo::GetName)
   */
  const char* CSimSoundManagerTypeInfo::GetName() const
  {
    return "CSimSoundManager";
  }

  /**
   * Address: 0x00760FA0 (FUN_00760FA0, Moho::CSimSoundManagerTypeInfo::Init)
   */
  void CSimSoundManagerTypeInfo::Init()
  {
    size_ = sizeof(CSimSoundManager);
    gpg::RType::Init();
    AddBase_ISoundManager(this);
    Finish();
  }

  /**
   * Address: 0x00762390 (FUN_00762390, Moho::CSimSoundManagerTypeInfo::AddBase_ISoundManager)
   */
  void CSimSoundManagerTypeInfo::AddBase_ISoundManager(gpg::RType* const typeInfo)
  {
    audio_reflection::AddBase(typeInfo, audio_reflection::ResolveISoundManagerType());
  }
} // namespace moho

