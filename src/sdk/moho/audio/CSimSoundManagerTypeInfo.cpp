#include "moho/audio/CSimSoundManagerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"

namespace
{
  using TypeInfo = moho::CSimSoundManagerTypeInfo;

  alignas(TypeInfo) unsigned char gCSimSoundManagerTypeInfoStorage[sizeof(TypeInfo)];
  bool gCSimSoundManagerTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCSimSoundManagerTypeInfo() noexcept
  {
    if (!gCSimSoundManagerTypeInfoConstructed) {
      new (gCSimSoundManagerTypeInfoStorage) TypeInfo();
      gCSimSoundManagerTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCSimSoundManagerTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00760F40 (FUN_00760F40, Moho::CSimSoundManagerTypeInfo::CSimSoundManagerTypeInfo)
   */
  CSimSoundManagerTypeInfo::CSimSoundManagerTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSimSoundManager), this);
  }

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

  /**
   * Address: 0x00C01500 (FUN_00C01500, cleanup_CSimSoundManagerTypeInfo)
   *
   * What it does:
   * Releases process-exit CSimSoundManagerTypeInfo storage.
   */
  void cleanup_CSimSoundManagerTypeInfo()
  {
    if (!gCSimSoundManagerTypeInfoConstructed) {
      return;
    }

    GetCSimSoundManagerTypeInfo().~CSimSoundManagerTypeInfo();
    gCSimSoundManagerTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BDC500 (FUN_00BDC500, register_CSimSoundManagerTypeInfo)
   *
   * What it does:
   * Forces CSimSoundManagerTypeInfo startup construction and installs process-exit
   * cleanup.
   */
  int register_CSimSoundManagerTypeInfo()
  {
    (void)GetCSimSoundManagerTypeInfo();
    return std::atexit(&cleanup_CSimSoundManagerTypeInfo);
  }
} // namespace moho

namespace
{
  struct CSimSoundManagerTypeInfoBootstrap
  {
    CSimSoundManagerTypeInfoBootstrap()
    {
      (void)moho::register_CSimSoundManagerTypeInfo();
    }
  };

  [[maybe_unused]] CSimSoundManagerTypeInfoBootstrap gCSimSoundManagerTypeInfoBootstrap;
} // namespace
