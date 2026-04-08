#include "moho/audio/HSoundTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/HSound.h"

namespace
{
  using TypeInfo = moho::HSoundTypeInfo;

  alignas(TypeInfo) unsigned char gHSoundTypeInfoStorage[sizeof(TypeInfo)];
  bool gHSoundTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetHSoundTypeInfo() noexcept
  {
    if (!gHSoundTypeInfoConstructed) {
      new (gHSoundTypeInfoStorage) TypeInfo();
      gHSoundTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gHSoundTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004E1360 (FUN_004E1360, Moho::HSoundTypeInfo::HSoundTypeInfo)
   */
  HSoundTypeInfo::HSoundTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(HSound), this);
  }

  /**
   * Address: 0x004E1400 (FUN_004E1400, Moho::HSoundTypeInfo::dtr)
   */
  HSoundTypeInfo::~HSoundTypeInfo() = default;

  /**
   * Address: 0x004E13F0 (FUN_004E13F0, Moho::HSoundTypeInfo::GetName)
   */
  const char* HSoundTypeInfo::GetName() const
  {
    return "HSound";
  }

  /**
   * Address: 0x004E13C0 (FUN_004E13C0, Moho::HSoundTypeInfo::Init)
   */
  void HSoundTypeInfo::Init()
  {
    size_ = sizeof(HSound);
    AddBase_CScriptEvent(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x004E4E80 (FUN_004E4E80, Moho::HSoundTypeInfo::AddBase_CScriptEvent)
   */
  void HSoundTypeInfo::AddBase_CScriptEvent(gpg::RType* const typeInfo)
  {
    audio_reflection::AddBase(typeInfo, audio_reflection::ResolveCScriptEventType());
  }

  /**
   * Address: 0x00BF10B0 (FUN_00BF10B0, cleanup_HSoundTypeInfo)
   */
  void cleanup_HSoundTypeInfo()
  {
    if (!gHSoundTypeInfoConstructed) {
      return;
    }

    GetHSoundTypeInfo().~HSoundTypeInfo();
    gHSoundTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC6AB0 (FUN_00BC6AB0, register_HSoundTypeInfo)
   */
  int register_HSoundTypeInfo()
  {
    (void)GetHSoundTypeInfo();
    return std::atexit(&cleanup_HSoundTypeInfo);
  }
} // namespace moho

namespace
{
  struct HSoundTypeInfoBootstrap
  {
    HSoundTypeInfoBootstrap()
    {
      (void)moho::register_HSoundTypeInfo();
    }
  };

  [[maybe_unused]] HSoundTypeInfoBootstrap gHSoundTypeInfoBootstrap;
} // namespace
