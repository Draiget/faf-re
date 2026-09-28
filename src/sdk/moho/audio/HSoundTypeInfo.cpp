#include "moho/audio/HSoundTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/HSound.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::HSoundTypeInfo;

  /**
   * Address: 0x00BF10B0 (FUN_00BF10B0, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetHSoundTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
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
   * Address: 0x00BC6AB0 (FUN_00BC6AB0, register_HSoundTypeInfo)
   */
  void register_HSoundTypeInfo()
  {
    (void)GetHSoundTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_HSoundTypeInfo_6cd9a3, moho::register_HSoundTypeInfo)
