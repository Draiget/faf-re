#include "moho/ui/EUIStateTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EUIStateTypeInfo) unsigned char gEUIStateTypeInfoStorage[sizeof(moho::EUIStateTypeInfo)];
  bool gEUIStateTypeInfoConstructed = false;

  void cleanup_EUIStateTypeInfo()
  {
    if (!gEUIStateTypeInfoConstructed) {
      return;
    }
    reinterpret_cast<moho::EUIStateTypeInfo*>(gEUIStateTypeInfoStorage)->~EUIStateTypeInfo();
    gEUIStateTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0083CBA0 (FUN_0083CBA0, Moho::EUIStateTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EUIState` enum metadata.
   */
  EUIStateTypeInfo::EUIStateTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EUIState), this);
  }

  /**
   * Address: 0x0083CC30 (FUN_0083CC30, Moho::EUIStateTypeInfo::dtr)
   */
  EUIStateTypeInfo::~EUIStateTypeInfo() = default;

  /**
   * Address: 0x0083CC20 (FUN_0083CC20, Moho::EUIStateTypeInfo::GetName)
   */
  const char* EUIStateTypeInfo::GetName() const
  {
    return "EUIState";
  }

  /**
   * Address: 0x0083CC00 (FUN_0083CC00, Moho::EUIStateTypeInfo::Init)
   */
  void EUIStateTypeInfo::Init()
  {
    size_ = sizeof(EUIState);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0083CC60 (FUN_0083CC60, Moho::EUIStateTypeInfo::AddEnums)
   */
  void EUIStateTypeInfo::AddEnums()
  {
    mPrefix = "UIS_";

    AddEnum(StripPrefix("UIS_none"), static_cast<std::int32_t>(UIS_none));
    AddEnum(StripPrefix("UIS_splash"), static_cast<std::int32_t>(UIS_splash));
    AddEnum(StripPrefix("UIS_frontend"), static_cast<std::int32_t>(UIS_frontend));
    AddEnum(StripPrefix("UIS_game"), static_cast<std::int32_t>(UIS_game));
    AddEnum(StripPrefix("UIS_lobby"), static_cast<std::int32_t>(UIS_lobby));
  }

  /**
   * Address: 0x00BE49F0 (FUN_00BE49F0, sub_BE49F0)
   *
   * What it does:
   * Constructs the type info and registers its teardown. Nothing built this
   * object before, so PreRegisterRType never ran for the enum and every
   * gpg::LookupRType(typeid(EUIState)) threw - which is where
   * cfunc_GetCurrentUIState died during OPTIONS_Apply.
   */
  void register_EUIStateTypeInfoStartup()
  {
    if (!gEUIStateTypeInfoConstructed) {
      new (gEUIStateTypeInfoStorage) EUIStateTypeInfo();
      gEUIStateTypeInfoConstructed = true;
      (void)std::atexit(&cleanup_EUIStateTypeInfo);
    }
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EUIStateTypeInfoStartup_083cba0, moho::register_EUIStateTypeInfoStartup)
