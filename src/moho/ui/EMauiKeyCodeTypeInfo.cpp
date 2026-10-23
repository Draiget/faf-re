#include "moho/ui/EMauiKeyCodeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  /**
   * Address: 0x0079CCD0 (FUN_0079CCD0, Moho::EMauiKeyCodeTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EMauiKeyCode` enum metadata.
   */
  EMauiKeyCodeTypeInfo::EMauiKeyCodeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EMauiKeyCode), this);
  }

  /**
   * Address: 0x0079CD60 (FUN_0079CD60, Moho::EMauiKeyCodeTypeInfo::dtr)
   */
  EMauiKeyCodeTypeInfo::~EMauiKeyCodeTypeInfo() = default;

  /**
   * Address: 0x0079CD50 (FUN_0079CD50, Moho::EMauiKeyCodeTypeInfo::GetName)
   */
  const char* EMauiKeyCodeTypeInfo::GetName() const
  {
    return "EMauiKeyCode";
  }

  /**
   * Address: 0x0079CD30 (FUN_0079CD30, Moho::EMauiKeyCodeTypeInfo::Init)
   */
  void EMauiKeyCodeTypeInfo::Init()
  {
    size_ = sizeof(EMauiKeyCode);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0079CD90 (FUN_0079CD90, Moho::EMauiKeyCodeTypeInfo::AddEnums)
   */
  void EMauiKeyCodeTypeInfo::AddEnums()
  {
    mPrefix = "MKEY_";

#define MOHO_REGISTER_EMAUI_KEYCODE(name, value) AddEnum(StripPrefix(#name), static_cast<std::int32_t>(name));
    MOHO_EMAUI_KEYCODE_LIST(MOHO_REGISTER_EMAUI_KEYCODE)
#undef MOHO_REGISTER_EMAUI_KEYCODE
  }
} // namespace moho

namespace
{
  /**
   * Address: 0x00C03080 (FUN_00C03080, atexit destructor of the EMauiKeyCodeTypeInfo object)
   *
   * What it does:
   * Constructs the static `EMauiKeyCode` enum descriptor. Same shape as the
   * event-type and scroll-axis descriptors: the constructor pre-registers the
   * RTTI mapping, and the binary static-initialises the object in .data.
   *
   * `cfunc_PostDraggerL` resolves a string keycode through
   * `RRef_EMauiKeyCode` + `SCR_GetEnum`, so a button press that passes a named
   * key would otherwise throw out of the Lua call the same silent way.
   */
  gpg::REnumType* construct_EMauiKeyCodeTypeInfo()
  {
    static moho::EMauiKeyCodeTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BDEB50 (FUN_00BDEB50, register_EMauiKeyCodeTypeInfo)
   *
   * What it does:
   * Constructs the `EMauiKeyCode` enum type-info object.
   */
  void register_EMauiKeyCodeTypeInfo()
  {
    (void)construct_EMauiKeyCodeTypeInfo();
  }

  struct EMauiKeyCodeTypeInfoBootstrap
  {
    EMauiKeyCodeTypeInfoBootstrap() { register_EMauiKeyCodeTypeInfo(); }
  };

  EMauiKeyCodeTypeInfoBootstrap gEMauiKeyCodeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: the descriptor has to exist before anything calls
// gpg::LookupRType on it. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EMauiKeyCodeTypeInfo_0079cc, register_EMauiKeyCodeTypeInfo)
