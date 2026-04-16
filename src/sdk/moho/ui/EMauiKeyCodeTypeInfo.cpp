#include "moho/ui/EMauiKeyCodeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

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
