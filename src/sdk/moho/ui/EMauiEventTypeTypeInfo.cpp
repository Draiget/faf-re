#include "moho/ui/EMauiEventTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  /**
   * Address: 0x00795A10 (FUN_00795A10, Moho::EMauiEventTypeTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EMauiEventType` enum metadata.
   */
  EMauiEventTypeTypeInfo::EMauiEventTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EMauiEventType), this);
  }

  /**
   * Address: 0x00795AA0 (FUN_00795AA0, Moho::EMauiEventTypeTypeInfo::dtr)
   */
  EMauiEventTypeTypeInfo::~EMauiEventTypeTypeInfo() = default;

  /**
   * Address: 0x00795A90 (FUN_00795A90, Moho::EMauiEventTypeTypeInfo::GetName)
   */
  const char* EMauiEventTypeTypeInfo::GetName() const
  {
    return "EMauiEventType";
  }

  /**
   * Address: 0x00795A70 (FUN_00795A70, Moho::EMauiEventTypeTypeInfo::Init)
   */
  void EMauiEventTypeTypeInfo::Init()
  {
    size_ = sizeof(EMauiEventType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00795AD0 (FUN_00795AD0, Moho::EMauiEventTypeTypeInfo::AddEnums)
   */
  void EMauiEventTypeTypeInfo::AddEnums()
  {
    mPrefix = "MET_";

    AddEnum(StripPrefix("MET_MouseMotion"), static_cast<std::int32_t>(MET_MouseMotion));
    AddEnum(StripPrefix("MET_MouseEnter"), static_cast<std::int32_t>(MET_MouseEnter));
    AddEnum(StripPrefix("MET_MouseHover"), static_cast<std::int32_t>(MET_MouseHover));
    AddEnum(StripPrefix("MET_MouseExit"), static_cast<std::int32_t>(MET_MouseExit));
    AddEnum(StripPrefix("MET_ButtonPress"), static_cast<std::int32_t>(MET_ButtonPress));
    AddEnum(StripPrefix("MET_ButtonDClick"), static_cast<std::int32_t>(MET_ButtonDClick));
    AddEnum(StripPrefix("MET_ButtonRelease"), static_cast<std::int32_t>(MET_ButtonRelease));
    AddEnum(StripPrefix("MET_WheelRotation"), static_cast<std::int32_t>(MET_WheelRotation));
    AddEnum(StripPrefix("MET_KeyDown"), static_cast<std::int32_t>(MET_KeyDown));
    AddEnum(StripPrefix("MET_KeyUp"), static_cast<std::int32_t>(MET_KeyUp));
    AddEnum(StripPrefix("MET_Char"), static_cast<std::int32_t>(MET_Char));
  }
} // namespace moho

namespace
{
  alignas(moho::EMauiEventTypeTypeInfo) unsigned char
    gEMauiEventTypeTypeInfoStorage[sizeof(moho::EMauiEventTypeTypeInfo)]{};
  bool gEMauiEventTypeTypeInfoConstructed = false;

  [[nodiscard]] moho::EMauiEventTypeTypeInfo& GetEMauiEventTypeTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::EMauiEventTypeTypeInfo*>(gEMauiEventTypeTypeInfoStorage);
  }

  void cleanup_EMauiEventTypeTypeInfo()
  {
    if (gEMauiEventTypeTypeInfoConstructed) {
      GetEMauiEventTypeTypeInfo().~EMauiEventTypeTypeInfo();
      gEMauiEventTypeTypeInfoConstructed = false;
    }
  }

  /**
   * Constructs the static `EMauiEventType` enum descriptor. The constructor
   * pre-registers the RTTI mapping itself, so placement-constructing it here is
   * the whole registration.
   *
   * Every MAUI event delivered to a control passes through
   * `CreateLuaEventObject`, which reflects the event type to build the Lua
   * payload. Without this instance nothing ever calls `PreRegisterRType`, and
   * the first mouse click aborts with "Attempting to lookup the RType for enum
   * moho::EMauiEventType before it is registered."
   */
  gpg::REnumType* construct_EMauiEventTypeTypeInfo()
  {
    if (!gEMauiEventTypeTypeInfoConstructed) {
      new (gEMauiEventTypeTypeInfoStorage) moho::EMauiEventTypeTypeInfo();
      gEMauiEventTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(&GetEMauiEventTypeTypeInfo());
  }

  int register_EMauiEventTypeTypeInfo()
  {
    (void)construct_EMauiEventTypeTypeInfo();
    return std::atexit(&cleanup_EMauiEventTypeTypeInfo);
  }

  struct EMauiEventTypeTypeInfoBootstrap
  {
    EMauiEventTypeTypeInfoBootstrap() { (void)register_EMauiEventTypeTypeInfo(); }
  };

  EMauiEventTypeTypeInfoBootstrap gEMauiEventTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: the descriptor has to exist before anything calls
// gpg::LookupRType on it. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EMauiEventTypeTypeInfo_00795a, register_EMauiEventTypeTypeInfo)
