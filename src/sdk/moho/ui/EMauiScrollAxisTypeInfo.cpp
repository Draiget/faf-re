#include "moho/ui/EMauiScrollAxisTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  /**
   * Address: 0x00786530 (FUN_00786530, Moho::EMauiScrollAxisTypeInfo::ctor)
   */
  EMauiScrollAxisTypeInfo::EMauiScrollAxisTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EMauiScrollAxis), this);
  }

  /**
   * Address: 0x007865F0 (FUN_007865F0, Moho::EMauiScrollAxisTypeInfo::dtr)
   */
  EMauiScrollAxisTypeInfo::~EMauiScrollAxisTypeInfo() = default;

  /**
   * Address: 0x007865E0 (FUN_007865E0, Moho::EMauiScrollAxisTypeInfo::GetName)
   */
  const char* EMauiScrollAxisTypeInfo::GetName() const
  {
    return "EMauiScrollAxis";
  }

  /**
   * Address: 0x00786590 (FUN_00786590, Moho::EMauiScrollAxisTypeInfo::Init)
   */
  void EMauiScrollAxisTypeInfo::Init()
  {
    size_ = sizeof(EMauiScrollAxis);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00786620 (FUN_00786620, Moho::EMauiScrollAxisTypeInfo::AddEnums)
   */
  void EMauiScrollAxisTypeInfo::AddEnums()
  {
    mPrefix = "MSA_";

    AddEnum(StripPrefix("MSA_Vert"), static_cast<std::int32_t>(MSA_Vert));
    AddEnum(StripPrefix("MSA_Horz"), static_cast<std::int32_t>(MSA_Horz));
  }
} // namespace moho


namespace
{
  alignas(moho::EMauiScrollAxisTypeInfo) unsigned char
    gEMauiScrollAxisTypeInfoStorage[sizeof(moho::EMauiScrollAxisTypeInfo)]{};
  bool gEMauiScrollAxisTypeInfoConstructed = false;

  [[nodiscard]] moho::EMauiScrollAxisTypeInfo& GetEMauiScrollAxisTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::EMauiScrollAxisTypeInfo*>(gEMauiScrollAxisTypeInfoStorage);
  }

  void cleanup_EMauiScrollAxisTypeInfo()
  {
    if (gEMauiScrollAxisTypeInfoConstructed) {
      GetEMauiScrollAxisTypeInfo().~EMauiScrollAxisTypeInfo();
      gEMauiScrollAxisTypeInfoConstructed = false;
    }
  }

  /**
   * Constructs the static `EMauiScrollAxis` enum descriptor. The constructor
   * pre-registers the RTTI mapping itself, so placement-constructing it here is
   * the whole registration. The binary static-initialises this descriptor in
   * .data (FUN_00786530 operates on a fixed global).
   *
   * `CMauiControl::GetScrollValues` reflects the axis to build its Lua call, and
   * MAUI runs that while handling an ordinary control event. Without this
   * instance nothing calls `PreRegisterRType`, and `gpg::LookupRType` throws
   * "Attempting to lookup the RType for enum moho::EMauiScrollAxis before it is
   * registered." That escapes through `LuaCallProtected`, which discards the
   * status, so the script aborts mid-handler with no error reported - which is
   * why a button changed texture on press but never reached the
   * `PostDragger(...)` that makes its OnClick fire.
   */
  gpg::REnumType* construct_EMauiScrollAxisTypeInfo()
  {
    if (!gEMauiScrollAxisTypeInfoConstructed) {
      new (gEMauiScrollAxisTypeInfoStorage) moho::EMauiScrollAxisTypeInfo();
      gEMauiScrollAxisTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(&GetEMauiScrollAxisTypeInfo());
  }

  int register_EMauiScrollAxisTypeInfo()
  {
    (void)construct_EMauiScrollAxisTypeInfo();
    return std::atexit(&cleanup_EMauiScrollAxisTypeInfo);
  }

  struct EMauiScrollAxisTypeInfoBootstrap
  {
    EMauiScrollAxisTypeInfoBootstrap() { (void)register_EMauiScrollAxisTypeInfo(); }
  };

  EMauiScrollAxisTypeInfoBootstrap gEMauiScrollAxisTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: the descriptor has to exist before anything calls
// gpg::LookupRType on it. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EMauiScrollAxisTypeInfo_007865, register_EMauiScrollAxisTypeInfo)
