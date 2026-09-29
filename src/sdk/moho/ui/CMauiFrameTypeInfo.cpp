#include "moho/ui/CMauiFrameTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C02E50 (FUN_00C02E50, atexit destructor of the CMauiFrameTypeInfo object)
   */
  [[nodiscard]] CMauiFrameTypeInfo& AcquireCMauiFrameTypeInfo()
  {
    static CMauiFrameTypeInfo sInstance;
    return sInstance;
  }

  struct CMauiFrameTypeInfoBootstrap
  {
    CMauiFrameTypeInfoBootstrap() { moho::register_CMauiFrameTypeInfoStartup(); }
  };
  CMauiFrameTypeInfoBootstrap gCMauiFrameTypeInfoBootstrap;

  /**
   * Address: 0x00796DF0 (FUN_00796DF0, Moho::CMauiFrameTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiFrame's reflected base, at offset 0.
   *
   * Without this the reflection graph has CMauiFrame standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * `gpg::RRef_CScriptObject` handed a CMauiFrame trips the binary's own
   * "isDer" assertion at reflection.h:458.
   */
  [[nodiscard]] gpg::RType* CachedCMauiControlType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiControl));
    }
    return cached;
  }

  void AddCMauiControlBase(gpg::RType& typeInfo)
  {
    gpg::RType* const baseType = CachedCMauiControlType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x00796060 (Moho::CMauiFrameTypeInfo::CMauiFrameTypeInfo)
 */
CMauiFrameTypeInfo::CMauiFrameTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiFrame), this);
}

/**
 * Address: 0x00796100
 */
CMauiFrameTypeInfo::~CMauiFrameTypeInfo() = default;

/**
 * Address: 0x007960F0
 */
const char* CMauiFrameTypeInfo::GetName() const
{
  return "CMauiFrame";
}

/**
 * Address: 0x007960C0
 */
void CMauiFrameTypeInfo::Init()
{
  static_assert(sizeof(moho::CMauiFrame) == 0x134, "moho::CMauiFrame is 0x134 bytes on x86");
  size_ = sizeof(moho::CMauiFrame);
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDE5B0 (FUN_00BDE5B0, register_CMauiFrameTypeInfoStartup)
 *
 * What it does:
 * Constructs the `CMauiFrame` type-info object.
 */
void moho::register_CMauiFrameTypeInfoStartup()
{
  (void)AcquireCMauiFrameTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiFrameTypeInfoStartup_050fa0, moho::register_CMauiFrameTypeInfoStartup)
