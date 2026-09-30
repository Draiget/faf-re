#include "moho/ai/CAiBrainTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"
#include "moho/script/CScriptObject.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6260 (FUN_00BF6260, atexit destructor of the CAiBrainTypeInfo object)
   */
  [[nodiscard]] CAiBrainTypeInfo& AcquireCAiBrainTypeInfo()
  {
    static CAiBrainTypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  /**
   * Address: 0x00581830 (FUN_00581830)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected base lane for `CAiBrain` at
   * offset `+0x00`.
   */
  void AddCScriptObjectBaseToCAiBrainType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  struct CAiBrainTypeInfoStartupBootstrap
  {
    CAiBrainTypeInfoStartupBootstrap()
    {
      moho::register_CAiBrainTypeInfoStartup();
    }
  };

  CAiBrainTypeInfoStartupBootstrap gCAiBrainTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00579B20 (FUN_00579B20, ??0CAiBrainTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `CAiBrain` RTTI for this type-info helper.
 */
CAiBrainTypeInfo::CAiBrainTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiBrain), this);
}

/**
 * Address: 0x00579BB0 (FUN_00579BB0, scalar deleting thunk)
 */
CAiBrainTypeInfo::~CAiBrainTypeInfo() = default;

/**
 * Address: 0x00579BA0 (FUN_00579BA0, ?GetName@CAiBrainTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBrainTypeInfo::GetName() const
{
  return "CAiBrain";
}

/**
 * Address: 0x00579B80 (FUN_00579B80, ?Init@CAiBrainTypeInfo@Moho@@UAEXXZ)
 */
void CAiBrainTypeInfo::Init()
{
  size_ = sizeof(CAiBrain);
  gpg::RType::Init();
  AddCScriptObjectBaseToCAiBrainType(this);
  Finish();
}

/**
 * Address: 0x00BCB3D0 (FUN_00BCB3D0, register_Moho::CAiBrainTypeInfo)
 *
 * What it does:
 * Ensures startup construction of `CAiBrainTypeInfo`.
 */
void moho::register_CAiBrainTypeInfoStartup()
{
  (void)AcquireCAiBrainTypeInfo();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiBrainTypeInfoStartup_776a4f, moho::register_CAiBrainTypeInfoStartup)
