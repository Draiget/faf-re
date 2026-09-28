#include "moho/ai/CAiPersonalityTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPersonality.h"
#include "moho/script/CScriptObject.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF76B0 (FUN_00BF76B0, atexit destructor of the CAiPersonalityTypeInfo object)
   */
  [[nodiscard]] CAiPersonalityTypeInfo* AcquireCAiPersonalityTypeInfo()
  {
    static CAiPersonalityTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005B6810 (FUN_005B6810, preregister_CAiPersonalityTypeInfo)
   *
   * What it does:
   * Constructs static CAiPersonality RTTI storage and preregisters it.
   */
  [[nodiscard]] gpg::RType* preregister_CAiPersonalityTypeInfo()
  {
    CAiPersonalityTypeInfo* const typeInfo = AcquireCAiPersonalityTypeInfo();
    gpg::PreRegisterRType(typeid(CAiPersonality), typeInfo);
    return typeInfo;
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
   * Address: 0x005B9520 (FUN_005B9520)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected base lane for
   * `CAiPersonality` at offset `+0x00`.
   */
  void AddCScriptObjectBaseToCAiPersonalityType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x005B68A0 (FUN_005B68A0, scalar deleting thunk)
 */
CAiPersonalityTypeInfo::~CAiPersonalityTypeInfo() = default;

/**
 * Address: 0x005B6890 (FUN_005B6890, ?GetName@CAiPersonalityTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPersonalityTypeInfo::GetName() const
{
  return "CAiPersonality";
}

/**
 * Address: 0x005B6870 (FUN_005B6870, ?Init@CAiPersonalityTypeInfo@Moho@@UAEXXZ)
 */
void CAiPersonalityTypeInfo::Init()
{
  size_ = sizeof(CAiPersonality);
  gpg::RType::Init();
  AddCScriptObjectBaseToCAiPersonalityType(this);
  Finish();
}

/**
 * Address: 0x00BCD600 (FUN_00BCD600, register_CAiPersonalityTypeInfo)
 *
 * What it does:
 * Constructs/preregisters static CAiPersonality RTTI storage.
 */
void moho::register_CAiPersonalityTypeInfo()
{
  (void)preregister_CAiPersonalityTypeInfo();
}

namespace
{
  struct CAiPersonalityTypeInfoBootstrap
  {
    CAiPersonalityTypeInfoBootstrap()
    {
      moho::register_CAiPersonalityTypeInfo();
    }
  };

  [[maybe_unused]] CAiPersonalityTypeInfoBootstrap gCAiPersonalityTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiPersonalityTypeInfo_7b34c0, moho::register_CAiPersonalityTypeInfo)

GPG_PREREGISTER_INIT(AcquireCAiPersonalityTypeInfo_7b34c0, AcquireCAiPersonalityTypeInfo)
