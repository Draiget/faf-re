#include "moho/ai/CAiPersonalityTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPersonality.h"
#include "moho/script/CScriptObject.h"

using namespace moho;

namespace
{
  alignas(CAiPersonalityTypeInfo) unsigned char gCAiPersonalityTypeInfoStorage[sizeof(CAiPersonalityTypeInfo)] = {};
  bool gCAiPersonalityTypeInfoConstructed = false;

  [[nodiscard]] CAiPersonalityTypeInfo* AcquireCAiPersonalityTypeInfo()
  {
    if (!gCAiPersonalityTypeInfoConstructed) {
      auto* const typeInfo = new (gCAiPersonalityTypeInfoStorage) CAiPersonalityTypeInfo();
      gpg::PreRegisterRType(typeid(CAiPersonality), typeInfo);
      gCAiPersonalityTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiPersonalityTypeInfo*>(gCAiPersonalityTypeInfoStorage);
  }

  /**
   * Address: 0x005B6810 (FUN_005B6810, preregister_CAiPersonalityTypeInfo)
   *
   * What it does:
   * Constructs static CAiPersonality RTTI storage and preregisters it.
   */
  [[nodiscard]] gpg::RType* preregister_CAiPersonalityTypeInfo()
  {
    return AcquireCAiPersonalityTypeInfo();
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

  /**
   * Address: 0x00BF76B0 (FUN_00BF76B0, cleanup_CAiPersonalityTypeInfo)
   *
   * What it does:
   * Releases static CAiPersonality RTTI storage.
   */
  void cleanup_CAiPersonalityTypeInfo()
  {
    if (!gCAiPersonalityTypeInfoConstructed) {
      return;
    }

    AcquireCAiPersonalityTypeInfo()->~CAiPersonalityTypeInfo();
    gCAiPersonalityTypeInfoConstructed = false;
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
 * Constructs/preregisters static CAiPersonality RTTI storage and installs
 * process-exit cleanup.
 */
int moho::register_CAiPersonalityTypeInfo()
{
  (void)preregister_CAiPersonalityTypeInfo();
  return std::atexit(&cleanup_CAiPersonalityTypeInfo);
}

namespace
{
  struct CAiPersonalityTypeInfoBootstrap
  {
    CAiPersonalityTypeInfoBootstrap()
    {
      (void)moho::register_CAiPersonalityTypeInfo();
    }
  };

  [[maybe_unused]] CAiPersonalityTypeInfoBootstrap gCAiPersonalityTypeInfoBootstrap;
} // namespace
