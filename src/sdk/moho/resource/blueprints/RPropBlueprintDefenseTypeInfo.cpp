#include "RPropBlueprintDefenseTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/RPropBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintDefenseTypeInfo;

  alignas(TypeInfo) unsigned char gRPropBlueprintDefenseTypeInfoStorage[sizeof(TypeInfo)];
  bool gRPropBlueprintDefenseTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRPropBlueprintDefenseTypeInfo()
  {
    if (!gRPropBlueprintDefenseTypeInfoConstructed) {
      new (gRPropBlueprintDefenseTypeInfoStorage) TypeInfo();
      gRPropBlueprintDefenseTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRPropBlueprintDefenseTypeInfoStorage);
  }

  /**
   * Address: 0x00BF3030 (FUN_00BF3030)
   */
  void cleanup_RPropBlueprintDefenseTypeInfo()
  {
    if (!gRPropBlueprintDefenseTypeInfoConstructed) {
      return;
    }

    AcquireRPropBlueprintDefenseTypeInfo().~TypeInfo();
    gRPropBlueprintDefenseTypeInfoConstructed = false;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  void AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0051D5F0 (FUN_0051D5F0)
   */
  RPropBlueprintDefenseTypeInfo::RPropBlueprintDefenseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprintDefense), this);
  }

  /**
   * Address: 0x0051D6C0 (FUN_0051D6C0, Moho::RPropBlueprintDefenseTypeInfo::dtr)
   */
  RPropBlueprintDefenseTypeInfo::~RPropBlueprintDefenseTypeInfo() = default;

  /**
   * Address: 0x0051D6B0 (FUN_0051D6B0, Moho::RPropBlueprintDefenseTypeInfo::GetName)
   */
  const char* RPropBlueprintDefenseTypeInfo::GetName() const
  {
    return "RPropBlueprintDefense";
  }

  /**
   * Address: 0x0051D650 (FUN_0051D650, Moho::RPropBlueprintDefenseTypeInfo::Init)
   */
  void RPropBlueprintDefenseTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprintDefense);
    gpg::RType::Init();
    AddFieldWithDescription(this, "MaxHealth", CachedFloatType(), 0x00, "Max health value for the prop");
    AddFieldWithDescription(this, "Health", CachedFloatType(), 0x04, "Starting health value for the prop");
    Finish();
  }

  /**
   * Address: 0x00BC87D0 (FUN_00BC87D0)
   */
  int register_RPropBlueprintDefenseTypeInfo()
  {
    (void)AcquireRPropBlueprintDefenseTypeInfo();
    return std::atexit(&cleanup_RPropBlueprintDefenseTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RPropBlueprintDefenseTypeInfo_51d5f0, moho::register_RPropBlueprintDefenseTypeInfo)
