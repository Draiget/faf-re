#include "RPropBlueprintEconomyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/RPropBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintEconomyTypeInfo;

  alignas(TypeInfo) unsigned char gRPropBlueprintEconomyTypeInfoStorage[sizeof(TypeInfo)];
  bool gRPropBlueprintEconomyTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRPropBlueprintEconomyTypeInfo()
  {
    if (!gRPropBlueprintEconomyTypeInfoConstructed) {
      new (gRPropBlueprintEconomyTypeInfoStorage) TypeInfo();
      gRPropBlueprintEconomyTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRPropBlueprintEconomyTypeInfoStorage);
  }

  /**
   * Address: 0x00BF3090 (FUN_00BF3090)
   */
  void cleanup_RPropBlueprintEconomyTypeInfo()
  {
    if (!gRPropBlueprintEconomyTypeInfoConstructed) {
      return;
    }

    AcquireRPropBlueprintEconomyTypeInfo().~TypeInfo();
    gRPropBlueprintEconomyTypeInfoConstructed = false;
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
   * Address: 0x0051D7A0 (FUN_0051D7A0)
   */
  RPropBlueprintEconomyTypeInfo::RPropBlueprintEconomyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprintEconomy), this);
  }

  /**
   * Address: 0x0051D870 (FUN_0051D870, Moho::RPropBlueprintEconomyTypeInfo::dtr)
   */
  RPropBlueprintEconomyTypeInfo::~RPropBlueprintEconomyTypeInfo() = default;

  /**
   * Address: 0x0051D860 (FUN_0051D860, Moho::RPropBlueprintEconomyTypeInfo::GetName)
   */
  const char* RPropBlueprintEconomyTypeInfo::GetName() const
  {
    return "RPropBlueprintEconomy";
  }

  /**
   * Address: 0x0051D800 (FUN_0051D800, Moho::RPropBlueprintEconomyTypeInfo::Init)
   */
  void RPropBlueprintEconomyTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprintEconomy);
    gpg::RType::Init();
    AddFieldWithDescription(this, "ReclaimMassMax", CachedFloatType(), 0x00, "Max Reclaimable mass resource.");
    AddFieldWithDescription(this, "ReclaimEnergyMax", CachedFloatType(), 0x04, "Max Reclaimable Energy resource.");
    Finish();
  }

  /**
   * Address: 0x00BC87F0 (FUN_00BC87F0)
   */
  int register_RPropBlueprintEconomyTypeInfo()
  {
    (void)AcquireRPropBlueprintEconomyTypeInfo();
    return std::atexit(&cleanup_RPropBlueprintEconomyTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RPropBlueprintEconomyTypeInfo_51d7a0, moho::register_RPropBlueprintEconomyTypeInfo)
