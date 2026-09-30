#include "RPropBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintTypeInfo;

  /**
   * Address: 0x00BF30F0 (FUN_00BF30F0, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireRPropBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RType* CachedEntityBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REntityBlueprint));
    }
    return cached;
  }

  struct RPropBlueprintTypeInfoBootstrap
  {
    RPropBlueprintTypeInfoBootstrap()
    {
      moho::register_RPropBlueprintTypeInfo();
    }
  };

  [[maybe_unused]] RPropBlueprintTypeInfoBootstrap gRPropBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  class RPropBlueprintDefenseTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "RPropBlueprintDefense";
    }

    void Init() override
    {
      size_ = sizeof(RPropBlueprintDefense);
      gpg::RType::Init();
      Finish();
    }
  };

  class RPropBlueprintEconomyTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "RPropBlueprintEconomy";
    }

    void Init() override
    {
      size_ = sizeof(RPropBlueprintEconomy);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x0051D5F0 (FUN_0051D5F0, preregister_RPropBlueprintDefenseTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for `RPropBlueprintDefense`.
   */
  [[nodiscard]] gpg::RType* preregister_RPropBlueprintDefenseTypeInfo()
  {
    static RPropBlueprintDefenseTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(RPropBlueprintDefense), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0051D7A0 (FUN_0051D7A0, preregister_RPropBlueprintEconomyTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for `RPropBlueprintEconomy`.
   */
  [[nodiscard]] gpg::RType* preregister_RPropBlueprintEconomyTypeInfo()
  {
    static RPropBlueprintEconomyTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(RPropBlueprintEconomy), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0051D950 (FUN_0051D950, Moho::RPropBlueprintTypeInfo::RPropBlueprintTypeInfo)
   */
  RPropBlueprintTypeInfo::RPropBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprint), this);
  }

  /**
   * Address: 0x0051DA20 (FUN_0051DA20, Moho::RPropBlueprintTypeInfo::dtr)
   */
  RPropBlueprintTypeInfo::~RPropBlueprintTypeInfo() = default;

  /**
   * Address: 0x0051DA10 (FUN_0051DA10, Moho::RPropBlueprintTypeInfo::GetName)
   */
  const char* RPropBlueprintTypeInfo::GetName() const
  {
    return "RPropBlueprint";
  }

  /**
   * Address: 0x0051DEA0 (FUN_0051DEA0, Moho::RPropBlueprintTypeInfo::AddBase_REntityBlueprint)
   */
  void RPropBlueprintTypeInfo::AddBaseREntityBlueprint(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedEntityBlueprintType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x0051D9B0 (FUN_0051D9B0, Moho::RPropBlueprintTypeInfo::Init)
   */
  void RPropBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprint);
    AddBaseREntityBlueprint(this);
    gpg::RType::Init();

    gpg::RField* const displayField = AddField<moho::RPropBlueprintDisplay>("Display", offsetof(RPropBlueprint, Display));
    displayField->mFlags = 3;
    displayField->mDesc = "Display information for the unit";

    gpg::RField* const defenseField = AddField<moho::RPropBlueprintDefense>("Defense", offsetof(RPropBlueprint, Defense));
    defenseField->mFlags = 3;
    defenseField->mDesc = "Defense information for the unit";

    gpg::RField* const economyField = AddField<moho::RPropBlueprintEconomy>("Economy", offsetof(RPropBlueprint, Economy));
    economyField->mFlags = 3;
    economyField->mDesc = "Economy information for the unit";

    Finish();
  }

  /**
   * Address: 0x00BC8810 (FUN_00BC8810, register_RPropBlueprintTypeInfo)
   */
  void register_RPropBlueprintTypeInfo()
  {
    (void)preregister_RPropBlueprintDefenseTypeInfo();
    (void)preregister_RPropBlueprintEconomyTypeInfo();
    (void)AcquireRPropBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RPropBlueprintTypeInfo_460a53, moho::register_RPropBlueprintTypeInfo)

GPG_PREREGISTER_INIT(preregister_RPropBlueprintDefenseTypeInfo_460a53, moho::preregister_RPropBlueprintDefenseTypeInfo)
GPG_PREREGISTER_INIT(preregister_RPropBlueprintEconomyTypeInfo_460a53, moho::preregister_RPropBlueprintEconomyTypeInfo)
