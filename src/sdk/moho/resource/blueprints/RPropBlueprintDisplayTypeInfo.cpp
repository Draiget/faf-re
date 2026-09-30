#include "RPropBlueprintDisplayTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintDisplayTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRPropBlueprintDisplayTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  struct RPropBlueprintDisplayTypeInfoBootstrap
  {
    RPropBlueprintDisplayTypeInfoBootstrap()
    {
      (void)moho::register_RPropBlueprintDisplayTypeInfo();
    }
  };

  RPropBlueprintDisplayTypeInfoBootstrap gRPropBlueprintDisplayTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0051D450 (FUN_0051D450, Moho::RPropBlueprintDisplayTypeInfo::RPropBlueprintDisplayTypeInfo)
   */
  RPropBlueprintDisplayTypeInfo::RPropBlueprintDisplayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprintDisplay), this);
  }

  /**
   * Address: 0x0051D510 (FUN_0051D510, scalar deleting destructor thunk)
   */
  RPropBlueprintDisplayTypeInfo::~RPropBlueprintDisplayTypeInfo() = default;

  /**
   * Address: 0x0051D500 (FUN_0051D500)
   */
  const char* RPropBlueprintDisplayTypeInfo::GetName() const
  {
    return "RPropBlueprintDisplay";
  }

  /**
   * Address: 0x0051D4B0 (FUN_0051D4B0)
   *
   * What it does:
   * Sets `RPropBlueprintDisplay` size and publishes display field metadata.
   */
  void RPropBlueprintDisplayTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprintDisplay);
    gpg::RType::Init();
    AddField<moho::RResId>("MeshBlueprint", offsetof(RPropBlueprintDisplay, MeshBlueprint), 3, "Name of mesh blueprint to use. Leave blank to use default mesh.");
    AddField<float>("UniformScale", offsetof(RPropBlueprintDisplay, UniformScale), 3, "Uniform scale to apply to mesh");
    Finish();
  }

  /**
   * Address: 0x00BC87B0 (FUN_00BC87B0, register_RPropBlueprintDisplayTypeInfo)
   */
  void register_RPropBlueprintDisplayTypeInfo()
  {
    (void)AcquireRPropBlueprintDisplayTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RPropBlueprintDisplayTypeInfo_882cea, moho::register_RPropBlueprintDisplayTypeInfo)
