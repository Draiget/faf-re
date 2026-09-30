#include "RMeshBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RMeshBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRMeshBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* CachedRBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RBlueprint));
    }
    return cached;
  }

  struct RMeshBlueprintTypeInfoBootstrap
  {
    RMeshBlueprintTypeInfoBootstrap()
    {
      (void)moho::register_RMeshBlueprintTypeInfo();
    }
  };

  RMeshBlueprintTypeInfoBootstrap gRMeshBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005186B0 (FUN_005186B0, Moho::RMeshBlueprintTypeInfo::RMeshBlueprintTypeInfo)
   */
  RMeshBlueprintTypeInfo::RMeshBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RMeshBlueprint), this);
  }

  /**
   * Address: 0x00BF2C60 (FUN_00BF2C60, scalar deleting destructor thunk)
   */
  RMeshBlueprintTypeInfo::~RMeshBlueprintTypeInfo() = default;

  /**
   * Address: 0x00518740 (FUN_00518740)
   */
  const char* RMeshBlueprintTypeInfo::GetName() const
  {
    return "RMeshBlueprint";
  }

  /**
   * Address: 0x0051A2D0 (FUN_0051A2D0)
   *
   * What it does:
   * Adds `RBlueprint` as the reflected base class lane.
   */
  void RMeshBlueprintTypeInfo::AddBaseRBlueprint(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRBlueprintType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x005187F0 (FUN_005187F0)
   *
   * What it does:
   * Registers mesh-blueprint field descriptors and descriptions.
   */
  void RMeshBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* const lodsField = typeInfo->AddField<msvc8::vector<moho::RMeshBlueprintLOD>>("LODs", offsetof(RMeshBlueprint, mLods));
    lodsField->mFlags = 3;
    lodsField->mDesc = "List of LOD info";
    typeInfo->AddField<float>("IconFadeInZoom", offsetof(RMeshBlueprint, mIconFadeInZoom), 3, "Zoom level at which to start fading in the strategic icon");
    typeInfo->AddField<float>("SortOrder", offsetof(RMeshBlueprint, mSortOrder), 3, "Sort order of mesh we render smallest to largest");
    typeInfo->AddField<float>("UniformScale", offsetof(RMeshBlueprint, mUniformScale), 3, "Uniform scale factor");
    typeInfo->AddField<bool>("StraddleWater", offsetof(RMeshBlueprint, mStraddleWater), 3, "Render both above and below the water.");
  }

  /**
   * Address: 0x00518710 (FUN_00518710)
   *
   * What it does:
   * Sets `RMeshBlueprint` size, registers `RBlueprint` base metadata, and
   * publishes mesh-blueprint fields.
   */
  void RMeshBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RMeshBlueprint);
    AddBaseRBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8530 (FUN_00BC8530, register_RMeshBlueprintTypeInfo)
   */
  void register_RMeshBlueprintTypeInfo()
  {
    (void)AcquireRMeshBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RMeshBlueprintTypeInfo_55474b, moho::register_RMeshBlueprintTypeInfo)
