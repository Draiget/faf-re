#include "RTrailBlueprintTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/RResId.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RTrailBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRTrailBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x005104B0 (FUN_005104B0)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `RTrailBlueprint`.
   */
  gpg::RType* CachedTrailBlueprintType()
  {
    gpg::RType* cached = moho::RTrailBlueprint::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RTrailBlueprint));
      moho::RTrailBlueprint::sType = cached;
    }
    return cached;
  }

  gpg::RType* CachedEffectBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REffectBlueprint));
    }
    return cached;
  }

  gpg::RRef MakeTrailBlueprintRef(moho::RTrailBlueprint* object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedTrailBlueprintType();
    return out;
  }

  gpg::RRef NewTrailBlueprintRef()
  {
    return MakeTrailBlueprintRef(new moho::RTrailBlueprint());
  }

  gpg::RRef ConstructTrailBlueprintRef(void* objectMemory)
  {
    if (!objectMemory) {
      return MakeTrailBlueprintRef(nullptr);
    }

    auto* const object = new (objectMemory) moho::RTrailBlueprint();
    return MakeTrailBlueprintRef(object);
  }

  void DeleteTrailBlueprintObject(void* objectMemory)
  {
    delete static_cast<moho::RTrailBlueprint*>(objectMemory);
  }

  void DestroyTrailBlueprintObject(void* objectMemory)
  {
    if (!objectMemory) {
      return;
    }

    static_cast<moho::RTrailBlueprint*>(objectMemory)->~RTrailBlueprint();
  }

  /**
   * Address: 0x005104F0 (FUN_005104F0)
   *
   * What it does:
   * Binds the callback lanes used by `RTrailBlueprintTypeInfo` for object
   * allocation, placement construction, deletion, and destruction.
   */
  [[nodiscard]] TypeInfo* BindTrailBlueprintTypeInfoHookLanes(TypeInfo* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewTrailBlueprintRef;
    typeInfo->ctorRefFunc_ = &ConstructTrailBlueprintRef;
    typeInfo->deleteFunc_ = &DeleteTrailBlueprintObject;
    typeInfo->dtrFunc_ = &DestroyTrailBlueprintObject;
    return typeInfo;
  }

  struct RTrailBlueprintTypeInfoBootstrap
  {
    RTrailBlueprintTypeInfoBootstrap()
    {
      moho::register_RTrailBlueprintTypeInfo();
    }
  };

  RTrailBlueprintTypeInfoBootstrap gRTrailBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050F1D0 (FUN_0050F1D0, Moho::RTrailBlueprintTypeInfo::RTrailBlueprintTypeInfo)
   */
  RTrailBlueprintTypeInfo::RTrailBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RTrailBlueprint), this);
  }

  /**
   * Address: 0x0050F290 (FUN_0050F290, scalar deleting destructor thunk)
   */
  RTrailBlueprintTypeInfo::~RTrailBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050F280 (FUN_0050F280)
   */
  const char* RTrailBlueprintTypeInfo::GetName() const
  {
    return "RTrailBlueprint";
  }

  /**
 * Address: 0x00510E50 (FUN_00510E50, Moho::RTrailBlueprintTypeInfo::AddBase_REffectBlueprint)
 *
 * What it does:
 * Registers `REffectBlueprint` as this type's reflected base at offset 0 - single
 * inheritance, so the sub-object starts where the object does.
 */
void RTrailBlueprintTypeInfo::AddBase_REffectBlueprint(gpg::RType* typeInfo)
{
  gpg::RType* const effectType = CachedEffectBlueprintType();
  gpg::RField baseField{};
  baseField.mName = effectType->GetName();
  baseField.mType = effectType;
  baseField.mOffset = 0;
  baseField.mFlags = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
   * Address: 0x0050F230 (FUN_0050F230)
   *
   * What it does:
   * Sets `RTrailBlueprint` size, binds lifetime/new/delete hooks, registers
   * `REffectBlueprint` base metadata, and publishes trail-specific fields.
   */
  void RTrailBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RTrailBlueprint);
    (void)BindTrailBlueprintTypeInfoHookLanes(this);
    AddBase_REffectBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050F330 (FUN_0050F330, Moho::RTrailBlueprintTypeInfo::AddFields)
   */
  void RTrailBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    typeInfo->AddField<moho::RResId>("BlueprintId", offsetof(RTrailBlueprint, BlueprintId), 3, "Blueprint ID");
    typeInfo->AddField<float>("Lifetime", offsetof(RTrailBlueprint, Lifetime), 3, "Lifetime of emitter");
    typeInfo->AddField<float>("TrailLength", offsetof(RTrailBlueprint, TrailLength), 3, "Trail Length");
    typeInfo->AddField<float>("Size", offsetof(RTrailBlueprint, StartSize), 3, "Startsize");
    typeInfo->AddField<float>("SortOrder", offsetof(RTrailBlueprint, SortOrder), 3, "Sort Order");
    typeInfo->AddField<std::int32_t>("BlendMode", offsetof(RTrailBlueprint, BlendMode), 3, "BlendMode");
    typeInfo->AddField<float>("TextureRepeatRate", offsetof(RTrailBlueprint, TextureRepeatRate), 3, "Texture repeat rate in units");
    typeInfo->AddField<float>("LODCutoff", offsetof(RTrailBlueprint, LODCutoff), 3, "cutoff distance");
    typeInfo->AddField<bool>("EmitIfVisible", offsetof(RTrailBlueprint, EmitIfVisible), 3, "Emit particles ONLY if this is emitter is visible");
    typeInfo->AddField<bool>("CatchupEmit", offsetof(RTrailBlueprint, CatchupEmit), 3, "catchup particles for the ticks that we weren't visible");
    typeInfo->AddField<msvc8::string>("RepeatTexture", offsetof(RTrailBlueprint, RepeatTexture), 3, "name of texture that repeats");
    typeInfo->AddField<msvc8::string>("RampTexture", offsetof(RTrailBlueprint, RampTexture), 3, "RampTextureName");
  }

  /**
   * Address: 0x00BC8070 (FUN_00BC8070, register_RTrailBlueprintTypeInfo)
   */
  void register_RTrailBlueprintTypeInfo()
  {
    (void)AcquireRTrailBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RTrailBlueprintTypeInfo_19d3be, moho::register_RTrailBlueprintTypeInfo)
