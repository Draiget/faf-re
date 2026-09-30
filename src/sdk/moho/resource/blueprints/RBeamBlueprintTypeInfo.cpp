#include "moho/resource/blueprints/RBeamBlueprintTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REffectBlueprint.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RBeamBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRBeamBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RType* CachedBeamBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RBeamBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEffectBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REffectBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeBeamBlueprintRef(moho::RBeamBlueprint* object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedBeamBlueprintType();
    return out;
  }

  [[nodiscard]] gpg::RRef NewBeamBlueprintRef()
  {
    return MakeBeamBlueprintRef(new moho::RBeamBlueprint());
  }

  [[nodiscard]] gpg::RRef ConstructBeamBlueprintRef(void* objectMemory)
  {
    if (!objectMemory) {
      return MakeBeamBlueprintRef(nullptr);
    }

    auto* const object = new (objectMemory) moho::RBeamBlueprint();
    return MakeBeamBlueprintRef(object);
  }

  void DeleteBeamBlueprintObject(void* objectMemory)
  {
    delete static_cast<moho::RBeamBlueprint*>(objectMemory);
  }

  void DestroyBeamBlueprintObject(void* objectMemory)
  {
    if (!objectMemory) {
      return;
    }

    static_cast<moho::RBeamBlueprint*>(objectMemory)->~RBeamBlueprint();
  }

  /**
   * Address: 0x00510530 (FUN_00510530)
   *
   * What it does:
   * Binds the callback lanes used by `RBeamBlueprintTypeInfo` for object
   * allocation, placement construction, deletion, and destruction.
   */
  [[nodiscard]] TypeInfo* BindBeamBlueprintTypeInfoHookLanes(TypeInfo* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewBeamBlueprintRef;
    typeInfo->ctorRefFunc_ = &ConstructBeamBlueprintRef;
    typeInfo->deleteFunc_ = &DeleteBeamBlueprintObject;
    typeInfo->dtrFunc_ = &DestroyBeamBlueprintObject;
    return typeInfo;
  }

  struct RBeamBlueprintTypeInfoBootstrap
  {
    RBeamBlueprintTypeInfoBootstrap()
    {
      moho::register_RBeamBlueprintTypeInfo();
    }
  };

  RBeamBlueprintTypeInfoBootstrap gRBeamBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050FA30 (FUN_0050FA30, Moho::RBeamBlueprintTypeInfo::RBeamBlueprintTypeInfo)
   */
  RBeamBlueprintTypeInfo::RBeamBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RBeamBlueprint), this);
  }

  /**
   * Address: 0x0050FAF0 (FUN_0050FAF0, Moho::RBeamBlueprintTypeInfo::dtr)
   */
  RBeamBlueprintTypeInfo::~RBeamBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050FAE0 (FUN_0050FAE0, Moho::RBeamBlueprintTypeInfo::GetName)
   */
  const char* RBeamBlueprintTypeInfo::GetName() const
  {
    return "RBeamBlueprint";
  }

  /**
 * Address: 0x00510F90 (FUN_00510F90, Moho::RBeamBlueprintTypeInfo::AddBase_REffectBlueprint)
 *
 * What it does:
 * Registers `REffectBlueprint` as this type's reflected base at offset 0 - single
 * inheritance, so the sub-object starts where the object does.
 */
void RBeamBlueprintTypeInfo::AddBase_REffectBlueprint(gpg::RType* const typeInfo)
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
   * Address: 0x0050FA90 (FUN_0050FA90, Moho::RBeamBlueprintTypeInfo::Init)
   */
  void RBeamBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RBeamBlueprint);
    (void)BindBeamBlueprintTypeInfoHookLanes(this);
    AddBase_REffectBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050FB90 (FUN_0050FB90, Moho::RBeamBlueprintTypeInfo::AddFields)
   */
  void RBeamBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    typeInfo->AddField<float>("Length", offsetof(RBeamBlueprint, Length), 3, "Total length of beam");
    typeInfo->AddField<float>("Lifetime", offsetof(RBeamBlueprint, Lifetime), 3, "Lifetime of the emitter");
    typeInfo->AddField<float>("Thickness", offsetof(RBeamBlueprint, Thickness), 3, "Thickness of the beam");
    typeInfo->AddField<float>("LODCutoff", offsetof(RBeamBlueprint, LODCutoff), 3, "cutoff distance");
    typeInfo->AddField<msvc8::string>("TextureName", offsetof(RBeamBlueprint, TextureName), 3, "Filename of texture");
    gpg::RField* const startColorField = typeInfo->AddField<moho::Vector4f>("StartColor", offsetof(RBeamBlueprint, StartColor));
    startColorField->mFlags = 3;
    startColorField->mDesc = "RGBA start color of beam";
    gpg::RField* const endColorField = typeInfo->AddField<moho::Vector4f>("EndColor", offsetof(RBeamBlueprint, EndColor));
    endColorField->mFlags = 3;
    endColorField->mDesc = "RGBA end color of beam";
    typeInfo->AddField<float>("UShift", offsetof(RBeamBlueprint, UShift), 3, "U Texture shift of beam texture");
    typeInfo->AddField<float>("VShift", offsetof(RBeamBlueprint, VShift), 3, "V Texture shift of beam texture");
    typeInfo->AddField<float>("RepeatRate", offsetof(RBeamBlueprint, RepeatRate), 3, "How often the texture repeats per ogrid");
    typeInfo->AddField<std::int32_t>("Blendmode", offsetof(RBeamBlueprint, BlendMode), 3, "blendmode of this beam");
  }

  /**
   * Address: 0x00BC80B0 (FUN_00BC80B0, register_RBeamBlueprintTypeInfo)
   */
  void register_RBeamBlueprintTypeInfo()
  {
    (void)AcquireRBeamBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RBeamBlueprintTypeInfo_860a8a, moho::register_RBeamBlueprintTypeInfo)
