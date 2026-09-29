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

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedInt32Type()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(std::int32_t));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  gpg::RField* AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
    return &typeInfo->fields_.back();
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
  baseField.v4 = 0;
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
    AddFieldWithDescription(typeInfo, "Length", CachedFloatType(), offsetof(RBeamBlueprint, Length), "Total length of beam");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), offsetof(RBeamBlueprint, Lifetime), "Lifetime of the emitter");
    AddFieldWithDescription(typeInfo, "Thickness", CachedFloatType(), offsetof(RBeamBlueprint, Thickness), "Thickness of the beam");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), offsetof(RBeamBlueprint, LODCutoff), "cutoff distance");
    AddFieldWithDescription(typeInfo, "TextureName", CachedStringType(), offsetof(RBeamBlueprint, TextureName), "Filename of texture");
    gpg::RField* const startColorField = typeInfo->AddFieldVector4f("StartColor", offsetof(RBeamBlueprint, StartColor));
    startColorField->v4 = 3;
    startColorField->mDesc = "RGBA start color of beam";
    gpg::RField* const endColorField = typeInfo->AddFieldVector4f("EndColor", offsetof(RBeamBlueprint, EndColor));
    endColorField->v4 = 3;
    endColorField->mDesc = "RGBA end color of beam";
    AddFieldWithDescription(typeInfo, "UShift", CachedFloatType(), offsetof(RBeamBlueprint, UShift), "U Texture shift of beam texture");
    AddFieldWithDescription(typeInfo, "VShift", CachedFloatType(), offsetof(RBeamBlueprint, VShift), "V Texture shift of beam texture");
    AddFieldWithDescription(typeInfo, "RepeatRate", CachedFloatType(), offsetof(RBeamBlueprint, RepeatRate), "How often the texture repeats per ogrid");
    AddFieldWithDescription(typeInfo, "Blendmode", CachedInt32Type(), offsetof(RBeamBlueprint, BlendMode), "blendmode of this beam");
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
