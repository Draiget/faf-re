#include "RTrailBlueprintTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/RResId.h"

namespace
{
  gpg::RType* CachedTrailBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RTrailBlueprint));
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

  gpg::RType* CachedRResIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RResId));
    }
    return cached;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  gpg::RType* CachedInt32Type()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(std::int32_t));
    }
    return cached;
  }

  gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  void AddFieldWithDescription(
    gpg::RType* typeInfo, const char* fieldName, gpg::RType* fieldType, const int offset, const char* description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
  }

  void AddEffectBase(gpg::RType* typeInfo)
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

  void RegisterTrailFields(gpg::RType* typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BlueprintId", CachedRResIdType(), 0x08, "Blueprint ID");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), 0x28, "Lifetime of emitter");
    AddFieldWithDescription(typeInfo, "TrailLength", CachedFloatType(), 0x2C, "Trail Length");
    AddFieldWithDescription(typeInfo, "StartSize", CachedFloatType(), 0x30, "Startsize");
    AddFieldWithDescription(typeInfo, "SortOrder", CachedFloatType(), 0x34, "Sort Order");
    AddFieldWithDescription(typeInfo, "BlendMode", CachedInt32Type(), 0x38, "BlendMode");
    AddFieldWithDescription(typeInfo, "TextureRepeatRate", CachedFloatType(), 0x44, "Texture repeat rate in units");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), 0x3C, "cutoff distance");
    AddFieldWithDescription(
      typeInfo, "EmitIfVisible", CachedBoolType(), 0x40, "Emit particles ONLY if this is emitter is visible"
    );
    AddFieldWithDescription(
      typeInfo, "CatchupEmit", CachedBoolType(), 0x41, "catchup particles for the ticks that we weren't visible"
    );
    AddFieldWithDescription(typeInfo, "RepeatTexture", CachedStringType(), 0x48, "name of texture that repeats");
    AddFieldWithDescription(typeInfo, "RampTexture", CachedStringType(), 0x64, "RampTextureName");
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
} // namespace

namespace moho
{
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
   * Address: 0x0050F230 (FUN_0050F230)
   *
   * What it does:
   * Sets `RTrailBlueprint` size, binds lifetime/new/delete hooks, registers
   * `REffectBlueprint` base metadata, and publishes trail-specific fields.
   */
  void RTrailBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RTrailBlueprint);
    newRefFunc_ = &NewTrailBlueprintRef;
    deleteFunc_ = &DeleteTrailBlueprintObject;
    ctorRefFunc_ = &ConstructTrailBlueprintRef;
    dtrFunc_ = &DestroyTrailBlueprintObject;
    AddEffectBase(this);
    gpg::RType::Init();
    RegisterTrailFields(this);
    Finish();
  }
} // namespace moho
