#include "moho/resource/blueprints/RBeamBlueprintTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REffectBlueprint.h"

namespace
{
  using TypeInfo = moho::RBeamBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRBeamBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gRBeamBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRBeamBlueprintTypeInfo()
  {
    if (!gRBeamBlueprintTypeInfoConstructed) {
      new (gRBeamBlueprintTypeInfoStorage) TypeInfo();
      gRBeamBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRBeamBlueprintTypeInfoStorage);
  }

  void cleanup_RBeamBlueprintTypeInfo()
  {
    if (!gRBeamBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRBeamBlueprintTypeInfo().~TypeInfo();
    gRBeamBlueprintTypeInfoConstructed = false;
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

  void AddEffectBase(gpg::RType* const typeInfo)
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
   * Address: 0x0050FA90 (FUN_0050FA90, Moho::RBeamBlueprintTypeInfo::Init)
   */
  void RBeamBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RBeamBlueprint);
    newRefFunc_ = &NewBeamBlueprintRef;
    deleteFunc_ = &DeleteBeamBlueprintObject;
    ctorRefFunc_ = &ConstructBeamBlueprintRef;
    dtrFunc_ = &DestroyBeamBlueprintObject;
    AddEffectBase(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050FB90 (FUN_0050FB90, Moho::RBeamBlueprintTypeInfo::AddFields)
   */
  void RBeamBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "Length", CachedFloatType(), 0x28, "Total length of beam");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), 0x2C, "Lifetime of the emitter");
    AddFieldWithDescription(typeInfo, "Thickness", CachedFloatType(), 0x30, "Thickness of the beam");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), 0x78, "cutoff distance");
    AddFieldWithDescription(typeInfo, "TextureName", CachedStringType(), 0x3C, "Filename of texture");
    gpg::RField* const startColorField = typeInfo->AddFieldVector4f("StartColor", 0x58);
    startColorField->v4 = 3;
    startColorField->mDesc = "RGBA start color of beam";
    gpg::RField* const endColorField = typeInfo->AddFieldVector4f("EndColor", 0x68);
    endColorField->v4 = 3;
    endColorField->mDesc = "RGBA end color of beam";
    AddFieldWithDescription(typeInfo, "UShift", CachedFloatType(), 0x34, "U Texture shift of beam texture");
    AddFieldWithDescription(typeInfo, "VShift", CachedFloatType(), 0x38, "V Texture shift of beam texture");
    AddFieldWithDescription(typeInfo, "RepeatRate", CachedFloatType(), 0x7C, "How often the texture repeats per ogrid");
    AddFieldWithDescription(typeInfo, "Blendmode", CachedInt32Type(), 0x80, "blendmode of this beam");
  }

  /**
   * Address: 0x00BC80B0 (FUN_00BC80B0, register_RBeamBlueprintTypeInfo)
   */
  void register_RBeamBlueprintTypeInfo()
  {
    (void)AcquireRBeamBlueprintTypeInfo();
    (void)std::atexit(&cleanup_RBeamBlueprintTypeInfo);
  }
} // namespace moho
