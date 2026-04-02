#include "moho/resource/blueprints/REmitterBlueprintTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"

namespace
{
  using TypeInfo = moho::REmitterBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gREmitterBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gREmitterBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireREmitterBlueprintTypeInfo()
  {
    if (!gREmitterBlueprintTypeInfoConstructed) {
      new (gREmitterBlueprintTypeInfoStorage) TypeInfo();
      gREmitterBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gREmitterBlueprintTypeInfoStorage);
  }

  void cleanup_REmitterBlueprintTypeInfo()
  {
    if (!gREmitterBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireREmitterBlueprintTypeInfo().~TypeInfo();
    gREmitterBlueprintTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedEmitterBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REmitterBlueprint));
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

  [[nodiscard]] gpg::RType* CachedEmitterCurveType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REmitterBlueprintCurve));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRResIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RResId));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
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

  [[nodiscard]] gpg::RField* AddFieldWithDescription(
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

  [[nodiscard]] gpg::RRef MakeEmitterBlueprintRef(moho::REmitterBlueprint* object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedEmitterBlueprintType();
    return out;
  }

  [[nodiscard]] gpg::RRef NewEmitterBlueprintRef()
  {
    return MakeEmitterBlueprintRef(new moho::REmitterBlueprint());
  }

  [[nodiscard]] gpg::RRef ConstructEmitterBlueprintRef(void* objectMemory)
  {
    if (!objectMemory) {
      return MakeEmitterBlueprintRef(nullptr);
    }

    auto* const object = new (objectMemory) moho::REmitterBlueprint();
    return MakeEmitterBlueprintRef(object);
  }

  void DeleteEmitterBlueprintObject(void* objectMemory)
  {
    delete static_cast<moho::REmitterBlueprint*>(objectMemory);
  }

  void DestroyEmitterBlueprintObject(void* objectMemory)
  {
    if (!objectMemory) {
      return;
    }

    static_cast<moho::REmitterBlueprint*>(objectMemory)->~REmitterBlueprint();
  }

  struct REmitterBlueprintTypeInfoBootstrap
  {
    REmitterBlueprintTypeInfoBootstrap()
    {
      moho::register_REmitterBlueprintTypeInfo();
    }
  };

  REmitterBlueprintTypeInfoBootstrap gREmitterBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050F460 (FUN_0050F460, Moho::REmitterBlueprintTypeInfo::REmitterBlueprintTypeInfo)
   */
  REmitterBlueprintTypeInfo::REmitterBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REmitterBlueprint), this);
  }

  /**
   * Address: 0x0050F520 (FUN_0050F520, Moho::REmitterBlueprintTypeInfo::dtr)
   */
  REmitterBlueprintTypeInfo::~REmitterBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050F510 (FUN_0050F510, Moho::REmitterBlueprintTypeInfo::GetName)
   */
  const char* REmitterBlueprintTypeInfo::GetName() const
  {
    return "REmitterBlueprint";
  }

  /**
   * Address: 0x0050F4C0 (FUN_0050F4C0, Moho::REmitterBlueprintTypeInfo::Init)
   */
  void REmitterBlueprintTypeInfo::Init()
  {
    size_ = sizeof(REmitterBlueprint);
    newRefFunc_ = &NewEmitterBlueprintRef;
    deleteFunc_ = &DeleteEmitterBlueprintObject;
    ctorRefFunc_ = &ConstructEmitterBlueprintRef;
    dtrFunc_ = &DestroyEmitterBlueprintObject;
    AddEffectBase(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050F5C0 (FUN_0050F5C0, Moho::REmitterBlueprintTypeInfo::AddFields)
   */
  void REmitterBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BlueprintId", CachedRResIdType(), 0x08, "Blueprint ID");
    AddFieldWithDescription(typeInfo, "SizeCurve", CachedEmitterCurveType(), 0x28, "Size of emitter over time");
    AddFieldWithDescription(typeInfo, "XDirectionCurve", CachedEmitterCurveType(), 0x40, "X direction");
    AddFieldWithDescription(typeInfo, "YDirectionCurve", CachedEmitterCurveType(), 0x58, "Y direction");
    AddFieldWithDescription(typeInfo, "ZDirectionCurve", CachedEmitterCurveType(), 0x70, "Z direction");
    AddFieldWithDescription(typeInfo, "EmitRateCurve", CachedEmitterCurveType(), 0x88, "EmitRateCurve");
    AddFieldWithDescription(typeInfo, "LifetimeCurve", CachedEmitterCurveType(), 0xA0, "LifetimeCurve");
    AddFieldWithDescription(typeInfo, "VelocityCurve", CachedEmitterCurveType(), 0xB8, "VelocityCurve");
    AddFieldWithDescription(typeInfo, "XAccelCurve", CachedEmitterCurveType(), 0xD0, "XAccelCurve");
    AddFieldWithDescription(typeInfo, "YAccelCurve", CachedEmitterCurveType(), 0xE8, "YAccelCurve");
    AddFieldWithDescription(typeInfo, "ZAccelCurve", CachedEmitterCurveType(), 0x100, "ZAccelCurve");
    AddFieldWithDescription(
      typeInfo,
      "ResistanceCurve",
      CachedEmitterCurveType(),
      0x118,
      "drag coefficient (actually, the drag coefficient divied by the mass)"
    );
    AddFieldWithDescription(typeInfo, "StartSizeCurve", CachedEmitterCurveType(), 0x130, "StartSizeCurve");
    AddFieldWithDescription(typeInfo, "EndSizeCurve", CachedEmitterCurveType(), 0x148, "EndSizeCurve");
    AddFieldWithDescription(typeInfo, "InitialRotationCurve", CachedEmitterCurveType(), 0x160, "InitialRotationCurve");
    AddFieldWithDescription(typeInfo, "RotationRateCurve", CachedEmitterCurveType(), 0x178, "RotationRateCurve");
    AddFieldWithDescription(typeInfo, "FrameRateCurve", CachedEmitterCurveType(), 0x190, "FrameRateCurve");
    AddFieldWithDescription(typeInfo, "TextureSelectionCurve", CachedEmitterCurveType(), 0x1A8, "TextureSelectionCurve");
    AddFieldWithDescription(typeInfo, "XPosCurve", CachedEmitterCurveType(), 0x1C0, "X Offset Curve");
    AddFieldWithDescription(typeInfo, "YPosCurve", CachedEmitterCurveType(), 0x1D8, "Y Offset Curve");
    AddFieldWithDescription(typeInfo, "ZPosCurve", CachedEmitterCurveType(), 0x1F0, "Z Offset Curve");
    AddFieldWithDescription(typeInfo, "RampSelectionCurve", CachedEmitterCurveType(), 0x208, "RampSelectionCurve");
    AddFieldWithDescription(typeInfo, "LocalVelocity", CachedBoolType(), 0x220, "Is velocity attached to bone");
    AddFieldWithDescription(typeInfo, "LocalAcceleration", CachedBoolType(), 0x221, "Is acceleration attached to bone");
    AddFieldWithDescription(typeInfo, "Gravity", CachedBoolType(), 0x222, "Gravity enabled?");
    AddFieldWithDescription(
      typeInfo, "AlignRotation", CachedBoolType(), 0x223, "Align the rotation of the particle with direction?"
    );
    AddFieldWithDescription(
      typeInfo, "AlignToBone", CachedBoolType(), 0x224, "Align the intitial rotation of the particle to the bone"
    );
    AddFieldWithDescription(
      typeInfo, "EmitIfVisible", CachedBoolType(), 0x225, "Emit particles ONLY if this is emitter is visible"
    );
    AddFieldWithDescription(
      typeInfo, "ParticleResistance", CachedBoolType(), 0x228, "true to enable the use of drag on a particle"
    );
    AddFieldWithDescription(
      typeInfo, "CatchupEmit", CachedBoolType(), 0x226, "catchup particles for the ticks that we weren't visible"
    );
    AddFieldWithDescription(
      typeInfo,
      "CreateIfVisible",
      CachedBoolType(),
      0x227,
      "when this emitter is initially created only create and emit if visible"
    );
    AddFieldWithDescription(typeInfo, "Flat", CachedBoolType(), 0x229, "Make the particles flat in world space.");
    AddFieldWithDescription(typeInfo, "InterpolateEmission", CachedBoolType(), 0x22A, "Interpolate emission over tick");
    AddFieldWithDescription(
      typeInfo, "SnapToWaterline", CachedBoolType(), 0x22B, "Snap underwater emission to the waterline"
    );
    AddFieldWithDescription(typeInfo, "OnlyEmitOnWater", CachedBoolType(), 0x22C, "Only emit if over water");
    AddFieldWithDescription(
      typeInfo, "TextureStripcount", CachedFloatType(), 0x230, "Number of strips in the animated texture"
    );
    AddFieldWithDescription(typeInfo, "SortOrder", CachedFloatType(), 0x234, "Sort order of particles emitted");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), 0x23C, "Lifetime of emitter in ticks");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), 0x238, "Distance emission cuts out.");
    AddFieldWithDescription(typeInfo, "Repeattime", CachedFloatType(), 0x240, "Repeattime of emitter in ticks");
    AddFieldWithDescription(
      typeInfo, "TextureFramecount", CachedFloatType(), 0x244, "number of frames in texture we are using."
    );
    AddFieldWithDescription(typeInfo, "Blendmode", CachedInt32Type(), 0x248, "Blendmode for this emitter.");

    gpg::RField* const textureNameField = AddFieldWithDescription(
      typeInfo, "TextureName", CachedStringType(), 0x24C, "Name of texture we are using for this particle"
    );
    textureNameField->mName = "Texture";

    gpg::RField* const rampTextureNameField = AddFieldWithDescription(
      typeInfo, "RampTextureName", CachedStringType(), 0x268, "Name of ramp texture we are using for this particle"
    );
    rampTextureNameField->mName = "RampTexture";
  }

  /**
   * Address: 0x00BC8090 (FUN_00BC8090, register_REmitterBlueprintTypeInfo)
   */
  void register_REmitterBlueprintTypeInfo()
  {
    (void)AcquireREmitterBlueprintTypeInfo();
    (void)std::atexit(&cleanup_REmitterBlueprintTypeInfo);
  }
} // namespace moho

