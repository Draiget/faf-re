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

  /**
   * Address: 0x00510490 (FUN_00510490)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `REmitterBlueprint`.
   */
  [[nodiscard]] gpg::RType* CachedEmitterBlueprintType()
  {
    gpg::RType* cached = moho::REmitterBlueprint::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REmitterBlueprint));
      moho::REmitterBlueprint::sType = cached;
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

  [[nodiscard]] gpg::RField* AddEmitterCurveFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    const int offset,
    const char* const description
  )
  {
    gpg::RField* const field = typeInfo->AddFieldEmitterBlueprintCurve(fieldName, offset);
    field->v4 = 3;
    field->mDesc = description;
    return field;
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

  /**
   * Address: 0x00510B10 (FUN_00510B10, Moho::REmitterBlueprintTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `REmitterBlueprint`, runs constructor initialization, and
   * returns a typed reflection reference.
   */
  [[nodiscard]] gpg::RRef NewEmitterBlueprintRef()
  {
    return MakeEmitterBlueprintRef(new moho::REmitterBlueprint());
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

  /**
   * Address: 0x00510510 (FUN_00510510)
   *
   * What it does:
   * Binds the callback lanes used by `REmitterBlueprintTypeInfo` for object
   * allocation, placement construction, deletion, and destruction.
   */
  [[nodiscard]] TypeInfo* BindEmitterBlueprintTypeInfoHookLanes(TypeInfo* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewEmitterBlueprintRef;
    typeInfo->ctorRefFunc_ = &moho::REmitterBlueprintTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &DeleteEmitterBlueprintObject;
    typeInfo->dtrFunc_ = &DestroyEmitterBlueprintObject;
    return typeInfo;
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
    (void)BindEmitterBlueprintTypeInfoHookLanes(this);
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
    AddEmitterCurveFieldWithDescription(typeInfo, "SizeCurve", 0x28, "Size of emitter over time");
    AddEmitterCurveFieldWithDescription(typeInfo, "XDirectionCurve", 0x40, "X direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "YDirectionCurve", 0x58, "Y direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZDirectionCurve", 0x70, "Z direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "EmitRateCurve", 0x88, "EmitRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "LifetimeCurve", 0xA0, "LifetimeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "VelocityCurve", 0xB8, "VelocityCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "XAccelCurve", 0xD0, "XAccelCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "YAccelCurve", 0xE8, "YAccelCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZAccelCurve", 0x100, "ZAccelCurve");
    AddEmitterCurveFieldWithDescription(
      typeInfo,
      "ResistanceCurve",
      0x118,
      "drag coefficient (actually, the drag coefficient divied by the mass)"
    );
    AddEmitterCurveFieldWithDescription(typeInfo, "StartSizeCurve", 0x130, "StartSizeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "EndSizeCurve", 0x148, "EndSizeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "InitialRotationCurve", 0x160, "InitialRotationCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "RotationRateCurve", 0x178, "RotationRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "FrameRateCurve", 0x190, "FrameRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "TextureSelectionCurve", 0x1A8, "TextureSelectionCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "XPosCurve", 0x1C0, "X Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "YPosCurve", 0x1D8, "Y Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZPosCurve", 0x1F0, "Z Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "RampSelectionCurve", 0x208, "RampSelectionCurve");
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
   * Address: 0x00510BB0 (FUN_00510BB0, Moho::REmitterBlueprintTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `REmitterBlueprint` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef REmitterBlueprintTypeInfo::CtrRef(void* const objectMemory)
  {
    if (!objectMemory) {
      return MakeEmitterBlueprintRef(nullptr);
    }

    auto* const object = new (objectMemory) REmitterBlueprint();
    return MakeEmitterBlueprintRef(object);
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
