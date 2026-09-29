#include "moho/resource/blueprints/REmitterBlueprintTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::REmitterBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireREmitterBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
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
 * Address: 0x00510EB0 (FUN_00510EB0, Moho::REmitterBlueprintTypeInfo::AddBase_REffectBlueprint)
 *
 * What it does:
 * Registers `REffectBlueprint` as this type's reflected base at offset 0 - single
 * inheritance, so the sub-object starts where the object does.
 */
void REmitterBlueprintTypeInfo::AddBase_REffectBlueprint(gpg::RType* const typeInfo)
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
   * Address: 0x0050F4C0 (FUN_0050F4C0, Moho::REmitterBlueprintTypeInfo::Init)
   */
  void REmitterBlueprintTypeInfo::Init()
  {
    size_ = sizeof(REmitterBlueprint);
    (void)BindEmitterBlueprintTypeInfoHookLanes(this);
    AddBase_REffectBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050F5C0 (FUN_0050F5C0, Moho::REmitterBlueprintTypeInfo::AddFields)
   */
  void REmitterBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BlueprintId", CachedRResIdType(), offsetof(REmitterBlueprint, BlueprintId), "Blueprint ID");
    AddEmitterCurveFieldWithDescription(typeInfo, "SizeCurve", offsetof(REmitterBlueprint, SizeCurve), "Size of emitter over time");
    AddEmitterCurveFieldWithDescription(typeInfo, "XDirectionCurve", offsetof(REmitterBlueprint, XDirectionCurve), "X direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "YDirectionCurve", offsetof(REmitterBlueprint, YDirectionCurve), "Y direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZDirectionCurve", offsetof(REmitterBlueprint, ZDirectionCurve), "Z direction");
    AddEmitterCurveFieldWithDescription(typeInfo, "EmitRateCurve", offsetof(REmitterBlueprint, EmitRateCurve), "EmitRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "LifetimeCurve", offsetof(REmitterBlueprint, LifetimeCurve), "LifetimeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "VelocityCurve", offsetof(REmitterBlueprint, VelocityCurve), "VelocityCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "XAccelCurve", offsetof(REmitterBlueprint, XAccelCurve), "XAccelCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "YAccelCurve", offsetof(REmitterBlueprint, YAccelCurve), "YAccelCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZAccelCurve", offsetof(REmitterBlueprint, ZAccelCurve), "ZAccelCurve");
    AddEmitterCurveFieldWithDescription(
      typeInfo,
      "ResistanceCurve",
      offsetof(REmitterBlueprint, ResistanceCurve),
      "drag coefficient (actually, the drag coefficient divied by the mass)"
    );
    AddEmitterCurveFieldWithDescription(typeInfo, "StartSizeCurve", offsetof(REmitterBlueprint, StartSizeCurve), "StartSizeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "EndSizeCurve", offsetof(REmitterBlueprint, EndSizeCurve), "EndSizeCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "InitialRotationCurve", offsetof(REmitterBlueprint, InitialRotationCurve), "InitialRotationCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "RotationRateCurve", offsetof(REmitterBlueprint, RotationRateCurve), "RotationRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "FrameRateCurve", offsetof(REmitterBlueprint, FrameRateCurve), "FrameRateCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "TextureSelectionCurve", offsetof(REmitterBlueprint, TextureSelectionCurve), "TextureSelectionCurve");
    AddEmitterCurveFieldWithDescription(typeInfo, "XPosCurve", offsetof(REmitterBlueprint, XPosCurve), "X Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "YPosCurve", offsetof(REmitterBlueprint, YPosCurve), "Y Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "ZPosCurve", offsetof(REmitterBlueprint, ZPosCurve), "Z Offset Curve");
    AddEmitterCurveFieldWithDescription(typeInfo, "RampSelectionCurve", offsetof(REmitterBlueprint, RampSelectionCurve), "RampSelectionCurve");
    AddFieldWithDescription(typeInfo, "LocalVelocity", CachedBoolType(), offsetof(REmitterBlueprint, LocalVelocity), "Is velocity attached to bone");
    AddFieldWithDescription(typeInfo, "LocalAcceleration", CachedBoolType(), offsetof(REmitterBlueprint, LocalAcceleration), "Is acceleration attached to bone");
    AddFieldWithDescription(typeInfo, "Gravity", CachedBoolType(), offsetof(REmitterBlueprint, Gravity), "Gravity enabled?");
    AddFieldWithDescription(
      typeInfo, "AlignRotation", CachedBoolType(), offsetof(REmitterBlueprint, AlignRotation), "Align the rotation of the particle with direction?"
    );
    AddFieldWithDescription(
      typeInfo, "AlignToBone", CachedBoolType(), offsetof(REmitterBlueprint, AlignToBone), "Align the intitial rotation of the particle to the bone"
    );
    AddFieldWithDescription(
      typeInfo, "EmitIfVisible", CachedBoolType(), offsetof(REmitterBlueprint, EmitIfVisible), "Emit particles ONLY if this is emitter is visible"
    );
    AddFieldWithDescription(
      typeInfo, "ParticleResistance", CachedBoolType(), offsetof(REmitterBlueprint, ParticleResistance), "true to enable the use of drag on a particle"
    );
    AddFieldWithDescription(
      typeInfo, "CatchupEmit", CachedBoolType(), offsetof(REmitterBlueprint, CatchupEmit), "catchup particles for the ticks that we weren't visible"
    );
    AddFieldWithDescription(
      typeInfo,
      "CreateIfVisible",
      CachedBoolType(),
      offsetof(REmitterBlueprint, CreateIfVisible),
      "when this emitter is initially created only create and emit if visible"
    );
    AddFieldWithDescription(typeInfo, "Flat", CachedBoolType(), offsetof(REmitterBlueprint, Flat), "Make the particles flat in world space.");
    AddFieldWithDescription(typeInfo, "InterpolateEmission", CachedBoolType(), offsetof(REmitterBlueprint, InterpolateEmission), "Interpolate emission over tick");
    AddFieldWithDescription(
      typeInfo, "SnapToWaterline", CachedBoolType(), offsetof(REmitterBlueprint, SnapToWaterline), "Snap underwater emission to the waterline"
    );
    AddFieldWithDescription(typeInfo, "OnlyEmitOnWater", CachedBoolType(), offsetof(REmitterBlueprint, OnlyEmitOnWater), "Only emit if over water");
    AddFieldWithDescription(
      typeInfo, "TextureStripcount", CachedFloatType(), offsetof(REmitterBlueprint, TextureStripCount), "Number of strips in the animated texture"
    );
    AddFieldWithDescription(typeInfo, "SortOrder", CachedFloatType(), offsetof(REmitterBlueprint, SortOrder), "Sort order of particles emitted");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), offsetof(REmitterBlueprint, Lifetime), "Lifetime of emitter in ticks");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), offsetof(REmitterBlueprint, LODCutoff), "Distance emission cuts out.");
    AddFieldWithDescription(typeInfo, "Repeattime", CachedFloatType(), offsetof(REmitterBlueprint, RepeatTime), "Repeattime of emitter in ticks");
    AddFieldWithDescription(
      typeInfo, "TextureFramecount", CachedFloatType(), offsetof(REmitterBlueprint, TextureFrameCount), "number of frames in texture we are using."
    );
    AddFieldWithDescription(typeInfo, "Blendmode", CachedInt32Type(), offsetof(REmitterBlueprint, BlendMode), "Blendmode for this emitter.");

    gpg::RField* const textureNameField = AddFieldWithDescription(
      typeInfo, "TextureName", CachedStringType(), offsetof(REmitterBlueprint, TextureName), "Name of texture we are using for this particle"
    );
    textureNameField->mName = "Texture";

    gpg::RField* const rampTextureNameField = AddFieldWithDescription(
      typeInfo, "RampTextureName", CachedStringType(), offsetof(REmitterBlueprint, RampTextureName), "Name of ramp texture we are using for this particle"
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
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_REmitterBlueprintTypeInfo_df6130, moho::register_REmitterBlueprintTypeInfo)
