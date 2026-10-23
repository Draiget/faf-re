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
  baseField.mFlags = 0;
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
    typeInfo->AddField<moho::RResId>("BlueprintId", offsetof(REmitterBlueprint, BlueprintId), 3, "Blueprint ID");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("SizeCurve", offsetof(REmitterBlueprint, SizeCurve), 3, "Size of emitter over time");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("XDirectionCurve", offsetof(REmitterBlueprint, XDirectionCurve), 3, "X direction");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("YDirectionCurve", offsetof(REmitterBlueprint, YDirectionCurve), 3, "Y direction");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("ZDirectionCurve", offsetof(REmitterBlueprint, ZDirectionCurve), 3, "Z direction");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("EmitRateCurve", offsetof(REmitterBlueprint, EmitRateCurve), 3, "EmitRateCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("LifetimeCurve", offsetof(REmitterBlueprint, LifetimeCurve), 3, "LifetimeCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("VelocityCurve", offsetof(REmitterBlueprint, VelocityCurve), 3, "VelocityCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("XAccelCurve", offsetof(REmitterBlueprint, XAccelCurve), 3, "XAccelCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("YAccelCurve", offsetof(REmitterBlueprint, YAccelCurve), 3, "YAccelCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("ZAccelCurve", offsetof(REmitterBlueprint, ZAccelCurve), 3, "ZAccelCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("ResistanceCurve", offsetof(REmitterBlueprint, ResistanceCurve), 3, "drag coefficient (actually, the drag coefficient divied by the mass)");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("StartSizeCurve", offsetof(REmitterBlueprint, StartSizeCurve), 3, "StartSizeCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("EndSizeCurve", offsetof(REmitterBlueprint, EndSizeCurve), 3, "EndSizeCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("InitialRotationCurve", offsetof(REmitterBlueprint, InitialRotationCurve), 3, "InitialRotationCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("RotationRateCurve", offsetof(REmitterBlueprint, RotationRateCurve), 3, "RotationRateCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("FrameRateCurve", offsetof(REmitterBlueprint, FrameRateCurve), 3, "FrameRateCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("TextureSelectionCurve", offsetof(REmitterBlueprint, TextureSelectionCurve), 3, "TextureSelectionCurve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("XPosCurve", offsetof(REmitterBlueprint, XPosCurve), 3, "X Offset Curve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("YPosCurve", offsetof(REmitterBlueprint, YPosCurve), 3, "Y Offset Curve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("ZPosCurve", offsetof(REmitterBlueprint, ZPosCurve), 3, "Z Offset Curve");
    typeInfo->AddField<moho::REmitterBlueprintCurve>("RampSelectionCurve", offsetof(REmitterBlueprint, RampSelectionCurve), 3, "RampSelectionCurve");
    typeInfo->AddField<bool>("LocalVelocity", offsetof(REmitterBlueprint, LocalVelocity), 3, "Is velocity attached to bone");
    typeInfo->AddField<bool>("LocalAcceleration", offsetof(REmitterBlueprint, LocalAcceleration), 3, "Is acceleration attached to bone");
    typeInfo->AddField<bool>("Gravity", offsetof(REmitterBlueprint, Gravity), 3, "Gravity enabled?");
    typeInfo->AddField<bool>("AlignRotation", offsetof(REmitterBlueprint, AlignRotation), 3, "Align the rotation of the particle with direction?");
    typeInfo->AddField<bool>("AlignToBone", offsetof(REmitterBlueprint, AlignToBone), 3, "Align the intitial rotation of the particle to the bone");
    typeInfo->AddField<bool>("EmitIfVisible", offsetof(REmitterBlueprint, EmitIfVisible), 3, "Emit particles ONLY if this is emitter is visible");
    typeInfo->AddField<bool>("ParticleResistance", offsetof(REmitterBlueprint, ParticleResistance), 3, "true to enable the use of drag on a particle");
    typeInfo->AddField<bool>("CatchupEmit", offsetof(REmitterBlueprint, CatchupEmit), 3, "catchup particles for the ticks that we weren't visible");
    typeInfo->AddField<bool>("CreateIfVisible", offsetof(REmitterBlueprint, CreateIfVisible), 3, "when this emitter is initially created only create and emit if visible");
    typeInfo->AddField<bool>("Flat", offsetof(REmitterBlueprint, Flat), 3, "Make the particles flat in world space.");
    typeInfo->AddField<bool>("InterpolateEmission", offsetof(REmitterBlueprint, InterpolateEmission), 3, "Interpolate emission over tick");
    typeInfo->AddField<bool>("SnapToWaterline", offsetof(REmitterBlueprint, SnapToWaterline), 3, "Snap underwater emission to the waterline");
    typeInfo->AddField<bool>("OnlyEmitOnWater", offsetof(REmitterBlueprint, OnlyEmitOnWater), 3, "Only emit if over water");
    typeInfo->AddField<float>("TextureStripcount", offsetof(REmitterBlueprint, TextureStripCount), 3, "Number of strips in the animated texture");
    typeInfo->AddField<float>("SortOrder", offsetof(REmitterBlueprint, SortOrder), 3, "Sort order of particles emitted");
    typeInfo->AddField<float>("Lifetime", offsetof(REmitterBlueprint, Lifetime), 3, "Lifetime of emitter in ticks");
    typeInfo->AddField<float>("LODCutoff", offsetof(REmitterBlueprint, LODCutoff), 3, "Distance emission cuts out.");
    typeInfo->AddField<float>("Repeattime", offsetof(REmitterBlueprint, RepeatTime), 3, "Repeattime of emitter in ticks");
    typeInfo->AddField<float>("TextureFramecount", offsetof(REmitterBlueprint, TextureFrameCount), 3, "number of frames in texture we are using.");
    typeInfo->AddField<std::int32_t>("Blendmode", offsetof(REmitterBlueprint, BlendMode), 3, "Blendmode for this emitter.");

    gpg::RField* const textureNameField = typeInfo->AddField<msvc8::string>("TextureName", offsetof(REmitterBlueprint, TextureName), 3, "Name of texture we are using for this particle");
    textureNameField->mName = "Texture";

    gpg::RField* const rampTextureNameField = typeInfo->AddField<msvc8::string>("RampTextureName", offsetof(REmitterBlueprint, RampTextureName), 3, "Name of ramp texture we are using for this particle");
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
