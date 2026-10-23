#include "REffectBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/RResId.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::REffectBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireREffectBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
    }
    return cached;
  }

  /**
   * Address: 0x0050F120 (FUN_0050F120)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `REffectBlueprintTypeInfo`.
   */
  [[maybe_unused]] void cleanup_REffectBlueprintTypeInfoRTypeBase(TypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct REffectBlueprintTypeInfoBootstrap
  {
    REffectBlueprintTypeInfoBootstrap()
    {
      moho::register_REffectBlueprintTypeInfo();
    }
  };

  REffectBlueprintTypeInfoBootstrap gREffectBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050F020 (FUN_0050F020, Moho::REffectBlueprintTypeInfo::REffectBlueprintTypeInfo)
   */
  REffectBlueprintTypeInfo::REffectBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REffectBlueprint), this);
  }

  /**
   * Address: 0x0050F0C0 (FUN_0050F0C0, scalar deleting destructor thunk)
   */
  REffectBlueprintTypeInfo::~REffectBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050F0B0 (FUN_0050F0B0)
   */
  const char* REffectBlueprintTypeInfo::GetName() const
  {
    return "REffectBlueprint";
  }

  /**
 * Address: 0x00510CF0 (FUN_00510CF0, Moho::REffectBlueprintTypeInfo::AddBase_RObject)
 *
 * What it does:
 * Registers `gpg::RObject` as this type's reflected base at offset 0 - single
 * inheritance, so the sub-object starts where the object does.
 */
void REffectBlueprintTypeInfo::AddBase_RObject(gpg::RType* typeInfo)
{
  gpg::RType* const rObjectType = CachedRObjectType();
  gpg::RField baseField(rObjectType->GetName(), rObjectType, 0);
  typeInfo->AddBase(baseField);
}

/**
   * Address: 0x0050F080 (FUN_0050F080)
   *
   * What it does:
   * Sets `REffectBlueprint` size, registers `RObject` base metadata, and
   * publishes base effect-blueprint fields.
   */
  void REffectBlueprintTypeInfo::Init()
  {
    size_ = sizeof(REffectBlueprint);
    AddBase_RObject(this);
    gpg::RType::Init();
    AddFields();
    Finish();
  }

  /**
   * Address: 0x0050F160 (FUN_0050F160, Moho::REffectBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers reflected `REffectBlueprint` field lanes and field metadata text.
   */
  void REffectBlueprintTypeInfo::AddFields()
  {
    AddField<moho::RResId>("BlueprintId", offsetof(REffectBlueprint, BlueprintId), 3, "Blueprint ID");
    AddField<bool>("HighFidelity", offsetof(REffectBlueprint, HighFidelity), 3, "Allowed in high fidelity");
    AddField<bool>("MedFidelity", offsetof(REffectBlueprint, MedFidelity), 3, "Allowed in medium fidelity");
    AddField<bool>("LowFidelity", offsetof(REffectBlueprint, LowFidelity), 3, "Allowed in low fidelity");
  }

  /**
   * Address: 0x00BC8050 (FUN_00BC8050, register_REffectBlueprintTypeInfo)
   */
  void register_REffectBlueprintTypeInfo()
  {
    (void)AcquireREffectBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_REffectBlueprintTypeInfo_ccecba, moho::register_REffectBlueprintTypeInfo)
