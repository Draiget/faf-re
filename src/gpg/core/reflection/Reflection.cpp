#include "gpg/core/reflection/ReflectionPrivate.h"

namespace gpg
{
/**
 * Address: 0x005F1A20 (FUN_005F1A20)
 * Address: 0x005F44A0 (FUN_005F44A0)
 * Address: 0x005FBB50 (FUN_005FBB50)
 * Address: 0x005FBC40 (FUN_005FBC40)
 * Address: 0x005FBD00 (FUN_005FBD00)
 * Address: 0x005FBDC0 (FUN_005FBDC0)
 * Address: 0x005FBE80 (FUN_005FBE80)
 * Address: 0x005FBFC0 (FUN_005FBFC0)
 * Address: 0x00602360 (FUN_00602360)
 * Address: 0x00602420 (FUN_00602420)
 * Address: 0x006024E0 (FUN_006024E0)
 * Address: 0x006025A0 (FUN_006025A0)
 * Address: 0x006052D0 (FUN_006052D0)
 * Address: 0x006076E0 (FUN_006076E0)
 * Address: 0x006077A0 (FUN_006077A0)
 * Address: 0x00607860 (FUN_00607860)
 * Address: 0x0060BA90 (FUN_0060BA90)
 * Address: 0x0060BB50 (FUN_0060BB50)
 * Address: 0x0060BC10 (FUN_0060BC10)
 * Address: 0x00610070 (FUN_00610070)
 * Address: 0x00614850 (FUN_00614850)
 * Address: 0x00617760 (FUN_00617760)
 * Address: 0x0061E4B0 (FUN_0061E4B0)
 * Address: 0x006221C0 (FUN_006221C0)
 * Address: 0x00623B30 (FUN_00623B30)
 * Address: 0x00626F40 (FUN_00626F40)
 * Address: 0x00627000 (FUN_00627000)
 * Address: 0x00632D30 (FUN_00632D30)
 * Address: 0x006350F0 (FUN_006350F0)
 * Address: 0x00638690 (FUN_00638690)
 * Address: 0x0064E270 (FUN_0064E270)
 * Address: 0x0064E2B0 (FUN_0064E2B0)
 * Address: 0x00650B90 (FUN_00650B90)
 * Address: 0x00650BD0 (FUN_00650BD0)
 * Address: 0x00650C10 (FUN_00650C10)
 * Address: 0x00653280 (FUN_00653280)
 * Address: 0x00657B30 (FUN_00657B30)
 * Address: 0x0065F100 (FUN_0065F100)
 * Address: 0x00699E80 (FUN_00699E80)
 * Address: 0x006DB800 (FUN_006DB800)
 * Address: 0x0076E7C0 (FUN_0076E7C0)
 * Address: 0x00897450 (FUN_00897450)
 *
 * What it does:
 * Writes one `gpg::RType` lifecycle callback lane set (`newRef`, `ctorRef`,
 * `delete`, `destruct`) into one destination type-info object.
 */
[[nodiscard]] RType* BindRTypeLifecycleCallbacks(
  RType* const typeInfo,
  const RType::new_ref_func_t newRefFunc,
  const RType::ctor_ref_func_t ctorRefFunc,
  const RType::delete_func_t deleteFunc,
  const RType::dtr_func_t dtrFunc
) noexcept
{
  if (typeInfo == nullptr) {
    return nullptr;
  }

  typeInfo->newRefFunc_ = newRefFunc;
  typeInfo->ctorRefFunc_ = ctorRefFunc;
  typeInfo->deleteFunc_ = deleteFunc;
  typeInfo->dtrFunc_ = dtrFunc;
  return typeInfo;
}
}

namespace
{

  gpg::RType* gSPhysConstantsRRefType = nullptr;
  gpg::RType* gCPathPointRRefType = nullptr;

[[nodiscard]] RType* ResolveTypeByNameFallbacks(
  RType*& cachedType,
  const char* const primaryName,
  const char* const fallbackName = nullptr
)
{
  if (!cachedType && primaryName) {
    cachedType = gpg::REF_FindTypeNamed(primaryName);
  }
  if (!cachedType && fallbackName) {
    cachedType = gpg::REF_FindTypeNamed(fallbackName);
  }
  return cachedType;
}

/**
 * Address: 0x00554FE0 (FUN_00554FE0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `REntityBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastREntityBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedType, "REntityBlueprint", "Moho::REntityBlueprint");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00557B90 (FUN_00557B90)
 *
 * What it does:
 * Upcasts one reflected reference lane to `EntityCategorySet` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastEntityCategorySetRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "BVSet<RBlueprint const *,EntityCategoryHelper>",
    "Moho::BVSet<RBlueprint const *,EntityCategoryHelper>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055AD10 (FUN_0055AD10)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RMeshBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRMeshBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::RMeshBlueprint::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::RMeshBlueprint));
    moho::RMeshBlueprint::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055AD60 (FUN_0055AD60)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CSndParams` using the secondary
 * runtime type cache lane.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCSndParamsRefObjectVariantB(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::CSndParams::sType2;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::CSndParams));
    moho::CSndParams::sType2 = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055FD20 (FUN_0055FD20)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RUnitBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRUnitBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::RUnitBlueprint::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::RUnitBlueprint));
    moho::RUnitBlueprint::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00572C50 (FUN_00572C50)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EFormationdStatus>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEFormationdStatusRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EFormationdStatus>",
    "Moho::Listener<EFormationdStatus>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00585650 (FUN_00585650)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Sim`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastSimRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedType, "Sim", "Moho::Sim");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005ACE40 (FUN_005ACE40)
 *
 * What it does:
 * Upcasts one reflected reference lane to `COGrid`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCOGridRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::COGrid::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::COGrid));
    moho::COGrid::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005CB6D0 (FUN_005CB6D0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `ReconBlip`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastReconBlipRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::ReconBlip::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::ReconBlip));
    moho::ReconBlip::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005E06E0 (FUN_005E06E0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CAiAttackerImpl`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCAiAttackerImplRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::CAiAttackerImpl));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x005E0A50 (FUN_005E0A50)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EAiAttackerEvent>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEAiAttackerEventRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EAiAttackerEvent>",
    "Moho::Listener<EAiAttackerEvent>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005EE170 (FUN_005EE170)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EAiTransportEvent>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEAiTransportEventRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EAiTransportEvent>",
    "Moho::Listener<EAiTransportEvent>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0060DA80 (FUN_0060DA80)
 *
 * What it does:
 * Upcasts one reflected reference lane to `EAiResult`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastEAiResultRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::EAiResult));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x00634270 (FUN_00634270)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RUnitBlueprintWeapon`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRUnitBlueprintWeaponRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x006342C0 (FUN_006342C0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RProjectileBlueprint` using the
 * secondary runtime-type lane.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRProjectileBlueprintRefObjectVariantB(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
  }
  if (!cachedType) {
    cachedType = gpg::REF_FindTypeNamed("RProjectileBlueprint");
  }
  if (!cachedType) {
    cachedType = gpg::REF_FindTypeNamed("Moho::RProjectileBlueprint");
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x006354E0 (FUN_006354E0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CBoneEntityManipulator`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCBoneEntityManipulatorRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "CBoneEntityManipulator",
    "Moho::CBoneEntityManipulator"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00637320 (FUN_00637320)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CBuilderArmManipulator`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCBuilderArmManipulatorRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "CBuilderArmManipulator",
    "Moho::CBuilderArmManipulator"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00698D20 (FUN_00698D20)
 *
 * What it does:
 * Upcasts one reflected reference lane to `SPhysConstants` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastSPhysConstantsRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  if (!gSPhysConstantsRRefType) {
    gSPhysConstantsRRefType = gpg::LookupRType(typeid(moho::SPhysConstants));
  }
  if (!gSPhysConstantsRRefType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, gSPhysConstantsRRefType);
  return upcast.mObj;
}

/**
 * Address: 0x006A00B0 (FUN_006A00B0)
 *
 * What it does:
 * Upcasts one reflected reference lane to
 * `ManyToOneListener<EProjectileImpactEvent>` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastManyToOneProjectileImpactListenerRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  gpg::RType* targetType = moho::ManyToOneListener<moho::EProjectileImpactEvent>::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::ManyToOneListener<moho::EProjectileImpactEvent>));
    moho::ManyToOneListener<moho::EProjectileImpactEvent>::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x006A4650 (FUN_006A4650)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Projectile` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastProjectileRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedProjectileType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedProjectileType, "Projectile", "Moho::Projectile");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x006BC340 (FUN_006BC340)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CPathPoint` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCPathPointRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  if (!gCPathPointRRefType) {
    gCPathPointRRefType = gpg::LookupRType(typeid(moho::CPathPoint));
  }
  if (!gCPathPointRRefType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, gCPathPointRRefType);
  return upcast.mObj;
}

/**
 * Address: 0x004C8AA0 (FUN_004C8AA0, sub_4C8AA0)
 *
 * What it does:
 * Binds new/construct callback lanes for `CScriptObject*` pointer reflection.
 */
[[maybe_unused]] gpg::RPointerTypeBase* BindCScriptObjectPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCScriptObjectPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCScriptObjectPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x004C8AB0 (FUN_004C8AB0, sub_4C8AB0)
 *
 * What it does:
 * Binds copy/move callback lanes for `CScriptObject*` pointer reflection.
 */
[[maybe_unused]] gpg::RPointerTypeBase* BindCScriptObjectPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCScriptObjectPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCScriptObjectPointerSlotRef;
    return typeInfo;
}

  void AddRect2IntField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, gpg::RTypeOf<int>(), offset));
  }

  void AddRect2FloatField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, gpg::RTypeOf<float>(), offset));
  }

  gpg::RPointerType<moho::CTaskThread> gCTaskThreadPointerType;
  gpg::RPointerType<moho::CLuaConOutputHandler> gCLuaConOutputHandlerPointerType;
  /**
   * Address: 0x004C86E0 (FUN_004C86E0, ??0?$RPointerType@VCScriptObject@moho@@@gpg@@QAE@XZ)
   * Demangled: gpg::RPointerType_CScriptObject::RPointerType_CScriptObject
   *
   * What it does:
   * Global storage slot for the reflected pointer-type descriptor
   * `gpg::RPointerType<moho::CScriptObject>`. The binary's one-shot
   * ctor at this address runs the base `gpg::RType` ctor and then
   * calls `gpg::PreRegisterRType(typeid(moho::CScriptObject*), this)`;
   * the recovered code factors the preregistration out into the
   * `PointerTypeRegistration` struct below so all pointer-type
   * descriptors are wired in one pass, preserving the same observable
   * side effect (registration is live before first reflection query).
   */
  gpg::RPointerType<moho::CScriptObject> gCScriptObjectPointerType;

  /**
   * Address: 0x01106AD8 (global storage for gpg::RVectorType<moho::SimArmy*>)
   *
   * What it does:
   * Startup-owned reflection descriptor for `std::vector<moho::SimArmy*>`.
   * The binary's registrar at 0x007522B0 runs the base `gpg::RType` ctor,
   * installs both vtables, and preregisters this global under
   * `typeid(std::vector<moho::SimArmy*>)`.
   */
  gpg::RVectorType<moho::SimArmy*> gSimArmyVectorType;

  struct Rect2ReflectionRegistration
  {
    Rect2ReflectionRegistration()
    {
      register_Rect2iTypeInfo();
      register_Rect2fTypeInfo();
    }
  };

Rect2ReflectionRegistration gRect2ReflectionRegistration;

struct PointerTypeRegistration
{
    PointerTypeRegistration()
    {
        (void)gpg::preregister_CAcquireTargetTaskPointerTypeStartup();
        (void)gpg::preregister_SimArmyPointerTypeStartup();
        (void)gpg::preregister_ShieldPointerTypeStartup();
        (void)gpg::preregister_CDecalHandlePointerTypeStartup();
        (void)gpg::preregister_SimArmyVectorTypeStartup();
        gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), &gCLuaConOutputHandlerPointerType);
        gpg::PreRegisterRType(typeid(moho::CScriptObject*), &gCScriptObjectPointerType);
    }
};

PointerTypeRegistration gPointerTypeRegistration;
}

namespace gpg
{
  /**
   * What it does:
   * Reads `x0`, `z0`, `x1`, `z1`. Inlined into
   * `gpg::SerSaveLoadHelper<gpg::Rect2i>::Deserialize` 0x00905CC0.
   */
  template <>
  void Rect2<int>::MemberDeserialize(ReadArchive* const archive)
  {
    archive->ReadInt(&x0);
    archive->ReadInt(&z0);
    archive->ReadInt(&x1);
    archive->ReadInt(&z1);
  }

  /**
   * What it does:
   * Writes `x0`, `z0`, `x1`, `z1`. Inlined into
   * `gpg::SerSaveLoadHelper<gpg::Rect2i>::Serialize` 0x00905D00.
   */
  template <>
  void Rect2<int>::MemberSerialize(WriteArchive* const archive) const
  {
    archive->WriteInt(x0);
    archive->WriteInt(z0);
    archive->WriteInt(x1);
    archive->WriteInt(z1);
  }

  /**
   * What it does:
   * Reads `x0`, `x1`, `z0`, `z1` (+0x00, +0x08, +0x04, +0x0C): both edges on
   * one axis, then the other, unlike `Rect2<int>`. Inlined into
   * `gpg::SerSaveLoadHelper<gpg::Rect2f>::Deserialize` 0x00905D40.
   */
  template <>
  void Rect2<float>::MemberDeserialize(ReadArchive* const archive)
  {
    archive->ReadFloat(&x0);
    archive->ReadFloat(&x1);
    archive->ReadFloat(&z0);
    archive->ReadFloat(&z1);
  }

  /**
   * What it does:
   * Writes `x0`, `x1`, `z0`, `z1`. Inlined into
   * `gpg::SerSaveLoadHelper<gpg::Rect2f>::Serialize` 0x00905D80.
   */
  template <>
  void Rect2<float>::MemberSerialize(WriteArchive* const archive) const
  {
    archive->WriteFloat(x0);
    archive->WriteFloat(x1);
    archive->WriteFloat(z0);
    archive->WriteFloat(z1);
  }
}


// Engine addition (dedicated-server plan WPL.4): `moho::sUIState` is defined
// here, in the file whose gpg::RRef::CurrentUIState the simulation reads it
// through, rather than in moho/ui/UiRuntimeTypes.cpp (user interface), so the
// simulation's objects link without the user interface. Constant-initialised;
// the user interface writes it as before.
moho::EUIState moho::sUIState = moho::UIS_none;
namespace gpg
{

/**
 * Address: 0x007522B0 (FUN_007522B0, register/preregister of RVectorType<SimArmy*>)
 *
 * What it does:
 * Preregisters the startup-owned `std::vector<moho::SimArmy*>` reflection
 * descriptor and returns it. In the binary this address also runs the base
 * `gpg::RType` ctor and installs both vtables; those side effects are produced
 * here by the `gSimArmyVectorType` global's construction (base `RType` ctor +
 * the specialization's vtable install), so this function reproduces the
 * remaining observable effect — registration before first reflection query.
 * Called from the reflection registration aggregator (binary `sub_BDBE20`),
 * modeled at source level by the `PointerTypeRegistration` static-init block.
 */
gpg::RType* preregister_SimArmyVectorTypeStartup()
{
  gpg::PreRegisterRType(typeid(fa::vector<moho::SimArmy*>), &gSimArmyVectorType);
  return &gSimArmyVectorType;
}

/**
 * Address: 0x008DA730 (FUN_008DA730, func_RTypeTreeSetToFind)
 *
 * What it does:
 * Resolves one preregistered RTTI-map node for `lookupTypeInfo` and returns
 * end-iterator when the lower-bound candidate is not an exact/equivalent key.
 */
[[nodiscard]] static TypeInfoMap::iterator FindRTypePreregisteredNode(
  TypeInfoMap& preregistered,
  const std::type_info* const lookupTypeInfo
)
{
  const TypeInfoMap::iterator found = preregistered.lower_bound(lookupTypeInfo);
  if (found == preregistered.end()) {
    return found;
  }

  const std::type_info* const candidateTypeInfo = found->first;
  if (lookupTypeInfo != nullptr) {
    if (candidateTypeInfo == nullptr || !lookupTypeInfo->before(*candidateTypeInfo)) {
      return found;
    }
  } else if (candidateTypeInfo == nullptr) {
    return found;
  }

  return preregistered.end();
}

RType* LookupRType(const std::type_info& typeInfo)
{
  TypeInfoMap& preregistered = GetRTypePreregisteredMap();
  const TypeInfoMap::iterator it = FindRTypePreregisteredNode(preregistered, &typeInfo);
  if (it == preregistered.end()) {
    const fa::string msg =
      STR_Printf("Attempting to lookup the RType for %s before it is registered.", typeInfo.name());
    throw std::runtime_error(msg.c_str());
  }

  RType* type = it->second;
  if (!type->finished_) {
    type->finished_ = true;
    type->Init();
    type->RegisterType();
    type->initFinished_ = true;
  }

  return type;
}

/**
 * Address: 0x008DC9F0 (FUN_008DC9F0,
 *   std::map<const std::type_info*, RType*, TypeInfoLess>::insert)
 *
 * IDA signature:
 * struct_SearchRes *__thiscall sub_8DC9F0(std::map_type_info *this@<ecx>,
 *   struct_SearchRes *ret@<eax>, std::pair_type_info_RType *entry);
 *
 * What it does:
 * Out-of-line emission of the preregistered RTTI map's `insert(value_type)`.
 * Performs the `TypeInfoLess` lower-bound red-black descent (keyed by
 * `std::type_info::before`), inserts a fresh node when the key is absent, and
 * returns `{iterator, inserted?}`. Sibling of `FindRTypePreregisteredNode`
 * (the `lower_bound` "find" emission); recovered through the same typed
 * `std::map` API so no red-black node offsets leak into behaviour code.
 */
static std::pair<TypeInfoMap::iterator, bool> InsertRTypePreregisteredNode(
  TypeInfoMap& preregistered,
  const TypeInfoMap::value_type& entry
)
{
  return preregistered.insert(entry);
}

/**
 * Address: 0x008DB5B0 (FUN_008DB5B0, std::_Tree<...>::_Insert)
 * Address: 0x008DA0D0 (FUN_008DA0D0, std::_Tree<...>::_Buynode)
 *
 * What they do:
 * The preregistered-map insert two members above compiles to these two
 * out-of-line Dinkumware `std::_Tree` bodies for this specific
 * `TypeInfoMap` instantiation. `_Insert` (0x008DB5B0) performs the
 * `TypeInfoLess` red-black descent (mirroring the `lower_bound` find
 * member above) and rebalance; it directly calls `_Buynode` (0x008DA0D0,
 * confirmed via its own `.c`: `sub_8DA0D0(this->_Parent, a4, this->
 * _Parent, a5, 0)`) to allocate and placement-construct the fresh
 * 0x18-byte node -- `operator new(0x18)`, then `_Left`/`_Right`/`_Parent`
 * pointers, the `pair<const std::type_info*, RType*>` value, and the
 * `_Color`/`_Isnil` byte pair.
 *
 * Both are generic Dinkumware `std::_Tree` internals for this map's real
 * `std::map` instantiation (this map deliberately uses `std::map`, not
 * `fa::map` -- there is no project-owned ABI-compat template to cite
 * these against; `RbTree.h`'s `fa::rb_tree<V>` models the 2007 MSVC8
 * binary layout specifically, which this map does not use). Recovering
 * `_Insert`/`_Buynode` as hand-rolled free functions would be a pure
 * STL-internal reimplementation with zero behavioral difference from the
 * real `std::map::insert` already used by the insert member above -- the
 * same "recover through the real container API, not raw node offsets"
 * choice already made for this map's find/insert members, and the same
 * modernization approach used elsewhere in this file for math primitives
 * (real `std::atan2`/`sqrt` instead of replicating x87 internals).
 *
 * Address: 0x008DD520 (FUN_008DD520, std::map<...>::insert(hint, value))
 * Address: 0x008DCE80 (FUN_008DCE80, std::_Tree<...> full-descent insert
 *   fallback)
 *
 * Same `TypeInfoMap` instantiation, reached from a *different* real
 * `std::map` entry point: `std::map_type_info::operator[]`
 * (0x008DF330, itself reached from `GetRTypeMap()[name] = this` at
 * `RType::RegisterType`, Reflection.cpp:13762 below) calls the *hint*-based
 * `insert(_Iterator, const value_type&)` overload (0x008DD520) rather
 * than the plain `insert(value_type)` used by `InsertRTypePreregisteredNode`
 * above. `operator[]`'s hint-insert tries a handful of fast-path
 * neighbor checks around the hint position (`func_StringGreater`,
 * 0x008D8590, compares two nodes' `typeinfo->name()` strings -- the
 * `TypeInfoLess`-equivalent ordering degraded to a raw `strcmp` once
 * inlined into the RB-tree body) and falls back to 0x008DCE80 -- a full
 * top-down descent from `_Myhead->_Parent` (the tree root) comparing
 * against each node's `_Myval.typeinfo` via `strcmp` -- when none of the
 * hint fast-paths apply. Both then call the same `_Insert`
 * (0x008DB5B0, cited above) to splice in the new node. Confirmed by
 * reading both `.c` files: 0x008DD520's `LABEL_22` path calls
 * `sub_8DCE80(this, ..., v7)` directly, and 0x008DCE80's body performs
 * the described descent then calls `Tree::_Insert`. Same generic
 * Dinkumware `std::_Tree` internals, same real (not `fa::`) `std::map`
 * instantiation, same reasoning as `_Insert`/`_Buynode` above --
 * `external_dependency`, no project-owned template to cite them against.
 */

/**
 * Address: 0x008DF850 (FUN_008DF850, gpg::PreRegisterRType)
 *
 * What it does:
 * Adds `{type_info*, RType*}` to the preregistration map used by lazy
 * reflection type finalization, via the out-of-line map-insert emission
 * `InsertRTypePreregisteredNode` (FUN_008DC9F0).
 */
void PreRegisterRType(const std::type_info& typeInfo, RType* type)
{
  InsertRTypePreregisteredNode(GetRTypePreregisteredMap(), TypeInfoMap::value_type(&typeInfo, type));
}

/**
 * Address: 0x008E0810 (FUN_008E0810, gpg::REF_RegisterAllTypes)
 *
 * What it does:
 * Iterates the preregistered RTTI map, forces each type through lazy
 * registration, aggregates initialization errors, and throws one runtime
 * error containing concatenated messages when any registration fails.
 */
void REF_RegisterAllTypes()
{
  // Address: 0x008D49F0 (FUN_008D49F0, std::basic_stringstream<char>::~basic_stringstream)
  // The `std::basic_stringstream<char>` destructor used to tear down `errs`
  // below compiles to the shared CRT body at `0x008D49F0` (FUN_008D49F0):
  // it reseats the ios/iostream/ostream/istream vtable lanes back to their
  // base-class vtables, then destroys the embedded `std::stringbuf` member
  // via `std::stringbuf::~stringbuf` (FUN_0047AC80). Binary-only wiring.
  std::stringstream errs;

  for (TypeInfoMap::const_iterator it = GetRTypePreregisteredMap().begin(); it != GetRTypePreregisteredMap().end();
       ++it) {
    try {
      (void)LookupRType(*it->first);
    } catch (const std::exception& ex) {
      errs << ex.what() << std::endl;
    }
  }

  const std::string aggregated = errs.str();
  if (!aggregated.empty()) {
    // Address: 0x008D4A80 (FUN_008D4A80, std::runtime_error::runtime_error(const std::string&))
    // The `std::runtime_error(const std::string&)` constructor the compiler
    // inlines here is at `0x008D4A80` (FUN_008D4A80): it stores the message
    // into the exception's `std::string` member via the runtime string-copy
    // helper at `0x0047B610` (FUN_0047B610). Binary-only wiring.
    throw std::runtime_error(aggregated);
  }
}

/**
 * Address: 0x008DD940 (FUN_008DD940, gpg::REF_GetTypeIndexed)
 *
 * What it does:
 * Returns the reflected type descriptor at one global type-vector index.
 */
const RType* REF_GetTypeIndexed(const int index)
{
  return GetRTypeVec()[index];
}

/**
 * Address: 0x008DF950 (FUN_008DF950, gpg::REF_GetTypeCount)
 *
 * What it does:
 * Returns the number of reflected types currently present in the global
 * registration map.
 */
std::size_t REF_GetTypeCount()
{
  return GetRTypeMap().size();
}

/**
 * Address: 0x008DF910 (FUN_008DF910, gpg::REF_FindTypeNamed `_0` overload)
 *
 * What it does:
 * Looks up one reflected type by exact name and returns null when the input
 * name is null or missing from the global RTTI map.
 */
RType* REF_FindTypeNamed(const char* const name)
{
  if (!name) {
    return nullptr;
  }

  const TypeMap::const_iterator it = GetRTypeMap().find(name);
  if (it == GetRTypeMap().end()) {
    return nullptr;
  }

  return it->second;
}

/**
 * Address: 0x008D9590 (FUN_008D9590, gpg::REF_UpcastPtr)
 *
 * What it does:
 * Recursively traverses reflected base lanes to find one compatible base pointer
 * view and returns `{nullptr, targetType}` for null-object upcast lanes.
 */
RRef REF_UpcastPtr(const RRef& source, const RType* const targetType)
{
  if (source.mType == targetType) {
    return source;
  }

  if (!source.mObj) {
    return RRef{nullptr, const_cast<RType*>(targetType)};
  }

  if (!source.mType) {
    return {};
  }

  const RField* base = source.mType->bases_.begin();
  if (!base) {
    return {};
  }

  const RField* const baseEnd = source.mType->bases_.end();
  for (; base != baseEnd; ++base) {
    RRef baseRef{};
    baseRef.mObj =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(source.mObj) + static_cast<std::uintptr_t>(base->mOffset));
    baseRef.mType = base->mType;

    const RRef upcast = REF_UpcastPtr(baseRef, targetType);
    if (upcast.mObj) {
      return upcast;
    }
  }

  return {};
}

/**
 * Address: 0x009501D0 (FUN_009501D0, gpg::SerHelperBase::SerHelperBase)
 *
 * IDA signature:
 * gpg::SerHelperBase* __thiscall gpg::SerHelperBase::SerHelperBase(gpg::SerHelperBase* this);
 *
 * What it does:
 * Lazily creates the process-global pending-helper list root (`sNewHelpers`),
 * then appends this freshly self-linked node (via the inherited
 * `moho::TDatListItem` base) to its tail so a later `InitNewHelpers` pass
 * drains and dispatches helpers in construction order. The list root is
 * allocated with raw `operator new` (no constructor call) because it is a
 * bare `TDatList<SerHelperBase, void>` node, not a payload-bearing
 * `SerHelperBase`-derived object - no recursion risk.
 */
gpg::SerHelperBase::SerHelperBase()
{
  if (sNewHelpers == nullptr) {
    sNewHelpers = new DList<SerHelperBase>();
  }

  // 0x00950229: no null test on the list; unlink, then link before the head.
  sNewHelpers->push_back(this);
}

gpg::DList<gpg::SerHelperBase>* gpg::SerHelperBase::sNewHelpers = nullptr;

/**
 * Address: 0x00950D50 (FUN_00950D50, gpg::SerHelperBase::InitNewHelpers)
 *
 * What it does:
 * Drains the pending serializer-helper intrusive list in FIFO order
 * (construction order), dispatching `Init()` on each helper, then releases
 * the list root.
 */
void gpg::SerHelperBase::InitNewHelpers()
{
  DList<SerHelperBase>* const root = sNewHelpers;
  if (root == nullptr) {
    return;
  }

  while (SerHelperBase* const helper = root->pop_front()) {
    helper->Init();
  }

  delete root;
  sNewHelpers = nullptr;
}

/**
 * Address: 0x004C8EC0 (FUN_004C8EC0, sub_4C8EC0)
 *
 * What it does:
 * Builds one temporary `gpg::RRef` for a script object and copies `{mObj,mType}`
 * into caller-provided output storage.
 */
[[maybe_unused]] static gpg::RRef* CopyScriptObjectRefToOutput(moho::CScriptObject* const value, gpg::RRef* const out)
{
  gpg::RRef ref{};
  ref = gpg::MakeRRef<moho::CScriptObject>(value);
  out->mObj = ref.mObj;
  out->mType = ref.mType;
  return out;
}

/**
 * Address: 0x004012B0 (FUN_004012B0)
 *
 * What it does:
 * Returns the raw referenced object pointer lane.
 */
#ifdef GetObject
#undef GetObject
#endif

/**
 * Address: 0x0094F730 (FUN_0094F730, gpg::RRefCompare::operator())
 *
 * What it does:
 * Orders two reflected references lexicographically by reflected type lane
 * and then by object pointer lane.
 */
bool RRefCompare::operator()(const RRef& lhs, const RRef& rhs) const noexcept
{
  if (lhs.mType != rhs.mType) {
    return lhs.mType < rhs.mType;
  }

  return lhs.mObj < rhs.mObj;
}

/**
 * Registers one reflected base on `typeInfo`, skipping when `baseType` is null.
 *
 * Every per-type-info `AddBase_*` member the binary emits reduces to this; the
 * only thing that varies is the base type and the sub-object offset.
 */
void AddBaseIfPresent(RType* const typeInfo, RType* const baseType, const std::int32_t offset)
{
  if (baseType == nullptr) {
    return;
  }

  gpg::AddReflectedBaseType(typeInfo, baseType, offset);
}

/**
 * Address: 0x004A3610 (FUN_004A3610)
 *
 * What it does:
 * Returns the indexed child reference at `ind`.
 */
RRef RRef::operator[](const unsigned int ind) const
{
  const RIndexed* indexed = mType->IsIndexed();
  return indexed->SubscriptIndex(mObj, static_cast<int>(ind));
}

/**
 * Address: 0x004012F0 (FUN_004012F0)
 * Demangled: gpg::RIndexed::SetCount
 *
 * What it does:
 * Base implementation rejects resize/count mutation for non-resizable indexed types.
 */
void RIndexed::SetCount(void*, int) const
{
  throw std::bad_cast{};
}

/**
 * Address: 0x00401320 (FUN_00401320)
 * Demangled: gpg::RIndexed::AssignPointer
 *
 * What it does:
 * Base implementation rejects pointer assignment for non-pointer indexed types.
 */
void RIndexed::AssignPointer(void*, const RRef&) const
{
    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB00 (FUN_0040CB00, gpg::RPointerType_CTaskThread::SubscriptIndex)
 * Address: 0x004214F0 (FUN_004214F0, gpg::RPointerType_CLuaConOutputHandler::SubscriptIndex)
 * Address: 0x0059D800 (FUN_0059D800, gpg::RPointerType_IFormationInstance::SubscriptIndex)
 * Address: 0x005C83C0 (FUN_005C83C0, gpg::RPointerType_ReconBlip::SubscriptIndex)
 * Address: 0x005DE260 (FUN_005DE260, gpg::RPointerType_CAcquireTargetTask::SubscriptIndex)
 * Address: 0x0063DE80 (FUN_0063DE80, gpg::RPointerType_IAniManipulator::SubscriptIndex)
 * Address: 0x0066CD80 (FUN_0066CD80, gpg::RPointerType_IEffect::SubscriptIndex)
 * Address: 0x0067E660 (FUN_0067E660, gpg::RPointerType_Entity::SubscriptIndex)
 * Address: 0x006B2850 (FUN_006B2850, gpg::RPointerType_CEconomyEvent::SubscriptIndex)
 * Address: 0x006E39F0 (FUN_006E39F0, gpg::RPointerType_CUnitCommand::SubscriptIndex)
 * Address: 0x00711910 (FUN_00711910, gpg::RPointerType_CArmyStatItem::SubscriptIndex)
 *
 * What it does:
 * Builds a reflected reference to the `ind`-th pointee in the array the pointer
 * slot addresses.
 *
 * Every cited emission is the same body specialized only in two constants the
 * compiler folded in: the element stride (`sizeof(T)`) and the pointee's
 * `RRef_<T>` factory. This shared recovery expresses both through the pointee
 * descriptor (`size_` / `ctorRefFunc_`), which is what those two constants
 * resolve to at runtime. Verified strides per citation: CTaskThread 0x1C,
 * IFormationInstance 0x10, ReconBlip 0x4D0, CAcquireTargetTask 0x3C,
 * IAniManipulator 0x80, IEffect 0x44, Entity 0x270, CEconomyEvent 0x7C,
 * CUnitCommand 0x178, CArmyStatItem 0xAC. Confirm a new T's body matches this
 * shape before extending the citation list — several sibling specializations
 * (SimArmy, Shield, CDecalHandle, RBlueprint, UnitWeapon, CScriptObject,
 * CSndParams, RUnitBlueprint) instead emit their own override and are recovered
 * separately.
 */
RRef gpg::RPointerTypeBase::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<void**>(obj);
    RType* const pointeeType = GetPointeeType();

    RRef out{};
    out.mType = pointeeType;
    if (!slot || !pointeeType || !*slot) {
        out.mObj = nullptr;
        return out;
    }

    const std::ptrdiff_t byteOffset =
      static_cast<std::ptrdiff_t>(pointeeType->size_) * static_cast<std::ptrdiff_t>(ind);
    auto* const base = static_cast<std::uint8_t*>(*slot);
    out.mObj = static_cast<void*>(base + byteOffset);

    if (pointeeType->ctorRefFunc_) {
        return pointeeType->ctorRefFunc_(out.mObj);
    }

    return out;
}

/**
 * Address: 0x0040CAF0 (FUN_0040CAF0, gpg::RPointerType_CTaskThread::GetCount)
 * Address: 0x004214E0 (FUN_004214E0, gpg::RPointerType_CLuaConOutputHandler::GetCount)
 * Address: 0x0059D7F0 (FUN_0059D7F0, gpg::RPointerType_IFormationInstance::GetCount)
 * Address: 0x005C83B0 (FUN_005C83B0, gpg::RPointerType_ReconBlip::GetCount)
 * Address: 0x005DE250 (FUN_005DE250, gpg::RPointerType_CAcquireTargetTask::GetCount)
 * Address: 0x0063DE70 (FUN_0063DE70, gpg::RPointerType_IAniManipulator::GetCount)
 * Address: 0x0066CD70 (FUN_0066CD70, gpg::RPointerType_IEffect::GetCount)
 * Address: 0x0067E650 (FUN_0067E650, gpg::RPointerType_Entity::GetCount)
 * Address: 0x006B2840 (FUN_006B2840, gpg::RPointerType_CEconomyEvent::GetCount)
 * Address: 0x006E39E0 (FUN_006E39E0, gpg::RPointerType_CUnitCommand::GetCount)
 * Address: 0x00711900 (FUN_00711900, gpg::RPointerType_CArmyStatItem::GetCount)
 *
 * What it does:
 * Returns 1 when the pointer slot holds a non-null pointer, else 0 (a pointer
 * type indexes at most one element).
 *
 * All cited emissions are byte-identical five-instruction bodies
 * (`mov ecx,[esp+4]; xor eax,eax; cmp [ecx],eax; setnz al; retn 4`) — the
 * pointee type never appears, so one shared recovery covers every T that does
 * not emit its own override.
 */
size_t gpg::RPointerTypeBase::GetCount(void* const obj) const
{
    auto* const slot = static_cast<void**>(obj);
    return (slot && *slot) ? 1u : 0u;
}

void gpg::RPointerTypeBase::SetCount(void* const obj, const int count) const
{
    auto* const slot = static_cast<void**>(obj);
    if (!slot) {
        throw std::bad_cast{};
    }

    if (count == 0) {
        *slot = nullptr;
        return;
    }
    if (count == 1) {
        return;
    }

    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB40 (FUN_0040CB40, gpg::RPointerType_CTaskThread::AssignPointer)
 * Address: 0x00421530 (FUN_00421530, gpg::RPointerType_CLuaConOutputHandler::AssignPointer)
 */
void gpg::RPointerTypeBase::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<void**>(obj);
    GPG_ASSERT(slot != nullptr);
    if (!slot) {
        return;
    }

    if (!from.mObj) {
        *slot = nullptr;
        return;
    }

    const RRef upcast = REF_UpcastPtr(from, GetPointeeType());
    if (!upcast.mObj) {
        throw BadRefCast("type error");
    }

    *slot = upcast.mObj;
}

const RIndexed* gpg::RPointerTypeBase::AsIndexedSelf() const noexcept
{
    return this;
}

const RIndexed* gpg::RVectorTypeBase::AsIndexedSelf() const noexcept
{
    return this;
}

/**
 * Address: 0x0074CB70 (FUN_0074CB70, gpg::RVectorType_SimArmy_P::GetName)
 * Address: 0x00C00FE0 (FUN_00C00FE0, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds and caches `"vector<SimArmy*>"` from the element pointer-type name
 * (`moho::SimArmy::GetPointerType()->GetName()` = `"SimArmy*"`).
 */
const char* gpg::RVectorType<moho::SimArmy*>::GetName() const
{
    static const fa::string sName = STR_Printf("vector<%s>", GetPointeeType()->GetName());
    return sName.c_str();
}

/**
 * Address: 0x0074CC10 (FUN_0074CC10, gpg::RVectorType_SimArmy_P::GetLexical)
 *
 * What it does:
 * Renders the reflected vector as `"<base RType lexical>, size=<count>"`,
 * where the base lexical comes from `RType::GetLexical` and the count comes
 * from the RIndexed subobject's `GetCount(ref.mObj)`.
 */
fa::string gpg::RVectorType<moho::SimArmy*>::GetLexical(const RRef& ref) const
{
    const fa::string base = RType::GetLexical(ref);
    const size_t count = GetCount(ref.mObj);
    return STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(count));
}

/**
 * Address: 0x0074CCA0 (FUN_0074CCA0, gpg::RVectorType_SimArmy_P::IsIndexed)
 *
 * What it does:
 * Returns the `RIndexed` subobject (`this ? this+0x64 : nullptr`). A vector is
 * indexed but NOT a pointer, so only slot 6 (IsIndexed) is overridden; slot 7
 * (IsPointer) keeps the RType base (returns nullptr).
 */
const RIndexed* gpg::RVectorType<moho::SimArmy*>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0074CCE0 (FUN_0074CCE0, gpg::RVectorType_SimArmy_P::SubscriptIndex)
 *
 * What it does:
 * Wraps `&vec[ind]` (a `moho::SimArmy**` slot inside the vector storage) as one
 * `gpg::RRef_SimArmy_P` reference.
 */
RRef gpg::RVectorType<moho::SimArmy*>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const vec = static_cast<fa::vector<moho::SimArmy*>*>(obj);
    RRef out{};
    out = gpg::MakeRRef<moho::SimArmy*>(vec->ptr_at(static_cast<std::size_t>(ind)));
    return out;
}

/**
 * Address: 0x0074CCB0 (FUN_0074CCB0, gpg::RVectorType_SimArmy_P::GetCount)
 *
 * What it does:
 * Returns the vector element count (`_Mylast - _Myfirst` divided by the 4-byte
 * pointer stride), or 0 when the storage is unallocated.
 */
size_t gpg::RVectorType<moho::SimArmy*>::GetCount(void* const obj) const
{
    auto* const vec = static_cast<const fa::vector<moho::SimArmy*>*>(obj);
    return vec->size();
}

/**
 * Address: 0x0074CCD0 (FUN_0074CCD0, gpg::RVectorType_SimArmy_P::SetCount)
 *
 * What it does:
 * Resizes the underlying `std::vector<SimArmy*>` storage to `count` (forwards to
 * `fa::vector<SimArmy*>::resize` at 0x0074DC40).
 */
void gpg::RVectorType<moho::SimArmy*>::SetCount(void* const obj, const int count) const
{
    auto* const vec = static_cast<fa::vector<moho::SimArmy*>*>(obj);
    vec->resize(static_cast<std::size_t>(count));
}

/**
 * Address: 0x0074CBF0 (FUN_0074CBF0, gpg::RVectorType_SimArmy_P::Init)
 *
 * What it does:
 * Records the element byte-size (16 = `sizeof(std::vector<SimArmy*>)`),
 * version 1, and installs the element (de)serialize callbacks.
 */
void gpg::RVectorType<moho::SimArmy*>::Init()
{
    size_ = sizeof(fa::vector<moho::SimArmy*>);
    version_ = 1;
    serLoadFunc_ = &gpg::DeserializeSimArmyPtrVector;
    serSaveFunc_ = &gpg::SerializeSimArmyPtrVector;
}

RType* gpg::RVectorType<moho::SimArmy*>::GetPointeeType() const
{
    return moho::SimArmy::GetPointerType();
}

/**
 * Address: 0x0074E240 (FUN_0074E240, gpg::RVectorType<SimArmy*> element deserializer)
 *
 * What it does:
 * Reads the element count, then reads that many tracked `moho::SimArmy*`
 * pointers (each via `ReadArchive::ReadPointer_SimArmy` with an empty owner
 * reference) into a fresh temporary vector and installs it into the
 * destination `std::vector<moho::SimArmy*>`, releasing the destination's old
 * storage. Bound as `RType::serLoadFunc_`; `version`/`ownerRef` are unused by
 * this body (the binary loads a fresh vector, not an owner-anchored slot).
 */
void DeserializeSimArmyPtrVector(ReadArchive* const archive, const std::intptr_t vectorPtr, int /*version*/, RRef* /*ownerRef*/)
{
    auto* const outVector = reinterpret_cast<fa::vector<moho::SimArmy*>*>(vectorPtr);

    unsigned int count = 0;
    archive->ReadUInt(&count);

    fa::vector<moho::SimArmy*> loaded;
    loaded.reserve(count);

    const gpg::RRef emptyOwner{};
    for (unsigned int i = 0; i < count; ++i) {
        moho::SimArmy* element = nullptr;
        archive->ReadPointer(&element, &emptyOwner);
        loaded.push_back(element);
    }

    *outVector = std::move(loaded);
}

/**
 * Address: 0x0074E350 (FUN_0074E350, gpg::RVectorType<SimArmy*> element serializer)
 *
 * What it does:
 * Writes the element count, then writes each `moho::SimArmy*` element as one
 * unowned tracked raw pointer (`RRef_SimArmy` + `WriteRawPointer`). Bound as
 * `RType::serSaveFunc_`; `version`/`ownerRef` are unused by this body.
 */
void SerializeSimArmyPtrVector(WriteArchive* const archive, const std::intptr_t vectorPtr, int /*version*/, RRef* /*ownerRef*/)
{
    const auto* const vector = reinterpret_cast<const fa::vector<moho::SimArmy*>*>(vectorPtr);

    const std::size_t count = vector->size();
    archive->WriteUInt(static_cast<unsigned int>(count));

    for (std::size_t i = 0; i < count; ++i) {
        archive->WritePointer<moho::SimArmy>((*vector)[i], gpg::TrackedPointerState::Unowned, gpg::RRef{});
    }
}


/**
 * Address: 0x006E3670 (FUN_006E3670, RPointerType_CUnitCommand non-deleting cleanup body)
 *
 * What it does:
 * Clears reflected base/field vector lanes for one `RPointerType<CUnitCommand>`
 * instance while preserving outer storage ownership.
 */
[[maybe_unused]] void DestroyCUnitCommandPointerTypeBody(gpg::RPointerType<moho::CUnitCommand>* const typeInfo) noexcept
{
    if (typeInfo == nullptr) {
        return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
}

/**
 * Address: 0x00905FD0 (FUN_00905FD0, gpg::Rect2iTypeInfo::Rect2iTypeInfo)
 *
 * What it does:
 * Constructs the Rect2<int> runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Rect2i)`.
 */
gpg::Rect2iTypeInfo::Rect2iTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(Rect2i), this);
}

/**
 * Address: 0x00906020 (FUN_00906020)
 * Demangled: gpg::Rect2iTypeInfo::GetName
 */
const char* gpg::Rect2iTypeInfo::GetName() const
{
  return "Rect2i";
}

/**
 * Address: 0x00906080 (FUN_00906080, gpg::Rect2fTypeInfo::Rect2fTypeInfo)
 *
 * What it does:
 * Constructs the Rect2<float> runtime type descriptor and preregisters it
 * with reflection registry using `typeid(Rect2f)`.
 */
gpg::Rect2fTypeInfo::Rect2fTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(Rect2f), this);
}

/**
 * Address: 0x009060D0 (FUN_009060D0)
 * Demangled: gpg::Rect2fTypeInfo::GetName
 */
const char* gpg::Rect2fTypeInfo::GetName() const
{
  return "Rect2f";
}

/**
 * Address: 0x00906270 (FUN_00906270)
 * Demangled: gpg::Rect2iTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers int fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2iTypeInfo::Init()
{
  size_ = sizeof(Rect2i);
  gpg::RType::Init();
  AddRect2IntField(this, "x0", offsetof(Rect2i, x0));
  AddRect2IntField(this, "y0", offsetof(Rect2i, z0));
  AddRect2IntField(this, "x1", offsetof(Rect2i, x1));
  AddRect2IntField(this, "y1", offsetof(Rect2i, z1));
  Finish();
}

/**
 * Address: 0x009062D0 (FUN_009062D0)
 * Demangled: gpg::Rect2fTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers float fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2fTypeInfo::Init()
{
  size_ = sizeof(Rect2f);
  gpg::RType::Init();
  AddRect2FloatField(this, "x0", offsetof(Rect2f, x0));
  AddRect2FloatField(this, "y0", offsetof(Rect2f, z0));
  AddRect2FloatField(this, "x1", offsetof(Rect2f, x1));
  AddRect2FloatField(this, "y1", offsetof(Rect2f, z1));
  Finish();
}

/**
 * Address: 0x00596690 (FUN_00596690, deleting-destructor thunk)
 *
 * What it does:
 * Runs one `REnumType` destructor lane and conditionally frees this object
 * storage when the low delete flag bit is set.
 */
[[maybe_unused]] gpg::REnumType* DestroyREnumTypeAndMaybeDelete(
  gpg::REnumType* const object,
  const unsigned char deleteFlag
) noexcept
{
  object->~REnumType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(object));
  }
  return object;
}

/**
 * Address: 0x008DF290 (FUN_008DF290)
 *
 * What it does:
 * Appends one enum option lane into the backing `fa::vector` and returns
 * the inserted slot.
 */
[[nodiscard]] REnumType::ROptionValue* AppendEnumOptionValue(
  fa::vector<REnumType::ROptionValue>& options,
  const REnumType::ROptionValue& value
)
{
  // sub_8DF290: fast in-place fill when capacity remains, else sub_8DCB70 =
  // insert(end(),1,value). insert() contains both paths, so a single by-name
  // call reproduces the binary and pins FUN_008DCB70 as the grow-lane emission.
  static_assert(sizeof(REnumType::ROptionValue) == 8, "REnumType::ROptionValue must be 8 bytes");
  options.insert(options.end(), 1, value);
  return options.empty() ? nullptr : &options.back();
}
}



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_Rect2iTypeInfo_65cf11, register_Rect2iTypeInfo)
GPG_PREREGISTER_INIT(register_Rect2fTypeInfo_65cf11, register_Rect2fTypeInfo)

GPG_PREREGISTER_INIT(preregister_CAcquireTargetTaskPointerTypeStartup_65cf11, gpg::preregister_CAcquireTargetTaskPointerTypeStartup)
GPG_PREREGISTER_INIT(preregister_SimArmyPointerTypeStartup_65cf11, gpg::preregister_SimArmyPointerTypeStartup)
GPG_PREREGISTER_INIT(preregister_ShieldPointerTypeStartup_65cf11, gpg::preregister_ShieldPointerTypeStartup)
GPG_PREREGISTER_INIT(preregister_CDecalHandlePointerTypeStartup_65cf11, gpg::preregister_CDecalHandlePointerTypeStartup)
GPG_PREREGISTER_INIT(preregister_SimArmyVectorTypeStartup_65cf11, gpg::preregister_SimArmyVectorTypeStartup)

namespace gpg
{
  /**
   * `gpg::SerSaveLoadHelper<Rect2i>`, vtable 0x00D44B44.
   *
   * Address: 0x00BE9E10 (FUN_00BE9E10 -- constructs the global and registers its destructor.)
   * Address: 0x00C09730 (FUN_00C09730 -- the global's destructor.)
   * Address: 0x00905E40 (FUN_00905E40 -- `Init`.)
   * Address: 0x00905CC0 (FUN_00905CC0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00905D00 (FUN_00905D00 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct Rect2iSerializer : gpg::SerSaveLoadHelper<Rect2i>
  {};
} // namespace gpg
namespace
{
  // Address: 0x00F8E528 -- process-global `Rect2iSerializer` singleton.
  gpg::Rect2iSerializer gRect2iSerializer;
}

namespace gpg
{
  /**
   * `gpg::SerSaveLoadHelper<Rect2f>`, vtable 0x00D44B3C.
   *
   * Address: 0x00BE9EB0 (FUN_00BE9EB0 -- constructs the global and registers its destructor.)
   * Address: 0x00C09700 (FUN_00C09700 -- the global's destructor.)
   * Address: 0x00905EE0 (FUN_00905EE0 -- `Init`.)
   * Address: 0x00905D40 (FUN_00905D40 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00905D80 (FUN_00905D80 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct Rect2fSerializer : gpg::SerSaveLoadHelper<Rect2f>
  {};
}

namespace
{
  // Address: 0x00F8E440 -- process-global `Rect2fSerializer` singleton.
  gpg::Rect2fSerializer gRect2fSerializer;
}

namespace gpg
{
/**
 * Address: 0x004012C0 (FUN_004012C0)
 * Demangled: gpg::RObject::RObject
 *
 * What it does:
 * Initializes the base vftable lane for reflected objects.
 */
RObject::RObject() noexcept = default;

/**
 * Address: 0x004012D0 (FUN_004012D0)
 * Demangled: gpg::RObject::dtr
 *
 * What it does:
 * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
 */
RObject::~RObject() noexcept = default;

/**
 * Address: 0x0040CBD0 (FUN_0040CBD0)
 * Demangled: sub_40CBD0
 */
gpg::RPointerType<moho::CTaskThread>::~RPointerType() = default;

/**
 * Address: 0x005DE390 (FUN_005DE390)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::dtr
 */
gpg::RPointerType<moho::CAcquireTargetTask>::~RPointerType() = default;

/**
 * Address: 0x00750630 (FUN_00750630)
 * Demangled: gpg::RPointerType_SimArmy::dtr
 */
gpg::RPointerType<moho::SimArmy>::~RPointerType() = default;

/**
 * Address: 0x00752420 (FUN_00752420, gpg::RVectorType_SimArmy_P::dtr)
 *
 * What it does:
 * Scalar-deleting dtor. The binary frees the two `fa::vector<RField>`
 * storage lanes owned by the RType base (`bases_._Myfirst` @ +0x2C,
 * `fields_._Myfirst` @ +0x3C), restores the RObject vftable, and conditionally
 * deletes `this`. The compiler-generated `~RType()` reproduces this exactly, so
 * the source dtor is defaulted.
 */
gpg::RVectorType<moho::SimArmy*>::~RVectorType() = default;

/**
 * Address: 0x00750690 (FUN_00750690)
 * Demangled: gpg::RPointerType_Shield::dtr
 */
gpg::RPointerType<moho::Shield>::~RPointerType() = default;

/**
 * Address: 0x0077EEC0 (FUN_0077EEC0)
 * Demangled: gpg::RPointerType_CDecalHandle::dtr
 */
gpg::RPointerType<moho::CDecalHandle>::~RPointerType() = default;

/**
 * Address: 0x00557380 (FUN_00557380)
 * Demangled: gpg::RPointerType_RBlueprint::dtr
 */
gpg::RPointerType<moho::RBlueprint>::~RPointerType() = default;

/**
 * Address: 0x005DE330 (FUN_005DE330)
 * Demangled: gpg::RPointerType_UnitWeapon::dtr
 */
gpg::RPointerType<moho::UnitWeapon>::~RPointerType() = default;

/**
 * Address: 0x0063DF50 (FUN_0063DF50)
 * Demangled: gpg::RPointerType_IAniManipulator::dtr
 */
gpg::RPointerType<moho::IAniManipulator>::~RPointerType() = default;

/**
 * Address: 0x0066CE50 (FUN_0066CE50)
 * Demangled: gpg::RPointerType_IEffect::dtr
 */
gpg::RPointerType<moho::IEffect>::~RPointerType() = default;

/**
 * Address: 0x006E3AC0 (FUN_006E3AC0)
 * Demangled: gpg::RPointerType_CUnitCommand::dtr
 */
gpg::RPointerType<moho::CUnitCommand>::~RPointerType() = default;

/**
 * Address: 0x0067E750 (FUN_0067E750)
 * Demangled: gpg::RPointerType_Entity::dtr
 */
gpg::RPointerType<moho::Entity>::~RPointerType() = default;

/**
 * Address: 0x006B2920 (FUN_006B2920)
 * Demangled: gpg::RPointerType_CEconomyEvent::dtr
 */
gpg::RPointerType<moho::CEconomyEvent>::~RPointerType() = default;

/**
 * Address: 0x004215C0 (FUN_004215C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::~RPointerType() = default;

/**
 * Address: 0x004C8A00 (FUN_004C8A00)
 * Demangled: gpg::RPointerType_CScriptObject::dtr
 */
gpg::RPointerType<moho::CScriptObject>::~RPointerType() = default;

/**
 * Address: 0x004E5FD0 (FUN_004E5FD0)
 * Demangled: sub_4E5FD0
 */
gpg::RPointerType<moho::CSndParams>::~RPointerType() = default;

/**
 * Address: 0x0059D8D0 (FUN_0059D8D0)
 * Demangled: gpg::RPointerType_IFormationInstance::dtr
 */
gpg::RPointerType<moho::IFormationInstance>::~RPointerType() = default;

/**
 * Address: 0x005A1900 (FUN_005A1900)
 * Demangled: gpg::RPointerType_RUnitBlueprint::dtr
 */
gpg::RPointerType<moho::RUnitBlueprint>::~RPointerType() = default;

/**
 * Address: 0x005C8550 (FUN_005C8550)
 * Demangled: gpg::RPointerType_ReconBlip::dtr
 */
gpg::RPointerType<moho::ReconBlip>::~RPointerType() = default;

/**
 * Address: 0x00711A30 (FUN_00711A30)
 * Demangled: gpg::RPointerType_CArmyStatItem::dtr
 */
gpg::RPointerType<moho::CArmyStatItem>::~RPointerType() = default;

/**
 * Address: 0x008DD9D0 (FUN_008DD9D0)
 * Address: 0x00506F60 (FUN_00506F60)
 * Address: 0x0050BC60 (FUN_0050BC60)
 * Address: 0x0050BE90 (FUN_0050BE90)
 * Address: 0x00518750 (FUN_00518750)
 * Address: 0x0051C300 (FUN_0051C300)
 * Address: 0x0051D6C0 (FUN_0051D6C0)
 * Address: 0x0051D870 (FUN_0051D870)
 * Address: 0x005218A0 (FUN_005218A0)
 * Address: 0x005229E0 (FUN_005229E0)
 * Address: 0x0053A360 (FUN_0053A360)
 * Address: 0x00541490 (FUN_00541490)
 * Address: 0x00550740 (FUN_00550740)
 * Address: 0x005526C0 (FUN_005526C0)
 * Address: 0x00552950 (FUN_00552950)
 * Address: 0x00557E40 (FUN_00557E40)
 * Address: 0x00558050 (FUN_00558050)
 * Address: 0x00558260 (FUN_00558260)
 * Address: 0x005584B0 (FUN_005584B0)
 * Address: 0x0055B070 (FUN_0055B070)
 * Address: 0x0055C0B0 (FUN_0055C0B0)
 * Address: 0x0055C2A0 (FUN_0055C2A0)
 * Address: 0x0055C4A0 (FUN_0055C4A0)
 * Address: 0x0055C6B0 (FUN_0055C6B0)
 * Address: 0x00563BA0 (FUN_00563BA0)
 * Address: 0x00563DD0 (FUN_00563DD0)
 * Address: 0x00566250 (FUN_00566250)
 * Address: 0x00566640 (FUN_00566640)
 * Address: 0x00571FC0 (FUN_00571FC0)
 * Address: 0x00572020 (FUN_00572020)
 * Address: 0x005777E0 (FUN_005777E0)
 * Address: 0x005A8470 (FUN_005A8470)
 * Address: 0x005A84D0 (FUN_005A84D0)
 * Address: 0x005DFB90 (FUN_005DFB90)
 * Address: 0x005DFBF0 (FUN_005DFBF0)
 * Address: 0x005ECFB0 (FUN_005ECFB0)
 * Address: 0x005ED010 (FUN_005ED010)
 * Address: 0x005F4AF0 (FUN_005F4AF0)
 * Address: 0x005FA1E0 (FUN_005FA1E0)
 * Address: 0x00604200 (FUN_00604200)
 * Address: 0x00607520 (FUN_00607520)
 * Address: 0x00610F90 (FUN_00610F90)
 * Address: 0x00618F20 (FUN_00618F20)
 * Address: 0x0061ABB0 (FUN_0061ABB0)
 * Address: 0x0061EE00 (FUN_0061EE00)
 * Address: 0x006261D0 (FUN_006261D0)
 * Address: 0x0062F6E0 (FUN_0062F6E0)
 * Address: 0x006434C0 (FUN_006434C0)
 * Address: 0x00645E10 (FUN_00645E10)
 * Address: 0x00646EB0 (FUN_00646EB0)
 * Address: 0x00694890 (FUN_00694890)
 * Address: 0x006EBFF0 (FUN_006EBFF0)
 * Address: 0x007668C0 (FUN_007668C0)
 * Address: 0x00766B00 (FUN_00766B00)
 * Address: 0x00786760 (FUN_00786760)
 * Address: 0x0078CB00 (FUN_0078CB00)
 * Address: 0x0078DD70 (FUN_0078DD70)
 * Address: 0x0078EF90 (FUN_0078EF90)
 * Address: 0x00796160 (FUN_00796160)
 * Address: 0x00797230 (FUN_00797230)
 * Address: 0x00797750 (FUN_00797750)
 * Address: 0x007992F0 (FUN_007992F0)
 * Address: 0x007A2B90 (FUN_007A2B90)
 * Address: 0x007B5E10 (FUN_007B5E10)
 * Address: 0x007C0920 (FUN_007C0920)
 * Address: 0x0086A4E0 (FUN_0086A4E0)
 * Address: 0x0087FF90 (FUN_0087FF90)
 * Address: 0x008801B0 (FUN_008801B0)
 * Demangled: gpg::RType::dtr
 *
 * What it does:
 * Frees the RType base's two `fa::vector<RField>` storage lanes
 * (`bases_._Myfirst` @ +0x2C, `fields_._Myfirst` @ +0x3C) and restores the
 * `gpg::RObject` vftable. The listed clone addresses are COMDAT clones of
 * this exact body: each one is the vtable-slot-2 scalar deleting destructor
 * of a distinct `gpg::RType`/`gpg::REnumType`-derived descriptor class
 * (TypeInfo / RBroadcasterRType_* / RListenerRType_* / PathQueue*TypeInfo /
 * SSavedGame*TypeInfo, etc.) that adds no data members of its own, so the
 * compiler emitted a byte-identical destructor body per class for the
 * vtable slot instead of one shared symbol.
 */
RType::~RType() = default;

/**
 * Address: 0x00418120 (FUN_00418120, gpg::REnumType::~REnumType)
 */
gpg::REnumType::~REnumType() = default;
}
