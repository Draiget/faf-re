#include "gpg/core/reflection/ReflectionPrivate.h"

namespace
{
  /**
   * Address: 0x00525DA0 (FUN_00525DA0)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprint` reference and copies its
   * `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintRefIntoOutput(
    moho::RUnitBlueprint* const blueprint,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::RUnitBlueprint>(blueprint);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x00525E30 (FUN_00525E30)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprintWeapon` reference and copies
   * its `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintWeaponRefIntoOutput(
    moho::RUnitBlueprintWeapon* const weaponBlueprint,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::RUnitBlueprintWeapon>(weaponBlueprint);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x00525E60 (FUN_00525E60)
   *
   * What it does:
   * Builds one temporary reflected `float` reference and copies its
   * `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildFloatRefIntoOutput(float* const value, gpg::RRef* const out)
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<float>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x00599A00 (FUN_00599A00)
   *
   * What it does:
   * Builds one temporary reflected `IAiCommandDispatchImpl` reference and
   * copies its `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildIAiCommandDispatchImplRefIntoOutput(
    moho::IAiCommandDispatchImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::IAiCommandDispatchImpl>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DC30 (FUN_0059DC30)
   *
   * What it does:
   * Builds one temporary reflected `IFormationInstance*` pointer-slot
   * reference and copies its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildIFormationInstancePointerRefIntoOutput(
    moho::IFormationInstance** const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::IFormationInstance*>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DD90 (FUN_0059DD90)
   *
   * What it does:
   * Builds one temporary reflected `CAiFormationDBImpl` reference and copies
   * its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCAiFormationDBImplRefIntoOutput(
    moho::CAiFormationDBImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CAiFormationDBImpl>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DDD0 (FUN_0059DDD0)
   *
   * What it does:
   * Builds one temporary reflected `IFormationInstance` reference and copies
   * its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildIFormationInstanceRefIntoOutput(
    moho::IFormationInstance* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_IFormationInstance(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005A1CB0 (FUN_005A1CB0)
   *
   * What it does:
   * Builds one temporary reflected `CAiBuilderImpl` reference and copies its
   * `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCAiBuilderImplRefIntoOutput(
    moho::CAiBuilderImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CAiBuilderImpl>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005A1E60 (FUN_005A1E60)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprint*` pointer-slot reference
   * and copies its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintPointerRefIntoOutput(
    moho::RUnitBlueprint** const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::RUnitBlueprint*>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005B5710 (FUN_005B5710)
   *
   * What it does:
   * Builds one temporary reflected `CPathPoint` reference and copies its
   * `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCPathPointRefIntoOutput(
    moho::CPathPoint* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CPathPoint>(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildNamedPolymorphicRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const char* const unqualifiedTypeName,
    const char* const qualifiedTypeName,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::REF_FindTypeNamed(unqualifiedTypeName);
      if (!declaredRType && qualifiedTypeName) {
        declaredRType = gpg::REF_FindTypeNamed(qualifiedTypeName);
      }
      declaredTypeCache = declaredRType;
    }

    out->mObj = object;
    out->mType = declaredRType;
    if (!object) {
      return out;
    }

    const std::type_info* runtimeTypeInfo = nullptr;
    try {
      runtimeTypeInfo = static_cast<const std::type_info*>(__RTtypeid(static_cast<void*>(object)));
    } catch (...) {
      runtimeTypeInfo = nullptr;
    }

    if (!runtimeTypeInfo) {
      return out;
    }

    if (!cache.initialized) {
      cache.initialized = true;
      for (TypeInfoRTypePair& entry : cache.entries) {
        entry.typeInfo = nullptr;
        entry.rType = nullptr;
      }
    }

    int foundSlot = 0;
    while (foundSlot < 3) {
      const TypeInfoRTypePair& entry = cache.entries[foundSlot];
      if (entry.typeInfo == runtimeTypeInfo || (entry.typeInfo && (*entry.typeInfo == *runtimeTypeInfo))) {
        break;
      }
      ++foundSlot;
    }

    gpg::RType* runtimeRType = nullptr;
    if (foundSlot >= 3) {
      runtimeRType = gpg::LookupRType(*runtimeTypeInfo);
      foundSlot = 2;
    } else {
      runtimeRType = cache.entries[foundSlot].rType;
    }

    for (int slot = foundSlot; slot > 0; --slot) {
      cache.entries[slot] = cache.entries[slot - 1];
    }
    cache.entries[0].typeInfo = runtimeTypeInfo;
    cache.entries[0].rType = runtimeRType;

    if (!runtimeRType) {
      return out;
    }

    if (!declaredRType) {
      declaredTypeCache = runtimeRType;
      out->mType = runtimeRType;
      return out;
    }

    if (runtimeRType == declaredRType) {
      return out;
    }

    int32_t baseOffset = 0;
    if (!runtimeRType->IsDerivedFrom(declaredRType, &baseOffset)) {
      gpg::HandleAssertFailure("isDer", 458, kReflectionHeaderPath);
    }

    out->mType = runtimeRType;
    out->mObj = static_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    return out;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildNamedDeclaredRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const char* const unqualifiedTypeName,
    const char* const qualifiedTypeName,
    gpg::RType*& declaredTypeCache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::REF_FindTypeNamed(unqualifiedTypeName);
      if (!declaredRType && qualifiedTypeName) {
        declaredRType = gpg::REF_FindTypeNamed(qualifiedTypeName);
      }
      declaredTypeCache = declaredRType;
    }

    out->mObj = object;
    out->mType = declaredRType;
    return out;
  }
  gpg::RType* gCFootPlantManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCFootPlantManipulatorRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAnimationManipulatorRRefCache{false, {}};
  gpg::RType* gCStorageManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCStorageManipulatorRRefCache{false, {}};
  gpg::RType* gCThrustManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCThrustManipulatorRRefCache{false, {}};
  gpg::RType* gSAssignedLocInfoRRefType = nullptr;
  gpg::RType* gSPickUpInfoRRefType = nullptr;
  gpg::RType* gCEffectManagerImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCEffectManagerImplRRefCache{false, {}};
  gpg::RType* gArmyLaunchInfoRRefType = nullptr;
  gpg::RType* gUnitWeaponInfoRRefType = nullptr;
  gpg::RType* gSOffsetInfoRRefType = nullptr;
  gpg::RType* gCEfxEmitterRRefType = nullptr;
  thread_local TypeInfoCache3 gCEfxEmitterRRefCache{false, {}};
  gpg::RType* gCEfxTrailEmitterRRefType = nullptr;
  thread_local TypeInfoCache3 gCEfxTrailEmitterRRefCache{false, {}};

/**
 * Address: 0x005B5850 (FUN_005B5850)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiPathSpline*` object pointer into
 * the canonical `gpg::RRef_CAiPathSpline` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiPathSplineRefValueFirst(
  moho::CAiPathSpline* const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::CAiPathSpline>(value);
    return out;
}

/**
 * Address: 0x005B95B0 (FUN_005B95B0)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiPersonality*` object pointer into
 * the canonical `gpg::RRef_CAiPersonality` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiPersonalityRefValueFirst(
  moho::CAiPersonality* const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::CAiPersonality>(value);
    return out;
}

/**
 * Address: 0x005C9290 (FUN_005C9290)
 *
 * What it does:
 * Value-first adapter that forwards one `EReconFlags*` value pointer into the
 * canonical `gpg::RRef_EReconFlags` builder.
 */
[[maybe_unused]] gpg::RRef* BuildEReconFlagsRefValueFirst(
  moho::EReconFlags* const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::EReconFlags>(value);
    return out;
}

/**
 * Address: 0x005C9A10 (FUN_005C9A10)
 *
 * What it does:
 * Value-first adapter that forwards one `SPerArmyReconInfo*` object pointer
 * into the canonical `gpg::RRef_SPerArmyReconInfo` builder.
 */
[[maybe_unused]] gpg::RRef* BuildSPerArmyReconInfoRefValueFirst(
  moho::SPerArmyReconInfo* const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::SPerArmyReconInfo>(value);
    return out;
}

/**
 * Address: 0x005C9A40 (FUN_005C9A40)
 *
 * What it does:
 * Value-first adapter that forwards one `ReconBlip*` slot pointer into the
 * canonical `gpg::RRef_ReconBlip_P` builder.
 */
[[maybe_unused]] gpg::RRef* BuildReconBlipSlotRefValueFirst(
  moho::ReconBlip** const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::ReconBlip*>(value);
    return out;
}

/**
 * Address: 0x005CA170 (FUN_005CA170)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiReconDBImpl*` object pointer into
 * the canonical `gpg::RRef_CAiReconDBImpl` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiReconDBImplRefValueFirst(
  moho::CAiReconDBImpl* const value,
  gpg::RRef* const out
)
{
    *out = gpg::MakeRRef<moho::CAiReconDBImpl>(value);
    return out;
}
}

namespace gpg
{

RRef RRef_ArchiveToken(ArchiveToken* const token)
{
  RRef out{};
  out.mObj = token;

  try {
    out.mType = LookupRType(typeid(ArchiveToken));
  } catch (...) {
    out.mType = nullptr;
  }

  return out;
}

/**
 * Address: 0x00582080 (FUN_00582080, gpg::RRef_int pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_int` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_int(RRef* const out, int* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<int>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00582050 (FUN_00582050, gpg::RRef_bool pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_bool` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_bool(RRef* const out, bool* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<bool>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006424B0 (FUN_006424B0)
 *
 * What it does:
 * Packs one `RRef_VectorBoolReference` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_VectorBoolReference(
  RRef* const out,
  std::vector<bool>::reference* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<std::vector<bool>::reference>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00517030 (FUN_00517030)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_Vector3f` and writes
 * the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildVector3fRefAdapterLane(
  Wm3::Vector3f* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  temp = gpg::MakeRRef<Wm3::Vector3f>(value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x005133B0 (FUN_005133B0)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_string` and writes the
 * resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildStringRefAdapterLane(
  fa::string* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  temp = gpg::MakeRRef<fa::string>(value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x00402D30 (FUN_00402D30, sub_402D30)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_uint` and copies lanes out.
 */
gpg::RRef* AssignUIntRef(RRef* const out, unsigned int* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<unsigned int>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x008E1B70 (FUN_008E1B70)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ulong` and copies lanes
 * into caller-provided output storage.
 */
gpg::RRef* AssignULongRef(RRef* const out, unsigned long* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<unsigned long>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A280 (FUN_0084A280)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EEconResource` and copies
 * lanes out.
 */
gpg::RRef* AssignEEconResourceRefAdapter(RRef* const out, moho::EEconResource* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EEconResource>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A140 (FUN_0084A140, sub_84A140)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESTITargetType` and copies
 * lanes out.
 */
gpg::RRef* AssignESTITargetTypeRef(RRef* const out, moho::ESTITargetType* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::ESTITargetType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00704040 (FUN_00704040, sub_704040)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESquadClass` and copies
 * lanes out.
 */
gpg::RRef* AssignESquadClassRef(RRef* const out, moho::ESquadClass* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::ESquadClass>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0078A9D0 (FUN_0078A9D0, sub_78A9D0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EMauiScrollAxis` and
 * copies lanes out.
 */
gpg::RRef* AssignEMauiScrollAxisRef(RRef* const out, moho::EMauiScrollAxis* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EMauiScrollAxis>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00795DD0 (FUN_00795DD0, sub_795DD0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EMauiEventType` and
 * copies lanes out.
 */
gpg::RRef* AssignEMauiEventTypeRef(RRef* const out, moho::EMauiEventType* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EMauiEventType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00830D40 (FUN_00830D40, sub_830D40)
 *
 * What it does:
 * Primary wrapper that materializes a temporary `RRef_EUnitCommandType` and
 * copies lanes out.
 */
gpg::RRef* AssignEUnitCommandTypeRefPrimary(RRef* const out, moho::EUnitCommandType* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EUnitCommandType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A170 (FUN_0084A170, sub_84A170)
 *
 * What it does:
 * Secondary wrapper that materializes a temporary `RRef_EUnitCommandType` and
 * copies lanes out.
 */
gpg::RRef* AssignEUnitCommandTypeRefSecondary(RRef* const out, moho::EUnitCommandType* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EUnitCommandType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B0C20 (FUN_006B0C20)
 *
 * What it does:
 * Materializes one temporary `RRef_EUnitState` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_EUnitState(RRef* const out, moho::EUnitState* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EUnitState>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x008BEC10 (FUN_008BEC10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EFireState` and copies
 * lanes out.
 */
gpg::RRef* PackRRef_EFireState(RRef* const out, moho::EFireState* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EFireState>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A2B0 (FUN_0084A2B0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ERuleBPUnitToggleCaps` and
 * copies lanes out.
 */
gpg::RRef* AssignERuleBPUnitToggleCapsRefAdapter(
  RRef* const out,
  moho::ERuleBPUnitToggleCaps* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::ERuleBPUnitToggleCaps>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A380 (FUN_0084A380)
 * Address: 0x008CD130 (FUN_008CD130)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESpecialFileType` and
 * copies lanes out.
 */
gpg::RRef* AssignESpecialFileTypeRefAdapter(
  RRef* const out,
  moho::ESpecialFileType* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::ESpecialFileType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0085F840 (FUN_0085F840, sub_85F840)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EGenericIconType` and
 * copies lanes out.
 */
gpg::RRef* AssignEGenericIconTypeRef(RRef* const out, moho::EGenericIconType* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EGenericIconType>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063A2B0 (FUN_0063A2B0, gpg::RRef_CFootPlantManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CFootPlantManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CFootPlantManipulator(RRef* const out, moho::CFootPlantManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CFootPlantManipulator",
    "Moho::CFootPlantManipulator",
    gCFootPlantManipulatorRRefType,
    gCFootPlantManipulatorRRefCache
  );
}

/**
 * Address: 0x0063A230 (FUN_0063A230)
 *
 * What it does:
 * Wrapper lane that materializes one temporary `RRef_CFootPlantManipulator`
 * and copies object/type fields into the destination reference record.
 */
[[maybe_unused]] gpg::RRef* AssignCFootPlantManipulatorRef(
  RRef* const out, moho::CFootPlantManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  RRef_CFootPlantManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00642650 (FUN_00642650, gpg::RRef_CAnimationManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAnimationManipulator` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CAnimationManipulator(RRef* const out, moho::CAnimationManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CAnimationManipulator",
    "Moho::CAnimationManipulator",
    moho::CAnimationManipulator::sType,
    gCAnimationManipulatorRRefCache
  );
}

/**
 * Address: 0x00642370 (FUN_00642370)
 *
 * What it does:
 * Packs one `RRef_CAnimationManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CAnimationManipulator(
  RRef* const out,
  moho::CAnimationManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CAnimationManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00645630 (FUN_00645630)
 *
 * What it does:
 * Packs one `RRef_CRotateManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CRotateManipulator(
  RRef* const out,
  moho::CRotateManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CRotateManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006469D0 (FUN_006469D0)
 *
 * What it does:
 * Packs one `RRef_CSlaveManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CSlaveManipulator(
  RRef* const out,
  moho::CSlaveManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CSlaveManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006488A0 (FUN_006488A0)
 *
 * What it does:
 * Packs one `RRef_CSlideManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CSlideManipulator(
  RRef* const out,
  moho::CSlideManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CSlideManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00649B80 (FUN_00649B80)
 *
 * What it does:
 * Packs one `RRef_CStorageManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CStorageManipulator(
  RRef* const out,
  moho::CStorageManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CStorageManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00649C00 (FUN_00649C00, gpg::RRef_CStorageManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CStorageManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CStorageManipulator(RRef* const out, moho::CStorageManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CStorageManipulator",
    "Moho::CStorageManipulator",
    gCStorageManipulatorRRefType,
    gCStorageManipulatorRRefCache
  );
}

/**
 * Address: 0x0064B470 (FUN_0064B470)
 * Address: 0x00635460 (FUN_00635460)
 * Address: 0x006372A0 (FUN_006372A0)
 *
 * What it does:
 * Packs one `RRef_CThrustManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CThrustManipulator(
  RRef* const out,
  moho::CThrustManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CThrustManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064B530 (FUN_0064B530, gpg::RRef_CThrustManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CThrustManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CThrustManipulator(RRef* const out, moho::CThrustManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CThrustManipulator",
    "Moho::CThrustManipulator",
    gCThrustManipulatorRRefType,
    gCThrustManipulatorRRefCache
  );
}

/**
 * Address: 0x0063CAE0 (FUN_0063CAE0)
 *
 * What it does:
 * Packs one `RRef_CAniActor` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CAniActor(RRef* const out, moho::CAniActor* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAniActor>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063E680 (FUN_0063E680)
 *
 * What it does:
 * Packs one `RRef_IAniManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_IAniManipulator(
  RRef* const out,
  moho::IAniManipulator* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IAniManipulator>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063CF70 (FUN_0063CF70)
 *
 * What it does:
 * Packs one `RRef_SAniManipBinding` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_SAniManipBinding(
  RRef* const out,
  moho::SAniManipBinding* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SAniManipBinding>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063E6B0 (FUN_0063E6B0)
 *
 * What it does:
 * Packs one `RRef_IAniManipulator_P` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_IAniManipulator_P(
  RRef* const out,
  moho::IAniManipulator** const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IAniManipulator*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006DDDC0 (FUN_006DDDC0)
 *
 * What it does:
 * Packs one `RRef_CFireWeaponTask` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CFireWeaponTask(RRef* const out, moho::CFireWeaponTask* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CFireWeaponTask>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF0C0 (FUN_005DF0C0)
 *
 * What it does:
 * Packs one `RRef_CAcquireTargetTask_P` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CAcquireTargetTask_P(
  RRef* const out,
  moho::CAcquireTargetTask** const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAcquireTargetTask*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0066C480 (FUN_0066C480, gpg::RRef_CEffectManagerImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEffectManagerImpl` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEffectManagerImpl(RRef* const out, moho::CEffectManagerImpl* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEffectManagerImpl",
    "Moho::CEffectManagerImpl",
    gCEffectManagerImplRRefType,
    gCEffectManagerImplRRefCache
  );
}

/**
 * Address: 0x0066C2A0 (FUN_0066C2A0, gpg::RRef_CEffectManagerImpl pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEffectManagerImpl` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEffectManagerImpl(RRef* const out, moho::CEffectManagerImpl* const value)
{
  RRef tmp{};
  (void)RRef_CEffectManagerImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0066D0B0 (FUN_0066D0B0, gpg::RRef_IEffect pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IEffect` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_IEffect(RRef* const out, moho::IEffect* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IEffect>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00658750 (FUN_00658750, gpg::RRef_CEfxBeam pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxBeam` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxBeam(RRef* const out, moho::CEfxBeam* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CEfxBeam>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065A7E0 (FUN_0065A7E0, gpg::RRef_CountedPtr_CParticleTexture pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CountedPtr_CParticleTexture` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CountedPtr_CParticleTexture(
  RRef* const out,
  moho::CountedPtr<moho::CParticleTexture>* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CountedPtr<moho::CParticleTexture>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065FA20 (FUN_0065FA20, gpg::RRef_SEfxCurve pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SEfxCurve` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SEfxCurve(RRef* const out, moho::SEfxCurve* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SEfxCurve>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065FF20 (FUN_0065FF20, gpg::RRef_CEfxEmitter)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEfxEmitter` using named declared
 * type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEfxEmitter(RRef* const out, moho::CEfxEmitter* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEfxEmitter",
    "Moho::CEfxEmitter",
    gCEfxEmitterRRefType,
    gCEfxEmitterRRefCache
  );
}

/**
 * Address: 0x0065FB30 (FUN_0065FB30, gpg::RRef_CEfxEmitter pack lane)
 * Address: 0x00608000 (FUN_00608000)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxEmitter` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxEmitter(RRef* const out, moho::CEfxEmitter* const value)
{
  RRef tmp{};
  (void)RRef_CEfxEmitter(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00672560 (FUN_00672560, gpg::RRef_CEfxTrailEmitter)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEfxTrailEmitter` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEfxTrailEmitter(RRef* const out, moho::CEfxTrailEmitter* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEfxTrailEmitter",
    "Moho::CEfxTrailEmitter",
    gCEfxTrailEmitterRRefType,
    gCEfxTrailEmitterRRefCache
  );
}

/**
 * Address: 0x00672510 (FUN_00672510, gpg::RRef_CEfxTrailEmitter pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxTrailEmitter` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxTrailEmitter(RRef* const out, moho::CEfxTrailEmitter* const value)
{
  RRef tmp{};
  (void)RRef_CEfxTrailEmitter(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0066D0E0 (FUN_0066D0E0, gpg::RRef_IEffect_P pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IEffect_P` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_IEffect_P(RRef* const out, moho::IEffect** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IEffect*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00761B70 (FUN_00761B70)
 *
 * What it does:
 * Builds one reflected reference from the `index`-th contiguous
 * `SAudioRequest` lane starting at `(*firstElementSlot)`.
 */
gpg::RRef* RRef_SAudioRequestArraySlot(
  RRef* const out,
  moho::SAudioRequest* const* const firstElementSlot,
  const int index
)
{
  if (out == nullptr) {
    return nullptr;
  }

  moho::SAudioRequest* const firstElement = (firstElementSlot != nullptr) ? *firstElementSlot : nullptr;
  if (firstElement == nullptr) {
    out->mObj = nullptr;
    out->mType = nullptr;
    return out;
  }

  *out = gpg::MakeRRef<moho::SAudioRequest>(firstElement + static_cast<std::ptrdiff_t>(index));
  return out;
}

/**
 * Address: 0x006755A0 (FUN_006755A0, helper lane)
 *
 * What it does:
 * Materializes a temporary `RRef_CollisionBeamEntity` and copies the resulting
 * object/type lanes into the destination reference.
 */
gpg::RRef* AssignCollisionBeamEntityRef(RRef* const out, moho::CollisionBeamEntity* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CollisionBeamEntity>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006FAE00 (FUN_006FAE00)
 *
 * What it does:
 * Packs one temporary `RRef_Prop` and copies `(mObj,mType)` into caller-owned
 * output storage.
 */
gpg::RRef* PackRRef_Prop(RRef* const out, moho::Prop* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Prop>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00553CD0 (FUN_00553CD0)
 *
 * What it does:
 * Materializes one temporary `RRef_EntId` and copies object/type lanes into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_EntId(RRef* const out, std::int32_t* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<std::int32_t>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0067F700 (FUN_0067F700, gpg::RRef_Entity_P pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_Entity_P` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_Entity_P(RRef* const out, moho::Entity** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Entity*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B1320 (FUN_006B1320)
 *
 * What it does:
 * Materializes one temporary `RRef_WeakPtr_Entity` and copies `(mObj,mType)`
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_WeakPtr_Entity(RRef* const out, moho::WeakPtr<moho::Entity>* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::WeakPtr<moho::Entity>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00688D30 (FUN_00688D30, sub_688D30)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EntityDB` and copies lanes
 * out.
 */
gpg::RRef* AssignEntityDBRef(RRef* const out, moho::EntityDB* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EntityDB>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00698D60 (FUN_00698D60, gpg::RRef_SPhysConstants pack lane A)
 *
 * What it does:
 * Builds one temporary `RRef_SPhysConstants` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPhysConstantsA(RRef* const out, moho::SPhysConstants* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SPhysConstants>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0069A0A0 (FUN_0069A0A0, gpg::RRef_SPhysConstants pack lane B)
 *
 * What it does:
 * Secondary pack lane that builds one temporary `RRef_SPhysConstants` and
 * copies its `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPhysConstantsB(RRef* const out, moho::SPhysConstants* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SPhysConstants>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00698850 (FUN_00698850, sub_698850)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_SPhysBody` and copies lanes
 * out.
 */
gpg::RRef* AssignSPhysBodyRef(RRef* const out, moho::SPhysBody* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SPhysBody>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B1040 (FUN_006B1040)
 *
 * What it does:
 * Materializes one temporary `RRef_Unit` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_Unit(RRef* const out, moho::Unit* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Unit>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00541A90 (FUN_00541A90, gpg::RRef_IUnit pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IUnit` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_IUnit(RRef* const out, moho::IUnit* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IUnit>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00571030 (FUN_00571030)
 *
 * What it does:
 * Builds one temporary `RRef_WeakPtr_IUnit` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_WeakPtr_IUnit(RRef* const out, moho::WeakPtr<moho::IUnit>* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::WeakPtr<moho::IUnit>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00559470 (FUN_00559470)
 *
 * What it does:
 * Materializes one temporary `RRef_SSTIEntityAttachInfo` and copies
 * object/type lanes into caller-owned output storage.
 */
gpg::RRef* PackRRef_SSTIEntityAttachInfo(RRef* const out, moho::SSTIEntityAttachInfo* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SSTIEntityAttachInfo>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00768C70 (FUN_00768C70)
 *
 * What it does:
 * Builds one temporary `RRef_PathQueue` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_PathQueue(RRef* const out, moho::PathQueue* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::PathQueue>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0050E270 (FUN_0050E270, gpg::RRef_RBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RBlueprint` and copies its `(mObj,mType)` pair
 * into caller-provided storage.
 */
gpg::RRef* PackRRef_RBlueprint(RRef* const out, moho::RBlueprint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RBlueprint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00557A60 (FUN_00557A60)
 *
 * What it does:
 * Materializes one temporary `RRef_RBlueprint_P` and copies object/type lanes
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_RBlueprintPointer(RRef* const out, moho::RBlueprint** const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RBlueprint*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00537850 (FUN_00537850)
 *
 * What it does:
 * Thin adapter lane that forwards `{out,value}` into `RRef_RRuleGameRules`.
 */
gpg::RRef* AssignRRuleGameRulesRef(RRef* const out, moho::RRuleGameRules* const value)
{
  *out = gpg::MakeRRef<moho::RRuleGameRules>(value);
  return out;
}

/**
 * Address: 0x00533210 (FUN_00533210)
 *
 * What it does:
 * Materializes one temporary `RRef_SRuleFootprintsBlueprint` and copies
 * object/type lanes into `out`.
 */
gpg::RRef* AssignSRuleFootprintsBlueprintRef(RRef* const out, moho::SRuleFootprintsBlueprint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SRuleFootprintsBlueprint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00548950 (FUN_00548950, gpg::RRef_ResourceDeposit pack lane)
 * Address: 0x005FD5D0 (FUN_005FD5D0)
 *
 * What it does:
 * Builds one temporary `RRef_ResourceDeposit` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_ResourceDeposit(RRef* const out, moho::ResourceDeposit* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::ResourceDeposit>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005110D0 (FUN_005110D0, gpg::RRef_REmitterBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_REmitterBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_REmitterBlueprint(RRef* const out, moho::REmitterBlueprint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::REmitterBlueprint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00517060 (FUN_00517060)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_REmitterCurveKey` and
 * writes the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildEmitterCurveKeyRefAdapterLane(
  moho::REmitterCurveKey* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  temp = gpg::MakeRRef<moho::REmitterCurveKey>(value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x005171D0 (FUN_005171D0)
 *
 * What it does:
 * Adapts one register-lane call shape into
 * `gpg::RRef_REmitterBlueprintCurve` and writes the resulting
 * `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildEmitterBlueprintCurveRefAdapterLane(
  moho::REmitterBlueprintCurve* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  temp = gpg::MakeRRef<moho::REmitterBlueprintCurve>(value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x00511170 (FUN_00511170, gpg::RRef_RBeamBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RBeamBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_RBeamBlueprint(RRef* const out, moho::RBeamBlueprint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RBeamBlueprint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00511120 (FUN_00511120, gpg::RRef_RTrailBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RTrailBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_RTrailBlueprint(RRef* const out, moho::RTrailBlueprint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RTrailBlueprint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0051CF60 (FUN_0051CF60)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_RProjectileBlueprint`
 * and writes the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildProjectileBlueprintRefAdapterLane(
  moho::RProjectileBlueprint* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  temp = gpg::MakeRRef<moho::RProjectileBlueprint>(value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x00500480 (FUN_00500480)
 *
 * What it does:
 * Materializes one reflected reference for `CColPrimitive<Wm3::Sphere3f>` and
 * copies the resulting lanes into `out`.
 */
gpg::RRef* AssignCColPrimitiveSphere3fRef(
  RRef* const out,
  moho::CColPrimitive<Wm3::Sphere3f>* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CColPrimitive<Wm3::Sphere3f>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005005C0 (FUN_005005C0)
 *
 * What it does:
 * Materializes one reflected reference for `CColPrimitive<Wm3::Box3f>` and copies
 * the resulting lanes into `out`.
 */
gpg::RRef* AssignCColPrimitiveBox3fRef(
  RRef* const out,
  moho::CColPrimitive<Wm3::Box3f>* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CColPrimitive<Wm3::Box3f>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00536B70 (FUN_00536B70)
 * Address: 0x005578F0 (FUN_005578F0)
 *
 * What it does:
 * Materializes one temporary `RRef_EntityCategory` and copies object/type
 * lanes into `out`.
 */
gpg::RRef* AssignEntityCategoryRef(RRef* const out, moho::EntityCategorySet* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::EntityCategorySet>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00723A10 (FUN_00723A10, sub_723A10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_COGrid` and copies lanes
 * out.
 */
gpg::RRef* AssignCOGridRef(RRef* const out, moho::COGrid* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::COGrid>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x007047B0 (FUN_007047B0)
 *
 * What it does:
 * Packs one temporary `RRef_CArmyImpl` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CArmyImpl(RRef* const out, moho::CArmyImpl* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CArmyImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751790 (FUN_00751790)
 *
 * What it does:
 * Packs one temporary `RRef_SimArmy_P` result into caller-owned output
 * storage by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_SimArmy_P(RRef* const out, moho::SimArmy** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SimArmy*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751E20 (FUN_00751E20)
 *
 * What it does:
 * Packs one temporary `RRef_SimArmy` result into caller-owned output storage
 * by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_SimArmy(RRef* const out, moho::SimArmy* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SimArmy>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

// NOTE: FUN_0074FF10 and FUN_0074FD80 are the RPointerType<moho::SimArmy>
// GetLexical / GetName vtable slots; recovered as methods of that
// specialization (see gpg::RPointerType<moho::SimArmy>::GetLexical / ::GetName
// above). The earlier free-helper transcriptions (BuildSimArmyPointerLexical /
// BuildSimArmyPointerTypeName) were the same two addresses and have been
// re-homed into the specialization (one-address-one-function).

/**
 * Address: 0x005446D0 (FUN_005446D0, gpg::RRef_LaunchInfoNew pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_LaunchInfoNew` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_LaunchInfoNew(RRef* const out, moho::LaunchInfoNew* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::LaunchInfoNew>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00544C80 (FUN_00544C80, gpg::RRef_ArmyLaunchInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::ArmyLaunchInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_ArmyLaunchInfo(RRef* const out, moho::ArmyLaunchInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "ArmyLaunchInfo",
    "Moho::ArmyLaunchInfo",
    gArmyLaunchInfoRRefType
  );
}

/**
 * Address: 0x005444E0 (FUN_005444E0, gpg::RRef_ArmyLaunchInfo pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_ArmyLaunchInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_ArmyLaunchInfo(RRef* const out, moho::ArmyLaunchInfo* const value)
{
  RRef tmp{};
  (void)RRef_ArmyLaunchInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00548BD0 (FUN_00548BD0, gpg::RRef_CSimResources pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CSimResources` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_CSimResources(RRef* const out, moho::CSimResources* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CSimResources>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005818C0 (FUN_005818C0, gpg::RRef_CAiBrain pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CAiBrain` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiBrain(RRef* const out, moho::CAiBrain* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiBrain>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00572930 (FUN_00572930, gpg::RRef_SAssignedLocInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SAssignedLocInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SAssignedLocInfo(RRef* const out, moho::SAssignedLocInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SAssignedLocInfo",
    "Moho::SAssignedLocInfo",
    gSAssignedLocInfoRRefType
  );
}

/**
 * Address: 0x00571090 (FUN_00571090)
 *
 * What it does:
 * Builds one temporary `RRef_SAssignedLocInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAssignedLocInfo(RRef* const out, moho::SAssignedLocInfo* const value)
{
  RRef tmp{};
  (void)RRef_SAssignedLocInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006288A0 (FUN_006288A0, gpg::RRef_SPickUpInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SPickUpInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SPickUpInfo(RRef* const out, moho::SPickUpInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SPickUpInfo",
    "Moho::SPickUpInfo",
    gSPickUpInfoRRefType
  );
}

/**
 * Address: 0x006E3DB0 (FUN_006E3DB0)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommand` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CUnitCommand(RRef* const out, moho::CUnitCommand* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitCommand>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006E3DE0 (FUN_006E3DE0)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommand_P` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CUnitCommand_P(RRef* const out, moho::CUnitCommand** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitCommand*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006EB770 (FUN_006EB770)
 *
 * What it does:
 * Packs one `RRef_WeakPtr_CUnitCommand` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_WeakPtr_CUnitCommand(
  RRef* const out,
  moho::WeakPtr<moho::CUnitCommand>* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::WeakPtr<moho::CUnitCommand>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006F8D30 (FUN_006F8D30)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommandQueue` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitCommandQueue(RRef* const out, moho::CUnitCommandQueue* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitCommandQueue>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF5E0 (FUN_005DF5E0)
 *
 * What it does:
 * Packs one `RRef_UnitWeapon` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeapon(RRef* const out, moho::UnitWeapon* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::UnitWeapon>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0055F020 (FUN_0055F020, gpg::RRef_UnitWeaponInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::UnitWeaponInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_UnitWeaponInfo(RRef* const out, moho::UnitWeaponInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "UnitWeaponInfo",
    "Moho::UnitWeaponInfo",
    gUnitWeaponInfoRRefType
  );
}

/**
 * Address: 0x0055E840 (FUN_0055E840)
 *
 * What it does:
 * Materializes one temporary `RRef_UnitWeaponInfo` and copies object/type
 * lanes into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeaponInfo(RRef* const out, moho::UnitWeaponInfo* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_UnitWeaponInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF090 (FUN_005DF090)
 *
 * What it does:
 * Packs one `RRef_UnitWeapon_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeapon_P(RRef* const out, moho::UnitWeapon** const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::UnitWeapon*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00404180 (FUN_00404180, sub_404180)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_IdPool` and copies lanes out.
 */
gpg::RRef* AssignIdPoolRef(RRef* const out, moho::IdPool* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::IdPool>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00572790 (FUN_00572790, gpg::RRef_SOffsetInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SOffsetInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SOffsetInfo(RRef* const out, moho::SOffsetInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SOffsetInfo",
    "Moho::SOffsetInfo",
    gSOffsetInfoRRefType
  );
}

/**
 * Address: 0x00571060 (FUN_00571060)
 *
 * What it does:
 * Builds one temporary `RRef_SOffsetInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SOffsetInfo(RRef* const out, moho::SOffsetInfo* const value)
{
  RRef tmp{};
  (void)RRef_SOffsetInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00763C20 (FUN_00763C20, sub_763C20)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_HPathCell` and copies
 * lanes out.
 */
gpg::RRef* AssignHPathCellRef(RRef* const out, moho::HPathCell* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::HPathCell>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x007126B0 (FUN_007126B0)
 *
 * What it does:
 * Packs one `RRef_CArmyStats` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CArmyStats(RRef* const out, moho::CArmyStats* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CArmyStats>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00712900 (FUN_00712900)
 *
 * What it does:
 * Packs one `RRef_Stats_CArmyStatItem` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_Stats_CArmyStatItem(
  RRef* const out,
  moho::Stats<moho::CArmyStatItem>* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Stats<moho::CArmyStatItem>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00712AF0 (FUN_00712AF0, sub_712AF0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CArmyStatItem_P` and
 * copies lanes out.
 */
gpg::RRef* AssignCArmyStatItemPointerRef(RRef* const out, moho::CArmyStatItem** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CArmyStatItem*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B3CD0 (FUN_006B3CD0)
 *
 * What it does:
 * Materializes one temporary `RRef_CEconomyEvent_P` and copies `(mObj,mType)`
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEconomyEvent_P(RRef* const out, moho::CEconomyEvent** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CEconomyEvent*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B3CA0 (FUN_006B3CA0, sub_6B3CA0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CEconomyEvent` and copies
 * lanes out.
 */
gpg::RRef* AssignCEconomyEventRef(RRef* const out, moho::CEconomyEvent* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CEconomyEvent>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0077DAF0 (FUN_0077DAF0)
 *
 * What it does:
 * Packs one `RRef_CDecalBuffer` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalBuffer(RRef* const out, moho::CDecalBuffer* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  temporary = gpg::MakeRRef<moho::CDecalBuffer>(value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

/**
 * Address: 0x0077F400 (FUN_0077F400)
 *
 * What it does:
 * Packs one `RRef_CDecalHandle_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalHandle_P(RRef* const out, moho::CDecalHandle** const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  temporary = gpg::MakeRRef<moho::CDecalHandle*>(value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

// FUN_0077EC40 (GetLexical) and FUN_0077EAB0 (GetName) are the corresponding
// vtable slots of RPointerType<moho::CDecalHandle>, recovered as methods of
// that specialization (one-address-one-function). The earlier free-helper
// transcriptions (BuildCDecalHandlePointerLexical / BuildCDecalHandlePointerTypeName)
// were the same two addresses and have been re-homed into the specialization.

/**
 * Address: 0x0077DB30 (FUN_0077DB30)
 *
 * What it does:
 * Packs one `RRef_CDecalHandle` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalHandle(RRef* const out, moho::CDecalHandle* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  temporary = gpg::MakeRRef<moho::CDecalHandle>(value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

// FUN_0077EDF0 is the SubscriptIndex vtable slot of
// RPointerType<moho::CDecalHandle>, recovered as a method of that
// specialization (one-address-one-function). The earlier free-helper
// transcription (RRef_CDecalHandleArraySlot) was the same address and has been
// re-homed into the specialization.

/**
 * Address: 0x005DEB80 (FUN_005DEB80)
 *
 * What it does:
 * Packs one `RRef_CAiAttackerImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiAttackerImpl(RRef* const out, moho::CAiAttackerImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiAttackerImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005EC3B0 (FUN_005EC3B0, gpg::RRef_CAiTransportImpl pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CAiTransportImpl` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiTransportImpl(RRef* const out, moho::CAiTransportImpl* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiTransportImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005D4680 (FUN_005D4680)
 *
 * What it does:
 * Packs one `RRef_CAiSteeringImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiSteeringImpl(RRef* const out, moho::CAiSteeringImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiSteeringImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005D08A0 (FUN_005D08A0)
 *
 * What it does:
 * Packs one `RRef_CAiSiloBuildImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiSiloBuildImpl(RRef* const out, moho::CAiSiloBuildImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiSiloBuildImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005EC420 (FUN_005EC420, gpg::RRef_SAiReservedTransportBone pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SAiReservedTransportBone` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAiReservedTransportBone(RRef* const out, moho::SAiReservedTransportBone* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SAiReservedTransportBone>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005EC450 (FUN_005EC450, gpg::RRef_SAttachPoint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SAttachPoint` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAttachPoint(RRef* const out, moho::SAttachPoint* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SAttachPoint>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00581D60 (FUN_00581D60, gpg::RRef_SPointVector pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SPointVector` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPointVector(RRef* const out, moho::SPointVector* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SPointVector>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751E60 (FUN_00751E60)
 *
 * What it does:
 * Packs one temporary `RRef_Shield` result into caller-owned output storage
 * by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_Shield(RRef* const out, moho::Shield* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Shield>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751F90 (FUN_00751F90)
 *
 * What it does:
 * Packs one temporary `RRef_Shield_P` result into caller-owned output
 * storage by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_Shield_P(RRef* const out, moho::Shield** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Shield*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

// FUN_00750320 (GetLexical) and FUN_00750190 (GetName) are the corresponding
// vtable slots of RPointerType<moho::Shield>, recovered as methods of that
// specialization (one-address-one-function). The earlier free-helper
// transcriptions (BuildShieldPointerLexical / BuildShieldPointerTypeName) were
// the same two addresses and have been re-homed into the specialization.

/**
 * Address: 0x0067FB70 (FUN_0067FB70, sub_67FB70)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_PositionHistory` and
 * copies lanes out.
 */
gpg::RRef* AssignPositionHistoryRef(RRef* const out, moho::PositionHistory* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::PositionHistory>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00712740 (FUN_00712740)
 *
 * What it does:
 * Packs one `RRef_STrigger` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_STrigger(RRef* const out, moho::STrigger* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::STrigger>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00712700 (FUN_00712700)
 *
 * What it does:
 * Packs one `RRef_SCondition` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_SCondition(RRef* const out, moho::SCondition* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SCondition>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064C930 (FUN_0064C930)
 *
 * What it does:
 * Packs one `RRef_RDebugCollision` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugCollision(
  RRef* const out,
  moho::RDebugCollision* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugCollision>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064F800 (FUN_0064F800)
 *
 * What it does:
 * Packs one `RRef_RDebugGrid` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugGrid(
  RRef* const out,
  moho::RDebugGrid* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugGrid>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064F830 (FUN_0064F830)
 *
 * What it does:
 * Packs one `RRef_RDebugRadar` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugRadar(
  RRef* const out,
  moho::RDebugRadar* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugRadar>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00651170 (FUN_00651170, gpg::RRef_RDebugNavPath pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavPath` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavPath(RRef* const out, moho::RDebugNavPath* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugNavPath>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006511A0 (FUN_006511A0, gpg::RRef_RDebugNavWaypoints pack lane)
 * Address: 0x005F4A00 (FUN_005F4A00)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavWaypoints` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavWaypoints(RRef* const out, moho::RDebugNavWaypoints* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugNavWaypoints>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006511D0 (FUN_006511D0, gpg::RRef_RDebugNavSteering pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavSteering` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavSteering(RRef* const out, moho::RDebugNavSteering* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugNavSteering>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00653A50 (FUN_00653A50, gpg::RRef_RDebugWeapons pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugWeapons` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugWeapons(RRef* const out, moho::RDebugWeapons* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::RDebugWeapons>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0076EA10 (FUN_0076EA10, sub_76EA10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntel` and copies lanes
 * out.
 */
gpg::RRef* AssignCIntelRef(RRef* const out, moho::CIntel* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CIntel>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0076FCE0 (FUN_0076FCE0, sub_76FCE0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntelPosHandle` and
 * copies lanes out.
 */
gpg::RRef* AssignCIntelPosHandleRef(RRef* const out, moho::CIntelPosHandle* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CIntelPosHandle>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0076FDC0 (FUN_0076FDC0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntelCounterHandle` and
 * copies `(mObj,mType)` lanes into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* AssignCIntelCounterHandleRef(RRef* const out, moho::CIntelCounterHandle* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CIntelCounterHandle>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006BAC70 (FUN_006BAC70)
 *
 * What it does:
 * Materializes one temporary `RRef_CUnitMotion` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitMotion(RRef* const out, moho::CUnitMotion* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitMotion>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0040F590 (FUN_0040F590, sub_40F590)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CRandomStream` and copies lanes out.
 */
gpg::RRef* AssignCRandomStreamRef(RRef* const out, moho::CRandomStream* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CRandomStream>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0072AC80 (FUN_0072AC80, sub_72AC80)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CPlatoon` and copies lanes
 * out.
 */
gpg::RRef* AssignCPlatoonRef(RRef* const out, moho::CPlatoon* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CPlatoon>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0089B150 (FUN_0089B150)
 *
 * What it does:
 * Materializes one temporary `RRef_SSessionSaveData` and copies `{mObj,mType}`
 * lanes into caller-provided output storage.
 */
[[maybe_unused]] gpg::RRef* AssignSSessionSaveDataRef(RRef* const out, moho::SSessionSaveData* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SSessionSaveData>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00920500 (FUN_00920500, sub_920500)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_Table` and copies lanes
 * out.
 */
gpg::RRef* AssignTableRef(RRef* const out, Table* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<Table>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A360 (FUN_0084A360)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef::CurrentUIState` result and
 * copies lanes out.
 */
gpg::RRef* AssignCurrentUIStateRefAdapter(RRef* const out)
{
  RRef tmp{};
  RRef::CurrentUIState(&tmp);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E4BF0 (FUN_004E4BF0)
 *
 * What it does:
 * Packs one `RRef_CSndVar` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndVar(RRef* const out, moho::CSndVar* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CSndVar>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E4D00 (FUN_004E4D00)
 *
 * What it does:
 * Packs one `RRef_CSndParams` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParams(RRef* const out, moho::CSndParams* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CSndParams>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E54E0 (FUN_004E54E0)
 *
 * What it does:
 * Packs one `RRef_CSndParams_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParamsPointer(RRef* const out, moho::CSndParams** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CSndParams*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E6640 (FUN_004E6640)
 *
 * What it does:
 * Packs one `RRef_CSndParams_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParamsPointerSecondary(RRef* const out, moho::CSndParams** const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CSndParams*>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0054E200 (FUN_0054E200)
 *
 * What it does:
 * Packs one `RRef_CAniPose` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAniPose(RRef* const out, moho::CAniPose* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAniPose>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00553D00 (FUN_00553D00)
 *
 * What it does:
 * Packs one `RRef_SOCellPos` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_SOCellPos(RRef* const out, moho::SOCellPos* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::SOCellPos>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0059DD60 (FUN_0059DD60)
 *
 * What it does:
 * Packs one `RRef_CAiFormationInstance` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiFormationInstance(
  RRef* const out,
  moho::CAiFormationInstance* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiFormationInstance>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005ABB80 (FUN_005ABB80)
 *
 * What it does:
 * Packs one `RRef_CAiPathFinder` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiPathFinder(RRef* const out, moho::CAiPathFinder* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAiPathFinder>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF570 (FUN_005DF570)
 *
 * What it does:
 * Packs one `RRef_LAiAttackerImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_LAiAttackerImpl(RRef* const out, moho::LAiAttackerImpl* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::LAiAttackerImpl>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF5A0 (FUN_005DF5A0)
 *
 * What it does:
 * Packs one `RRef_CAcquireTargetTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAcquireTargetTask(RRef* const out, moho::CAcquireTargetTask* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CAcquireTargetTask>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00605780 (FUN_00605780)
 *
 * What it does:
 * Packs one `RRef_CUnitCaptureTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitCaptureTask(RRef* const out, moho::CUnitCaptureTask* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitCaptureTask>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0060C7A0 (FUN_0060C7A0)
 *
 * What it does:
 * Packs one `RRef_CUnitGetBuiltTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitGetBuiltTask(RRef* const out, moho::CUnitGetBuiltTask* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitGetBuiltTask>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00614B50 (FUN_00614B50)
 *
 * What it does:
 * Packs one `RRef_CUnitGuardTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitGuardTask(RRef* const out, moho::CUnitGuardTask* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitGuardTask>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006282E0 (FUN_006282E0)
 *
 * What it does:
 * Packs one `RRef_CUnitUnloadUnits` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitUnloadUnits(RRef* const out, moho::CUnitUnloadUnits* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::CUnitUnloadUnits>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063E800 (FUN_0063E800)
 *
 * What it does:
 * Packs one `RRef_shared_ptr_CAniPose` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_SharedPtrCAniPose(
  RRef* const out,
  boost::shared_ptr<moho::CAniPose>* const value
)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<boost::shared_ptr<moho::CAniPose>>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0067F600 (FUN_0067F600)
 *
 * What it does:
 * Packs one `RRef_Entity` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_Entity(RRef* const out, moho::Entity* const value)
{
  RRef tmp{};
  tmp = gpg::MakeRRef<moho::Entity>(value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}
}

