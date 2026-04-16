#include "moho/ai/CAiSiloBuildImpl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/UnitWeaponRuntimeView.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  gpg::RType* gUnitType = nullptr;
  gpg::RType* gUnitWeaponType = nullptr;
  gpg::RType* gCEconRequestType = nullptr;
  gpg::RType* gSEconValueType = nullptr;
  gpg::RType* gESiloBuildStageType = nullptr;
  gpg::RType* gESiloTypeListType = nullptr;

  constexpr float kSiloMinimumBuildRate = 0.1f;
  constexpr std::uint64_t kSiloBuildingStateMask = (1ull << static_cast<std::uint32_t>(UNITSTATE_SiloBuildingAmmo));

  /**
   * Address: 0x005CEB20 (FUN_005CEB20, func_ZeroVec3)
   *
   * What it does:
   * Clears one `SSiloBuildInfo` lane (`weapon/ammo/maxStorage`) to all zeros.
   */
  void ZeroSiloBuildInfoWords(SSiloBuildInfo* const info) noexcept
  {
    if (!info) {
      return;
    }

    info->mWeapon = nullptr;
    info->mAmmo = 0;
    info->mMaxStorageCount = 0;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveCAiSiloBuildImplType()
  {
    if (!CAiSiloBuildImpl::sType) {
      CAiSiloBuildImpl::sType = gpg::LookupRType(typeid(CAiSiloBuildImpl));
    }
    return CAiSiloBuildImpl::sType;
  }

  [[nodiscard]] gpg::RType* ResolveSSiloBuildInfoType()
  {
    if (!SSiloBuildInfo::sType) {
      SSiloBuildInfo::sType = gpg::LookupRType(typeid(SSiloBuildInfo));
    }
    return SSiloBuildInfo::sType;
  }

  [[nodiscard]] gpg::RType* ResolveESiloTypeListType()
  {
    return CachedType<std::list<ESiloType>>(gESiloTypeListType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitType()
  {
    return CachedType<Unit>(gUnitType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitWeaponType()
  {
    return CachedType<UnitWeapon>(gUnitWeaponType);
  }

  [[nodiscard]] gpg::RType* ResolveCEconRequestType()
  {
    if (!CEconRequest::sType) {
      CEconRequest::sType = CachedType<CEconRequest>(gCEconRequestType);
    }
    return CEconRequest::sType;
  }

  [[nodiscard]] gpg::RType* ResolveSEconValueType()
  {
    if (!SEconValue::sType) {
      SEconValue::sType = CachedType<SEconValue>(gSEconValueType);
    }
    return SEconValue::sType;
  }

  [[nodiscard]] gpg::RType* ResolveESiloBuildStageType()
  {
    return CachedType<ESiloBuildStage>(gESiloBuildStageType);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<TObject*>(upcast.mObj);
    }

    throw std::runtime_error("CAiSiloBuildImpl pointer type mismatch during archive load");
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& owner
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

  [[nodiscard]] std::size_t ToSiloIndex(const ESiloType type) noexcept
  {
    return static_cast<std::size_t>(static_cast<std::int32_t>(type));
  }

  [[nodiscard]] bool HasQueuedSiloTypes(const SSiloTypeList& list) noexcept
  {
    return list.mHead != nullptr && list.mHead->mNext != list.mHead && list.mSize > 0;
  }

  /**
   * Address: 0x005D01E0 (FUN_005D01E0, silo-list sentinel allocator)
   *
   * What it does:
   * Allocates one `SSiloTypeListNode` head sentinel and self-links its
   * `{next,prev}` lanes for empty-list state.
   */
  [[nodiscard]] SSiloTypeListNode* AllocateSelfLinkedSiloTypeSentinel()
  {
    auto* const node = static_cast<SSiloTypeListNode*>(gpg::core::legacy::AllocateChecked12ByteLane(1u));
    node->mNext = node;
    node->mPrev = node;
    return node;
  }

  [[nodiscard]] ESiloType FrontSiloType(const SSiloTypeList& list) noexcept
  {
    return list.mHead->mNext->mValue;
  }

  [[nodiscard]] SSiloTypeListNode* AllocateSiloTypeNode(const ESiloType value)
  {
    auto* const node = static_cast<SSiloTypeListNode*>(::operator new(sizeof(SSiloTypeListNode)));
    node->mNext = node;
    node->mPrev = node;
    node->mValue = value;
    return node;
  }

  void InitializeSiloTypeList(SSiloTypeList& list)
  {
    list.mProxyOrUnused = nullptr;
    list.mHead = AllocateSelfLinkedSiloTypeSentinel();
    list.mHead->mValue = SILOTYPE_Tactical;
    list.mSize = 0;
  }

  /**
   * Address: 0x005CFE10 (FUN_005CFE10, sub_5CFE10)
   */
  void ClearSiloTypeList(SSiloTypeList& list)
  {
    if (!list.mHead) {
      list.mSize = 0;
      return;
    }

    SSiloTypeListNode* node = list.mHead->mNext;
    list.mHead->mNext = list.mHead;
    list.mHead->mPrev = list.mHead;
    list.mSize = 0;

    while (node != list.mHead) {
      SSiloTypeListNode* const next = node->mNext;
      ::operator delete(node);
      node = next;
    }
  }

  void DestroySiloTypeListStorage(SSiloTypeList& list)
  {
    if (!list.mHead) {
      list.mSize = 0;
      return;
    }

    ClearSiloTypeList(list);
    ::operator delete(list.mHead);
    list.mHead = nullptr;
  }

  /**
   * Address: 0x005CFDB0 (FUN_005CFDB0, sub_5CFDB0)
   */
  void PopFrontSiloType(SSiloTypeList& list)
  {
    if (!list.mHead) {
      return;
    }

    SSiloTypeListNode* const node = list.mHead->mNext;
    if (node == list.mHead) {
      return;
    }

    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    ::operator delete(node);
    --list.mSize;
  }

  void PushBackSiloType(SSiloTypeList& list, const ESiloType value)
  {
    if (!list.mHead) {
      return;
    }

    SSiloTypeListNode* const node = AllocateSiloTypeNode(value);
    SSiloTypeListNode* const before = list.mHead;
    SSiloTypeListNode* const prev = before->mPrev;
    node->mNext = before;
    node->mPrev = prev;
    prev->mNext = node;
    before->mPrev = node;
    ++list.mSize;
  }

  [[nodiscard]] SEconValue TakeGrantedResourcesAndReset(CEconRequest* const request)
  {
    SEconValue out{};
    out.energy = request->mGranted.energy;
    out.mass = request->mGranted.mass;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;
    return out;
  }

  /**
    * Alias of FUN_005CFA20 (non-canonical helper lane).
   */
  void DestroyEconomyRequestPointer(CEconRequest*& request)
  {
    if (!request) {
      return;
    }

    request->mNode.ListUnlink();
    delete request;
    request = nullptr;
  }

  void ReplaceEconomyRequestPointer(CEconRequest*& request, CEconRequest* const replacement)
  {
    DestroyEconomyRequestPointer(request);
    request = replacement;
  }

  [[nodiscard]] CEconRequest* CreateEconomyRequest(const SEconValue& requested, CSimArmyEconomyInfo* const economy)
  {
    auto* const request = new CEconRequest{};
    request->mRequested = requested;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (economy) {
      request->mNode.ListLinkBefore(&economy->registrationNode);
    }
    return request;
  }

  [[nodiscard]] float CallUnitNumericScript(Unit* const unit, const char* const scriptName, const float fallbackValue)
  {
    if (!unit || !scriptName || !*scriptName) {
      return fallbackValue;
    }

    LuaPlus::LuaObject result = unit->RunScript(scriptName);
    if (!result || !result.IsNumber()) {
      return fallbackValue;
    }
    return static_cast<float>(result.GetNumber());
  }

  void DispatchWeaponCallback(Unit* const unit, const char* const callbackName, UnitWeapon* const weapon)
  {
    if (!unit || !weapon || !callbackName || !*callbackName) {
      return;
    }

    (void)unit->RunScript(callbackName, static_cast<void*>(weapon));
  }
} // namespace

gpg::RType* SSiloBuildInfo::sType = nullptr;
gpg::RType* CAiSiloBuildImpl::sType = nullptr;

/**
 * Address: 0x005D04A0 (FUN_005D04A0, Moho::SSiloBuildInfo::MemberDeserialize)
 */
void SSiloBuildInfo::MemberDeserialize(gpg::ReadArchive* const archive, SSiloBuildInfo* const info)
{
  if (!archive || !info) {
    return;
  }

  const gpg::RRef owner{};
  info->mWeapon = ReadPointerWithType<UnitWeapon>(archive, owner, ResolveUnitWeaponType());
  archive->ReadInt(&info->mAmmo);
  archive->ReadInt(&info->mMaxStorageCount);
}

/**
 * Address: 0x005D04F0 (FUN_005D04F0, Moho::SSiloBuildInfo::MemberSerialize)
 */
void SSiloBuildInfo::MemberSerialize(const SSiloBuildInfo* const info, gpg::WriteArchive* const archive)
{
  if (!archive || !info) {
    return;
  }

  const gpg::RRef owner{};
  WritePointerWithType(archive, info->mWeapon, ResolveUnitWeaponType(), gpg::TrackedPointerState::Unowned, owner);
  archive->WriteInt(info->mAmmo);
  archive->WriteInt(info->mMaxStorageCount);
}

/**
 * Address: 0x005CF5B0 (FUN_005CF5B0, ??0CAiSiloBuildImpl@Moho@@AAE@XZ)
 */
CAiSiloBuildImpl::CAiSiloBuildImpl()
  : mUnit(nullptr)
  , mSiloInfo{}
  , mSiloTypes{}
  , mRequest(nullptr)
  , mState(SBS_Idle)
  , mSegmentCost{}
  , mSegmentSpent{}
  , mSegments(1.0f)
  , mCurSegments(0)
{
  ZeroSiloBuildInfoWords(&mSiloInfo[0]);
  ZeroSiloBuildInfoWords(&mSiloInfo[1]);
  InitializeSiloTypeList(mSiloTypes);
}

/**
 * Address: 0x005CED30 (FUN_005CED30, ??0CAiSiloBuildImpl@Moho@@QAE@PAVUnit@1@@Z)
 */
CAiSiloBuildImpl::CAiSiloBuildImpl(Unit* const unit)
  : CAiSiloBuildImpl()
{
  mUnit = unit;

  if (mUnit) {
    mUnit->WorkProgress = 0.0f;
  }

  SiloUpdateProjectileBlueprint();
}

/**
 * Address: 0x005CF640 (FUN_005CF640, scalar deleting thunk)
 * Address: 0x005CEDF0 (FUN_005CEDF0, core dtor)
 */
CAiSiloBuildImpl::~CAiSiloBuildImpl()
{
  DestroyEconomyRequestPointer(mRequest);
  DestroySiloTypeListStorage(mSiloTypes);
}

/**
 * Address: 0x005CF850 (FUN_005CF850, Moho::CAiSiloBuildImpl::MemberConstruct)
 */
void CAiSiloBuildImpl::MemberConstruct(gpg::SerConstructResult* const result)
{
  CAiSiloBuildImpl* const object = new (std::nothrow) CAiSiloBuildImpl();
  if (!result) {
    delete object;
    return;
  }

  gpg::RRef objectRef{};
  objectRef.mObj = object;
  objectRef.mType = ResolveCAiSiloBuildImplType();
  result->SetUnowned(objectRef, 0u);
}

/**
 * Address: 0x005D1080 (FUN_005D1080, Moho::CAiSiloBuildImpl::MemberDeserialize)
 */
void CAiSiloBuildImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  mUnit = ReadPointerWithType<Unit>(archive, owner, ResolveUnitType());

  for (std::size_t index = 0; index < 2; ++index) {
    gpg::RType* const siloInfoType = ResolveSSiloBuildInfoType();
    GPG_ASSERT(siloInfoType != nullptr);
    archive->Read(siloInfoType, &mSiloInfo[index], owner);
  }

  gpg::RType* const siloListType = ResolveESiloTypeListType();
  GPG_ASSERT(siloListType != nullptr);
  archive->Read(siloListType, &mSiloTypes, owner);

  CEconRequest* const loadedRequest = ReadPointerWithType<CEconRequest>(archive, owner, ResolveCEconRequestType());
  ReplaceEconomyRequestPointer(mRequest, loadedRequest);

  gpg::RType* const stateType = ResolveESiloBuildStageType();
  GPG_ASSERT(stateType != nullptr);
  archive->Read(stateType, &mState, owner);

  archive->ReadFloat(&mSegments);
  archive->ReadInt(&mCurSegments);

  gpg::RType* const econValueType = ResolveSEconValueType();
  GPG_ASSERT(econValueType != nullptr);
  archive->Read(econValueType, &mSegmentCost, owner);
  archive->Read(econValueType, &mSegmentSpent, owner);
}

/**
 * Address: 0x005D1230 (FUN_005D1230, Moho::CAiSiloBuildImpl::MemberSerialize)
 */
void CAiSiloBuildImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  WritePointerWithType(archive, mUnit, ResolveUnitType(), gpg::TrackedPointerState::Unowned, owner);

  for (std::size_t index = 0; index < 2; ++index) {
    gpg::RType* const siloInfoType = ResolveSSiloBuildInfoType();
    GPG_ASSERT(siloInfoType != nullptr);
    archive->Write(siloInfoType, &mSiloInfo[index], owner);
  }

  gpg::RType* const siloListType = ResolveESiloTypeListType();
  GPG_ASSERT(siloListType != nullptr);
  archive->Write(siloListType, &mSiloTypes, owner);

  WritePointerWithType(archive, mRequest, ResolveCEconRequestType(), gpg::TrackedPointerState::Owned, owner);

  gpg::RType* const stateType = ResolveESiloBuildStageType();
  GPG_ASSERT(stateType != nullptr);
  archive->Write(stateType, &mState, owner);

  archive->WriteFloat(mSegments);
  archive->WriteInt(mCurSegments);

  gpg::RType* const econValueType = ResolveSEconValueType();
  GPG_ASSERT(econValueType != nullptr);
  archive->Write(econValueType, &mSegmentCost, owner);
  archive->Write(econValueType, &mSegmentSpent, owner);
}

/**
 * Address: 0x005D08E0 (FUN_005D08E0)
 *
 * What it does:
 * Thin serializer-save thunk lane forwarding one silo-build object/archive
 * pair into `CAiSiloBuildImpl::MemberSerialize`.
 */
[[maybe_unused]] void CAiSiloBuildImplMemberSerializeThunkA(
  const CAiSiloBuildImpl* const object,
  gpg::WriteArchive* const archive
)
{
  if (object != nullptr) {
    object->MemberSerialize(archive);
  }
}

/**
 * Address: 0x005D1030 (FUN_005D1030)
 *
 * What it does:
 * Secondary serializer-save thunk lane forwarding one silo-build
 * object/archive pair into `CAiSiloBuildImpl::MemberSerialize`.
 */
[[maybe_unused]] void CAiSiloBuildImplMemberSerializeThunkB(
  const CAiSiloBuildImpl* const object,
  gpg::WriteArchive* const archive
)
{
  if (object != nullptr) {
    object->MemberSerialize(archive);
  }
}

/**
 * Address: 0x005CEE40 (FUN_005CEE40, ?SiloUpdateProjectileBlueprint@CAiSiloBuildImpl@Moho@@UAEXXZ)
 */
void CAiSiloBuildImpl::SiloUpdateProjectileBlueprint()
{
  for (std::size_t slotIndex = 0; slotIndex < 2; ++slotIndex) {
    SSiloBuildInfo& slot = mSiloInfo[slotIndex];
    slot.mWeapon = nullptr;
    slot.mAmmo = 0;
    slot.mMaxStorageCount = 0;

    if (!mUnit || !mUnit->AiAttacker) {
      continue;
    }

    const int weaponCount = mUnit->AiAttacker->GetWeaponCount();
    for (int weaponIndex = 0; weaponIndex < weaponCount; ++weaponIndex) {
      auto* const weapon = AsUnitWeaponRuntimeView(reinterpret_cast<UnitWeapon*>(mUnit->AiAttacker->GetWeapon(weaponIndex)));
      if (!weapon || !weapon->mWeaponInfo) {
        continue;
      }

      if (!WeaponSupportsSiloBuild(weapon)) {
        continue;
      }
      if (!weapon->mProjectileBlueprint) {
        continue;
      }

      const bool isNukeWeapon = WeaponIsNukeClass(weapon);
      const bool expectedNukeFlag = (slotIndex == ToSiloIndex(SILOTYPE_Nuke));
      if (isNukeWeapon != expectedNukeFlag) {
        continue;
      }

      slot.mWeapon = reinterpret_cast<UnitWeapon*>(weapon);
      slot.mMaxStorageCount = WeaponSiloMaxStorageCount(weapon);
    }
  }

  if (mUnit) {
    mUnit->NeedSyncGameData = true;
  }
}

/**
 * Address: 0x005CEF00 (FUN_005CEF00, ?SiloIsBusy@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
 */
bool CAiSiloBuildImpl::SiloIsBusy(const ESiloType type) const
{
  if (!HasQueuedSiloTypes(mSiloTypes)) {
    return false;
  }
  return FrontSiloType(mSiloTypes) == type;
}

/**
 * Address: 0x005CEF20 (FUN_005CEF20, ?SiloIsFull@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
 */
bool CAiSiloBuildImpl::SiloIsFull(const ESiloType type) const
{
  const SSiloBuildInfo& slot = mSiloInfo[ToSiloIndex(type)];
  return (slot.mAmmo + SiloGetBuildCount(type)) >= slot.mMaxStorageCount;
}

/**
 * Address: 0x005CEF50 (FUN_005CEF50, ?SiloGetBuildCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
 */
std::int32_t CAiSiloBuildImpl::SiloGetBuildCount(const ESiloType type) const
{
  if (!mSiloTypes.mHead) {
    return 0;
  }

  std::int32_t count = 0;
  for (SSiloTypeListNode* node = mSiloTypes.mHead->mNext; node != mSiloTypes.mHead; node = node->mNext) {
    if (node->mValue == type) {
      ++count;
    }
  }
  return count;
}

/**
 * Address: 0x005CEF80 (FUN_005CEF80, ?SiloGetStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
 */
std::int32_t CAiSiloBuildImpl::SiloGetStorageCount(const ESiloType type) const
{
  return mSiloInfo[ToSiloIndex(type)].mAmmo;
}

/**
 * Address: 0x005CEF90 (FUN_005CEF90, ?SiloGetMaxStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
 */
std::int32_t CAiSiloBuildImpl::SiloGetMaxStorageCount(const ESiloType type) const
{
  return mSiloInfo[ToSiloIndex(type)].mMaxStorageCount;
}

/**
 * Address: 0x005CEFA0 (FUN_005CEFA0, ?SiloAdjustStorageCount@CAiSiloBuildImpl@Moho@@UAEXW4ESiloType@2@H@Z)
 */
void CAiSiloBuildImpl::SiloAdjustStorageCount(const ESiloType type, const std::int32_t delta)
{
  mSiloInfo[ToSiloIndex(type)].mAmmo += delta;
  if (mUnit) {
    mUnit->NeedSyncGameData = true;
  }
}

/**
 * Address: 0x005CEFC0 (FUN_005CEFC0, ?SiloAddBuild@CAiSiloBuildImpl@Moho@@UAE_NW4ESiloType@2@@Z)
 */
bool CAiSiloBuildImpl::SiloAddBuild(const ESiloType type)
{
  auto* const weapon = AsUnitWeaponRuntimeView(mSiloInfo[ToSiloIndex(type)].mWeapon);
  if (!weapon || weapon->mEnabled == 0u || SiloIsFull(type)) {
    return false;
  }

  if (mUnit) {
    mUnit->NeedSyncGameData = true;
  }

  PushBackSiloType(mSiloTypes, type);
  return true;
}

/**
 * Address: 0x005CF030 (FUN_005CF030, ?SiloAssistWithResource@CAiSiloBuildImpl@Moho@@UAEXABUSEconValue@2@@Z)
 */
void CAiSiloBuildImpl::SiloAssistWithResource(const SEconValue& value)
{
  if (mState == SBS_Idle) {
    return;
  }

  mSegmentSpent.energy += value.energy;
  mSegmentSpent.mass += value.mass;

  while (mSegmentSpent.energy >= mSegmentCost.energy) {
    if (mSegmentSpent.mass < mSegmentCost.mass) {
      break;
    }

    mSegmentSpent.energy = std::max(0.0f, mSegmentSpent.energy - mSegmentCost.energy);
    mSegmentSpent.mass = std::max(0.0f, mSegmentSpent.mass - mSegmentCost.mass);

    if (mUnit) {
      mUnit->mBeatResourceAccumulators.resourcesSpentEnergy += mSegmentCost.energy;
      mUnit->mBeatResourceAccumulators.resourcesSpentMass += mSegmentCost.mass;
      mUnit->WorkProgress = static_cast<float>(mCurSegments++) / mSegments;
    } else {
      ++mCurSegments;
    }

    if (static_cast<float>(mCurSegments) >= mSegments) {
      mState = SBS_Finish;
    }
  }
}

/**
 * Address: 0x005CF130 (FUN_005CF130, ?SiloStopBuild@CAiSiloBuildImpl@Moho@@UAEXXZ)
 */
void CAiSiloBuildImpl::SiloStopBuild()
{
  if (!mUnit) {
    return;
  }

  if (mUnit->IsAutoMode()) {
    mUnit->SetAutoMode(false);
    mUnit->RepeatQueueEnabled = true;
  }

  mUnit->NeedSyncGameData = true;

  if (mState == SBS_Prepare || mState == SBS_Active) {
    mUnit->SharedEconomyRateEnergy = 0.0f;
    mUnit->SharedEconomyRateMass = 0.0f;
  }

  mUnit->UnitStateMask &= ~kSiloBuildingStateMask;
  mUnit->WorkProgress = 0.0f;
  mState = SBS_Idle;
  ClearSiloTypeList(mSiloTypes);
  mCurSegments = 0;
}

/**
 * Address: 0x005CF1E0 (FUN_005CF1E0, ?SiloTick@CAiSiloBuildImpl@Moho@@UAEXXZ)
 */
void CAiSiloBuildImpl::SiloTick()
{
  if (!mUnit) {
    return;
  }

  if (mUnit->IsBeingBuilt() || mUnit->IsDead() || mUnit->DestroyQueued()) {
    return;
  }

  if (mUnit->IsPaused) {
    return;
  }

  switch (mState) {
  case SBS_Idle:
    if (mSiloTypes.mSize != 0) {
      mState = SBS_Prepare;
      return;
    }

    if (mUnit->IsAutoMode()) {
      for (int typeIndex = 0; typeIndex < 2; ++typeIndex) {
        if (SiloAddBuild(static_cast<ESiloType>(typeIndex))) {
          break;
        }
      }
    }
    return;

  case SBS_Prepare:
  {
    if (!HasQueuedSiloTypes(mSiloTypes)) {
      mState = SBS_Idle;
      return;
    }

    const ESiloType queuedType = FrontSiloType(mSiloTypes);
    UnitWeapon* const queuedWeapon = mSiloInfo[ToSiloIndex(queuedType)].mWeapon;
    auto* const weaponView = AsUnitWeaponRuntimeView(queuedWeapon);
    RProjectileBlueprint* const projectileBlueprint = weaponView ? weaponView->mProjectileBlueprint : nullptr;
    if (!weaponView || !projectileBlueprint) {
      PopFrontSiloType(mSiloTypes);
      mState = SBS_Idle;
      return;
    }

    const float buildRate =
      std::max(kSiloMinimumBuildRate, CallUnitNumericScript(mUnit, "GetEconomyBuildRate", 0.0f));
    const float energyAdj = CallUnitNumericScript(mUnit, "GetEnergyBuildAdjMod", 0.0f);
    const float massAdj = CallUnitNumericScript(mUnit, "GetMassBuildAdjMod", 0.0f);

    mSegments = (projectileBlueprint->Economy.BuildTime * 10.0f) / buildRate;
    mSegmentCost.energy = (projectileBlueprint->Economy.BuildCostEnergy * energyAdj) / mSegments;
    mSegmentCost.mass = (projectileBlueprint->Economy.BuildCostMass * massAdj) / mSegments;

    CSimArmyEconomyInfo* economy = nullptr;
    if (mUnit->ArmyRef) {
      economy = mUnit->ArmyRef->GetEconomy();
    }
    ReplaceEconomyRequestPointer(mRequest, CreateEconomyRequest(mSegmentCost, economy));

    mState = SBS_Active;
    mUnit->SharedEconomyRateEnergy = mSegmentCost.energy;
    mUnit->SharedEconomyRateMass = mSegmentCost.mass;
    mUnit->UnitStateMask |= kSiloBuildingStateMask;
    DispatchWeaponCallback(mUnit, "OnSiloBuildStart", queuedWeapon);
    return;
  }

  case SBS_Active:
    if (mRequest && mRequest->mGranted.energy >= mSegmentCost.energy && mRequest->mGranted.mass >= mSegmentCost.mass) {
      const SEconValue granted = TakeGrantedResourcesAndReset(mRequest);
      mUnit->SharedEconomyRateEnergy = mSegmentCost.energy;
      mUnit->SharedEconomyRateMass = mSegmentCost.mass;
      mUnit->mBeatResourceAccumulators.resourcesSpentEnergy += granted.energy;
      mUnit->mBeatResourceAccumulators.resourcesSpentMass += granted.mass;
      mUnit->WorkProgress = static_cast<float>(mCurSegments++) / mSegments;
    }

    if (static_cast<float>(mCurSegments) >= mSegments) {
      mState = SBS_Finish;
    }
    return;

  case SBS_Finish:
  {
    mUnit->SharedEconomyRateEnergy = 0.0f;
    mUnit->SharedEconomyRateMass = 0.0f;
    mUnit->UnitStateMask &= ~kSiloBuildingStateMask;
    mUnit->WorkProgress = 0.0f;

    if (HasQueuedSiloTypes(mSiloTypes)) {
      const ESiloType builtType = FrontSiloType(mSiloTypes);
      UnitWeapon* const builtWeapon = mSiloInfo[ToSiloIndex(builtType)].mWeapon;
      if (builtWeapon) {
        DispatchWeaponCallback(mUnit, "OnSiloBuildEnd", builtWeapon);
        DispatchWeaponCallback(mUnit, "OnNukeArmed", builtWeapon);
      }

      SiloAdjustStorageCount(builtType, 1);
      PopFrontSiloType(mSiloTypes);
      mCurSegments = 0;
    }

    mState = SBS_Idle;
    return;
  }

  default:
    return;
  }
}
