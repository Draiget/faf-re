#include "moho/unit/core/UnitPrivate2.h"

namespace
{
  /**
   * Address: 0x00561C80 (FUN_00561C80, sub_561C80)
   *
   * What it does:
   * Copy-assigns one `fastvector_n<CmdId, 8>` command-id snapshot lane,
   * preserving element order while reusing existing storage when capacity
   * allows. The binary copies these as raw dword ranges (`>> 2` element count,
   * `*dst = *src` word copies), so this is a plain trivially-copyable lane copy.
   */
  void CopyUnitCommandSnapshotVector(
    gpg::fastvector_n<moho::CmdId, 8>& destination,
    const gpg::fastvector_n<moho::CmdId, 8>& source
  )
  {
    destination = source;
  }

  /**
   * Instantiates `gpg::core::FastVectorInline<T>::AssignFrom` per element type. For
   * `UnitWeaponInfo` (0x98 bytes) that emission is the copy-assign
   * body (FUN_00561D90), whose element-wise copy loop the binary emitted twice
   * as byte-identical ICF twins (FUN_0055E900) and (FUN_00562990), with the
   * uninitialised-copy lane at (FUN_00562470).
   */
  template <class T, std::size_t N>
  void CopyFastVectorN(gpg::fastvector_n<T, N>& destination, const gpg::fastvector_n<T, N>& source)
  {
    destination = source;
  }

  /**
   * Address: 0x005BF420 (FUN_005BF420)
   *
   * What it does:
   * Copies the `UnitAttributes` lanes touched by the binary helper used by
   * `SSTIUnitVariableData::AssignFrom` (intentionally excluding reserved tail
   * bytes and non-copied metadata lanes).
   */
  moho::UnitAttributes* CopyUnitAttributesSnapshot(
    moho::UnitAttributes* const destination,
    const moho::UnitAttributes* const source
  )
  {
    destination->blueprint = source->blueprint;
    destination->restrictionCategory.mUniverse = source->restrictionCategory.mUniverse;
    destination->restrictionCategory.mBits.mFirstWordIndex = source->restrictionCategory.mBits.mFirstWordIndex;

    destination->restrictionCategory.mBits.mWords = source->restrictionCategory.mBits.mWords;

    destination->spawnElevationOffset = source->spawnElevationOffset;
    destination->moveSpeedMult = source->moveSpeedMult;
    destination->accelerationMult = source->accelerationMult;
    destination->turnMult = source->turnMult;
    destination->breakOffTriggerMult = source->breakOffTriggerMult;
    destination->breakOffDistanceMult = source->breakOffDistanceMult;
    destination->consumptionPerSecondEnergy = source->consumptionPerSecondEnergy;
    destination->consumptionPerSecondMass = source->consumptionPerSecondMass;
    destination->productionPerSecondEnergy = source->productionPerSecondEnergy;
    destination->productionPerSecondMass = source->productionPerSecondMass;
    destination->buildRate = source->buildRate;
    destination->regenRate = source->regenRate;
    destination->commandCapsMask = source->commandCapsMask;
    destination->toggleCapsMask = source->toggleCapsMask;
    destination->mReclaimable = source->mReclaimable;
    destination->mCapturable = source->mCapturable;
    destination->unknown_006A = source->unknown_006A;
    destination->unknown_006B = source->unknown_006B;
    destination->unknown_006C = source->unknown_006C;
    return destination;
  }

  // Lazy reflected-type caches used by SSTIUnitVariableData::MemberDeserialize.
  // Mirror the binary's `if (!X::sType) X::sType = gpg::LookupRType(&X RTTI)`
  // idiom at FUN_0055E030. EntId's distinct class RTTI is represented by
  // EntIdValue while runtime id fields retain their integer aliases.
  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::RTypeOf<EntIdValue>();
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponInfoVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::RTypeOf<gpg::fastvector<UnitWeaponInfo>>();
    }
    return cached;
  }
}


/**
 * Address: 0x0055E030 (FUN_0055E030, Moho::SSTIUnitVariableData::MemberDeserialize)
 *
 * IDA signature:
 * int __usercall sub_55E030@<eax>(int this@<eax>, gpg::ReadArchive* archive@<esi>);
 *
 * What it does:
 * Loads the full reflected unit variable-data payload from one archive in the
 * serializer's field order. mCommands/mBuildQueue (+0x98/+0xC8) are runtime
 * command queues and are deliberately not serialized (the binary skips them).
 */
void SSTIUnitVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  archive->Read(CachedEntIdType(), &mCreator, ownerRef);
  archive->ReadInt(&mCreationTick);
  archive->ReadBool(&mAutoMode);
  archive->ReadBool(&mAutoSurfaceMode);
  archive->ReadBool(&mIsBusy);
  archive->ReadFloat(&mFuelRatio);
  archive->ReadFloat(&mShieldRatio);
  archive->ReadInt(&mStunTicks);
  archive->ReadBool(&mIsPaused);
  archive->ReadBool(&mIsValidTarget);
  archive->ReadBool(&mRepeatQueue);
  // These enum values include reflected archive framing around the integer.
  EJobType jobType{};
  archive->Read(gpg::RTypeOf<EJobType>(), &jobType, ownerRef);
  mJobType = static_cast<int>(jobType);
  EFireState fireState{};
  archive->Read(gpg::RTypeOf<EFireState>(), &fireState, ownerRef);
  mFireState = static_cast<int>(fireState);
  archive->ReadFloat(&mWorkProgress);

  // Binary emits a 2-iteration, stride-4 interleaved loop over the tactical/
  // nuke silo-count pairs (base +0x30, reads cursor-8 / cursor / cursor+8 each
  // iteration). That yields the exact stream order below.
  archive->ReadInt(&mTacticalSiloBuildCount);
  archive->ReadInt(&mTacticalSiloStorageCount);
  archive->ReadInt(&mTacticalSiloMaxStorageCount);
  archive->ReadInt(&mNukeSiloBuildCount);
  archive->ReadInt(&mNukeSiloStorageCount);
  archive->ReadInt(&mNukeSiloMaxStorageCount);

  archive->Read(CachedEntIdType(), &mSelectionInheritorId, ownerRef);
  archive->ReadString(&mCustomName);

  archive->Read(gpg::RTypeOf<SEconValue>(), &mProduced, ownerRef);
  archive->Read(gpg::RTypeOf<SEconValue>(), &mResourcesSpent, ownerRef);
  archive->Read(gpg::RTypeOf<SEconValue>(), &mMaintainenceCost, ownerRef);

  archive->Read(CachedEntIdType(), &mFocusUnit, ownerRef);
  archive->Read(CachedEntIdType(), &mGuardedUnit, ownerRef);
  archive->Read(CachedEntIdType(), &mTargetBlip, ownerRef);

  archive->ReadPointerShared(&mPriorSharedPose, &ownerRef);
  archive->ReadPointerShared(&mSharedPose, &ownerRef);

  archive->Read(
    CachedUnitWeaponInfoVectorType(), static_cast<gpg::core::FastVectorInline<UnitWeaponInfo>*>(&mWeaponInfo), ownerRef
  );
  archive->Read(gpg::RTypeOf<UnitAttributes>(), &mAttributes, ownerRef);

  archive->ReadInt(reinterpret_cast<int*>(&mScriptbits));
  archive->ReadInt64(reinterpret_cast<__int64*>(&mUnitStates));
  archive->ReadBool(&mDidRefresh);
  archive->ReadBool(&mOverchargePaused);
}

/**
 * Address: 0x0055E420 (FUN_0055E420, Moho::SSTIUnitVariableData::MemberSerialize)
 *
 * IDA signature:
 * void __usercall sub_55E420(SSTIUnitVariableData* this@<edi>, gpg::WriteArchive* archive@<esi>);
 *
 * What it does:
 * Write mirror of MemberDeserialize (FUN_0055E030). Emits the full reflected
 * unit variable-data payload into one archive, field-for-field and in the same
 * order the deserializer reads. The two shared animation poses are written as
 * SHARED tracked raw pointers via gpg::RRef_CAniPose; mCommands/mBuildQueue
 * (+0x98/+0xC8) are runtime command queues the binary deliberately skips.
 */
void SSTIUnitVariableData::MemberSerialize(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  archive->Write(CachedEntIdType(), &mCreator, ownerRef);
  archive->WriteInt(mCreationTick);
  archive->WriteBool(mAutoMode);
  archive->WriteBool(mAutoSurfaceMode);
  archive->WriteBool(mIsBusy);
  archive->WriteFloat(mFuelRatio);
  archive->WriteFloat(mShieldRatio);
  archive->WriteInt(mStunTicks);
  archive->WriteBool(mIsPaused);
  archive->WriteBool(mIsValidTarget);
  archive->WriteBool(mRepeatQueue);
  const EJobType jobType = static_cast<EJobType>(mJobType);
  archive->Write(gpg::RTypeOf<EJobType>(), &jobType, ownerRef);
  const EFireState fireState = static_cast<EFireState>(mFireState);
  archive->Write(gpg::RTypeOf<EFireState>(), &fireState, ownerRef);
  archive->WriteFloat(mWorkProgress);

  // Binary emits a 2-iteration, stride-4 interleaved loop over the tactical/
  // nuke silo-count pairs (cursor base +0x30 = mTacticalSiloStorageCount,
  // writes cursor-8 / cursor / cursor+8 each iteration, then cursor += 4).
  // That yields the exact stream order below (Build/Storage/Max for tactical,
  // then the same three for nuke).
  archive->WriteInt(mTacticalSiloBuildCount);
  archive->WriteInt(mTacticalSiloStorageCount);
  archive->WriteInt(mTacticalSiloMaxStorageCount);
  archive->WriteInt(mNukeSiloBuildCount);
  archive->WriteInt(mNukeSiloStorageCount);
  archive->WriteInt(mNukeSiloMaxStorageCount);

  archive->Write(CachedEntIdType(), &mSelectionInheritorId, ownerRef);
  archive->WriteString(&mCustomName);

  archive->Write(gpg::RTypeOf<SEconValue>(), &mProduced, ownerRef);
  archive->Write(gpg::RTypeOf<SEconValue>(), &mResourcesSpent, ownerRef);
  archive->Write(gpg::RTypeOf<SEconValue>(), &mMaintainenceCost, ownerRef);

  archive->Write(CachedEntIdType(), &mFocusUnit, ownerRef);
  archive->Write(CachedEntIdType(), &mGuardedUnit, ownerRef);
  archive->Write(CachedEntIdType(), &mTargetBlip, ownerRef);

  // Two SHARED tracked animation-pose pointers: prior pose then current pose,
  // each wrapped via gpg::RRef_CAniPose and emitted through WriteRawPointer
  // with TrackedPointerState::Shared (the binary's `push 3; state`).
  gpg::RRef poseRef{};
  poseRef = gpg::MakeRRef<moho::CAniPose>(mPriorSharedPose.get());
  gpg::WriteRawPointer(archive, poseRef, gpg::TrackedPointerState::Shared, ownerRef);

  poseRef = gpg::MakeRRef<moho::CAniPose>(mSharedPose.get());
  gpg::WriteRawPointer(archive, poseRef, gpg::TrackedPointerState::Shared, ownerRef);

  archive->Write(
    CachedUnitWeaponInfoVectorType(), static_cast<const gpg::core::FastVectorInline<UnitWeaponInfo>*>(&mWeaponInfo), ownerRef
  );
  archive->Write(gpg::RTypeOf<UnitAttributes>(), &mAttributes, ownerRef);

  archive->WriteInt(static_cast<int>(mScriptbits));
  archive->WriteInt64(static_cast<std::int64_t>(mUnitStates));
  archive->WriteBool(mDidRefresh);
  archive->WriteBool(mOverchargePaused);
}

/**
 * Address: 0x005BD7A0 (FUN_005BD7A0, ??0SSTIUnitVariableData@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one unit variable-data payload to default sim-sync values.
 */
SSTIUnitVariableData::SSTIUnitVariableData()
  : mCreator(static_cast<EntId>(0xF0000000u))
  , mCreationTick(0)
  , mAutoMode(false)
  , mAutoSurfaceMode(false)
  , mIsBusy(false)
  , mPad00B(0)
  , mFuelRatio(-1.0f)
  , mShieldRatio(0.0f)
  , mStunTicks(0)
  , mIsPaused(false)
  , mIsValidTarget(true)
  , mRepeatQueue(false)
  , mPad01B(0)
  , mJobType(0)
  , mFireState(0)
  , mWorkProgress(0.0f)
  , mTacticalSiloBuildCount(0)
  , mNukeSiloBuildCount(0)
  , mTacticalSiloStorageCount(0)
  , mNukeSiloStorageCount(0)
  , mTacticalSiloMaxStorageCount(0)
  , mNukeSiloMaxStorageCount(0)
  , mSelectionInheritorId(static_cast<EntId>(0xF0000000u))
  , mCustomName()
  , mProduced{0.0f, 0.0f}
  , mResourcesSpent{0.0f, 0.0f}
  , mMaintainenceCost{0.0f, 0.0f}
  , mFocusUnit(static_cast<EntId>(0xF0000000u))
  , mGuardedUnit(static_cast<EntId>(0xF0000000u))
  , mTargetBlip(static_cast<EntId>(0xF0000000u))
  , mPriorSharedPose()
  , mSharedPose()
  , mPad094_097{}
  , mCommands()
  , mBuildQueue()
  , mWeaponInfo(0)
  , mAttributes{}
  , mScriptbits(0)
  , mUnitStates(0)
  , mDidRefresh(true)
  , mOverchargePaused(false)
  , mPad222_227{}
{
  mCustomName.tidy(false, 0U);

  mAttributes.blueprint = nullptr;
  mAttributes.unknown_0004 = 0;
  mAttributes.spawnElevationOffset = std::numeric_limits<float>::infinity();
  mAttributes.moveSpeedMult = 1.0f;
  mAttributes.accelerationMult = 1.0f;
  mAttributes.turnMult = 1.0f;
  mAttributes.breakOffTriggerMult = 1.0f;
  mAttributes.breakOffDistanceMult = 1.0f;
  mAttributes.consumptionPerSecondEnergy = 0.0f;
  mAttributes.consumptionPerSecondMass = 0.0f;
  mAttributes.productionPerSecondEnergy = 0.0f;
  mAttributes.productionPerSecondMass = 0.0f;
  mAttributes.buildRate = 1.0f;
  mAttributes.regenRate = 0.0f;
  mAttributes.commandCapsMask = 0U;
  mAttributes.toggleCapsMask = 0U;
  mAttributes.mReclaimable = true;
  mAttributes.mCapturable = true;
  mAttributes.unknown_006A = 0;
  mAttributes.unknown_006B = 0;
  mAttributes.unknown_006C = 0U;
}

/**
 * Address: 0x00560500 (FUN_00560500, ??1SSTIUnitVariableData@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases dynamic sync lanes through member dtors (`string`, `shared_ptr`,
 * and fastvector_n payloads) and clears the weapon-info fastvector lane
 * back to inline storage, which destroys every live `UnitWeaponInfo`
 * element before releasing the heap block (`~FastVectorN` alone only frees
 * the bytes). That one call is the whole of `FUN_00561D40`, the
 * `FastVectorN<UnitWeaponInfo, 1>` emission of `ResetStorageToInline`.
 */
SSTIUnitVariableData::~SSTIUnitVariableData()
{
  mWeaponInfo.ResetStorageToInline();
}

SSTIUnitVariableData::SSTIUnitVariableData(const SSTIUnitVariableData& other)
  : SSTIUnitVariableData()
{
  AssignFrom(other);
}

SSTIUnitVariableData& SSTIUnitVariableData::operator=(const SSTIUnitVariableData& other)
{
  return AssignFrom(other);
}

/**
 * Address: 0x005BF1E0 (FUN_005BF1E0, Moho::SSTIUnitVariableData::Assign)
 *
 * What it does:
 * Copies one unit variable-data payload, including shared-pose and command/
 * build queue snapshots.
 */
SSTIUnitVariableData& SSTIUnitVariableData::AssignFrom(const SSTIUnitVariableData& other)
{
  if (this == &other) {
    return *this;
  }

  mCreator = other.mCreator;
  mCreationTick = other.mCreationTick;
  mAutoMode = other.mAutoMode;
  mAutoSurfaceMode = other.mAutoSurfaceMode;
  mIsBusy = other.mIsBusy;
  mPad00B = other.mPad00B;
  mFuelRatio = other.mFuelRatio;
  mShieldRatio = other.mShieldRatio;
  mStunTicks = other.mStunTicks;
  mIsPaused = other.mIsPaused;
  mIsValidTarget = other.mIsValidTarget;
  mRepeatQueue = other.mRepeatQueue;
  mPad01B = other.mPad01B;
  mJobType = other.mJobType;
  mFireState = other.mFireState;
  mWorkProgress = other.mWorkProgress;
  mTacticalSiloBuildCount = other.mTacticalSiloBuildCount;
  mNukeSiloBuildCount = other.mNukeSiloBuildCount;
  mTacticalSiloStorageCount = other.mTacticalSiloStorageCount;
  mNukeSiloStorageCount = other.mNukeSiloStorageCount;
  mTacticalSiloMaxStorageCount = other.mTacticalSiloMaxStorageCount;
  mNukeSiloMaxStorageCount = other.mNukeSiloMaxStorageCount;
  mSelectionInheritorId = other.mSelectionInheritorId;
  mCustomName = other.mCustomName;
  mProduced = other.mProduced;
  mResourcesSpent = other.mResourcesSpent;
  mMaintainenceCost = other.mMaintainenceCost;
  mFocusUnit = other.mFocusUnit;
  mGuardedUnit = other.mGuardedUnit;
  mTargetBlip = other.mTargetBlip;
  mPriorSharedPose = other.mPriorSharedPose;
  mSharedPose = other.mSharedPose;
  // Opaque layout pad bytes: preserved bit-for-bit, no typed meaning to copy.
  std::copy_n(other.mPad094_097, std::size(other.mPad094_097), mPad094_097);
  CopyUnitCommandSnapshotVector(mCommands, other.mCommands);
  CopyUnitCommandSnapshotVector(mBuildQueue, other.mBuildQueue);
  CopyFastVectorN(mWeaponInfo, other.mWeaponInfo);
  (void)CopyUnitAttributesSnapshot(&mAttributes, &other.mAttributes);
  mScriptbits = other.mScriptbits;
  mUnitStates = other.mUnitStates;
  mDidRefresh = other.mDidRefresh;
  mOverchargePaused = other.mOverchargePaused;
  // Opaque layout pad bytes: preserved bit-for-bit, no typed meaning to copy.
  std::copy_n(other.mPad222_227, std::size(other.mPad222_227), mPad222_227);
  return *this;
}

void SSTIUnitVariableData::AssignHeapMembersFrom(const SSTIUnitVariableData& other)
{
  mCustomName = other.mCustomName;
  CopyUnitCommandSnapshotVector(mCommands, other.mCommands);
  CopyUnitCommandSnapshotVector(mBuildQueue, other.mBuildQueue);
  CopyFastVectorN(mWeaponInfo, other.mWeaponInfo);
  EntityCategorySet& restriction = mAttributes.restrictionCategory;
  const EntityCategorySet& sourceRestriction = other.mAttributes.restrictionCategory;
  restriction.mUniverse = sourceRestriction.mUniverse;
  restriction.mBits.mFirstWordIndex = sourceRestriction.mBits.mFirstWordIndex;
  restriction.mBits.mWords = sourceRestriction.mBits.mWords;
}

void SSTIUnitVariableData::AssignInlineMembersFrom(const SSTIUnitVariableData& other)
{
  mCreator = other.mCreator;
  mCreationTick = other.mCreationTick;
  mAutoMode = other.mAutoMode;
  mAutoSurfaceMode = other.mAutoSurfaceMode;
  mIsBusy = other.mIsBusy;
  mPad00B = other.mPad00B;
  mFuelRatio = other.mFuelRatio;
  mShieldRatio = other.mShieldRatio;
  mStunTicks = other.mStunTicks;
  mIsPaused = other.mIsPaused;
  mIsValidTarget = other.mIsValidTarget;
  mRepeatQueue = other.mRepeatQueue;
  mPad01B = other.mPad01B;
  mJobType = other.mJobType;
  mFireState = other.mFireState;
  mWorkProgress = other.mWorkProgress;
  mTacticalSiloBuildCount = other.mTacticalSiloBuildCount;
  mNukeSiloBuildCount = other.mNukeSiloBuildCount;
  mTacticalSiloStorageCount = other.mTacticalSiloStorageCount;
  mNukeSiloStorageCount = other.mNukeSiloStorageCount;
  mTacticalSiloMaxStorageCount = other.mTacticalSiloMaxStorageCount;
  mNukeSiloMaxStorageCount = other.mNukeSiloMaxStorageCount;
  mSelectionInheritorId = other.mSelectionInheritorId;
  mProduced = other.mProduced;
  mResourcesSpent = other.mResourcesSpent;
  mMaintainenceCost = other.mMaintainenceCost;
  mFocusUnit = other.mFocusUnit;
  mGuardedUnit = other.mGuardedUnit;
  mTargetBlip = other.mTargetBlip;
  mPriorSharedPose = other.mPriorSharedPose;
  mSharedPose = other.mSharedPose;
  std::copy_n(other.mPad094_097, std::size(other.mPad094_097), mPad094_097);

  // CopyUnitAttributesSnapshot without the restriction category (AssignHeapMembersFrom's).
  UnitAttributes& attributes = mAttributes;
  const UnitAttributes& source = other.mAttributes;
  attributes.blueprint = source.blueprint;
  attributes.spawnElevationOffset = source.spawnElevationOffset;
  attributes.moveSpeedMult = source.moveSpeedMult;
  attributes.accelerationMult = source.accelerationMult;
  attributes.turnMult = source.turnMult;
  attributes.breakOffTriggerMult = source.breakOffTriggerMult;
  attributes.breakOffDistanceMult = source.breakOffDistanceMult;
  attributes.consumptionPerSecondEnergy = source.consumptionPerSecondEnergy;
  attributes.consumptionPerSecondMass = source.consumptionPerSecondMass;
  attributes.productionPerSecondEnergy = source.productionPerSecondEnergy;
  attributes.productionPerSecondMass = source.productionPerSecondMass;
  attributes.buildRate = source.buildRate;
  attributes.regenRate = source.regenRate;
  attributes.commandCapsMask = source.commandCapsMask;
  attributes.toggleCapsMask = source.toggleCapsMask;
  attributes.mReclaimable = source.mReclaimable;
  attributes.mCapturable = source.mCapturable;
  attributes.unknown_006A = source.unknown_006A;
  attributes.unknown_006B = source.unknown_006B;
  attributes.unknown_006C = source.unknown_006C;

  mScriptbits = other.mScriptbits;
  mUnitStates = other.mUnitStates;
  mDidRefresh = other.mDidRefresh;
  mOverchargePaused = other.mOverchargePaused;
  std::copy_n(other.mPad222_227, std::size(other.mPad222_227), mPad222_227);
}

/**
 * Address: 0x006A8B30 (FUN_006A8B30, ?CalcTransportLoadFactor@Unit@Moho@@UBEMXZ)
 *
 * What it does:
 * FAF build: always returns 1.0f.
 *
 * The FAF-patched ForgedAlliance.exe overwrites the entry of this function
 * with `fld1; ret` (bytes `D9 E8 C3` at 0x006A8B30), so every caller --
 * `CUnitMotion::ComputeAirControl`, `Unit::GetTopSpeed` -- sees a load factor
 * of exactly 1.0 and the retail mass-ratio body that follows (the
 * `AiTransport`/`mAttachedEntities` sum cached in `TransportLoadFactor`) is
 * dead code: it is never reached and never writes the cache.
 */
float Unit::CalcTransportLoadFactor() const
{
  // 0x006A8B30: `fld1` / `ret` (FAF patch).
  return 1.0f;
}

/**
 * Address: 0x006AD5D0 (FUN_006AD5D0, ?SerEconomyEvents@Unit@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads tracked owned `CEconomyEvent*` lanes until a null terminator is read,
 * unlinking each loaded event node from its prior ring and linking it into
 * this unit's event-list head.
 */
void Unit::SerEconomyEvents(gpg::ReadArchive& archive, const int)
{
  CEconomyEvent* economyEvent = nullptr;
  gpg::RRef ownerRef{};
  archive.ReadPointerOwned(&economyEvent, &ownerRef);

  while (economyEvent != nullptr) {
    mEconomyEventListHead.push_back(economyEvent);
    economyEvent = nullptr;
    ownerRef = gpg::RRef{};
    archive.ReadPointerOwned(&economyEvent, &ownerRef);
  }
}

/**
 * Address: 0x006AD540 (FUN_006AD540, ?SerEconomyEvents@Unit@Moho@@ABEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes unit-owned economy-event pointer lanes as tracked owned pointers,
 * then writes a null terminator pointer lane.
 */
void Unit::SerEconomyEvents(gpg::WriteArchive& archive, const int) const
{
  for (auto* node = mEconomyEventListHead.mNext; node != &mEconomyEventListHead; node = node->mNext) {
    gpg::RRef eventOwnerRef{};
    archive.WritePointer<moho::CEconomyEvent>(node->Get(), gpg::TrackedPointerState::Owned, eventOwnerRef);
  }

  gpg::RRef tailOwnerRef{};
  archive.WritePointer<moho::CEconomyEvent*>(nullptr, gpg::TrackedPointerState::Owned, tailOwnerRef);
}
namespace moho
{
namespace
{
  /**
   * Reflection type-descriptor cache used by the runtime `Unit` member
   * serializer pair. Mirrors the per-type `LookupRType(typeid(T))` cache the
   * binary emits inline as one static `gpg::RType*` slot per member lane.
   */
  template <class TReflected>
  [[nodiscard]] gpg::RType* ResolveUnitSerializerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(TReflected));
    }
    return sType;
  }

  /**
   * Typed view over the four contiguous `Unit` reserved-O-grid bound lanes
   * (`ReservedOgridRect{Min,Max}{X,Z}` at +0x5A8), which together form the
   * unit occupation rectangle serialized/read as a single `gpg::Rect2i`.
   */
  [[nodiscard]] gpg::Rect2i& UnitOccupationRect(moho::Unit& unit) noexcept
  {
    static_assert(
      offsetof(moho::Unit, ReservedOgridRectMinX) == 0x05A8,
      "Unit occupation rect must begin at +0x5A8"
    );
    return reinterpret_cast<gpg::Rect2i&>(unit.ReservedOgridRectMinX);
  }
}



/**
 * Address: 0x006B33A0 (FUN_006B33A0)
 * Mangled: Moho::Unit::MemberSerialize
 *
 * IDA signature:
 * void __userpurge Moho::Unit::MemberSerialize(BinaryWriteArchive *archive@<eax>, Moho::Unit *this@<ecx>, int version);
 *
 * What it does:
 * Serializes every runtime `Unit` state lane, in declaration order, into the
 * write archive: the `Entity` base sub-object, the constant/variable unit data
 * payloads, the owned AI/command sidecar pointers (tracked OWNED pointers),
 * the weak-reference lanes, formation/guard state, economy lanes, and the
 * cached recon/blip state. Throws `gpg::SerializationError` for archive
 * versions below 1.
 */
void Unit::MemberSerialize(gpg::WriteArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  const gpg::RRef ownerRef{};
  const gpg::RRef unowned{};

  // Entity base sub-object (adjusted `this + 0x08`).
  archive->Write(ResolveUnitSerializerType<Entity>(), static_cast<const Entity*>(this), ownerRef);

  // Constant / variable unit-data payloads.
  archive->Write(ResolveUnitSerializerType<SSTIUnitConstantData>(), &mConstDat, ownerRef);
  archive->Write(ResolveUnitSerializerType<SSTIUnitVariableData>(), &VarDat(), ownerRef);

  // Owned AI / motion / command sidecar pointers (tracked OWNED lanes).
  {
    archive->WritePointer<moho::IAiSteering>(AiSteering, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::CUnitMotion>(UnitMotion, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::CUnitCommandQueue>(CommandQueue, gpg::TrackedPointerState::Owned, unowned);
  }

  // Weak-reference lanes.
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &CreatorRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &TransportedByRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &AssignedTransportRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Entity>>(), &FocusEntityRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Entity>>(), &TargetBlipEntityRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &GuardedUnitRef, ownerRef);

  // Guarded-position vector and guarded-by unit set.
  archive->Write(ResolveUnitSerializerType<Wm3::Vector3f>(), &GuardedPos, ownerRef);
  archive->Write(ResolveUnitSerializerType<EntitySetTemplate<Unit>>(), &GuardedByList, ownerRef);

  // Owned formation instance.
  {
    gpg::RRef ref{};
    gpg::RRef_IFormationInstance(&ref, GuardFormation);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(mNeedsKillCleanup);
  archive->WriteInt(mCreationTick);

  // Owned extra economy storage.
  {
    archive->WritePointer<moho::CEconStorage>(mExtraStorage, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteInt(PriorityBoost);

  // Owned consumption (upkeep) request.
  {
    archive->WritePointer<moho::CEconRequest>(mConsumptionData, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(ConsumptionActive);
  archive->WriteBool(ProductionActive);
  archive->WriteFloat(ResourceConsumed);

  // Owned animation actor.
  {
    archive->WritePointer<moho::CAniActor>(AniActor, gpg::TrackedPointerState::Owned, unowned);
  }

  // Owned AI implementation lanes.
  {
    archive->WritePointer<moho::IAiAttacker>(AiAttacker, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::IAiCommandDispatch>(AiCommandDispatch, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::IAiNavigator>(AiNavigator, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::IAiBuilder>(AiBuilder, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::IAiSiloBuild>(AiSiloBuild, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    archive->WritePointer<moho::IAiTransport>(AiTransport, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(FootprintDown);
  archive->WriteFloat(TransportLoadFactor);

  // Armor-multiplier map (`std::map<std::string,float>` reflection lane).
  archive->Write(
    ResolveUnitSerializerType<std::map<std::string, float>>(),
    &ArmorMultipliers,
    ownerRef
  );

  // Owned economy-event pointer list terminated by a null lane.
  SerEconomyEvents(*archive, version);

  archive->WriteUByte(CurrentTerrainType);
  archive->WriteBool(mDebugAIStates);

  archive->Write(ResolveUnitSerializerType<SInfoCache>(), &mInfoCache, ownerRef);
  archive->Write(ResolveUnitSerializerType<gpg::Rect2i>(), &UnitOccupationRect(*this), ownerRef);
  archive->Write(
    ResolveUnitSerializerType<gpg::fastvector<WeakPtr<Entity>>>(),
    &mBlipsInRange,
    ownerRef
  );

  archive->WriteUInt(static_cast<unsigned int>(mBlipLastUpdateTick));
  archive->WriteBool(mIsNotPod);
  archive->WriteBool(mIsEngineer);
  archive->WriteBool(mIsNaval);
  archive->WriteBool(mIsAir);
  archive->WriteBool(mIsMelee);
  archive->WriteBool(mUsesGridBasedMotion);
  archive->WriteInt(CaptorCount);

  archive->Write(
    ResolveUnitSerializerType<gpg::fastvector<ReconBlip*>>(),
    &mReconBlips,
    ownerRef
  );

  // A keyframe keeps the published ids as they stand: refreshing them on load would replace one of
  // a creator that is gone, or a command that has ended, which the game keeps publishing until the
  // unit next changes.
  if (gSimExactArchive.load()) {
    archive->WriteBool(NeedSyncGameData);
    SSTIUnitVariableData& published = VarDat();
    for (const gpg::fastvector_n<CmdId, 8>* const ids : {&published.mCommands, &published.mBuildQueue}) {
      archive->WriteInt(static_cast<int>(ids->size()));
      for (const CmdId id : *ids) {
        archive->WriteInt(static_cast<int>(id));
      }
    }
    archive->WriteBool(CommandQueue != nullptr && CommandQueue->mNeedsRefresh);
    archive->WriteBool(AiBuilder != nullptr && AiBuilder->BuilderIsFactoryQueueDirty());
  }
}

/**
 * Address: 0x006B2B50 (FUN_006B2B50, ?MemberDeserialize@Unit@Moho@@SAXPAVReadArchive@gpg@@PAV12@H@Z)
 * Mangled: Moho::Unit::MemberDeserialize
 *
 * IDA signature:
 * void __userpurge Moho::Unit::MemberDeserialize(gpg::ReadArchive *archive@<eax>, Moho::Unit *this@<esi>, int version);
 *
 * What it does:
 * Mirror of `MemberSerialize`: reads every runtime `Unit` state lane back in
 * declaration order, destroying any pre-existing owned sidecar object as each
 * owned pointer lane is replaced, then re-applies occupancy/collision state
 * (re-occupy ground, re-mark the O-grid occupation rect if non-degenerate, and
 * refresh collision when a collision shape is present). Throws
 * `gpg::SerializationError` for archive versions below 1.
 */
void Unit::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  const gpg::RRef ownerRef{};

  // Entity base sub-object (adjusted `this + 0x08`).
  archive->Read(ResolveUnitSerializerType<Entity>(), static_cast<Entity*>(this), ownerRef);

  // Constant / variable unit-data payloads.
  archive->Read(ResolveUnitSerializerType<SSTIUnitConstantData>(), &mConstDat, ownerRef);
  archive->Read(ResolveUnitSerializerType<SSTIUnitVariableData>(), &VarDat(), ownerRef);

  // Steering: read new owned pointer, swap in, release prior instance.
  {
    IAiSteering* steering = nullptr;
    archive->ReadPointerOwned(&steering, &ownerRef);
    IAiSteering* const prior = AiSteering;
    AiSteering = steering;
    delete prior;
  }

  // Unit motion.
  {
    CUnitMotion* motion = nullptr;
    archive->ReadPointerOwned(&motion, &ownerRef);
    CUnitMotion* const prior = UnitMotion;
    UnitMotion = motion;
    delete prior;
  }

  // Command queue.
  {
    CUnitCommandQueue* queue = nullptr;
    archive->ReadPointerOwned(&queue, &ownerRef);
    CUnitCommandQueue* const prior = CommandQueue;
    CommandQueue = queue;
    delete prior;
  }

  // Weak-reference lanes.
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &CreatorRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &TransportedByRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &AssignedTransportRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Entity>>(), &FocusEntityRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Entity>>(), &TargetBlipEntityRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &GuardedUnitRef, ownerRef);

  // Guarded-position vector and guarded-by unit set.
  archive->Read(ResolveUnitSerializerType<Wm3::Vector3f>(), &GuardedPos, ownerRef);
  archive->Read(ResolveUnitSerializerType<EntitySetTemplate<Unit>>(), &GuardedByList, ownerRef);

  // Formation instance (deleted through the reflection deleting-destructor slot).
  {
    IFormationInstance* formation = nullptr;
    archive->ReadPointerOwned(&formation, &ownerRef);
    IFormationInstance* const prior = GuardFormation;
    GuardFormation = static_cast<CAiFormationInstance*>(formation);
    delete prior;
  }

  archive->ReadBool(&mNeedsKillCleanup);
  archive->ReadInt(&mCreationTick);

  // Extra economy storage: detach from its economy then free raw storage.
  {
    CEconStorage* storage = nullptr;
    archive->ReadPointerOwned(&storage, &ownerRef);
    CEconStorage* const prior = mExtraStorage;
    mExtraStorage = storage;
    if (prior) {
      if (prior->mEconomy) {
        prior->Chng(-1);
      }
      ::operator delete(prior);
    }
  }

  archive->ReadInt(&PriorityBoost);

  // Consumption (upkeep) request: unlink its intrusive node then free storage.
  {
    CEconRequest* request = nullptr;
    archive->ReadPointerOwned(&request, &ownerRef);
    CEconRequest* const prior = mConsumptionData;
    mConsumptionData = request;
    if (prior) {
      prior->mNode.ListUnlink();
      ::operator delete(prior);
    }
  }

  archive->ReadBool(&ConsumptionActive);
  archive->ReadBool(&ProductionActive);
  archive->ReadFloat(&ResourceConsumed);

  // Animation actor.
  {
    CAniActor* actor = nullptr;
    archive->ReadPointerOwned(&actor, &ownerRef);
    CAniActor* const prior = AniActor;
    AniActor = actor;
    delete prior;
  }

  // AI implementation lanes.
  {
    IAiAttacker* attacker = nullptr;
    archive->ReadPointerOwned(&attacker, &ownerRef);
    CAiAttackerImpl* const prior = AiAttacker;
    AiAttacker = static_cast<CAiAttackerImpl*>(attacker);
    delete prior;
  }
  {
    IAiCommandDispatch* dispatch = nullptr;
    archive->ReadPointerOwned(&dispatch, &ownerRef);
    IAiCommandDispatchImpl* const prior = AiCommandDispatch;
    AiCommandDispatch = static_cast<IAiCommandDispatchImpl*>(dispatch);
    delete prior;
  }
  {
    IAiNavigator* navigator = nullptr;
    archive->ReadPointerOwned(&navigator, &ownerRef);
    IAiNavigator* const prior = AiNavigator;
    AiNavigator = navigator;
    delete prior;
  }
  {
    IAiBuilder* builder = nullptr;
    archive->ReadPointerOwned(&builder, &ownerRef);
    IAiBuilder* const prior = AiBuilder;
    AiBuilder = builder;
    delete prior;
  }
  {
    IAiSiloBuild* siloBuild = nullptr;
    archive->ReadPointerOwned(&siloBuild, &ownerRef);
    CAiSiloBuildImpl* const prior = AiSiloBuild;
    AiSiloBuild = static_cast<CAiSiloBuildImpl*>(siloBuild);
    delete prior;
  }
  {
    IAiTransport* transport = nullptr;
    archive->ReadPointerOwned(&transport, &ownerRef);
    IAiTransport* const prior = AiTransport;
    AiTransport = transport;
    delete prior;
  }

  archive->ReadBool(&FootprintDown);
  archive->ReadFloat(&TransportLoadFactor);

  // Armor-multiplier map (`std::map<std::string,float>` reflection lane).
  archive->Read(
    ResolveUnitSerializerType<std::map<std::string, float>>(),
    &ArmorMultipliers,
    ownerRef
  );

  // Owned economy-event pointer list terminated by a null lane.
  SerEconomyEvents(*archive, version);

  archive->ReadUByte(&CurrentTerrainType);
  archive->ReadBool(&mDebugAIStates);

  archive->Read(ResolveUnitSerializerType<SInfoCache>(), &mInfoCache, ownerRef);
  archive->Read(ResolveUnitSerializerType<gpg::Rect2i>(), &UnitOccupationRect(*this), ownerRef);
  archive->Read(
    ResolveUnitSerializerType<gpg::fastvector<WeakPtr<Entity>>>(),
    &mBlipsInRange,
    ownerRef
  );

  archive->ReadUInt(reinterpret_cast<unsigned int*>(&mBlipLastUpdateTick));
  archive->ReadBool(&mIsNotPod);
  archive->ReadBool(&mIsEngineer);
  archive->ReadBool(&mIsNaval);
  archive->ReadBool(&mIsAir);
  archive->ReadBool(&mIsMelee);
  archive->ReadBool(&mUsesGridBasedMotion);
  archive->ReadInt(&CaptorCount);

  archive->Read(
    ResolveUnitSerializerType<gpg::fastvector<ReconBlip*>>(),
    &mReconBlips,
    ownerRef
  );

  bool needSyncGameData = true;
  if (gSimExactArchive.load()) {
    archive->ReadBool(&needSyncGameData); // see MemberSerialize
    SSTIUnitVariableData& published = VarDat();
    for (gpg::fastvector_n<CmdId, 8>* const ids : {&published.mCommands, &published.mBuildQueue}) {
      int count = 0;
      archive->ReadInt(&count);
      ids->ResetStorageToInline();
      for (int index = 0; index < count; ++index) {
        int id = 0;
        archive->ReadInt(&id);
        ids->push_back(static_cast<CmdId>(id));
      }
    }
    bool queueRefresh = false;
    archive->ReadBool(&queueRefresh);
    if (CommandQueue != nullptr) {
      CommandQueue->mNeedsRefresh = queueRefresh;
    }
    bool factoryDirty = false;
    archive->ReadBool(&factoryDirty);
    if (AiBuilder != nullptr) {
      AiBuilder->BuilderSetFactoryQueueDirty(factoryDirty);
    }
  }

  // Post-load fixups: re-occupy ground, re-mark the occupation rect on the
  // O-grid when it is non-degenerate, then refresh collision when present.
  if (FootprintDown) {
    ExecuteOccupyGround();
  }

  if (!IsCollisionRectEquivalentToZero(GetReservedOgridRect(*this))) {
    if (SimulationRef && SimulationRef->mOGrid) {
      SimulationRef->mOGrid->OccupyRect(UnitOccupationRect(*this));
    }
  }

  NeedSyncGameData = needSyncGameData;

  if (CollisionExtents) {
    UpdateCollision();
  }
}
}

