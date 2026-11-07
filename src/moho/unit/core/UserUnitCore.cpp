#include "moho/unit/core/UserUnitPrivate.h"

namespace
{
  void WarnFocusArmyUnitDamagedCallbackError(const std::exception& exception) noexcept;
  constexpr const char* kOverlayCategoryAntiAir = "OVERLAYANTIAIR";
  constexpr const char* kOverlayCategoryDirectFire = "OVERLAYDIRECTFIRE";
  constexpr const char* kOverlayCategoryAntiNavy = "OVERLAYANTINAVY";

  enum class UserUnitIntelLane : std::int32_t
  {
    None = 0,
    Vision = 1,
    WaterVision = 2,
    Radar = 3,
    Sonar = 4,
    Omni = 5,
    RadarStealthField = 6,
    SonarStealthField = 7,
    CloakField = 8,
    Jammer = 9,
    Spoof = 10,
    Cloak = 11,
    RadarStealth = 12,
    SonarStealth = 13,
  };

  constexpr std::uint32_t kIntelRangeMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint8_t kToggleCapJamming = 0x04u;
  constexpr std::uint8_t kToggleCapIntel = 0x08u;
  constexpr std::uint8_t kToggleCapStealth = 0x20u;
  constexpr std::int32_t kRangeCategoryAll = 6;

  // The weapon snapshot the client reads here is the very `UnitWeaponInfo` the
  // sim publishes into `SSTIUnitVariableData::mWeaponInfo` (Unit.h), so it is
  // named directly rather than re-declared. A second byte-identical layout used
  // to stand here and was reached by `reinterpret_cast` off the same vector --
  // its own asserts pinned +0x00/+0x28/+0x50/+0x54/+0x58 and 0x98, exactly
  // `UnitWeaponInfo`'s, which means any future change to one of the two would
  // have silently misread `layerMask`/`minRange`/`maxRange` here instead of
  // failing to compile.


  // The factory build-queue row type and the published queue itself are owned by
  // `moho/ui/UiRuntimeTypes.{h,cpp}` (`moho::FactoryQueueDisplayItem`,
  // `moho::sCurrentBuildQueue`). The queue-rebuild and Lua-table workers below
  // take that vector as a parameter exactly as the binary does - it arrives in
  // `ebx` at 0x00835DF0 and in `esi` at 0x00836080 - so this translation unit
  // keeps no build-queue global of its own.


  // UserCommandQueue and its two sub-runs are real types now, declared in
  // moho/command/UserCommandQueue.h so the layout is stated once instead of
  // living as a reinterpret view over an opaque forward declaration.

}

namespace moho
{
  const IUnit* GetIUnitBridge(const UserUnit* const self) noexcept
  {
    return self;
  }

  IUnit* GetIUnitBridge(UserUnit* const self) noexcept
  {
    return self;
  }
}

namespace
{

  /**
   * Address: 0x008BEF80 (FUN_008BEF80, Moho::IUnit_UserUnit::CalcTransportLoadFactor)
   *
   * What it does:
   * Returns the fixed transport-load factor used by the UserUnit IUnit bridge.
   */
  [[maybe_unused]] [[nodiscard]] float IUnitBridgeCalcTransportLoadFactor(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return 1.0f;
  }

  /**
   * Address: 0x008BEFA0 (FUN_008BEFA0, Moho::IUnit_UserUnit::DestroyQueued)
   *
   * What it does:
   * Returns false for the UserUnit IUnit bridge destroy-queued lane.
   */
  [[maybe_unused]] [[nodiscard]] bool IUnitBridgeDestroyQueued(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return false;
  }

  /**
   * Address: 0x008BEFC0 (FUN_008BEFC0, Moho::IUnit_UserUnit::IsNavigatorIdle)
   *
   * What it does:
   * Returns false for the UserUnit IUnit bridge navigator-idle lane.
   */
  [[maybe_unused]] [[nodiscard]] bool IUnitBridgeIsNavigatorIdle(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return false;
  }

  /**
   * Address: 0x008BF020 (FUN_008BF020, Moho::IUnit_UserUnit::IsUnitState)
   *
   * What it does:
   * Tests one unit-state bit in the `UserUnit` IUnit-bridge state mask.
   */
  [[nodiscard]] bool IUnitBridgeIsUnitState(const IUnit* const bridge, const EUnitState state) noexcept
  {
    if (bridge == nullptr) {
      return false;
    }

    const std::uint32_t stateIndex = static_cast<std::uint32_t>(state);
    if (stateIndex >= 64u) {
      return false;
    }

    // The bridge is `UserUnit`'s `IUnit` base (+0x148 on x86); its +0x268 is
    // the owning unit's `mUnitVarDat.mUnitStates` (0x198 + 0x218).
    const auto* const unit = static_cast<const UserUnit*>(bridge);
    const std::uint64_t stateMask = (std::uint64_t{1} << stateIndex);
    return (unit->mUnitVarDat.mUnitStates & stateMask) != 0u;
  }

  // `UserEntity::mVisionHandle` already sits at +0x18; the pad-struct that used
  // to be cast over `UserUnit*` here declared the same pointer at the same
  // offset.
  [[nodiscard]] VisionDB::Handle*& GetUserUnitVisionHandle(UserUnit* const self) noexcept
  {
    return self->mVisionHandle;
  }

  [[maybe_unused]] [[nodiscard]] const VisionDB::Handle* GetUserUnitVisionHandle(const UserUnit* const self) noexcept
  {
    return self->mVisionHandle;
  }

  /**
   * Address: 0x008C06A0 (FUN_008C06A0)
   *
   * IDA signature:
   * void __usercall sub_8C06A0(Moho::UserEntity *unit@<esi>);
   *
   * What it does:
   * Takes one entity out of the player's current selection. Works on a copy of
   * the session selection and only republishes when the entity really was
   * selected, so a unit going busy off-screen never disturbs the selection.
   */
  void DeselectFromSessionSelection(UserEntity* const entity) noexcept
  {
    if (entity == nullptr || entity->mSession == nullptr) {
      return;
    }

    WeakSet<UserEntity> selection(entity->mSession->mSelection);
    if (selection.Find(entity) == selection.end()) {
      return;
    }

    (void)selection.Remove(entity);
    entity->mSession->SetSelection(selection);
  }

  /**
   * Address: 0x008B2300 (FUN_008B2300)
   *
   * IDA signature:
   * struct _EXCEPTION_REGISTRATION_RECORD *__stdcall sub_8B2300(
   *   Moho::UserArmy *army, Moho::UserUnit *unit);
   *
   * What it does:
   * Files one unit into its army's quick-select avatar run, which the binary
   * keeps sorted by ascending blueprint `QuickSelectPriority`. The scan skips
   * lanes whose weak reference has already gone stale and inserts before the
   * first surviving avatar that outranks the new unit, appending when none
   * does.
   *
   * Only `unit` is null-tested (0x008B231E). Each surviving avatar is compared
   * with the unit's priority read afresh (0x008B2347..0x008B2375, signed `jg`);
   * the hit is `insert(it, WeakPtr(unit))` (0x008B23D2), the fall-through
   * `push_back(WeakPtr(unit))` (0x008B2429).
   */
  void AddArmyAvatar(UserArmy* const army, UserUnit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    const IUnit* const unitBridge = unit;
    fa::vector<WeakPtr<UserUnit>>& avatars = army->mAvatars;
    for (WeakPtr<UserUnit>* it = avatars.begin(); it != avatars.end(); ++it) {
      const UserUnit* const avatar = it->GetObjectPtr();
      if (avatar == nullptr) {
        continue;
      }

      const std::int32_t unitPriority = unitBridge->GetBlueprint()->General.QuickSelectPriority;
      const IUnit* const avatarBridge = avatar;
      if (avatarBridge->GetBlueprint()->General.QuickSelectPriority > unitPriority) {
        avatars.insert(it, WeakPtr<UserUnit>(unit));
        return;
      }
    }

    avatars.push_back(WeakPtr<UserUnit>(unit));
  }

  /**
   * Address: 0x008B2520 (FUN_008B2520, idle engineer weak-set insert helper)
   *
   * What it does:
   * Inserts one `UserUnit` into the owning army idle-engineer weak set.
   */
  [[nodiscard]] bool InsertIdleEngineerWeakSetEntry(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (unit == nullptr || army == nullptr) {
      return false;
    }

    return army->mEngineers.Add(unit).second;
  }

  /**
   * Address: 0x008B2590 (FUN_008B2590, idle factory weak-set insert helper)
   *
   * What it does:
   * Inserts one `UserUnit` into the owning army idle-factory weak set.
   */
  [[nodiscard]] bool InsertIdleFactoryWeakSetEntry(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (unit == nullptr || army == nullptr) {
      return false;
    }

    return army->mFactories.Add(unit).second;
  }

  /**
   * Address: 0x008B2470 (FUN_008B2470, UserArmy::UnregisterPrioritySelectionSlot)
   * Address: 0x008B3870 (FUN_008B3870, `std::copy` over `WeakPtr<UserUnit>` --
   *   the tail shift of `fa::vector<WeakPtr<UserUnit>>::erase` below,
   *   formerly transcribed here as `PatchUserArmyPriorityRegistryRecordTail`)
   *
   * IDA signature:
   * _DWORD *__usercall sub_8B2470@<eax>(Moho::UserUnit *unit@<eax>,
   *                                      Moho::UserArmy *army@<edi>);
   *
   * What it does:
   * Erases `unit`'s record from the army's quick-select avatar run
   * (`UserArmy::mAvatars`, `[+0x1EC, +0x1F0)` on x86): finds the first
   * `WeakPtr<UserUnit>` naming it (0x008B2484..0x008B249A decodes each slot
   * with the `WeakPtr<UserUnit>` `-8`), then `erase`s it -- the survivors are
   * copy-assigned one record down through FUN_008B3870, the single vacated
   * tail record `[end-8, end)` is unlinked from its owner chain
   * (0x008B24C1..0x008B24F3), and `_Mylast` steps back one record.
   *
   * The previous transcription walked those records as raw dwords and
   * unlinked every shifted record from `cursor+1` to the old end rather than
   * only the vacated tail, leaving the surviving avatars out of their owners'
   * weak chains (and, when the erased record was the last, leaving it linked).
   *
   * Called from `UserUnit::DestroyUserUnit` (FUN_008BF9B0) when the unit's
   * blueprint `QuickSelectPriority` is positive, and from `UserUnit::Tick`
   * (FUN_008C0A30) during the dead-unit cleanup sweep.
   */
  void UnregisterUserArmyPrioritySelectionSlot(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (army == nullptr || unit == nullptr) {
      return;
    }

    fa::vector<WeakPtr<UserUnit>>& avatars = army->mAvatars;
    for (auto it = avatars.begin(); it != avatars.end(); ++it) {
      if (it->GetObjectPtr() == unit) {
        (void)avatars.erase(it);
        return;
      }
    }
  }

  /**
   * Address: 0x008B72F0 (FUN_008B72F0, struct_UserUnitManager::Get empty-check helper)
   *
   * What it does:
   * Resolves one command-manager active range and returns whether it is empty.
   */
  [[nodiscard]] bool IsUserCommandManagerQueueEmpty(const UserCommandQueue* const manager) noexcept
  {
    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueRange =
      ResolveUserCommandQueueRange(manager);
    return queueRange == nullptr || queueRange->empty();
  }

  /**
   * Address: 0x008C0D00 (FUN_008C0D00, cfunc_IssueDockCommandL idle candidate helper)
   *
   * What it does:
   * Returns whether one `UserUnit` is currently idle enough for dock-target
   * candidate selection (not busy and no pending command queue entries).
   */
  [[nodiscard]] bool IsDockTargetQueueIdle(const UserUnit* const unit) noexcept
  {
    if (unit == nullptr || unit->mUnitVarDat.mIsBusy != 0u) {
      return false;
    }

    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueRange = ResolveUserCommandQueueRange(unit->GetCommandQueue());
    return queueRange != nullptr && queueRange->empty();
  }

  /**
   * Address: 0x008B7350 (FUN_008B7350)
   *
   * What it does:
   * Consumes pending command-issue slots whose due sequence is <= `seqNo`,
   * marks resolved links dirty, then rebuilds resolved-link storage back to
   * inline mode when any slot was consumed.
   */
  void AdvanceUserCommandManagerBySeq(UserCommandQueue* const managerPtr, const std::int32_t seqNo) noexcept
  {
    while (!managerPtr->issueQueue.empty() && (managerPtr->issueQueue.front().mCommandId - seqNo) <= 0) {
      managerPtr->issueQueue.pop_front();
      managerPtr->resolvedLinksDirty = 1u;
    }

    if (managerPtr->resolvedLinksDirty == 0u) {
      return;
    }

    managerPtr->resolvedLinks.ResetStorageToInline();
  }
}

namespace moho
{
  /**
   * Address: 0x008BEE30 (FUN_008BEE30)
   *
   * What it does:
   * Resolves one command-target entity owner when target type is `Entity`
   * (`1`) and the weak-owner slot is non-null; returns null otherwise.
   * Exposed (declared in UserUnit.h) so `Moho::ISSUE_SetCommandTarget`
   * (Sim.cpp) can run the transport/ferry-beacon category checks its own
   * body runs against the drag target.
   */
  [[nodiscard]] UserEntity* DecodeEntityFromCommandTargetIfEntity(
    const UserTarget* const target
  ) noexcept
  {
    return target->targetType == UserTargetType::Entity ? target->targetEntity.GetObjectPtr() : nullptr;
  }
  /**
   * Address: 0x008BED50 (FUN_008BED50, sub_8BED50)
   *
   * What it does:
   * Resolves one command-target world position: returns entity position when
   * target type is `Entity` and weak owner resolves, returns inline target
   * position for `Position`, otherwise returns `Invalid<Wm3::Vector3f>()`.
   * Exposed (declared in UserUnit.h) so `Moho::ISSUE_SetCommandTarget`
   * (Sim.cpp) can resolve the drag-target world position it publishes.
   */
  [[nodiscard]] Wm3::Vector3<float> ResolvePositionFromTarget(const UserTarget& target) noexcept
  {
    if (target.targetType == UserTargetType::Position) {
      return target.position;
    }

    if (target.targetType == UserTargetType::Entity) {
      if (UserEntity* const targetEntity = target.targetEntity.GetObjectPtr(); targetEntity != nullptr) {
        return targetEntity->mVariableData.mCurTransform.pos_;
      }
    }

    return InvalidCommandQueuePosition();
  }
}

namespace
{

  /**
   * The intel lanes the sim replicates into every entity. The pad-struct that
   * used to stand here declared these eight `uint32`s at +0x100..+0x11C over a
   * `UserUnit*`, which is `UserEntity::mVariableData` (+0x50) plus
   * `SSTIEntityVariableData::mIntelAttributes` (+0xB0) - the same eight fields
   * in the same order, already declared as `SSTIIntelAttributes`.
   */
  [[nodiscard]] const SSTIIntelAttributes& GetIntelRanges(const UserUnit* const self) noexcept
  {
    return self->mVariableData.mIntelAttributes;
  }

  [[nodiscard]] std::uint32_t GetIntelRangeMagnitude(const UserUnit* const self, const UserUnitIntelLane intel) noexcept
  {
    const SSTIIntelAttributes& ranges = GetIntelRanges(self);

    // Binary parity with 0x005BD530 (EntityAttributes::GetRange):
    // enum ordinals are shifted relative to stored lanes.
    switch (intel) {
    case UserUnitIntelLane::None:
      return ranges.vision & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Vision:
      return ranges.waterVision & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::WaterVision:
      return ranges.radar & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Radar:
      return ranges.sonar & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Sonar:
      return ranges.omni & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Spoof:
      return ranges.cloak & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Cloak:
      return ranges.radarStealth & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::RadarStealth:
      return ranges.sonarStealth & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Omni:
    case UserUnitIntelLane::RadarStealthField:
    case UserUnitIntelLane::SonarStealthField:
    case UserUnitIntelLane::CloakField:
    case UserUnitIntelLane::Jammer:
    case UserUnitIntelLane::SonarStealth:
      return 0u;
    }
    return 0u;
  }

  [[nodiscard]] float GetIntelRangeAsFloat(const UserUnit* const self, const UserUnitIntelLane intel) noexcept
  {
    return static_cast<float>(GetIntelRangeMagnitude(self, intel));
  }

  [[nodiscard]] const UnitWeaponInfo* GetWeaponInfoBegin(const UserUnit* const self) noexcept
  {
    return self->mUnitVarDat.mWeaponInfo.data();
  }

  [[nodiscard]] const UnitWeaponInfo* GetWeaponInfoEnd(const UserUnit* const self) noexcept
  {
    return self->mUnitVarDat.mWeaponInfo.data() + self->mUnitVarDat.mWeaponInfo.size();
  }

  [[nodiscard]] bool ContainsBlueprintCategory(
    const EntityCategorySet& categorySet,
    const REntityBlueprint* const blueprint
  ) noexcept
  {
    return blueprint != nullptr && categorySet.Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] bool WeaponAllowsBlueprint(
    const UnitWeaponInfo& weaponInfo,
    const REntityBlueprint* const blueprint
  ) noexcept
  {
    if (!weaponInfo.mCat1.Bits().mWords.empty()
        && ContainsBlueprintCategory(weaponInfo.mCat1, blueprint)) {
      return false;
    }
    if (!weaponInfo.mCat2.Bits().mWords.empty()
        && !ContainsBlueprintCategory(weaponInfo.mCat2, blueprint)) {
      return false;
    }
    return true;
  }

  [[nodiscard]] bool IsUnitInOverlayCategory(const UserUnit* const unit, const char* const categoryName)
  {
    fa::string category{};
    category.assign_owned(categoryName != nullptr ? categoryName : "");
    const UserEntity* const entityView = unit;
    return entityView != nullptr && entityView->IsInCategory(category);
  }

  [[nodiscard]] bool CanReuseSharedPoseForSkeleton(
    const boost::shared_ptr<CAniPose>& sharedPose,
    const boost::shared_ptr<const CAniSkel>& skeleton
  )
  {
    if (!sharedPose || !skeleton) {
      return false;
    }

    return sharedPose->GetSkeleton().get() == skeleton.get();
  }

  [[nodiscard]] float PlanarDistanceXZ(const Wm3::Vector3<float>& from, const Wm3::Vector3<float>& to) noexcept
  {
    const float dx = to.x - from.x;
    const float dz = to.z - from.z;
    return std::sqrt((dx * dx) + (dz * dz));
  }

  /**
   * Address: 0x008528B0 (FUN_008528B0)
   *
   * What it does:
   * Copies one contiguous `Vector3<float>` range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the copied destination lane.
   */
  [[maybe_unused]] Wm3::Vector3<float>* CopyVector3RangeNullable(
    Wm3::Vector3<float>* destination,
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const Wm3::Vector3<float>* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        auto* const out = reinterpret_cast<Wm3::Vector3<float>*>(destinationAddress);
        out->x = source->x;
        out->y = source->y;
        out->z = source->z;
      }
      destinationAddress += sizeof(Wm3::Vector3<float>);
    }

    return reinterpret_cast<Wm3::Vector3<float>*>(destinationAddress);
  }
}

namespace moho
{
  /**
   * Bridge exposing the file-local ResolveHelperBuildCount (FUN_008B4220) to the
   * recovered `cfunc_DecreaseBuildCountInQueueL` worker in Sim.cpp. The worker
   * holds command-issue helpers as the canonical `UserCommandIssueHelper`; this
   * reinterprets that same object as the UserUnit-local event-ring view the
   * count resolver was recovered against (identical binary layout).
   */
  std::int32_t QueuedBuildCommandCount(const UserCommandIssueHelper& helper) noexcept
  {
    return ResolveHelperBuildCount(helper);
  }

  /**
   * Bridge exposing the file-local `IsDockTargetQueueIdle` (FUN_008C0D00) to the
   * recovered `cfunc_IssueDockCommandL` worker in CCommandLuaFunctionRegistrations.cpp.
   * Returns whether one candidate platform unit is idle enough (not busy, no
   * pending command queue entries) to be considered a dock target.
   */
  bool USERUNIT_IsDockTargetIdle(const UserUnit* const unit) noexcept
  {
    return IsDockTargetQueueIdle(unit);
  }

  /**
   * Bridge exposing the file-local `GetLastQueuedUserCommandHelper` (FUN_008B7320)
   * to the recovered `cfunc_IssueDockCommandL` worker. Resolves the unit's
   * command-manager handle (`UserUnit::GetCommandQueue`, slot 6) and returns the
   * most recent queued command-issue helper as an opaque cross-TU handle. The
   * dock worker reinterprets this handle as the command-graph anchor history the
   * binary walks to seed its centroid (identical binary object).
   */
  const QueuedUserCommandRecord* GetLastQueuedUserCommandAnchor(const UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    UserCommandQueue* const manager = const_cast<UserUnit*>(unit)->GetCommandQueue();
    if (manager == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<const QueuedUserCommandRecord*>(GetLastQueuedUserCommandHelper(manager));
  }

  /**
   * Address: 0x008C1220 (FUN_008C1220, sub_8C1220)
   *
   * IDA signature:
   * void __thiscall sub_8C1220(UserUnit *unit, std::list<RUnitBlueprint const*> *out);
   *
   * What it does:
   * Walks one unit's active command queue and collects the target unit
   * blueprints referenced by every pending `Upgrade` command into `out`.
   * Each queued upgrade helper's build blueprint is wrapped in a reflection
   * reference, upcast to `RUnitBlueprint`, and appended to the output list.
   *
   * `out` is a real `std::list<T>` in the binary (node-buy at 0x008C5EF0 +
   * `_Incsize` at 0x008C5F30, both cited on `fa::list<T>::insert` in
   * `legacy/containers/Vector.h`), not a set: it preserves queue order and
   * allows duplicate blueprint pointers when multiple pending commands
   * target the same blueprint. The IDA-signature comment previously (and
   * wrongly) said `std::set<RUnitBlueprint const*>`, and the recovered
   * body used `fa::set` to match -- the caller's own comment
   * (`CCommandLuaFunctionRegistrations.cpp`) already documents that its
   * loop's final state depends on which target is iterated *last*, which
   * only matches the binary's real command-queue order under a real
   * order-preserving list; a pointer-sorted set silently picks the
   * "last" target by heap-address order instead, an observable behavior
   * bug independent of the citation.
   */
  void CollectUpgradeCommandTargetBlueprints(UserUnit* const unit, fa::list<const RUnitBlueprint*>& out)
  {
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queue = RebuildAndGetUserUnitManagerQueue(unit->mManager);
    if (queue == nullptr) {
      return;
    }

    for (const WeakPtr<UserCommandIssueHelper>& link : *queue) {
      UserCommandIssueHelper* const helper = link.GetObjectPtr();
      if (helper == nullptr) {
        continue;
      }

      if (ResolveHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_Upgrade) {
        continue;
      }

      gpg::RRef entityRef{};
      entityRef = gpg::MakeRRef<moho::REntityBlueprint>(helper->mConstantData.blueprint);
      // The reference `RRef_REntityBlueprint` builds describes the blueprint
      // *object*, and `upcast.mObj` is used as one below, so the target is the
      // class descriptor. `GetPointerType()` is the descriptor for
      // `RUnitBlueprint*`; `REF_UpcastPtr` would walk the object's base list
      // looking for it, never find it, and hand back a null `mObj`.
      const gpg::RRef upcast = gpg::REF_UpcastPtr(entityRef, RUnitBlueprint::StaticGetClass());
      if (upcast.mObj != nullptr) {
        out.push_back(static_cast<const RUnitBlueprint*>(upcast.mObj));
      }
    }
  }
}

namespace
{

  /**
   * Address: 0x008C1410 (FUN_008C1410)
   *
   * What it does:
   * Emits one fixed warning when the focus-army-damaged Lua callback throws.
   */
  void WarnFocusArmyUnitDamagedCallbackError(const std::exception& exception) noexcept
  {
    const char* const message = exception.what() != nullptr ? exception.what() : "";
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnFocusArmyUnitDamaged': %s", message);
  }
}


CScrLuaMetatableFactory<UserUnit> CScrLuaMetatableFactory<UserUnit>::sInstance{};
namespace moho
{

  UserCommandIssueHelper* ResolveUserUnitFrontCommandIssueHelper(UserCommandQueue* const manager) noexcept
  {
    if (manager == nullptr) {
      return nullptr;
    }

    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr) {
      return nullptr;
    }

    // The binary walks the resolved range until the first non-null slot; a
    // retired order leaves its slot behind rather than compacting the range.
    for (const WeakPtr<UserCommandIssueHelper>& link : *queueVector) {
      if (link.GetObjectPtr() != nullptr) {
        return link.GetObjectPtr();
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x008C60F0 (FUN_008C60F0)
   *
   * What it does:
   * Returns cached `UserUnit` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_GetUserUnitFactory(
    LuaPlus::LuaObject* const object,
    LuaPlus::LuaState* const state
  )
  {
    return SCR_WriteMetatable<UserUnit>(object, state);
  }
}

namespace
{
  /// The metatable the `CScriptObject` sub-object is built against, fetched
  /// through the recovered factory accessor at 0x008C60F0.
  [[nodiscard]] LuaPlus::LuaObject MakeUserUnitScriptMetatable(moho::CWldSession* const session)
  {
    LuaPlus::LuaObject metatable;
    (void)moho::func_GetUserUnitFactory(&metatable, session != nullptr ? session->mState : nullptr);
    return metatable;
  }
}


/**
 * Address: 0x008BF420 (FUN_008BF420, ??0UserUnit@Moho@@QAE@@Z)
 *
 * IDA signature:
 * Moho::UserUnit *__thiscall Moho::UserUnit::UserUnit(
 *   Moho::CWldSession *session, Moho::UserUnit *this, Moho::SCreateUnitParams *params);
 *
 * What it does:
 * Builds one client-side unit from a sim create packet: runs the UserEntity,
 * IUnit and CScriptObject sub-objects, copies the constant data, allocates the
 * primary command queue (and a second one for factories), then files the unit
 * either into its army's quick-select avatar run or into the engineer
 * classification.
 */
UserUnit::UserUnit(CWldSession* const session, const SCreateUnitParams& params)
  : UserEntity(*session, params)
  , IUnit()
  , CScriptObject(
      MakeUserUnitScriptMetatable(session),
      LuaPlus::LuaObject(),
      LuaPlus::LuaObject(),
      LuaPlus::LuaObject()
    )
  , mUnitConstDat(params.mConstDat)
  , mReserved0194(0u)
  , mUnitVarDat()
  , mCreator()
  , mManager(nullptr)
  , mFactoryManager(nullptr)
  , mSelectionSets()
  , mQueueEmptyCached(false)
  , mIsEngineer(false)
  , mIsFactory(false)
{
  mManager = new UserCommandQueue(this);

  // 0x008BF66F: factories carry a second queue for what they are building.
  if (IsInCategory(fa::string("FACTORY", 7u))) {
    mFactoryManager = new UserCommandQueue(this);

    // 0x008BF745: only a factory that is also a structure counts as one for
    // the idle-factory registry; mobile factories are handled as engineers.
    if (IsInCategory(fa::string("STRUCTURE", 9u))) {
      mIsFactory = true;
    }
  }

  // 0x008BF7B7: a unit the blueprint gives a quick-select priority goes into
  // the army's avatar run; everything else is a candidate for the idle
  // engineer registry instead. The two are exclusive in the binary.
  const auto* const unitBlueprint = static_cast<const RUnitBlueprint*>(mParams.mBlueprint);
  if (mArmy != nullptr && unitBlueprint != nullptr && unitBlueprint->General.QuickSelectPriority > 0) {
    AddArmyAvatar(mArmy, this);
    return;
  }

  mIsEngineer = IsInCategory(fa::string("ENGINEER", 8u))
    && !IsInCategory(fa::string("COMMAND", 7u))
    && !IsInCategory(fa::string("SCOUT", 5u))
    && !IsInCategory(fa::string("UNTARGETABLE", 12u));
}

/**
 * Address: 0x008BF9B0 (FUN_008BF9B0, ??1UserUnit@Moho@@UAE@XZ)
 * Deleting-destructor thunk: 0x008BF990 (FUN_008BF990, ??_GUserUnit@Moho@@UAEPAXI@Z)
 *
 * What it does:
 * Drops the unit from its army's registries, hands its selection to the
 * successor named by `mUnitVarDat.mSelectionInheritorId`, and tears down the
 * per-unit command queues. The three-instruction thunk at 0x008BF990 that
 * forwards here and conditionally frees the storage is what C++ emits for a
 * virtual destructor, so it has no separate body.
 */
UserUnit::~UserUnit()
{
  UserEntity* const entityView = this;
  UserArmy* const army = this->mArmy;
  const IUnit* const iunitBridge = GetIUnitBridge(this);

  if (army != nullptr && iunitBridge != nullptr) {
    const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
    if (blueprint != nullptr && blueprint->General.QuickSelectPriority > 0) {
      // Binary lane at 0x008BFA0B: `QuickSelectPriority > 0` units are
      // tracked in the UserArmy high-priority selection registry (not in
      // the idle weak-sets), and must be unregistered from that run via
      // FUN_008B2470.
      UnregisterUserArmyPrioritySelectionSlot(this, army);
    } else if (mQueueEmptyCached) {
      if (mIsFactory) {
        (void)army->mFactories.Remove(this);
      }
      if (mIsEngineer) {
        (void)army->mEngineers.Remove(this);
      }
    }
  }

  // 0x008BFA49..0x008BFB1A: a unit that names a successor hands its selection
  // over on the way out. The successor only joins the selection if this unit
  // was itself selected, so an off-screen death never steals the player's
  // current selection.
  if (static_cast<std::uint32_t>(mUnitVarDat.mSelectionInheritorId) != ToRaw(EEntityIdSentinel::Invalid)) {
    WeakSet<UserEntity> selectionSnapshot(entityView->mSession->mSelection);
    if (selectionSnapshot.Find(entityView) != selectionSnapshot.end()) {
      UserEntity* const inheritor =
        entityView->mSession->LookupEntityId(static_cast<EntId>(mUnitVarDat.mSelectionInheritorId));
      if (inheritor != nullptr) {
        (void)selectionSnapshot.Add(inheritor);
        entityView->mSession->SetSelection(selectionSnapshot);

        if (UserUnit* const inheritorUnit = inheritor->IsUserUnit(); inheritorUnit != nullptr) {
          UserUnit::AddToSelectionSet(inheritorUnit, this);
        }
      }
    }
  }

  mSelectionSets.clear();

  delete mFactoryManager;
  mFactoryManager = nullptr;
  delete mManager;
  mManager = nullptr;

  if (VisionDB::Handle* const handle = GetUserUnitVisionHandle(this); handle != nullptr) {
    delete handle;
    GetUserUnitVisionHandle(this) = nullptr;
  }
}

/**
 * Address: 0x00852950 (FUN_00852950, Moho::UserUnit::GetSkirt)
 *
 * What it does:
 * Samples this unit's current world XZ position and writes the resolved
 * blueprint skirt rectangle into `outSkirtRect`.
 */
gpg::Rect2f* UserUnit::GetSkirt(gpg::Rect2f* const outSkirtRect) const
{
  const UserEntity* const entityView = this;
  const SCoordsVec2 currentPosition{
    entityView->mVariableData.mCurTransform.pos_.x,
    entityView->mVariableData.mCurTransform.pos_.z
  };
  const RUnitBlueprint* const blueprint = GetIUnitBridge(this)->GetBlueprint();
  *outSkirtRect = blueprint->GetSkirtRect(currentPosition);
  return outSkirtRect;
}

/**
 * Address: 0x008C09B0 (FUN_008C09B0, moho::UserUnit::UpdateVisibility)
 *
 * What it does:
 * Updates mesh hidden-state from replicated visibility mode/intel bits and
 * toggles mesh-pose lock lane for non-mobile units in recon-grid mode.
 */
void UserUnit::UpdateVisibility()
{
  UserEntity* const entityView = this;
  MeshInstance* const meshInstance = entityView->mMeshInstance;
  if (meshInstance == nullptr) {
    return;
  }

  switch (entityView->mVariableData.mVisibilityMode) {
  case EUserEntityVisibilityMode::Hidden:
    meshInstance->isHidden = 1u;
    break;
  case EUserEntityVisibilityMode::MapPlayableRect:
    meshInstance->isHidden = 0u;
    break;
  case EUserEntityVisibilityMode::ReconGrid:
    if (GetIUnitBridge(this)->IsMobile()) {
      meshInstance->isHidden = ((mIntelStateFlags & 0x08u) == 0u) ? 1u : 0u;
      return;
    }

    // A structure shows on RECON_LOSEver (bit 0x10, `shr edx,4 / not dl / and
    // dl,1` at 0x008C0A02) and freezes its pose whenever it is not currently in
    // LOS. 0x008C0A16 computes `!(mIntelStateFlags & 0x08)` into cl and TAIL
    // JUMPS to MeshInstance::LockPose (0x007DE6E0) -- it does not write
    // `isLocked` itself.
    //
    // This open-coded the assignment and lost the two things LockPose actually
    // does. It never ran the lock arm's `endPose->CopyPose(curPose, true)`, so a
    // ghost was flagged locked but kept the live pose it was interpolating --
    // a building out of intel went on animating its construction. And with no
    // change guard, the unlock arm re-stamped `frameCounter` and reset
    // `currInterpolant` to -1 on every single beat a structure was visible,
    // restarting its pose interpolation continuously instead of only on the
    // transition.
    meshInstance->isHidden = ((mIntelStateFlags & 0x10u) == 0u) ? 1u : 0u;
    meshInstance->LockPose((mIntelStateFlags & 0x08u) == 0u);
    break;
  }
}

/**
 * Address: 0x008C0750 (FUN_008C0750, Moho::UserUnit::UpdateUnitData)
 *
 * IDA signature:
 * void __thiscall Moho::UserUnit::UpdateUnitData(
 *   Moho::UserUnit *this, Moho::SSTIUnitVariableData *payload, int *mask);
 *
 * What it does:
 * Applies one replicated variable-data payload from a sync beat: assigns the
 * payload wholesale, records the intel mask, re-seats both shared poses,
 * re-resolves the creator weak reference (inheriting the creator's selection
 * sets when a factory built this unit), and resyncs both command queues when
 * the payload says the sim refreshed them. A unit that has just gone busy
 * drops out of the current selection.
 */
void UserUnit::UpdateUnitData(const SSTIUnitVariableData& payload, const std::uint32_t intelStateFlags)
{
  const bool wasBusy = ApplyUnitPayload(payload, intelStateFlags);

  if (!wasBusy && mUnitVarDat.mIsBusy) {
    DeselectFromSessionSelection(this);
  }

  ApplyUnitPoses();
  FinishUnitDataLinks();
}

bool UserUnit::ApplyUnitPayload(const SSTIUnitVariableData& payload, const std::uint32_t intelStateFlags)
{
  const bool wasBusy = mUnitVarDat.mIsBusy;
  mUnitVarDat.AssignFrom(payload);
  mIntelStateFlags = intelStateFlags;
  return wasBusy;
}

void UserUnit::ApplyUnitPoses()
{
  mPosePrimary = mUnitVarDat.mPriorSharedPose;
  mPoseSecondary = mUnitVarDat.mSharedPose;
}

bool UserUnit::UnitDataUpdateRunsLua(const SSTIUnitVariableData& payload) const
{
  if (!mUnitVarDat.mIsBusy && payload.mIsBusy) {
    return true;
  }

  const EntId replicatedCreator = payload.mCreator;
  if ((replicatedCreator & 0xF0000000u) == 0xF0000000u) {
    return false;
  }
  const UserEntity* const heldCreator = mCreator.GetObjectPtr();
  if (heldCreator != nullptr && heldCreator->mParams.mEntityId == static_cast<std::uint32_t>(replicatedCreator)) {
    return false;
  }
  const UserEntity* const creator = WLD_GetActiveSession()->LookupEntityId(static_cast<EntId>(replicatedCreator));
  return creator != nullptr && creator->IsInCategory(fa::string("FACTORY", 7u));
}

void UserUnit::FinishUnitDataLinks()
{
  const EntId replicatedCreator = mUnitVarDat.mCreator;
  if ((replicatedCreator & 0xF0000000u) == 0xF0000000u) {
    // 0x008C0823: the sentinel id means "no creator"; drop whatever we held.
    mCreator.UnlinkFromOwnerChain();
  } else {
    const UserEntity* const heldCreator = mCreator.GetObjectPtr();
    if (heldCreator == nullptr || heldCreator->mParams.mEntityId != static_cast<std::uint32_t>(replicatedCreator)) {
      mCreator.ResetFromObject(WLD_GetActiveSession()->LookupEntityId(static_cast<EntId>(replicatedCreator)));

      UserEntity* const creator = mCreator.GetObjectPtr();
      if (creator != nullptr && creator->IsInCategory(fa::string("FACTORY", 7u))) {
        // 0x008C0949: a unit rolling off a factory inherits that factory's
        // selection-set membership. The binary decodes the weak lane straight
        // to a `UserUnit` here; the category test is what makes that safe.
        UserUnit::AddToSelectionSet(this, static_cast<UserUnit*>(creator));
      }
    }
  }

  if (mUnitVarDat.mDidRefresh) {
    if (mManager != nullptr) {
      ResyncUserCommandQueueLinks(mManager, mUnitVarDat.mCommands.start_, mUnitVarDat.mCommands.end_);
    }
    if (mFactoryManager != nullptr) {
      ResyncUserCommandQueueLinks(mFactoryManager, mUnitVarDat.mBuildQueue.start_, mUnitVarDat.mBuildQueue.end_);
    }
  }
}

gpg::RType* UserUnit::sType = nullptr;

/**
 * Address: 0x008BEF00 (FUN_008BEF00, Moho::IUnit_UserUnit::GetEntityId)
 * IUnit slot 4.
 */
EntId UserUnit::GetEntityId() const
{
  return static_cast<EntId>(mParams.mEntityId);
}

/**
 * Address: 0x008BEF10 (FUN_008BEF10, Moho::IUnit_UserUnit::GetPosition)
 * IUnit slot 5.
 */
const Wm3::Vec3f& UserUnit::GetPosition() const
{
  return mVariableData.mCurTransform.pos_;
}

/**
 * Address: 0x008BEF20 (FUN_008BEF20, Moho::IUnit_UserUnit::GetTransform)
 * IUnit slot 6.
 */
const VTransform& UserUnit::GetTransform() const
{
  return mVariableData.mCurTransform;
}

/**
 * Address: 0x008BEF30 (FUN_008BEF30, Moho::IUnit_UserUnit::GetBlueprint)
 * IUnit slot 7.
 *
 * What it does:
 * Hands back the entity blueprint the unit was created with, narrowed to the
 * unit blueprint it is known to be - `SCreateUnitParams` only ever carries one.
 */
const RUnitBlueprint* UserUnit::GetBlueprint() const
{
  return static_cast<const RUnitBlueprint*>(mParams.mBlueprint);
}

/**
 * Address: 0x008BEF60 (FUN_008BEF60, Moho::IUnit_UserUnit::GetLuaObject)
 * IUnit slot 8.
 */
LuaPlus::LuaObject UserUnit::GetLuaObject()
{
  return mLuaObj;
}

/**
 * Address: 0x008BEF80 (FUN_008BEF80, Moho::IUnit_UserUnit::CalcTransportLoadFactor)
 * IUnit slot 9.
 */
float UserUnit::CalcTransportLoadFactor() const
{
  return 1.0f;
}

/**
 * Address: 0x008BEF90 (FUN_008BEF90, Moho::IUnit_UserUnit::IsDead)
 * IUnit slot 10.
 */
bool UserUnit::IsDead() const
{
  return mVariableData.mIsDead != 0u;
}

/**
 * Address: 0x008BEFA0 (FUN_008BEFA0, Moho::IUnit_UserUnit::DestroyQueued)
 * IUnit slot 11.
 */
bool UserUnit::DestroyQueued() const
{
  return false;
}

/**
 * Address: 0x008C04E0 (FUN_008C04E0, Moho::IUnit_UserUnit::IsMobile)
 * IUnit slot 12.
 *
 * What it does:
 * One unsigned range test over the blueprint's motion type: everything from
 * `Land` through `AmphibiousFloating` moves, `None` and `Special` do not.
 */
bool UserUnit::IsMobile() const
{
  const auto motionType = static_cast<std::uint32_t>(GetBlueprint()->Physics.MotionType);
  return (motionType - 1u) <= (static_cast<std::uint32_t>(RULEUMT_AmphibiousFloating) - 1u);
}

/**
 * Address: 0x008BEFC0 (FUN_008BEFC0, Moho::IUnit_UserUnit::IsNavigatorIdle)
 * IUnit slot 14.
 */
bool UserUnit::IsNavigatorIdle() const
{
  return false;
}

/**
 * Address: 0x008BF020 (FUN_008BF020, Moho::IUnit_UserUnit::IsUnitState)
 * IUnit slot 15.
 *
 * What it does:
 * Tests one bit of the replicated state mask. The binary shifts through
 * `__allshl`, which yields zero once the count reaches 64; the explicit bound
 * keeps that same answer without the shift being undefined.
 */
bool UserUnit::IsUnitState(const EUnitState state) const
{
  const auto stateIndex = static_cast<std::uint32_t>(state);
  if (stateIndex >= 64u) {
    return false;
  }
  return (mUnitVarDat.mUnitStates & (std::uint64_t{1} << stateIndex)) != 0u;
}

/**
 * Address: 0x008BEF50 (FUN_008BEF50, Moho::IUnit_UserUnit::GetAttributes)
 * IUnit slot 16.
 */
UnitAttributes& UserUnit::GetAttributes()
{
  return mUnitVarDat.mAttributes;
}

/**
 * Address: 0x008BEF40 (FUN_008BEF40, Moho::IUnit_UserUnit::GetAttributes)
 * IUnit slot 17.
 */
const UnitAttributes& UserUnit::GetAttributes() const
{
  return mUnitVarDat.mAttributes;
}

/**
 * Address: 0x0085B0B0 (FUN_0085B0B0, Moho::UserUnit::HasScriptBit)
 *
 * What it does:
 * Tests the sign-extended script flags with the original 64-bit shift semantics.
 */
bool UserUnit::HasScriptBit(const std::uint8_t bitIndex) const
{
  const auto scriptBits = static_cast<std::uint64_t>(
    static_cast<std::int64_t>(static_cast<std::int32_t>(mUnitVarDat.mScriptbits))
  );
  return bitIndex < 64u && (scriptBits & (std::uint64_t{1} << bitIndex)) != 0u;
}

/**
 * Address: 0x008BF0C0 (FUN_008BF0C0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 18.
 *
 * What it does:
 * The default value only picks the lane: a string default routes to the
 * string-typed stat under this unit's stats root.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const std::string& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetStringItem(statPath);
}

/**
 * Address: 0x008BF0B0 (FUN_008BF0B0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 19.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const float& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetFloatItem(statPath);
}

/**
 * Address: 0x008BF0A0 (FUN_008BF0A0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 20.
 *
 * What it does:
 * The int-defaulted lane is the only one that creates the stat when it is
 * missing - the binary rewrites the second argument to `true` and tail-calls
 * the same lookup slot 21 uses.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const int& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetItem(statPath, true);
}

/**
 * Address: 0x008BF080 (FUN_008BF080, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 21.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath)
{
  return mUnitConstDat.mStatsRoot->GetItem(statPath, false);
}

/**
 * Address: 0x008BEEC0 (FUN_008BEEC0, Moho::CScriptObject_UserUnit::GetClass)
 * CScriptObject slot 0.
 */
gpg::RType* UserUnit::GetClass() const
{
  return CachedUserUnitType();
}

/**
 * Address: 0x008BEEE0 (FUN_008BEEE0, Moho::CScriptObject_UserUnit::GetDerivedObjectRef)
 * CScriptObject slot 1.
 *
 * What it does:
 * Pairs the whole-object pointer with the reflected type. There is no dynamic
 * walk here - `UserUnit` is the most-derived type by construction.
 */
gpg::RRef UserUnit::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x008C0A30 (FUN_008C0A30, moho::UserUnit::Tick)
 *
 * What it does:
 * Advances command-manager queue state, updates idle engineer/factory weak-set
 * membership, and maintains the vision-handle lane for fog/recon tracking.
 */
void UserUnit::Tick(const std::int32_t seqNo)
{
  AdvanceUserCommandManagerBySeq(mManager, seqNo);
  if (mFactoryManager != nullptr) {
    AdvanceUserCommandManagerBySeq(mFactoryManager, seqNo);
  }

  if (IsBeingBuilt()) {
    return;
  }

  UserEntity* const entityView = this;
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  UserArmy* const army = this->mArmy;
  if (iunitBridge->IsDead()) {
    if (army != nullptr) {
      const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
      if (blueprint != nullptr && blueprint->General.QuickSelectPriority > 0) {
        // Matches FUN_008C0A30 @ 0x008C0AA8: priority units leave the
        // high-priority selection registry instead of the idle weak-sets.
        UnregisterUserArmyPrioritySelectionSlot(this, army);
      } else if (mQueueEmptyCached) {
          if (mIsFactory) {
          (void)army->mFactories.Remove(this);
        }
        if (mIsEngineer) {
          (void)army->mEngineers.Remove(this);
        }
      }
    }

    if (VisionDB::Handle* const handle = GetUserUnitVisionHandle(this); handle != nullptr) {
      delete handle;
      GetUserUnitVisionHandle(this) = nullptr;
    }
    return;
  }

  const bool isQueueEmpty = this->mUnitVarDat.mIsBusy == 0u && IsUserCommandManagerQueueEmpty(mManager);
  if (isQueueEmpty != mQueueEmptyCached) {
    if (army != nullptr) {
      if (mIsEngineer) {
        if (isQueueEmpty) {
          (void)InsertIdleEngineerWeakSetEntry(this, army);
        } else {
          (void)army->mEngineers.Remove(this);
        }
      }
      if (mIsFactory) {
        if (isQueueEmpty) {
          (void)InsertIdleFactoryWeakSetEntry(this, army);
        } else {
          (void)army->mFactories.Remove(this);
        }
      }
    }
    mQueueEmptyCached = isQueueEmpty;
  }

  // 0x008C0B9C: with fog of war off the vision handle is left untouched.
  if (!console::RenderFogOfWarEnabled()) {
    return;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  const std::uint32_t visionRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::None);
  VisionDB::Handle*& visionHandle = GetUserUnitVisionHandle(this);
  if (visionRange != 0u && visionHandle == nullptr && !mUnitConstDat.mFake) {
    const Wm3::Vector2f zero(0.0f, 0.0f);
    // `CWldSession::mVisionDb` is that same lane at +0x3C8, already declared.
    visionHandle = session->mVisionDb.NewHandle(zero, zero);
  }

  if (visionHandle == nullptr) {
    return;
  }

  if (mUnitConstDat.mFake) {
    delete visionHandle;
    visionHandle = nullptr;
    return;
  }

  bool isAlly = false;
  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  if (focusArmy != nullptr && army != nullptr) {
    isAlly = focusArmy->IsAlly(army->mArmyIndex);
  }

  const Wm3::Vector2f currentPos(entityView->mVariableData.mCurTransform.pos_.x, entityView->mVariableData.mCurTransform.pos_.z);
  const Wm3::Vector2f previousPos(
    entityView->mVariableData.mLastTransform.pos_.x, entityView->mVariableData.mLastTransform.pos_.z
  );
  visionHandle->Update(currentPos, previousPos, static_cast<float>(visionRange), isAlly);
}

/**
  * Alias of FUN_008B8EB0 (non-canonical helper lane).
 *
 * What it does:
 * For UserUnit instances, forwards replicated variable-data updates to the
 * shared UserEntity implementation for mesh/visibility/vision refresh.
 */
void UserUnit::UpdateEntityData(const SSTIEntityVariableData& variableData)
{
  UserEntity::UpdateEntityData(variableData);
}

/**
 * Address: 0x008BF120 (FUN_008BF120)
 *
 * What it does:
 * Returns this object as the const UserUnit identity view.
 */
const UserUnit* UserUnit::IsUserUnit() const
{
  return this;
}

/**
 * Address: 0x008BF110 (FUN_008BF110)
 *
 * What it does:
 * Returns this object as the mutable UserUnit identity view.
 */
UserUnit* UserUnit::IsUserUnit()
{
  return this;
}

/**
 * Address: 0x008BF170 (FUN_008BF170)
 *
 * What it does:
 * Calls IUnit::GetBlueprint through the embedded +0x148 subobject and reads
 * blueprint uniform scale at +0x270.
 */
float UserUnit::GetUniformScale() const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  return blueprint->Display.UniformScale;
}

/**
 * Address: 0x008BF150 (FUN_008BF150)
 *
 * What it does:
 * Returns the current user command-queue handle (mutable view slot).
 */
const UserCommandQueue* UserUnit::GetCommandQueue() const
{
  return mManager;
}

/**
 * Address: 0x008BF130 (FUN_008BF130)
 *
 * What it does:
 * Returns the current user command-queue handle (const view slot).
 */
UserCommandQueue* UserUnit::GetCommandQueue()
{
  return mManager;
}

/**
 * Address: 0x008BF160 (FUN_008BF160)
 *
 * What it does:
 * Returns the current factory command-queue handle (mutable view slot).
 */
const UserCommandQueue* UserUnit::GetFactoryCommandQueue() const
{
  return mFactoryManager;
}

/**
 * Address: 0x008BF140 (FUN_008BF140)
 *
 * What it does:
 * Returns the current factory command-queue handle (const view slot).
 */
UserCommandQueue* UserUnit::GetFactoryCommandQueue()
{
  return mFactoryManager;
}

/**
  * Alias of FUN_008B8530 (non-canonical helper lane).
 *
 * What it does:
 * Returns replicated UI-dirty state from UserEntity variable-data bytes.
 */
bool UserUnit::RequiresUIRefresh() const
{
  return mVariableData.mRequestRefreshUI != 0;
}

/**
 * Address: 0x008BEFB0 (FUN_008BEFB0)
 *
 * What it does:
 * Returns replicated "being built" state from UserEntity variable-data bytes.
 */
bool UserUnit::IsBeingBuilt() const
{
  return mVariableData.mIsBeingBuilt != 0;
}

/**
 * Address: 0x008C0500 (FUN_008C0500, moho::UserUnit::IsSelectable)
 *
 * IDA signature:
 * char __thiscall Moho::UserUnit::Select(Moho::UserEntity *this);
 *
 * What it does:
 * Evaluates whether this user unit is currently selectable by UI selectors.
 *
 * The first guard rejects a unit that is riding something: `mIsBusy`
 * (+0x1A2 == `mUnitVarDat` +0x0A) is the sim's "has an attach target" lane
 * (`Unit.cpp` sets it from `mAttachInfo.HasAttachTarget()`), so a *mobile*
 * passenger inside a transport is not individually selectable - while an
 * attached POD stays selectable, which is why the category test is the third
 * term of the same conjunction.
 *
 * The whole conjunction is one short-circuit chain at 0x008C0522..0x008C056D,
 * and its sense is the opposite of what a naive read of the decompile gives:
 *
 *   0x008C0522  mov al, [esi+1A2h] / test al, al / jz  loc_8C056F   ; -> continue
 *   0x008C052C  call [[esi+148h]+30h]  (IUnit slot 12, IsMobile)
 *   0x008C053D  test al, al           / jz  loc_8C056F              ; -> continue
 *   0x008C0562  call UserEntity::IsInCategory("POD")
 *   0x008C0569  mov [esp+var_65], bl  ; bl == 1  -> "reject"
 *   0x008C056D  jz  loc_8C0574        ; POD false keeps the reject flag set
 *   0x008C056F  mov [esp+var_65], 0   ; POD true clears it -> continue
 *   0x008C059C  cmp [esp+var_65], 0 / jz loc_8C05B6                 ; 0 == continue
 *
 * so the rejecting case is `busy && mobile && !POD`, not `!busy || !mobile`.
 */
bool UserUnit::IsSelectable() const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  if (iunitBridge == nullptr) {
    return false;
  }

  const UserEntity* const entityView = this;  // base conversion, not a reinterpretation


  const fa::string podCategory("POD", 3u);
  if (mUnitVarDat.mIsBusy && iunitBridge->IsMobile() && !entityView->IsInCategory(podCategory)) {
    return false;
  }

  if (IUnitBridgeIsUnitState(iunitBridge, UNITSTATE_UnSelectable)) {
    return false;
  }

  if (iunitBridge->IsDead()) {
    return false;
  }

  // FAF hot-patch: 0x008C05FE jumps to 0x01291439 in .exxt, which tests
  // "CQUEMOV" (string at 0x01292A9C, via the pointer at 0x01292A98) and goes
  // straight to the SELECTABLE test at 0x008C062A when it holds, before
  // falling back to the original "FACTORY" test at 0x008C0603. It is the UI
  // half of the 0x006EFAC9 patch in `ProcessIssuedUnitCommand` (Sim.cpp):
  // a CQUEMOV unit can be selected, and so given orders, while being built.
  if (IsBeingBuilt()) {
    const fa::string queueMoveCategory("CQUEMOV", 7u);
    const fa::string factoryCategory("FACTORY", 7u);
    if (!entityView->IsInCategory(queueMoveCategory) && !entityView->IsInCategory(factoryCategory)) {
      return false;
    }
  }

  const fa::string selectableCategory("SELECTABLE", 10u);
  return entityView->IsInCategory(selectableCategory);
}

/**
 * Address: 0x008C1350 (FUN_008C1350, moho::UserUnit::NotifyFocusArmyUnitDamaged)
 *
 * What it does:
 * Imports the game-main Lua module and calls
 * `OnFocusArmyUnitDamaged` with this unit's Lua object.
 */
void UserUnit::NotifyFocusArmyUnitDamaged()
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  LuaPlus::LuaObject gameMainModule = SCR_Import(session->mState, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject onFocusArmyUnitDamaged = gameMainModule["OnFocusArmyUnitDamaged"];
  LuaPlus::LuaFunction callback(onFocusArmyUnitDamaged);

  IUnit* const iunitBridge = GetIUnitBridge(this);
  const LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
  try {
    callback.Call_Object(unitObject);
  } catch (const std::exception& exception) {
    WarnFocusArmyUnitDamagedCallbackError(exception);
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnFocusArmyUnitDamaged': unknown exception");
  }
}

/**
 * Address: 0x0083EEC0 (FUN_0083EEC0, moho::UserUnit::DoOnDetectAdjacencyBonusFor)
 *
 * What it does:
 * Invokes `/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus(unitObject, blueprintObject)`
 * and returns the callback boolean result.
 */
bool UserUnit::DoOnDetectAdjacencyBonusFor(const RUnitBlueprint* const blueprint)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || blueprint == nullptr) {
    return false;
  }

  LuaPlus::LuaObject gameMainModule = SCR_Import(session->mState, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject onDetectAdjacencyBonus = gameMainModule["OnDetectAdjacencyBonus"];
  LuaPlus::LuaFunction callback(onDetectAdjacencyBonus);

  const LuaPlus::LuaObject blueprintObject = blueprint->GetLuaBlueprint(session->mState);
  IUnit* const iunitBridge = GetIUnitBridge(this);
  const LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();

  try {
    const LuaPlus::LuaObject callbackResult = callback.Call_Obj2_Obj(unitObject, blueprintObject);
    return callbackResult.GetBoolean();
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus': %s",
      exception.what() != nullptr ? exception.what() : "<unknown>"
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus': %s", "<unknown>");
  }

  return false;
}

/**
 * Address: 0x008C00E0 (FUN_008C00E0, moho::UserUnit::CreateMeshInstance)
 *
 * What it does:
 * Creates the unit mesh instance, applies team-color lookup parameter, and
 * wires animation poses from shared unit pose lanes when skeletons match.
 */
void UserUnit::CreateMeshInstance(const bool forUnitPose)
{
  UserEntity* const entityView = this;
  if (entityView == nullptr || entityView->mSession == nullptr) {
    return;
  }

  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const Unit* const unitView = iunitBridge ? iunitBridge->IsUnit() : nullptr;
  const SSTIUnitVariableData* const unitVarDat = unitView ? &unitView->VarDat() : nullptr;

  const UserArmy* const army = entityView->mArmy;
  const std::int32_t playerColor = army ? static_cast<std::int32_t>(army->mVarDat.mPlayerColorBgra) : -1;
  const std::int32_t colorIndex = army ? func_GetColorIndex(playerColor) : 0;

  const float uniformScale = GetUniformScale();
  const Wm3::Vec3f uniformMeshScale{uniformScale, uniformScale, uniformScale};

  entityView->mMeshInstance = MeshRenderer::GetInstance()->CreateMeshInstance(
    entityView->mSession->mGameTick,
    playerColor,
    static_cast<const RMeshBlueprint*>(entityView->mVariableData.mMeshBlueprint),
    uniformMeshScale,
    true,
    boost::shared_ptr<MeshMaterial>{}
  );

  if (entityView->mMeshInstance == nullptr) {
    entityView->mPosePrimary.reset();
    entityView->mPoseSecondary.reset();
    return;
  }

  std::uint32_t teamColorLookupCount = GetPlayerColorCount();
  if (teamColorLookupCount == 0u) {
    teamColorLookupCount = 1u;
  }

  const float lookupCount = static_cast<float>(teamColorLookupCount);
  float clampedColorIndex = static_cast<float>(colorIndex);
  const float maxColorIndex = lookupCount - 1.0f;
  if (clampedColorIndex > maxColorIndex) {
    clampedColorIndex = maxColorIndex;
  }
  if (clampedColorIndex < 0.0f) {
    clampedColorIndex = 0.0f;
  }
  entityView->mMeshInstance->meshColor = (clampedColorIndex + 0.5f) / lookupCount;

  const boost::shared_ptr<Mesh> mesh = entityView->mMeshInstance->GetMesh();
  const boost::shared_ptr<RScmResource> resource = mesh ? mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
  const boost::shared_ptr<const CAniSkel> skeleton = resource ? resource->GetSkeleton() : boost::shared_ptr<const CAniSkel>{};

  const boost::shared_ptr<CAniPose> priorSharedPose =
    unitVarDat ? unitVarDat->mPriorSharedPose : boost::shared_ptr<CAniPose>{};
  if (CanReuseSharedPoseForSkeleton(priorSharedPose, skeleton)) {
    entityView->mPosePrimary = priorSharedPose;
  } else {
    entityView->mPosePrimary.reset(new CAniPose(skeleton, uniformScale));
    if (entityView->mPosePrimary) {
      entityView->mPosePrimary->mLocalTransform = entityView->mVariableData.mLastTransform;
    }
  }

  const boost::shared_ptr<CAniPose> sharedPose = unitVarDat ? unitVarDat->mSharedPose : boost::shared_ptr<CAniPose>{};
  if (CanReuseSharedPoseForSkeleton(sharedPose, skeleton)) {
    entityView->mPoseSecondary = sharedPose;
  } else {
    entityView->mPoseSecondary.reset(new CAniPose(skeleton, uniformScale));
    if (entityView->mPoseSecondary) {
      entityView->mPoseSecondary->mLocalTransform = entityView->mVariableData.mCurTransform;
    }
  }
}

/**
 * Address: 0x008C04D0 (FUN_008C04D0, j_?DestroyMeshInstance@UserEntity@Moho@@MAEXXZ)
 *
 * What it does:
 * Forwards user-unit mesh teardown to the base `UserEntity` destroy path.
 */
void UserUnit::DestroyMeshInstance()
{
  UserEntity* const entityView = this;
  entityView->UserEntity::DestroyMeshInstance();
}

/**
 * Address: 0x008BFC50 (FUN_008BFC50)
 *
 * What it does:
 * Aggregates weapon min/max radii over runtime weapon entries filtered by
 * range category (`6` means match all categories).
 */
bool UserUnit::FindWeaponBy(
  const std::int32_t rangeCategoryFilter, float* const outMinRange, float* const outMaxRange
) const
{
  constexpr float kInitialMinRangeSentinel = std::numeric_limits<float>::max();
  constexpr float kInitialMaxRangeSentinel = std::numeric_limits<float>::lowest();

  *outMaxRange = kInitialMaxRangeSentinel;
  *outMinRange = kInitialMinRangeSentinel;

  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const auto& weaponBlueprints = blueprint->Weapons.WeaponBlueprints;
  const UnitWeaponInfo* const weaponRuntime = mUnitVarDat.mWeaponInfo.data();

  for (std::size_t i = 0; i < weaponBlueprints.size(); ++i) {
    const auto& weaponBlueprint = weaponBlueprints[i];
    if (rangeCategoryFilter != kRangeCategoryAll &&
        rangeCategoryFilter != static_cast<std::int32_t>(weaponBlueprint.RangeCategory)) {
      continue;
    }

    const auto& weaponStats = weaponRuntime[weaponBlueprint.WeaponIndex];
    if (weaponStats.mMaxRadius > *outMaxRange) {
      *outMaxRange = weaponStats.mMaxRadius;
    }
    if (weaponStats.mMinRadius <= *outMinRange) {
      *outMinRange = weaponStats.mMinRadius;
    }
  }

  if (*outMaxRange <= kInitialMaxRangeSentinel) {
    *outMaxRange = 0.0f;
  }
  if (kInitialMinRangeSentinel <= *outMinRange) {
    *outMinRange = 0.0f;
  }

  return *outMaxRange > 0.0f || *outMinRange > 0.0f;
}

/**
 * Address: 0x008BFD70 (FUN_008BFD70)
 *
 * What it does:
 * Returns active intel ranges (`omni`, `radar`, `sonar`) unless Intel toggle
 * state currently disables this intel block.
 */
bool UserUnit::GetIntelRanges(float* const outOmniRange, float* const outRadarRange, float* const outSonarRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if ((toggleCaps & kToggleCapIntel) != 0u && (mUnitVarDat.mScriptbits & kToggleCapIntel) != 0u) {
    return false;
  }

  *outOmniRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::Sonar);
  *outRadarRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::WaterVision);
  *outSonarRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::Radar);

  return *outOmniRange > 0.0f || *outRadarRange > 0.0f || *outSonarRange > 0.0f;
}

/**
 * Address: 0x008BFE50 (FUN_008BFE50)
 *
 * What it does:
 * Computes the largest active counter-intel radius from replicated intel
 * ranges plus blueprint jam/spoof maxima.
 */
bool UserUnit::GetMaxCounterIntel(float* const outMaxCounterIntelRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if (((toggleCaps & kToggleCapJamming) != 0u && (mUnitVarDat.mScriptbits & kToggleCapJamming) != 0u) ||
      ((toggleCaps & kToggleCapStealth) != 0u && (mUnitVarDat.mScriptbits & kToggleCapStealth) != 0u)) {
    return false;
  }

  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const std::uint32_t spoofRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::Spoof);
  const std::uint32_t cloakRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::Cloak);
  const std::uint32_t radarStealthRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::RadarStealth);

  std::uint32_t maxCounterIntel = radarStealthRange;
  if (maxCounterIntel < cloakRange) {
    maxCounterIntel = cloakRange;
  }

  std::uint32_t maxJamOrSpoof = blueprint->Intel.SpoofRadius.max;
  if (maxJamOrSpoof < blueprint->Intel.JamRadius.max) {
    maxJamOrSpoof = blueprint->Intel.JamRadius.max;
  }
  if (maxCounterIntel < maxJamOrSpoof) {
    maxCounterIntel = maxJamOrSpoof;
  }
  if (maxCounterIntel < spoofRange) {
    maxCounterIntel = spoofRange;
  }

  *outMaxCounterIntelRange = static_cast<float>(maxCounterIntel);
  return *outMaxCounterIntelRange > 0.0f;
}

/**
 * Address: 0x008BEFD0 (FUN_008BEFD0)
 *
 * What it does:
 * Returns UI mirror of auto-mode state.
 */
bool UserUnit::GetAutoMode() const
{
  return mUnitVarDat.mAutoMode;
}

/**
 * Address: 0x008BEFE0 (FUN_008BEFE0)
 *
 * What it does:
 * Returns UI mirror of auto-surface mode state.
 */
bool UserUnit::IsAutoSurfaceMode() const
{
  return mUnitVarDat.mAutoSurfaceMode;
}

/**
 * Address: 0x008BEFF0 (FUN_008BEFF0)
 *
 * What it does:
 * Returns UI mirror of repeat-queue state.
 */
bool UserUnit::Func1() const
{
  return mUnitVarDat.mRepeatQueue;
}

/**
 * Address: 0x008BF000 (FUN_008BF000)
 *
 * What it does:
 * Returns whether overcharge is currently paused in UI state.
 */
bool UserUnit::IsOverchargePaused() const
{
  return mUnitVarDat.mOverchargePaused;
}

/**
 * Address: 0x008BF010 (FUN_008BF010)
 *
 * What it does:
 * Returns the in-object custom-name storage anchor at +0x1DC.
 */
char* UserUnit::GetCustomName()
{
  return reinterpret_cast<char*>(&mUnitVarDat.mCustomName);
}

/**
 * Address: 0x008BF060 (FUN_008BF060)
 *
 * What it does:
 * Returns UI fuel ratio.
 */
float UserUnit::GetFuel() const
{
  return mUnitVarDat.mFuelRatio;
}

/**
 * Address: 0x008BF070 (FUN_008BF070)
 *
 * What it does:
 * Returns UI shield ratio.
 */
float UserUnit::GetShield() const
{
  return mUnitVarDat.mShieldRatio;
}

/**
 * Address: 0x00893080 (FUN_00893080)
 *
 * What it does:
 * Inserts one selection-set name into this unit's persisted selection-set
 * container.
 */
void UserUnit::AddSelectionSet(const char* const selectionSetName)
{
  fa::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  (void)mSelectionSets.insert(selectionSet);
}

/**
 * Address: 0x008BFF30 (FUN_008BFF30, Moho::UserUnit::AddToSelectionSet)
 *
 * IDA signature:
 * void __stdcall Moho::UserUnit::AddToSelectionSet(Moho::UserUnit *a1, Moho::UserUnit *a2);
 *
 * What it does:
 * Hands every selection-set name owned by `source` to `target`, and tells the UI
 * about each one through `/lua/ui/game/selection.lua:AddUnitToSelectionSet`.
 * Called when a unit leaves play and its successor takes over its named sets
 * (0x008BFAEE), and when a freshly replicated unit inherits them from the
 * factory that built it (0x008C0956).
 */
void UserUnit::AddToSelectionSet(UserUnit* const target, UserUnit* const source)
{
  if (source == nullptr) {
    return;
  }

  // 0x008BFF41: the source's names are snapshotted before anything is added to
  // the target, so the walk is stable even when `target == source`.
  const fa::set<fa::string> inheritedNames = source->mSelectionSets;

  LuaPlus::LuaObject selectionModule =
    SCR_Import(WLD_GetActiveSession()->mState, "/lua/ui/game/selection.lua");
  LuaPlus::LuaObject addUnitToSelectionSet = selectionModule["AddUnitToSelectionSet"];
  LuaPlus::LuaFunction callback(addUnitToSelectionSet);

  // 0x008BFF9E: the bridge is resolved once, but `GetLuaObject` is dispatched
  // per name because the call below consumes the object.
  IUnit* const targetBridge = GetIUnitBridge(target);
  for (const fa::string& selectionSetName : inheritedNames) {
    target->AddSelectionSet(selectionSetName.c_str());
    const LuaPlus::LuaObject targetObject = targetBridge->GetLuaObject();
    callback.Call_StringObject(std::string(selectionSetName.c_str(), selectionSetName.size()), targetObject);
  }
}

/**
 * Address: 0x008BF190 (FUN_008BF190)
 *
 * What it does:
 * Removes one selection-set name from this unit's persisted selection-set
 * container.
 */
void UserUnit::RemoveSelectionSet(const char* const selectionSetName)
{
  fa::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  (void)mSelectionSets.erase(selectionSet);
}

/**
 * Address: 0x008C5B90 (FUN_008C5B90, fa::set<fa::string>::find)
 *
 * What it does:
 * Per-T canonical-template-helper binding for the engine-instantiated
 * `fa::set<fa::string>::find(const key&)` _Tree::_Lbound walk +
 * key-equal check body. Returns the iterator to the matching node or
 * `end()` if the key is not present.
 *
 * Used by `UserUnit::HasSelectionSet` (FUN_008BF220, the only recovered
 * caller of FUN_008C5B90 in the binary) to preserve the MSVC8 per-T
 * `_Tree::find` template emission symbol shape even when the modern
 * compiler would inline the natural `mSelectionSets.find(...)` call.
 */
fa::set<fa::string>::iterator FindStringSetEntry(
  const fa::set<fa::string>& storage,
  const fa::string& key)
{
  return storage.find(key);
}

/**
 * Address: 0x008BF220 (FUN_008BF220)
 *
 * What it does:
 * Returns whether this unit currently stores one named selection-set key.
 * Routes the per-T `fa::set<fa::string>::find` through the named
 * helper (FUN_008C5B90) to preserve the MSVC8 template emission symbol.
 */
bool UserUnit::HasSelectionSet(const char* const selectionSetName) const
{
  fa::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  return FindStringSetEntry(mSelectionSets, selectionSet) != mSelectionSets.end();
}

bool UserUnit::IsRepeatQueueEnabled() const
{
  return Func1();
}

/**
 * Address: 0x008C0D30 (FUN_008C0D30, Moho::UserUnit::CanAttackTarget)
 *
 * What it does:
 * Evaluates attack viability against one optional target entity by applying
 * movement-layer overlays, weapon layer/category filters, and optional
 * range-gating checks.
 */
bool UserUnit::CanAttackTarget(const UserEntity* targetEntity, bool rangeCheck) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const UserEntity* const selfEntity = this;
  const REntityBlueprint* const targetBlueprint = (targetEntity != nullptr) ? targetEntity->mParams.mBlueprint : nullptr;

  if (targetBlueprint != nullptr) {
    if (iunitBridge->IsMobile() && targetEntity != nullptr) {
      const std::uint32_t targetLayerMask = targetEntity->mVariableData.mLayerMask;

      if (mUnitVarDat.mAutoSurfaceMode) {
        if ((targetLayerMask & static_cast<std::uint32_t>(LAYER_Air)) != 0u
            && IsUnitInOverlayCategory(this, kOverlayCategoryAntiAir)) {
          return true;
        }
        if ((targetLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u
            && IsUnitInOverlayCategory(this, kOverlayCategoryDirectFire)) {
          return true;
        }
      }

      const std::uint32_t selfLayerMask = selfEntity->mVariableData.mLayerMask;
      const RUnitBlueprint* const selfBlueprint = iunitBridge->GetBlueprint();
      const bool selfOnLand = (selfLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u;
      const bool selfOnSeabed = (selfLayerMask & static_cast<std::uint32_t>(LAYER_Seabed)) != 0u;
      const bool targetUnderwater = (targetLayerMask
                                     & (static_cast<std::uint32_t>(LAYER_Sub) | static_cast<std::uint32_t>(LAYER_Seabed)))
                                    != 0u;
      const bool targetOnLand = (targetLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u;

      if (selfOnLand && targetUnderwater) {
        const ERuleBPUnitMovementType motionType = selfBlueprint->Physics.MotionType;
        if ((motionType == RULEUMT_Amphibious || motionType == RULEUMT_AmphibiousFloating)
            && IsUnitInOverlayCategory(this, kOverlayCategoryAntiNavy)) {
          return true;
        }
      } else if (selfOnSeabed && targetOnLand
                 && selfBlueprint->Physics.MotionType == RULEUMT_Amphibious
                 && IsUnitInOverlayCategory(this, kOverlayCategoryDirectFire)) {
        return true;
      }
    }

    const float targetDistance = rangeCheck
      ? PlanarDistanceXZ(selfEntity->mVariableData.mCurTransform.pos_, targetEntity->mVariableData.mCurTransform.pos_)
      : 0.0f;
    const std::uint32_t targetLayerMask = targetEntity->mVariableData.mLayerMask;

    const UnitWeaponInfo* weaponInfo = GetWeaponInfoBegin(this);
    const UnitWeaponInfo* const weaponInfoEnd = GetWeaponInfoEnd(this);
    while (weaponInfo != weaponInfoEnd) {
      if ((static_cast<std::uint32_t>(weaponInfo->mLayer) & targetLayerMask) != 0u
          && WeaponAllowsBlueprint(*weaponInfo, targetBlueprint)) {
        if (iunitBridge->IsMobile() || !rangeCheck
            || (weaponInfo->mMinRadius <= targetDistance && targetDistance <= weaponInfo->mMaxRadius)) {
          return true;
        }
      }
      ++weaponInfo;
    }
    return false;
  }

  if (!rangeCheck) {
    return false;
  }

  if (iunitBridge->IsMobile()) {
    return true;
  }

  CWldSession* const activeSession = WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return false;
  }

  const float cursorDistance = PlanarDistanceXZ(selfEntity->mVariableData.mCurTransform.pos_, activeSession->CursorWorldPos);
  const UnitWeaponInfo* weaponInfo = GetWeaponInfoBegin(this);
  const UnitWeaponInfo* const weaponInfoEnd = GetWeaponInfoEnd(this);
  while (weaponInfo != weaponInfoEnd) {
    if (cursorDistance > weaponInfo->mMinRadius && weaponInfo->mMaxRadius > cursorDistance) {
      return true;
    }
    ++weaponInfo;
  }

  return false;
}

/**
 * Address: 0x008C1880 (FUN_008C1880, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@_NPAUSBuildInfo@1@PBVUserCommand@1@@Z)
 *
 * What it does:
 * Runs world-space placement validation, then rejects placements that overlap
 * visible static or still-being-built unit skirts or queued mobile-build
 * command skirts.
 */
bool moho::USERUNIT_CanBeBuiltAt(
  CWldSession& session,
  const RUnitBlueprint* const buildBlueprint,
  const SCoordsVec2& buildPosition,
  const bool allowCommandOverlap,
  SOccupationResult* const buildInfo,
  const UserCommand* const ignoredCommand
)
{
  (void)allowCommandOverlap;

  auto* const map = session.mWldMap->mTerrainRes->mMap;
  auto* const resources = reinterpret_cast<ISimResources*>(session.mSimResources.px);
  if (!OCCUPY_Check(*map, *buildBlueprint, buildPosition, *resources, *buildInfo)) {
    return false;
  }

  const SCoordsVec2 candidatePosition{buildInfo->pos.x, buildInfo->pos.z};
  const gpg::Rect2f candidateSkirt = buildBlueprint->GetSkirtRect(candidatePosition);
  const gpg::Rect2i& playableRect = map->mPlayableRect;
  if (static_cast<float>(playableRect.x0 + 2) >= candidateSkirt.x0
      || static_cast<float>(playableRect.z0 + 2) >= candidateSkirt.z0
      || candidateSkirt.x1 >= static_cast<float>(playableRect.x1 - 2)
      || candidateSkirt.z1 >= static_cast<float>(playableRect.z1 - 2)) {
    return false;
  }

  Wm3::AxisAlignedBox3f overlapQuery{};
  overlapQuery.Min.x = candidateSkirt.x0 - 8.0f;
  overlapQuery.Min.y = -std::numeric_limits<float>::max();
  overlapQuery.Min.z = candidateSkirt.z0 - 8.0f;
  overlapQuery.Max.x = candidateSkirt.x1 + 8.0f;
  overlapQuery.Max.y = std::numeric_limits<float>::max();
  overlapQuery.Max.z = candidateSkirt.z1 + 8.0f;

  constexpr std::uint32_t kIntelVisibleMask = 0x08u;
  // Heap-backed: `CollectInBox`/`Collect` take the base `gpg::fastvector<T>&`,
  // whose grow path frees `start_` without an `originalVec_` test. See the
  // note in CWldSession::DoBeat.
  gpg::fastvector<UserEntity*> nearbyUnits{};
  auto* const spatialStorage = session.GetEntitySpatialDbStorage();
  spatialStorage->CollectInBox(nearbyUnits, overlapQuery);

  for (UserEntity* const nearbyEntity : nearbyUnits) {
    UserUnit* const nearbyUnit = nearbyEntity != nullptr ? nearbyEntity->IsUserUnit() : nullptr;
    if (nearbyUnit == nullptr || (nearbyUnit->mIntelStateFlags & kIntelVisibleMask) == 0u) {
      continue;
    }

    const IUnit* const iunitBridge = GetIUnitBridge(nearbyUnit);
    const RUnitBlueprint* const nearbyBlueprint = iunitBridge->GetBlueprint();
    // 0x008C1880: the binary tests `IsBeingBuilt()` here, not `IsDead()`, so a
    // mobile unit still under construction blocks with its blueprint skirt.
    if (!nearbyBlueprint->IsMobile() || nearbyUnit->IsBeingBuilt()) {
      gpg::Rect2f nearbySkirt{};
      if (nearbyUnit->GetSkirt(&nearbySkirt)->Overlaps(candidateSkirt)) {
        return false;
      }
    }
  }

  auto* const commandManager = session.mCommandManager;
  if (commandManager == nullptr) {
    return true;
  }

  for (const auto& [issueCommandId, issueHelper] : commandManager->mCommands) {
    auto* const helper = issueHelper;
    if (helper == nullptr || ResolveHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile) {
      continue;
    }

    if (ignoredCommand != nullptr && reinterpret_cast<const UserCommand*>(helper) == ignoredCommand) {
      continue;
    }

    gpg::RRef buildBlueprintRef{};
    buildBlueprintRef = gpg::MakeRRef<moho::REntityBlueprint>(helper->mConstantData.blueprint);
    // Object reference in, object pointer out (it is handed to `GetSkirtRect`
    // below), so the upcast target is the class descriptor - the same one
    // `RefreshQueuedBuildGhosts` uses on this exact blueprint lane, and the
    // one the binary's `RRef::Upcast_RUnitBlueprint` resolves through
    // `LookupRType(typeid(RUnitBlueprint))`. Aimed at `GetPointerType()` - the
    // descriptor for `RUnitBlueprint*` - the walk over the object's bases can
    // never match, so `mObj` came back null for every queued order and this
    // loop skipped all of them. That is why two queued buildings could be
    // placed overlapping, or one inside another: the footprint test that
    // rejects it is right here and was never reached.
    const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(buildBlueprintRef, RUnitBlueprint::StaticGetClass());
    const auto* const queuedBuildBlueprint = static_cast<const RUnitBlueprint*>(unitBlueprintRef.mObj);
    if (queuedBuildBlueprint == nullptr) {
      continue;
    }

    const Wm3::Vector3<float> queuedTarget = ResolveHelperTargetPosition(*helper, &session);
    const SCoordsVec2 queuedPosition{queuedTarget.x, queuedTarget.z};
    const gpg::Rect2f queuedSkirt = queuedBuildBlueprint->GetSkirtRect(queuedPosition);
    if (queuedSkirt.Overlaps(candidateSkirt)) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x008C1BC0 (FUN_008C1BC0, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSOCellPos@1@_NPAUSBuildInfo@1@@Z)
 *
 * What it does:
 * Converts one cell-origin placement probe into world-space center
 * coordinates and forwards to the world-space buildability path.
 */
bool moho::USERUNIT_CanBeBuiltAt(
  CWldSession& session,
  const RUnitBlueprint* const buildBlueprint,
  const SOCellPos& cellPosition,
  const bool allowCommandOverlap,
  SOccupationResult* const buildInfo
)
{
  const float halfSizeX = static_cast<float>(buildBlueprint->mFootprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(buildBlueprint->mFootprint.mSizeZ) * 0.5f;

  const SCoordsVec2 buildPosition{
    static_cast<float>(cellPosition.x) + halfSizeX,
    static_cast<float>(cellPosition.z) + halfSizeZ,
  };

  return USERUNIT_CanBeBuiltAt(
    session,
    buildBlueprint,
    buildPosition,
    allowCommandOverlap,
    buildInfo,
    nullptr
  );
}

/**
 * Address: 0x008C1430 (FUN_008C1430, ?USERUNIT_CanOccupy@Moho@@YA_NAAVCWldSession@1@ABUSFootprint@1@AAUSOCellPos@1@@Z)
 *
 * What it does:
 * Validates one candidate occupancy rectangle against map bounds and rejects
 * placement if it overlaps a visible non-mobile unit footprint in the spatial
 * database.
 */
bool moho::USERUNIT_CanOccupy(CWldSession& session, const SFootprint& footprint, SOCellPos& position)
{
  const std::int16_t cellX = position.x;
  if (cellX < 0 || position.z < 0) {
    return false;
  }

  STIMap* const map = session.mWldMap->mTerrainRes->mMap;
  CHeightField* const field = map->GetHeightField();

  const std::int32_t rectX1 = static_cast<std::int32_t>(cellX) + static_cast<std::int32_t>(footprint.mSizeX);
  if (rectX1 >= (field->width - 1)) {
    return false;
  }

  const std::int32_t rectZ1 = static_cast<std::int32_t>(position.z) + static_cast<std::int32_t>(footprint.mSizeZ);
  if (rectZ1 >= (field->height - 1)) {
    return false;
  }

  const gpg::Rect2i queryRect{
    static_cast<std::int32_t>(cellX),
    static_cast<std::int32_t>(position.z),
    rectX1,
    rectZ1,
  };

  constexpr EEntityType kSpatialTypeUnit = static_cast<EEntityType>(0x00000100u);
  constexpr std::uint32_t kIntelVisibleMask = 0x08u;

  // Heap-backed: `CollectInBox`/`Collect` take the base `gpg::fastvector<T>&`,
  // whose grow path frees `start_` without an `originalVec_` test. See the
  // note in CWldSession::DoBeat.
  gpg::fastvector<UserEntity*> nearbyUnits{};
  auto* const spatialStorage = session.GetEntitySpatialDbStorage();
  spatialStorage->Collect(nearbyUnits, kSpatialTypeUnit);

  for (UserEntity* const nearbyEntity : nearbyUnits) {
    auto* const nearbyUserUnit = static_cast<UserUnit*>(nearbyEntity);
    const IUnit* const iunitBridge = GetIUnitBridge(nearbyUserUnit);
    const RUnitBlueprint* const unitBlueprint = iunitBridge->GetBlueprint();
    if (unitBlueprint->IsMobile() || (nearbyUserUnit->mIntelStateFlags & kIntelVisibleMask) == 0u) {
      continue;
    }

    const SFootprint& nearbyFootprint = unitBlueprint->mFootprint;
    const SOCellPos nearbyCell = nearbyFootprint.ToCellPos(nearbyEntity->mVariableData.mCurTransform.pos_);
    const gpg::Rect2i nearbyRect{
      static_cast<std::int32_t>(nearbyCell.x),
      static_cast<std::int32_t>(nearbyCell.z),
      static_cast<std::int32_t>(nearbyCell.x) + static_cast<std::int32_t>(nearbyFootprint.mSizeX),
      static_cast<std::int32_t>(nearbyCell.z) + static_cast<std::int32_t>(nearbyFootprint.mSizeZ),
    };

    if (queryRect.Overlaps(nearbyRect)) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x008C1610 (FUN_008C1610, ?USERUNIT_WithinBuildDistance@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@@Z)
 *
 * What it does:
 * Checks whether all selected user units are within each unit's own
 * `Economy.MaxBuildDistance` from the snapped world-space center of one
 * candidate blueprint footprint.
 */
bool moho::USERUNIT_WithinBuildDistance(
  CWldSession& session, const RUnitBlueprint* const buildBlueprint, const SCoordsVec2& buildPosition
)
{
  fa::vector<UserUnit*> selectedUnits{};
  session.GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    return false;
  }

  const float halfSizeX = static_cast<float>(buildBlueprint->mFootprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(buildBlueprint->mFootprint.mSizeZ) * 0.5f;
  const std::int32_t anchorCellX = static_cast<std::int32_t>(buildPosition.x - halfSizeX);
  const std::int32_t anchorCellZ = static_cast<std::int32_t>(buildPosition.z - halfSizeZ);

  const float snappedBuildCenterX = static_cast<float>(anchorCellX) + halfSizeX;
  const float snappedBuildCenterZ = static_cast<float>(anchorCellZ) + halfSizeZ;

  for (std::size_t i = 0; i < selectedUnits.size(); ++i) {
    UserUnit* const selected = selectedUnits[i];
    if (selected == nullptr) {
      continue;
    }

    const IUnit* const iunit = GetIUnitBridge(selected);
    const RUnitBlueprint* const selectedBlueprint = iunit->GetBlueprint();
    const float maxBuildDistance = selectedBlueprint->Economy.MaxBuildDistance;
    if (maxBuildDistance <= 0.0f) {
      continue;
    }

    const Wm3::Vec3f& unitPosition = iunit->GetPosition();
    const float dx = unitPosition.x - snappedBuildCenterX;
    const float dz = unitPosition.z - snappedBuildCenterZ;
    const float planarDistance = std::sqrt((dx * dx) + (dz * dz));
    if (planarDistance > maxBuildDistance) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x008C1C30 (FUN_008C1C30, ?USERUNIT_GetBounds@Moho@@YA?AV?$AxisAlignedBox3@M@Wm3@@PBVRUnitBlueprint@1@ABV?$Vector3@M@3@@Z)
 *
 * What it does:
 * Builds one world-space unit bounds AABB from collision offsets/sizes for
 * mobile blueprints, and from skirt-rectangle extents for non-mobile
 * blueprints.
 */
Wm3::AxisAlignedBox3f moho::USERUNIT_GetBounds(
  const RUnitBlueprint* const unitBlueprint,
  const Wm3::Vector3f& worldPosition
)
{
  Wm3::AxisAlignedBox3f bounds{};

  if (unitBlueprint->IsMobile()) {
    const float minX =
      (worldPosition.x + unitBlueprint->mCollisionOffsetX) - (unitBlueprint->mSizeX * 0.5f);
    const float minY = worldPosition.y + unitBlueprint->mCollisionOffsetY;
    const float minZ =
      (worldPosition.z + unitBlueprint->mCollisionOffsetZ) - (unitBlueprint->mSizeZ * 0.5f);

    bounds.Min.x = minX;
    bounds.Min.y = minY;
    bounds.Min.z = minZ;
    bounds.Max.x = minX + unitBlueprint->mSizeX;
    bounds.Max.y = minY + unitBlueprint->mSizeY;
    bounds.Max.z = minZ + unitBlueprint->mSizeZ;
    return bounds;
  }

  const SCoordsVec2 footprintPosition{worldPosition.x, worldPosition.z};
  const gpg::Rect2f skirtRect = unitBlueprint->GetSkirtRect(footprintPosition);

  bounds.Min.x = skirtRect.x0;
  bounds.Min.y = worldPosition.y;
  bounds.Min.z = skirtRect.z0;
  bounds.Max.x = skirtRect.x1;
  bounds.Max.y = worldPosition.y + unitBlueprint->mSizeY;
  bounds.Max.z = skirtRect.z1;
  return bounds;
}
