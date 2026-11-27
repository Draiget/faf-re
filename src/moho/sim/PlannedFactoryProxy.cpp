#include "moho/sim/PlannedFactoryProxy.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/command/ClientOnlyIds.h"
#include "moho/command/CommandManager.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/UserCommandQueue.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{
  // Defined with `ISSUE_Command` (UserCommandIssue.cpp); `T* const` parameters, see CWldSessionCommands.cpp.
  [[nodiscard]] std::uint32_t*
  AllocatePackedCommandIdFromManager(CommandManager* const commandManager, std::uint32_t* const outCommandId) noexcept;

  namespace
  {
    /// A planned factory and a new unit with its blueprint are the same structure within this distance
    /// (x, z). The sim builds at the order's position, so they meet exactly; the slack covers float noise.
    constexpr float kNewUnitMatchDistance = 2.0f;
    /// Two build orders of one blueprint within this distance (x, z) are for the same factory.
    constexpr float kSameSiteDistance = 1.0f;
    /// Beats in a row a builder's command may be missing from its queue before the builder is dropped.
    constexpr std::uint8_t kBuilderGraceBeats = 3;

    [[nodiscard]] float GroundDistanceSq(
      const Vector3f& a,
      const Vector3f& b
    ) noexcept
    {
      const float dx = a.x - b.x;
      const float dz = a.z - b.z;
      return (dx * dx) + (dz * dz);
    }

    [[nodiscard]] Vector3f PositionOf(
      const UserEntity& entity
    ) noexcept
    {
      const Wm3::Vec3f& pos = entity.mVariableData.mCurTransform.pos_;
      return Vector3f{pos.x, pos.y, pos.z};
    }

    /// Half the footprint (x, z) of a planned factory: its skirt, or a T1 factory's when the blueprint has none.
    void FootprintHalfSize(
      const REntityBlueprint* const bp,
      float& halfX,
      float& halfZ
    ) noexcept
    {
      halfX = 4.0f;
      halfZ = 4.0f;
      if (const auto* const unitBp = dynamic_cast<const RUnitBlueprint*>(bp)) {
        if (unitBp->Physics.SkirtSizeX > 0.0f) {
          halfX = unitBp->Physics.SkirtSizeX * 0.5f;
        }
        if (unitBp->Physics.SkirtSizeZ > 0.0f) {
          halfZ = unitBp->Physics.SkirtSizeZ * 0.5f;
        }
      }
    }

    [[nodiscard]] UserUnit* LookupUserUnit(
      CWldSession& session,
      const std::uint32_t entityId
    )
    {
      UserEntity* const entity = session.LookupEntityId(static_cast<EntId>(entityId));
      return entity != nullptr ? entity->IsUserUnit() : nullptr;
    }

    [[nodiscard]] bool IsFactoryBlueprint(
      const CWldSession& session,
      const REntityBlueprint* const bp
    )
    {
      if (bp == nullptr || session.mRules == nullptr) {
        return false;
      }
      // A factory structure: mobile factories (experimentals, carriers) are units the engineer builds.
      const EntityCategorySet* const factories = session.mRules->GetEntityCategory("FACTORY");
      const EntityCategorySet* const structures = session.mRules->GetEntityCategory("STRUCTURE");
      return factories != nullptr && structures != nullptr && EntityCategory::HasBlueprint(bp, factories) &&
        EntityCategory::HasBlueprint(bp, structures);
    }

    /// Whether a unit of the focus army with blueprint `bp` already stands at `pos`.
    [[nodiscard]] bool OwnUnitStandsAt(
      CWldSession& session,
      const REntityBlueprint* const bp,
      const Vector3f& pos
    )
    {
      const UserArmy* const focusArmy = session.GetFocusUserArmy();
      gpg::fastvector<UserEntity*> units;
      (void)session.GetEntitySpatialDbStorage()->Collect(units, ENTITYTYPE_Unit);
      for (UserEntity* const entity : units) {
        const UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        if (
          unit != nullptr && !PlannedFactoryManager::IsPlannedProxyUnit(unit) && unit->mArmy == focusArmy &&
          unit->mParams.mBlueprint == bp && unit->mVariableData.mIsDead == 0 &&
          GroundDistanceSq(PositionOf(*unit), pos) <= kNewUnitMatchDistance * kNewUnitMatchDistance
        ) {
          return true;
        }
      }
      return false;
    }

    /// Puts `replacement` (or nothing) in `from`'s place in the selection, when `from` is selected.
    void ReplaceInSelection(
      CWldSession& session,
      UserUnit* const from,
      UserUnit* const replacement
    )
    {
      if (session.mSelection.Find(from) == session.mSelection.end()) {
        return;
      }
      WeakSet<UserEntity> selection = session.GetSelection();
      (void)selection.Remove(from);
      if (replacement != nullptr) {
        (void)selection.Add(replacement);
      }
      session.SetSelection(selection);
    }

    /// The client-only unit that shows a planned factory: zero health and progress, no strategic icon,
    /// bounds of the blueprint's skirt so the world view can hover it.
    [[nodiscard]] UserUnit* CreateProxyUnit(
      CWldSession& session,
      const PlannedUnitProxy& proxy
    )
    {
      UserArmy* const focusArmy = session.GetFocusUserArmy();
      SCreateUnitParams createParams{};
      createParams.mBlueprint = proxy.mBlueprint;
      createParams.mEntityId =
        static_cast<EntId>(MakePlannedProxyUnitId(static_cast<std::uint8_t>(focusArmy->mArmyIndex), proxy.mProxyId));
      createParams.mTickCreated = session.mGameTick;
      // A sim unit's stats root comes with its create packet; FAF's UI reads stats of every selected unit
      // (UserUnit:GetStat), so this unit needs one of its own, empty.
      createParams.mConstDat.mStatsRoot.reset(new Stats<StatItem>(), [](Stats<StatItem>* const root) {
        GPG_NONVIRTUAL_DESTROY(delete root);
      });

      auto* const unit = new UserUnit(&session, createParams);
      unit->mArmy = focusArmy;
      const Wm3::Vec3f pos{proxy.mPosition.x, proxy.mPosition.y, proxy.mPosition.z};
      const Wm3::Quatf identity{0.0f, 0.0f, 0.0f, 1.0f};
      unit->mTransform.pos_ = pos;
      unit->mTransform.orient_ = identity;
      unit->mVariableData.mCurTransform.pos_ = pos;
      unit->mVariableData.mCurTransform.orient_ = identity;
      unit->mVariableData.mLastTransform.pos_ = pos;
      unit->mVariableData.mLastTransform.orient_ = identity;
      unit->mVariableData.mCurImpactValue = 1.0f;
      unit->mLastInterpAmt = 0.0f;
      unit->mVariableData.mFractionComplete = 0.0f;
      unit->mVariableData.mHealth = 0.0f;
      unit->mVariableData.mMaxHealth = 0.0f;
      constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
      unit->mIntelStateFlags |= kStrategicIconEntitySuppressedMask;

      if (const auto* const unitBp = dynamic_cast<const RUnitBlueprint*>(proxy.mBlueprint); unitBp != nullptr) {
        if (session.mRules != nullptr) {
          unit->mUnitVarDat.mAttributes = UnitAttributes(unitBp, session.mRules);
        }
      }

      float halfX = 0.0f;
      float halfZ = 0.0f;
      FootprintHalfSize(proxy.mBlueprint, halfX, halfZ);
      Wm3::AxisAlignedBox3f bounds;
      bounds.Min = {pos.x - halfX, pos.y - 1.0f, pos.z - halfZ};
      bounds.Max = {pos.x + halfX, pos.y + 4.0f, pos.z + halfZ};
      unit->mSpatialDbEntry.UpdateBounds(bounds);

      session.AddEntity(unit);
      RegisterClientOnlyUnit(static_cast<std::uint32_t>(createParams.mEntityId));
      return unit;
    }

    /// Deletes one rally-line helper and returns its id to the command id pool and out of the client-only set.
    void DeleteRallyHelper(
      CWldSession* const session,
      RallyPointOrder& order
    )
    {
      if (order.helperId == 0) {
        return;
      }
      if (session != nullptr && session->mCommandManager != nullptr) {
        fa::vector<CmdId> ids;
        ids.push_back(static_cast<CmdId>(order.helperId));
        DeleteCommandIssueHelpers(*session->mCommandManager, ids);
      }
      ReleaseClientOnlyCommand(order.helperId);
      order.helperId = 0;
    }

    /// Deletes the rally-line helpers the proxy owns. Without a session (its end) only the ids are released:
    /// the session deletes its helpers itself, and the next one hands the same ids out again.
    void DeleteRallyHelpers(
      CWldSession* const session,
      PlannedUnitProxy& proxy
    )
    {
      for (RallyPointOrder& order : proxy.mRallyOrders) {
        DeleteRallyHelper(session, order);
      }
    }
  } // namespace

  void PlannedUnitProxy::AddPreOrder(
    const std::string& bpId,
    const std::int32_t count
  )
  {
    if (bpId.empty() || count <= 0) {
      return;
    }
    if (!mPreOrders.empty() && mPreOrders.back().blueprintId == bpId) {
      mPreOrders.back().count += count;
    } else {
      mPreOrders.push_back(PreOrder{bpId, count});
    }
  }

  bool PlannedUnitProxy::RemovePreOrderByIndex(
    const std::size_t index,
    const std::int32_t count
  )
  {
    if (index >= mPreOrders.size() || count <= 0) {
      return false;
    }
    if (mPreOrders[index].count <= count) {
      mPreOrders.erase(mPreOrders.begin() + static_cast<std::ptrdiff_t>(index));
    } else {
      mPreOrders[index].count -= count;
    }
    return true;
  }

  void PlannedUnitProxy::ClearPreOrders() noexcept
  {
    mPreOrders.clear();
  }

  void PlannedUnitProxy::AddRallyOrder(
    const RallyPointOrder& order,
    const bool clear
  )
  {
    if (clear) {
      mRallyOrders.clear();
    }
    mRallyOrders.push_back(order);
  }

  void PlannedUnitProxy::ClearRallyOrders() noexcept
  {
    mRallyOrders.clear();
  }

  bool PlannedUnitProxy::HasBuilder(
    const std::uint32_t builderId,
    const std::int32_t commandId
  ) const noexcept
  {
    return std::ranges::any_of(mBuilders, [&](const Builder& builder) {
      return builder.builderId == builderId && builder.commandId == commandId;
    });
  }

  void PlannedUnitProxy::AddBuilder(
    const std::uint32_t builderId,
    const std::int32_t commandId
  )
  {
    if (!HasBuilder(builderId, commandId)) {
      mBuilders.push_back(Builder{builderId, commandId, 0});
    }
  }

  bool PlannedUnitProxy::RemoveBuilder(
    const std::uint32_t builderId
  )
  {
    return std::erase_if(mBuilders, [builderId](const Builder& builder) {
      return builder.builderId == builderId;
    }) != 0;
  }

  std::uint32_t PlannedUnitProxy::FirstBuilderId() const noexcept
  {
    return mBuilders.empty() ? 0u : mBuilders.front().builderId;
  }

  PlannedFactoryManager& PlannedFactoryManager::Get() noexcept
  {
    static PlannedFactoryManager sInstance;
    return sInstance;
  }

  bool PlannedFactoryManager::IsPlannedProxyUnit(
    const UserUnit* const unit
  ) noexcept
  {
    return unit != nullptr && IsClientOnlyUnitId(static_cast<std::uint32_t>(unit->mParams.mEntityId));
  }

  bool PlannedFactoryManager::AnyPlannedProxyUnit(
    const gpg::fastvector<UserUnit*>& units
  ) noexcept
  {
    for (const UserUnit* const unit : units) {
      if (IsPlannedProxyUnit(unit)) {
        return true;
      }
    }
    return false;
  }

  std::uint32_t PlannedFactoryManager::FreeSlot() const noexcept
  {
    std::vector<bool> taken(kMaxPlannedProxies, false);
    for (const auto& proxy : mProxies) {
      taken[proxy->mProxyId] = true;
    }
    const auto it = std::ranges::find(taken, false);
    return static_cast<std::uint32_t>(it - taken.begin());
  }

  PlannedUnitProxy* PlannedFactoryManager::AddProxy(
    const std::uint32_t builderId,
    const std::int32_t commandId,
    const REntityBlueprint* const bp,
    const Vector3f& pos
  )
  {
    for (const auto& proxy : mProxies) {
      if (proxy->mBlueprint == bp && GroundDistanceSq(proxy->mPosition, pos) <= kSameSiteDistance * kSameSiteDistance) {
        proxy->AddBuilder(builderId, commandId);
        return proxy.get();
      }
    }

    const std::uint32_t slot = FreeSlot();
    if (slot >= kMaxPlannedProxies) {
      return nullptr;
    }

    auto proxy = std::make_unique<PlannedUnitProxy>();
    proxy->mProxyId = slot;
    proxy->mBlueprint = bp;
    proxy->mPosition = pos;
    proxy->AddBuilder(builderId, commandId);
    mProxies.push_back(std::move(proxy));
    return mProxies.back().get();
  }

  PlannedUnitProxy* PlannedFactoryManager::FindForNewUnit(
    const REntityBlueprint* const bp,
    const Vector3f& pos
  ) noexcept
  {
    PlannedUnitProxy* best = nullptr;
    float bestDistSq = kNewUnitMatchDistance * kNewUnitMatchDistance;
    for (const auto& proxy : mProxies) {
      if (proxy->mBlueprint != bp || bp == nullptr) {
        continue;
      }
      const float distSq = GroundDistanceSq(proxy->mPosition, pos);
      if (distSq <= bestDistSq) {
        bestDistSq = distSq;
        best = proxy.get();
      }
    }
    return best;
  }

  void PlannedFactoryManager::RemoveBuilder(
    const std::uint32_t builderId
  )
  {
    for (const auto& proxy : mProxies) {
      (void)proxy->RemoveBuilder(builderId);
    }
  }

  void PlannedFactoryManager::Clear() noexcept
  {
    for (const auto& proxy : mProxies) {
      DeleteRallyHelpers(nullptr, *proxy);
      if (proxy->mUserUnit != nullptr) {
        ReleaseClientOnlyUnit(static_cast<std::uint32_t>(proxy->mUserUnit->mParams.mEntityId));
      }
    }
    mProxies.clear();
    mNewUnitIds.clear();
  }

  bool PlannedFactoryManager::RemoveUnitlessProxy(
    const std::uint32_t proxyId
  ) noexcept
  {
    return std::erase_if(mProxies, [proxyId](const std::unique_ptr<PlannedUnitProxy>& proxy) {
      return proxy->mProxyId == proxyId && proxy->mUserUnit == nullptr;
    }) != 0;
  }

  void PlannedFactoryManager::ForgetAll() noexcept
  {
    Clear();
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByUserUnit(
    const UserUnit* const unit
  ) noexcept
  {
    if (!IsPlannedProxyUnit(unit)) {
      return nullptr;
    }
    for (const auto& proxy : mProxies) {
      if (proxy->mUserUnit == unit) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByProxyId(
    const std::uint32_t proxyId
  ) noexcept
  {
    for (const auto& proxy : mProxies) {
      if (proxy->mProxyId == proxyId) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  std::vector<PlannedUnitProxy*> PlannedFactoryManager::GetSelectedProxies(
    const CWldSession& session
  )
  {
    std::vector<PlannedUnitProxy*> selected;
    for (const auto& proxy : mProxies) {
      if (proxy->mUserUnit != nullptr && session.mSelection.Find(proxy->mUserUnit) != session.mSelection.end()) {
        selected.push_back(proxy.get());
      }
    }
    return selected;
  }

  void PlannedFactoryManager::OnBuildOrderIssued(
    CWldSession& session,
    const gpg::fastvector<UserUnit*>& builders,
    const std::int32_t commandId,
    const REntityBlueprint* const bp,
    const Vector3f& pos
  )
  {
    if (!IsFactoryPreOrdersEnabled() || session.IsReplay || bp == nullptr) {
      return;
    }
    const UserArmy* const focusArmy = session.GetFocusUserArmy();
    if (focusArmy == nullptr || !IsFactoryBlueprint(session, bp) || OwnUnitStandsAt(session, bp, pos)) {
      return;
    }

    for (UserUnit* const builder : builders) {
      if (builder == nullptr || IsPlannedProxyUnit(builder) || builder->mArmy != focusArmy) {
        continue;
      }
      PlannedUnitProxy* const proxy =
        AddProxy(static_cast<std::uint32_t>(builder->mParams.mEntityId), commandId, bp, pos);
      if (proxy != nullptr && proxy->mUserUnit == nullptr) {
        proxy->mUserUnit = CreateProxyUnit(session, *proxy);
        gpg::Logf(
          "PlannedFactory: %s planned at (%.1f, %.1f) by 0x%08x, command 0x%08x",
          bp->mBlueprintId.c_str(),
          pos.x,
          pos.z,
          static_cast<std::uint32_t>(builder->mParams.mEntityId),
          static_cast<std::uint32_t>(commandId)
        );
      }
    }
  }

  bool PlannedFactoryManager::OnProxyCommand(
    CWldSession& session,
    const gpg::fastvector<UserUnit*>& proxyUnits,
    const SSTICommandIssueData& data,
    const bool clearQueue
  )
  {
    if (!IsFactoryPreOrdersEnabled()) {
      return false;
    }

    switch (data.mCommandType) {
    case EUnitCommandType::UNITCOMMAND_BuildFactory: {
      if (data.mBlueprint == nullptr || data.mBlueprint->mBlueprintId.empty()) {
        return false;
      }
      const std::string bpId = data.mBlueprint->mBlueprintId.c_str();
      for (UserUnit* const unit : proxyUnits) {
        if (PlannedUnitProxy* const proxy = FindByUserUnit(unit)) {
          if (clearQueue) {
            proxy->ClearPreOrders();
          }
          proxy->AddPreOrder(bpId, 1);
        }
      }
      return true;
    }
    case EUnitCommandType::UNITCOMMAND_Move:
    case EUnitCommandType::UNITCOMMAND_FormMove:
    case EUnitCommandType::UNITCOMMAND_Patrol:
    case EUnitCommandType::UNITCOMMAND_FormPatrol:
    case EUnitCommandType::UNITCOMMAND_AggressiveMove:
    case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
    case EUnitCommandType::UNITCOMMAND_Guard:
      // A factory takes these as rally orders for what it builds (`ISSUE_FactoryCommand`).
      OnProxyFactoryCommand(session, proxyUnits, data, clearQueue);
      return true;
    default:
      return false;
    }
  }

  bool PlannedFactoryManager::RetargetFromPlannedFactory(
    CWldSession& session,
    SSTICommandIssueData& data
  )
  {
    const PlannedUnitProxy* proxy = nullptr;
    for (const auto& candidate : mProxies) {
      if (
        candidate->mUserUnit != nullptr &&
        static_cast<std::uint32_t>(candidate->mUserUnit->mParams.mEntityId) ==
          static_cast<std::uint32_t>(data.mTarget.mEnt)
      ) {
        proxy = candidate.get();
        break;
      }
    }
    if (proxy == nullptr) {
      return false;
    }

    switch (data.mCommandType) {
    case EUnitCommandType::UNITCOMMAND_Guard:
    case EUnitCommandType::UNITCOMMAND_Repair:
      for (const PlannedUnitProxy::Builder& builder : proxy->mBuilders) {
        if (
          const UserUnit* const unit = LookupUserUnit(session, builder.builderId);
          unit != nullptr && unit->mVariableData.mIsDead == 0
        ) {
          data.mTarget.mEnt = static_cast<std::int32_t>(builder.builderId);
          return true;
        }
      }
      return false;
    case EUnitCommandType::UNITCOMMAND_Move:
    case EUnitCommandType::UNITCOMMAND_FormMove:
    case EUnitCommandType::UNITCOMMAND_AggressiveMove:
    case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
    case EUnitCommandType::UNITCOMMAND_Patrol:
    case EUnitCommandType::UNITCOMMAND_FormPatrol:
      data.mTarget.mType = EAiTargetType::AITARGET_Ground;
      data.mTarget.mEnt = static_cast<std::int32_t>(ToRaw(EEntityIdSentinel::Invalid));
      data.mTarget.mPos = Wm3::Vec3f{proxy->mPosition.x, proxy->mPosition.y, proxy->mPosition.z};
      return true;
    default:
      return false;
    }
  }

  void PlannedFactoryManager::OnProxyFactoryCommand(
    CWldSession& session,
    const gpg::fastvector<UserUnit*>& proxyUnits,
    const SSTICommandIssueData& data,
    const bool clearQueue
  )
  {
    if (!IsFactoryPreOrdersEnabled() || session.mCommandManager == nullptr) {
      return;
    }

    RallyPointOrder order{};
    order.commandType = data.mCommandType;
    order.targetType = data.mTarget.mType;
    if (data.mTarget.mType == EAiTargetType::AITARGET_Entity) {
      order.targetEntityId = static_cast<std::uint32_t>(data.mTarget.mEnt);
      if (UserEntity* const target = session.LookupEntityId(static_cast<EntId>(data.mTarget.mEnt))) {
        order.position = PositionOf(*target);
      }
    } else {
      order.position = Vector3f{data.mTarget.mPos.x, data.mTarget.mPos.y, data.mTarget.mPos.z};
    }

    for (UserUnit* const unit : proxyUnits) {
      PlannedUnitProxy* const proxy = FindByUserUnit(unit);
      if (proxy == nullptr) {
        continue;
      }
      if (clearQueue) {
        DeleteRallyHelpers(&session, *proxy);
      }
      RallyPointOrder kept = order;

      // The rally line: a helper of the proxy's own, never sent, drawn from the proxy's factory queue
      // like a factory's rally command. Its id comes from the same pool as every command id and goes back
      // to it when the helper is deleted.
      UserCommandQueue* const factoryQueue = unit->GetFactoryCommandQueue();
      if (factoryQueue == nullptr) {
        proxy->AddRallyOrder(kept, clearQueue);
        continue;
      }
      std::uint32_t packedId = 0u;
      SSTICommandIssueData lineData = data;
      lineData.nextCommandId =
        static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(session.mCommandManager, &packedId));
      if ((static_cast<std::uint32_t>(lineData.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
        proxy->AddRallyOrder(kept, clearQueue);
        continue;
      }
      // Registered before anything can reach the driver with it: a drag or removal of the line is dropped
      // there (ClientOnlyIds.h) and lands in OnRallyHelperRetargeted / OnRallyHelperRemoved instead.
      RegisterClientOnlyCommand(lineData.nextCommandId);
      kept.helperId = lineData.nextCommandId;
      SSTICommandConstantData constantData{};
      InitializePublishedCommandDescriptorFromIssueData(&constantData, &lineData);
      UserCommandIssueHelper* const helper = FindOrCreateCommandIssueHelper(
        *session.mCommandManager, constantData, 0u, static_cast<std::int32_t>(session.mGameTick)
      );
      helper->mVariableData = SSTICommandVariableData(lineData);
      helper->mVariableDataDirty = 1u;
      helper->mDeleteWhenDue = 0u;
      if (clearQueue) {
        factoryQueue->primaryLinks.clear();
        factoryQueue->issueQueue.clear();
      }
      factoryQueue->primaryLinks.push_back(WeakPtr<UserCommandIssueHelper>(helper));
      factoryQueue->resolvedLinksDirty = 1u;
      proxy->AddRallyOrder(kept, clearQueue);
    }
    session.DirtyCommandGraph();
  }

  void PlannedFactoryManager::OnRallyHelperRetargeted(
    const std::int32_t helperId,
    const SSTITarget& target,
    const Vector3f& position
  )
  {
    for (const auto& proxy : mProxies) {
      for (RallyPointOrder& order : proxy->mRallyOrders) {
        if (order.helperId != helperId) {
          continue;
        }
        order.targetType = target.mType;
        order.targetEntityId = target.mType == EAiTargetType::AITARGET_Entity ? target.mEnt : 0u;
        order.position = position;
        return;
      }
    }
  }

  void PlannedFactoryManager::OnRallyHelperRemoved(
    CWldSession& session,
    const std::int32_t helperId
  )
  {
    for (const auto& proxy : mProxies) {
      for (auto it = proxy->mRallyOrders.begin(); it != proxy->mRallyOrders.end(); ++it) {
        if (it->helperId == helperId) {
          DeleteRallyHelper(&session, *it);
          proxy->mRallyOrders.erase(it);
          session.DirtyCommandGraph();
          return;
        }
      }
    }
  }

  void PlannedFactoryManager::QueueOrdersOnSelected(
    const CWldSession& session,
    const std::string& bpId,
    const std::int32_t count,
    const bool clear
  )
  {
    if (!IsFactoryPreOrdersEnabled() || bpId.empty() || count <= 0) {
      return;
    }
    for (PlannedUnitProxy* const proxy : GetSelectedProxies(session)) {
      if (clear) {
        proxy->ClearPreOrders();
      }
      proxy->AddPreOrder(bpId, count);
    }
  }

  void PlannedFactoryManager::NoteNewUnit(
    const UserUnit& unit
  )
  {
    if (mProxies.empty() || IsPlannedProxyUnit(&unit)) {
      return;
    }
    mNewUnitIds.push_back(static_cast<std::uint32_t>(unit.mParams.mEntityId));
  }

  void PlannedFactoryManager::Dispatch(
    CWldSession& session,
    PlannedUnitProxy& proxy,
    UserUnit& factory
  )
  {
    gpg::fastvector<UserUnit*> target;
    target.push_back(&factory);

    // Sent like the player's own clicks would be, but never clearing a queue: a clear also ends the
    // command mode the player is in (commandmode.lua, OnCommandIssued), and the new factory has nothing
    // queued yet.
    if (session.mRules != nullptr) {
      for (const PlannedUnitProxy::PreOrder& order : proxy.mPreOrders) {
        RResId bpResId{};
        (void)gpg::STR_InitFilename(&bpResId.name, order.blueprintId.c_str());
        REntityBlueprint* const bp = session.mRules->GetEntityBlueprint(bpResId);
        auto* const unitBp = dynamic_cast<RUnitBlueprint*>(bp);
        if (unitBp == nullptr) {
          continue;
        }
        SSTICommandIssueData command(EUnitCommandType::UNITCOMMAND_BuildFactory);
        command.mBlueprint = unitBp;
        for (std::int32_t i = 0; i < order.count; ++i) {
          ISSUE_Command(target, command, false);
        }
      }
    }

    for (const RallyPointOrder& rally : proxy.mRallyOrders) {
      SSTICommandIssueData command(rally.commandType);
      command.mTarget.mType = rally.targetType;
      command.mTarget.mPos = Wm3::Vec3f{rally.position.x, rally.position.y, rally.position.z};
      if (rally.targetType == EAiTargetType::AITARGET_Entity) {
        // The entity may be gone, or be another planned factory: then the order goes to where it was.
        UserEntity* const targetEntity = IsClientOnlyUnitId(rally.targetEntityId)
          ? nullptr
          : session.LookupEntityId(static_cast<EntId>(rally.targetEntityId));
        if (targetEntity != nullptr) {
          command.mTarget.mEnt = static_cast<std::int32_t>(rally.targetEntityId);
        } else {
          command.mCommandType = EUnitCommandType::UNITCOMMAND_Move;
          command.mTarget.mType = EAiTargetType::AITARGET_Ground;
        }
      }
      ISSUE_FactoryCommand(target, command, false);
    }

    if (proxy.mRepeatBuild) {
      if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
        (void)driver->ProcessInfoPair(factory.mParams.mEntityId, "SetRepeatQueue", "true");
      }
    }
  }

  std::unique_ptr<PlannedUnitProxy> PlannedFactoryManager::Take(
    const std::size_t index
  )
  {
    std::unique_ptr<PlannedUnitProxy> proxy = std::move(mProxies[index]);
    mProxies.erase(mProxies.begin() + static_cast<std::ptrdiff_t>(index));
    return proxy;
  }

  void PlannedFactoryManager::Destroy(
    CWldSession& session,
    std::unique_ptr<PlannedUnitProxy> proxy,
    UserUnit* const replacement
  )
  {
    DeleteRallyHelpers(&session, *proxy);
    if (UserUnit* const unit = proxy->mUserUnit; unit != nullptr) {
      ReleaseClientOnlyUnit(static_cast<std::uint32_t>(unit->mParams.mEntityId));
      ReplaceInSelection(session, unit, replacement);
      if (replacement != nullptr) {
        // Control groups the planned factory was put in carry over to the factory.
        for (const fa::string& set : unit->mSelectionSets) {
          (void)replacement->mSelectionSets.insert(set);
        }
      }
      // Gone for good, the way a unit the sim deletes leaves the session (DoBeat's delete list).
      session.RemoveEntity(unit);
      delete unit;
    }
  }

  void PlannedFactoryManager::Update(
    CWldSession& session
  )
  {
    std::vector<std::uint32_t> newUnitIds;
    newUnitIds.swap(mNewUnitIds);
    if (mProxies.empty()) {
      return;
    }

    // Every proxy that goes is taken out of the list first, and only then are its orders sent and its unit
    // removed: both run user Lua (UI_OnCommandIssued, the selection callbacks), which then finds the list
    // already settled and cannot reach a proxy on its way out.
    std::vector<std::pair<std::unique_ptr<PlannedUnitProxy>, UserUnit*>> started;
    std::vector<std::unique_ptr<PlannedUnitProxy>> dropped;

    const UserArmy* const focusArmy = session.GetFocusUserArmy();
    if (!IsFactoryPreOrdersEnabled() || session.IsReplay || focusArmy == nullptr) {
      while (!mProxies.empty()) {
        dropped.push_back(Take(mProxies.size() - 1));
      }
    } else {
      // 1. A plan made for another army than the focus one (the focus changed) goes, as does one without a
      //    unit (its army is unknown; in a game every plan has one).
      for (std::size_t index = mProxies.size(); index-- > 0;) {
        if (mProxies[index]->mUserUnit == nullptr || mProxies[index]->mUserUnit->mArmy != focusArmy) {
          dropped.push_back(Take(index));
        }
      }

      // 2. A new unit of the focus army with a planned factory's blueprint at its spot is that factory.
      for (const std::uint32_t id : newUnitIds) {
        UserUnit* const unit = LookupUserUnit(session, id);
        if (unit == nullptr || unit->mArmy != focusArmy || unit->mVariableData.mIsDead != 0) {
          continue;
        }
        PlannedUnitProxy* const proxy = FindForNewUnit(unit->mParams.mBlueprint, PositionOf(*unit));
        if (proxy == nullptr) {
          continue;
        }
        gpg::Logf(
          "PlannedFactory: 0x%08x started at (%.1f, %.1f): %zu build orders, %zu rally orders, repeat %d",
          id,
          proxy->mPosition.x,
          proxy->mPosition.z,
          proxy->mPreOrders.size(),
          proxy->mRallyOrders.size(),
          proxy->mRepeatBuild ? 1 : 0
        );
        const auto it = std::ranges::find_if(mProxies, [proxy](const std::unique_ptr<PlannedUnitProxy>& p) {
          return p.get() == proxy;
        });
        started.emplace_back(Take(static_cast<std::size_t>(it - mProxies.begin())), unit);
      }

      // 3. A builder counts while its build command is in its queue.
      for (std::size_t index = mProxies.size(); index-- > 0;) {
        PlannedUnitProxy& proxy = *mProxies[index];
        std::erase_if(proxy.mBuilders, [&session](PlannedUnitProxy::Builder& builder) {
          UserUnit* const unit = LookupUserUnit(session, builder.builderId);
          bool present = unit != nullptr && unit->mVariableData.mIsDead == 0;
          if (present) {
            const UserCommandIssueHelper* const helper =
              FindCommandIssueHelperInSession(&session, static_cast<CmdId>(builder.commandId));
            present = helper != nullptr && UserUnitManagerContainsCommandIssueHelper(unit->GetCommandQueue(), helper);
          }
          if (present) {
            builder.missedBeats = 0;
            return false;
          }
          return ++builder.missedBeats >= kBuilderGraceBeats;
        });
        if (proxy.mBuilders.empty()) {
          gpg::Logf(
            "PlannedFactory: plan at (%.1f, %.1f) dropped, no engineer has its build order",
            proxy.mPosition.x,
            proxy.mPosition.z
          );
          dropped.push_back(Take(index));
        }
      }
    }

    for (auto& [proxy, factory] : started) {
      Dispatch(session, *proxy, *factory);
      Destroy(session, std::move(proxy), factory);
    }
    for (auto& proxy : dropped) {
      Destroy(session, std::move(proxy), nullptr);
    }
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByFootprint(
    const Vector3f& ground
  )
  {
    for (const auto& proxy : mProxies) {
      float halfX = 0.0f;
      float halfZ = 0.0f;
      FootprintHalfSize(proxy->mBlueprint, halfX, halfZ);
      if (std::abs(ground.x - proxy->mPosition.x) <= halfX && std::abs(ground.z - proxy->mPosition.z) <= halfZ) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  PlannedUnitProxy* PlannedFactoryManager::PickAt(
    const GeomCamera3& camera,
    const Vector3f* const cursorGround,
    const float screenX,
    const float screenY,
    const float pickRadius
  )
  {
    if (!IsFactoryPreOrdersEnabled() || mProxies.empty()) {
      return nullptr;
    }
    if (cursorGround != nullptr) {
      if (PlannedUnitProxy* const hit = FindByFootprint(*cursorGround)) {
        return hit;
      }
    }
    if (pickRadius <= 0.0f || camera.viewport.r[3].z <= 0.0f || camera.viewport.r[3].w <= 0.0f) {
      return nullptr;
    }

    PlannedUnitProxy* best = nullptr;
    float bestDistSq = pickRadius * pickRadius;
    for (const auto& proxy : mProxies) {
      const Vector3f& p = proxy->mPosition;
      // Depth along the view; a point behind the camera projects mirrored onto the screen.
      const float w = (camera.viewProjection.r[0].w * p.x) + (camera.viewProjection.r[1].w * p.y) +
        (camera.viewProjection.r[2].w * p.z) + camera.viewProjection.r[3].w;
      if (w <= 0.001f) {
        continue;
      }
      const Wm3::Vector2f screen = camera.Project(Wm3::Vector3f{p.x, p.y, p.z});
      const float dx = screen.x - screenX;
      const float dy = screen.y - screenY;
      const float distSq = (dx * dx) + (dy * dy);
      if (distSq <= bestDistSq) {
        bestDistSq = distSq;
        best = proxy.get();
      }
    }
    return best;
  }
} // namespace moho
