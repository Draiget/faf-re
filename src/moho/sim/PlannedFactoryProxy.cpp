#include "moho/sim/PlannedFactoryProxy.h"

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/console/CConCommand.h"
#include "moho/entity/EntityId.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UserArmy.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{
  PlannedUnitProxy::PlannedUnitProxy() = default;

  PlannedUnitProxy::~PlannedUnitProxy()
  {
    if (mUserUnit != nullptr) {
      CWldSession* const session = WLD_GetActiveSession();
      if (session != nullptr) {
        if (session->mSelection.Find(mUserUnit) != session->mSelection.end()) {
          WeakSet<UserEntity> sel = session->GetSelection();
          (void)sel.Remove(mUserUnit);
          if (static_cast<std::uint32_t>(mUserUnit->mUnitVarDat.mSelectionInheritorId) != ToRaw(EEntityIdSentinel::Invalid)) {
            if (UserEntity* const newUnit = session->LookupEntityId(mUserUnit->mUnitVarDat.mSelectionInheritorId)) {
              (void)sel.Add(newUnit);
            }
          }
          session->SetSelection(sel);
        }
        mUserUnit->mVariableData.mIsDead = 1;
        mUserUnit->mMarkedForDeletion = 1;
        session->OrphanEntity(mUserUnit);
      } else {
        delete mUserUnit;
      }
      mUserUnit = nullptr;
    }
  }

  void PlannedUnitProxy::AddPreOrder(const std::string& bpId, const std::int32_t count)
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

  bool PlannedUnitProxy::RemovePreOrder(const std::string& bpId, std::int32_t count)
  {
    if (bpId.empty() || count <= 0) {
      return false;
    }

    bool removed = false;
    for (int i = static_cast<int>(mPreOrders.size()) - 1; i >= 0 && count > 0; --i) {
      const auto idx = static_cast<std::size_t>(i);
      if (mPreOrders[idx].blueprintId == bpId) {
        removed = true;
        if (mPreOrders[idx].count <= count) {
          count -= mPreOrders[idx].count;
          mPreOrders.erase(mPreOrders.begin() + i);
        } else {
          mPreOrders[idx].count -= count;
          count = 0;
        }
      }
    }
    return removed;
  }

  bool PlannedUnitProxy::RemovePreOrderByIndex(const std::size_t index, const std::int32_t count)
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

  void PlannedUnitProxy::ClearPreOrders()
  {
    mPreOrders.clear();
  }

  void PlannedUnitProxy::SetRallyPoint(const Vector3f& rallyPos)
  {
    mRallyPoint = rallyPos;
    mHasRallyPoint = true;
  }

  void PlannedUnitProxy::ClearRallyPoint()
  {
    mHasRallyPoint = false;
  }

  void PlannedUnitProxy::SetRepeatBuild(const bool repeat)
  {
    mRepeatBuild = repeat;
  }

  void PlannedUnitProxy::ToggleRepeatBuild()
  {
    mRepeatBuild = !mRepeatBuild;
  }

  bool PlannedUnitProxy::IsSelected() const noexcept
  {
    if (mUserUnit != nullptr) {
      if (CWldSession* const sess = WLD_GetActiveSession()) {
        return sess->mSelection.Find(mUserUnit) != sess->mSelection.end();
      }
    }
    return mIsSelected;
  }

  bool PlannedUnitProxy::HasBuilder(const std::uint32_t builderId, const std::uint32_t cmdIndex) const noexcept
  {
    for (const auto& builder : mBuilders) {
      if (builder.builderId == builderId && builder.cmdIndex == cmdIndex) {
        return true;
      }
    }
    return false;
  }

  void PlannedUnitProxy::AddBuilder(const std::uint32_t builderId, const std::uint32_t cmdIndex)
  {
    if (!HasBuilder(builderId, cmdIndex)) {
      mBuilders.push_back(BuilderKey{builderId, cmdIndex});
    }
  }

  bool PlannedUnitProxy::RemoveBuilder(const std::uint32_t builderId, const std::uint32_t cmdIndex)
  {
    for (auto it = mBuilders.begin(); it != mBuilders.end(); ++it) {
      if (it->builderId == builderId && it->cmdIndex == cmdIndex) {
        mBuilders.erase(it);
        return true;
      }
    }
    return false;
  }

  bool PlannedUnitProxy::RemoveAllBuildersFor(const std::uint32_t builderId)
  {
    const auto initialSize = mBuilders.size();
    mBuilders.erase(
      std::remove_if(
        mBuilders.begin(),
        mBuilders.end(),
        [builderId](const BuilderKey& b) {
          return b.builderId == builderId;
        }),
      mBuilders.end());
    return mBuilders.size() != initialSize;
  }

  // --- PlannedFactoryManager ---

  PlannedUnitProxy* PlannedFactoryManager::RegisterOrUpdatePlannedFactory(
    const std::uint32_t builderId,
    const std::uint32_t cmdIndex,
    const REntityBlueprint* bp,
    const Vector3f& pos)
  {
    // 1. If builder command already maps to an existing proxy, update position (waypoint drag)
    if (auto* existing = FindByBuilderAndIndex(builderId, cmdIndex)) {
      existing->mPosition = pos;
      if (bp != nullptr) {
        existing->mBlueprint = bp;
      }
      if (existing->mUserUnit != nullptr) {
        existing->mUserUnit->mTransform.pos_ = { pos.x, pos.y, pos.z };
        existing->mUserUnit->mTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
        existing->mUserUnit->mVariableData.mCurTransform.pos_ = { pos.x, pos.y, pos.z };
        existing->mUserUnit->mVariableData.mCurTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
        existing->mUserUnit->mVariableData.mLastTransform.pos_ = { pos.x, pos.y, pos.z };
        existing->mUserUnit->mVariableData.mLastTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
        existing->mUserUnit->mVariableData.mCurImpactValue = 1.0f;
        existing->mUserUnit->mLastInterpAmt = 0.0f;
        float halfSizeX = 3.5f;
        float halfSizeZ = 3.5f;
        if (const auto* rbp = dynamic_cast<const RUnitBlueprint*>(existing->mBlueprint)) {
          if (rbp->Physics.SkirtSizeX > 0.0f) halfSizeX = rbp->Physics.SkirtSizeX * 0.5f;
          if (rbp->Physics.SkirtSizeZ > 0.0f) halfSizeZ = rbp->Physics.SkirtSizeZ * 0.5f;
        }
        Wm3::AxisAlignedBox3f bounds;
        bounds.Min = { pos.x - halfSizeX, pos.y - 1.0f, pos.z - halfSizeZ };
        bounds.Max = { pos.x + halfSizeX, pos.y + 4.0f, pos.z + halfSizeZ };
        existing->mUserUnit->mSpatialDbEntry.UpdateBounds(bounds);
      }
      return existing;
    }

    // 2. If another builder already ordered a factory at this location, attach as co-builder
    if (auto* existingAtPos = FindByPosition(pos, 1.0f)) {
      existingAtPos->AddBuilder(builderId, cmdIndex);
      if (existingAtPos->mBlueprint == nullptr && bp != nullptr) {
        existingAtPos->mBlueprint = bp;
      }
      return existingAtPos;
    }

    // 3. Otherwise instantiate a new proxy
    auto newProxy = std::make_unique<PlannedUnitProxy>();
    newProxy->mProxyId = mNextProxyId++;
    newProxy->mBuilderEntityId = builderId;
    newProxy->mBuilderCmdIndex = cmdIndex;
    newProxy->mBlueprint = bp;
    newProxy->mPosition = pos;
    newProxy->AddBuilder(builderId, cmdIndex);

    CWldSession* const session = WLD_GetActiveSession();
    if (session != nullptr && bp != nullptr) {
      SCreateUnitParams createParams{};
      createParams.mBlueprint = bp;
      const auto armyIndex = session->GetFocusUserArmy() ? session->GetFocusUserArmy()->mArmyIndex : 0;
      createParams.mEntityId = MakeEntityId(EEntityIdFamily::Unit, armyIndex, 0x7000u | (newProxy->mProxyId & 0x0FFFu));
      createParams.mTickCreated = session->mGameTick;

      auto* userUnit = new UserUnit(session, createParams);
      userUnit->mArmy = session->GetFocusUserArmy();
      userUnit->mTransform.pos_ = { pos.x, pos.y, pos.z };
      userUnit->mTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
      userUnit->mVariableData.mCurTransform.pos_ = { pos.x, pos.y, pos.z };
      userUnit->mVariableData.mCurTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
      userUnit->mVariableData.mLastTransform.pos_ = { pos.x, pos.y, pos.z };
      userUnit->mVariableData.mLastTransform.orient_ = { 0.0f, 0.0f, 0.0f, 1.0f };
      userUnit->mVariableData.mCurImpactValue = 1.0f;
      userUnit->mLastInterpAmt = 0.0f;
      userUnit->mVariableData.mFractionComplete = 0.0f;
      userUnit->mVariableData.mHealth = 0.0f;
      userUnit->mVariableData.mMaxHealth = 0.0f;
      constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
      userUnit->mIntelStateFlags |= kStrategicIconEntitySuppressedMask;

      const auto* unitBp = dynamic_cast<const RUnitBlueprint*>(bp);
      if (unitBp != nullptr && session->mRules != nullptr) {
        userUnit->mUnitVarDat.mAttributes = UnitAttributes(unitBp, session->mRules);
      }

      float halfSizeX = 3.5f;
      float halfSizeZ = 3.5f;
      if (unitBp != nullptr) {
        if (unitBp->Physics.SkirtSizeX > 0.0f) halfSizeX = unitBp->Physics.SkirtSizeX * 0.5f;
        if (unitBp->Physics.SkirtSizeZ > 0.0f) halfSizeZ = unitBp->Physics.SkirtSizeZ * 0.5f;
      }
      Wm3::AxisAlignedBox3f bounds;
      bounds.Min = { pos.x - halfSizeX, pos.y - 1.0f, pos.z - halfSizeZ };
      bounds.Max = { pos.x + halfSizeX, pos.y + 4.0f, pos.z + halfSizeZ };
      userUnit->mSpatialDbEntry.UpdateBounds(bounds);

      session->AddEntity(userUnit);
      newProxy->mUserUnit = userUnit;
    }

    gpg::Logf("[PlannedFactory] Registered proxy %u at (%.1f, %.1f, %.1f) for builder %u",
              newProxy->mProxyId, pos.x, pos.y, pos.z, builderId);
    mProxies.push_back(std::move(newProxy));
    return mProxies.back().get();
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByPosition(const Vector3f& pos, const float tolerance)
  {
    float bestDistSq = tolerance * tolerance;
    PlannedUnitProxy* bestProxy = nullptr;

    for (const auto& proxy : mProxies) {
      if (!proxy) {
        continue;
      }
      const float dx = proxy->mPosition.x - pos.x;
      const float dz = proxy->mPosition.z - pos.z;
      const float distSq = (dx * dx) + (dz * dz);
      if (distSq <= bestDistSq) {
        bestDistSq = distSq;
        bestProxy = proxy.get();
      }
    }

    return bestProxy;
  }

  const PlannedUnitProxy* PlannedFactoryManager::FindByPosition(const Vector3f& pos, const float tolerance) const
  {
    return const_cast<PlannedFactoryManager*>(this)->FindByPosition(pos, tolerance);
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByBuilderAndIndex(
    const std::uint32_t builderId,
    const std::uint32_t cmdIndex)
  {
    for (const auto& proxy : mProxies) {
      if (proxy->HasBuilder(builderId, cmdIndex)) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  const PlannedUnitProxy* PlannedFactoryManager::FindByBuilderAndIndex(
    const std::uint32_t builderId,
    const std::uint32_t cmdIndex) const
  {
    return const_cast<PlannedFactoryManager*>(this)->FindByBuilderAndIndex(builderId, cmdIndex);
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByProxyId(const std::uint32_t proxyId)
  {
    for (const auto& proxy : mProxies) {
      if (proxy->mProxyId == proxyId) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  const PlannedUnitProxy* PlannedFactoryManager::FindByProxyId(const std::uint32_t proxyId) const
  {
    return const_cast<PlannedFactoryManager*>(this)->FindByProxyId(proxyId);
  }

  bool PlannedFactoryManager::IsPlannedProxyUnit(const UserUnit* unit) const
  {
    if (unit == nullptr) {
      return false;
    }
    for (const auto& proxy : mProxies) {
      if (proxy && proxy->mUserUnit == unit) {
        return true;
      }
    }
    return false;
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByUserUnit(const UserUnit* unit)
  {
    if (unit == nullptr) {
      return nullptr;
    }
    for (const auto& proxy : mProxies) {
      if (proxy && proxy->mUserUnit == unit) {
        return proxy.get();
      }
    }
    return nullptr;
  }

  const PlannedUnitProxy* PlannedFactoryManager::FindByUserUnit(const UserUnit* unit) const
  {
    return const_cast<PlannedFactoryManager*>(this)->FindByUserUnit(unit);
  }

  namespace {
    struct MutexRecursionGuard {
      bool& mFlag;
      MutexRecursionGuard(bool& flag) : mFlag(flag) { mFlag = true; }
      ~MutexRecursionGuard() { mFlag = false; }
    };
  }

  void PlannedFactoryManager::RemoveByBuilder(const std::uint32_t builderId)
  {
    if (mIsMutating) {
      return;
    }
    MutexRecursionGuard guard(mIsMutating);

    for (auto it = mProxies.begin(); it != mProxies.end();) {
      PlannedUnitProxy* proxy = it->get();
      if (proxy == nullptr) {
        it = mProxies.erase(it);
        continue;
      }
      proxy->RemoveAllBuildersFor(builderId);
      if (proxy->mBuilders.empty()) {
        it = mProxies.erase(it);
      } else {
        proxy->mBuilderEntityId = proxy->mBuilders.front().builderId;
        proxy->mBuilderCmdIndex = proxy->mBuilders.front().cmdIndex;
        ++it;
      }
    }
  }

  void PlannedFactoryManager::RemoveByBuilderAndIndex(const std::uint32_t builderId, const std::uint32_t cmdIndex)
  {
    if (mIsMutating) {
      return;
    }
    MutexRecursionGuard guard(mIsMutating);

    for (auto it = mProxies.begin(); it != mProxies.end(); ++it) {
      PlannedUnitProxy* proxy = it->get();
      if (proxy != nullptr && proxy->RemoveBuilder(builderId, cmdIndex)) {
        if (proxy->mBuilders.empty()) {
          mProxies.erase(it);
        } else {
          proxy->mBuilderEntityId = proxy->mBuilders.front().builderId;
          proxy->mBuilderCmdIndex = proxy->mBuilders.front().cmdIndex;
        }
        break;
      }
    }
  }

  bool PlannedFactoryManager::RemoveProxy(const std::uint32_t proxyId)
  {
    if (mIsMutating) {
      return false;
    }
    MutexRecursionGuard guard(mIsMutating);

    const auto it = std::find_if(
      mProxies.begin(),
      mProxies.end(),
      [proxyId](const std::unique_ptr<PlannedUnitProxy>& p) {
        return p && p->mProxyId == proxyId;
      });

    if (it != mProxies.end()) {
      gpg::Logf("[PlannedFactory] RemoveProxy %u", proxyId);
      mProxies.erase(it);
      return true;
    }
    return false;
  }

  void PlannedFactoryManager::ClearAll()
  {
    if (mIsMutating) {
      return;
    }
    MutexRecursionGuard guard(mIsMutating);
    mProxies.clear();
  }

  std::size_t PlannedFactoryManager::GetCount() const noexcept
  {
    return mProxies.size();
  }

  void PlannedFactoryManager::SelectProxy(const std::uint32_t proxyId, const bool addToSelection)
  {
    gpg::Logf("[PlannedFactory] SelectProxy %u (add=%d)", proxyId, addToSelection ? 1 : 0);
    if (!addToSelection) {
      ClearSelection();
    }
    if (auto* proxy = FindByProxyId(proxyId)) {
      proxy->SetSelected(true);
      if (proxy->mUserUnit != nullptr) {
        if (CWldSession* const sess = WLD_GetActiveSession()) {
          WeakSet<UserEntity> sel = addToSelection ? sess->GetSelection() : WeakSet<UserEntity>{};
          (void)sel.Add(proxy->mUserUnit);
          sess->SetSelection(sel);
        }
      }
    }
  }

  void PlannedFactoryManager::DeselectProxy(const std::uint32_t proxyId)
  {
    if (auto* proxy = FindByProxyId(proxyId)) {
      proxy->SetSelected(false);
      if (proxy->mUserUnit != nullptr) {
        if (CWldSession* const sess = WLD_GetActiveSession()) {
          WeakSet<UserEntity> sel = sess->GetSelection();
          (void)sel.Remove(proxy->mUserUnit);
          sess->SetSelection(sel);
        }
      }
    }
  }

  void PlannedFactoryManager::ClearSelection()
  {
    for (const auto& proxy : mProxies) {
      if (proxy) {
        proxy->SetSelected(false);
      }
    }
  }

  std::vector<PlannedUnitProxy*> PlannedFactoryManager::GetSelectedProxies()
  {
    std::vector<PlannedUnitProxy*> result;
    for (const auto& proxy : mProxies) {
      if (proxy && proxy->IsSelected()) {
        result.push_back(proxy.get());
      }
    }
    return result;
  }

  std::vector<const PlannedUnitProxy*> PlannedFactoryManager::GetSelectedProxies() const
  {
    std::vector<const PlannedUnitProxy*> result;
    for (const auto& proxy : mProxies) {
      if (proxy && proxy->IsSelected()) {
        result.push_back(proxy.get());
      }
    }
    return result;
  }

  void PlannedFactoryManager::QueuePlannedFactoryOrders(const std::string& bpId, const int count, const bool clearQueue)
  {
    if (!IsFactoryPreOrdersEnabled() || bpId.empty() || count <= 0) {
      return;
    }
    gpg::Logf("[PlannedFactory] QueuePlannedFactoryOrders: %dx '%s' (clear=%d) for %zu selected proxies",
              count, bpId.c_str(), clearQueue ? 1 : 0, GetSelectedProxies().size());
    for (auto* const proxy : GetSelectedProxies()) {
      if (proxy != nullptr) {
        if (clearQueue) {
          proxy->ClearPreOrders();
        }
        proxy->AddPreOrder(bpId, count);
      }
    }
  }

  void PlannedFactoryManager::SetSelectedPlannedFactoriesRallyPoint(const Vector3f& pos)
  {
    if (!IsFactoryPreOrdersEnabled()) {
      return;
    }
    for (auto* const proxy : GetSelectedProxies()) {
      if (proxy != nullptr) {
        proxy->SetRallyPoint(pos);
      }
    }
  }

  void PlannedFactoryManager::SetSelectedPlannedFactoriesRepeat(const bool repeat)
  {
    if (!IsFactoryPreOrdersEnabled()) {
      return;
    }
    for (auto* const proxy : GetSelectedProxies()) {
      if (proxy != nullptr) {
        proxy->SetRepeatBuild(repeat);
      }
    }
  }

  PlannedUnitProxy* PlannedFactoryManager::HitTestRay(const Ray3f& ray, const float radius)
  {
    if (!IsFactoryPreOrdersEnabled()) {
      return nullptr;
    }

    const float dirLenSq = (ray.direction.x * ray.direction.x) +
                           (ray.direction.y * ray.direction.y) +
                           (ray.direction.z * ray.direction.z);
    if (dirLenSq < 1e-6f) {
      return nullptr;
    }

    const float invLen = 1.0f / std::sqrt(dirLenSq);
    const Vector3f normDir = ray.direction * invLen;

    PlannedUnitProxy* bestHit = nullptr;
    float closestT = std::numeric_limits<float>::max();
    const float radiusSq = radius * radius;

    for (const auto& proxy : mProxies) {
      const Vector3f diff = proxy->mPosition - ray.origin;
      const float t = (diff.x * normDir.x) + (diff.y * normDir.y) + (diff.z * normDir.z);
      if (t < 0.0f) {
        continue;
      }

      const Vector3f closestPoint = ray.origin + (normDir * t);
      const float dx = proxy->mPosition.x - closestPoint.x;
      const float dy = proxy->mPosition.y - closestPoint.y;
      const float dz = proxy->mPosition.z - closestPoint.z;
      const float distSq = (dx * dx) + (dy * dy) + (dz * dz);

      if (distSq <= radiusSq && t < closestT) {
        closestT = t;
        bestHit = proxy.get();
      }
    }

    return bestHit;
  }

  const PlannedUnitProxy* PlannedFactoryManager::HitTestRay(const Ray3f& ray, const float radius) const
  {
    return const_cast<PlannedFactoryManager*>(this)->HitTestRay(ray, radius);
  }

  PlannedUnitProxy* PlannedFactoryManager::HitTestScreenPoint(
    const GeomCamera3* const camera,
    const float screenX,
    const float screenY,
    const float pickRadius)
  {
    if (!IsFactoryPreOrdersEnabled() || camera == nullptr || pickRadius <= 0.0f) {
      return nullptr;
    }

    PlannedUnitProxy* bestHit = nullptr;
    float bestDistSq = pickRadius * pickRadius;
    float bestW = std::numeric_limits<float>::max();

    for (const auto& proxy : mProxies) {
      if (!proxy) {
        continue;
      }

      const float w = (camera->viewProjection.r[0].w * proxy->mPosition.x) +
                      (camera->viewProjection.r[1].w * proxy->mPosition.y) +
                      (camera->viewProjection.r[2].w * proxy->mPosition.z) +
                      camera->viewProjection.r[3].w;
      if (w <= 0.001f) {
        continue;
      }

      const Wm3::Vector3f wpos{proxy->mPosition.x, proxy->mPosition.y, proxy->mPosition.z};
      Wm3::Vector2f screenPos;
      if (camera->viewport.r[3].z > 0.0f && camera->viewport.r[3].w > 0.0f) {
        screenPos = camera->Project(wpos);
      } else {
        screenPos = camera->Project(wpos, 0.0f, 1920.0f, 1080.0f, 0.0f);
      }

      const float dx = screenPos.x - screenX;
      const float dy = screenPos.y - screenY;
      const float distSq = (dx * dx) + (dy * dy);

      if (distSq <= bestDistSq) {
        if (distSq < bestDistSq || w < bestW) {
          bestDistSq = distSq;
          bestW = w;
          bestHit = proxy.get();
        }
      }
    }

    return bestHit;
  }

  const PlannedUnitProxy* PlannedFactoryManager::HitTestScreenPoint(
    const GeomCamera3* const camera,
    const float screenX,
    const float screenY,
    const float pickRadius) const
  {
    return const_cast<PlannedFactoryManager*>(this)->HitTestScreenPoint(camera, screenX, screenY, pickRadius);
  }

  PlannedUnitProxy* PlannedFactoryManager::HitTestScreenPoint(
    const CUIWorldView* const view,
    const float screenX,
    const float screenY,
    const float pickRadius)
  {
    if (view == nullptr) {
      return nullptr;
    }
    const GeomCamera3* camera = const_cast<CUIWorldView*>(view)->GetCameraView();
    return HitTestScreenPoint(camera, screenX, screenY, pickRadius);
  }

  std::vector<PlannedUnitProxy*> PlannedFactoryManager::HitTestScreenRect(
    const GeomCamera3* const camera,
    const float minX,
    const float minY,
    const float maxX,
    const float maxY)
  {
    if (!IsFactoryPreOrdersEnabled() || camera == nullptr) {
      return {};
    }

    const float x0 = std::min(minX, maxX);
    const float x1 = std::max(minX, maxX);
    const float y0 = std::min(minY, maxY);
    const float y1 = std::max(minY, maxY);

    std::vector<PlannedUnitProxy*> results;
    for (const auto& proxy : mProxies) {
      if (!proxy) {
        continue;
      }

      const float w = (camera->viewProjection.r[0].w * proxy->mPosition.x) +
                      (camera->viewProjection.r[1].w * proxy->mPosition.y) +
                      (camera->viewProjection.r[2].w * proxy->mPosition.z) +
                      camera->viewProjection.r[3].w;
      if (w <= 0.001f) {
        continue;
      }

      const Wm3::Vector3f wpos{proxy->mPosition.x, proxy->mPosition.y, proxy->mPosition.z};
      Wm3::Vector2f screenPos;
      if (camera->viewport.r[3].z > 0.0f && camera->viewport.r[3].w > 0.0f) {
        screenPos = camera->Project(wpos);
      } else {
        screenPos = camera->Project(wpos, 0.0f, 1920.0f, 1080.0f, 0.0f);
      }

      if (screenPos.x >= x0 && screenPos.x <= x1 && screenPos.y >= y0 && screenPos.y <= y1) {
        results.push_back(proxy.get());
      }
    }

    return results;
  }

  std::vector<const PlannedUnitProxy*> PlannedFactoryManager::HitTestScreenRect(
    const GeomCamera3* const camera,
    const float minX,
    const float minY,
    const float maxX,
    const float maxY) const
  {
    auto mutableResults = const_cast<PlannedFactoryManager*>(this)->HitTestScreenRect(camera, minX, minY, maxX, maxY);
    return {mutableResults.begin(), mutableResults.end()};
  }

  std::vector<PlannedUnitProxy*> PlannedFactoryManager::HitTestScreenRect(
    const CUIWorldView* const view,
    const float minX,
    const float minY,
    const float maxX,
    const float maxY)
  {
    if (view == nullptr) {
      return {};
    }
    const GeomCamera3* camera = const_cast<CUIWorldView*>(view)->GetCameraView();
    return HitTestScreenRect(camera, minX, minY, maxX, maxY);
  }

  const std::vector<std::unique_ptr<PlannedUnitProxy>>& PlannedFactoryManager::GetAllProxies() const noexcept
  {
    return mProxies;
  }

  bool PlannedFactoryManager::DispatchPreOrdersForUnit(UserUnit* const unit)
  {
    if (unit == nullptr) {
      return false;
    }
    Wm3::Vec3f uPos = unit->GetPosition();
    if (uPos.x == 0.0f && uPos.z == 0.0f) {
      uPos = unit->mVariableData.mCurTransform.pos_;
    }
    if (uPos.x == 0.0f && uPos.z == 0.0f) {
      return false;
    }
    return DispatchPreOrdersForUnit(unit, Vector3f{uPos.x, uPos.y, uPos.z});
  }

  bool PlannedFactoryManager::DispatchPreOrdersForUnit(UserUnit* const unit, const Vector3f& unitPos)
  {
    if (unit == nullptr || !IsFactoryPreOrdersEnabled()) {
      return false;
    }

    CWldSession* const session = WLD_GetActiveSession();
    const auto unitId = (session != nullptr) ? unit->mParams.mEntityId : 0u;

    gpg::Logf("[PlannedFactory] DispatchPreOrdersForUnit: unit %u at (%.1f, %.1f, %.1f), proxies count=%zu",
              unitId, unitPos.x, unitPos.y, unitPos.z, mProxies.size());

    if (session != nullptr) {
      const UserArmy* const focusArmy = session->GetFocusUserArmy();
      if (focusArmy != nullptr && unit->mArmy != nullptr && unit->mArmy != focusArmy) {
        return false;
      }
    }

    PlannedUnitProxy* proxy = FindByPosition(unitPos, 8.0f);
    if (proxy == nullptr) {
      float bestDistSq = 64.0f; // 8.0f * 8.0f
      for (const auto& p : mProxies) {
        if (!p) continue;
        const float dx = p->mPosition.x - unitPos.x;
        const float dz = p->mPosition.z - unitPos.z;
        const float distSq = (dx * dx) + (dz * dz);
        if (distSq <= bestDistSq) {
          bestDistSq = distSq;
          proxy = p.get();
        }
      }
    }

    if (proxy == nullptr) {
      return false;
    }

    gpg::Logf("[PlannedFactory] Matching proxy %u found for unit %u! Dispatching %zu pre-orders (rally=%d, repeat=%d)",
              proxy->mProxyId, unitId, proxy->mPreOrders.size(),
              proxy->mHasRallyPoint ? 1 : 0, proxy->mRepeatBuild ? 1 : 0);

    if (mDispatchHook) {
      mDispatchHook(unit, *proxy);
      (void)RemoveProxy(proxy->mProxyId);
      return true;
    }

    gpg::fastvector<UserUnit*> targetUnits;
    targetUnits.push_back(unit);

    if (session != nullptr && session->mRules != nullptr) {
      for (const auto& order : proxy->mPreOrders) {
        RResId bpResId{};
        (void)gpg::STR_InitFilename(&bpResId.name, order.blueprintId.c_str());
        REntityBlueprint* const bp = session->mRules->GetEntityBlueprint(bpResId);
        if (bp != nullptr) {
          SSTICommandIssueData factoryCommand(EUnitCommandType::UNITCOMMAND_BuildFactory);
          factoryCommand.mBlueprint = static_cast<RUnitBlueprint*>(bp);
          for (int i = 0; i < order.count; ++i) {
            ISSUE_FactoryCommand(targetUnits, factoryCommand, false);
          }
        }
      }
    }

    if (proxy->mHasRallyPoint) {
      SSTICommandIssueData rallyCommand(EUnitCommandType::UNITCOMMAND_Move);
      rallyCommand.mTarget.mType = EAiTargetType::AITARGET_Ground;
      rallyCommand.mTarget.mPos = proxy->mRallyPoint;
      ISSUE_FactoryCommand(targetUnits, rallyCommand, false);
    }

    if (proxy->mRepeatBuild && session != nullptr) {
      if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
        driver->ProcessInfoPair(unit->mParams.mEntityId, "SetRepeatQueue", "true");
      }
    }

    if (proxy->mUserUnit != nullptr && unit != nullptr && session != nullptr) {
      proxy->mUserUnit->mUnitVarDat.mSelectionInheritorId = unit->mParams.mEntityId;
    }

    (void)RemoveProxy(proxy->mProxyId);
    return true;
  }

  bool PlannedFactoryManager::OnUnitCreatedOrProgress(
    const Vector3f& pos,
    const float progress,
    const std::function<void(const std::vector<PlannedUnitProxy::PreOrder>&, const Vector3f&, bool)>& callback,
    const float tolerance)
  {
    if (!IsFactoryPreOrdersEnabled() || progress <= 0.0f) {
      return false;
    }

    PlannedUnitProxy* proxy = FindByPosition(pos, tolerance);
    if (proxy == nullptr) {
      float bestDistSq = tolerance * tolerance;
      for (const auto& p : mProxies) {
        const float dx = p->mPosition.x - pos.x;
        const float dz = p->mPosition.z - pos.z;
        const float distSq = (dx * dx) + (dz * dz);
        if (distSq <= bestDistSq) {
          bestDistSq = distSq;
          proxy = p.get();
        }
      }
    }

    if (proxy == nullptr) {
      return false;
    }

    if (callback) {
      callback(proxy->mPreOrders, proxy->mRallyPoint, proxy->mRepeatBuild);
    }

    (void)RemoveProxy(proxy->mProxyId);
    return true;
  }

  PlannedFactoryManager& PlannedFactoryManager::Instance()
  {
    static PlannedFactoryManager sInstance;
    return sInstance;
  }
}
