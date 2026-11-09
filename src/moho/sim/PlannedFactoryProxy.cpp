#include "moho/sim/PlannedFactoryProxy.h"

namespace moho
{
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

    mProxies.push_back(std::move(newProxy));
    return mProxies.back().get();
  }

  PlannedUnitProxy* PlannedFactoryManager::FindByPosition(const Vector3f& pos, const float tolerance)
  {
    float bestDistSq = tolerance * tolerance;
    PlannedUnitProxy* bestProxy = nullptr;

    for (const auto& proxy : mProxies) {
      const float dx = proxy->mPosition.x - pos.x;
      const float dy = proxy->mPosition.y - pos.y;
      const float dz = proxy->mPosition.z - pos.z;
      const float distSq = (dx * dx) + (dy * dy) + (dz * dz);
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

  void PlannedFactoryManager::RemoveByBuilder(const std::uint32_t builderId)
  {
    for (auto it = mProxies.begin(); it != mProxies.end();) {
      PlannedUnitProxy* proxy = it->get();
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
    for (auto it = mProxies.begin(); it != mProxies.end(); ++it) {
      PlannedUnitProxy* proxy = it->get();
      if (proxy->RemoveBuilder(builderId, cmdIndex)) {
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
    const auto it = std::find_if(
      mProxies.begin(),
      mProxies.end(),
      [proxyId](const std::unique_ptr<PlannedUnitProxy>& p) {
        return p->mProxyId == proxyId;
      });

    if (it != mProxies.end()) {
      mProxies.erase(it);
      return true;
    }
    return false;
  }

  void PlannedFactoryManager::ClearAll()
  {
    mProxies.clear();
  }

  std::size_t PlannedFactoryManager::GetCount() const noexcept
  {
    return mProxies.size();
  }

  PlannedUnitProxy* PlannedFactoryManager::HitTestRay(const Ray3f& ray, const float radius)
  {
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

  const std::vector<std::unique_ptr<PlannedUnitProxy>>& PlannedFactoryManager::GetAllProxies() const noexcept
  {
    return mProxies;
  }

  PlannedFactoryManager& PlannedFactoryManager::Instance()
  {
    static PlannedFactoryManager sInstance;
    return sInstance;
  }
}
