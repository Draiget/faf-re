#include "moho/sim/PlannedFactoryProxy.h"

#include "moho/console/CConCommand.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/ui/UiRuntimeTypes.h"

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

  void PlannedFactoryManager::SelectProxy(const std::uint32_t proxyId, const bool addToSelection)
  {
    if (!addToSelection) {
      ClearSelection();
    }
    if (auto* proxy = FindByProxyId(proxyId)) {
      proxy->SetSelected(true);
    }
  }

  void PlannedFactoryManager::DeselectProxy(const std::uint32_t proxyId)
  {
    if (auto* proxy = FindByProxyId(proxyId)) {
      proxy->SetSelected(false);
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

  PlannedFactoryManager& PlannedFactoryManager::Instance()
  {
    static PlannedFactoryManager sInstance;
    return sInstance;
  }
}
