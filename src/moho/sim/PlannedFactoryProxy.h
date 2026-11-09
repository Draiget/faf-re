#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cmath>
#include <limits>

#include "moho/math/Vector3f.h"

namespace moho
{
  struct REntityBlueprint;
  struct GeomCamera3;
  using CCamera = GeomCamera3;
  class CUIWorldView;

  /**
   * 3D Ray representation used for picking and hit testing.
   */
  struct Ray3f
  {
    Vector3f origin{Vector3f::ZERO};
    Vector3f direction{Vector3f::ZERO};

    Ray3f() = default;
    Ray3f(const Vector3f& orig, const Vector3f& dir)
      : origin(orig), direction(dir)
    {
    }
  };

  using Ray = Ray3f;

  /**
   * Client-side proxy representing a planned factory that has been ordered
   * by an engineer/ACU but has not yet begun physical construction (progress == 0).
   */
  struct PlannedUnitProxy
  {
    struct PreOrder
    {
      std::string blueprintId{};
      std::int32_t count{1};

      bool operator==(const PreOrder& other) const noexcept
      {
        return count == other.count && blueprintId == other.blueprintId;
      }
    };

    struct BuilderKey
    {
      std::uint32_t builderId{0};
      std::uint32_t cmdIndex{0};

      bool operator==(const BuilderKey& other) const noexcept
      {
        return builderId == other.builderId && cmdIndex == other.cmdIndex;
      }
    };

    std::uint32_t mProxyId{0};
    std::uint32_t mBuilderEntityId{0};
    std::uint32_t mBuilderCmdIndex{0};
    const REntityBlueprint* mBlueprint{nullptr};
    Vector3f mPosition{Vector3f::ZERO};

    std::vector<PreOrder> mPreOrders{};
    Vector3f mRallyPoint{Vector3f::ZERO};
    bool mHasRallyPoint{false};
    bool mRepeatBuild{false};

    std::vector<BuilderKey> mBuilders{};
    bool mIsSelected{false};
    float mBoundingRadius{5.0f};

    void AddPreOrder(const std::string& bpId, std::int32_t count = 1);
    bool RemovePreOrder(const std::string& bpId, std::int32_t count = 1);
    bool RemovePreOrderByIndex(std::size_t index, std::int32_t count = 1);
    void ClearPreOrders();

    void SetRallyPoint(const Vector3f& rallyPos);
    void ClearRallyPoint();

    void SetRepeatBuild(bool repeat);
    void ToggleRepeatBuild();

    void SetSelected(bool selected) noexcept { mIsSelected = selected; }
    [[nodiscard]] bool IsSelected() const noexcept { return mIsSelected; }

    void SetBoundingRadius(float radius) noexcept { mBoundingRadius = radius; }
    [[nodiscard]] float GetBoundingRadius() const noexcept { return mBoundingRadius; }

    [[nodiscard]] bool HasBuilder(std::uint32_t builderId, std::uint32_t cmdIndex) const noexcept;
    void AddBuilder(std::uint32_t builderId, std::uint32_t cmdIndex);
    bool RemoveBuilder(std::uint32_t builderId, std::uint32_t cmdIndex);
    bool RemoveAllBuildersFor(std::uint32_t builderId);
  };

  /**
   * Tracker and lifecycle manager for all client-side planned factory ghosts.
   */
  class PlannedFactoryManager
  {
  public:
    PlannedFactoryManager() = default;
    ~PlannedFactoryManager() = default;

    PlannedFactoryManager(const PlannedFactoryManager&) = delete;
    PlannedFactoryManager& operator=(const PlannedFactoryManager&) = delete;
    PlannedFactoryManager(PlannedFactoryManager&&) noexcept = default;
    PlannedFactoryManager& operator=(PlannedFactoryManager&&) noexcept = default;

    PlannedUnitProxy* RegisterOrUpdatePlannedFactory(
      std::uint32_t builderId,
      std::uint32_t cmdIndex,
      const REntityBlueprint* bp,
      const Vector3f& pos);

    [[nodiscard]] PlannedUnitProxy* FindByPosition(const Vector3f& pos, float tolerance = 1.0f);
    [[nodiscard]] const PlannedUnitProxy* FindByPosition(const Vector3f& pos, float tolerance = 1.0f) const;

    [[nodiscard]] PlannedUnitProxy* FindByBuilderAndIndex(std::uint32_t builderId, std::uint32_t cmdIndex);
    [[nodiscard]] const PlannedUnitProxy* FindByBuilderAndIndex(std::uint32_t builderId, std::uint32_t cmdIndex) const;

    [[nodiscard]] PlannedUnitProxy* FindByProxyId(std::uint32_t proxyId);
    [[nodiscard]] const PlannedUnitProxy* FindByProxyId(std::uint32_t proxyId) const;

    void RemoveByBuilder(std::uint32_t builderId);
    void RemoveByBuilderAndIndex(std::uint32_t builderId, std::uint32_t cmdIndex);
    bool RemoveProxy(std::uint32_t proxyId);
    void ClearAll();

    [[nodiscard]] std::size_t GetCount() const noexcept;

    // Selection management
    void SelectProxy(std::uint32_t proxyId, bool addToSelection = false);
    void DeselectProxy(std::uint32_t proxyId);
    void ClearSelection();
    [[nodiscard]] std::vector<PlannedUnitProxy*> GetSelectedProxies();
    [[nodiscard]] std::vector<const PlannedUnitProxy*> GetSelectedProxies() const;

    // 3D Ray hit test
    [[nodiscard]] PlannedUnitProxy* HitTestRay(const Ray3f& ray, float radius = 5.0f);
    [[nodiscard]] const PlannedUnitProxy* HitTestRay(const Ray3f& ray, float radius = 5.0f) const;

    // Screen point hit test (mouse pick)
    [[nodiscard]] PlannedUnitProxy* HitTestScreenPoint(
      const GeomCamera3* camera,
      float screenX,
      float screenY,
      float pickRadius = 30.0f);
    [[nodiscard]] const PlannedUnitProxy* HitTestScreenPoint(
      const GeomCamera3* camera,
      float screenX,
      float screenY,
      float pickRadius = 30.0f) const;

    [[nodiscard]] PlannedUnitProxy* HitTestScreenPoint(
      const CUIWorldView* view,
      float screenX,
      float screenY,
      float pickRadius = 30.0f);

    // Screen rectangle hit test (drag box selection)
    [[nodiscard]] std::vector<PlannedUnitProxy*> HitTestScreenRect(
      const GeomCamera3* camera,
      float minX,
      float minY,
      float maxX,
      float maxY);
    [[nodiscard]] std::vector<const PlannedUnitProxy*> HitTestScreenRect(
      const GeomCamera3* camera,
      float minX,
      float minY,
      float maxX,
      float maxY) const;

    [[nodiscard]] std::vector<PlannedUnitProxy*> HitTestScreenRect(
      const CUIWorldView* view,
      float minX,
      float minY,
      float maxX,
      float maxY);

    [[nodiscard]] const std::vector<std::unique_ptr<PlannedUnitProxy>>& GetAllProxies() const noexcept;

    static PlannedFactoryManager& Instance();
    static PlannedFactoryManager& Get() noexcept { return Instance(); }

  private:
    std::uint32_t mNextProxyId{1};
    std::vector<std::unique_ptr<PlannedUnitProxy>> mProxies;
  };
}
