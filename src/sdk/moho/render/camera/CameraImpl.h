#pragma once

#include "moho/render/camera/GeomCamera3.h"
#include "wm3/Vector3.h"

namespace moho
{
  class CameraImpl
  {
  public:
    /**
     * Address context: called from `RCamManager::Frame` (`0x007AABB0`) camera-loop lane.
     *
     * What it does:
     * Advances one camera runtime for the current sim/frame delta pair.
     */
    void Frame(float simDeltaSeconds, float frameSeconds);

    /**
     * Address: 0x007A7DC0 (sub_7A7DC0)
     * Slot: 0
     */
    virtual void Reserved00() = 0;

    /**
     * Address: 0x007A69F0 (Moho::CameraImpl::CameraGetName)
     * Slot: 1
     */
    [[nodiscard]] virtual const char* CameraGetName() const = 0;

    /**
     * Address: 0x007A6A00 (Moho::CameraImpl::CameraGetView)
     * Slot: 2
     */
    [[nodiscard]] virtual const GeomCamera3& CameraGetView() const = 0;

    /**
     * Address: 0x007A6C80 (Moho::CameraImpl::CameraGetOffset)
     * Slot: 18
     *
     * What it does:
     * Returns the world-camera offset vector used by listener metric updates.
     */
    [[nodiscard]] virtual const Wm3::Vec3f& CameraGetOffset() const = 0;

    /**
     * Address: 0x007A6CA0 (Moho::CameraImpl::CameraGetTargetZoom)
     * Slot: 19
     */
    [[nodiscard]] virtual float CameraGetTargetZoom() const = 0;

    /**
     * Address: 0x007A7310 (Moho::CameraImpl::GetMaxZoom)
     * Slot: 20
     */
    [[nodiscard]] virtual float GetMaxZoom() const = 0;

    /**
     * Address: 0x007A79E0 (Moho::CameraImpl::LODMetric)
     * Slot: 45
     */
    [[nodiscard]] virtual float LODMetric(const Wm3::Vec3f& offset) const = 0;
  };

  static_assert(sizeof(CameraImpl) == sizeof(void*), "CameraImpl size must be pointer-sized");
} // namespace moho
