#include "EntityTransformPayload.h"

#include <cstring>

#include "moho/math/Vector4f.h"
#include "moho/render/camera/VTransform.h"
#include "Wm3Vector3.h"

namespace moho
{
  /**
   * Address: 0x006770F0 (FUN_006770F0, struct_QuatBVec::struct_QuatBVec)
   *
   * What it does:
   * Initializes one history sample to identity orientation and zero position.
   */
  void InitializePositionHistorySample(EntityTransformPayload& sample) noexcept
  {
    sample.quatW = 1.0f;
    sample.quatX = 0.0f;
    sample.quatY = 0.0f;
    sample.quatZ = 0.0f;
    sample.posX = 0.0f;
    sample.posY = 0.0f;
    sample.posZ = 0.0f;
  }

  /**
    * Alias of FUN_00678800 (non-canonical helper lane).
   *
   * What it does:
   * Initializes all position-history samples and resets cursor to `0`.
   */
  void InitializePositionHistory(PositionHistory& history) noexcept
  {
    for (EntityTransformPayload& sample : history.samples) {
      InitializePositionHistorySample(sample);
    }
    history.cursor = 0;
  }

  /**
    * Alias of FUN_00678E90 (non-canonical helper lane).
   *
   * What it does:
   * Reads packed transform lanes from entity orientation/position storage.
   */
  EntityTransformPayload ReadEntityTransformPayload(const Vector4f& orientation, const Wm3::Vector3f& position) noexcept
  {
    EntityTransformPayload payload{};
    payload.quatW = orientation.x;
    payload.quatX = orientation.y;
    payload.quatY = orientation.z;
    payload.quatZ = orientation.w;
    payload.posX = position.x;
    payload.posY = position.y;
    payload.posZ = position.z;
    return payload;
  }

  /**
    * Alias of FUN_00678E90 (non-canonical helper lane).
   *
   * What it does:
   * Writes packed transform lanes back to entity orientation/position storage.
   */
  void WriteEntityTransformPayload(
    Vector4f& orientation, Wm3::Vector3f& position, const EntityTransformPayload& payload
  ) noexcept
  {
    orientation.x = payload.quatW;
    orientation.y = payload.quatX;
    orientation.z = payload.quatY;
    orientation.w = payload.quatZ;
    position.x = payload.posX;
    position.y = payload.posY;
    position.z = payload.posZ;
  }

  /**
    * Alias of FUN_00679210 (non-canonical helper lane).
   *
   * What it does:
   * Builds packed payload from a typed `VTransform`.
   */
  EntityTransformPayload ReadEntityTransformPayload(const VTransform& transform) noexcept
  {
    EntityTransformPayload payload{};
    // Entity orientation lanes are stored as (w,x,y,z) in Vector4f::x/y/z/w slots.
    payload.quatW = transform.orient_.w;
    payload.quatX = transform.orient_.x;
    payload.quatY = transform.orient_.y;
    payload.quatZ = transform.orient_.z;
    payload.posX = transform.pos_.x;
    payload.posY = transform.pos_.y;
    payload.posZ = transform.pos_.z;
    return payload;
  }

  /**
    * Alias of FUN_00679CE0 (non-canonical helper lane).
   *
   * What it does:
   * Rebuilds a typed `VTransform` from packed payload lanes.
   */
  VTransform BuildVTransformFromEntityTransformPayload(const EntityTransformPayload& payload) noexcept
  {
    VTransform transform{};
    transform.orient_.w = payload.quatW;
    transform.orient_.x = payload.quatX;
    transform.orient_.y = payload.quatY;
    transform.orient_.z = payload.quatZ;
    transform.pos_.x = payload.posX;
    transform.pos_.y = payload.posY;
    transform.pos_.z = payload.posZ;
    return transform;
  }

  /**
   * Address: 0x004F0A50 (FUN_004F0A50)
   *
   * What it does:
   * Bitwise position-lane compare (`memcmp(..., 0x0C)` equivalent).
   */
  bool EntityTransformPositionDiffers(const EntityTransformPayload& lhs, const EntityTransformPayload& rhs) noexcept
  {
    return std::memcmp(&lhs.posX, &rhs.posX, sizeof(float) * 3u) != 0;
  }

  /**
   * Address: 0x004F0B40 (FUN_004F0B40)
   *
   * What it does:
   * Bitwise quaternion-lane compare (`memcmp(..., 0x10)` equivalent).
   */
  bool EntityTransformOrientationDiffers(const EntityTransformPayload& lhs, const EntityTransformPayload& rhs) noexcept
  {
    return std::memcmp(&lhs.quatW, &rhs.quatW, sizeof(float) * 4u) != 0;
  }

  /**
    * Alias of FUN_00678F10 (non-canonical helper lane).
   *
   * What it does:
   * Appends previous/current transform snapshots into the rolling history ring.
   */
  void RecordEntityPositionHistory(
    PositionHistory& history, const EntityTransformPayload& previous, const EntityTransformPayload& current
  ) noexcept
  {
    const std::int32_t cursor = history.cursor;
    history.samples[cursor] = previous;
    const std::int32_t nextCursor = (cursor + 1) % kEntityPositionHistorySampleCount;
    history.cursor = nextCursor;
    history.samples[nextCursor] = current;
  }
} // namespace moho
