#pragma once

#include <cstddef>
#include <cstdint>

namespace Wm3
{
  template <class T>
  class Vector3;
  using Vector3f = Vector3<float>;
} // namespace Wm3

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct Vector4f;
  class VTransform;

  /**
    * Alias of FUN_00678E90 (non-canonical helper lane).
   *
   * What it does:
   * Packed transform payload used by Entity/Prop paths: quaternion lanes followed
   * by world position lanes.
   */
  struct EntityTransformPayload
  {
    float quatW; // Entity::Vector4f.x lane
    float quatX; // Entity::Vector4f.y lane
    float quatY; // Entity::Vector4f.z lane
    float quatZ; // Entity::Vector4f.w lane
    float posX;
    float posY;
    float posZ;
  };

  inline constexpr std::int32_t kEntityPositionHistorySampleCount = 25;

  static_assert(offsetof(EntityTransformPayload, quatW) == 0x00, "EntityTransformPayload::quatW offset must be 0x00");
  static_assert(offsetof(EntityTransformPayload, quatX) == 0x04, "EntityTransformPayload::quatX offset must be 0x04");
  static_assert(offsetof(EntityTransformPayload, quatY) == 0x08, "EntityTransformPayload::quatY offset must be 0x08");
  static_assert(offsetof(EntityTransformPayload, quatZ) == 0x0C, "EntityTransformPayload::quatZ offset must be 0x0C");
  static_assert(offsetof(EntityTransformPayload, posX) == 0x10, "EntityTransformPayload::posX offset must be 0x10");
  static_assert(offsetof(EntityTransformPayload, posY) == 0x14, "EntityTransformPayload::posY offset must be 0x14");
  static_assert(offsetof(EntityTransformPayload, posZ) == 0x18, "EntityTransformPayload::posZ offset must be 0x18");
  static_assert(sizeof(EntityTransformPayload) == 0x1C, "EntityTransformPayload size must be 0x1C");

  /**
   * Address: 0x00676FA0 (FUN_00676FA0)
   *
   * What it does:
   * Stores a rolling transform history buffer used by entity sync/serialization.
   */
  struct PositionHistory
  {
    inline static gpg::RType* sType = nullptr;

    EntityTransformPayload samples[kEntityPositionHistorySampleCount];
    std::int32_t cursor;

    /**
     * Address: 0x0067EE60 (FUN_0067EE60, Moho::PositionHistory::MemberDeserialize)
     *
     * What it does:
     * Deserializes 25 sampled transforms and the active cursor index.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0067EED0 (FUN_0067EED0, Moho::PositionHistory::MemberSerialize)
     *
     * What it does:
     * Serializes 25 sampled transforms and the active cursor index.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  using EntityPositionHistoryRing = PositionHistory;

  /**
   * Address: 0x006770F0 (FUN_006770F0, struct_QuatBVec::struct_QuatBVec)
   *
   * What it does:
   * Initializes one history sample to identity orientation and zero position.
   */
  void InitializePositionHistorySample(EntityTransformPayload& sample) noexcept;

  /**
    * Alias of FUN_00678800 (non-canonical helper lane).
   *
   * What it does:
   * Initializes all position-history samples and resets cursor to `0`.
   */
  void InitializePositionHistory(PositionHistory& history) noexcept;

  /**
    * Alias of FUN_00678E90 (non-canonical helper lane).
   *
   * What it does:
   * Reads packed transform lanes from entity orientation/position storage.
   */
  [[nodiscard]]
  EntityTransformPayload
  ReadEntityTransformPayload(const Vector4f& orientation, const Wm3::Vector3f& position) noexcept;

  /**
    * Alias of FUN_00678E90 (non-canonical helper lane).
   *
   * What it does:
   * Writes packed transform lanes back to entity orientation/position storage.
   */
  void WriteEntityTransformPayload(
    Vector4f& orientation, Wm3::Vector3f& position, const EntityTransformPayload& payload
  ) noexcept;

  /**
    * Alias of FUN_00679210 (non-canonical helper lane).
   *
   * What it does:
   * Builds packed payload from a typed `VTransform`.
   */
  [[nodiscard]]
  EntityTransformPayload ReadEntityTransformPayload(const VTransform& transform) noexcept;

  /**
    * Alias of FUN_00679CE0 (non-canonical helper lane).
   *
   * What it does:
   * Rebuilds a typed `VTransform` from packed payload lanes.
   */
  [[nodiscard]]
  VTransform BuildVTransformFromEntityTransformPayload(const EntityTransformPayload& payload) noexcept;

  /**
   * Address: 0x004F0A50 (FUN_004F0A50)
   *
   * What it does:
   * Bitwise position-lane compare (`memcmp(..., 0x0C)` equivalent).
   */
  [[nodiscard]]
  bool EntityTransformPositionDiffers(const EntityTransformPayload& lhs, const EntityTransformPayload& rhs) noexcept;

  /**
   * Address: 0x004F0B40 (FUN_004F0B40)
   *
   * What it does:
   * Bitwise quaternion-lane compare (`memcmp(..., 0x10)` equivalent).
   */
  [[nodiscard]]
  bool EntityTransformOrientationDiffers(const EntityTransformPayload& lhs, const EntityTransformPayload& rhs) noexcept;

  /**
    * Alias of FUN_00678F10 (non-canonical helper lane).
   *
   * What it does:
   * Appends previous/current transform snapshots into the rolling history ring.
   */
  void RecordEntityPositionHistory(
    PositionHistory& history, const EntityTransformPayload& previous, const EntityTransformPayload& current
  ) noexcept;

  static_assert(offsetof(PositionHistory, samples) == 0x00, "PositionHistory::samples offset must be 0x00");
  static_assert(sizeof(PositionHistory) == 0x2C0, "PositionHistory size must be 0x2C0");
  static_assert(offsetof(PositionHistory, cursor) == 0x2BC, "PositionHistory::cursor offset must be 0x2BC");
} // namespace moho
