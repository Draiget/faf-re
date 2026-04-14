#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAiTargetType.h"
#include "moho/misc/WeakPtr.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class Entity;
  class Sim;
  struct SSTITarget;
  enum EImpactType : std::int32_t;

  class CAiTarget
  {
  public:
    CAiTarget() = default;

    /**
     * Address: 0x005D5670 (FUN_005D5670)
     *
     * What it does:
     * Copy-constructs target payload/link state from another target object.
     */
    CAiTarget(const CAiTarget& source);

    /**
     * Address: 0x005D5670 (FUN_005D5670)
     *
     * What it does:
     * Assigns payload/link state from another target object.
     */
    CAiTarget& operator=(const CAiTarget& source);

    /**
     * Address: 0x005D57E0 (FUN_005D57E0)
     *
     * What it does:
     * Unlinks this target node from its current entity weak-link chain.
     */
    ~CAiTarget();

    /**
     * Address: 0x005D55B0 (FUN_005D55B0)
     *
     * What it does:
     * Rebinds this target to `entity`, then recomputes mobility/target-point data.
     */
    CAiTarget* UpdateTarget(Entity* entity);

    /**
     * Address: 0x00623240 (FUN_00623240, Moho::CAiTarget::GetLuaTarget)
     *
     * What it does:
     * Parses one Lua target object (`Type` + payload fields) and updates this
     * target to entity or ground form.
     */
    CAiTarget* GetLuaTarget(Sim* sim, const LuaPlus::LuaObject& object);

    /**
     * Address: 0x005E2A90 (FUN_005E2A90, Moho::CAiTarget::GetTargetPosGun)
     *
     * What it does:
     * Resolves one weapon-target world position from this target payload and
     * either uses exact live position lanes or selected target-point lanes.
     */
    [[nodiscard]] Wm3::Vec3f GetTargetPosGun(bool useActualPos);

    /**
     * Address: 0x005E2A10 (FUN_005E2A10, Moho::CAiTarget::HasTarget)
     *
     * What it does:
     * Reports whether this target currently resolves to a valid alive target
     * payload (entity or ground target).
     */
    [[nodiscard]] bool HasTarget() const;

    /**
     * Address: 0x005E2D40 (FUN_005E2D40, Moho::CAiTarget::HasSameTargetEntity)
     *
     * What it does:
     * Returns whether both targets resolve to the same live target-entity lane.
     */
    [[nodiscard]] bool HasSameTargetEntity(const CAiTarget& other) const;

    /**
     * Address: 0x005E2DB0 (FUN_005E2DB0, Moho::CAiTarget::NoTarget)
     *
     * What it does:
     * Returns true when this target has a bound weak-entity lane but resolves
     * to either a missing entity or a dead entity.
     */
    [[nodiscard]] bool NoTarget() const;

    /**
     * Address: 0x005E2CE0 (FUN_005E2CE0, Moho::CAiTarget::GetEntity)
     *
     * What it does:
     * Returns the current entity target; when target is a recon blip this
     * resolves to that blip's source unit entity.
     */
    [[nodiscard]] Entity* GetEntity() const;

    /**
     * Address: 0x0062A900 (FUN_0062A900, Moho::CAiTarget::ImpactDidHitEntity)
     *
     * What it does:
     * Tests whether one impact event actually hit this target's entity/ground
     * payload, including one-level parent-attach fallback for entity targets.
     */
    [[nodiscard]] bool ImpactDidHitEntity(Entity* entity, EImpactType impactType);

    /**
     * Address: 0x005E2860 (FUN_005E2860)
     *
     * What it does:
     * Refreshes `targetIsMobile` by checking the target entity category bitset.
     */
    void UpdateTargetIsMobile(Sim* sim);

    /**
     * Address: 0x005E28F0 (FUN_005E28F0)
     *
     * What it does:
     * Selects a target-point index for unit/recon-blip entity targets.
     */
    void PickTargetPoint();

    /**
     * Address: 0x005E2620 (FUN_005E2620)
     *
     * What it does:
     * Decodes command-network `SSTITarget` payload into this runtime target object.
     */
    CAiTarget* DecodeFromSSTITarget(const SSTITarget& source, Sim* sim);

    /**
     * Address: 0x005E27D0 (FUN_005E27D0)
     *
     * What it does:
     * Encodes this runtime target object into command-network `SSTITarget` payload.
     */
    void EncodeToSSTITarget(SSTITarget& out) const;

    /**
     * Address: 0x005E3880 (FUN_005E3880)
     *
     * What it does:
     * Deserializes reflected `CAiTarget` fields from archive stream.
     */
    static void DeserializeFromArchive(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E3950 (FUN_005E3950)
     *
     * What it does:
     * Serializes reflected `CAiTarget` fields into archive stream.
     */
    static void SerializeToArchive(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  private:
    /**
     * Address: 0x005D5670 (FUN_005D5670)
     *
     * What it does:
     * Core link/payload copier used by copy-ctor and assignment.
     */
    void CopyFromLinkedTarget(const CAiTarget& source);

    /**
     * Address: 0x005D57E0 (FUN_005D57E0)
     *
     * What it does:
     * Unlinks this target from owner weak-link slot chain.
     */
    void UnlinkEntityTargetRef();

  public:
    static gpg::RType* sType;

    EAiTargetType targetType;
    WeakPtr<Entity> targetEntity;
    Wm3::Vec3f position;
    std::int32_t targetPoint;
    bool targetIsMobile;
  };

  static_assert(offsetof(CAiTarget, targetType) == 0x00, "CAiTarget::targetType offset must be 0x00");
  static_assert(offsetof(CAiTarget, targetEntity) == 0x04, "CAiTarget::targetEntity offset must be 0x04");
  static_assert(offsetof(CAiTarget, position) == 0x0C, "CAiTarget::position offset must be 0x0C");
  static_assert(offsetof(CAiTarget, targetPoint) == 0x18, "CAiTarget::targetPoint offset must be 0x18");
  static_assert(offsetof(CAiTarget, targetIsMobile) == 0x1C, "CAiTarget::targetIsMobile offset must be 0x1C");
  static_assert(sizeof(CAiTarget) == 0x20, "CAiTarget size must be 0x20");

  /**
   * Address: 0x005E2EC0 (FUN_005E2EC0, Moho::SCR_ToLua<Moho::CAiTarget>)
   *
   * What it does:
   * Serializes one AI target payload into Lua table form.
   */
  void SCR_ToLua_CAiTarget(LuaPlus::LuaObject& outObject, LuaPlus::LuaState* state, const CAiTarget& target);

  /**
   * Address: 0x005E3000 (FUN_005E3000, Moho::SCR_FromLuaCopy<Moho::CAiTarget>)
   *
   * What it does:
   * Parses one Lua target table (`Type` + payload fields) into `outTarget`.
   */
  void SCR_FromLuaCopy_CAiTarget(CAiTarget& outTarget, const LuaPlus::LuaObject& object);
} // namespace moho
