#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAiTargetType.h"
#include "moho/misc/WeakPtr.h"
#include "wm3/Vector3.h"

namespace moho
{
  class Entity;
  class Sim;
  struct SSTITarget;

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
} // namespace moho
