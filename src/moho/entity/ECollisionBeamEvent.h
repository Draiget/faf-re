#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/ManyToOneBroadcaster.h"

namespace moho
{
  enum ECollisionBeamEvent : int
  {
    CollisionBeamEvent_HitTarget = 0,
    CollisionBeamEvent_MissTarget = 1,
    CollisionBeamEvent_Irrelavent = 2
  };

  /**
   * Single-listener sink for collision-beam impact events, and the broadcaster
   * node that binds to it. Both come from the one template pair in
   * `moho/misc/ManyToOneBroadcaster.h`.
   *
   * The broadcaster half used to be an explicit specialization spelled out here,
   * carrying its own `void* ownerLinkSlot` / `void* nextInOwner` pair and an
   * open-coded `GetListener`; the listener half was a second explicit
   * specialization in CAcquireTargetTask.h whose slot-0 virtual was called
   * `HandleCollisionBeamListenerState(int)` rather than `OnEvent`. Both were
   * duplicates of the projectile-impact pair, which is the same template with a
   * different event type.
   */
  using ManyToOneBroadcaster_ECollisionBeamEvent = ManyToOneBroadcaster<ECollisionBeamEvent>;
  using ManyToOneListener_ECollisionBeamEvent = ManyToOneListener<ECollisionBeamEvent>;
} // namespace moho
