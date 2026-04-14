#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  class RType;
}

namespace moho
{
  enum ECollisionBeamEvent : int
  {
    CollisionBeamEvent_HitTarget = 0,
    CollisionBeamEvent_MissTarget = 1,
    CollisionBeamEvent_Irrelavent = 2
  };

  template <class TEvent>
  class ManyToOneBroadcaster;

  template <class TEvent>
  class ManyToOneListener;

  template <>
  class ManyToOneBroadcaster<ECollisionBeamEvent>
  {
  public:
    static gpg::RType* sType;

  public:
    void* ownerLinkSlot; // +0x00
    void* nextInOwner;   // +0x04

    /**
     * Address: 0x005DC340 (FUN_005DC340, Moho::ManyToOneBroadcaster_ECollisionBeamEvent::BroadcastEvent)
     *
     * What it does:
     * Rebinds this collision-beam broadcaster node to the supplied listener
     * chain head while preserving intrusive owner-chain integrity.
     */
    void BroadcastEvent(ManyToOneListener<ECollisionBeamEvent>* listener);
  };

  using ManyToOneBroadcaster_ECollisionBeamEvent = ManyToOneBroadcaster<ECollisionBeamEvent>;

  static_assert(
    sizeof(ManyToOneBroadcaster_ECollisionBeamEvent) == 0x08,
    "ManyToOneBroadcaster<ECollisionBeamEvent> size must be 0x08"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_ECollisionBeamEvent, ownerLinkSlot) == 0x00,
    "ManyToOneBroadcaster<ECollisionBeamEvent>::ownerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_ECollisionBeamEvent, nextInOwner) == 0x04,
    "ManyToOneBroadcaster<ECollisionBeamEvent>::nextInOwner offset must be 0x04"
  );
} // namespace moho
