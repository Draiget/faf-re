#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Recovered enum lane used by collision-beam broadcaster/listener chains.
   *
   * Enumerator values remain pending deeper behavior reconstruction; only the
   * ABI/storage lane is required for startup reflection recovery.
   */
  enum ECollisionBeamEvent : int
  {
    CollisionBeamEvent_None = 0
  };

  template <class TEvent>
  class ManyToOneBroadcaster;

  template <>
  class ManyToOneBroadcaster<ECollisionBeamEvent>
  {
  public:
    static gpg::RType* sType;

  public:
    std::uint32_t weakLinkHead_; // +0x00
    std::uint32_t reserved04;    // +0x04
  };

  using ManyToOneBroadcaster_ECollisionBeamEvent = ManyToOneBroadcaster<ECollisionBeamEvent>;

  static_assert(
    sizeof(ManyToOneBroadcaster_ECollisionBeamEvent) == 0x08,
    "ManyToOneBroadcaster<ECollisionBeamEvent> size must be 0x08"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_ECollisionBeamEvent, weakLinkHead_) == 0x00,
    "ManyToOneBroadcaster<ECollisionBeamEvent>::weakLinkHead_ offset must be 0x00"
  );
  static_assert(
    offsetof(ManyToOneBroadcaster_ECollisionBeamEvent, reserved04) == 0x04,
    "ManyToOneBroadcaster<ECollisionBeamEvent>::reserved04 offset must be 0x04"
  );
} // namespace moho

