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

    /**
     * Intrusive link->owner downcast for the bound collision-beam listener.
     *
     * `ownerLinkSlot` points at the listener node's weak-link field, which sits
     * at `listener + 0x04` (see `BindManyToOneListener`, which stores
     * `listener + WeakPtr<void>::kOwnerLinkOffset`). The owning listener is
     * therefore `ownerLinkSlot - 0x04`, and a slot holding the bare offset
     * value `4` is the empty-chain sentinel, which decays to null under the
     * same subtraction.
     *
     * Reconstructed from `CollisionBeamEntity::CheckCollision` (FUN_006732D0),
     * which repeats this exact gate once per event code:
     *   `8B 87 70 02 00 00  mov  eax, [edi+270h]`
     *   `85 C0              test eax, eax`
     *   `74 0F              jz   skip`
     *   `8D 48 FC           lea  ecx, [eax-4]`
     *   `85 C9              test ecx, ecx`
     *   `74 08              jz   skip`
     *   `8B 01 / 8B 10 / FF D2   call [[ecx]]  ; slot-0 virtual`
     *
     * Mirrors `ManyToOneBroadcaster<EProjectileImpactEvent>::GetListener`.
     */
    [[nodiscard]] ManyToOneListener<ECollisionBeamEvent>* GetListener() const noexcept
    {
      constexpr std::uintptr_t kListenerWeakLinkOffset = 0x04u;
      const auto slot = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
      if (slot == 0u || slot == kListenerWeakLinkOffset) {
        return nullptr;
      }
      return reinterpret_cast<ManyToOneListener<ECollisionBeamEvent>*>(slot - kListenerWeakLinkOffset);
    }
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
