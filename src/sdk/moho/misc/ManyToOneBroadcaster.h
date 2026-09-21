#pragma once

#include <cstddef>

#include "moho/misc/WeakObject.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * One-to-one counterpart of `moho::Listener<TEvent>` (moho/misc/Listener.h).
   *
   * Where `Listener<TEvent>` links into a ring shared by many listeners, a
   * `ManyToOneListener<TEvent>` is the single sink a `ManyToOneBroadcaster<TEvent>`
   * points at: the listener owns a weak-link chain head and the broadcaster is
   * one node in it, so the broadcaster observes the listener's lifetime rather
   * than owning it.
   *
   * Layout `{ vptr@0x00; WeakObject::weakLinkHead_@0x04 }`, size 0x08, confirmed
   * by RTTI (`.?AV?$ManyToOneListener@W4ECollisionBeamEvent@Moho@@@Moho@@`:
   * base `Moho::WeakObject` at mdisp=4, one-slot vftable at subobjectOffset=0,
   * `dumps/rtti_dump_all.hpp:13754`), and by the two owners the binary declares:
   * `CAcquireTargetTask` carries the `EProjectileImpactEvent` listener at
   * mdisp=24 and the `ECollisionBeamEvent` one at mdisp=32
   * (`dumps/rtti_dump_all.hpp:44768`).
   *
   * `OnEvent` is the slot-0 virtual: `Projectile::Impact` dispatches it with
   * `mov edx,[ecx]; mov eax,[edx]; call eax` at 0x0069E10E, and
   * `CollisionBeamEntity::CheckCollision` repeats the same shape at 0x006733F0.
   *
   * This used to be three separate explicit specializations - one per event in
   * `EProjectileImpactEvent.h`, `ECollisionBeamEvent.h` and
   * `CAcquireTargetTask.h` - whose bodies were identical apart from the name of
   * the slot-0 virtual (`OnEvent` in one, `HandleCollisionBeamListenerState` in
   * another, for the same one-int-argument dispatch). One template emits both.
   */
  template <class TEvent>
  class ManyToOneListener : public WeakObject
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x005D88F0 (FUN_005D88F0, the `EProjectileImpactEvent` emission)
     * Address: 0x005D8930 (FUN_005D8930, the `ECollisionBeamEvent` emission)
     *
     * What it does:
     * Starts the listener with an empty weak-link chain, so a broadcaster that
     * binds before any other node does becomes the head.
     */
    ManyToOneListener() noexcept
      : WeakObject()
    {
      weakLinkHead_ = 0u;
    }

    virtual int OnEvent(TEvent event) = 0;
  };

  /**
   * The broadcaster half: one intrusive weak node aimed at the single
   * `ManyToOneListener<TEvent>` currently bound, or at nothing.
   *
   * RTTI declares it a base rather than a member of both owners -
   * `Moho::Projectile` carries `ManyToOneBroadcaster<EProjectileImpactEvent>` at
   * mdisp=624 (0x270, `dumps/rtti_dump_all.hpp:63981`) and
   * `Moho::CollisionBeamEntity` carries `ManyToOneBroadcaster<ECollisionBeamEvent>`
   * at the same 0x270 (`dumps/rtti_dump_all.hpp:57156`). Both are modelled as a
   * member at that offset here, which is layout-identical (`sizeof(Entity)` is
   * 0x270, so the base would land exactly where the member does) and is why the
   * `add eax, 0x270` the call sites emit is the same either way.
   *
   * The node itself is `WeakPtr<ManyToOneListener<TEvent>>` - the same
   * `{ownerLinkSlot@0x00, nextInOwner@0x04}` pair, the same head-insert on bind,
   * the same chain-walk on unbind, and the same `slot - kOwnerLinkOffset` decode
   * back to the owner. That is not an analogy: `SetListener`'s two emissions
   * below are instruction-for-instruction `WeakPtr<T>::ResetFromOwnerLinkSlot`
   * (moho/misc/WeakPtr.h), which is why this holds one instead of restating it.
   * Three hand-written copies of those fields - a `void* ownerLinkSlot` /
   * `void* nextInOwner` pair plus an open-coded `GetListener` in each of
   * `ECollisionBeamEvent.h` and `ProjectileStartupRegistrations.h`, and a
   * `reinterpret_cast<WeakPtr<void>&>` reach-in named `BindManyToOneListener` in
   * `CAiAttackerImpl.cpp` - were collapsed into this template on 2026-09-21.
   */
  template <class TEvent>
  class ManyToOneBroadcaster
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /// +0x00 `ownerLinkSlot`, +0x04 `nextInOwner`. Null slot = unbound.
    WeakPtr<ManyToOneListener<TEvent>> mListener;

    /**
     * Address: 0x005DC230 (FUN_005DC230, the `EProjectileImpactEvent` emission;
     *   the lost IDA database labelled it
     *   `Moho::ManyToOneBroadcaster_EProjectileImpactEvent::BroadcastEvent`, and
     *   0x005DB470 is a jump thunk to it under the same label)
     * Address: 0x005DC340 (FUN_005DC340, the `ECollisionBeamEvent` emission,
     *   labelled `Moho::ManyToOneBroadcaster_ECollisionBeamEvent::BroadcastEvent`,
     *   with the thunk at 0x005DB6E0)
     *
     * IDA signature:
     * void __usercall sub_5DC230(ManyToOneBroadcaster<TEvent> *this@<eax>,
     *                             ManyToOneListener<TEvent> *listener@<ecx>);
     *
     * What it does:
     * Binds this broadcaster to `listener`, or unbinds it when `listener` is
     * null.
     *
     * On the name: the body dispatches no event, so `BroadcastEvent` is at best
     * a badly chosen one. Two signals do point at it being the programmer's own
     * - the lost database labelled both emissions that way, and one real mangled
     * symbol in the binary, `?LoadAndBroadcastManyToOneListenerEProjectileImpactEvent@gpg@@...`
     * (0x0069EF30), calls this to "broadcast" a listener it just deserialized.
     * Neither is a mangled symbol for *this* method though, and the label is a
     * human annotation rather than demangled text, so behaviour wins and the
     * method is `SetListener`, pairing with `GetListener` below. Flip it if a
     * mangled symbol for the method itself ever surfaces.
     *
     * The body is byte-for-byte
     * `WeakPtr<T>::ResetFromOwnerLinkSlot(EncodeOwnerLinkSlot(listener))`:
     *
     *     test ecx,ecx / lea edx,[ecx+4] / xor edx,edx   ; EncodeOwnerLinkSlot,
     *                                                    ;   kOwnerLinkOffset = 4
     *     mov  ecx,[eax] / cmp edx,ecx / je ret          ; same slot -> nothing
     *     cmp  [ecx],eax / mov ecx,[ecx] / add ecx,4     ; walk the old owner's
     *     cmp  [ecx],eax / jne loop                      ;   chain to this node
     *     mov  esi,[eax+4] / mov [ecx],esi               ; splice it out
     *     mov  [eax],edx                                 ; take the new slot
     *     mov  ecx,[edx] / mov [eax+4],ecx / mov [edx],eax  ; push at the head
     *     mov  dword [eax+4],0                           ; or clear when unbound
     *
     * The one difference is that `ResetFromOwnerLinkSlot` also treats the bare
     * offset value 4 as an empty-chain sentinel; the binary walks into it. No
     * caller can produce that value here, and the guard only turns a fault into
     * a no-op, so it is kept.
     */
    void SetListener(ManyToOneListener<TEvent>* const listener) noexcept
    {
      mListener.Set(listener);
    }

    /**
     * The intrusive link -> owner decode, i.e. `WeakPtr<T>::GetObjectPtr()`:
     * `ownerLinkSlot` points at the bound listener's `weakLinkHead_`, which sits
     * at listener+0x04, so the listener is `ownerLinkSlot - 0x04`; a null or
     * sentinel slot means nothing is bound.
     *
     * Both dispatch sites gate on exactly this, once per event code -
     * `CollisionBeamEntity::CheckCollision` (FUN_006732D0) reads
     * `mov eax,[edi+270h] / test eax,eax / jz skip / lea ecx,[eax-4] /
     * test ecx,ecx / jz skip` before calling slot 0 through it, and
     * `Projectile::Impact` (FUN_0069DEC0) repeats it at 0x0069E0E6-0x0069E10A.
     */
    [[nodiscard]] ManyToOneListener<TEvent>* GetListener() const noexcept
    {
      return mListener.GetObjectPtr();
    }
  };

  static_assert(sizeof(ManyToOneBroadcaster<int>) == 0x08, "ManyToOneBroadcaster<TEvent> size must be 0x08");
  static_assert(
    offsetof(ManyToOneBroadcaster<int>, mListener) == 0x00,
    "ManyToOneBroadcaster<TEvent>::mListener offset must be 0x00"
  );
  static_assert(sizeof(ManyToOneListener<int>) == 0x08, "ManyToOneListener<TEvent> size must be 0x08");
  static_assert(
    offsetof(ManyToOneListener<int>, weakLinkHead_) == 0x04,
    "ManyToOneListener<TEvent>::weakLinkHead_ offset must be 0x04"
  );
  static_assert(
    WeakPtr<ManyToOneListener<int>>::kOwnerLinkOffset == 0x04,
    "ManyToOneListener<TEvent> weak-owner slot offset must be 0x04"
  );
} // namespace moho
