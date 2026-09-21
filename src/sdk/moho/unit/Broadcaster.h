#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  enum EAiAttackerEvent : std::int32_t;
  enum ECommandEvent : int;
  enum EFormationdStatus : std::int32_t;
  enum EUnitCommandQueueStatus : int;
  struct SNavPath;

  class Broadcaster : public TDatList<Broadcaster, void>
  {
  public:
    /**
     * The ring mechanic every `BroadcastEvent` below is built on, written once.
     *
     * A listener is free to unlink or relink itself from inside its own
     * callback, so the ring cannot be walked in place. Instead the whole ring is
     * moved onto a local sentinel, and each listener is moved back onto the live
     * head *before* it is told the event — so a callback that unlinks sees a
     * consistent ring, and one that relinks lands on the head rather than on the
     * sentinel that is about to die.
     *
     * Every emission is the same instruction sequence, and reads slot `+0x04`
     * throughout: `empty()` tests it (`mov eax,[esi+4]; cmp eax,esi`),
     * `pop_front()` takes it, and `push_back()` writes `mov [node+4], head` /
     * `mov [head], node`. Note that slot `+0x04` is `mNext` *by name* in this
     * tree and the *prev* link in the binary — see the warning on
     * `TDatListItem`; the two views agree by slot, which is what matters here.
     *
     * `pop_front()` then `push_back()` unlinks the node twice, the second time
     * on an already-self-linked node. That is not an oversight: the binary emits
     * both unlink sequences (0x006E9500-0x006E9518 and 0x006E9523-0x006E9534 in
     * the `ECommandEvent` emission), which is what pins the source to this pair
     * of calls rather than a single splice.
     *
     * Four of the five hand-written copies this replaces walked the ring the
     * other way — slot `+0x00` and `ListLinkAfter` instead of `+0x04` and
     * `ListLinkBefore`. Those two mistakes are mirror images, so the ring was
     * left in the right order and nothing crashed; what they got wrong is the
     * order listeners are *notified* in, which came out reversed. Only
     * `Broadcaster::BroadcastEvent(EFormationdStatus)` had it right.
     *
     * The binary additionally inlines `~TDatList` on the local sentinel, on both
     * the early-return and the loop-exit path. `TDatList` carries no destructor
     * in this tree, so nothing is emitted for it here; both copies are pure
     * self-assignment on an already-empty node, so no behaviour rides on it.
     */
    template <class TListener, class TEvent>
    void DispatchToListeners(const TEvent& event)
    {
      Broadcaster pending{};

      if (empty()) {
        return;
      }

      move_nodes_to(pending);

      while (!pending.empty()) {
        auto* const link = static_cast<Broadcaster*>(pending.pop_front());
        push_back(link);

        if (TListener* const listener = TListener::FromListenerLink(link); listener != nullptr) {
          (void)listener->OnEvent(event);
        }
      }
    }

    /**
     * Address: 0x005DB480 (FUN_005DB480,
     * `Broadcaster<EAiAttackerEvent>::BroadcastEvent` — unnamed in the lost
     * database, but instruction-for-instruction the same body as the four
     * overloads below, reached as `attacker->mListeners` from
     * `CAiAttackerImpl::SetState` (0x005D7320), `SetDesiredTarget` (0x005D75B0)
     * and `ForceEngage` (0x005D8650))
     *
     * What it does:
     * Broadcasts one attacker event to all linked listeners. The definition
     * lives in CAiAttackerImpl.cpp beside the `Listener<EAiAttackerEvent>`
     * overrides its dispatch resolves to.
     */
    void BroadcastEvent(EAiAttackerEvent event);

    /**
     * Address: 0x0056B070 (FUN_0056B070,
     * ?BroadcastEvent@?$Broadcaster@W4EFormationdStatus@Moho@@@Moho@@IAEXW4EFormationdStatus@2@@Z)
     *
     * What it does:
     * Broadcasts one formation-status event to all linked listeners while
     * preserving iteration safety when listeners relink/unlink during
     * callback. Same intrusive-broadcast shape as the overloads below
     * (distinct per-T body, not ICF-folded); the definition lives in
     * CAiFormationInstance.cpp beside its only broadcaster,
     * `CFormationInstance::mStatusListeners`.
     */
    void BroadcastEvent(EFormationdStatus event);

    /**
     * Address: 0x006E94A0 (FUN_006E94A0,
     * ?BroadcastEvent@?$Broadcaster@W4ECommandEvent@Moho@@@Moho@@IAEXW4ECommandEvent@2@@Z)
     *
     * What it does:
     * Broadcasts one command event to all linked listeners while preserving
     * iteration safety when listeners relink/unlink during callback.
     */
    void BroadcastEvent(ECommandEvent event);

    /**
     * Address: 0x006F8070 (FUN_006F8070,
     * ?BroadcastEvent@?$Broadcaster@W4EUnitCommandQueueStatus@Moho@@@Moho@@IAEXW4EUnitCommandQueueStatus@2@@Z)
     *
     * What it does:
     * Broadcasts one queue-status event to all linked listeners while
     * preserving iteration safety when listeners relink/unlink during callback.
     */
    void BroadcastEvent(EUnitCommandQueueStatus event);

    /**
     * Address: 0x005AAD80 (FUN_005AAD80,
     * ?BroadcastEvent@?$Broadcaster@ABUSNavPath@Moho@@@Moho@@IAEXABUSNavPath@2@@Z)
     *
     * What it does:
     * Broadcasts one navigation-path payload to all linked path listeners
     * (CAiPathNavigator) while preserving iteration safety when listeners
     * relink/unlink themselves during callback. Same intrusive-broadcast shape
     * as the ECommandEvent / EUnitCommandQueueStatus overloads (distinct per-T
     * body, not ICF-folded); the definition lives in CAiPathFinder.cpp because
     * the concrete listener dispatch resolves to CAiPathNavigator::OnEvent.
     */
    void BroadcastEvent(const SNavPath& event);
  };

  static_assert(offsetof(Broadcaster, mPrev) == 0x00, "Broadcaster::mPrev offset must be 0x00");
  static_assert(offsetof(Broadcaster, mNext) == 0x04, "Broadcaster::mNext offset must be 0x04");
  static_assert(sizeof(Broadcaster) == 0x08, "Broadcaster size must be 0x08");

  template <class TEvent>
  class BroadcasterEventTag : public Broadcaster
  {
  public:
    /// Cached reflection descriptor for this instantiation. The binary keeps
    /// one static per `Broadcaster<TEvent>`, populated by the base-registration
    /// helpers on first lookup, so later reflection paths find it resolved
    /// rather than re-resolving or reading null.
    inline static gpg::RType* sType = nullptr;
  };

  static_assert(
    sizeof(BroadcasterEventTag<ECommandEvent>) == sizeof(Broadcaster),
    "BroadcasterEventTag<ECommandEvent> size must match Broadcaster"
  );

  /**
   * Address: 0x006F9210 (FUN_006F9210, sub_6F9210)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Broadcaster_EUnitCommandQueueStatus_RType();

  /**
   * Address: 0x006F9270 (FUN_006F9270, sub_6F9270)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Listener_EUnitCommandQueueStatus_RType();

  /**
   * Address: 0x00BD95D0 (FUN_00BD95D0, sub_BD95D0)
   *
   * What it does:
   * Runs broadcaster status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Broadcaster_EUnitCommandQueueStatus_RType_AtExit();

  /**
   * Address: 0x006EBDF0 (FUN_006EBDF0, sub_6EBDF0)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Broadcaster_ECommandEvent_RType();

  /**
   * Address: 0x005F4A70 (FUN_005F4A70, register_Listener_ECommandEvent_RType)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Listener_ECommandEvent_RType();

  /**
   * Address: 0x00BD8FD0 (FUN_00BD8FD0, sub_BD8FD0)
   *
   * What it does:
   * Runs broadcaster command-event type registration and queues shutdown
   * cleanup via `atexit`.
   */
  int register_Broadcaster_ECommandEvent_RType_AtExit();

  /**
   * Address: 0x00BD95F0 (FUN_00BD95F0, sub_BD95F0)
   *
   * What it does:
   * Runs listener status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Listener_EUnitCommandQueueStatus_RType_AtExit();
} // namespace moho
