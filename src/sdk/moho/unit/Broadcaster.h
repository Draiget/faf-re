#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/DList.h"
#include "moho/misc/Listener.h"

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
  struct SDiskWatchEvent;
  struct SNavPath;

  /**
   * The publishing side of `Listener<TEvent>`: a ring of subscribed
   * listeners, notified in ring order by `BroadcastEvent`.
   *
   * RTTI names every instantiation (`Broadcaster<ECommandEvent>` at
   * `CUnitCommand`+0x34, `Broadcaster<SD3DDeviceEvent const&>` at
   * `ID3DDevice`+0x04, ...) but lists no base beneath any of them, so the
   * ring head is a member, not a `gpg::DList` base: a base would appear in
   * the owner's base-class array with its `boost::noncopyable`, as
   * `Listener<TEvent>`'s `DListItem` does.
   */
  template <class TEvent>
  class Broadcaster
  {
  public:
    using listener_type = Listener<TEvent>;

    /**
     * Address: 0x005F42C0 (FUN_005F42C0, `this` = head in ECX, listener in
     *   EAX: a null-checked cast to the node, unlink, then link before the
     *   head. Called out of line from the melee attack task's `Starting`
     *   state; formerly `CUnitMeleeAttackTargetTask::RelinkAiAttackerListener`)
     * Address: 0x005F4310 (FUN_005F4310, byte-identical copy)
     * Address: 0x00651EF0 (FUN_00651EF0, byte-identical copy; formerly
     *   `RelinkOwnerNodeOffset04BeforeAnchor`)
     * Address: 0x005E9D50 (FUN_005E9D50, byte-identical copy; formerly
     *   `RelinkOwnerNodeBeforeAnchor`)
     * Address: 0x005F4560 (FUN_005F4560, a third copy; IDA split it at
     *   0x005F4567 after the cast, formerly
     *   `RelinkBroadcasterNodeBeforeAnchor` in Broadcaster.cpp)
     *
     * What it does:
     * Moves `listener` to the back of this broadcaster's ring, unlinking it
     * from any ring it is on first.
     */
    void AddListener(listener_type* const listener) noexcept
    {
      mListeners.push_back(listener);
    }

    /**
     * Address: 0x005DB480 (FUN_005DB480, `Broadcaster<EAiAttackerEvent>`;
     *   reached as `attacker->BroadcastEvent` from `CAiAttackerImpl::SetState`
     *   (0x005D7320), `SetDesiredTarget` (0x005D75B0) and `ForceEngage`
     *   (0x005D8650))
     * Address: 0x0056B070 (FUN_0056B070,
     *   ?BroadcastEvent@?$Broadcaster@W4EFormationdStatus@Moho@@@Moho@@IAEXW4EFormationdStatus@2@@Z)
     * Address: 0x006E94A0 (FUN_006E94A0,
     *   ?BroadcastEvent@?$Broadcaster@W4ECommandEvent@Moho@@@Moho@@IAEXW4ECommandEvent@2@@Z)
     * Address: 0x006E9110 (FUN_006E9110, the ECommandEvent broadcast reached
     *   through a `CUnitCommand*`: a base adjustment to +0x34 and this call;
     *   zero callers)
     * Address: 0x006F8070 (FUN_006F8070,
     *   ?BroadcastEvent@?$Broadcaster@W4EUnitCommandQueueStatus@Moho@@@Moho@@IAEXW4EUnitCommandQueueStatus@2@@Z)
     * Address: 0x005AAD80 (FUN_005AAD80,
     *   ?BroadcastEvent@?$Broadcaster@ABUNavPath@Moho@@@Moho@@IAEXABUNavPath@2@@Z)
     * Address: 0x004637D0 (FUN_004637D0, `Broadcaster<SDiskWatchEvent const&>`;
     *   called with `esi = &watch->mListeners` from `CDiskDirWatch::Update`
     *   (0x0046264B))
     * Address: 0x00431D80 (FUN_00431D80, `Broadcaster<SD3DDeviceEvent const&>`,
     *   `this` in ESI; formerly `DispatchDeviceEventToListeners`)
     * Address: 0x005A6C50 (FUN_005A6C50, `Broadcaster<EAiNavigatorEvent>`;
     *   reached from `CAiNavigatorImpl::AbortMove` (0x005A3750), the
     *   resume-task broadcast (0x005A3730) and the land/air navigators' tick;
     *   formerly `CAiNavigatorImpl::DispatchNavigatorEvent`)
     * Address: 0x005E8A30 (FUN_005E8A30, `Broadcaster<EAiTransportEvent>`;
     *   formerly `BroadcastTransportEvent` in CAiTransportImpl.cpp)
     * Address: 0x008986F0 (FUN_008986F0,
     *   ?BroadcastEvent@?$Broadcaster@USSelectionEvent@Moho@@@Moho@@IAEXUSSelectionEvent@2@@Z;
     *   `CWldSession::SetSelection`'s publish, formerly
     *   `BroadcastSelectionEventListeners` calling slot 0 through a raw
     *   vtable cast)
     * Address: 0x00898820 (FUN_00898820, `Broadcaster<SPauseEvent>`, reached
     *   from `CWldSession::RequestPause`/`Resume` with `add esi, 8`;
     *   formerly `DispatchSessionPauseCallbacks`)
     * Address: 0x007AE2B0 (FUN_007AE2B0,
     *   ?BroadcastEvent@?$Broadcaster@USCameraTracking@Moho@@@Moho@@IAEXUSCameraTracking@2@@Z;
     *   longer only because the by-value event (a string and a flag) is
     *   copied for each listener's call; formerly
     *   `BroadcastCameraTrackingEvent` in CameraImpl.cpp)
     *
     * What it does:
     * A listener may unlink or relink itself from inside its callback, so the
     * ring is not walked in place: the whole ring moves onto a local head,
     * and each listener goes back onto this ring *before* it is told the
     * event. A callback that unlinks sees a consistent ring; one that relinks
     * lands here rather than on the local head that is about to die.
     *
     * Every emission is the same instruction sequence (0x006E94A0 and
     * 0x00431D80 differ only in the argument push): the empty test reads
     * slot `+0x04`, `pop_front` takes the node at `+0x04` and casts it to the
     * listener behind a null test (`lea ecx, [eax-4]`), and `push_back`
     * casts it back behind a second null test and links it before the head.
     * `pop_front` then `push_back` unlinks the node twice, the second time on
     * a self-linked node; the binary emits both sequences, which is what pins
     * the source to this pair of calls rather than one splice.
     */
    void BroadcastEvent(TEvent event)
    {
      gpg::DList<listener_type> pending;
      mListeners.move_nodes_to(pending);

      while (!pending.empty()) {
        listener_type* const listener = pending.pop_front();
        mListeners.push_back(listener);
        listener->OnEvent(event);
      }
    }

    /// Cached reflection descriptor for this instantiation.
    inline static gpg::RType* sType = nullptr;

    gpg::DList<listener_type> mListeners; // +0x00
  };

  static_assert(sizeof(Broadcaster<std::int32_t>) == 0x08, "Broadcaster<T> size must be 0x08");

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
   * Runs broadcaster status-type registration.
   */
  void register_Broadcaster_EUnitCommandQueueStatus_RTypeStartup();

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
   * Runs broadcaster command-event type registration.
   */
  void register_Broadcaster_ECommandEvent_RTypeStartup();

  /**
   * Address: 0x00BD95F0 (FUN_00BD95F0, sub_BD95F0)
   *
   * What it does:
   * Runs listener status-type registration.
   */
  void register_Listener_EUnitCommandQueueStatus_RTypeStartup();
} // namespace moho
