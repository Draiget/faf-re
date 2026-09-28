#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/DList.h"

namespace moho
{
  enum EFormationdStatus : std::int32_t;

  /**
   * One subscriber to a `Broadcaster<TEvent>`.
   *
   * RTTI (every instantiation, e.g. `Listener<ECommandEvent>` COL at
   * vtable 0x00E1F624): a one-slot vtable at +0x00 and a
   * `gpg::DListItem<Listener<TEvent>>` base at +0x04, which carries the
   * `boost::noncopyable` at the same offset. The node is what links the
   * listener onto its broadcaster's ring, so a listener is found from a ring
   * node with `DListItem::Get()` -- the `node - 4` every broadcast loop
   * spells as `lea ecx, [eax-4]` behind a null test.
   */
  template <class TEvent>
  class Listener : public gpg::DListItem<Listener<TEvent>>
  {
  public:
    /**
     * Address: 0x005F2960 (FUN_005F2960, Listener<EAiAttackerEvent> ctor lane)
     * Address: 0x005F2970 (FUN_005F2970, Listener<ECommandEvent> ctor lane)
     * Address: 0x00618E40 (FUN_00618E40, Listener<EAiNavigatorEvent> ctor lane)
     * Address: 0x00618E50 (FUN_00618E50, Listener<EFormationdStatus> ctor lane)
     * Address: 0x00599120 (FUN_00599120, Listener<EUnitCommandQueueStatus> ctor
     *   lane, `this` in EAX -- the whole body is this constructor:
     *   `lea ecx, [eax+4]` takes the node, the two stores self-link it, and
     *   `mov [eax], 0xE1B374` installs the instantiation's vtable. It has
     *   zero callers because every derived constructor inlines it;
     *   `IAiCommandDispatchImpl` is the one that instantiates this
     *   specialisation, naming it in its own initializer list.)
     * Address: 0x005AD5A0 (FUN_005AD5A0, Listener<NavPath const&> ctor lane,
     *   `this` in EAX, vtable 0x00E1BE1C; zero callers; formerly
     *   `InitializePathNavigatorListenerLane` in CAiPathNavigator.cpp.)
     * Address: 0x00865710 (FUN_00865710, Listener<SSelectionEvent> ctor lane,
     *   vtable 0x00E47A10; formerly `InitializeSelectionEventListenerLane`
     *   over a `SelectionEventListenerRuntimeLane` in CWldSession.cpp.)
     * Address: 0x00869800 (FUN_00869800, Listener<SPauseEvent> ctor lane,
     *   vtable 0x00E47B30; formerly `InitializePauseEventListenerLane`.)
     * Address: 0x00447460 (FUN_00447460, Listener<SD3DDeviceEvent const&>
     *   ctor lane, `this` in EAX, vtable 0x00E02A94; inlined into
     *   `DeviceExitListener`'s constructor, zero callers; formerly
     *   `InitializeDeviceListenerLink` in DeviceExitListener.cpp.)
     *
     * What it does:
     * Self-links the listener's node (the `DListItem` base) and installs the
     * instantiation's vtable.
     */
    Listener() = default;

    /**
     * Address: 0x00869A40 (FUN_00869A40, Listener<SPauseEvent>: the vtable
     *   0x00E47B30 goes back in, then the node unlinks; formerly listed as a
     *   constructor)
     * Address: 0x005F42F0 (FUN_005F42F0, the node's unlink alone, listener
     *   in EAX; zero callers)
     * Address: 0x005F4340 (FUN_005F4340, a second copy of that body)
     *
     * What it does:
     * Nothing of its own; the `DListItem` base's destructor unlinks the
     * listener from whatever broadcaster it is on. Not virtual: the vtable
     * has one slot.
     */
    ~Listener() = default;

    virtual void OnEvent(TEvent event) = 0;
  };

  static_assert(sizeof(Listener<std::int32_t>) == 0x0C, "Listener<T> size must be 0x0C");

  using Listener_EFormationdStatus = Listener<EFormationdStatus>;
} // namespace moho
