#pragma once
#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"
#include "SSelectionEvent.h"
#include "moho/misc/Listener.h"

namespace moho
{
  /**
   * SelectionListener
   *
   * Layout evidence:
   * - Primary base: `ISessionListener` (lane-attach / lane-detach session hooks).
   * - Secondary base: `Listener<SSelectionEvent>` — confirmed by
   *   `??_7SelectionListener@Moho@@6B?$Listener@USSelectionEvent@Moho@@@Moho@@@`
   *   data-xref into the OnEvent slot (FUN_00869060 = `Receive`).
   * - `boost::noncopyable_::noncopyable` mixin: matches the engine's selection
   *   listener registration shape (constructed once per UI session, never copied).
   *
   * The Listener<SSelectionEvent> base owns the broadcaster lane link at
   * `+0x04` from the listener subobject start (see `Listener<T>` definition).
   * The session attach/detach hooks reinsert this listener's intrusive node
   * before the session selection broadcaster's anchor.
   */
  class SelectionListener
    : public ISessionListener
    , public Listener<SSelectionEvent>
    , boost::noncopyable_::noncopyable
  {
  public:
    /**
     * Address: 0x00869540 (FUN_00869540)
     * Slot: 0 (ISessionListener primary vtable)
     *
     * What it does:
     * Re-links this listener node into the provided session-listener lane.
     */
    void AttachToSessionListenerLane(void* laneContext) override;

    /**
     * Address: 0x00869580 (FUN_00869580)
     * Slot: 1 (ISessionListener primary vtable)
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(void* laneContext) override;

    /**
     * Address: 0x00869060 (FUN_00869060, Moho::SelectionListener::Receive)
     * Slot: 0 (Listener<SSelectionEvent> secondary vtable)
     *
     * What it does:
     * Builds four Lua sequence tables from the previous/current/added/removed
     * selection sets carried by `event`, then dispatches them to
     * `/lua/ui/game/gamemain.lua:OnSelectionChanged(prev, current, added, removed)`.
     * Lua call errors are caught and routed through `gpg::Warnf` with the
     * "Error running '/lua/ui/game/gamemain.lua:OnSelectionChanged': %s" template.
     */
    void OnEvent(SSelectionEvent event) override;
  };
} // namespace moho
