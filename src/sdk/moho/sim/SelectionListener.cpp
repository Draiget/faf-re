#include "moho/sim/SelectionListener.h"

#include <cstddef>
#include <cstdint>

#include "moho/unit/Broadcaster.h"

namespace
{
  struct SelectionListenerRuntimeView final
  {
    std::uint32_t mUnknown0x04;
    moho::Broadcaster mSessionListenerLink;
  };

  static_assert(
    offsetof(SelectionListenerRuntimeView, mSessionListenerLink) == 0x04,
    "SelectionListenerRuntimeView::mSessionListenerLink offset must be 0x04"
  );
  static_assert(sizeof(SelectionListenerRuntimeView) == 0x0C, "SelectionListenerRuntimeView size must be 0x0C");

  [[nodiscard]] moho::Broadcaster& SelectionListenerLink(moho::SelectionListener& listener) noexcept
  {
    auto* const base = reinterpret_cast<std::uint8_t*>(&listener);
    auto* const view = reinterpret_cast<SelectionListenerRuntimeView*>(base + 0x04);
    return view->mSessionListenerLink;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00869540 (FUN_00869540)
   *
   * What it does:
   * Detaches this selection-listener node from its current lane and reinserts
   * it immediately before the provided lane anchor.
   */
  void SelectionListener::AttachToSessionListenerLane(void* const laneContext)
  {
    auto& listenerLink = SelectionListenerLink(*this);
    auto* const laneAnchor = static_cast<Broadcaster*>(laneContext);
    listenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x00869580 (FUN_00869580)
   *
   * What it does:
   * Detaches this selection-listener node from its current lane and leaves it
   * self-linked.
   */
  void SelectionListener::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    SelectionListenerLink(*this).ListUnlink();
  }
} // namespace moho
