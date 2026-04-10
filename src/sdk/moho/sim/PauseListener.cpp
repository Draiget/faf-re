#include "moho/sim/PauseListener.h"

#include <cstddef>
#include <cstdint>

#include "moho/unit/Broadcaster.h"

namespace
{
  struct PauseListenerRuntimeView final
  {
    std::uint32_t mUnknown0x04;
    moho::Broadcaster mSessionListenerLink;
  };

  static_assert(
    offsetof(PauseListenerRuntimeView, mSessionListenerLink) == 0x04,
    "PauseListenerRuntimeView::mSessionListenerLink offset must be 0x04"
  );
  static_assert(sizeof(PauseListenerRuntimeView) == 0x0C, "PauseListenerRuntimeView size must be 0x0C");

  [[nodiscard]] moho::Broadcaster& PauseListenerLink(moho::PauseListener& listener) noexcept
  {
    auto* const base = reinterpret_cast<std::uint8_t*>(&listener);
    auto* const view = reinterpret_cast<PauseListenerRuntimeView*>(base + 0x04);
    return view->mSessionListenerLink;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00869700 (FUN_00869700)
   *
   * What it does:
   * Detaches this pause-listener node from its current lane and reinserts it
   * into the pause lane embedded at `laneContext + 0x08`.
   */
  void PauseListener::AttachToSessionListenerLane(void* const laneContext)
  {
    auto& listenerLink = PauseListenerLink(*this);
    auto* const laneOwnerBytes = static_cast<std::uint8_t*>(laneContext);
    auto* const laneAnchor = reinterpret_cast<Broadcaster*>(laneOwnerBytes + 0x08);
    listenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x00869750 (FUN_00869750)
   *
   * What it does:
   * Detaches this pause-listener node from its current lane and leaves it
   * self-linked.
   */
  void PauseListener::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    PauseListenerLink(*this).ListUnlink();
  }
} // namespace moho
