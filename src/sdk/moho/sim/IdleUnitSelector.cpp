#include "moho/sim/IdleUnitSelector.h"

#include <cstddef>
#include <cstdint>

#include "moho/unit/Broadcaster.h"

namespace
{
  struct IdleUnitSelectorRuntimeView final
  {
    std::uint32_t mUnknown0x04;
    moho::Broadcaster mSessionListenerLink;
  };

  static_assert(
    offsetof(IdleUnitSelectorRuntimeView, mSessionListenerLink) == 0x04,
    "IdleUnitSelectorRuntimeView::mSessionListenerLink offset must be 0x04"
  );
  static_assert(sizeof(IdleUnitSelectorRuntimeView) == 0x0C, "IdleUnitSelectorRuntimeView size must be 0x0C");

  [[nodiscard]] moho::Broadcaster& IdleUnitSelectorSessionListenerLink(moho::IdleUnitSelector& listener) noexcept
  {
    auto* const base = reinterpret_cast<std::uint8_t*>(&listener);
    auto* const view = reinterpret_cast<IdleUnitSelectorRuntimeView*>(base + 0x04);
    return view->mSessionListenerLink;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008656A0 (FUN_008656A0)
   *
   * What it does:
   * Detaches this idle-selector listener node from its current lane and
   * reinserts it immediately before the provided lane anchor.
   */
  void IdleUnitSelector::AttachToSessionListenerLane(void* const laneContext)
  {
    auto& listenerLink = IdleUnitSelectorSessionListenerLink(*this);
    auto* const laneAnchor = static_cast<Broadcaster*>(laneContext);
    listenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x008656E0 (FUN_008656E0)
   *
   * What it does:
   * Detaches this idle-selector listener node from its current lane and leaves
   * it self-linked.
   */
  void IdleUnitSelector::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    IdleUnitSelectorSessionListenerLink(*this).ListUnlink();
  }
} // namespace moho
