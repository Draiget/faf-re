#include "moho/ai/IAiCommandDispatch.h"

#include <new>

#include "moho/misc/Listener.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

using namespace moho;

namespace
{
  struct ListenerQueueStatusRuntimeView
  {
    void* vftable;
    moho::Broadcaster link;
  };

  class ListenerQueueStatusVtableProbe final : public moho::Listener<moho::EUnitCommandQueueStatus>
  {
  public:
    void OnEvent(const moho::EUnitCommandQueueStatus) override
    {
    }
  };

  [[nodiscard]] void* ListenerQueueStatusVtable() noexcept
  {
    static ListenerQueueStatusVtableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }
} // namespace

gpg::RType* IAiCommandDispatch::sType = nullptr;

/**
 * Address: 0x005989F0 (FUN_005989F0, ??0IAiCommandDispatch@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes one AI-command-dispatch base object with interface vtable
 * ownership.
 */
IAiCommandDispatch::IAiCommandDispatch() = default;

/**
 * Address: 0x00599110 (FUN_00599110)
 *
 * What it does:
 * In-place constructor lane adapter for one `IAiCommandDispatch` interface
 * subobject.
 */
[[maybe_unused]] IAiCommandDispatch* InitializeIAiCommandDispatchInterfaceLane(
  IAiCommandDispatch* const dispatchStorage
) noexcept
{
  if (dispatchStorage == nullptr) {
    return nullptr;
  }

  ::new (static_cast<void*>(dispatchStorage)) IAiCommandDispatch();
  return dispatchStorage;
}

/**
 * Address: 0x00599120 (FUN_00599120)
 *
 * What it does:
 * Initializes one detached `Listener<EUnitCommandQueueStatus>` intrusive
 * node and restores its listener vtable lane.
 */
[[maybe_unused]] Listener<EUnitCommandQueueStatus>* InitializeQueueStatusListenerLane(
  Listener<EUnitCommandQueueStatus>* const listener
) noexcept
{
  if (listener == nullptr) {
    return nullptr;
  }

  auto* const runtime = reinterpret_cast<ListenerQueueStatusRuntimeView*>(listener);
  runtime->link.ListResetLinks();
  runtime->vftable = ListenerQueueStatusVtable();
  return listener;
}

/**
 * Address: 0x00598A00 (FUN_00598A00, scalar deleting thunk)
 */
IAiCommandDispatch::~IAiCommandDispatch() = default;
