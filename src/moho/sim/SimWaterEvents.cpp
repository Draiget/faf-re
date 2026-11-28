#include "moho/sim/SimWaterEvents.h"

#include <atomic>
#include <mutex>

namespace moho
{
  namespace
  {
    // More than a busy naval fight lands between two frames; past it the events are dropped (render only).
    constexpr std::size_t kMaxQueued = 4096U;

    std::atomic<bool> gEnabled{false};
    std::mutex gMutex;
    std::vector<SSimWaterEvent> gQueue;

    void Push(
      const SSimWaterEvent& event
    )
    {
      const std::lock_guard<std::mutex> lock(gMutex);
      if (gQueue.size() < kMaxQueued) {
        gQueue.push_back(event);
      }
    }
  } // namespace

  void EnableSimWaterEvents(
    const bool on
  ) noexcept
  {
    if (gEnabled.exchange(on, std::memory_order_relaxed) && !on) {
      const std::lock_guard<std::mutex> lock(gMutex);
      gQueue.clear();
    }
  }

  bool SimWaterEventsEnabled() noexcept
  {
    return gEnabled.load(std::memory_order_relaxed);
  }

  void SimWaterImpact(
    const float x,
    const float z,
    const float damage,
    const float scale,
    const int army
  )
  {
    if (!SimWaterEventsEnabled()) {
      return;
    }
    SSimWaterEvent event;
    event.kind = SSimWaterEvent::Kind::Impact;
    event.x = x;
    event.z = z;
    event.value = damage;
    event.scale = scale;
    event.army = army;
    Push(event);
  }

  void SimWaterUnitDeath(
    const float x,
    const float y,
    const float z,
    const float mass,
    const int army
  )
  {
    if (!SimWaterEventsEnabled()) {
      return;
    }
    SSimWaterEvent event;
    event.kind = SSimWaterEvent::Kind::UnitDeath;
    event.x = x;
    event.y = y;
    event.z = z;
    event.value = mass;
    event.army = army;
    Push(event);
  }

  std::size_t DrainSimWaterEvents(
    std::vector<SSimWaterEvent>& out
  )
  {
    const std::lock_guard<std::mutex> lock(gMutex);
    const std::size_t count = gQueue.size();
    out.insert(out.end(), gQueue.begin(), gQueue.end());
    gQueue.clear();
    return count;
  }
} // namespace moho
