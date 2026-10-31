#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

#include "moho/sim/Sim.h"
#include "remote/wire/ArmyLane.h"

// Engine addition, server mode (plan WP5.13): the view army's intel grids as the server sends
// them. The grids live in the sim's armies and change while the sim ticks, but the loopback link
// runs on the thread that takes the sim's packets (ReplayRunner.cpp, RemoteSimDriver.cpp), so the
// grids are copied on the sim thread, at the end of each beat's sync walk, and handed over by
// beat: the vision and water grids of the focus army and of every army that lists it as an ally
// (`UserArmy::CanSeeCell` 0x008B17F0), one bit per cell.

namespace faf::remote::client
{
  class CGridSnapshots final : public moho::CSyncObserver
  {
  public:
    CGridSnapshots() = default;
    ~CGridSnapshots() override;

    /**
     * Watches every sync walk from now on (`Sim::SetSyncObserver`). An observer already set (the
     * game's `/oraclegolden`, say) keeps getting every call, through this one.
     */
    void Install();
    void Uninstall();

    /** The grids copied at `beat` (older copies are dropped); false when that beat was not copied. */
    [[nodiscard]] bool Take(std::uint32_t beat, std::vector<wire::SGridSlot>& out);

    void OnEntityWillSync(moho::Entity& entity) override;
    void OnEntitySynced(moho::Entity& entity) override;
    void OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet) override;

  private:
    moho::CSyncObserver* mNext = nullptr; // the observer this one replaced
    std::mutex mLock;
    std::deque<std::pair<std::uint32_t, std::vector<wire::SGridSlot>>> mBeats; // beat, grids
    bool mInstalled = false;
  };
} // namespace faf::remote::client
