#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  struct SSyncData;
}

namespace faf::server
{
  /**
   * Plan WP17.15: each army's state during a game, for the dashboard (`GET /api/v1/armies`), read only from what the
   * server already gets every beat, never from the sim itself (no Lua runs in the sim's state for it):
   *  - the beat's packet: each army's economy (`mArmyUpdates`), its commander (the new unit whose blueprint has the
   *    category COMMAND), the commander's health (`mEntityUpdates`) and death (`mDeleteIds`);
   *  - the beat's Lua sync, decoded into the server's own state: `Sync.Score` (FAF's score thread, every 2 s: score,
   *    units and unit cap, the brain type) and `Sync.UserUnitEnhancements` (every enhancement by unit).
   * The server is an observer (its focus army is -1), so both carry every army (`lua/sim/score.lua`,
   * `lua/SimSync.lua`).
   */
  class CArmyBoard
  {
  public:
    struct SPlayer
    {
      std::string name;
      int team = 0;
      bool human = false;
      std::int32_t uid = 0;
      std::string result;
    };

    /** The packet of one beat, as the driver hands it over. */
    void ReadPacket(const moho::SSyncData& packet);
    /** The beat's decoded sync table, when it has `Score` or `UserUnitEnhancements`. */
    void ReadSync(const LuaPlus::LuaObject& sync);
    /** `{"beat":..,"armies":[..]}` without braces around it, for a control reply; `players` by army (0-based). */
    [[nodiscard]] std::string Json(int beat, const std::vector<SPlayer>& players) const;

    /** For the tests. */
    [[nodiscard]] std::size_t Armies() const
    {
      return mArmies.size();
    }

  private:
    struct SArmy
    {
      bool economySeen = false;
      float massStored = 0.0f, massIncome = 0.0f, energyStored = 0.0f, energyIncome = 0.0f;
      std::uint64_t massStorage = 0, energyStorage = 0;
      int faction = -1;
      bool outOfGame = false;
      std::uint32_t acu = 0;
      bool acuSeen = false, acuAlive = false;
      float acuHealth = 0.0f, acuMaxHealth = 0.0f;
      bool scoreSeen = false;
      double score = 0.0;
      int units = 0, unitCap = 0;
      std::string type;
      bool defeated = false;
    };

    SArmy& Army(std::size_t index);

    std::vector<SArmy> mArmies;
    std::map<std::uint32_t, std::vector<std::string>> mEnhancements; // by unit, the last full table
  };

  /** The army an entity id belongs to: its source bits (0x0FF00000), the army's 0-based index. */
  [[nodiscard]] constexpr std::size_t ArmyOfEntity(
    const std::uint32_t id
  ) noexcept
  {
    return (id >> 20u) & 0xFFu;
  }
} // namespace faf::server
