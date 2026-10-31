#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "moho/command/ICommandSink.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/sim/SSyncFilter.h"
#include "remote/ViewIdMap.h"

// Engine addition, server mode (plan WP5.10, with WP3.6): a client's commands as the sim must
// see them. A client knows its view's ids (remote/ViewIdMap.h), so every id-bearing field of a
// command it sends is translated back to the sim's id before the command goes on to `next`
// (research/WP5.5-id-inventory.md, rows C3-C11):
//
//   - entity ids: `DestroyEntity`, `WarpEntity`, `ProcessInfoPair`, `RemoveCommandFromUnitQueue`'s
//     unit, the unit sets of `IssueCommand`, `IssueFactoryCommand`, `LuaSimCallback` and
//     `ExecuteDebugCommand`, and an entity target (`AITARGET_Entity`) in `mTarget`, `mTarget2`
//     and `SetCommandTarget`;
//   - command ids: the coordinated-attack partner (`unk04`, -1 for none) and the command to
//     insert before (`mIndex`, top byte 0xFF for none) of an issued command, and the command of
//     `Increase/DecreaseCommandCount`, `SetCommandTarget`, `SetCommandType`, `SetCommandCells`
//     and `RemoveCommandFromUnitQueue`. The client's own new command id (`nextCommandId`) is its
//     own and passes as it is.
//
// A renumbered id the view was never given, or one already retired, drops the whole command,
// which is counted and logged. Inside a sim callback's Lua arguments, the fields the routing
// policy marks (`kCallbackIdFields`, WP5.11) are translated too; the rest pass as they are.

namespace faf::remote
{
  /**
   * Plan WP5.11: the Lua fields of sim callbacks that carry an entity id, as the routing policy
   * marks them. FA's Lua hands entity ids around as decimal strings (a Lua number is a float here
   * and cannot hold every id); these are translated like any other entity id. From the corpus
   * audit over the core replays (headless --inbound-check, plan WPR.19): the `target` of
   * `RingWithStorages`, `RingRadar`, `FlagShield` and `ValidateAssist`, `Rebuild`'s `entity` and
   * `DistributeOrders`'s `Target` carry a unit or blip id; `OnControlGroupAssign`'s arguments and
   * `WeaponPriorities`'s `SelectedUnits` are lists of unit ids. The other keys whose values
   * matched ids are army indices, amounts, coordinates and marker numbers.
   */
  struct SCallbackIdField
  {
    const char* callback;
    const char* key; // a field of the argument table; null: the argument table itself
    bool list;       // the field is a list of ids (every element is one)
  };
  inline constexpr SCallbackIdField kCallbackIdFields[] = {
    {"Rebuild", "entity", false},
    {"DistributeOrders", "Target", false},
    {"RingWithStorages", "target", false},
    {"RingRadar", "target", false},
    {"FlagShield", "target", false},
    {"ValidateAssist", "target", false},
    {"OnControlGroupAssign", nullptr, true},
    {"WeaponPriorities", "SelectedUnits", true},
  };

  /**
   * Every id-bearing field of every command, rewritten by `RewriteEntity` / `RewriteCommand`
   * before the command goes on to `next`; a field either refuses drops the whole command.
   */
  class CCommandIdRewriter : public moho::ICommandSink
  {
  public:
    explicit CCommandIdRewriter(moho::ICommandSink& next) noexcept
      : mNext(next)
    {}

    [[nodiscard]] std::uint64_t Commands() const noexcept { return mCommands; }
    [[nodiscard]] std::uint64_t IdsRewritten() const noexcept { return mIdsRewritten; }
    [[nodiscard]] std::uint64_t Dropped() const noexcept { return mDropped; }
    /** The last dropped command's message name and the id that dropped it. */
    [[nodiscard]] const std::string& LastDrop() const noexcept { return mLastDrop; }
    /** Issued commands passed on whose target was a recon blip, by command type (plan WP5.12). */
    [[nodiscard]] std::uint64_t BlipTargets(moho::EUnitCommandType type) const noexcept
    {
      const auto index = static_cast<std::size_t>(type);
      return index < mBlipTargets.size() ? mBlipTargets[index] : 0u;
    }

    void SetCommandSource(moho::CommandSourceId sourceId) override;
    void OnCommandSourceTerminated() override;
    void VerifyChecksum(const gpg::MD5Digest& digest, moho::CSeqNo seqNo) override;
    void RequestPause() override;
    void Resume() override;
    void SingleStep() override;
    void CreateUnit(uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, float heading) override;
    void CreateProp(const char* id, const Wm3::Vec3f& loc) override;
    void DestroyEntity(moho::EntId entityId) override;
    void WarpEntity(moho::EntId entityId, const moho::VTransform& transform) override;
    void ProcessInfoPair(moho::EntId entityId, gpg::StrArg key, gpg::StrArg value) override;
    void IssueCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    void IssueFactoryCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    void IncreaseCommandCount(moho::CmdId id, int count) override;
    void DecreaseCommandCount(moho::CmdId id, int count) override;
    void SetCommandTarget(moho::CmdId id, const moho::SSTITarget& target) override;
    void SetCommandType(moho::CmdId id, moho::EUnitCommandType type) override;
    void SetCommandCells(
      moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
    ) override;
    void RemoveCommandFromUnitQueue(moho::CmdId id, moho::EntId unitId) override;
    void ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args) override;
    void LuaSimCallback(
      const char* name, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    void ExecuteDebugCommand(
      const char* command, const Wm3::Vector3<float>& position, uint32_t army,
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    void AdvanceBeat(int beats) override;
    void EndGame() override;

    /**
     * Values in sim callbacks' Lua arguments, outside the marked fields, that have the form of a
     * renumbered id (`LooksRenumbered`): passed as they are, counted, and the first few logged.
     */
    [[nodiscard]] std::uint64_t UnmarkedIds() const noexcept { return mUnmarkedIds; }

  protected:
    /** The id as `next` gets it, in place; false refuses it (the command is dropped). */
    [[nodiscard]] virtual bool RewriteEntity(std::uint32_t& id) = 0;
    [[nodiscard]] virtual bool RewriteCommand(std::uint32_t& id) = 0;
    /** Whether an unmarked Lua value is worth logging as an id (none by default). */
    [[nodiscard]] virtual bool LooksRenumbered(std::uint32_t value) const { return false; }

  private:
    using EntitySet = moho::BVSet<moho::EntId, moho::EntIdUniverse>;

    // Each returns false, having counted and logged the drop, for an id that is refused.
    [[nodiscard]] bool Entity(const char* message, std::uint32_t& id);
    [[nodiscard]] bool Command(const char* message, std::uint32_t& id);
    [[nodiscard]] bool Target(const char* message, moho::SSTITarget& target);
    [[nodiscard]] bool Entities(const char* message, const EntitySet& in, EntitySet& out);
    [[nodiscard]] bool IssueData(const char* message, moho::SSTICommandIssueData& data);
    void Drop(const char* message, const char* kind, std::uint32_t id);
    void CountBlipTarget(const moho::SSTICommandIssueData& data) noexcept;
    [[nodiscard]] bool CallbackIds(const char* name, const LuaPlus::LuaObject& args);
    void LogUnmarked(const char* name, const LuaPlus::LuaObject& value, const std::string& path, int depth);

    moho::ICommandSink& mNext;
    std::uint64_t mUnmarkedIds = 0;
    std::uint64_t mCommands = 0;
    std::uint64_t mIdsRewritten = 0;
    std::uint64_t mDropped = 0;
    std::string mLastDrop;
    std::array<std::uint64_t, 64> mBlipTargets{};
  };

  /**
   * Plan WP5.6: a client's selection mask (`SetSyncFilterMaskB`, the selected unit ids; research
   * row R4) in sim ids. An id that does not map back, or that `known` rejects (the view's client
   * holds no record of it), is left out; returns how many were. Mask A needs nothing: the retail
   * driver never stores it (0x0073B43D jumps over the copy).
   */
  [[nodiscard]] std::uint32_t TranslateSelectionMask(
    const CViewIdMap& map, const moho::SSyncFilterMaskBlock& in, moho::SSyncFilterMaskBlock& out,
    const std::function<bool(std::uint32_t simId)>& known
  );

  /** A client's commands from its view's ids to the sim's (the server's intake). */
  class CInboundIdTranslator final : public CCommandIdRewriter
  {
  public:
    CInboundIdTranslator(moho::ICommandSink& next, const CViewIdMap& map) noexcept
      : CCommandIdRewriter(next)
      , mMap(&map)
    {}

    /** The view the commands come from (a client's army). */
    void SetMap(const CViewIdMap& map) noexcept { mMap = &map; }

  protected:
    [[nodiscard]] bool RewriteEntity(std::uint32_t& id) override { return mMap->EntityToSim(id, id); }
    [[nodiscard]] bool RewriteCommand(std::uint32_t& id) override { return mMap->CommandToSim(id, id); }
    /** A blip or foreign projectile id of this view, as only a view id can be. */
    [[nodiscard]] bool LooksRenumbered(const std::uint32_t value) const override
    {
      std::uint32_t simId = 0;
      return mMap->MapsEntity(value) && mMap->EntityToSim(value, simId);
    }

  private:
    const CViewIdMap* mMap;
  };
} // namespace faf::remote
