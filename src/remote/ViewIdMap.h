#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <span>
#include <unordered_map>

#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP5.9, decision D6): the ids one view's client sees. A raw
// sim id tells a player things the view should not: a blip's serial counts the observed army's
// blips, a foreign projectile's serial counts that army's shots, and a command id's low part
// counts every command anyone issued. So for one view the server renumbers
//
//   - recon blips (entity family 3) and foreign projectiles (family 1 whose source byte is not
//     the view's army): a view id keeps the family nibble and the source byte (the client reads
//     both: the spatial class, a blip's army) and gets the next serial of that family and source
//     in this view, in order of first appearance;
//   - command ids whose top byte is not one of the view army's command sources (other clients'
//     commands and the sim's own, top byte 0x80): view id 0x80000000 | the next serial. The
//     client's own command ids (its source in the top byte) keep their value, so the commands it
//     issues stay its own.
//
// Everything else (units, props, shields, script entities, own projectiles) keeps its sim id.
// Serials only count up, so a view id is not handed out twice in a game (unless a serial range
// wraps, which `Overflows` counts): when the sim deletes or erases an entity, or releases a
// command, its mapping is retired, and a later sim object with the same sim id gets a fresh view
// id. Inbound translation (WP5.10) uses `EntityToSim` and `CommandToSim`.

namespace faf::remote
{
  class CViewIdMap
  {
  public:
    explicit CViewIdMap(std::int32_t viewArmy) noexcept
      : mViewArmy(viewArmy)
    {}

    /** Whether a sim entity id is renumbered for this view. */
    [[nodiscard]] bool MapsEntity(std::uint32_t simId) const noexcept;

    /** `isOwnCommand(id)`: the command's source is one of the view army's (it keeps its id). */
    using OwnCommandTest = std::function<bool(std::uint32_t commandId)>;

    /**
     * Rewrites every id field of `frame` (record ids, attachment parents and children, a unit's
     * creator, selection inheritor, focus, guarded unit, target blip, commands and build queue)
     * into view ids, allocating on first appearance, and sorts the records by their new ids.
     */
    void Translate(wire::SViewFrame& frame, const OwnCommandTest& isOwnCommand);

    /**
     * Beats a retired view id still translates inbound: a client's command can name an entity it
     * still shows for its latency after the sim deleted it, and the sim should get that command as
     * a lockstep client's would arrive. Well under the ~99 beats after which the sim reuses a
     * released serial (`EntityDB` 0x00684560's 100-slot ring), so a late id never reaches a newer entity.
     */
    static constexpr std::uint32_t kInboundGraceBeats = 50;

    /** The beat from now on (retirements count their grace from it); ends the grace of older ones. */
    void AdvanceTo(std::uint32_t beat);

    /** The sim deleted or erased these entities: their view ids retire. */
    void RetireEntities(std::span<const std::uint32_t> simIds);
    /** The sim released these commands: their view ids retire. */
    void RetireCommands(std::span<const std::uint32_t> simIds);
    /** Retires every mapped command for which `alive(simId)` is false. */
    void RetireCommandsUnless(const std::function<bool(std::uint32_t simId)>& alive);

    /** The sim id behind a view id (inbound translation), or false when the view never got it. */
    [[nodiscard]] bool EntityToSim(std::uint32_t viewId, std::uint32_t& simId) const;
    [[nodiscard]] bool CommandToSim(std::uint32_t viewId, std::uint32_t& simId) const;
    /**
     * The view id the view was given for a sim id, without handing out a new one: false for an id
     * that is renumbered but the view never got (or that retired). Ids kept as they are map to themselves.
     */
    [[nodiscard]] bool EntityToView(std::uint32_t simId, std::uint32_t& viewId) const;
    /**
     * The view id a client of this view holds for a sim id: the current one, or one retired within
     * the grace beats (the client may still name it). What a client sends, as the checks model it.
     */
    [[nodiscard]] bool EntityToHeldView(std::uint32_t simId, std::uint32_t& viewId) const;
    [[nodiscard]] bool CommandToHeldView(std::uint32_t simId, const OwnCommandTest& isOwnCommand, std::uint32_t& viewId) const;

    /** Diagnostics: the beat a renumbered sim entity id last retired in this view, or false if it never did. */
    [[nodiscard]] bool RetiredAt(const std::uint32_t simId, std::uint32_t& beat) const
    {
      const auto found = mRetiredAt.find(simId);
      if (found == mRetiredAt.end()) {
        return false;
      }
      beat = found->second;
      return true;
    }
    [[nodiscard]] bool CommandToView(std::uint32_t simId, const OwnCommandTest& isOwnCommand, std::uint32_t& viewId) const;

    [[nodiscard]] std::uint64_t EntitiesMapped() const noexcept { return mEntitiesMapped; }
    [[nodiscard]] std::uint64_t CommandsMapped() const noexcept { return mCommandsMapped; }
    [[nodiscard]] std::size_t LiveEntities() const noexcept { return mEntityToView.size(); }
    [[nodiscard]] std::size_t LiveCommands() const noexcept { return mCommandToView.size(); }
    /**
     * Serials only count up, so a view id can come back only when a family and source's 20-bit
     * serial (or the command's 24-bit one) wraps: the times that happened (must stay 0).
     */
    [[nodiscard]] std::uint64_t Overflows() const noexcept { return mOverflows; }

  private:
    [[nodiscard]] std::uint32_t Entity(std::uint32_t simId);
    [[nodiscard]] std::uint32_t Command(std::uint32_t simId, const OwnCommandTest& isOwnCommand);

    std::int32_t mViewArmy;
    std::unordered_map<std::uint32_t, std::uint32_t> mEntityToView;
    std::unordered_map<std::uint32_t, std::uint32_t> mEntityToSim;
    std::unordered_map<std::uint32_t, std::uint32_t> mCommandToView;
    std::unordered_map<std::uint32_t, std::uint32_t> mCommandToSim;
    std::unordered_map<std::uint32_t, std::uint32_t> mNextSerial; // family and source (id >> 20) -> next serial
    struct SGrace
    {
      std::uint32_t until;  // the beat the view id stops translating inbound
      std::uint32_t viewId;
      std::uint32_t simId;
      bool command;
    };
    std::deque<SGrace> mGrace; // retired, oldest first
    std::unordered_map<std::uint32_t, std::uint32_t> mRetiredAt; // sim id -> beat it last retired (diagnostics)
    std::unordered_map<std::uint32_t, std::uint32_t> mGraceEntities; // sim id -> view id, while in grace
    std::unordered_map<std::uint32_t, std::uint32_t> mGraceCommands;
    std::uint32_t mBeat = 0;
    std::uint32_t mNextCommand = 0;
    std::uint64_t mEntitiesMapped = 0;
    std::uint64_t mCommandsMapped = 0;
    std::uint64_t mOverflows = 0;
  };
} // namespace faf::remote
