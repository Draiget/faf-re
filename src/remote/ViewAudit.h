#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "remote/wire/ArmyLane.h"
#include "remote/wire/CommandLane.h"

// Engine addition, server mode (plan WP6.9, switch `srv_ViewAudit`, docs/SWITCHES.md): the server's own check of what
// it puts in each player's view, against the rules that view is held to. The spy client (headless `--spy`) checks
// the same from a client's side, after the wire; this runs on the server, before it, in a real game too.
//
// What it checks, for every view a player gets:
// - Lua lane (remote/SyncRouting.h): every top-level `Sync` key has a route in the policy in use, and one routed to
//   observers is there only when the view's own focus wrote it; every id in a field the policy marks (`SyncIdFields`)
//   is one its audience lets the view have (the unit's owner, its allies, a prop label at a spot the view sees); every
//   other id written as Lua writes entity ids (a string of digits, `GetEntityId()`; not in a score or in text a player
//   typed) that names an entity of another army is one the view's client holds a record of, checked once that beat's
//   frames are done; no id the view's id map renumbers goes raw. Writes of keys the policy doesn't route at all (they
//   reach observers only) count too.
// - Command-records lane (remote/wire/CommandLane.h): every unit and target entity a record names is one the view's
//   client knows: a record its frames hold (now or lately), or for a blip or another army's projectile a view id its
//   frames gave it (live or within the retirement grace).
// - Army lane (remote/ArmyRecords.h): another army's economy, resource sharing, whole-map flag, start position and
//   no-rush ring are zero (plan §6, army variable data).
//
// Each finding is an incident: the first few of each kind are logged in full (`view audit: ...`), then one line per
// thousand; `Summary` is the game's total. With the switch off nothing is made and nothing runs.

namespace faf::remote
{
  /** `srv_ViewAudit`: read when a game's views are first built. `--view-audit` (server, headless) sets it. */
  [[nodiscard]] bool ViewAuditSwitchOn() noexcept;
  void SetViewAuditSwitch(bool on) noexcept;

  enum class EViewAuditIncident : std::uint8_t
  {
    UnroutedKey,     // a `Sync` key the policy in use doesn't list (in a view, or written for observers only)
    ObserversKey,    // a key routed to observers in a player's view, not written under that player's focus
    OutsideAudience, // an id in a marked field its audience doesn't let the view have
    NotHeld,         // an entity id of another army the view's client holds no record of
    RenumberedRaw,   // a sim id the view's id map renumbers, sent as it is
    BadPayload,      // a view's `Sync` bytes that don't walk
    CommandUnit,     // a command record's unit the view's client doesn't know
    CommandTarget,   // a command record's target entity the view's client doesn't know
    ArmyField,       // another army's focus-only field, not zero
    Count
  };
  [[nodiscard]] std::string_view ViewAuditIncidentName(EViewAuditIncident kind) noexcept;

  /** An id as the sim has it, for one view. */
  struct SAuditEntity
  {
    bool exists = false;     // an entity has this id now
    std::int32_t owner = -1; // its army, or a dead unit's (from the id); -1 none (a prop, ...)
    bool renumbered = false; // the view's id map gives it a number of its own
  };

  /** What the Lua audit asks about the world, for one view. */
  struct SViewAuditLuaFacts
  {
    std::function<SAuditEntity(std::uint32_t id)> entity;
    std::function<bool(std::int32_t army)> allied;             // the view's army is `army` or counts it as an ally
    std::function<bool(std::uint32_t id)> labelSeen;           // a reclaim label for this prop may be in the view now
    std::function<bool(std::string_view key)> wroteUnderFocus; // sim Lua wrote `key` under the view's focus this beat
  };

  class CViewAudit
  {
  public:
    /** Lines in full for each kind before they thin out to one per `kLineEvery`. */
    static constexpr std::uint64_t kFullLines = 10;
    static constexpr std::uint64_t kLineEvery = 1000;

    /**
     * On the sim thread, with the beat's routed tables in place: `view`'s `Sync` bytes (`LuaObject::ToByteStream`'s
     * encoding of one table), for army `army` (-1: a player watching everything, who may have it all).
     */
    void CheckLuaPayload(
      std::uint32_t beat,
      std::size_t view,
      std::int32_t army,
      std::span<const std::uint8_t> payload,
      const SViewAuditLuaFacts& facts
    );
    /** On the sim thread: the router's count of writes of keys it has no route for, and their names, so far. */
    void NoteUnroutedWrites(std::uint32_t beat, std::uint64_t writesSoFar, std::span<const std::string> keys);
    /**
     * On the sim thread, once the frames of the beats checked so far are done: each id `CheckLuaPayload` kept is one
     * `holds(view, id)` says the view's client holds (now, or lately).
     */
    void CheckHeldIds(const std::function<bool(std::size_t view, std::uint32_t simId)>& holds);
    /**
     * On the view's own work: its command-records lane. `holds(viewId, why)` is whether its client holds that entity;
     * when not, `why` says what the view knows of the id, for the log line.
     */
    using HeldTest = std::function<bool(std::uint32_t viewId, std::string& why)>;
    void CheckCommandLane(std::uint32_t beat, std::size_t view, const wire::SCommandLane& lane, const HeldTest& holds);
    /** On the view's own work: every army's record as `view` (an army's view) gets it. */
    void CheckArmyRecords(std::uint32_t beat, std::size_t view, std::span<const wire::SArmyRecord> records);

    [[nodiscard]] std::uint64_t Incidents() const noexcept;
    [[nodiscard]] std::uint64_t Incidents(
      const EViewAuditIncident kind
    ) const noexcept
    {
      return mIncidents[static_cast<std::size_t>(kind)].load(std::memory_order_relaxed);
    }
    /** One line: what was checked and every incident by kind. */
    [[nodiscard]] std::string Summary() const;

  private:
    struct SWalk;
    struct SPendingId
    {
      std::size_t view;
      std::int32_t army;
      std::uint32_t id;
      std::uint32_t beat;
      std::string where; // key.field
    };

    /** Counts one incident (or `count`) and logs it as the rate allows; `text` says what and where. */
    void Report(EViewAuditIncident kind, const char* text, std::uint64_t count = 1u);
    bool WalkValue(SWalk& walk, std::string_view field, int depth);
    void CheckId(SWalk& walk, std::uint32_t id, std::string_view field, bool isKey, bool isText, int depth);

    std::array<std::atomic<std::uint64_t>, static_cast<std::size_t>(EViewAuditIncident::Count)> mIncidents{};
    std::mutex mLogLock;
    // The sim thread's.
    std::vector<SPendingId> mPending;
    std::uint64_t mUnroutedSeen = 0;
    std::uint64_t mLuaViewBeats = 0;
    std::uint64_t mLuaKeys = 0;
    std::uint64_t mLuaIds = 0;
    std::uint64_t mLuaMarkedIds = 0;
    std::uint64_t mLuaHeldChecks = 0;
    std::uint64_t mLuaNumbersSkipped = 0; // whole numbers that look like an id but aren't written as one
    // The views' work.
    std::atomic<std::uint64_t> mCommandLanes{0};
    std::atomic<std::uint64_t> mCommandIds{0};
    std::atomic<std::uint64_t> mArmyLanes{0};
  };
} // namespace faf::remote
