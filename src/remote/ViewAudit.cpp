#include "remote/ViewAudit.h"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "remote/SyncRouting.h"

// Engine addition, server mode: see ViewAudit.h.

namespace faf::remote
{
  namespace
  {
    // Plan WP6.9, WP0.10 (docs/SWITCHES.md, server and headless): 0, the default, audits nothing.
    std::int32_t srv_ViewAudit = 0;
    moho::TConVar<std::int32_t> gTConVar_srv_ViewAudit(
      "srv_ViewAudit",
      "Server mode: 1 checks every Lua Sync key and id, command record and army record each player's view gets "
      "against the rules for that view, and logs what breaks them; 0 (default) checks nothing.",
      &srv_ViewAudit
    );

    // `LuaObject::ToByteStream`'s tags.
    constexpr std::uint8_t kTagNumber = 0;
    constexpr std::uint8_t kTagString = 1;
    constexpr std::uint8_t kTagNil = 2;
    constexpr std::uint8_t kTagBool = 3;
    constexpr std::uint8_t kTagTableBegin = 4;
    constexpr std::uint8_t kTagTableEnd = 5;

    // A whole number below this is taken for a count, not an id (as the spy client takes it): army 0's units fall
    // under it, but Lua writes ids as strings (`GetEntityId()`), and every string of digits is looked at.
    constexpr std::uint32_t kSmallestId = 1u << 20;

    [[nodiscard]] bool ParseDigits(
      const std::string_view text,
      std::uint32_t& id
    ) noexcept
    {
      return !text.empty() &&
        std::from_chars(text.data(), text.data() + text.size(), id).ptr == text.data() + text.size();
    }

    /**
     * Fields that hold text a player or a script wrote, never an id: chat lines (`ChatMessages`, `UnitData.Chat`,
     * `AIChat`), a marker ping's name (`lua/ui/game/ping.lua` `NamePing`), dialogue and objective text.
     */
    [[nodiscard]] bool IsTextField(
      const std::string_view field
    ) noexcept
    {
      constexpr std::string_view kText[] = {
        "text", "Text", "msg", "Msg", "Name", "name", "title", "Title", "description", "Description"
      };
      for (const std::string_view text : kText) {
        if (field == text) {
          return true;
        }
      }
      return false;
    }

    [[nodiscard]] bool WholeNumberId(
      const float value,
      std::uint32_t& id
    ) noexcept
    {
      if (!(value >= static_cast<float>(kSmallestId)) || value >= 4294967040.0f || std::floor(value) != value) {
        return false;
      }
      id = static_cast<std::uint32_t>(value);
      return true;
    }

    constexpr std::string_view kNames[] = {
      "Sync keys with no route",
      "observers' keys in a player's view",
      "ids outside their audience",
      "entity ids the view doesn't hold",
      "renumbered ids sent raw",
      "Sync tables that did not walk",
      "command units the view doesn't know",
      "command targets the view doesn't know",
      "other armies' focus-only fields not zero",
    };
    static_assert(std::size(kNames) == static_cast<std::size_t>(EViewAuditIncident::Count));
  } // namespace

  bool ViewAuditSwitchOn() noexcept
  {
    return srv_ViewAudit != 0;
  }

  void SetViewAuditSwitch(
    const bool on
  ) noexcept
  {
    srv_ViewAudit = on ? 1 : 0;
  }

  std::string_view ViewAuditIncidentName(
    const EViewAuditIncident kind
  ) noexcept
  {
    const auto index = static_cast<std::size_t>(kind);
    return index < std::size(kNames) ? kNames[index] : std::string_view("?");
  }

  struct CViewAudit::SWalk
  {
    std::uint32_t beat;
    std::size_t view;
    std::int32_t army;
    std::span<const std::uint8_t> bytes;
    const SViewAuditLuaFacts& facts;
    std::size_t pos = 0;
    std::string_view topKey{};
    bool endsLabel = false; // the id's value is a boolean: a reclaim label's end, not a new one

    [[nodiscard]] bool Left(
      const std::size_t count
    ) const noexcept
    {
      return pos + count <= bytes.size();
    }
    [[nodiscard]] bool ReadString(
      std::string_view& text
    ) noexcept
    {
      const auto* const start = bytes.data() + pos;
      const void* const end = std::memchr(start, 0, bytes.size() - pos);
      if (end == nullptr) {
        return false;
      }
      text = std::string_view(reinterpret_cast<const char*>(start), static_cast<const std::uint8_t*>(end) - start);
      pos += text.size() + 1u;
      return true;
    }
    [[nodiscard]] float ReadFloat() noexcept
    {
      float value = 0.0f;
      std::memcpy(&value, bytes.data() + pos, sizeof(value));
      pos += sizeof(value);
      return value;
    }
  };

  void CViewAudit::Report(
    const EViewAuditIncident kind,
    const char* const text,
    const std::uint64_t count
  )
  {
    const auto index = static_cast<std::size_t>(kind);
    const std::uint64_t before = mIncidents[index].fetch_add(count, std::memory_order_relaxed);
    const std::uint64_t after = before + count;
    const std::scoped_lock lock(mLogLock);
    if (before < kFullLines) {
      gpg::Warnf("view audit: %s: %s", kNames[index].data(), text);
    } else if (before / kLineEvery != after / kLineEvery) {
      gpg::Warnf(
        "view audit: %llu %s so far; the latest: %s", static_cast<unsigned long long>(after), kNames[index].data(), text
      );
    }
  }

  void CViewAudit::CheckId(
    SWalk& walk,
    const std::uint32_t id,
    const std::string_view field,
    const bool isKey,
    const bool isText,
    const int depth
  )
  {
    ++mLuaIds;
    const SAuditEntity entity = walk.facts.entity(id);
    char where[160];
    std::snprintf(
      where,
      sizeof(where),
      "id 0x%08x in %.*s.%.*s, view %zu (army %d), beat %u",
      id,
      static_cast<int>(walk.topKey.size()),
      walk.topKey.data(),
      static_cast<int>(field.size()),
      field.data(),
      walk.view,
      walk.army,
      walk.beat
    );
    if (entity.exists && entity.renumbered) {
      Report(EViewAuditIncident::RenumberedRaw, where);
    }

    const SSyncIdField* mark = nullptr;
    for (const SSyncIdField& candidate : SyncIdFields()) {
      if (
        candidate.key == walk.topKey && (isKey ? (depth == 1 && candidate.field.empty()) : candidate.field == field)
      ) {
        mark = &candidate;
        break;
      }
    }
    if (mark != nullptr) {
      ++mLuaMarkedIds;
      bool allowed = false;
      switch (mark->audience) {
      case ESyncIdAudience::Seen:
        allowed = walk.endsLabel || walk.facts.labelSeen(id);
        break;
      case ESyncIdAudience::Owner:
        // Lua decides for itself under a focus: `NoteFocusArmyChanged` releases the old army's units.
        allowed = entity.owner == walk.army || walk.facts.wroteUnderFocus(walk.topKey);
        break;
      case ESyncIdAudience::Allies:
        allowed = walk.facts.allied(entity.owner);
        break;
      }
      if (!allowed) {
        Report(EViewAuditIncident::OutsideAudience, where);
      }
      return;
    }
    // A score's totals and what players type only look like ids now and then: an energy total of 2097210, a chat line
    // or a marker ping's name saying "2" (army 0's units are 0 and up). Lua writes an entity's id as `GetEntityId()`
    // gives it, a string; a whole number that happens to fall on one is counted, not checked.
    if (walk.topKey == "Score" || walk.topKey == "ScoreAccum" || IsTextField(field)) {
      return;
    }
    if (!isText) {
      ++mLuaNumbersSkipped;
      return;
    }
    if (entity.exists && entity.owner != walk.army) {
      mPending.push_back(SPendingId{walk.view, walk.army, id, walk.beat, std::string(where)});
    }
  }

  bool CViewAudit::WalkValue(
    SWalk& walk,
    const std::string_view field,
    const int depth
  )
  {
    if (!walk.Left(1u)) {
      return false;
    }
    const std::uint8_t tag = walk.bytes[walk.pos++];
    std::uint32_t id = 0;
    switch (tag) {
    case kTagNumber:
      if (!walk.Left(sizeof(float))) {
        return false;
      }
      if (WholeNumberId(walk.ReadFloat(), id)) {
        CheckId(walk, id, field, false, false, depth);
      }
      return true;
    case kTagString: {
      std::string_view text;
      if (!walk.ReadString(text)) {
        return false;
      }
      if (ParseDigits(text, id)) {
        CheckId(walk, id, field, false, true, depth);
      }
      return true;
    }
    case kTagNil:
      return true;
    case kTagBool:
      ++walk.pos;
      return walk.Left(0u);
    case kTagTableBegin:
      break;
    default:
      return false;
    }

    while (walk.Left(1u) && walk.bytes[walk.pos] != kTagTableEnd) {
      const std::uint8_t keyTag = walk.bytes[walk.pos++];
      std::string_view entryField = "*";
      if (keyTag == kTagString) {
        std::string_view text;
        if (!walk.ReadString(text)) {
          return false;
        }
        if (depth > 0 && ParseDigits(text, id)) {
          walk.endsLabel = walk.Left(1u) && walk.bytes[walk.pos] == kTagBool;
          CheckId(walk, id, field, true, true, depth);
        } else {
          entryField = text;
        }
      } else if (keyTag == kTagNumber) {
        if (!walk.Left(sizeof(float))) {
          return false;
        }
        if (WholeNumberId(walk.ReadFloat(), id) && depth > 0) {
          CheckId(walk, id, field, true, false, depth);
        }
      } else {
        return false;
      }
      if (depth == 0) {
        walk.topKey = entryField;
        ++mLuaKeys;
        bool known = false;
        const ESyncRoute route = RouteOfSyncKey(entryField, known);
        if (!known || (route == ESyncRoute::Observers && !walk.facts.wroteUnderFocus(entryField))) {
          char text[160];
          std::snprintf(
            text,
            sizeof(text),
            "'%.*s' in view %zu (army %d), beat %u",
            static_cast<int>(entryField.size()),
            entryField.data(),
            walk.view,
            walk.army,
            walk.beat
          );
          Report(known ? EViewAuditIncident::ObserversKey : EViewAuditIncident::UnroutedKey, text);
        }
      }
      if (!WalkValue(walk, entryField, depth + 1)) {
        return false;
      }
    }
    if (!walk.Left(1u)) {
      return false;
    }
    ++walk.pos;
    return true;
  }

  void CViewAudit::CheckLuaPayload(
    const std::uint32_t beat,
    const std::size_t view,
    const std::int32_t army,
    const std::span<const std::uint8_t> payload,
    const SViewAuditLuaFacts& facts
  )
  {
    ++mLuaViewBeats;
    if (payload.empty()) {
      return;
    }
    // A player watching everything may have every key and id, as an observer's client: only that it walks and that
    // each key has a route are checked.
    static const SViewAuditLuaFacts kEverything{[](std::uint32_t) {
      return SAuditEntity{};
    }, [](std::int32_t) {
      return true;
    }, [](std::uint32_t) {
      return true;
    }, [](std::string_view) {
      return true;
    }};
    SWalk walk{beat, view, army, payload, army < 0 ? kEverything : facts};
    if (!WalkValue(walk, "", 0) || walk.pos != payload.size()) {
      char text[96];
      std::snprintf(text, sizeof(text), "view %zu (army %d), beat %u", view, army, beat);
      Report(EViewAuditIncident::BadPayload, text);
    }
  }

  void CViewAudit::NoteUnroutedWrites(
    const std::uint32_t beat,
    const std::uint64_t writesSoFar,
    const std::span<const std::string> keys
  )
  {
    if (writesSoFar <= mUnroutedSeen) {
      return;
    }
    std::string names;
    for (const std::string& key : keys) {
      names += (names.empty() ? "" : ", ") + key;
    }
    char text[256];
    std::snprintf(
      text,
      sizeof(text),
      "%llu writes by beat %u, observers only (keys so far: %s)",
      static_cast<unsigned long long>(writesSoFar - mUnroutedSeen),
      beat,
      names.c_str()
    );
    Report(EViewAuditIncident::UnroutedKey, text, writesSoFar - mUnroutedSeen);
    mUnroutedSeen = writesSoFar;
  }

  void CViewAudit::CheckHeldIds(
    const std::function<bool(std::size_t view, std::uint32_t simId)>& holds
  )
  {
    for (const SPendingId& pending : mPending) {
      ++mLuaHeldChecks;
      if (!holds(pending.view, pending.id)) {
        Report(EViewAuditIncident::NotHeld, pending.where.c_str());
      }
    }
    mPending.clear();
  }

  void CViewAudit::CheckCommandLane(
    const std::uint32_t beat,
    const std::size_t view,
    const wire::SCommandLane& lane,
    const HeldTest& holds
  )
  {
    if (lane.Empty()) {
      return;
    }
    mCommandLanes.fetch_add(1u, std::memory_order_relaxed);
    std::uint64_t ids = 0;
    char text[256];
    std::string why;
    for (const wire::SCommandUpdate& update : lane.updates) {
      if ((update.fields & wire::kCommandUnits) != 0u) {
        for (const std::uint32_t unit : update.data.units) {
          ++ids;
          why.clear();
          if (!holds(unit, why)) {
            std::snprintf(
              text,
              sizeof(text),
              "unit 0x%08x of command 0x%08x, view %zu, beat %u (%s)",
              unit,
              update.id,
              view,
              beat,
              why.c_str()
            );
            Report(EViewAuditIncident::CommandUnit, text);
          }
        }
      }
      for (const std::uint32_t field : {wire::kCommandTarget1, wire::kCommandTarget2}) {
        if ((update.fields & field) == 0u) {
          continue;
        }
        const wire::SCommandTarget& target = field == wire::kCommandTarget1 ? update.data.target1 : update.data.target2;
        if (target.entity == wire::kNoCommandEntity) {
          continue;
        }
        ++ids;
        why.clear();
        if (!holds(target.entity, why)) {
          std::snprintf(
            text,
            sizeof(text),
            "target 0x%08x of command 0x%08x, view %zu, beat %u (%s)",
            target.entity,
            update.id,
            view,
            beat,
            why.c_str()
          );
          Report(EViewAuditIncident::CommandTarget, text);
        }
      }
    }
    mCommandIds.fetch_add(ids, std::memory_order_relaxed);
  }

  void CViewAudit::CheckArmyRecords(
    const std::uint32_t beat,
    const std::size_t view,
    const std::span<const wire::SArmyRecord> records
  )
  {
    mArmyLanes.fetch_add(1u, std::memory_order_relaxed);
    for (std::size_t index = 0; index < records.size(); ++index) {
      if (index == view) {
        continue;
      }
      const wire::SArmyRecord& record = records[index];
      const char* field = nullptr;
      for (const float value : record.economy) {
        field = value != 0.0f ? "economy" : field;
      }
      if (record.maxStorage[0] != 0u || record.maxStorage[1] != 0u) {
        field = "max storage";
      } else if (record.resourceSharing != 0u) {
        field = "resource sharing";
      } else if (record.useWholeMap != 0u) {
        field = "use whole map";
      } else if (record.armyStart[0] != 0.0f || record.armyStart[1] != 0.0f) {
        field = "start position";
      } else if (
        record.noRushTimer != 0 || record.noRushRadius != 0.0f || record.noRushOffset[0] != 0.0f ||
        record.noRushOffset[1] != 0.0f
      ) {
        field = "no-rush ring";
      }
      if (field != nullptr) {
        char text[128];
        std::snprintf(text, sizeof(text), "army %zu's %s in view %zu, beat %u", index, field, view, beat);
        Report(EViewAuditIncident::ArmyField, text);
      }
    }
  }

  std::uint64_t CViewAudit::Incidents() const noexcept
  {
    std::uint64_t total = 0;
    for (const std::atomic<std::uint64_t>& count : mIncidents) {
      total += count.load(std::memory_order_relaxed);
    }
    return total;
  }

  std::string CViewAudit::Summary() const
  {
    char text[512];
    std::snprintf(
      text,
      sizeof(text),
      "view audit: %llu incidents; Lua: %llu view beats, %llu keys, %llu ids (%llu in marked fields, %llu checked "
      "against held records, %llu whole numbers not written as ids); command lanes: %llu, %llu ids; army lanes: %llu",
      static_cast<unsigned long long>(Incidents()),
      static_cast<unsigned long long>(mLuaViewBeats),
      static_cast<unsigned long long>(mLuaKeys),
      static_cast<unsigned long long>(mLuaIds),
      static_cast<unsigned long long>(mLuaMarkedIds),
      static_cast<unsigned long long>(mLuaHeldChecks),
      static_cast<unsigned long long>(mLuaNumbersSkipped),
      static_cast<unsigned long long>(mCommandLanes.load()),
      static_cast<unsigned long long>(mCommandIds.load()),
      static_cast<unsigned long long>(mArmyLanes.load())
    );
    std::string summary = text;
    for (std::size_t kind = 0; kind < mIncidents.size(); ++kind) {
      if (const std::uint64_t count = mIncidents[kind].load(); count != 0u) {
        summary += "; " + std::to_string(count) + " " + std::string(kNames[kind]);
      }
    }
    return summary;
  }
} // namespace faf::remote
