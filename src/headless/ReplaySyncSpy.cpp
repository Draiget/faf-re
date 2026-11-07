#include "headless/ReplaySyncSpy.h"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityId.h"
#include "moho/sim/Sim.h"
#include "remote/ViewIdMap.h"
#include "remote/VisibilityOracle.h"
#include "remote/wire/BitStream.h"
#include "remote/wire/LuaSyncLane.h"

namespace faf::headless
{
  namespace
  {
    // `LuaObject::ToByteStream`'s tags.
    constexpr std::uint8_t kTagNumber = 0;
    constexpr std::uint8_t kTagString = 1;
    constexpr std::uint8_t kTagNil = 2;
    constexpr std::uint8_t kTagBool = 3;
    constexpr std::uint8_t kTagTableBegin = 4;
    constexpr std::uint8_t kTagTableEnd = 5;

    constexpr std::uint32_t kSmallestNumberId = 1u << 20;

    [[nodiscard]] bool ParseDigits(const std::string_view text, std::uint32_t& id) noexcept
    {
      return !text.empty() && std::from_chars(text.data(), text.data() + text.size(), id).ptr == text.data() + text.size();
    }

    [[nodiscard]] bool WholeNumberId(const float value, std::uint32_t& id) noexcept
    {
      if (!(value >= static_cast<float>(kSmallestNumberId)) || value >= 4294967040.0f || std::floor(value) != value) {
        return false;
      }
      id = static_cast<std::uint32_t>(value);
      return true;
    }
  } // namespace

  struct CReplaySyncSpy::SWalk
  {
    const moho::Sim& sim;
    std::size_t view;
    std::int32_t army;
    const remote::CViewIdMap idMap;
    const std::vector<std::uint8_t>& table;
    std::size_t pos = 0;
    std::string_view topKey;
    bool endsLabel = false; // the id's value is a boolean: a reclaim label's end, not a new one

    [[nodiscard]] bool Left(const std::size_t count) const noexcept { return pos + count <= table.size(); }
    [[nodiscard]] bool ReadString(std::string_view& text) noexcept
    {
      const auto* const start = table.data() + pos;
      const void* const end = std::memchr(start, 0, table.size() - pos);
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
      std::memcpy(&value, table.data() + pos, sizeof(value));
      pos += sizeof(value);
      return value;
    }
  };

  void CReplaySyncSpy::Example(const SWalk& walk, const char* const what, const std::uint32_t id, const std::string_view field)
  {
    if (mExamples.size() >= 12u) {
      return;
    }
    char text[192];
    std::snprintf(
      text, sizeof(text), "%s: id 0x%08x in %.*s.%.*s, view of army %d, beat %d", what, id, static_cast<int>(walk.topKey.size()),
      walk.topKey.data(), static_cast<int>(field.size()), field.data(), walk.army, static_cast<int>(walk.sim.mCurBeat)
    );
    mExamples.emplace_back(text);
  }

  void CReplaySyncSpy::CheckId(SWalk& walk, const std::uint32_t id, const std::string_view field, const bool isKey, const int depth)
  {
    const moho::Entity* const entity = walk.sim.mEntityDB != nullptr ? walk.sim.mEntityDB->FindEntityById(id) : nullptr;
    ++mIds;
    if (entity != nullptr && walk.idMap.MapsEntity(id)) {
      ++mRawRenumbered;
      Example(walk, "renumbered id sent raw", id, field);
    }

    const remote::SSyncIdField* mark = nullptr;
    for (const remote::SSyncIdField& candidate : remote::SyncIdFields()) {
      if (candidate.key == walk.topKey && (isKey ? (depth == 1 && candidate.field.empty()) : candidate.field == field)) {
        mark = &candidate;
        break;
      }
    }
    const std::int32_t owner = entity != nullptr                                                      ? entity->GetArmyIndex()
                               : moho::ClassifyEntityIdFamily(id) == moho::EEntityIdFamily::Unit ? moho::ExtractEntityIdSourceIndex(id)
                                                                                                    : -1;
    if (mark != nullptr) {
      ++mMarkedIds;
      // Lua decides for itself under a focus: `NoteFocusArmyChanged` releases the old army's units.
      const std::string key(walk.topKey);
      const auto seen = [&] {
        // The map's first labels. A label's end only goes to who holds it, and the sim may have given
        // its id to another prop by then, somewhere else.
        if (walk.sim.mCurBeat <= 1u || entity == nullptr || walk.endsLabel) {
          return true;
        }
        const Wm3::Vec3f position = entity->GetPositionWm3();
        return remote::ViewCanSeePoint(walk.sim, walk.army, position, false) || remote::ViewCanSeePoint(walk.sim, walk.army, position, true);
      };
      const bool allowed = (mark->audience == remote::ESyncIdAudience::Seen && seen())
                           || (mark->audience == remote::ESyncIdAudience::Owner
                               && (owner == walk.army || mRouter.WroteUnderFocus(walk.view, key.c_str())))
                           || (mark->audience == remote::ESyncIdAudience::Allies && mRouter.Allied(walk.sim, walk.view, owner));
      if (!allowed) {
        ++mOutsideAudience;
        Example(walk, "outside its audience", id, field);
      }
      return;
    }
    // A score's totals and a chat line's text only look like ids now and then: an energy total of
    // 2097210, a message saying "1".
    if (entity != nullptr && owner != walk.army && walk.topKey != "Score" && walk.topKey != "ScoreAccum" && field != "text") {
      ++mUnmarked;
      Example(walk, "unmarked", id, field);
    }
  }

  bool CReplaySyncSpy::WalkValue(SWalk& walk, const std::string_view field, const int depth)
  {
    if (!walk.Left(1u)) {
      return false;
    }
    const std::uint8_t tag = walk.table[walk.pos++];
    std::uint32_t id = 0;
    switch (tag) {
      case kTagNumber: {
        if (!walk.Left(sizeof(float))) {
          return false;
        }
        if (WholeNumberId(walk.ReadFloat(), id)) {
          CheckId(walk, id, field, false, depth);
        }
        return true;
      }
      case kTagString: {
        std::string_view text;
        if (!walk.ReadString(text)) {
          return false;
        }
        if (ParseDigits(text, id)) {
          CheckId(walk, id, field, false, depth);
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

    while (walk.Left(1u) && walk.table[walk.pos] != kTagTableEnd) {
      const std::uint8_t keyTag = walk.table[walk.pos++];
      std::string_view entryField = "*";
      if (keyTag == kTagString) {
        std::string_view text;
        if (!walk.ReadString(text)) {
          return false;
        }
        if (ParseDigits(text, id)) {
          walk.endsLabel = walk.Left(1u) && walk.table[walk.pos] == kTagBool;
          CheckId(walk, id, field, true, depth);
        } else {
          entryField = text;
        }
      } else if (keyTag == kTagNumber) {
        if (!walk.Left(sizeof(float))) {
          return false;
        }
        if (WholeNumberId(walk.ReadFloat(), id)) {
          CheckId(walk, id, field, true, depth);
        }
      } else {
        return false;
      }
      if (depth == 0) {
        walk.topKey = entryField;
        ++mKeys[std::string(entryField)];
        bool known = false;
        const remote::ESyncRoute route = remote::RouteOfSyncKey(entryField, known);
        const std::string name(entryField);
        if (!known) {
          ++mUnknownKeys;
          Example(walk, "key with no route", 0u, entryField);
        } else if (route == remote::ESyncRoute::Observers && !mRouter.WroteUnderFocus(walk.view, name.c_str())) {
          ++mOutsideAudience;
          Example(walk, "observers' key", 0u, entryField);
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

  void CReplaySyncSpy::Check(const moho::Sim& sim)
  {
    std::vector<std::uint8_t> table;
    std::vector<std::string> prints;
    for (std::size_t view = 0; view < mRouter.ViewCount(); ++view) {
      ++mViewBeats;
      // After the wire: what the client holds.
      remote::wire::BitWriter writer;
      table.clear();
      prints.clear();
      if (!remote::wire::EncodeLuaSyncLane(mRouter.Payload(view), mRouter.Prints(view), writer)) {
        ++mDecodeFailures;
        continue;
      }
      remote::wire::BitReader reader(writer.Bytes());
      if (!remote::wire::DecodeLuaSyncLane(reader, table, prints)) {
        ++mDecodeFailures;
        continue;
      }
      const std::int32_t army = mRouter.ViewArmy(view);
      SWalk walk{sim, view, army, remote::CViewIdMap(army), table};
      if (!table.empty() && (!WalkValue(walk, "", 0) || walk.pos != table.size())) {
        ++mDecodeFailures;
      }
    }
  }

  std::string CReplaySyncSpy::Summary() const
  {
    char text[320];
    std::snprintf(
      text, sizeof(text),
      "lua spy: %zu keys over %llu view beats, %llu ids (%llu in marked fields); %llu keys with no route, %llu outside their audience, "
      "%llu renumbered ids sent raw, %llu that did not decode; %llu unmarked ids of other armies",
      mKeys.size(), static_cast<unsigned long long>(mViewBeats), static_cast<unsigned long long>(mIds),
      static_cast<unsigned long long>(mMarkedIds), static_cast<unsigned long long>(mUnknownKeys),
      static_cast<unsigned long long>(mOutsideAudience), static_cast<unsigned long long>(mRawRenumbered),
      static_cast<unsigned long long>(mDecodeFailures), static_cast<unsigned long long>(mUnmarked)
    );
    std::string summary = text;
    for (const std::string& example : mExamples) {
      summary += "\n    ";
      summary += example;
    }
    return summary;
  }
} // namespace faf::headless
