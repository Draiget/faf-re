#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP7.2): sound parameters on the wire. Sim Lua makes them
// at run time (`Sound{Cue, Bank, LodCutoff}`), so unlike blueprints there is no table either
// side could build at load. The server interns each (bank, cue, LOD cutoff) on first use and
// sends the new entry on the reliable stream before any event that names it; the client adds
// entries strictly in id order. Ids are per session and never reused.

namespace faf::remote::wire
{
  struct SSoundEntry
  {
    std::string bank;
    std::string cue;
    std::string lodCutoff; // the LOD cutoff variable's name, or empty

    [[nodiscard]] bool operator==(const SSoundEntry& other) const noexcept = default;
  };

  /** The server side: interning, and the reliable-stream record for a new entry. */
  class CSoundTableWriter
  {
  public:
    struct SInterned
    {
      std::uint32_t id = 0;
      bool isNew = false; // the caller must send `WriteEntry(id)` before using `id`
    };

    [[nodiscard]] SInterned Intern(const SSoundEntry& entry);
    /** Writes entry `id` (as `Intern` returned it) for `CSoundTableReader::ReadEntry`. */
    void WriteEntry(std::uint32_t id, BitWriter& writer) const;
    [[nodiscard]] std::uint32_t Size() const noexcept { return static_cast<std::uint32_t>(mEntries.size()); }

  private:
    std::map<std::tuple<std::string, std::string, std::string>, std::uint32_t> mIds;
    std::vector<SSoundEntry> mEntries;
  };

  /** The client side: entries arrive in id order; anything else is refused. */
  class CSoundTableReader
  {
  public:
    static constexpr std::size_t kMaxNameBytes = 256;
    static constexpr std::uint32_t kMaxEntries = 1u << 16;

    /** False (table unchanged) for a malformed record, an id out of order, or a full table. */
    [[nodiscard]] bool ReadEntry(BitReader& reader);
    [[nodiscard]] const SSoundEntry* Find(std::uint32_t id) const noexcept;
    [[nodiscard]] std::uint32_t Size() const noexcept { return static_cast<std::uint32_t>(mEntries.size()); }

  private:
    std::vector<SSoundEntry> mEntries;
  };
} // namespace faf::remote::wire
