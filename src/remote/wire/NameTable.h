#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP7.2): names the sim makes up at run time and the client
// resolves itself, such as strategic underlay texture paths. Like the sound table: the server
// interns each name on first use and sends the new entry on the reliable stream before anything
// that names it; the client adds entries strictly in id order. Ids are per session.

namespace faf::remote::wire
{
  class CNameTableWriter
  {
  public:
    struct SInterned
    {
      std::uint32_t id = 0;
      bool isNew = false; // the caller must send `WriteEntry(id)` before using `id`
    };

    [[nodiscard]] SInterned Intern(std::string_view name);

    /** Entry record: varuint id, varuint byte length, the bytes. */
    void WriteEntry(std::uint32_t id, BitWriter& writer) const;

    [[nodiscard]] std::uint32_t Size() const noexcept { return static_cast<std::uint32_t>(mNames.size()); }

  private:
    std::map<std::string, std::uint32_t, std::less<>> mIds;
    std::vector<std::string> mNames;
  };

  class CNameTableReader
  {
  public:
    static constexpr std::size_t kMaxNameBytes = 512;
    static constexpr std::uint32_t kMaxEntries = 1u << 16;

    /** False (table unchanged) for a malformed record, an id out of order, or a full table. */
    [[nodiscard]] bool ReadEntry(BitReader& reader);

    [[nodiscard]] const std::string* Find(std::uint32_t id) const noexcept;
    [[nodiscard]] std::uint32_t Size() const noexcept { return static_cast<std::uint32_t>(mNames.size()); }

  private:
    std::vector<std::string> mNames;
  };
} // namespace faf::remote::wire
