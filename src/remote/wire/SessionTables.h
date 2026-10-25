#pragma once

#include <cstdint>
#include <vector>

#include "remote/wire/BitStream.h"
#include "remote/wire/NameTable.h"
#include "remote/wire/SoundTable.h"

// Engine addition, server mode (plan WP7.2): the tables a session builds as it goes (sounds,
// names) and the reliable-stream record that carries their new entries. The server writes the
// entries interned since its last record before the frames that use them; the client reads them
// in order. Record: varuint count of sound entries and the entries, then the same for names.

namespace faf::remote::wire
{
  class CSessionTableWriters
  {
  public:
    /** The sound table id of `entry`, interning it (and queueing it for the next record). */
    [[nodiscard]] std::uint32_t Sound(const SSoundEntry& entry);
    /** The name table id of `name`, as `Sound`. */
    [[nodiscard]] std::uint32_t Name(std::string_view name);

    /** True when entries are waiting for `WritePending`. */
    [[nodiscard]] bool HasPending() const noexcept { return !mNewSounds.empty() || !mNewNames.empty(); }

    /** Writes the queued entries and forgets them. */
    void WritePending(BitWriter& writer);

  private:
    CSoundTableWriter mSounds;
    CNameTableWriter mNames;
    std::vector<std::uint32_t> mNewSounds;
    std::vector<std::uint32_t> mNewNames;
  };

  class CSessionTableReaders
  {
  public:
    /** Reads one record; false (with whatever was read kept) when it is malformed. */
    [[nodiscard]] bool Read(BitReader& reader);

    [[nodiscard]] const CSoundTableReader& Sounds() const noexcept { return mSounds; }
    [[nodiscard]] const CNameTableReader& Names() const noexcept { return mNames; }

  private:
    CSoundTableReader mSounds;
    CNameTableReader mNames;
  };
} // namespace faf::remote::wire
