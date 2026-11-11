#pragma once

#include <cstdint>

namespace moho
{
  struct SSyncData;
}

namespace faf::headless
{
  /**
   * Engine addition (plan N4, WP16.1): a digest of what the sim published in one beat, independent of
   * `sim_ChecksumPeriod` and never touching the sim's checksum context: creations, every entity and unit update,
   * deletions, every army's economy, and the Lua `Sync` bytes (read whole, then the stream is rewound for whoever
   * decodes it next). Desync reports are left out (they depend on the checksum period by design). 64-bit FNV-1a,
   * field by field. headless `--state-digests` and the server's `--state-digests` write it, so a server's game and
   * its replay played back elsewhere compare beat by beat.
   */
  [[nodiscard]] std::uint64_t DigestPublishedState(const moho::SSyncData& packet);
} // namespace faf::headless
