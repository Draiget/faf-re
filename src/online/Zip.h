#pragma once

// Engine addition (in-game launcher plan, WP6, the launcher's mods): reading a zip archive in memory, moved from the
// map editor's vault downloads (editor/doc/EdVault.cpp) so the game's mod downloads use the same reader.

#include <expected>
#include <string>
#include <vector>

namespace faf::online
{
  /** A file in a zip archive: its path inside the archive and its bytes. */
  struct ZipEntry
  {
    std::string name;
    std::string data;
  };

  /**
   * The entries of a zip archive in memory (stored or deflated; sizes from the central directory, each file's CRC-32
   * checked). The error when it isn't one, an entry is damaged, or the whole would unpack past 1 GB.
   */
  [[nodiscard]] std::expected<std::vector<ZipEntry>, std::string> ReadZip(const std::string& zip);

  /**
   * `entries` as a zip archive in memory: each file deflated (stored when that is no smaller), its CRC-32, names as
   * UTF-8; a name ending in "/" is a folder. The error past 1 GB or 65535 entries (no zip64).
   */
  [[nodiscard]] std::expected<std::string, std::string> WriteZip(const std::vector<ZipEntry>& entries);
} // namespace faf::online
