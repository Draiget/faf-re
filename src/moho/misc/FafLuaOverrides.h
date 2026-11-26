#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace moho
{
  class CVFSImpl;

  /**
   * Engine addition, not in the shipped binary: FAF UI Lua that faf-re ships before FAF releases it.
   *
   * `faf-re-lua.nx2` next to the executable (data/fa-lua in the repository, written by
   * tools/fa-lua/refresh.py) holds whole replacements for FAF files and a manifest.txt that pairs
   * each one with the SHA-256 of the FAF file it was made from. A replacement is used only while
   * the FAF file the init file mounted is exactly that file, so a FAF release that changes the
   * file, or takes our change, wins without anyone updating anything. Only UI Lua can be replaced
   * (FAFLUA_IsReplaceablePath), never a file the simulation loads. `/nofaflua` turns it off.
   */
  inline constexpr const char* kFafLuaArchiveName = "faf-re-lua.nx2";

  /** One manifest.txt line: `<sha256 hex> <game path> <entry in the archive> [notes...]`. */
  struct SFafLuaManifestEntry
  {
    std::string mBaseDigest;  // lowercase hex, 64 characters
    std::string mMountedPath; // lowercase, starts with '/'
    std::string mEntry;       // path inside the archive, '/' separated
    std::string mNotes;       // the rest of the line (pull requests, FAF branches), for the log
  };

  /**
   * Parses manifest.txt. Blank lines and lines starting with '#' are skipped; a line that isn't
   * `<64 hex digits> /<path> <entry> ...` adds a message to `problems` (when given) and is skipped.
   */
  [[nodiscard]] std::vector<SFafLuaManifestEntry>
  FAFLUA_ParseManifest(std::string_view text, std::vector<std::string>* problems);

  /** True for a lowercase game path that may be replaced: UI Lua under /lua/ui/ or /lua/keymap/. */
  [[nodiscard]] bool FAFLUA_IsReplaceablePath(std::string_view loweredMountedPath);

  /** Lowercase hex SHA-256 of `size` bytes. */
  [[nodiscard]] std::string FAFLUA_DigestHex(const void* data, std::size_t size);

  /**
   * Mounts `<executableDirectory>/faf-re-lua.nx2` when it is there and installs, on `vfs`, every
   * replacement whose FAF file matches its digest, logging each file used and each one skipped.
   * `vfs` is a file system just built from the init file's mount table that no other thread
   * reads yet.
   */
  void FAFLUA_Apply(CVFSImpl& vfs, const std::filesystem::path& executableDirectory);
} // namespace moho
