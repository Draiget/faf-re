#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A file to put in a zip: its name inside the zip (with '/' between folders) and its bytes. */
  struct ZipEntry
  {
    std::string name;
    std::string data;
  };

  /**
   * A zip archive of the entries, each deflated (zlib, raw) or stored when deflating doesn't make it smaller, with
   * their CRC-32s and the central directory, as any zip reader (and the FAF vault's) takes it.
   */
  std::string WriteZip(const std::vector<ZipEntry>& entries);

  /** What packaging a map folder found: the files that go in, and what is wrong (errors) or worth a look (warnings). */
  struct PackagePlan
  {
    /** The folder's name, `name.vNNNN`, the zip's only top folder. */
    std::string folder;
    int version = 0;
    /** The files that go in, relative to the folder. */
    std::vector<std::string> files;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
  };

  /**
   * Checks a map folder for the vault: its name is `name.vNNNN` in lower case; the scenario's `map_version` is that
   * number; its `map`, `save` and `script` paths are inside `/maps/<folder>/` and those files are there; it has a name
   * (and a description, else a warning). The files are every file in the folder but the editor's backups and sidecar
   * and the system's clutter (Thumbs.db, desktop.ini, *.bak).
   */
  PackagePlan PlanPackage(const std::string& folder, const std::string& scenario, const std::vector<std::string>& files);

  /** The version of a `name.vNNNN` folder, or 0. */
  int FolderVersion(const std::string& folder);

  /**
   * The scenario with `map_version` set to `version`: the value replaced where it has one, else a line added after
   * `ScenarioInfo = {` (the game's maps lack it; the vault wants it to match the folder's version).
   */
  std::string WithMapVersion(const std::string& scenario, int version);

  /** Every file under a folder on disk, relative to it with '/' between folders. */
  std::vector<std::string> FilesUnder(const std::filesystem::path& folder);
} // namespace faf::editor
