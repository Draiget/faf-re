#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /**
   * One autosave (design §8 Files): a copy of an open map's five files, written while it has unsaved changes into
   * `<autosave folder>/<map folder>/`, with `autosave.txt` saying whose it is. A save of the map, or "Don't save",
   * removes it; one still there at the next start was left by a crash or a close without saving, and is offered.
   */
  struct EdAutosaveEntry
  {
    std::filesystem::path folder; // the autosave's own folder
    std::string scenario;         // the map's game path, "/maps/<folder>/<folder>_scenario.lua"
    std::string title;            // the map's name, for the offer
    std::filesystem::path disk;   // the map's folder on disk, where Recover puts the files back
    std::int64_t time = 0;        // when it was written, seconds since 1970
  };

  /** autosave.txt's text for an entry, and back (false when a key it needs is missing). */
  [[nodiscard]] std::string AutosaveNote(const EdAutosaveEntry& entry);
  bool ReadAutosaveNote(std::string_view text, EdAutosaveEntry& entry);

  /** Every autosave under `root` (folders with an autosave.txt), newest first. */
  [[nodiscard]] std::vector<EdAutosaveEntry> ListAutosaves(const std::filesystem::path& root);

  /**
   * Whether an autosave is due now: the map has unsaved changes, `interval` seconds passed since the last autosave
   * (or the edit that started this run of changes), and `idle` seconds since the last input (so a stroke isn't cut
   * in the middle and the pause isn't felt). Times in seconds on one clock.
   */
  [[nodiscard]] bool
  AutosaveDue(double now, bool modified, double lastAutosave, double lastInput, double interval, double idle);

  /** The files of a map folder a backup or an autosave carries: the .scmap and the .lua files. */
  [[nodiscard]] std::vector<std::filesystem::path> MapFolderFiles(const std::filesystem::path& folder);

  /**
   * Copies a map folder's files into `<root>/<folder name>/<YYYYMMDD-HHMMSS>/` and keeps the newest `keep` of that
   * map's backups (older ones removed; 0 keeps all). `made` is the new backup's folder.
   */
  bool BackupMapFolder(
    const std::filesystem::path& folder,
    const std::filesystem::path& root,
    int keep,
    std::filesystem::path& made,
    std::string& error
  );

  /** The backups beyond the newest `keep` of `backups` (names sort by time): the ones to remove. */
  [[nodiscard]] std::vector<std::filesystem::path>
  BackupsToRemove(std::vector<std::filesystem::path> backups, int keep);

  /**
   * Recover: the map's current files backed up (BackupMapFolder into `backupRoot`, so this can be undone), then
   * the autosave's files copied over them. False with `error`, nothing changed, when the backup fails.
   */
  bool RestoreAutosave(
    const EdAutosaveEntry& entry,
    const std::filesystem::path& backupRoot,
    int keep,
    std::filesystem::path& backup,
    std::string& error
  );

  /** Removes an autosave's folder (after a save, "Don't save", or Discard). */
  void RemoveAutosave(const std::filesystem::path& folder);
} // namespace faf::editor
