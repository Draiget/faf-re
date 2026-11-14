#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /**
   * The editor's own files in the user's settings folder (FAF Studio's userdata.lua: every file has a format, a file
   * from a newer editor is never written over, an unreadable one is kept as `.bad`; Help > Reset user settings).
   */

  /** The `Format=N` line of an ini file (0 when it has none: a file from before formats). */
  [[nodiscard]] int UserFileFormat(std::string_view text);

  /** `file` copied to `<file>.bad` (an older copy replaced); the copy's path, empty when it couldn't be made. */
  std::filesystem::path KeepBadCopy(const std::filesystem::path& file);

  /** The files Reset user settings puts aside: settings, layout and theme, keys, play setups. */
  [[nodiscard]] const std::vector<std::string>& UserSettingFiles();

  /** Each of UserSettingFiles() in `folder` renamed to `<name>.reset` (over an older one); how many were. */
  int PutUserSettingsAside(const std::filesystem::path& folder);

  /**
   * Where an editor started without `/init` finds FAF's game data (FAF Studio's PrepareEditorStart): FAF's
   * init_faf.lua next to the exe, in the FAF client's bin folders beside it or under ProgramData.
   */
  [[nodiscard]] std::vector<std::filesystem::path>
  InitFileCandidates(const std::filesystem::path& exeFolder, const std::filesystem::path& programData);

  /** The first of `candidates` that `exists`; empty when none. */
  [[nodiscard]] std::filesystem::path FindInitFile(
    const std::vector<std::filesystem::path>& candidates,
    const std::function<bool(const std::filesystem::path&)>& exists
  );

  /** True when the arguments already say where the data is (`/init <file>`). */
  [[nodiscard]] bool HasInitArgument(const std::vector<std::string>& arguments);
} // namespace faf::editor
