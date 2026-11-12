#include "editor/doc/EdAutosave.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    [[nodiscard]] std::string Stamp()
    {
      char stamp[32];
      const std::time_t now = std::time(nullptr);
      std::tm local{};
      (void)localtime_s(&local, &now);
      (void)std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &local);
      return stamp;
    }
  } // namespace

  std::string AutosaveNote(
    const EdAutosaveEntry& entry
  )
  {
    return "scenario=" + entry.scenario + "\ntitle=" + entry.title + "\ndisk=" + entry.disk.generic_string() +
      "\ntime=" + std::to_string(entry.time) + "\n";
  }

  bool ReadAutosaveNote(
    std::string_view text,
    EdAutosaveEntry& entry
  )
  {
    bool scenario = false;
    bool disk = false;
    while (!text.empty()) {
      const std::size_t end = text.find('\n');
      std::string_view line = text.substr(0, end);
      text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
        line.remove_suffix(1);
      }
      const std::size_t equals = line.find('=');
      if (equals == std::string_view::npos) {
        continue;
      }
      const std::string_view key = line.substr(0, equals);
      const std::string value(line.substr(equals + 1));
      if (key == "scenario") {
        entry.scenario = value;
        scenario = !value.empty();
      } else if (key == "title") {
        entry.title = value;
      } else if (key == "disk") {
        entry.disk = std::filesystem::path(value);
        disk = !value.empty();
      } else if (key == "time") {
        entry.time = std::atoll(value.c_str());
      }
    }
    return scenario && disk;
  }

  std::vector<EdAutosaveEntry> ListAutosaves(
    const std::filesystem::path& root
  )
  {
    std::vector<EdAutosaveEntry> out;
    std::error_code error;
    for (const auto& item : std::filesystem::directory_iterator(root, error)) {
      std::ifstream in(item.path() / "autosave.txt", std::ios::binary);
      if (!item.is_directory() || !in) {
        continue;
      }
      std::ostringstream text;
      text << in.rdbuf();
      EdAutosaveEntry entry;
      if (ReadAutosaveNote(text.str(), entry)) {
        entry.folder = item.path();
        out.push_back(std::move(entry));
      }
    }
    std::sort(out.begin(), out.end(), [](const EdAutosaveEntry& a, const EdAutosaveEntry& b) {
      return a.time > b.time;
    });
    return out;
  }

  bool AutosaveDue(
    const double now,
    const bool modified,
    const double lastAutosave,
    const double lastInput,
    const double interval,
    const double idle
  )
  {
    return modified && interval > 0.0 && now - lastAutosave >= interval && now - lastInput >= idle;
  }

  std::vector<std::filesystem::path> MapFolderFiles(
    const std::filesystem::path& folder
  )
  {
    std::vector<std::filesystem::path> out;
    std::error_code error;
    for (const auto& item : std::filesystem::directory_iterator(folder, error)) {
      const std::string extension = Lower(item.path().extension().string());
      if (item.is_regular_file() && (extension == ".scmap" || extension == ".lua")) {
        out.push_back(item.path());
      }
    }
    std::sort(out.begin(), out.end());
    return out;
  }

  std::vector<std::filesystem::path> BackupsToRemove(
    std::vector<std::filesystem::path> backups,
    const int keep
  )
  {
    if (keep <= 0 || static_cast<int>(backups.size()) <= keep) {
      return {};
    }
    std::sort(backups.begin(), backups.end());
    backups.resize(backups.size() - static_cast<std::size_t>(keep));
    return backups;
  }

  bool BackupMapFolder(
    const std::filesystem::path& folder,
    const std::filesystem::path& root,
    const int keep,
    std::filesystem::path& made,
    std::string& error
  )
  {
    const std::vector<std::filesystem::path> files = MapFolderFiles(folder);
    if (files.empty()) {
      error = "no map files in " + folder.string();
      return false;
    }
    const std::filesystem::path mapRoot = root / folder.filename();
    made = mapRoot / Stamp();
    std::error_code code;
    std::filesystem::create_directories(made, code);
    for (const std::filesystem::path& file : files) {
      if (!code) {
        std::filesystem::copy_file(
          file, made / file.filename(), std::filesystem::copy_options::overwrite_existing, code
        );
      }
    }
    if (code) {
      error = "the backup into " + made.string() + " failed: " + code.message();
      return false;
    }
    // The newest `keep` of this map's backups stay.
    std::vector<std::filesystem::path> backups;
    for (const auto& item : std::filesystem::directory_iterator(mapRoot, code)) {
      if (item.is_directory()) {
        backups.push_back(item.path());
      }
    }
    for (const std::filesystem::path& old : BackupsToRemove(std::move(backups), keep)) {
      std::error_code ignored;
      std::filesystem::remove_all(old, ignored);
    }
    return true;
  }

  bool RestoreAutosave(
    const EdAutosaveEntry& entry,
    const std::filesystem::path& backupRoot,
    const int keep,
    std::filesystem::path& backup,
    std::string& error
  )
  {
    if (!BackupMapFolder(entry.disk, backupRoot, keep, backup, error)) {
      return false;
    }
    std::error_code code;
    for (const std::filesystem::path& file : MapFolderFiles(entry.folder)) {
      std::filesystem::copy_file(
        file, entry.disk / file.filename(), std::filesystem::copy_options::overwrite_existing, code
      );
      if (code) {
        error = "copying " + file.filename().string() + " back failed: " + code.message() +
          " (the map's files before "
          "are in " +
          backup.string() + ")";
        return false;
      }
    }
    return true;
  }

  void RemoveAutosave(
    const std::filesystem::path& folder
  )
  {
    std::error_code ignored;
    if (std::filesystem::exists(folder / "autosave.txt", ignored)) {
      std::filesystem::remove_all(folder, ignored);
    }
  }
} // namespace faf::editor
