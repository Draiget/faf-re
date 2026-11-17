#include "editor/doc/EdUserFiles.h"

#include <cctype>
#include <cstdlib>
#include <system_error>

namespace faf::editor
{
  int UserFileFormat(
    std::string_view text
  )
  {
    while (!text.empty()) {
      const std::size_t end = text.find('\n');
      std::string_view line = text.substr(0, end);
      text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
      while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front())) != 0) {
        line.remove_prefix(1);
      }
      if (line.size() > 6 && (line.starts_with("Format") || line.starts_with("format"))) {
        line.remove_prefix(6);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
          line.remove_prefix(1);
        }
        if (!line.empty() && line.front() == '=') {
          line.remove_prefix(1);
          return std::atoi(std::string(line).c_str());
        }
      }
    }
    return 0;
  }

  std::filesystem::path KeepBadCopy(
    const std::filesystem::path& file
  )
  {
    std::filesystem::path bad = file;
    bad += ".bad";
    std::error_code error;
    std::filesystem::copy_file(file, bad, std::filesystem::copy_options::overwrite_existing, error);
    return error ? std::filesystem::path() : bad;
  }

  const std::vector<std::string>& UserSettingFiles()
  {
    static const std::vector<std::string> kFiles = {"settings.ini", "layout.ini", "keys.ini", "play_setups.ini"};
    return kFiles;
  }

  int PutUserSettingsAside(
    const std::filesystem::path& folder
  )
  {
    int moved = 0;
    for (const std::string& name : UserSettingFiles()) {
      const std::filesystem::path file = folder / name;
      std::error_code error;
      if (!std::filesystem::exists(file, error)) {
        continue;
      }
      std::filesystem::path aside = file;
      aside += ".reset";
      std::filesystem::remove(aside, error);
      error.clear();
      std::filesystem::rename(file, aside, error);
      moved += error ? 0 : 1;
    }
    return moved;
  }

  std::vector<std::filesystem::path> InitFileCandidates(
    const std::filesystem::path& exeFolder,
    const std::filesystem::path& programData
  )
  {
    std::vector<std::filesystem::path> out;
    out.push_back(exeFolder / "init_faf.lua");
    const std::filesystem::path parent = exeFolder.parent_path();
    out.push_back(parent / "bin_x64" / "init_faf.lua");
    out.push_back(parent / "bin" / "init_faf.lua");
    if (!programData.empty()) {
      out.push_back(programData / "FAForever" / "bin_x64" / "init_faf.lua");
      out.push_back(programData / "FAForever" / "bin" / "init_faf.lua");
    }
    return out;
  }

  std::filesystem::path FindInitFile(
    const std::vector<std::filesystem::path>& candidates,
    const std::function<bool(const std::filesystem::path&)>& exists
  )
  {
    for (const std::filesystem::path& candidate : candidates) {
      if (exists(candidate)) {
        return candidate;
      }
    }
    return {};
  }

  bool HasInitArgument(
    const std::vector<std::string>& arguments
  )
  {
    for (const std::string& argument : arguments) {
      if (argument.size() == 5) {
        std::string lower = argument;
        for (char& c : lower) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (lower == "/init" || lower == "-init") {
          return true;
        }
      }
    }
    return false;
  }
} // namespace faf::editor
