#include "editor/doc/EdEditorMods.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>

namespace faf::editor
{
  std::map<std::string, std::string> ModInfoFields(
    const std::string& text
  )
  {
    std::map<std::string, std::string> out;
    std::istringstream lines(text);
    std::string line;
    int depth = 0; // inside a table: its lines aren't top-level keys
    while (std::getline(lines, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      const std::size_t comment = line.find("--");
      const std::string code = comment == std::string::npos ? line : line.substr(0, comment);
      const int before = depth;
      for (const char c : code) {
        depth += c == '{' ? 1 : c == '}' ? -1 : 0;
      }
      depth = std::max(depth, 0);
      if (before != 0) {
        continue;
      }
      std::size_t i = code.find_first_not_of(" \t");
      if (i == std::string::npos || (std::isalpha(static_cast<unsigned char>(code[i])) == 0 && code[i] != '_')) {
        continue;
      }
      std::size_t k = i;
      while (k < code.size() && (std::isalnum(static_cast<unsigned char>(code[k])) != 0 || code[k] == '_')) {
        ++k;
      }
      const std::string key = code.substr(i, k - i);
      k = code.find_first_not_of(" \t", k);
      if (k == std::string::npos || code[k] != '=' || (k + 1 < code.size() && code[k + 1] == '=')) {
        continue;
      }
      std::string value = code.substr(k + 1);
      value.erase(0, value.find_first_not_of(" \t"));
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == ',')) {
        value.pop_back();
      }
      if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front()) {
        value = value.substr(1, value.size() - 2);
      } else if (value.size() >= 4 && value.rfind("[[", 0) == 0 && value.compare(value.size() - 2, 2, "]]") == 0) {
        value = value.substr(2, value.size() - 4);
      }
      out[key] = value;
    }
    return out;
  }

  EditorModInfo ReadEditorModInfo(
    const std::string& text,
    const std::filesystem::path& folder
  )
  {
    const std::map<std::string, std::string> fields = ModInfoFields(text);
    const auto get = [&](const char* key) {
      const auto it = fields.find(key);
      return it != fields.end() ? it->second : std::string();
    };
    EditorModInfo info;
    info.folder = folder;
    info.name = get("name").empty() ? folder.filename().string() : get("name");
    info.uid = get("uid");
    info.description = get("description");
    info.editorMod = get("editor_mod") == "true";
    if (const std::string api = get("editor_api"); !api.empty()) {
      info.api = std::atoi(api.c_str());
    }
    return info;
  }

  std::vector<EditorModInfo> FindEditorMods(
    const std::filesystem::path& mods
  )
  {
    std::vector<EditorModInfo> out;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(mods, ec)) {
      if (!entry.is_directory(ec)) {
        continue;
      }
      std::ifstream in(entry.path() / "mod_info.lua", std::ios::binary);
      if (!in) {
        continue;
      }
      std::ostringstream text;
      text << in.rdbuf();
      EditorModInfo info = ReadEditorModInfo(text.str(), entry.path());
      if (info.editorMod && !info.uid.empty()) {
        out.push_back(std::move(info));
      }
    }
    std::sort(out.begin(), out.end(), [](const EditorModInfo& a, const EditorModInfo& b) {
      return a.name < b.name;
    });
    return out;
  }

  std::string EditorModIncompatibility(
    const int api
  )
  {
    if (api > kEditorApiVersion) {
      return "it needs editor API " + std::to_string(api) + "; this editor has " + std::to_string(kEditorApiVersion);
    }
    if (api < kEditorApiOldest) {
      return "it was written for editor API " + std::to_string(api) + "; the oldest this editor takes is " +
        std::to_string(kEditorApiOldest);
    }
    return {};
  }

  std::string EditorModCommandId(
    const std::string& modName,
    const std::string& id
  )
  {
    std::string mod;
    for (const char c : modName) {
      if (std::isalnum(static_cast<unsigned char>(c)) != 0) {
        mod += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
    }
    std::string own;
    for (const char c : id) {
      if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '.') {
        own += c;
      }
    }
    return "mod." + (mod.empty() ? std::string("unnamed") : mod) + "." + own;
  }

  std::set<std::string> ParseEnabledMods(
    const std::string& text
  )
  {
    std::set<std::string> out;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
      line.erase(0, line.find_first_not_of(" \t"));
      while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())) != 0) {
        line.pop_back();
      }
      if (!line.empty() && line[0] != '#') {
        out.insert(line);
      }
    }
    return out;
  }

  std::string SaveEnabledMods(
    const std::set<std::string>& uids
  )
  {
    std::string out;
    for (const std::string& uid : uids) {
      out += uid + "\n";
    }
    return out;
  }
} // namespace faf::editor
