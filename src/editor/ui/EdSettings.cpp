#include "editor/ui/EdSettings.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    struct Definition
    {
      const char* key;
      const char* initial;
      std::vector<std::string> allowed; // empty: "0" or "1"
    };

    const std::vector<Definition>& Definitions()
    {
      static const std::vector<Definition> kDefinitions = {
        {EdSettings::kTitleBar, "own", {"own", "windows"}},
        {EdSettings::kRenderer, "auto", {"auto", "d3d12", "vulkan"}},
        {EdSettings::kBackgroundFps, "30", {"0", "10", "30", "60"}},
        {EdSettings::kFullHelp, "0", {}},
        {EdSettings::kPanelsWhilePlaying, "1", {}},
        {EdSettings::kStartScreen, "1", {}},
        {EdSettings::kVaultItems, "1", {}},
      };
      return kDefinitions;
    }

    const Definition* Find(
      std::string_view key
    )
    {
      for (const Definition& d : Definitions()) {
        if (key == d.key) {
          return &d;
        }
      }
      return nullptr;
    }

    [[nodiscard]] std::string_view Trim(
      std::string_view text
    )
    {
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
      }
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
      }
      return text;
    }
  } // namespace

  std::vector<std::string> EdSettings::Allowed(
    std::string_view key
  )
  {
    const Definition* const d = Find(key);
    return d != nullptr ? d->allowed : std::vector<std::string>{};
  }

  bool EdSettings::Known(
    std::string_view key
  )
  {
    return Find(key) != nullptr;
  }

  std::vector<std::string> EdSettings::Read(
    std::string_view text
  )
  {
    std::vector<std::string> problems;
    int number = 0;
    while (!text.empty()) {
      const std::size_t end = text.find('\n');
      const std::string_view line = Trim(text.substr(0, end));
      text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
      ++number;
      if (line.empty() || line.front() == ';' || line.front() == '#' || line.front() == '[') {
        continue;
      }
      const std::size_t equals = line.find('=');
      const std::string_view key = Trim(line.substr(0, equals));
      const std::string_view value =
        equals == std::string_view::npos ? std::string_view{} : Trim(line.substr(equals + 1));
      if (equals == std::string_view::npos || !Known(key)) {
        problems.push_back("line " + std::to_string(number) + ": no setting \"" + std::string(key) + "\"");
      } else if (!Set(key, value)) {
        problems.push_back(
          "line " + std::to_string(number) + ": " + std::string(key) + " can't be \"" + std::string(value) + "\""
        );
      }
    }
    return problems;
  }

  std::string EdSettings::Write() const
  {
    std::string out = "; The map editor's settings (Settings in the editor). <key>=<value>.\n[Settings]\n";
    for (const Definition& d : Definitions()) {
      out += std::string(d.key) + "=" + Get(d.key) + "\n";
    }
    return out;
  }

  std::string EdSettings::Get(
    std::string_view key
  ) const
  {
    if (const auto found = mValues.find(key); found != mValues.end()) {
      return found->second;
    }
    const Definition* const d = Find(key);
    return d != nullptr ? d->initial : std::string();
  }

  bool EdSettings::GetBool(
    std::string_view key
  ) const
  {
    return Get(key) == "1";
  }

  int EdSettings::GetInt(
    std::string_view key
  ) const
  {
    return std::atoi(Get(key).c_str());
  }

  bool EdSettings::Set(
    std::string_view key,
    std::string_view value
  )
  {
    const Definition* const d = Find(key);
    if (d == nullptr) {
      return false;
    }
    const std::string v(value);
    const bool ok = d->allowed.empty() ? (v == "0" || v == "1")
                                       : std::find(d->allowed.begin(), d->allowed.end(), v) != d->allowed.end();
    if (!ok) {
      return false;
    }
    mValues[std::string(key)] = v;
    return true;
  }

  bool EdSettings::SetBool(
    std::string_view key,
    const bool value
  )
  {
    return Set(key, value ? "1" : "0");
  }

  bool EdSettings::SetInt(
    std::string_view key,
    const int value
  )
  {
    return Set(key, std::to_string(value));
  }
} // namespace faf::editor
