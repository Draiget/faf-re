#include "editor/ui/EdCommands.h"

#include <algorithm>
#include <cctype>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return out;
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

    /** A key's name as the editor writes it, from any usual spelling; empty when it isn't a key. */
    [[nodiscard]] std::string KeyName(
      std::string_view key
    )
    {
      const std::string low = Lower(Trim(key));
      if (low.empty()) {
        return {};
      }
      if (low.size() == 1) {
        const char c = low[0];
        if (std::isalnum(static_cast<unsigned char>(c)) != 0) {
          return std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
        if (std::string_view("=-[];',./`\\").find(c) != std::string_view::npos) {
          return std::string(1, c);
        }
        return {};
      }
      if (low[0] == 'f' && low.size() <= 3 && std::all_of(low.begin() + 1, low.end(), [](const unsigned char c) {
        return std::isdigit(c) != 0;
      })) {
        const int n = std::stoi(low.substr(1));
        return n >= 1 && n <= 24 ? "F" + std::to_string(n) : std::string();
      }
      static const std::pair<const char*, const char*> kNames[] = {
        {"delete", "Delete"}, {"del", "Delete"},        {"escape", "Escape"},
        {"esc", "Escape"},    {"enter", "Enter"},       {"return", "Enter"},
        {"tab", "Tab"},       {"space", "Space"},       {"backspace", "Backspace"},
        {"home", "Home"},     {"end", "End"},           {"pageup", "PageUp"},
        {"pgup", "PageUp"},   {"pagedown", "PageDown"}, {"pgdn", "PageDown"},
        {"insert", "Insert"}, {"ins", "Insert"},        {"up", "Up"},
        {"down", "Down"},     {"left", "Left"},         {"right", "Right"},
        {"plus", "="},        {"minus", "-"},
      };
      for (const auto& [from, to] : kNames) {
        if (low == from) {
          return to;
        }
      }
      return {};
    }

    [[nodiscard]] bool WordStart(
      std::string_view text,
      const std::size_t at
    )
    {
      if (at == 0) {
        return true;
      }
      const unsigned char before = static_cast<unsigned char>(text[at - 1]);
      const unsigned char here = static_cast<unsigned char>(text[at]);
      return std::isalnum(before) == 0 || (std::islower(before) != 0 && std::isupper(here) != 0);
    }
  } // namespace

  std::string CanonicalChord(
    std::string_view chord
  )
  {
    chord = Trim(chord);
    if (chord.empty()) {
      return {};
    }
    bool ctrl = false;
    bool shift = false;
    bool alt = false;
    std::string key;
    std::size_t start = 0;
    while (start <= chord.size()) {
      std::size_t plus = chord.find('+', start);
      // A trailing "+" (as in "Ctrl++") is the key itself.
      if (plus == start && plus + 1 == chord.size()) {
        plus = std::string_view::npos;
      }
      const std::string_view part =
        chord.substr(start, plus == std::string_view::npos ? std::string_view::npos : plus - start);
      const std::string low = Lower(Trim(part));
      if (low == "ctrl" || low == "control") {
        ctrl = true;
      } else if (low == "shift") {
        shift = true;
      } else if (low == "alt") {
        alt = true;
      } else {
        if (!key.empty()) {
          return {};
        }
        key = low == "+" ? "=" : KeyName(part);
        if (key.empty()) {
          return {};
        }
      }
      if (plus == std::string_view::npos) {
        break;
      }
      start = plus + 1;
    }
    if (key.empty()) {
      return {};
    }
    std::string out;
    if (ctrl) {
      out += "Ctrl+";
    }
    if (shift) {
      out += "Shift+";
    }
    if (alt) {
      out += "Alt+";
    }
    return out + key;
  }

  std::vector<std::string> SplitChords(
    std::string_view keys
  )
  {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= keys.size()) {
      const std::size_t comma = keys.find(',', start);
      const std::string chord =
        CanonicalChord(keys.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start));
      if (!chord.empty() && std::find(out.begin(), out.end(), chord) == out.end()) {
        out.push_back(chord);
      }
      if (comma == std::string_view::npos) {
        break;
      }
      start = comma + 1;
    }
    return out;
  }

  std::string CanonicalKeys(
    std::string_view keys
  )
  {
    std::string out;
    for (const std::string& chord : SplitChords(keys)) {
      out += (out.empty() ? "" : ", ") + chord;
    }
    return out;
  }

  void EdCommands::Add(
    EdCommand command
  )
  {
    command.keys = CanonicalKeys(command.keys);
    for (EdCommand& existing : mCommands) {
      if (existing.id == command.id) {
        existing = std::move(command);
        return;
      }
    }
    mCommands.push_back(std::move(command));
  }

  const EdCommand* EdCommands::Find(
    std::string_view id
  ) const
  {
    for (const EdCommand& command : mCommands) {
      if (command.id == id) {
        return &command;
      }
    }
    return nullptr;
  }

  std::string EdCommands::WhyNot(
    std::string_view id
  ) const
  {
    const EdCommand* const command = Find(id);
    if (command == nullptr) {
      return "no such command";
    }
    return command->why ? command->why() : std::string();
  }

  bool EdCommands::Checked(
    std::string_view id
  ) const
  {
    const EdCommand* const command = Find(id);
    return command != nullptr && command->checked && command->checked();
  }

  bool EdCommands::Run(
    std::string_view id
  )
  {
    const EdCommand* const command = Find(id);
    if (command == nullptr || !WhyNot(id).empty() || !command->run) {
      return false;
    }
    // A copy: the action may add or replace commands.
    const std::function<void()> run = command->run;
    run();
    return true;
  }

  const EdCommand* EdCommands::ForChord(
    std::string_view chord
  ) const
  {
    const std::string wanted = CanonicalChord(chord);
    if (wanted.empty()) {
      return nullptr;
    }
    for (const EdCommand& command : mCommands) {
      for (const std::string& own : SplitChords(command.keys)) {
        if (own == wanted) {
          return &command;
        }
      }
    }
    return nullptr;
  }

  std::vector<std::pair<std::string, std::string>> EdCommands::Clashes() const
  {
    std::vector<std::pair<std::string, std::string>> out;
    for (std::size_t a = 0; a < mCommands.size(); ++a) {
      const std::vector<std::string> mine = SplitChords(mCommands[a].keys);
      for (std::size_t b = a + 1; b < mCommands.size(); ++b) {
        for (const std::string& theirs : SplitChords(mCommands[b].keys)) {
          if (std::find(mine.begin(), mine.end(), theirs) != mine.end()) {
            out.emplace_back(mCommands[a].id, mCommands[b].id);
          }
        }
      }
    }
    return out;
  }

  bool EdCommands::SetKeys(
    std::string_view id,
    std::string_view keys
  )
  {
    for (EdCommand& command : mCommands) {
      if (command.id == id) {
        command.keys = CanonicalKeys(keys);
        return true;
      }
    }
    return false;
  }

  bool EdCommands::SetTitle(
    std::string_view id,
    std::string_view title
  )
  {
    for (EdCommand& command : mCommands) {
      if (command.id == id) {
        if (command.title != title) {
          command.title = std::string(title);
        }
        return true;
      }
    }
    return false;
  }

  int FuzzyScore(
    std::string_view query,
    std::string_view text
  )
  {
    const std::string q = Lower(Trim(query));
    if (q.empty()) {
      return 1;
    }
    const std::string t = Lower(text);
    int score = 0;
    std::size_t at = 0;
    std::size_t last = std::string::npos;
    for (const char c : q) {
      if (c == ' ') {
        continue;
      }
      const std::size_t found = t.find(c, at);
      if (found == std::string::npos) {
        return 0;
      }
      score += 1;
      if (WordStart(text, found)) {
        score += 5;
      }
      if (last != std::string::npos && found == last + 1) {
        score += 3;
      }
      last = found;
      at = found + 1;
    }
    if (t.rfind(q, 0) == 0) {
      score += 20;
    } else if (t.find(q) != std::string::npos) {
      score += 10;
    }
    return score;
  }

  std::string MenuLabelText(
    std::string_view label
  )
  {
    std::string out;
    for (std::size_t i = 0; i < label.size(); ++i) {
      if (label[i] == '&' && i + 1 < label.size() && label[i + 1] != '&') {
        continue;
      }
      out += label[i];
    }
    return out;
  }

  char MenuAccessKey(
    std::string_view label
  )
  {
    const std::size_t amp = label.find('&');
    if (amp == std::string_view::npos || amp + 1 >= label.size()) {
      return 0;
    }
    return static_cast<char>(std::toupper(static_cast<unsigned char>(label[amp + 1])));
  }
} // namespace faf::editor
