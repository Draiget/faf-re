#include "editor/ui/EdKeymap.h"

#include <algorithm>
#include <cctype>

#include "editor/ui/EdCommands.h"

namespace faf::editor
{
  namespace
  {
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

    [[nodiscard]] std::string Join(
      const std::vector<std::string>& chords
    )
    {
      std::string out;
      for (const std::string& chord : chords) {
        out += (out.empty() ? "" : ", ") + chord;
      }
      return out;
    }

    /** The key of a canonical chord, after its modifiers. */
    [[nodiscard]] std::string_view KeyOf(
      std::string_view chord
    )
    {
      for (const std::string_view modifier : {"Ctrl+", "Shift+", "Alt+"}) {
        if (chord.substr(0, modifier.size()) == modifier) {
          chord.remove_prefix(modifier.size());
        }
      }
      return chord;
    }
  } // namespace

  EdKeyDefaults KeyDefaults(
    const EdCommands& commands
  )
  {
    EdKeyDefaults out;
    for (const EdCommand& command : commands.All()) {
      out[command.id] = command.keys;
    }
    return out;
  }

  std::vector<std::string> ReadKeymap(
    EdCommands& commands,
    std::string_view text
  )
  {
    std::vector<std::string> problems;
    int lineNumber = 0;
    while (!text.empty()) {
      const std::size_t end = text.find('\n');
      std::string_view line = Trim(text.substr(0, end));
      text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
      ++lineNumber;
      if (line.empty() || line.front() == ';' || line.front() == '#' || line.front() == '[') {
        continue;
      }
      const std::size_t equals = line.find('=');
      if (equals == std::string_view::npos) {
        problems.push_back("line " + std::to_string(lineNumber) + ": no '=' in \"" + std::string(line) + "\"");
        continue;
      }
      const std::string id(Trim(line.substr(0, equals)));
      const std::string_view keys = Trim(line.substr(equals + 1));
      if (commands.Find(id) == nullptr) {
        problems.push_back("line " + std::to_string(lineNumber) + ": no command " + id);
        continue;
      }
      // Each chord it can't read is said, and the others kept.
      std::size_t start = 0;
      while (start <= keys.size()) {
        const std::size_t comma = keys.find(',', start);
        const std::string_view chord =
          Trim(keys.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start));
        if (!chord.empty() && CanonicalChord(chord).empty()) {
          problems.push_back(
            "line " + std::to_string(lineNumber) + ": " + id + ": can't read the key \"" + std::string(chord) + "\""
          );
        }
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1;
      }
      (void)commands.SetKeys(id, keys);
    }
    return problems;
  }

  std::string WriteKeymap(
    const EdCommands& commands,
    const EdKeyDefaults& defaults
  )
  {
    std::string out = "; The editor's keys you changed (Settings > Keys). <command>=<keys>, an empty value for none.\n"
                      "[Keys]\n";
    for (const EdCommand& command : commands.All()) {
      const auto found = defaults.find(command.id);
      const std::string& before = found == defaults.end() ? std::string() : found->second;
      if (command.keys != before) {
        out += command.id + "=" + command.keys + "\n";
      }
    }
    return out;
  }

  std::string KeySlot(
    std::string_view keys,
    const int slot
  )
  {
    const std::vector<std::string> chords = SplitChords(keys);
    return slot >= 0 && static_cast<std::size_t>(slot) < chords.size() ? chords[static_cast<std::size_t>(slot)]
                                                                       : std::string();
  }

  std::string WithKeySlot(
    std::string_view keys,
    const int slot,
    std::string_view chord
  )
  {
    std::vector<std::string> chords = SplitChords(keys);
    const std::string wanted = CanonicalChord(chord);
    if (slot < 0 || slot >= kKeySlots) {
      return Join(chords);
    }
    // The chord leaves wherever else it was, so it's in one slot.
    if (!wanted.empty()) {
      chords.erase(std::remove(chords.begin(), chords.end(), wanted), chords.end());
    }
    const std::size_t at = static_cast<std::size_t>(slot);
    if (wanted.empty()) {
      if (at < chords.size()) {
        chords.erase(chords.begin() + static_cast<std::ptrdiff_t>(at));
      }
    } else if (at < chords.size()) {
      chords[at] = wanted;
    } else {
      chords.push_back(wanted);
    }
    return Join(chords);
  }

  std::string ChordOf(
    std::string_view key,
    const bool ctrl,
    const bool shift,
    const bool alt
  )
  {
    if (key.empty()) {
      return {};
    }
    std::string chord;
    if (ctrl) {
      chord += "Ctrl+";
    }
    if (shift) {
      chord += "Shift+";
    }
    if (alt) {
      chord += "Alt+";
    }
    chord += key;
    return CanonicalChord(chord);
  }

  std::string VirtualKeyName(
    const unsigned virtualKey
  )
  {
    if ((virtualKey >= 'A' && virtualKey <= 'Z') || (virtualKey >= '0' && virtualKey <= '9')) {
      return std::string(1, static_cast<char>(virtualKey));
    }
    if (virtualKey >= 0x70 && virtualKey <= 0x87) { // VK_F1 to VK_F24
      return "F" + std::to_string(virtualKey - 0x70 + 1);
    }
    static const std::pair<unsigned, const char*> kNames[] = {
      {0x08, "Backspace"}, {0x09, "Tab"},      {0x0D, "Enter"}, {0x1B, "Escape"}, {0x20, "Space"},
      {0x21, "PageUp"},    {0x22, "PageDown"}, {0x23, "End"},   {0x24, "Home"},   {0x25, "Left"},
      {0x26, "Up"},        {0x27, "Right"},    {0x28, "Down"},  {0x2D, "Insert"}, {0x2E, "Delete"},
      {0xBA, ";"},         {0xBB, "="},        {0xBD, "-"},     {0xBE, "."},      {0xBF, "/"},
      {0xC0, "`"},         {0xDB, "["},        {0xDC, "\\"},    {0xDD, "]"},      {0xDE, "'"},
    };
    for (const auto& [code, name] : kNames) {
      if (code == virtualKey) {
        return name;
      }
    }
    return {};
  }

  bool PanelsKeepChord(
    std::string_view chord,
    const bool typing
  )
  {
    const std::string canonical = CanonicalChord(chord);
    if (canonical.empty()) {
      return true;
    }
    const std::string_view key = KeyOf(canonical);
    const bool ctrl = canonical.rfind("Ctrl+", 0) == 0;
    const bool alt = canonical.find("Alt+") != std::string::npos;
    const bool shift = canonical.find("Shift+") != std::string::npos;
    const bool functionKey = key.size() >= 2 && key[0] == 'F' && std::isdigit(static_cast<unsigned char>(key[1])) != 0;
    if (!ctrl && !alt && !shift) {
      for (const std::string_view nav : {"Up", "Down", "Left", "Right", "Space", "Enter", "Tab", "Escape"}) {
        if (key == nav) {
          return true;
        }
      }
    }
    if (!typing) {
      return false;
    }
    if (!ctrl && !alt) {
      return !functionKey && key != "Escape";
    }
    if (ctrl && !alt) {
      for (const std::string_view edit :
           {"A", "C", "V", "X", "Z", "Y", "Left", "Right", "Home", "End", "Backspace", "Delete"}) {
        if (key == edit) {
          return true;
        }
      }
    }
    return false;
  }

  bool RunsOverGame(
    std::string_view commandId
  )
  {
    return commandId == "play.toggle" || commandId == "play.editorview";
  }
} // namespace faf::editor
