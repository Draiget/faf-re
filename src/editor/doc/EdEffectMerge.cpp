#include "editor/doc/EdEffectMerge.h"

#include "editor/doc/EdModProject.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <utility>
#include <vector>

namespace faf::editor
{
  namespace
  {
    /**
     * A written blueprint's top-level entries in order: name -> its text (the entry's lines). An entry starts on a line
     * of one indent (a tab or four spaces) and a name; the lines after it that are indented deeper, or close it, are
     * its block.
     */
    std::vector<std::pair<std::string, std::string>> Entries(
      const std::string& text
    )
    {
      std::vector<std::pair<std::string, std::string>> out;
      std::size_t at = text.find('\n');
      while (at != std::string::npos && at + 1 < text.size()) {
        const std::size_t start = at + 1;
        at = text.find('\n', start);
        const std::string line = text.substr(start, at == std::string::npos ? std::string::npos : at - start + 1);
        std::size_t indent = 0;
        if (line.rfind("\t", 0) == 0) {
          indent = 1;
        } else if (line.rfind("    ", 0) == 0) {
          indent = 4;
        }
        const bool top =
          indent > 0 && line.size() > indent && line[indent] != '\t' && line[indent] != ' ' && line[indent] != '}';
        if (top) {
          const std::size_t eq = line.find(" =");
          out.emplace_back(line.substr(indent, eq == std::string::npos ? std::string::npos : eq - indent), line);
        } else if (!out.empty() && indent > 0) {
          out.back().second += line;
        }
      }
      return out;
    }

    std::string Quote(
      const std::string& text
    )
    {
      std::string out = "'";
      for (const char c : text) {
        if (c == '\'' || c == '\\') {
          out += '\\';
        }
        out += c;
      }
      return out + "'";
    }

    /** The changed entries as a merge, or the edited text whole as a replacement. */
    EffectModBlueprint Build(
      const std::string& kind,
      const std::string& gameText,
      const std::string& editedText,
      const std::string& source,
      const std::set<std::string>& ignore,
      std::string why
    )
    {
      EffectModBlueprint out;
      const auto game = Entries(gameText);
      const auto edited = Entries(editedText);
      std::vector<std::string> changed;
      for (const auto& [name, text] : edited) {
        if (ignore.count(name) != 0) {
          continue;
        }
        const auto it = std::find_if(game.begin(), game.end(), [&](const auto& g) {
          return g.first == name;
        });
        if (it == game.end() || it->second != text) {
          changed.push_back(text);
        }
      }
      if (why.empty()) {
        for (const auto& [name, text] : game) {
          if (ignore.count(name) == 0 && std::none_of(edited.begin(), edited.end(), [&](const auto& e) {
            return e.first == name;
          })) {
            why = name + " was taken out (a merge can't take a key away)";
            break;
          }
        }
      }
      out.changed = static_cast<int>(changed.size());
      if (changed.empty() && why.empty()) {
        return out;
      }
      const std::string header = kind + " {\n";
      if (!why.empty()) {
        // The edited blueprint whole, under the game's file.
        out.replaced = true;
        out.why = why;
        std::string body = editedText;
        const std::size_t open = body.find(header);
        if (open != std::string::npos) {
          body.insert(open + header.size(), "    Source = " + Quote(source) + ",\n");
        }
        out.text = std::string(kModProjectMark) + "\n-- replaces the game's " + source + ": " + why + "\n" + body;
        return out;
      }
      out.text =
        std::string(kModProjectMark) + "\n" + header + "    Merge = true,\n    Source = " + Quote(source) + ",\n";
      for (const std::string& text : changed) {
        out.text += text;
      }
      out.text += "}\n";
      return out;
    }
  } // namespace

  EffectModBlueprint EmitterModBlueprint(
    const EmitterBlueprint& game,
    const EmitterBlueprint& edited,
    const std::string& source
  )
  {
    // A curve with fewer keys than the game's would keep the game's last keys in a merge.
    std::string why;
    for (int c = 0; c < kEmitterCurveCount && why.empty(); ++c) {
      const auto& before = game.curves[static_cast<std::size_t>(c)].keys;
      const auto& after = edited.curves[static_cast<std::size_t>(c)].keys;
      if (after.size() < before.size()) {
        why = std::string(CurveInfo(c).name) + " has " + std::to_string(after.size()) + " keys, the game's " +
          std::to_string(before.size()) + " (a merge can't take keys away)";
      }
    }
    return Build("EmitterBlueprint", WriteEmitter(game), WriteEmitter(edited), source, {"BlueprintId"}, why);
  }

  EffectModBlueprint FlatModBlueprint(
    const FlatBlueprint& game,
    const FlatBlueprint& edited,
    const std::string& source
  )
  {
    return Build(edited.kind, WriteFlatBlueprint(game), WriteFlatBlueprint(edited), source, {"BlueprintId"}, {});
  }

  std::string EffectModFile(
    const std::string& source
  )
  {
    std::string path = source;
    std::replace(path.begin(), path.end(), '\\', '/');
    while (!path.empty() && path.front() == '/') {
      path.erase(path.begin());
    }
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    // Only below effects/, no way up.
    if (lower.rfind("effects/", 0) != 0 || path.find("..") != std::string::npos) {
      const std::size_t slash = path.find_last_of('/');
      return "effects/emitters/" + (slash == std::string::npos ? path : path.substr(slash + 1));
    }
    return path;
  }
} // namespace faf::editor
