#include "editor/doc/EdUnits.h"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace faf::editor
{
  bool SaveUnit::operator==(const SaveUnit& other) const
  {
    return name == other.name && type == other.type && orders == other.orders && platoon == other.platoon &&
           std::memcmp(position, other.position, sizeof(position)) == 0 &&
           std::memcmp(orientation, other.orientation, sizeof(orientation)) == 0;
  }

  bool UnitGroup::operator==(const UnitGroup& other) const
  {
    if (name != other.name || orders != other.orders || platoon != other.platoon || groups != other.groups || units != other.units ||
        order.size() != other.order.size()) {
      return false;
    }
    for (std::size_t i = 0; i < order.size(); ++i) {
      if (order[i].group != other.order[i].group || order[i].unit != other.order[i].unit) {
        return false;
      }
    }
    return true;
  }

  namespace
  {
    /** A small reader over the save's Lua: names, ['strings'], 'strings', numbers and punctuation. */
    struct Reader
    {
      const std::string& text;
      std::size_t at = 0;
      std::string error;

      void Skip()
      {
        for (;;) {
          while (at < text.size() && std::isspace(static_cast<unsigned char>(text[at])) != 0) {
            ++at;
          }
          if (text.compare(at, 2, "--") == 0) {
            const std::size_t end = text.find('\n', at);
            at = end == std::string::npos ? text.size() : end;
            continue;
          }
          return;
        }
      }

      bool Expect(const char c)
      {
        Skip();
        if (at < text.size() && text[at] == c) {
          ++at;
          return true;
        }
        error = std::string("expected '") + c + "' at " + std::to_string(at);
        return false;
      }

      bool Peek(const char c)
      {
        Skip();
        return at < text.size() && text[at] == c;
      }

      bool Name(std::string& out)
      {
        Skip();
        const std::size_t start = at;
        while (at < text.size() && (std::isalnum(static_cast<unsigned char>(text[at])) != 0 || text[at] == '_')) {
          ++at;
        }
        out = text.substr(start, at - start);
        if (out.empty()) {
          error = "expected a name at " + std::to_string(at);
          return false;
        }
        return true;
      }

      bool String(std::string& out)
      {
        Skip();
        if (at >= text.size() || (text[at] != '\'' && text[at] != '"')) {
          error = "expected a string at " + std::to_string(at);
          return false;
        }
        const char quote = text[at++];
        out.clear();
        while (at < text.size() && text[at] != quote) {
          if (text[at] == '\\' && at + 1 < text.size()) {
            ++at;
          }
          out += text[at++];
        }
        return Expect(quote);
      }

      /** `name` or `['name']`. */
      bool Key(std::string& out)
      {
        if (Peek('[')) {
          ++at;
          return String(out) && Expect(']');
        }
        return Name(out);
      }

      bool Number(float& out)
      {
        Skip();
        char* end = nullptr;
        out = std::strtof(text.c_str() + at, &end);
        if (end == text.c_str() + at) {
          error = "expected a number at " + std::to_string(at);
          return false;
        }
        at = static_cast<std::size_t>(end - text.c_str());
        return true;
      }

      bool Vector(float (&out)[3])
      {
        if (!Expect('{')) {
          return false;
        }
        for (int i = 0; i < 3; ++i) {
          if (!Number(out[i])) {
            return false;
          }
          if (Peek(',')) {
            ++at;
          }
        }
        return Expect('}');
      }

      void Comma()
      {
        if (Peek(',')) {
          ++at;
        }
      }
    };

    bool ReadUnit(Reader& reader, SaveUnit& unit)
    {
      if (!reader.Expect('{')) {
        return false;
      }
      while (!reader.Peek('}')) {
        std::string key;
        if (!reader.Key(key) || !reader.Expect('=')) {
          return false;
        }
        bool ok = true;
        if (key == "type") {
          ok = reader.String(unit.type);
        } else if (key == "orders") {
          ok = reader.String(unit.orders);
        } else if (key == "platoon") {
          ok = reader.String(unit.platoon);
        } else if (key == "Position") {
          ok = reader.Vector(unit.position);
        } else if (key == "Orientation") {
          ok = reader.Vector(unit.orientation);
        } else {
          reader.error = "unknown unit field " + key;
          return false;
        }
        if (!ok) {
          return false;
        }
        reader.Comma();
      }
      return reader.Expect('}');
    }

    bool ReadGroup(Reader& reader, UnitGroup& group)
    {
      std::string word;
      if (!reader.Name(word) || word != "GROUP") {
        reader.error = "expected GROUP";
        return false;
      }
      if (!reader.Expect('{')) {
        return false;
      }
      while (!reader.Peek('}')) {
        std::string key;
        if (!reader.Key(key) || !reader.Expect('=')) {
          return false;
        }
        if (key == "orders") {
          if (!reader.String(group.orders)) {
            return false;
          }
        } else if (key == "platoon") {
          if (!reader.String(group.platoon)) {
            return false;
          }
        } else if (key == "Units") {
          if (!reader.Expect('{')) {
            return false;
          }
          while (!reader.Peek('}')) {
            std::string name;
            if (!reader.Key(name) || !reader.Expect('=')) {
              return false;
            }
            reader.Skip();
            if (reader.text.compare(reader.at, 5, "GROUP") == 0) {
              UnitGroup child;
              child.name = name;
              if (!ReadGroup(reader, child)) {
                return false;
              }
              group.order.push_back({static_cast<int>(group.groups.size()), -1});
              group.groups.push_back(std::move(child));
            } else {
              SaveUnit unit;
              unit.name = name;
              if (!ReadUnit(reader, unit)) {
                return false;
              }
              group.order.push_back({-1, static_cast<int>(group.units.size())});
              group.units.push_back(std::move(unit));
            }
            reader.Comma();
          }
          if (!reader.Expect('}')) {
            return false;
          }
        } else {
          reader.error = "unknown group field " + key;
          return false;
        }
        reader.Comma();
      }
      return reader.Expect('}');
    }

    std::string Quoted(const std::string& text)
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

    std::string Vector(const float (&value)[3])
    {
      // Six decimals, a half rounded away from zero as the game's writer did (23.6328125 is 23.632813; printf's own
      // rounding gives 23.632812).
      const auto six = [](const float v) { return std::round(static_cast<double>(v) * 1e6) / 1e6; };
      char text[96];
      (void)std::snprintf(text, sizeof(text), "{ %f, %f, %f }", six(value[0]), six(value[1]), six(value[2]));
      return text;
    }

    void WriteGroup(const UnitGroup& group, const int indent, const std::string& nl, std::string& out)
    {
      const std::string inner(static_cast<std::size_t>(indent + 4), ' ');
      const std::string member(static_cast<std::size_t>(indent + 8), ' ');
      out += "GROUP {" + nl;
      out += inner + "orders = " + Quoted(group.orders) + "," + nl;
      out += inner + "platoon = " + Quoted(group.platoon) + "," + nl;
      out += inner + "Units = {" + nl;
      for (const UnitGroup::Member& entry : group.order) {
        if (entry.group >= 0) {
          const UnitGroup& child = group.groups[static_cast<std::size_t>(entry.group)];
          out += member + "[" + Quoted(child.name) + "] = ";
          WriteGroup(child, indent + 8, nl, out);
          out += "," + nl;
        } else {
          const SaveUnit& unit = group.units[static_cast<std::size_t>(entry.unit)];
          const std::string field(static_cast<std::size_t>(indent + 12), ' ');
          out += member + "[" + Quoted(unit.name) + "] = {" + nl;
          out += field + "type = " + Quoted(unit.type) + "," + nl;
          out += field + "orders = " + Quoted(unit.orders) + "," + nl;
          out += field + "platoon = " + Quoted(unit.platoon) + "," + nl;
          out += field + "Position = " + Vector(unit.position) + "," + nl;
          out += field + "Orientation = " + Vector(unit.orientation) + "," + nl;
          out += member + "}," + nl;
        }
      }
      out += inner + "}," + nl;
      out += std::string(static_cast<std::size_t>(indent), ' ') + "}";
    }

    int Highest(const UnitGroup& group)
    {
      int highest = 0;
      for (const SaveUnit& unit : group.units) {
        if (unit.name.rfind("UNIT_", 0) == 0) {
          highest = std::max(highest, std::atoi(unit.name.c_str() + 5));
        }
      }
      for (const UnitGroup& child : group.groups) {
        highest = std::max(highest, Highest(child));
      }
      return highest;
    }
  } // namespace

  bool ParseUnitGroup(const std::string& text, UnitGroup& group, std::string& error)
  {
    Reader reader{text, 0, {}};
    group = UnitGroup{};
    if (!ReadGroup(reader, group)) {
      error = reader.error;
      return false;
    }
    group.newline = text.find("\r\n") != std::string::npos ? "\r\n" : "\n";
    return true;
  }

  std::string FormatUnitGroup(const UnitGroup& group, const int indent)
  {
    std::string out;
    WriteGroup(group, indent, group.newline, out);
    return out;
  }

  void CollectUnits(const UnitGroup& group, std::vector<const SaveUnit*>& units)
  {
    for (const UnitGroup::Member& entry : group.order) {
      if (entry.group >= 0) {
        CollectUnits(group.groups[static_cast<std::size_t>(entry.group)], units);
      } else {
        units.push_back(&group.units[static_cast<std::size_t>(entry.unit)]);
      }
    }
  }

  int HighestUnitNumber(const UnitGroup& group)
  {
    return Highest(group);
  }

  SaveUnit* FindUnit(UnitGroup& group, const std::string& name)
  {
    for (SaveUnit& unit : group.units) {
      if (unit.name == name) {
        return &unit;
      }
    }
    for (UnitGroup& child : group.groups) {
      if (SaveUnit* const found = FindUnit(child, name); found != nullptr) {
        return found;
      }
    }
    return nullptr;
  }

  bool RemoveUnit(UnitGroup& group, const std::string& name)
  {
    for (std::size_t i = 0; i < group.units.size(); ++i) {
      if (group.units[i].name != name) {
        continue;
      }
      const int removed = static_cast<int>(i);
      group.units.erase(group.units.begin() + static_cast<std::ptrdiff_t>(i));
      // Its place in the order goes, and the units after it move down one.
      group.order.erase(std::remove_if(group.order.begin(), group.order.end(),
                                       [&](const UnitGroup::Member& member) { return member.unit == removed; }),
                        group.order.end());
      for (UnitGroup::Member& member : group.order) {
        if (member.unit > removed) {
          --member.unit;
        }
      }
      return true;
    }
    for (UnitGroup& child : group.groups) {
      if (RemoveUnit(child, name)) {
        return true;
      }
    }
    return false;
  }

  void AddUnit(UnitGroup& root, SaveUnit unit)
  {
    UnitGroup* initial = nullptr;
    for (UnitGroup& child : root.groups) {
      if (child.name == "INITIAL") {
        initial = &child;
      }
    }
    if (initial == nullptr) {
      UnitGroup group;
      group.name = "INITIAL";
      group.newline = root.newline;
      root.order.push_back({static_cast<int>(root.groups.size()), -1});
      root.groups.push_back(std::move(group));
      initial = &root.groups.back();
    }
    initial->order.push_back({-1, static_cast<int>(initial->units.size())});
    initial->units.push_back(std::move(unit));
  }
} // namespace faf::editor
