#include "editor/tools/EdMissionImport.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <set>

namespace faf::editor
{
  namespace
  {
    bool IsIdStart(
      const char c
    )
    {
      return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
    }

    bool IsIdChar(
      const char c
    )
    {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    }

    bool IsSpace(
      const char c
    )
    {
      return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
    }

    std::string Trim(
      const std::string& s
    )
    {
      std::size_t a = 0;
      std::size_t b = s.size();
      while (a < b && IsSpace(s[a])) {
        ++a;
      }
      while (b > a && IsSpace(s[b - 1])) {
        --b;
      }
      return s.substr(a, b - a);
    }

    std::string Blank(
      const std::string& s
    )
    {
      std::string out = s;
      for (char& c : out) {
        if (c != '\n') {
          c = ' ';
        }
      }
      return out;
    }

    std::string Unescape(
      const std::string& s
    )
    {
      std::string out;
      for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
          const char c = s[++i];
          out += c == 'n' ? '\n' : c == 't' ? '\t' : c;
        } else {
          out += s[i];
        }
      }
      return out;
    }

    /** At `at` (a '['): the end (inclusive) of `[=*[`, its level, or npos. */
    std::size_t LongOpen(
      const std::string& t,
      const std::size_t at,
      std::size_t& level
    )
    {
      if (at >= t.size() || t[at] != '[') {
        return std::string::npos;
      }
      std::size_t i = at + 1;
      level = 0;
      while (i < t.size() && t[i] == '=') {
        ++level;
        ++i;
      }
      return i < t.size() && t[i] == '[' ? i : std::string::npos;
    }

    std::size_t LongClose(
      const std::string& t,
      const std::size_t from,
      const std::size_t level
    )
    {
      const std::string close = "]" + std::string(level, '=') + "]";
      const std::size_t at = t.find(close, from);
      return at == std::string::npos ? std::string::npos : at + close.size() - 1;
    }

    struct Lines
    {
      std::vector<std::size_t> newlines;
      explicit Lines(
        const std::string& text
      )
      {
        for (std::size_t i = 0; i < text.size(); ++i) {
          if (text[i] == '\n') {
            newlines.push_back(i);
          }
        }
      }
      [[nodiscard]] int Of(
        const std::size_t pos
      ) const
      {
        return static_cast<int>(std::lower_bound(newlines.begin(), newlines.end(), pos) - newlines.begin()) + 1;
      }
    };

    /** The bracket closing the one at `open` (in a masked text), or npos. */
    std::size_t CloseOf(
      const std::string& plain,
      const std::size_t open,
      const std::size_t limit = 30000
    )
    {
      int depth = 0;
      const std::size_t stop = std::min(plain.size(), open + limit + 1);
      for (std::size_t i = open; i < stop; ++i) {
        const char c = plain[i];
        if (c == '(' || c == '{' || c == '[') {
          ++depth;
        } else if (c == ')' || c == '}' || c == ']') {
          if (--depth == 0) {
            return i;
          }
        }
      }
      return std::string::npos;
    }

    /** The comma separated items in [from, to] of a masked text (inclusive positions; empty ones dropped). */
    std::vector<std::pair<std::size_t, std::size_t>> Items(
      const std::string& plain,
      const std::size_t from,
      const std::size_t to
    )
    {
      std::vector<std::pair<std::size_t, std::size_t>> items;
      if (to == std::string::npos || from > to || to >= plain.size()) {
        return items;
      }
      const auto add = [&](const std::size_t a, const std::size_t b) {
        if (b + 1 > a && b < plain.size()) {
          for (std::size_t i = a; i <= b; ++i) {
            if (!IsSpace(plain[i])) {
              items.emplace_back(a, b);
              return;
            }
          }
        }
      };
      int depth = 0;
      std::size_t start = from;
      for (std::size_t i = from; i <= to; ++i) {
        const char c = plain[i];
        if (c == '(' || c == '{' || c == '[') {
          ++depth;
        } else if (c == ')' || c == '}' || c == ']') {
          --depth;
        } else if (c == ',' && depth == 0) {
          if (i > start) {
            add(start, i - 1);
          }
          start = i + 1;
        }
      }
      if (to >= start) {
        add(start, to);
      }
      return items;
    }

    /** An item's value when it is one string literal (`literal` true), else the expression as written (80 chars). */
    std::string Literal(
      const std::string& plain,
      const std::string& code,
      const std::size_t a,
      const std::size_t b,
      bool& literal
    )
    {
      const std::string p = Trim(plain.substr(a, b - a + 1));
      const std::string c = Trim(code.substr(a, b - a + 1));
      literal = false;
      if (p.size() >= 2 && (p[0] == '"' || p[0] == '\'') && p.back() == p[0]) {
        bool blank = true;
        for (std::size_t i = 1; i + 1 < p.size(); ++i) {
          blank = blank && IsSpace(p[i]);
        }
        if (blank && c.size() >= 2) {
          literal = true;
          return Unescape(c.substr(1, c.size() - 2));
        }
      }
      std::string out;
      bool space = false;
      for (const char ch : c) {
        if (IsSpace(ch)) {
          space = true;
          continue;
        }
        if (space && !out.empty()) {
          out += ' ';
        }
        space = false;
        out += ch;
      }
      if (out.size() > 80) {
        out = out.substr(0, 77) + "...";
      }
      return out;
    }

    int NumberInName(
      const std::string& name
    )
    {
      // Mission<n>
      for (std::size_t at = name.find("Mission"); at != std::string::npos; at = name.find("Mission", at + 1)) {
        std::size_t i = at + 7;
        std::size_t j = i;
        while (j < name.size() && std::isdigit(static_cast<unsigned char>(name[j]))) {
          ++j;
        }
        if (j > i) {
          return std::atoi(name.substr(i, j - i).c_str());
        }
      }
      // ^M<n>[upper _ digit]
      if (name.size() > 2 && name[0] == 'M' && std::isdigit(static_cast<unsigned char>(name[1]))) {
        std::size_t j = 1;
        while (j < name.size() && std::isdigit(static_cast<unsigned char>(name[j]))) {
          ++j;
        }
        if (j < name.size() && (std::isupper(static_cast<unsigned char>(name[j])) || name[j] == '_')) {
          return std::atoi(name.substr(1, j - 1).c_str());
        }
      }
      // <lower>M<n><upper>
      for (std::size_t i = 1; i + 2 < name.size(); ++i) {
        if (
          name[i] == 'M' && std::islower(static_cast<unsigned char>(name[i - 1])) &&
          std::isdigit(static_cast<unsigned char>(name[i + 1]))
        ) {
          std::size_t j = i + 1;
          while (j < name.size() && std::isdigit(static_cast<unsigned char>(name[j]))) {
            ++j;
          }
          if (j < name.size() && std::isupper(static_cast<unsigned char>(name[j]))) {
            return std::atoi(name.substr(i + 1, j - i - 1).c_str());
          }
        }
      }
      // ^Stage<n>
      if (name.starts_with("Stage")) {
        std::size_t j = 5;
        while (j < name.size() && std::isdigit(static_cast<unsigned char>(name[j]))) {
          ++j;
        }
        if (j > 5) {
          return std::atoi(name.substr(5, j - 5).c_str());
        }
      }
      return -1;
    }

    bool IsAiPath(
      std::string path
    )
    {
      std::transform(path.begin(), path.end(), path.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return (path.size() >= 6 && path.ends_with("ai.lua")) || path.contains("/opai/") || path.contains("basemanager");
    }

    bool AllWord(
      const std::string& s,
      const std::size_t from
    )
    {
      if (from >= s.size()) {
        return false;
      }
      for (std::size_t i = from; i < s.size(); ++i) {
        if (!IsIdChar(s[i])) {
          return false;
        }
      }
      return true;
    }

    std::string ObjectiveCall(
      const std::string& callee,
      const std::string& last
    )
    {
      if (callee.starts_with("Objectives.") && AllWord(callee, 11)) {
        return last;
      }
      if (callee.starts_with("ScenarioFramework.Objectives.") && AllWord(callee, 29)) {
        return last;
      }
      if (callee.starts_with("ScenarioFramework.") && AllWord(callee, 18) && last.contains("Objective")) {
        return last;
      }
      return {};
    }

    bool Letters(
      const std::string& s,
      const std::size_t from,
      const std::size_t to
    )
    {
      for (std::size_t i = from; i < to; ++i) {
        if (std::isalpha(static_cast<unsigned char>(s[i])) == 0) {
          return false;
        }
      }
      return true;
    }

    bool TriggerName(
      const std::string& last
    )
    {
      const auto ends = [&last](const char* suffix) {
        const std::size_t n = std::char_traits<char>::length(suffix);
        return last.size() >= n && last.compare(last.size() - n, n, suffix) == 0;
      };
      if (last.starts_with("Create") && ends("Trigger")) {
        return Letters(last, 6, last.size() - 7);
      }
      if (last.starts_with("Add") && ends("Callback")) {
        return Letters(last, 3, last.size() - 8);
      }
      if (last.starts_with("Add") && ends("Taunt")) {
        return Letters(last, 3, last.size() - 5);
      }
      return false;
    }

    const std::set<std::string>& PlatoonCalls()
    {
      static const std::set<std::string> kCalls = {
        "CreateArmyGroupAsPlatoon",
        "CreateArmyGroupAsPlatoonVeteran",
        "CreatePlatoon",
        "PlatoonPatrolChain",
        "PlatoonMoveChain",
        "PlatoonAttackChain",
        "PlatoonPatrolRoute",
        "PlatoonMoveRoute",
        "PlatoonAttackRoute",
        "GroupPatrolChain",
        "GroupMoveChain",
        "GroupAttackChain",
        "GroupPatrolRoute",
        "MakePlatoon",
        "AssignUnitsToPlatoon",
        "ForkAIThread",
        "SetPlatoonAI",
        "DisbandPlatoon",
      };
      return kCalls;
    }

    const std::set<std::string>& Keywords()
    {
      static const std::set<std::string> kWords = {
        "and",   "break", "do",  "else", "elseif", "end",    "false", "for",  "function", "if",    "in",
        "local", "nil",   "not", "or",   "repeat", "return", "then",  "true", "until",    "while",
      };
      return kWords;
    }

    /** After `at`: spaces, then `c`? The position after it, or npos. */
    std::size_t After(
      const std::string& s,
      std::size_t at,
      const char c
    )
    {
      while (at < s.size() && IsSpace(s[at])) {
        ++at;
      }
      return at < s.size() && s[at] == c ? at + 1 : std::string::npos;
    }

    /** Spaces then a number: its value, or -1. */
    int NumberAt(
      const std::string& s,
      std::size_t at
    )
    {
      while (at < s.size() && IsSpace(s[at])) {
        ++at;
      }
      std::size_t j = at;
      while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) {
        ++j;
      }
      return j > at ? std::atoi(s.substr(at, j - at).c_str()) : -1;
    }
  } // namespace

  void MaskLua(
    const std::string& text,
    std::string& plain,
    std::string& code
  )
  {
    plain.clear();
    code.clear();
    const std::size_t len = text.size();
    std::size_t copied = 0;
    std::size_t i = 0;
    while (i < len) {
      const std::size_t s = text.find_first_of("-\"'[", i);
      if (s == std::string::npos) {
        break;
      }
      const char ch = text[s];
      std::size_t stop = std::string::npos;
      int kind = 0; // 1 comment, 2 long string, 3 string
      if (ch == '-') {
        if (s + 1 < len && text[s + 1] == '-') {
          kind = 1;
          std::size_t level = 0;
          if (const std::size_t opened = LongOpen(text, s + 2, level); opened != std::string::npos) {
            const std::size_t closed = LongClose(text, opened + 1, level);
            stop = closed == std::string::npos ? len - 1 : closed;
          } else {
            const std::size_t nl = text.find('\n', s + 2);
            stop = nl == std::string::npos ? len - 1 : nl - 1;
          }
        }
      } else if (ch == '[') {
        std::size_t level = 0;
        if (const std::size_t opened = LongOpen(text, s, level); opened != std::string::npos) {
          kind = 2;
          const std::size_t closed = LongClose(text, opened + 1, level);
          stop = closed == std::string::npos ? len - 1 : closed;
        }
      } else {
        // A quoted string ends at its closing quote, or at the end of the line when it isn't closed.
        kind = 3;
        stop = len - 1;
        std::size_t k = s + 1;
        while (k < len) {
          const char c = text[k];
          if (c == '\\') {
            k += 2;
          } else if (c == '\n') {
            stop = k - 1;
            break;
          } else if (c == ch) {
            stop = k;
            break;
          } else {
            ++k;
          }
        }
      }
      if (kind == 0) {
        i = s + 1;
        continue;
      }
      if (s > copied) {
        plain += text.substr(copied, s - copied);
        code += text.substr(copied, s - copied);
      }
      const std::string region = text.substr(s, stop + 1 - s);
      if (kind == 1) {
        plain += Blank(region);
        code += Blank(region);
      } else if (kind == 2) {
        plain += Blank(region);
        code += region;
      } else {
        if (region.size() >= 2 && region.back() == ch) {
          plain += ch + Blank(region.substr(1, region.size() - 2)) + ch;
        } else {
          plain += Blank(region);
        }
        code += region;
      }
      copied = stop + 1;
      i = stop + 1;
    }
    if (copied < len) {
      plain += text.substr(copied);
      code += text.substr(copied);
    }
  }

  MissionOutline ParseMissionScript(
    const std::string& text
  )
  {
    std::string plain;
    std::string code;
    MaskLua(text, plain, code);
    const Lines lines(text);
    MissionOutline o;
    const std::size_t len = plain.size();
    o.lineCount = lines.Of(len);
    struct Frame
    {
      bool fn = false;
      std::string name;
      std::string owner;
      int line = 0;
    };
    struct Assignment
    {
      int n = 0;
      int line = 0;
      std::string fn;
    };
    std::vector<Frame> frames;
    std::vector<Assignment> assignments;
    std::map<int, int> referenced;
    std::map<std::string, std::set<std::string>> refs;
    std::set<std::string> aiAlias;
    std::map<std::string, std::size_t> helperAt;
    std::map<std::string, std::size_t> dialogueAt;
    std::map<std::string, std::size_t> optionAt;
    const auto owner = [&frames]() -> std::string {
      return frames.empty() ? std::string() : frames.back().owner;
    };
    // `name = ` just before position s.
    const auto target = [&plain](const std::size_t s) -> std::string {
      std::size_t i = s;
      while (i > 0 && IsSpace(plain[i - 1])) {
        --i;
      }
      if (i == 0 || plain[i - 1] != '=') {
        return {};
      }
      --i;
      while (i > 0 && IsSpace(plain[i - 1])) {
        --i;
      }
      const std::size_t end = i;
      while (i > 0 && (IsIdChar(plain[i - 1]) || plain[i - 1] == '.')) {
        --i;
      }
      if (i == end || !IsIdStart(plain[i]) || s - i > 100) {
        return {};
      }
      return plain.substr(i, end - i);
    };
    const auto helper = [&](const std::string& name, const char* kind, const int line, const std::string& fn) {
      if (const auto it = helperAt.find(name); it != helperAt.end()) {
        ++o.helpers[it->second].count;
        return;
      }
      helperAt[name] = o.helpers.size();
      o.helpers.push_back({name, kind, 1, line, fn, -1});
    };
    const auto call =
      [&](
        const std::string& callee, const std::size_t s, const std::size_t paren, const int line, const std::string& fn
      ) {
      const std::size_t close = CloseOf(plain, paren);
      const auto items = close != std::string::npos && close > paren + 1
        ? Items(plain, paren + 1, close - 1)
        : std::vector<std::pair<std::size_t, std::size_t>>{};
      std::size_t lastAt = callee.size();
      while (lastAt > 0 && IsIdChar(callee[lastAt - 1])) {
        --lastAt;
      }
      const std::string last = lastAt < callee.size() ? callee.substr(lastAt) : callee;
      std::size_t firstEnd = 0;
      while (firstEnd < callee.size() && IsIdChar(callee[firstEnd])) {
        ++firstEnd;
      }
      const std::string first = callee.substr(0, firstEnd);
      const auto arg = [&](const std::size_t n, bool& literal) -> std::string {
        literal = false;
        if (n >= items.size()) {
          return {};
        }
        return Literal(plain, code, items[n].first, items[n].second, literal);
      };
      const std::string objective = ObjectiveCall(callee, last);
      if (callee == "import") {
        bool literal = false;
        const std::string path = arg(0, literal);
        const std::string var = target(s);
        const bool ai = literal && IsAiPath(path);
        o.imports.push_back({var, literal ? path : std::string(), line, ai});
        if (ai && !var.empty()) {
          aiAlias.insert(var);
        }
      } else if (!objective.empty()) {
        ImportedObjective ob;
        ob.call = callee;
        ob.name = objective;
        ob.var = target(s);
        ob.line = line;
        ob.fn = fn;
        bool lit = false;
        if (objective == "CreateGroup") {
          ob.group = true;
          const std::string v = arg(0, lit);
          (lit ? ob.title : ob.titleExpr) = v;
        } else {
          std::string v = arg(0, lit);
          if (lit) {
            ob.otype = v;
          }
          v = arg(1, lit);
          if (lit) {
            ob.complete = v;
          }
          v = arg(2, lit);
          (lit ? ob.title : ob.titleExpr) = v;
          v = arg(3, lit);
          (lit ? ob.description : ob.descriptionExpr) = v;
        }
        o.objectives.push_back(std::move(ob));
      } else if (TriggerName(last)) {
        bool lit = false;
        std::string callback = arg(0, lit);
        if (!callback.empty() && !lit && callback.starts_with("function")) {
          callback = "(inline function)";
        }
        std::string where;
        if (const std::size_t colon = callee.rfind(':'); colon != std::string::npos) {
          where = callee.substr(0, colon);
        }
        o.triggers.push_back({last, where, callback, line, fn, -1});
      } else if (last == "Dialogue" && !items.empty()) {
        const std::string p = Trim(plain.substr(items[0].first, items[0].second - items[0].first + 1));
        bool ok = !p.empty() && IsIdStart(p[0]);
        for (const char c : p) {
          ok = ok && (IsIdChar(c) || c == '.');
        }
        if (ok) {
          if (const auto it = dialogueAt.find(p); it != dialogueAt.end()) {
            ++o.dialogueRefs[it->second].count;
          } else {
            dialogueAt[p] = o.dialogueRefs.size();
            o.dialogueRefs.push_back({p, 1, line, fn, -1});
          }
        }
      }
      if (!first.empty() && aiAlias.contains(first) && callee != first) {
        helper(callee, "ai module", line, fn);
      } else if (callee.contains("OpAI") || callee.contains("BaseManager")) {
        helper(callee, "opai", line, fn);
      } else if (PlatoonCalls().contains(last)) {
        helper(callee, "platoon", line, fn);
      }
    };
    std::size_t pos = 0;
    while (pos < len) {
      std::size_t s = pos;
      while (s < len && !IsIdStart(plain[s])) {
        ++s;
      }
      if (s >= len) {
        break;
      }
      std::size_t e = s;
      while (e < len && IsIdChar(plain[e])) {
        ++e;
      }
      const char prev = s > 0 ? plain[s - 1] : '\0';
      const std::string word = plain.substr(s, e - s);
      const bool afterDot = (prev == '.' || prev == ':') && !(s >= 2 && plain[s - 2] == '.' && plain[s - 1] == '.');
      if (std::isdigit(static_cast<unsigned char>(prev)) || afterDot) {
        pos = e;
        continue;
      }
      if (Keywords().contains(word)) {
        pos = e;
        if (word == "function") {
          std::size_t n = e;
          while (n < len && IsSpace(plain[n])) {
            ++n;
          }
          std::string fname;
          if (n < len && IsIdStart(plain[n])) {
            std::size_t ne = n;
            while (ne < len && (IsIdChar(plain[ne]) || plain[ne] == '.' || plain[ne] == ':')) {
              ++ne;
            }
            fname = plain.substr(n, ne - n);
            pos = ne;
          }
          frames.push_back({true, fname, fname.empty() ? owner() : fname, lines.Of(s)});
          if (!fname.empty()) {
            refs[fname];
          }
        } else if (word == "if" || word == "do" || word == "repeat") {
          frames.push_back({false, {}, owner(), 0});
        } else if (word == "end" || word == "until") {
          if (!frames.empty()) {
            const Frame top = frames.back();
            frames.pop_back();
            if (top.fn && !top.name.empty()) {
              ImportedFunction f;
              f.name = top.name;
              f.line = top.line;
              f.endLine = lines.Of(s);
              o.functions.push_back(std::move(f));
            }
          }
        }
        continue;
      }
      std::size_t ee = e;
      while (ee + 1 < len && (plain[ee] == '.' || plain[ee] == ':') && IsIdStart(plain[ee + 1])) {
        std::size_t k = ee + 1;
        while (k < len && IsIdChar(plain[k])) {
          ++k;
        }
        ee = k;
      }
      const std::string name = plain.substr(s, ee - s);
      const int line = lines.Of(s);
      const std::string fn = owner();
      pos = ee;
      if (const std::size_t paren = After(plain, ee, '('); paren != std::string::npos) {
        call(name, s, paren - 1, line, fn);
      }
      if (!fn.empty() && refs.contains(fn) && name.find_first_of(".:") == std::string::npos) {
        refs[fn].insert(name);
      }
      if (name == "ScenarioInfo.MissionNumber") {
        // `= N` (not `==`): a stage is entered; a comparison: the number is checked.
        std::size_t at = ee;
        while (at < len && IsSpace(plain[at])) {
          ++at;
        }
        if (at < len && plain[at] == '=' && (at + 1 >= len || plain[at + 1] != '=')) {
          if (const int n = NumberAt(plain, at + 1); n >= 0) {
            assignments.push_back({n, line, fn});
          }
        } else if (at < len && (plain[at] == '=' || plain[at] == '~' || plain[at] == '<' || plain[at] == '>')) {
          std::size_t k = at + 1;
          if (k < len && plain[k] == '=') {
            ++k;
          }
          if (const int m = NumberAt(plain, k); m >= 0 && !referenced.contains(m)) {
            referenced[m] = line;
          }
        }
      } else if (name == "Difficulty" || name == "ScenarioInfo.Options.Difficulty") {
        ++o.difficultyUses;
        if (o.difficultyLine == 0) {
          o.difficultyLine = line;
        }
        std::size_t at = ee;
        while (at < len && IsSpace(plain[at])) {
          ++at;
        }
        if (
          at < len &&
          (plain[at] == '<' || plain[at] == '>' ||
           ((plain[at] == '=' || plain[at] == '~') && at + 1 < len && plain[at + 1] == '='))
        ) {
          ++o.difficultyBranches;
        }
      }
      static const std::string kOptions = "ScenarioInfo.Options.";
      if (name.starts_with(kOptions) && AllWord(name, kOptions.size())) {
        const std::string key = name.substr(kOptions.size());
        if (key != "Difficulty") {
          if (const auto it = optionAt.find(key); it != optionAt.end()) {
            ++o.options[it->second].count;
          } else {
            optionAt[key] = o.options.size();
            o.options.push_back({key, 1, line});
          }
        }
      }
    }

    // Which stage each function belongs to: the function that sets MissionNumber, a name that carries the number,
    // then the single stage that calls it.
    std::stable_sort(o.functions.begin(), o.functions.end(), [](const ImportedFunction& a, const ImportedFunction& b) {
      return a.line < b.line;
    });
    std::map<std::string, const ImportedFunction*> byName;
    std::vector<std::string> names;
    for (const ImportedFunction& f : o.functions) {
      if (byName.emplace(f.name, &f).second) {
        names.push_back(f.name);
      }
    }
    std::sort(names.begin(), names.end());
    std::map<std::string, int> stageOf;
    std::map<std::string, std::string> howOf;
    for (const Assignment& a : assignments) {
      if (!a.fn.empty() && byName.contains(a.fn) && !stageOf.contains(a.fn)) {
        stageOf[a.fn] = a.n;
        howOf[a.fn] = "sets";
      }
    }
    for (const std::string& name : names) {
      if (!stageOf.contains(name)) {
        if (const int n = NumberInName(name); n >= 0) {
          stageOf[name] = n;
          howOf[name] = "name";
        }
      }
    }
    for (int round = 0; round < 5; ++round) {
      bool changed = false;
      for (const std::string& name : names) {
        if (stageOf.contains(name)) {
          continue;
        }
        int callers = 0;
        bool unstaged = false;
        bool many = false;
        int found = -1;
        for (const std::string& caller : names) {
          if (caller != name && refs.contains(caller) && refs[caller].contains(name)) {
            ++callers;
            const auto cs = stageOf.find(caller);
            if (cs == stageOf.end()) {
              unstaged = true;
            } else if (found >= 0 && found != cs->second) {
              many = true;
            } else {
              found = cs->second;
            }
          }
        }
        if (callers > 0 && !unstaged && !many && found >= 0) {
          stageOf[name] = found;
          howOf[name] = "called";
          changed = true;
        }
      }
      if (!changed) {
        break;
      }
    }
    // The stages: numbers set somewhere, or that an IntroMissionN / StartMissionN function belongs to.
    std::map<int, std::size_t> stageAt;
    const auto stage = [&](const int n, const std::string& fname) {
      auto it = stageAt.find(n);
      if (it == stageAt.end()) {
        stageAt[n] = o.stages.size();
        o.stages.push_back({n, "Mission " + std::to_string(n), {}, 0});
        it = stageAt.find(n);
      }
      ImportedStage& st = o.stages[it->second];
      if (!fname.empty() && st.entry.empty()) {
        st.entry = fname;
        const auto f = byName.find(fname);
        st.line = f != byName.end() ? f->second->line : 0;
      }
    };
    for (const Assignment& a : assignments) {
      stage(a.n, a.fn);
    }
    for (const std::string& name : names) {
      const auto how = howOf.find(name);
      if (
        how != howOf.end() && how->second == "name" && (name.starts_with("Intro") || name.starts_with("Start")) &&
        NumberInName(name) >= 0 && name.contains("Mission")
      ) {
        stage(stageOf[name], name);
      }
    }
    std::stable_sort(o.stages.begin(), o.stages.end(), [](const ImportedStage& a, const ImportedStage& b) {
      return a.number < b.number;
    });
    for (ImportedFunction& f : o.functions) {
      const auto st = stageOf.find(f.name);
      f.stage = st != stageOf.end() ? st->second : -1;
      const auto how = howOf.find(f.name);
      f.how = how != howOf.end() ? how->second : std::string();
      if (f.how == "sets") {
        f.role = "enters stage " + std::to_string(f.stage);
      } else if (f.name.starts_with("Intro")) {
        f.role = "intro";
      } else if (f.name.starts_with("Start")) {
        f.role = "start";
      } else if (f.how == "called") {
        f.role = "called from stage " + std::to_string(f.stage);
      } else {
        f.role = "helper";
      }
    }
    const auto stageOfFn = [&stageOf](const std::string& fn) {
      const auto it = stageOf.find(fn);
      return fn.empty() || it == stageOf.end() ? -1 : it->second;
    };
    for (ImportedObjective& r : o.objectives) {
      r.stage = stageOfFn(r.fn);
    }
    for (ImportedTrigger& r : o.triggers) {
      r.stage = stageOfFn(r.fn);
    }
    for (ImportedHelper& r : o.helpers) {
      r.stage = stageOfFn(r.fn);
    }
    for (ImportedDialogueRef& r : o.dialogueRefs) {
      r.stage = stageOfFn(r.fn);
    }
    std::set<int> numbered;
    for (const ImportedStage& st : o.stages) {
      numbered.insert(st.number);
    }
    for (const auto& [n, line] : referenced) {
      if (!numbered.contains(n)) {
        o.notes.push_back(
          "MissionNumber " + std::to_string(n) + " is checked (line " + std::to_string(line) + ") but nothing sets it"
        );
      }
    }
    std::sort(o.notes.begin(), o.notes.end());
    return o;
  }

  std::vector<ImportedStageRows> ImportedStages(
    const MissionOutline& o
  )
  {
    struct Info
    {
      int number = 0;
      std::string name;
      std::string entry;
      int line = 0;
      std::vector<const ImportedFunction*> functions;
      std::vector<const ImportedObjective*> objectives;
      std::vector<const ImportedTrigger*> triggers;
      std::vector<const ImportedHelper*> helpers;
      std::vector<const ImportedDialogueRef*> dialogueRefs;
    };
    Info setup;
    setup.name = "Script setup";
    std::vector<Info> numbered;
    for (const ImportedStage& st : o.stages) {
      Info info;
      info.number = st.number;
      info.name = st.name;
      info.entry = st.entry;
      info.line = st.line;
      numbered.push_back(std::move(info));
    }
    const auto into = [&](const int n) -> Info& {
      for (Info& info : numbered) {
        if (info.number == n && n >= 0) {
          return info;
        }
      }
      return setup;
    };
    for (const auto& f : o.functions) {
      into(f.stage).functions.push_back(&f);
    }
    for (const auto& r : o.objectives) {
      into(r.stage).objectives.push_back(&r);
    }
    for (const auto& r : o.triggers) {
      into(r.stage).triggers.push_back(&r);
    }
    for (const auto& r : o.helpers) {
      into(r.stage).helpers.push_back(&r);
    }
    for (const auto& r : o.dialogueRefs) {
      into(r.stage).dialogueRefs.push_back(&r);
    }
    const auto rowsOf = [&o](const Info& info, const bool isSetup) {
      std::vector<ImportedRow> rows;
      const auto add = [&rows](std::string text, std::string extra, const char* kind) {
        rows.push_back({std::move(text), std::move(extra), kind});
      };
      add("imported from the script: read-only (never rewritten or compiled)", "", "note");
      if (!isSetup) {
        add(
          "stage " + std::to_string(info.number) + (info.entry.empty() ? "" : " starts in " + info.entry),
          info.line > 0 ? "line " + std::to_string(info.line) : "",
          "note"
        );
      } else {
        add("what the script does outside the numbered stages", std::to_string(o.lineCount) + " lines", "note");
      }
      for (const ImportedFunction* f : info.functions) {
        const std::string other =
          f->stage >= 0 && f->stage != info.number ? "  [mission " + std::to_string(f->stage) + "]" : "";
        add(
          "function " + f->name + "  - " + f->role + other,
          "line " + std::to_string(f->line) + "-" + std::to_string(f->endLine),
          "function"
        );
      }
      for (const ImportedObjective* ob : info.objectives) {
        const std::string label =
          ob->group ? "objective group" : "objective" + (ob->otype.empty() ? "" : " (" + ob->otype + ")");
        const std::string title = !ob->title.empty() ? ob->title : !ob->titleExpr.empty() ? ob->titleExpr : "?";
        add(label + ": " + title, "line " + std::to_string(ob->line), "objective");
        std::string detail = (ob->var.empty() ? "" : ob->var + " = ") + ob->call;
        const std::string d = !ob->description.empty() ? ob->description : ob->descriptionExpr;
        if (!d.empty()) {
          detail += "  " + d;
        }
        add("    " + detail + (ob->fn.empty() ? "" : "  (in " + ob->fn + ")"), "", "detail");
      }
      for (const ImportedTrigger* t : info.triggers) {
        add(
          "trigger " + t->kind + (t->callback.empty() ? "" : ": " + t->callback) +
            (t->target.empty() ? "" : "  on " + t->target),
          "line " + std::to_string(t->line),
          "trigger"
        );
      }
      for (const ImportedHelper* h : info.helpers) {
        add(
          h->kind + ": " + h->name + (h->count > 1 ? "  x" + std::to_string(h->count) : ""),
          "line " + std::to_string(h->line),
          "ai"
        );
      }
      for (const ImportedDialogueRef* d : info.dialogueRefs) {
        add(
          "dialogue " + d->name + (d->count > 1 ? "  x" + std::to_string(d->count) : ""),
          "line " + std::to_string(d->line),
          "detail"
        );
      }
      if (isSetup) {
        for (const ImportedImport& imp : o.imports) {
          if (imp.ai) {
            add("imports " + imp.var + " = " + imp.path, "line " + std::to_string(imp.line), "ai");
          }
        }
        if (o.difficultyUses > 0) {
          add(
            "difficulty: used " + std::to_string(o.difficultyUses) + " times, " + std::to_string(o.difficultyBranches) +
              " comparisons",
            o.difficultyLine > 0 ? "line " + std::to_string(o.difficultyLine) : "",
            "detail"
          );
        }
        for (const ImportedOption& op : o.options) {
          add(
            "option ScenarioInfo.Options." + op.key + (op.count > 1 ? "  x" + std::to_string(op.count) : ""),
            "line " + std::to_string(op.line),
            "detail"
          );
        }
        for (const std::string& n : o.notes) {
          add(n, "", "note");
        }
      }
      return rows;
    };
    std::vector<ImportedStageRows> out;
    const std::size_t used = setup.functions.size() + setup.objectives.size() + setup.triggers.size() +
      setup.helpers.size() + setup.dialogueRefs.size() + o.imports.size() + o.options.size() + o.notes.size() +
      static_cast<std::size_t>(o.difficultyUses);
    if (used > 0) {
      out.push_back({0, setup.name, rowsOf(setup, true)});
    }
    for (const Info& info : numbered) {
      out.push_back({info.number, info.name, rowsOf(info, false)});
    }
    return out;
  }

  std::vector<MissionDialogue> ParseMissionStrings(
    const std::string& text
  )
  {
    std::vector<MissionDialogue> dialogues;
    const std::string t = "\n" + text;
    std::string plain;
    std::string code;
    MaskLua(t, plain, code);
    MissionDialogue texts;
    texts.name = "Text strings";
    std::size_t pos = 0;
    for (int guard = 0; guard < 20000; ++guard) {
      // "\n<name> = "
      std::size_t s = plain.find('\n', pos);
      std::string name;
      std::size_t at = std::string::npos;
      while (s != std::string::npos) {
        std::size_t i = s + 1;
        if (i < plain.size() && IsIdStart(plain[i])) {
          std::size_t j = i;
          while (j < plain.size() && IsIdChar(plain[j])) {
            ++j;
          }
          std::size_t k = j;
          while (k < plain.size() && (plain[k] == ' ' || plain[k] == '\t')) {
            ++k;
          }
          if (k < plain.size() && plain[k] == '=' && (k + 1 >= plain.size() || plain[k + 1] != '=')) {
            ++k;
            while (k < plain.size() && (plain[k] == ' ' || plain[k] == '\t')) {
              ++k;
            }
            name = plain.substr(i, j - i);
            at = k;
            break;
          }
        }
        s = plain.find('\n', s + 1);
      }
      if (at == std::string::npos || at >= plain.size()) {
        break;
      }
      const char ch = plain[at];
      pos = at;
      if (ch == '{') {
        const std::size_t close = CloseOf(plain, at, 400000);
        if (close == std::string::npos) {
          break;
        }
        pos = close + 1;
        MissionDialogue d;
        d.name = name;
        for (const auto& entry : Items(plain, at + 1, close - 1)) {
          const std::size_t ob = plain.find('{', entry.first);
          if (ob == std::string::npos || ob > entry.second) {
            continue;
          }
          const std::size_t ce = CloseOf(plain, ob);
          if (ce == std::string::npos || ce > entry.second) {
            continue;
          }
          MissionDialogueLine line;
          line.seconds = 5.0;
          bool hasText = false;
          for (const auto& field : Items(plain, ob + 1, ce - 1)) {
            std::size_t k = field.first;
            while (k <= field.second && IsSpace(plain[k])) {
              ++k;
            }
            std::size_t ke = k;
            while (ke <= field.second && IsIdChar(plain[ke])) {
              ++ke;
            }
            if (ke == k || !IsIdStart(plain[k])) {
              continue;
            }
            const std::string key = plain.substr(k, ke - k);
            std::size_t eq = ke;
            while (eq <= field.second && IsSpace(plain[eq])) {
              ++eq;
            }
            if (eq > field.second || plain[eq] != '=') {
              continue;
            }
            ++eq;
            if (eq > field.second) {
              continue;
            }
            bool lit = false;
            const std::string v = Literal(plain, code, eq, field.second, lit);
            if (key == "text") {
              line.text = v;
              hasText = true;
            } else if (key == "character") {
              line.speaker = v;
            } else if (key == "delay") {
              const double secs = std::atof(v.c_str());
              line.seconds = secs > 0.0 ? secs : line.seconds;
            }
          }
          if (!hasText) {
            continue;
          }
          // "[{i Speaker}]: text" names the speaker.
          if (line.speaker.empty() && line.text.starts_with("[{i ")) {
            const std::size_t end = line.text.find("}]:");
            if (end != std::string::npos) {
              line.speaker = line.text.substr(4, end - 4);
              std::size_t rest = end + 3;
              if (rest < line.text.size() && line.text[rest] == ' ') {
                ++rest;
              }
              line.text = line.text.substr(rest);
            }
          }
          d.lines.push_back(std::move(line));
        }
        if (!d.lines.empty()) {
          dialogues.push_back(std::move(d));
        }
      } else if (ch == '\'' || ch == '"') {
        std::size_t eol = plain.find('\n', at);
        if (eol == std::string::npos) {
          eol = plain.size();
        }
        bool lit = false;
        const std::string v = Literal(plain, code, at, eol - 1, lit);
        if (lit) {
          texts.lines.push_back({v, name, 0.0});
        }
        pos = eol;
      }
    }
    if (!texts.lines.empty()) {
      dialogues.push_back(std::move(texts));
    }
    return dialogues;
  }
} // namespace faf::editor
