#include "editor/doc/EdGroupOptions.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <set>
#include <utility>

namespace faf::editor
{
  namespace
  {
    // ---- Lua text as tokens (comments and long strings handled; GPG's Lua also takes `#` comments and `!=`) ----

    struct Tok
    {
      enum class K
      {
        Name,
        Num,
        Str,
        Op,
        End,
      };
      K k = K::End;
      std::string s;
      double n = 0.0;
    };

    std::vector<Tok> Lex(const std::string& t)
    {
      std::vector<Tok> out;
      const std::size_t n = t.size();
      std::size_t i = 0;
      // `[==[`: its level, or -1 when not a long bracket.
      const auto longLevel = [&](const std::size_t p) {
        std::size_t q = p + 1;
        int level = 0;
        while (q < n && t[q] == '=') {
          ++level;
          ++q;
        }
        return q < n && t[q] == '[' ? level : -1;
      };
      const auto longEnd = [&](const std::size_t from, const int level) {
        const std::string close = "]" + std::string(static_cast<std::size_t>(level), '=') + "]";
        const std::size_t e = t.find(close, from);
        return e == std::string::npos ? std::make_pair(n, n) : std::make_pair(e, e + close.size());
      };
      while (i < n) {
        const char c = t[i];
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
          ++i;
          continue;
        }
        if ((c == '-' && i + 1 < n && t[i + 1] == '-') || c == '#') {
          i += c == '#' ? 1 : 2;
          if (c == '-' && i < n && t[i] == '[') {
            if (const int level = longLevel(i); level >= 0) {
              i = longEnd(i + static_cast<std::size_t>(level) + 2, level).second;
              continue;
            }
          }
          while (i < n && t[i] != '\n') {
            ++i;
          }
          continue;
        }
        if (c == '[') {
          if (const int level = longLevel(i); level >= 0) {
            const std::size_t start = i + static_cast<std::size_t>(level) + 2;
            const auto [close, after] = longEnd(start, level);
            out.push_back({Tok::K::Str, t.substr(start, close - start)});
            i = after;
            continue;
          }
        }
        if (c == '"' || c == '\'') {
          std::string s;
          std::size_t j = i + 1;
          while (j < n && t[j] != c && t[j] != '\n') {
            if (t[j] == '\\' && j + 1 < n) {
              s += t[j + 1];
              j += 2;
              continue;
            }
            s += t[j++];
          }
          out.push_back({Tok::K::Str, s});
          i = j < n ? j + 1 : n;
          continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c)) != 0 || (c == '.' && i + 1 < n && std::isdigit(static_cast<unsigned char>(t[i + 1])) != 0)) {
          std::size_t j = i;
          while (j < n && (std::isalnum(static_cast<unsigned char>(t[j])) != 0 || (t[j] == '.' && !(j + 1 < n && t[j + 1] == '.')))) {
            ++j;
          }
          const std::string text = t.substr(i, j - i);
          out.push_back({Tok::K::Num, text, std::strtod(text.c_str(), nullptr)});
          i = j;
          continue;
        }
        if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_') {
          std::size_t j = i;
          while (j < n && (std::isalnum(static_cast<unsigned char>(t[j])) != 0 || t[j] == '_')) {
            ++j;
          }
          out.push_back({Tok::K::Name, t.substr(i, j - i)});
          i = j;
          continue;
        }
        static const char* const kOps[] = {"...", "==", "~=", "!=", "<=", ">=", ".."};
        std::string op(1, c);
        for (const char* const o : kOps) {
          if (t.compare(i, std::char_traits<char>::length(o), o) == 0) {
            op = o;
            break;
          }
        }
        out.push_back({Tok::K::Op, op == "!=" ? std::string("~=") : op});
        i += op.size();
      }
      out.push_back({Tok::K::End, ""});
      return out;
    }

    bool IsName(const Tok& t, const char* const s)
    {
      return t.k == Tok::K::Name && t.s == s;
    }
    bool IsOp(const Tok& t, const char* const s)
    {
      return t.k == Tok::K::Op && t.s == s;
    }
    bool Opens(const Tok& t)
    {
      return IsOp(t, "(") || IsOp(t, "{") || IsOp(t, "[");
    }
    bool Closes(const Tok& t)
    {
      return IsOp(t, ")") || IsOp(t, "}") || IsOp(t, "]");
    }

    // ---- Values, three-valued: a condition on what the editor can't know is "maybe" ----

    enum class Tri
    {
      No,
      Yes,
      Maybe,
    };
    Tri And(const Tri a, const Tri b)
    {
      return a == Tri::No || b == Tri::No ? Tri::No : a == Tri::Yes && b == Tri::Yes ? Tri::Yes : Tri::Maybe;
    }
    Tri Or(const Tri a, const Tri b)
    {
      return a == Tri::Yes || b == Tri::Yes ? Tri::Yes : a == Tri::No && b == Tri::No ? Tri::No : Tri::Maybe;
    }
    Tri Not(const Tri a)
    {
      return a == Tri::Yes ? Tri::No : a == Tri::No ? Tri::Yes : Tri::Maybe;
    }

    struct Val
    {
      enum class K
      {
        Unknown,
        Nil,
        Bool,
        Num,
        Str,
      };
      K k = K::Unknown;
      bool b = false;
      double n = 0.0;
      std::string s;
      /** An unknown value can still be known to be true or false (`x or true`). */
      Tri truth = Tri::Maybe;

      static Val Unknown(const Tri truth = Tri::Maybe)
      {
        Val v;
        v.truth = truth;
        return v;
      }
      static Val Bool(const bool b)
      {
        Val v;
        v.k = K::Bool;
        v.b = b;
        return v;
      }
      static Val Num(const double n)
      {
        Val v;
        v.k = K::Num;
        v.n = n;
        return v;
      }
      static Val Str(std::string s)
      {
        Val v;
        v.k = K::Str;
        v.s = std::move(s);
        return v;
      }
      static Val Nil()
      {
        Val v;
        v.k = K::Nil;
        return v;
      }
    };

    Tri Truth(const Val& v)
    {
      switch (v.k) {
        case Val::K::Unknown:
          return v.truth;
        case Val::K::Nil:
          return Tri::No;
        case Val::K::Bool:
          return v.b ? Tri::Yes : Tri::No;
        default:
          return Tri::Yes;
      }
    }

    std::string NumberText(const double n)
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%.14g", n);
      return text;
    }

    /** What the script's names hold while one lobby setting is evaluated. */
    struct Env
    {
      /** Script variables (`local optional_wreckage = ScenarioInfo.Options.optional_wreckage or 1`). */
      std::map<std::string, Val> vars;
      /** `ScenarioInfo.Options.<key>` read directly. */
      std::map<std::string, Val> options;
      /** Each script variable's option key. */
      const std::map<std::string, std::string>* varKeys = nullptr;
      /** The options read while evaluating (to learn which ones decide). */
      std::set<std::string>* touched = nullptr;
    };

    /** A Lua expression over tokens [p, e), evaluated with what the editor knows. */
    class Eval
    {
    public:
      Eval(const std::vector<Tok>& t, const std::size_t p, const std::size_t e, const Env& env) : mT(t), mP(p), mE(e), mEnv(env) {}

      Val Run()
      {
        return mP < mE ? Or() : Val::Unknown();
      }

    private:
      const Tok& Peek() const
      {
        static const Tok kEnd;
        return mP < mE ? mT[mP] : kEnd;
      }
      bool AtName(const char* const s) const
      {
        return IsName(Peek(), s);
      }
      bool AtOp(const char* const s) const
      {
        return IsOp(Peek(), s);
      }
      /** Skips a bracketed run starting at an opener. */
      void SkipBalanced()
      {
        int depth = 0;
        do {
          if (Opens(Peek())) {
            ++depth;
          } else if (Closes(Peek())) {
            --depth;
          }
          ++mP;
        } while (mP < mE && depth > 0);
      }

      Val Or()
      {
        Val a = And();
        while (AtName("or")) {
          ++mP;
          const Val b = And();
          const Tri ta = Truth(a);
          a = ta == Tri::Yes ? a : ta == Tri::No ? b : Val::Unknown(Truth(b) == Tri::Yes ? Tri::Yes : Tri::Maybe);
        }
        return a;
      }
      Val And()
      {
        Val a = Compare();
        while (AtName("and")) {
          ++mP;
          const Val b = Compare();
          const Tri ta = Truth(a);
          a = ta == Tri::No ? a : ta == Tri::Yes ? b : Val::Unknown(Truth(b) == Tri::No ? Tri::No : Tri::Maybe);
        }
        return a;
      }
      Val Compare()
      {
        Val a = Concat();
        static const char* const kCompares[] = {"==", "~=", "<", ">", "<=", ">="};
        for (;;) {
          const char* op = nullptr;
          for (const char* const c : kCompares) {
            if (AtOp(c)) {
              op = c;
            }
          }
          if (op == nullptr) {
            return a;
          }
          ++mP;
          const Val b = Concat();
          a = Compared(op, a, b);
        }
      }
      static Val Compared(const std::string& op, const Val& a, const Val& b)
      {
        if (a.k == Val::K::Unknown || b.k == Val::K::Unknown) {
          return Val::Unknown();
        }
        if (op == "==" || op == "~=") {
          bool same = a.k == b.k;
          if (same) {
            same = a.k == Val::K::Num ? a.n == b.n : a.k == Val::K::Str ? a.s == b.s : a.k == Val::K::Bool ? a.b == b.b : true;
          }
          return Val::Bool(op == "==" ? same : !same);
        }
        int order = 0;
        if (a.k == Val::K::Num && b.k == Val::K::Num) {
          order = a.n < b.n ? -1 : a.n > b.n ? 1 : 0;
        } else if (a.k == Val::K::Str && b.k == Val::K::Str) {
          order = a.s.compare(b.s);
        } else {
          return Val::Unknown(); // an error in the game's Lua
        }
        return Val::Bool(op == "<" ? order < 0 : op == ">" ? order > 0 : op == "<=" ? order <= 0 : order >= 0);
      }
      Val Concat()
      {
        Val a = Add();
        while (AtOp("..")) {
          ++mP;
          const Val b = Add();
          const auto text = [](const Val& v, std::string& out) {
            if (v.k == Val::K::Str) {
              out = v.s;
            } else if (v.k == Val::K::Num) {
              out = NumberText(v.n);
            } else {
              return false;
            }
            return true;
          };
          std::string x;
          std::string y;
          a = text(a, x) && text(b, y) ? Val::Str(x + y) : Val::Unknown(Tri::Yes);
        }
        return a;
      }
      Val Add()
      {
        Val a = Mul();
        while (AtOp("+") || AtOp("-")) {
          const bool plus = AtOp("+");
          ++mP;
          const Val b = Mul();
          a = a.k == Val::K::Num && b.k == Val::K::Num ? Val::Num(plus ? a.n + b.n : a.n - b.n) : Val::Unknown();
        }
        return a;
      }
      Val Mul()
      {
        Val a = Unary();
        while (AtOp("*") || AtOp("/") || AtOp("%")) {
          const char op = Peek().s[0];
          ++mP;
          const Val b = Unary();
          if (a.k != Val::K::Num || b.k != Val::K::Num || (op != '*' && b.n == 0.0)) {
            a = Val::Unknown();
          } else {
            a = Val::Num(op == '*' ? a.n * b.n : op == '/' ? a.n / b.n : a.n - b.n * static_cast<double>(static_cast<long long>(a.n / b.n)));
          }
        }
        return a;
      }
      Val Unary()
      {
        if (AtName("not")) {
          ++mP;
          const Val v = Unary();
          const Tri t = Not(Truth(v));
          return t == Tri::Maybe ? Val::Unknown() : Val::Bool(t == Tri::Yes);
        }
        if (AtOp("-")) {
          ++mP;
          const Val v = Unary();
          return v.k == Val::K::Num ? Val::Num(-v.n) : Val::Unknown();
        }
        if (AtOp("#")) {
          ++mP;
          (void)Unary();
          return Val::Unknown(Tri::Yes);
        }
        Val a = Primary();
        if (AtOp("^")) {
          ++mP;
          (void)Unary();
          a = Val::Unknown(Tri::Yes);
        }
        return a;
      }
      Val Primary()
      {
        const Tok& t = Peek();
        Val v;
        if (t.k == Tok::K::Num) {
          ++mP;
          v = Val::Num(t.n);
        } else if (t.k == Tok::K::Str) {
          ++mP;
          v = Val::Str(t.s);
        } else if (IsName(t, "true") || IsName(t, "false")) {
          ++mP;
          v = Val::Bool(t.s == "true");
        } else if (IsName(t, "nil")) {
          ++mP;
          v = Val::Nil();
        } else if (IsOp(t, "(")) {
          ++mP;
          v = Or();
          if (AtOp(")")) {
            ++mP;
          }
        } else if (IsOp(t, "{")) {
          SkipBalanced();
          return Val::Unknown(Tri::Yes); // a table: true
        } else if (t.k == Tok::K::Name) {
          ++mP;
          // ScenarioInfo.Options.<key>: the lobby's value.
          if (t.s == "ScenarioInfo" && AtOp(".") && mP + 3 < mE && IsName(mT[mP + 1], "Options") && IsOp(mT[mP + 2], ".") &&
              mT[mP + 3].k == Tok::K::Name) {
            const std::string key = mT[mP + 3].s;
            mP += 4;
            if (mEnv.touched != nullptr) {
              mEnv.touched->insert(key);
            }
            const auto found = mEnv.options.find(key);
            v = found == mEnv.options.end() ? Val::Unknown() : found->second;
          } else {
            const auto found = mEnv.vars.find(t.s);
            v = found == mEnv.vars.end() ? Val::Unknown() : found->second;
            if (mEnv.varKeys != nullptr && mEnv.touched != nullptr) {
              if (const auto key = mEnv.varKeys->find(t.s); key != mEnv.varKeys->end()) {
                mEnv.touched->insert(key->second);
              }
            }
          }
        } else {
          ++mP;
          return Val::Unknown();
        }
        // Fields, indexing and calls on it: not known.
        while (mP < mE) {
          if (AtOp(".") || AtOp(":")) {
            mP += 2;
            v = Val::Unknown();
          } else if (AtOp("[") || AtOp("(") || AtOp("{")) {
            SkipBalanced();
            v = Val::Unknown();
          } else if (Peek().k == Tok::K::Str && v.k == Val::K::Unknown) {
            ++mP;
          } else {
            break;
          }
        }
        return v;
      }

      const std::vector<Tok>& mT;
      std::size_t mP;
      std::size_t mE;
      const Env& mEnv;
    };

    // ---- The script's blocks: what encloses each group creation and each call ----

    struct Range
    {
      std::size_t b = 0;
      std::size_t e = 0;
    };
    struct Frame
    {
      enum class Kind
      {
        Function,
        If,
        NumFor,
        GenFor,
        While,
        Plain, // do ... end, repeat ... until
      };
      Kind kind = Kind::Plain;
      std::string name; // a function's (its last part: `ScenarioUtils.CreateResources` is CreateResources)
      std::vector<Range> priors; // an if's earlier conditions (false where this branch runs)
      Range cond;
      bool inElse = false;
      std::string var; // a numeric for's
      Range from;
      Range to;
      Range step;
    };
    /** Where something is: the blocks around it inside its function, and that function's name. */
    struct Site
    {
      std::vector<Frame> frames;
      std::string function;
    };
    struct Creation
    {
      Site site;
      Range name;
      Range wreck; // empty: not given (units)
      bool asPlatoonOrTree = false;
    };
    struct Script
    {
      std::vector<Tok> toks;
      std::vector<Creation> creations;
      std::map<std::string, std::vector<Site>> calls;
      std::map<std::string, std::string> varKeys;
      std::map<std::string, Range> varDefaults; // the `or <value>` after the option
      std::vector<std::string> keyOrder;
    };

    Site SiteOf(const std::vector<Frame>& stack)
    {
      Site site;
      std::size_t from = 0;
      for (std::size_t i = stack.size(); i-- > 0;) {
        if (stack[i].kind == Frame::Kind::Function) {
          site.function = stack[i].name;
          from = i + 1;
          break;
        }
      }
      site.frames.assign(stack.begin() + static_cast<std::ptrdiff_t>(from), stack.end());
      return site;
    }

    /** Ranges split at the commas outside brackets in [b, e). */
    std::vector<Range> SplitCommas(const std::vector<Tok>& t, const std::size_t b, const std::size_t e)
    {
      std::vector<Range> parts{{b, b}};
      int depth = 0;
      for (std::size_t i = b; i < e; ++i) {
        if (Opens(t[i])) {
          ++depth;
        } else if (Closes(t[i])) {
          --depth;
        } else if (depth == 0 && IsOp(t[i], ",")) {
          parts.back().e = i;
          parts.push_back({i + 1, i + 1});
          continue;
        }
        parts.back().e = i + 1;
      }
      return parts;
    }

    /** The index of the next `word` keyword from `i` (or the last token). */
    std::size_t FindWord(const std::vector<Tok>& t, std::size_t i, const char* const word)
    {
      while (i + 1 < t.size() && !IsName(t[i], word)) {
        ++i;
      }
      return i;
    }

    Script ReadScript(const std::string& text)
    {
      Script s;
      s.toks = Lex(text);
      const std::vector<Tok>& t = s.toks;
      // The options the script reads, anywhere (conditions too): `x = ScenarioInfo.Options.key or <default>` names x.
      for (std::size_t i = 0; i + 4 < t.size(); ++i) {
        if (!(IsName(t[i], "ScenarioInfo") && IsOp(t[i + 1], ".") && IsName(t[i + 2], "Options") && IsOp(t[i + 3], ".") &&
              t[i + 4].k == Tok::K::Name)) {
          continue;
        }
        const std::string key = t[i + 4].s;
        if (std::find(s.keyOrder.begin(), s.keyOrder.end(), key) == s.keyOrder.end()) {
          s.keyOrder.push_back(key);
        }
        if (i >= 2 && IsOp(t[i - 1], "=") && t[i - 2].k == Tok::K::Name && s.varKeys.count(t[i - 2].s) == 0) {
          s.varKeys[t[i - 2].s] = key;
          if (i + 6 < t.size() && IsName(t[i + 5], "or") && (t[i + 6].k == Tok::K::Num || t[i + 6].k == Tok::K::Str)) {
            s.varDefaults[t[i - 2].s] = {i + 6, i + 7};
          }
        }
      }
      std::vector<Frame> stack;
      for (std::size_t i = 0; i + 1 < t.size();) {
        const Tok& tok = t[i];
        if (tok.k != Tok::K::Name) {
          ++i;
          continue;
        }
        if (tok.s == "function") {
          Frame f;
          f.kind = Frame::Kind::Function;
          std::size_t j = i + 1;
          while (t[j].k == Tok::K::Name || IsOp(t[j], ".") || IsOp(t[j], ":")) {
            if (t[j].k == Tok::K::Name) {
              f.name = t[j].s;
            }
            ++j;
          }
          stack.push_back(std::move(f));
          i = j;
          continue;
        }
        if (tok.s == "if" || tok.s == "elseif") {
          const std::size_t then = FindWord(t, i + 1, "then");
          if (tok.s == "if") {
            Frame f;
            f.kind = Frame::Kind::If;
            f.cond = {i + 1, then};
            stack.push_back(std::move(f));
          } else if (!stack.empty() && stack.back().kind == Frame::Kind::If) {
            stack.back().priors.push_back(stack.back().cond);
            stack.back().cond = {i + 1, then};
          }
          i = then + 1;
          continue;
        }
        if (tok.s == "else") {
          if (!stack.empty() && stack.back().kind == Frame::Kind::If && !stack.back().inElse) {
            stack.back().priors.push_back(stack.back().cond);
            stack.back().inElse = true;
          }
          ++i;
          continue;
        }
        if (tok.s == "for" || tok.s == "while") {
          const std::size_t doAt = FindWord(t, i + 1, "do");
          Frame f;
          if (tok.s == "while") {
            f.kind = Frame::Kind::While;
            f.cond = {i + 1, doAt};
          } else if (t[i + 1].k == Tok::K::Name && IsOp(t[i + 2], "=")) {
            f.kind = Frame::Kind::NumFor;
            f.var = t[i + 1].s;
            const std::vector<Range> parts = SplitCommas(t, i + 3, doAt);
            f.from = parts[0];
            f.to = parts.size() > 1 ? parts[1] : Range{};
            f.step = parts.size() > 2 ? parts[2] : Range{};
          } else {
            f.kind = Frame::Kind::GenFor;
          }
          stack.push_back(std::move(f));
          i = doAt + 1;
          continue;
        }
        if (tok.s == "do" || tok.s == "repeat") {
          stack.push_back(Frame{});
          ++i;
          continue;
        }
        if (tok.s == "end" || tok.s == "until") {
          if (!stack.empty()) {
            stack.pop_back();
          }
          ++i;
          continue;
        }
        // A call: a group creation, or a call of the map's own functions (to find when they run).
        if (IsOp(t[i + 1], "(")) {
          std::size_t close = i + 1;
          for (int depth = 0; close < t.size(); ++close) {
            depth += Opens(t[close]) ? 1 : Closes(t[close]) ? -1 : 0;
            if (depth == 0) {
              break;
            }
          }
          if (tok.s.rfind("CreateArmy", 0) == 0) {
            const std::vector<Range> args = SplitCommas(t, i + 2, close);
            if (args.size() >= 2) {
              Creation c;
              c.site = SiteOf(stack);
              c.name = args[1];
              c.asPlatoonOrTree = tok.s != "CreateArmyGroup";
              if (!c.asPlatoonOrTree && args.size() >= 3) {
                c.wreck = args[2];
              }
              s.creations.push_back(std::move(c));
            }
          } else if (i == 0 || !IsName(t[i - 1], "function")) {
            s.calls[tok.s].push_back(SiteOf(stack));
          }
        }
        ++i;
      }
      return s;
    }

    /** Whether the code at `site` runs, lifted through the calls of its function (a few levels). */
    Tri SiteRuns(const Script& s, const Site& site, const Env& env, const std::string& loopVar, const double loopValue, bool useLoop, int depth);

    Tri FramesRun(const Script& s, const std::vector<Frame>& frames, Env env, const std::string& loopVar, const double loopValue, const bool useLoop)
    {
      Tri runs = Tri::Yes;
      const auto eval = [&](const Range r) { return Eval(s.toks, r.b, r.e, env).Run(); };
      for (const Frame& f : frames) {
        switch (f.kind) {
          case Frame::Kind::If:
            for (const Range& prior : f.priors) {
              runs = And(runs, Not(Truth(eval(prior))));
            }
            if (!f.inElse) {
              runs = And(runs, Truth(eval(f.cond)));
            }
            break;
          case Frame::Kind::While:
            runs = And(runs, Truth(eval(f.cond)));
            break;
          case Frame::Kind::GenFor:
            runs = And(runs, Tri::Maybe);
            break;
          case Frame::Kind::NumFor: {
            const Val from = eval(f.from);
            const Val to = f.to.e > f.to.b ? eval(f.to) : Val::Unknown();
            const Val step = f.step.e > f.step.b ? eval(f.step) : Val::Num(1.0);
            if (from.k != Val::K::Num || to.k != Val::K::Num || step.k != Val::K::Num || step.n == 0.0) {
              runs = And(runs, Tri::Maybe);
              env.vars[f.var] = Val::Unknown();
              break;
            }
            const double lo = step.n > 0.0 ? from.n : to.n;
            const double hi = step.n > 0.0 ? to.n : from.n;
            if (useLoop && f.var == loopVar) {
              // The group's name takes this loop's variable: made only on the turn it equals the name's number.
              const double turns = (loopValue - from.n) / step.n;
              const bool onTurn = turns >= 0.0 && turns == static_cast<double>(static_cast<long long>(turns));
              runs = And(runs, loopValue >= lo && loopValue <= hi && onTurn ? Tri::Yes : Tri::No);
              env.vars[f.var] = Val::Num(loopValue);
            } else {
              runs = And(runs, lo <= hi ? Tri::Yes : Tri::No);
              env.vars[f.var] = Val::Unknown();
            }
            break;
          }
          default:
            break;
        }
      }
      return runs;
    }

    Tri SiteRuns(const Script& s, const Site& site, const Env& env, const std::string& loopVar, const double loopValue, const bool useLoop, const int depth)
    {
      Tri runs = FramesRun(s, site.frames, env, loopVar, loopValue, useLoop);
      if (runs == Tri::No || site.function.empty() || depth >= 4) {
        return runs;
      }
      const auto calls = s.calls.find(site.function);
      if (calls == s.calls.end() || calls->second.empty()) {
        return runs; // run by the game (OnPopulate) or handed over (ForkThread): taken as running
      }
      Tri called = Tri::No;
      for (const Site& caller : calls->second) {
        if (caller.function == site.function) {
          continue; // a recursive call adds nothing
        }
        called = Or(called, SiteRuns(s, caller, env, "", 0.0, false, depth + 1));
      }
      return And(runs, called);
    }

    /** Whether creation `c` makes the group named `group` under `env`, and as what. */
    struct Made
    {
      Tri made = Tri::No;
      Tri wreck = Tri::No;
    };
    Made CreationMakes(const Script& s, const Creation& c, const Env& env, const std::string& group)
    {
      Made result;
      const std::vector<Tok>& t = s.toks;
      if (c.name.e <= c.name.b || t[c.name.b].k != Tok::K::Str) {
        return result; // a name made at run time some other way: not matched
      }
      const std::string& head = t[c.name.b].s;
      std::string loopVar;
      double loopValue = 0.0;
      bool useLoop = false;
      Tri named = Tri::No;
      if (c.name.e == c.name.b + 1) {
        named = head == group ? Tri::Yes : Tri::No;
      } else if (IsOp(t[c.name.b + 1], "..") && group.rfind(head, 0) == 0) {
        const std::string rest = group.substr(head.size());
        // `'Name_' .. w` with w a numeric for's variable: the turn w = the name's number.
        if (c.name.e == c.name.b + 3 && t[c.name.b + 2].k == Tok::K::Name) {
          for (const Frame& f : c.site.frames) {
            if (f.kind == Frame::Kind::NumFor && f.var == t[c.name.b + 2].s) {
              char* end = nullptr;
              loopValue = std::strtod(rest.c_str(), &end);
              if (rest.empty() || end == nullptr || *end != '\0') {
                return result;
              }
              loopVar = f.var;
              useLoop = true;
            }
          }
        }
        if (useLoop) {
          named = Tri::Yes;
        } else {
          const Val name = Eval(t, c.name.b, c.name.e, env).Run();
          named = name.k == Val::K::Str ? (name.s == group ? Tri::Yes : Tri::No) : Tri::Maybe;
        }
      }
      if (named == Tri::No) {
        return result;
      }
      result.made = And(named, SiteRuns(s, c.site, env, loopVar, loopValue, useLoop, 0));
      if (c.wreck.e > c.wreck.b) {
        result.wreck = Truth(Eval(t, c.wreck.b, c.wreck.e, env).Run());
      }
      return result;
    }

    Val KeyValue(const LobbyOptionInfo::Value& value)
    {
      return value.number ? Val::Num(value.numberKey) : Val::Str(value.key);
    }

    std::string Quoted(const std::string& text)
    {
      return "\"" + text + "\"";
    }
  } // namespace

  std::vector<LobbyOptionInfo> ParseLobbyOptions(const std::string& optionsText)
  {
    std::vector<LobbyOptionInfo> options;
    const std::vector<Tok> t = Lex(optionsText);
    std::size_t i = 0;
    while (i + 2 < t.size() && !(IsName(t[i], "options") && IsOp(t[i + 1], "=") && IsOp(t[i + 2], "{"))) {
      ++i;
    }
    if (i + 2 >= t.size()) {
      return options;
    }
    // Each entry: a table at depth 1, its fields at depth 2.
    const auto close = [&](std::size_t open) {
      int depth = 0;
      for (; open < t.size(); ++open) {
        depth += Opens(t[open]) ? 1 : Closes(t[open]) ? -1 : 0;
        if (depth == 0) {
          return open;
        }
      }
      return t.size() - 1;
    };
    const std::size_t listEnd = close(i + 2);
    for (std::size_t at = i + 3; at < listEnd; ++at) {
      if (!IsOp(t[at], "{")) {
        continue;
      }
      const std::size_t entryEnd = close(at);
      LobbyOptionInfo option;
      for (std::size_t f = at + 1; f < entryEnd; ++f) {
        if (Opens(t[f]) && !(f >= 2 && IsName(t[f - 2], "values"))) {
          f = close(f);
          continue;
        }
        if (t[f].k != Tok::K::Name || !IsOp(t[f + 1], "=")) {
          continue;
        }
        const std::string field = t[f].s;
        const Tok& value = t[f + 2];
        if (field == "key" && (value.k == Tok::K::Str || value.k == Tok::K::Num)) {
          option.key = value.s;
        } else if (field == "label" && value.k == Tok::K::Str) {
          option.label = value.s;
        } else if (field == "help" && value.k == Tok::K::Str) {
          option.help = value.s;
        } else if (field == "default" && value.k == Tok::K::Num) {
          option.defaultIndex = static_cast<int>(value.n);
        } else if (field == "values" && IsOp(value, "{")) {
          const std::size_t valuesEnd = close(f + 2);
          for (std::size_t v = f + 3; v < valuesEnd; ++v) {
            LobbyOptionInfo::Value entry;
            if (IsOp(t[v], "{")) {
              const std::size_t entryClose = close(v);
              for (std::size_t g = v + 1; g + 2 < entryClose + 1; ++g) {
                if (t[g].k == Tok::K::Name && IsOp(t[g + 1], "=")) {
                  const Tok& x = t[g + 2];
                  if (t[g].s == "key") {
                    entry.key = x.s;
                    entry.number = x.k == Tok::K::Num;
                    entry.numberKey = x.n;
                  } else if (t[g].s == "text" && x.k == Tok::K::Str) {
                    entry.text = x.s;
                  } else if (t[g].s == "help" && x.k == Tok::K::Str) {
                    entry.help = x.s;
                  }
                }
              }
              v = entryClose;
            } else if (t[v].k == Tok::K::Str || t[v].k == Tok::K::Num) {
              entry.key = t[v].s;
              entry.number = t[v].k == Tok::K::Num;
              entry.numberKey = t[v].n;
              entry.text = t[v].s;
            } else {
              continue;
            }
            if (entry.text.empty()) {
              entry.text = entry.key;
            }
            option.values.push_back(std::move(entry));
          }
          f = valuesEnd;
        }
      }
      if (!option.key.empty()) {
        options.push_back(std::move(option));
      }
      at = entryEnd;
    }
    return options;
  }

  bool GroupLobbyRule::Never() const
  {
    return std::all_of(cases.begin(), cases.end(), [](const Case& c) { return c.made == Made::No; });
  }

  GroupLobbyRule LobbyRuleOfGroup(const std::string& scriptText, const std::vector<LobbyOptionInfo>& options, const std::string& group)
  {
    GroupLobbyRule rule;
    const Script s = ReadScript(scriptText);
    std::vector<const Creation*> naming;
    // The creations that can name it: 'Name' exactly, or 'Name_' .. something with the group's name starting so.
    for (const Creation& c : s.creations) {
      if (c.name.e <= c.name.b || s.toks[c.name.b].k != Tok::K::Str) {
        continue;
      }
      const std::string& head = s.toks[c.name.b].s;
      const bool exact = c.name.e == c.name.b + 1;
      if (exact ? head == group : IsOp(s.toks[c.name.b + 1], "..") && group.rfind(head, 0) == 0) {
        naming.push_back(&c);
      }
    }
    if (naming.empty()) {
      return rule;
    }
    // Which options decide: those read while every option is unknown.
    std::set<std::string> touched;
    Env probe;
    probe.varKeys = &s.varKeys;
    probe.touched = &touched;
    for (const Creation* c : naming) {
      (void)CreationMakes(s, *c, probe, group);
    }
    rule.scriptNames = true;
    for (const std::string& key : s.keyOrder) {
      if (touched.count(key) != 0) {
        rule.keys.push_back(key);
      }
    }
    for (const std::string& key : rule.keys) {
      int index = -1;
      for (std::size_t o = 0; o < options.size(); ++o) {
        if (options[o].key == key) {
          index = static_cast<int>(o);
        }
      }
      rule.optionIndex.push_back(index);
      std::string fallback;
      for (const auto& [var, varKey] : s.varKeys) {
        if (varKey == key) {
          if (const auto d = s.varDefaults.find(var); d != s.varDefaults.end()) {
            fallback = s.toks[d->second.b].s;
          }
        }
      }
      rule.scriptDefault.push_back(fallback);
    }
    // Every combination of the deciding options' values.
    std::vector<int> counts;
    std::size_t total = 1;
    for (const int index : rule.optionIndex) {
      const int count = index < 0 ? 1 : std::max(1, static_cast<int>(options[static_cast<std::size_t>(index)].values.size()));
      counts.push_back(count);
      total *= static_cast<std::size_t>(count);
    }
    total = std::min<std::size_t>(total, 256);
    for (std::size_t n = 0; n < total; ++n) {
      GroupLobbyRule::Case c;
      Env env;
      env.varKeys = &s.varKeys;
      std::size_t rest = n;
      for (std::size_t k = 0; k < rule.keys.size(); ++k) {
        const int pick = static_cast<int>(rest % static_cast<std::size_t>(counts[k]));
        rest /= static_cast<std::size_t>(counts[k]);
        const int index = rule.optionIndex[k];
        const auto& values = index < 0 ? std::vector<LobbyOptionInfo::Value>{} : options[static_cast<std::size_t>(index)].values;
        // The lobby's value; an option the lobby doesn't offer is nil (the script's `or` default then).
        const Val lobby = values.empty() ? Val::Nil() : KeyValue(values[static_cast<std::size_t>(pick)]);
        c.picks.push_back(values.empty() ? -1 : pick);
        env.options[rule.keys[k]] = lobby;
        for (const auto& [var, key] : s.varKeys) {
          if (key != rule.keys[k]) {
            continue;
          }
          Val value = lobby;
          if (value.k == Val::K::Nil) {
            if (const auto d = s.varDefaults.find(var); d != s.varDefaults.end()) {
              const Tok& tok = s.toks[d->second.b];
              value = tok.k == Tok::K::Num ? Val::Num(tok.n) : Val::Str(tok.s);
            }
          }
          env.vars[var] = value;
        }
      }
      Tri made = Tri::No;
      for (const Creation* creation : naming) {
        const Made m = CreationMakes(s, *creation, env, group);
        made = Or(made, m.made);
        if (m.made != Tri::No) {
          c.asWreck = c.asWreck || m.wreck != Tri::No;
          c.asUnit = c.asUnit || m.wreck != Tri::Yes;
        }
      }
      c.made = made == Tri::Yes ? GroupLobbyRule::Made::Yes : made == Tri::No ? GroupLobbyRule::Made::No : GroupLobbyRule::Made::Maybe;
      rule.cases.push_back(std::move(c));
    }
    return rule;
  }

  std::vector<std::string> DescribeLobbyRule(const GroupLobbyRule& rule, const std::vector<LobbyOptionInfo>& options)
  {
    std::vector<std::string> lines;
    if (!rule.scriptNames) {
      return lines;
    }
    const auto outcome = [](const GroupLobbyRule::Case& c) {
      const std::string as = c.asWreck && c.asUnit ? "as wrecks or live units" : c.asWreck ? "as wrecks" : "as live units";
      switch (c.made) {
        case GroupLobbyRule::Made::No:
          return std::string("not created");
        case GroupLobbyRule::Made::Yes:
          return "created " + as;
        default:
          return "maybe created " + as + " (it also depends on the game: slots, factions)";
      }
    };
    const auto valueText = [&](const std::size_t k, const int pick) {
      const int index = rule.optionIndex[k];
      if (index < 0 || pick < 0) {
        return std::string("(not in the lobby)");
      }
      const LobbyOptionInfo& option = options[static_cast<std::size_t>(index)];
      std::string text = Quoted(option.values[static_cast<std::size_t>(pick)].text);
      if (option.defaultIndex == pick + 1) {
        text += " (default)";
      }
      return text;
    };
    const auto optionName = [&](const std::size_t k) {
      const int index = rule.optionIndex[k];
      if (index < 0) {
        return rule.keys[k];
      }
      const LobbyOptionInfo& option = options[static_cast<std::size_t>(index)];
      return (option.label.empty() ? option.key : Quoted(option.label)) + " (" + option.key + ")";
    };
    if (rule.keys.empty()) {
      lines.push_back(rule.cases.empty() || rule.cases[0].made == GroupLobbyRule::Made::No
                          ? "No lobby option decides it: the script never creates it."
                      : rule.cases[0].made == GroupLobbyRule::Made::Yes
                          ? "No lobby option decides it: the script creates it in every game."
                          : "No lobby option decides it; the script creates it only in some games (slots, factions).");
      return lines;
    }
    // Options the script reads that this map's lobby doesn't offer: always the script's default.
    for (std::size_t k = 0; k < rule.keys.size(); ++k) {
      if (rule.optionIndex[k] < 0) {
        lines.push_back("The script reads the option " + rule.keys[k] + ", which this map's _options.lua doesn't offer, so it is always " +
                        (rule.scriptDefault[k].empty() ? std::string("nil") : rule.scriptDefault[k]) + " (the script's default).");
      }
    }
    if (rule.Never()) {
      lines.push_back("No lobby setting creates it: never in a game.");
      return lines;
    }
    if (rule.keys.size() == 1) {
      lines.push_back("Lobby option " + optionName(0) + ":");
      for (const GroupLobbyRule::Case& c : rule.cases) {
        lines.push_back("  " + valueText(0, c.picks[0]) + ": " + outcome(c));
      }
      return lines;
    }
    std::string names;
    for (std::size_t k = 0; k < rule.keys.size(); ++k) {
      names += (k == 0 ? "" : ", ") + optionName(k);
    }
    lines.push_back("Lobby options " + names + "; created with:");
    int shown = 0;
    for (const GroupLobbyRule::Case& c : rule.cases) {
      if (c.made == GroupLobbyRule::Made::No) {
        continue;
      }
      if (++shown > 8) {
        lines.push_back("  ... and more");
        break;
      }
      std::string settings;
      for (std::size_t k = 0; k < rule.keys.size(); ++k) {
        if (rule.optionIndex[k] >= 0) {
          settings += (settings.empty() ? "" : ", ") + valueText(k, c.picks[k]);
        }
      }
      lines.push_back("  " + settings + ": " + outcome(c));
    }
    lines.push_back("  any other setting: not created");
    return lines;
  }
} // namespace faf::editor
