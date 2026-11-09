// The lexer and parser (src/lua/LuaParser.cpp): literals, comments and the fork's lexical
// additions, then malformed chunks - every one must fail to load with a message, never crash or
// throw past luaL_loadbuffer - and the compile-time limits. Syntax errors read
// "<chunk>(<line>): <message> near `<token>'" (luaX_errorline, retail format "%s(%d): %s near `%s'").

#include <cstdint>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaParser : public faf_lua_tests::LuaFixture
  {
  protected:
    /** The load error of `source`; a test failure when it loads. */
    std::string LoadError(const std::string& source)
    {
      std::string message;
      const int status = Load(source, &message);
      EXPECT_NE(status, 0) << "loaded: " << source;
      return message;
    }
  };

  TEST_F(LuaParser, StringLiteralsAndEscapes)
  {
    EXPECT_EQ(Str(R"(return "a\tb\nc")"), "a\tb\nc");
    EXPECT_EQ(Str(R"(return 'it\'s "q"')"), "it's \"q\"");
    EXPECT_EQ(Str(R"(return "back\\slash")"), "back\\slash");
    EXPECT_EQ(Str(R"(return "\65\066\0671")"), "ABC1"); // up to three decimal digits
    EXPECT_EQ(Str(R"(return "\a\b\f\v\r")"), "\a\b\f\v\r");
    EXPECT_EQ(Str("return \"line\\\nnext\""), "line\nnext"); // backslash-newline
    EXPECT_EQ(Num(R"(return string.len("\0\0\0"))"), 3.0);
  }

  // Fork: `\xNN` is an escape (read_string 0x00918C40); a `\x` without a hex digit is a plain x.
  TEST_F(LuaParser, HexEscapes)
  {
    EXPECT_EQ(Str(R"(return "\x41\x62")"), "Ab");
    EXPECT_EQ(Str(R"(return "\x4")"), "\x04");
    EXPECT_EQ(Str(R"(return "\x414")"), "A4"); // two digits at most
    EXPECT_EQ(Str(R"(return "\xg")"), "xg");
  }

  TEST_F(LuaParser, LongStringsAndComments)
  {
    EXPECT_EQ(Str("return [[plain]]"), "plain");
    EXPECT_EQ(Str("return [[\nskips the first newline]]"), "skips the first newline");
    EXPECT_EQ(Str("return [[a\nb]]"), "a\nb");
    EXPECT_EQ(Str("return [[outer [[nested]] tail]]"), "outer [[nested]] tail"); // 5.0 nests
    EXPECT_EQ(Str("return [[no \\n escapes]]"), "no \\n escapes");
    EXPECT_EQ(Num("-- a comment\nreturn 1 -- trailing"), 1.0);
    EXPECT_EQ(Num("--[[ a long\ncomment ]] return 2"), 2.0);
    EXPECT_EQ(Num("--[[ nested [[ inner ]] still comment ]] return 3"), 3.0);
    EXPECT_EQ(Num("return --[[inline]] 4"), 4.0);
  }

  // Fork additions in luaX_lex (0x00919100): `!=` spells `~=`, `#` starts a comment anywhere, and a
  // UTF-8 byte-order mark is skipped (compares with 0xEF/0xBB/0xBF at 0x00919298..0x009192FF).
  TEST_F(LuaParser, ForkLexicalAdditions)
  {
    EXPECT_TRUE(Bool("return 1 != 2"));
    EXPECT_FALSE(Bool("return 'a' != 'a'"));
    EXPECT_EQ(Num("# a hash comment\nreturn 5 # another"), 5.0);
    EXPECT_EQ(Num("\xEF\xBB\xBFreturn 6"), 6.0);
    EXPECT_TRUE(Contains(LoadError("return 1 ! 2"), "invalid character"));
    EXPECT_TRUE(Contains(LoadError("\xEF\xBBreturn 1"), "invalid character"));
  }

  // Fork: `0x` literals of up to eight hex digits (read_numeral 0x00918440 compares with a
  // lower-case 'x' at 0x009184AF), read as an integer and stored as a float.
  TEST_F(LuaParser, NumberLiterals)
  {
    EXPECT_EQ(Num("return 0x10"), 16.0);
    EXPECT_EQ(Num("return 0xFF"), 255.0);
    EXPECT_EQ(Num("return 0xaBc"), 2748.0);
    EXPECT_EQ(Num("return 0x7fffffff"), 2147483648.0); // 2^31 - 1 rounds to 2^31 as a float
    EXPECT_EQ(Num("return 3.25"), 3.25);
    EXPECT_EQ(Num("return 1e2"), 100.0);
    EXPECT_EQ(Num("return 1.5e-1"), static_cast<double>(0.15f));
    EXPECT_EQ(Num("return 007"), 7.0);
    EXPECT_EQ(Num("return .25"), 0.25);
  }

  // Fork: a constructor may open with `&<hash size>` and a second `&<array size>` (constructor
  // 0x0091B710 compares with '&' at 0x0091B789; message at 0x00D467C4). The hints only size the
  // table.
  TEST_F(LuaParser, ConstructorSizeHints)
  {
    EXPECT_EQ(Num("local t = {&4&8 10, 20} return t[1] + t[2]"), 30.0);
    EXPECT_EQ(Num("local t = {&16} t.a = 1 t.b = 2 return t.a + t.b"), 3.0);
    EXPECT_EQ(Num("local t = {&2 x = 5} return t.x"), 5.0);
    EXPECT_TRUE(Contains(LoadError("local t = {& 'x'}"), "size expected following & (line 1)"));
    EXPECT_TRUE(Contains(LoadError("local t = {&1& }"), "size expected following &"));
  }

  TEST_F(LuaParser, StatementSeparatorsAndScopes)
  {
    EXPECT_EQ(Num("local a = 1; local b = 2; return a + b;"), 3.0);
    EXPECT_EQ(Num("local a = 1 do local a = 2 end return a"), 1.0);
    EXPECT_EQ(Num("local a = 1 local a = a + 1 return a"), 2.0);
    EXPECT_EQ(Num("local function f() return 1 end; return f()"), 1.0);
    EXPECT_EQ(Num("return (((((1)))))"), 1.0);
  }

  struct SyntaxCase
  {
    const char* source;
    const char* expected;
  };

  TEST_F(LuaParser, SyntaxErrorsReportTheProblem)
  {
    const std::vector<SyntaxCase> cases = {
      {"x = ", "test(1): unexpected symbol near `<eof>'"},
      {"if x then", "`end' expected near `<eof>'"},
      {"if x then\nelse\n", "`end' expected (to close `if' at line 1) near `<eof>'"},
      {"while true do\n\n", "`end' expected (to close `while' at line 1)"},
      {"for i = 1 do end", "`,' expected near `do'"},
      {"for i do end", "`=' or `in' expected near `do'"},
      {"f(", "unexpected symbol near `<eof>'"},
      {"local function end", "<name> expected near `end'"},
      {"local 1 = 2", "<name> expected near `1'"},
      {"function f(a, ) end", "<name> or `...' expected near `)'"},
      {"x = 'abc", "unfinished string"},
      {"x = 'abc\ny'", "unfinished string"},
      {"x = [[abc", "unfinished long string"},
      {"--[[ never closed", "unfinished long comment"},
      {"x = 3e", "malformed number near `3e'"},
      {"x = 1..2", "ambiguous syntax (decimal point x string concatenation)"},
      {"x = 1 2", "unexpected symbol near `2'"},
      {"break", "no loop to break"},
      {"return return", "unexpected symbol near `return'"},
      {"return 1 x = 2", "<eof> expected near `x'"},
      {"x = }", "unexpected symbol near `}'"},
      {"a.b:c = 1", "function arguments expected near `='"},
      {"local t = {1, 2", "`}' expected near `<eof>'"},
      {"x = = 1", "unexpected symbol near `='"},
      {"goto x", "`=' expected near `x'"},
      {"x = '\\300'", "escape sequence too large"},
      {"x = \x01", "invalid control char"},
      {"x = \xC3", "invalid character"},
      {"local x = f\n(g)()", "ambiguous syntax (function call x new statement)"},
      {"\n\n\nx = ", "test(4):"},
      {"repeat x = 1", "`until' expected near `<eof>'"},
      {"function a.b:c.d() end", "`(' expected near `.'"},
      {"local a, = 1", "<name> expected near `='"},
      {"x = function", "`(' expected near `<eof>'"},
      {"x = {[1] 2}", "`=' expected near `2'"},
    };
    for (const SyntaxCase& c : cases) {
      const std::string message = LoadError(c.source);
      EXPECT_TRUE(Contains(message, c.expected)) << "source: " << c.source << "\nmessage: " << message;
    }
  }

  TEST_F(LuaParser, LoadstringReportsErrorsAsValues)
  {
    EXPECT_TRUE(Bool("local f, e = loadstring('x =') return f == nil and type(e) == 'string'"));
    EXPECT_TRUE(Contains(Str("local f, e = loadstring('x =') return e"), "[string \"x =\"](1): unexpected symbol"));
    EXPECT_TRUE(Contains(Str("local f, e = loadstring('x =', '=named') return e"), "named(1):"));
    EXPECT_EQ(Num("return loadstring('return 1 + 1')()"), 2.0);
  }

  // Nesting past LUA_MAXPARSERLEVEL (200) and past the 200 locals / 32 upvalues of one function
  // fails with a "too many" message instead of overflowing anything.
  TEST_F(LuaParser, CompileLimits)
  {
    EXPECT_TRUE(Contains(LoadError("x = " + std::string(300, '(') + "1" + std::string(300, ')')), "too many"));
    EXPECT_TRUE(Contains(LoadError("x = " + std::string(300, '{') + std::string(300, '}')), "too many"));
    std::string deepBlocks;
    for (int i = 0; i < 300; ++i) {
      deepBlocks += "do ";
    }
    for (int i = 0; i < 300; ++i) {
      deepBlocks += "end ";
    }
    EXPECT_TRUE(Contains(LoadError(deepBlocks), "too many"));

    std::string manyLocals;
    for (int i = 0; i < 210; ++i) {
      manyLocals += "local v" + std::to_string(i) + " = " + std::to_string(i) + "\n";
    }
    EXPECT_TRUE(Contains(LoadError(manyLocals), "too many local variables (limit=200)"));

    std::string manyUpvalues;
    for (int i = 0; i < 40; ++i) {
      manyUpvalues += "local u" + std::to_string(i) + " = " + std::to_string(i) + "\n";
    }
    manyUpvalues += "return function() return 0";
    for (int i = 0; i < 40; ++i) {
      manyUpvalues += " + u" + std::to_string(i);
    }
    manyUpvalues += " end";
    EXPECT_TRUE(Contains(LoadError(manyUpvalues), "too many upvalues (limit=32)"));

    // Just under the limits loads and runs.
    std::string fewLocals;
    for (int i = 0; i < 150; ++i) {
      fewLocals += "local v" + std::to_string(i) + " = " + std::to_string(i) + "\n";
    }
    EXPECT_EQ(Num(fewLocals + "return v149 + v0"), 149.0);
  }

  // Many constants and a long function body: the constant table and code vector grow.
  TEST_F(LuaParser, LargeChunksCompile)
  {
    std::string source = "local t = {}\n";
    for (int i = 0; i < 3000; ++i) {
      source += "t['key" + std::to_string(i) + "'] = " + std::to_string(i) + ".5\n";
    }
    source += "return t.key2999 + t.key0";
    EXPECT_EQ(Num(source), 3000.0);
  }

  // Every prefix of a valid program, and many byte-level mutations of it, must load or fail with
  // a message; none may crash or escape as an exception.
  TEST_F(LuaParser, TruncatedAndMutatedChunksNeverCrash)
  {
    const std::string program = R"(
      local function f(a, b, ...)
        local t = {1, 2, x = 'y', [3] = {a, b}; n = arg.n}
        for i = 1, 10, 2 do t[i] = (t[i] or 0) + i * 2 end
        for k, v in pairs(t) do if type(v) == 'number' and v > 3 then break end end
        while a < b do a = a + 1 if a == 5 then continue end end
        repeat b = b - 1 until b <= 0
        local s = "str\t\x41" .. [[long]] .. 'q' -- comment
        return t, s, a ~= b and a != b, -a, not b, a .. b, a & b | 0x0F << 1 >> 2
      end
      return f(1, 9, 'extra')
    )";
    for (std::size_t length = 0; length <= program.size(); length += 3) {
      std::string message;
      const int status = Load(program.substr(0, length), &message);
      if (status != 0) {
        EXPECT_FALSE(message.empty()) << "prefix " << length;
      }
    }
    EXPECT_EQ(Load(program), 0);

    std::uint32_t seed = 12345u;
    const auto nextRandom = [&seed]() {
      seed = seed * 1664525u + 1013904223u;
      return seed >> 8;
    };
    const char kAlphabet[] = "()[]{}=~<>!.,;:'\"\\#-+*/^&|0123456789xeE abcdefghijklmnopqrstuvwxyz\n\t\x01\x7F\xEF";
    for (int round = 0; round < 3000; ++round) {
      std::string mutated = program;
      const int edits = 1 + static_cast<int>(nextRandom() % 4u);
      for (int e = 0; e < edits; ++e) {
        const std::size_t at = nextRandom() % mutated.size();
        const char c = kAlphabet[nextRandom() % (sizeof(kAlphabet) - 1u)];
        switch (nextRandom() % 3u) {
        case 0: mutated[at] = c; break;
        case 1: mutated.insert(mutated.begin() + static_cast<std::ptrdiff_t>(at), c); break;
        default: mutated.erase(mutated.begin() + static_cast<std::ptrdiff_t>(at)); break;
        }
      }
      std::string message;
      const int status = Load(mutated, &message);
      if (status != 0) {
        EXPECT_FALSE(message.empty()) << "round " << round;
      }
    }
    EXPECT_EQ(Num("return 40 + 2"), 42.0); // the state is still usable
  }
} // namespace
