// The string library (luaopen_string 0x00926EF0): len, sub, upper/lower, rep, byte/char,
// format with the fork's %Q and %b additions, and the 5.0 pattern functions find, gfind and gsub.

#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"

namespace
{
  using faf_lua_tests::Contains;

  class LuaStringLib : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaStringLib, LenSubCase)
  {
    EXPECT_EQ(Num("return string.len('hello')"), 5.0);
    EXPECT_EQ(Num("return string.len('')"), 0.0);
    EXPECT_EQ(Str("return string.sub('hello', 2, 4)"), "ell");
    EXPECT_EQ(Str("return string.sub('hello', -3)"), "llo");
    EXPECT_EQ(Str("return string.sub('hello', 2)"), "ello");
    EXPECT_EQ(Str("return string.sub('hello', 0)"), "hello");
    EXPECT_EQ(Str("return string.sub('hello', -100, 2)"), "he");
    EXPECT_EQ(Str("return string.sub('hello', 10)"), "");
    EXPECT_EQ(Str("return string.sub('hello', 3, 2)"), "");
    EXPECT_EQ(Str("return string.sub('hello', 2, -2)"), "ell");
    EXPECT_EQ(Str("return string.upper('MiXeD 1!')"), "MIXED 1!");
    EXPECT_EQ(Str("return string.lower('MiXeD 1!')"), "mixed 1!");
    EXPECT_EQ(Str("return string.rep('ab', 3)"), "ababab");
    EXPECT_EQ(Str("return string.rep('x', 0)"), "");
    EXPECT_EQ(Num("return string.len(string.rep('abc', 1000))"), 3000.0);
    EXPECT_EQ(Str("return string.len(12345) .. ''"), "5"); // numbers convert to strings for string functions
  }

  TEST_F(LuaStringLib, ByteAndChar)
  {
    EXPECT_EQ(Num("return string.byte('ABC')"), 65.0);
    EXPECT_EQ(Num("return string.byte('ABC', 2)"), 66.0);
    EXPECT_EQ(Num("return string.byte('ABC', -1)"), 67.0);
    EXPECT_TRUE(Run("return string.byte('ABC', 10)").IsNil());
    EXPECT_TRUE(Run("return string.byte('', 1)").IsNil());
    EXPECT_EQ(Num("return string.byte('\\255')"), 255.0);
    EXPECT_EQ(Str("return string.char(72, 105)"), "Hi");
    EXPECT_EQ(Str("return string.char()"), "");
    EXPECT_EQ(Str("return string.char(0, 65)"), std::string("\0A", 2));
    EXPECT_TRUE(Contains(ErrorOf("return string.char(256)"), "invalid value"));
    EXPECT_TRUE(Contains(ErrorOf("return string.char(-1)"), "invalid value"));
  }

  TEST_F(LuaStringLib, FormatConversions)
  {
    EXPECT_EQ(Str("return string.format('%d', 3.7)"), "3");
    EXPECT_EQ(Str("return string.format('%i|%d', -2, 0)"), "-2|0");
    EXPECT_EQ(Str("return string.format('%5.2f|', 3.14159)"), " 3.14|");
    EXPECT_EQ(Str("return string.format('%x %X %o', 255, 255, 8)"), "ff FF 10");
    EXPECT_EQ(Str("return string.format('%c%c', 72, 105)"), "Hi");
    EXPECT_EQ(Str("return string.format('%e', 1)"), "1.000000e+00");
    EXPECT_EQ(Str("return string.format('%g', 0.5)"), "0.5");
    EXPECT_EQ(Str("return string.format('%G', 1e-10)"), "1E-10");
    EXPECT_EQ(Str("return string.format('%E', 1500)"), "1.500000E+03");
    EXPECT_EQ(Str("return string.format('%.3f', 1/3)"), "0.333");
    EXPECT_EQ(Str("return string.format('%s and %s', 'a', 1)"), "a and 1");
    EXPECT_EQ(Str("return string.format('%10s|%-5d|%+d|%05d', 'r', 3, 5, 42)"), "         r|3    |+5|00042");
    EXPECT_EQ(Str("return string.format('%.3s', 'abcdef')"), "abc");
    EXPECT_EQ(Str("return string.format('100%%')"), "100%");
    EXPECT_EQ(Str("return string.format('no directives')"), "no directives");
    EXPECT_EQ(Str("return string.format('%x', -1)"), "ffffffff");
    // A string of 100 or more characters with no precision is appended whole.
    EXPECT_EQ(Num("return string.len(string.format('<%s>', string.rep('z', 300)))"), 302.0);
  }

  TEST_F(LuaStringLib, FormatErrors)
  {
    EXPECT_TRUE(Contains(ErrorOf("return string.format('%y', 1)"), "invalid option to `format'"));
    EXPECT_TRUE(Contains(ErrorOf("return string.format('%123d', 1)"), "invalid format (width or precision too long)"));
    EXPECT_TRUE(Contains(ErrorOf("return string.format('%1$d', 1)"), "obsolete option (d$) to `format'"));
    EXPECT_TRUE(Contains(ErrorOf("return string.format('%d')"), "bad argument #2 to `format'"));
    EXPECT_TRUE(Contains(ErrorOf("return string.format('%d', 'x')"), "bad argument #2 to `format' (number expected, got string)"));
  }

  // %q writes a string Lua can read back (5.0 addquoted: \" \\ \n escaped, \0 as \000).
  TEST_F(LuaStringLib, FormatQuoted)
  {
    EXPECT_EQ(Str("return string.format('%q', 'say \"hi\"\\\\')"), "\"say \\\"hi\\\"\\\\\"");
    EXPECT_EQ(Str("return string.format('%q', 'a\\nb')"), "\"a\\\nb\"");
    EXPECT_EQ(Str("return string.format('%q', 'z\\0z')"), "\"z\\000z\"");
    EXPECT_TRUE(Bool("local s = 'tab\\t \"q\" back\\\\ nl\\n zero\\0 end' return loadstring('return ' .. string.format('%q', s))() == s"));
  }

  // Fork: %Q quotes with C escapes and \xNN for unprintable bytes (luaI_addquotedbinary
  // 0x009262C0), and %b<T> appends a number's raw little-endian bytes (str_format_helper
  // 0x00926690): F double, f float, d int32, w int16, b byte.
  TEST_F(LuaStringLib, FormatForkConversions)
  {
    EXPECT_EQ(Str("return string.format('%Q', 'a\\nb\"\\1')"), "\"a\\nb\\\"\\x01\"");
    EXPECT_TRUE(Bool("local s = 'x\\0\\255\\t\"' return loadstring('return ' .. string.format('%Q', s))() == s"));
    EXPECT_EQ(Str("return string.format('%bd', 258)"), std::string("\x02\x01\x00\x00", 4));
    EXPECT_EQ(Str("return string.format('%bw', -2)"), std::string("\xFE\xFF", 2));
    EXPECT_EQ(Str("return string.format('%bb', 65)"), "A");
    EXPECT_EQ(Str("return string.format('%bf', 1)"), std::string("\x00\x00\x80\x3F", 4));
    EXPECT_EQ(Str("return string.format('%bF', 1)"), std::string("\x00\x00\x00\x00\x00\x00\xF0\x3F", 8));
    EXPECT_EQ(Str("return string.format('[%bd]', 1)"), std::string("[\x01\x00\x00\x00]", 6));
    EXPECT_EQ(Str("return string.format('%bz', 1)"), ""); // unknown width: nothing
  }

  TEST_F(LuaStringLib, FindPlainAndPatterns)
  {
    EXPECT_EQ(Str("local a, b = string.find('hello world', 'wor') return a .. ',' .. b"), "7,9");
    EXPECT_TRUE(Run("return string.find('hello', 'xyz')").IsNil());
    EXPECT_EQ(Num("return string.find('a.b.c', '.', 1, 1)"), 2.0); // plain: '.' is literal
    EXPECT_EQ(Num("return string.find('a.b.c', '.')"), 1.0);       // pattern: any char
    EXPECT_EQ(Num("return string.find('abcabc', 'b', 3)"), 5.0);
    EXPECT_EQ(Num("return string.find('abcabc', 'b', -2)"), 5.0);
    EXPECT_EQ(Num("return string.find('abc', '')"), 1.0);
    EXPECT_EQ(Str("local a, b, k, v = string.find('key=val', '(%w+)=(%w+)') return a .. b .. k .. v"), "17keyval");
    EXPECT_EQ(Num("return string.find('hello', '^h')"), 1.0);
    EXPECT_TRUE(Run("return string.find('hello', '^e')").IsNil());
    EXPECT_EQ(Num("local a, b = string.find('hello', 'o$') return b"), 5.0);
    EXPECT_EQ(Str("local _, _, p = string.find('abc', '()b') return tostring(p)"), "2"); // position capture
  }

  TEST_F(LuaStringLib, PatternClassesAndQuantifiers)
  {
    const auto match = [this](const char* subject, const char* pattern) {
      return Str(std::string("local s, e = string.find('") + subject + "', '" + pattern + "') return s and string.sub('" + subject + "', s, e) or 'nil'");
    };
    EXPECT_EQ(match("abc 123 def", "%d+"), "123");
    EXPECT_EQ(match("abc 123 def", "%a+"), "abc");
    EXPECT_EQ(match("abc 123", "%s"), " ");
    EXPECT_EQ(match("--x--", "%w"), "x");
    EXPECT_EQ(match("abc!", "%p"), "!");
    EXPECT_EQ(match("abcDEF", "%u+"), "DEF");
    EXPECT_EQ(match("ABCdef", "%l+"), "def");
    EXPECT_EQ(match("zz 1aF zz", "%x+"), "1aF");
    EXPECT_EQ(match("xyz", "[a-y]+"), "xy");
    EXPECT_EQ(match("abc", "[^ab]"), "c");
    EXPECT_EQ(match("a-b", "[%-]"), "-");
    EXPECT_EQ(match("aaa", "a*"), "aaa");
    EXPECT_EQ(match("aaa", "a-"), "");   // lazy, empty
    EXPECT_EQ(match("<a><b>", "<.->"), "<a>");
    EXPECT_EQ(match("<a><b>", "<.*>"), "<a><b>");
    EXPECT_EQ(match("color colour", "colou?r"), "color");
    EXPECT_EQ(match("f(a(b)c)d", "%b()"), "(a(b)c)");
    EXPECT_EQ(match("abcabc", "(abc)%1"), "abcabc");
    EXPECT_EQ(match("x = 10", "%S+$"), "10");
    EXPECT_EQ(match("a.b", "%."), ".");
  }

  TEST_F(LuaStringLib, PatternErrors)
  {
    EXPECT_TRUE(Contains(ErrorOf("string.find('a', '[a')"), "malformed pattern (missing `]')"));
    EXPECT_TRUE(Contains(ErrorOf("string.find('a', '%')"), "malformed pattern (ends with `%')"));
    EXPECT_TRUE(Contains(ErrorOf("string.find('a', '(a')"), "unfinished capture"));
    EXPECT_TRUE(Contains(ErrorOf("string.find('a', '.)')"), "invalid pattern capture"));
    EXPECT_TRUE(Run("return string.find('a', 'a)')").IsNil()); // no special character: a plain search
    EXPECT_TRUE(Contains(ErrorOf("string.find('a', '%b')"), "unbalanced pattern"));
    EXPECT_TRUE(Contains(ErrorOf("string.find('aa', '(a)%2')"), "invalid capture index"));
    EXPECT_TRUE(Contains(ErrorOf("string.find(string.rep('a', 40), string.rep('(a)', 40))"), "too many captures"));
  }

  TEST_F(LuaStringLib, Gsub)
  {
    EXPECT_EQ(Str("local s, n = string.gsub('hello world', 'o', '0') return s .. n"), "hell0 w0rld2");
    EXPECT_EQ(Str("return (string.gsub('aaaa', 'a', 'b', 2))"), "bbaa");
    EXPECT_EQ(Str("return (string.gsub('hello world', '(%w+)', '<%1>'))"), "<hello> <world>");
    EXPECT_EQ(Str("return (string.gsub('abc', '(%w)', '%1%1'))"), "aabbcc");
    EXPECT_TRUE(Contains(ErrorOf("string.gsub('abc', '%w', '%0')"), "invalid capture index")); // %0 is 5.1
    EXPECT_EQ(Str("return (string.gsub('a', 'a', '%%'))"), "%");
    EXPECT_EQ(Str("return (string.gsub('$name is $age', '%$(%w+)', function(k) return k == 'name' and 'Bob' or '42' end))"), "Bob is 42");
    // 5.0: a function result that is not a string removes the match.
    EXPECT_EQ(Str("return (string.gsub('abc', 'b', function() end))"), "ac");
    // Fork: a number result counts as "not a string" too - add_s asks lua_isstring, which is true
    // for strings only in this build (0x0090C800, `cmp eax, 4`).
    EXPECT_EQ(Str("return (string.gsub('abc', 'b', function() return 7 end))"), "ac");
    EXPECT_EQ(Str("return (string.gsub('abc', 'b', function() return '7' end))"), "a7c");
    EXPECT_EQ(Str("local s, n = string.gsub('abc', '', '-') return s .. n"), "-a-b-c-4");
    EXPECT_EQ(Str("local s, n = string.gsub('aaa', '^a', 'b') return s .. n"), "baa1");
    EXPECT_EQ(Str("return (string.gsub('  trim me  ', '^%s*(.-)%s*$', '%1'))"), "trim me");
    EXPECT_TRUE(Contains(ErrorOf("string.gsub('a', 'a', {})"), "bad argument #3 to `gsub' (string or function expected)"));
    EXPECT_TRUE(Contains(ErrorOf("string.gsub('a', 'a', '%2')"), "invalid capture index"));
    EXPECT_EQ(Str("return (string.gsub('abc', '.', string.upper))"), "ABC"); // a C function replaces too
  }

  TEST_F(LuaStringLib, Gfind)
  {
    EXPECT_EQ(Str("local out = '' for w in string.gfind('one two three', '%a+') do out = out .. w .. ';' end return out"), "one;two;three;");
    EXPECT_EQ(Str("local out = '' for k, v in string.gfind('a=1, b=2', '(%w+)=(%w+)') do out = out .. k .. v end return out"), "a1b2");
    EXPECT_EQ(Num("local n = 0 for w in string.gfind('', '%a+') do n = n + 1 end return n"), 0.0);
    EXPECT_EQ(Num("local n = 0 for w in string.gfind('abc', '') do n = n + 1 end return n"), 4.0);
  }
} // namespace
