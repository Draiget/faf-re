// Lua values leaving and re-entering a state: the SCR byte stream (LuaObject::ToByteStream,
// 0x004D2C80, and SCR_FromByteStream, 0x004D2A40) that lobby messages and sim callbacks use, the
// `serialize` library's text archives (0x00923AC0 / 0x00923D20), and string.dump with
// loadstring's binary chunks (LuaDump.cpp, LuaUndump.h).

#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"

namespace
{
  using faf_lua_tests::Contains;
  using LuaPlus::LuaObject;

  std::string ContentOf(const gpg::MemBufferStream& stream)
  {
    return std::string(stream.GetConstBuffer().begin(), stream.GetLength());
  }

  std::string FloatBytes(const float value)
  {
    char bytes[4];
    std::memcpy(bytes, &value, sizeof(bytes));
    return std::string(bytes, sizeof(bytes));
  }

  class LuaByteStream : public faf_lua_tests::LuaFixture
  {
  protected:
    /** The bytes ToByteStream writes for the value `expression` evaluates to, and whether it wrote all of it. */
    std::string Encode(const std::string& expression, bool* complete = nullptr)
    {
      LuaObject value = Run("return " + expression);
      gpg::MemBufferStream stream(16u);
      const bool ok = value.ToByteStream(stream);
      if (complete != nullptr) {
        *complete = ok;
      }
      return ContentOf(stream);
    }

    /** Decodes `bytes` with the capped (remote) decoder, or the uncapped local one. */
    LuaObject Decode(const std::string& bytes, const bool local = false)
    {
      gpg::MemBufferStream stream(gpg::CopyMemBuffer(bytes.data(), bytes.size()));
      const gpg::BinaryReader reader(&stream);
      LuaObject decoder;
      LuaObject out;
      if (local) {
        decoder.SCR_FromLocalByteStream(out, &state, &reader);
      } else {
        decoder.SCR_FromByteStream(out, &state, &reader);
      }
      return out;
    }

    /** Encodes, decodes into the global `rt`, and runs `check` on it. */
    bool RoundTrip(const std::string& expression, const std::string& check)
    {
      const LuaObject decoded = Decode(Encode(expression));
      state.GetGlobals().SetObject("rt", decoded);
      return Bool("return " + check);
    }
  };

  // The wire tags: 0 number (a float follows), 1 string, 2 nil, 3 boolean (a byte follows),
  // 4 table begin, 5 table end.
  TEST_F(LuaByteStream, ScalarEncodings)
  {
    EXPECT_EQ(Encode("nil"), std::string("\x02", 1));
    EXPECT_EQ(Encode("true"), std::string("\x03\x01", 2));
    EXPECT_EQ(Encode("false"), std::string("\x03\x00", 2));
    EXPECT_EQ(Encode("1.5"), std::string("\x00", 1) + FloatBytes(1.5f));
    EXPECT_EQ(Encode("{}"), std::string("\x04\x05", 2));
    EXPECT_EQ(Encode("'abc'").substr(0, 1), std::string("\x01", 1));
    EXPECT_EQ(Encode("{[1] = true}"), std::string("\x04\x00", 2) + FloatBytes(1.0f) + std::string("\x03\x01\x05", 3));
  }

  TEST_F(LuaByteStream, RoundTrips)
  {
    EXPECT_TRUE(RoundTrip("42.25", "rt == 42.25"));
    EXPECT_TRUE(RoundTrip("-0.1", "rt == -0.1"));
    EXPECT_TRUE(RoundTrip("'hello world'", "rt == 'hello world'"));
    EXPECT_TRUE(RoundTrip("''", "rt == ''"));
    EXPECT_TRUE(RoundTrip("true", "rt == true"));
    EXPECT_TRUE(RoundTrip("false", "rt == false"));
    EXPECT_TRUE(RoundTrip("nil", "rt == nil"));
    EXPECT_TRUE(RoundTrip("{1, 2, 3}", "rt[1] == 1 and rt[2] == 2 and rt[3] == 3 and table.getn(rt) == 3"));
    EXPECT_TRUE(RoundTrip("{a = 'x', b = {c = {d = true}}, [10] = 5}", "rt.a == 'x' and rt.b.c.d == true and rt[10] == 5"));
    EXPECT_TRUE(RoundTrip("{[true] = 'yes', [2.5] = 'float key'}", "rt[true] == 'yes' and rt[2.5] == 'float key'"));
  }

  // Functions, userdata and threads cannot travel: inside a table their entries are left out and
  // the call answers false; a table that contains itself is written once.
  TEST_F(LuaByteStream, UnsupportedValuesAreLeftOut)
  {
    bool complete = true;
    const std::string bytes = Encode("{keep = 1, fn = print, [print] = 2, co = coroutine.create(function() end)}", &complete);
    EXPECT_FALSE(complete);
    state.GetGlobals().SetObject("rt", Decode(bytes));
    EXPECT_TRUE(Bool("return rt.keep == 1 and rt.fn == nil and rt.co == nil and table.getsize(rt) == 1"));

    Run("cyclic = {name = 'c'} cyclic.self = cyclic");
    LuaObject cyclic = state.GetGlobal("cyclic");
    gpg::MemBufferStream stream(16u);
    EXPECT_FALSE(cyclic.ToByteStream(stream));
    state.GetGlobals().SetObject("rt", Decode(ContentOf(stream)));
    EXPECT_TRUE(Bool("return rt.name == 'c' and rt.self == nil"));
  }

  TEST_F(LuaByteStream, MalformedStreamsFailCleanly)
  {
    // A nil key or value inside a table throws instead of ending the process.
    const std::string nilKey = std::string("\x04\x02\x00", 3) + FloatBytes(1.0f) + std::string("\x05", 1);
    EXPECT_THROW((void)Decode(nilKey), std::runtime_error);
    const std::string nilValue = std::string("\x04\x00", 2) + FloatBytes(1.0f) + std::string("\x02\x05", 2);
    EXPECT_THROW((void)Decode(nilValue), std::runtime_error);
    const std::string nanKey = std::string("\x04\x00", 2) + FloatBytes(std::numeric_limits<float>::quiet_NaN()) + std::string("\x03\x01\x05", 3);
    EXPECT_THROW((void)Decode(nanKey), std::runtime_error);
    // A short read throws too.
    EXPECT_ANY_THROW((void)Decode(std::string("\x00\x01", 2)));
    EXPECT_ANY_THROW((void)Decode(std::string("\x04\x00", 2)));
    // An unknown tag or a stray end-of-table marker reads as nil.
    EXPECT_TRUE(Decode(std::string("\x09", 1)).IsNil());
    EXPECT_TRUE(Decode(std::string("\x05", 1)).IsNil());
    EXPECT_EQ(Num("return 1 + 1"), 2.0);
  }

  // Tables nested deeper than 256 arrive cut at that depth; the local decoder rebuilds them whole.
  TEST_F(LuaByteStream, NestingCapForRemoteStreams)
  {
    std::string bytes;
    constexpr int kDepth = 300;
    for (int i = 0; i < kDepth; ++i) {
      bytes += std::string("\x04\x00", 2) + FloatBytes(1.0f);
    }
    bytes += std::string("\x03\x01", 2); // innermost value
    for (int i = 0; i < kDepth; ++i) {
      bytes += std::string("\x05", 1);
    }
    const std::string depthOf = "local d, t = 0, rt while type(t) == 'table' do d = d + 1 t = t[1] end return d";
    state.GetGlobals().SetObject("rt", Decode(bytes));
    EXPECT_EQ(Num(depthOf), 256.0);
    state.GetGlobals().SetObject("rt", Decode(bytes, true));
    EXPECT_EQ(Num(depthOf), 300.0);
  }

  // ---------------------------------------------------------------------------------------------

  class LuaSerializeLib : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaSerializeLib, TextArchiveRoundTrip)
  {
    EXPECT_TRUE(Bool("return type(serialize.tostring) == 'cfunction' and type(serialize.fromstring) == 'cfunction'"));
    EXPECT_TRUE(Bool("local s = serialize.tostring(1.5, 'two', true) return type(s) == 'string' and string.len(s) > 0"));
    EXPECT_TRUE(Bool("local a, b, c = serialize.fromstring(serialize.tostring(1.5, 'two', true)) return a == 1.5 and b == 'two' and c == true"));
    EXPECT_TRUE(Bool(R"(
      local t = {1, 2, x = 'y', sub = {deep = 4}}
      local back = serialize.fromstring(serialize.tostring(t))
      return back ~= t and back[2] == 2 and back.x == 'y' and back.sub.deep == 4)"));
    EXPECT_TRUE(Bool(R"(
      local shared = {}
      local t = {a = shared, b = shared}
      local back = serialize.fromstring(serialize.tostring(t))
      return back.a == back.b)"));
  }

  // ---------------------------------------------------------------------------------------------

  class LuaDump : public faf_lua_tests::LuaFixture
  {
  };

  TEST_F(LuaDump, DumpedFunctionsLoadAndRun)
  {
    EXPECT_EQ(Str("local s = string.dump(function() end) return string.sub(s, 1, 4)"), "\x1BLua");
    EXPECT_EQ(Num(R"(
      local f = function(a, b) local t = {a, b, 'k', 1.5} return t[1] * t[2] + t[4] end
      local g = loadstring(string.dump(f))
      return g(3, 4))"), 13.5);
    EXPECT_EQ(Str(R"(
      local f = function(s) return string.upper(s) .. '!' end
      return loadstring(string.dump(f))('x'))"), "X!");
    // Nested prototypes, loops, varargs and upvalue-free closures survive the trip.
    EXPECT_EQ(Num(R"(
      local f = function(...)
        local inc = function(x) return x + 1 end
        local s = 0
        for i = 1, arg.n do s = s + inc(arg[i]) end
        while s > 100 do s = s - 100 end
        return s
      end
      return loadstring(string.dump(f))(1, 2, 3))"), 9.0);
    // The same function dumped twice gives the same bytes.
    EXPECT_TRUE(Bool("local f = function(a) return a * 2 end return string.dump(f) == string.dump(f)"));
  }

  TEST_F(LuaDump, BadBinaryChunksFailToLoad)
  {
    EXPECT_TRUE(Contains(ErrorOf("string.dump(print)"), "bad argument #1 to `dump'"));
    const std::string truncated = Str(R"(
      local s = string.dump(function(a) return a + 1 end)
      local f, e = loadstring(string.sub(s, 1, string.len(s) - 5))
      return tostring(f) .. ' ' .. tostring(e))");
    EXPECT_TRUE(Contains(truncated, "nil")) << truncated;
    EXPECT_TRUE(Contains(truncated, "unexpected end of file")) << truncated;
    const std::string header = Str("local f, e = loadstring('\\27Lua') return tostring(e)");
    EXPECT_TRUE(Contains(header, "unexpected end of file")) << header;
    // Every prefix of a dump fails cleanly.
    EXPECT_TRUE(Bool(R"(
      local s = string.dump(function(a, b) local t = {a = a} return t.a .. b end)
      for n = 1, string.len(s) - 1, 5 do
        local f, e = loadstring(string.sub(s, 1, n))
        if f ~= nil or type(e) ~= 'string' then return false end
      end
      return loadstring(s) ~= nil)"));
  }
} // namespace
