// The LuaPlus C++ API the engine drives Lua through (LuaObject.h, LuaObjectApi.inl,
// LuaObjectPlusRefs.inl, LuaObjectClasses.inl): building tables, writing and reading by string,
// number and object keys, dotted lookups, lengths, type queries and conversions, metatables,
// registered C functions, LuaFunction calls, table iteration, stack objects, thread states, and
// references that keep their values alive across collections.
//
// The calls that raise Lua errors are made from inside a C function that Lua calls through pcall,
// as the engine makes them: the error then has a frame to unwind to.

#include <map>
#include <string>
#include <gtest/gtest.h>

#include "LuaTestSupport.h"
#include "lua/LuaTableIterator.h"

namespace
{
  using faf_lua_tests::Contains;
  using LuaPlus::LuaObject;
  using LuaPlus::LuaState;

  class LuaObjectApi : public faf_lua_tests::LuaFixture
  {
  protected:
    LuaObject NewTable()
    {
      LuaObject table;
      table.AssignNewTable(&state, 0, 0);
      return table;
    }
  };

  // ---------------------------------------------------------------------------------------------
  // C functions the tests register.

  int Twice(lua_State* const L)
  {
    lua_pushnumber(L, lua_tonumber(L, 1) * 2.0f);
    return 1;
  }

  int AddUpvalue(lua_State* const L)
  {
    lua_pushnumber(L, lua_tonumber(L, 1) + lua_tonumber(L, lua_upvalueindex(1)));
    return 1;
  }

  // Uses the LuaState argument helpers a binding uses: CheckString, OptNumber, CheckAny.
  int Describe(lua_State* const L)
  {
    LuaState* const state = LuaState::CastState(L);
    size_t length = 0;
    const char* const text = state->CheckString(1, &length);
    const lua_Number count = state->OptNumber(2, 7.0f);
    lua_pushfstring(L, "%s/%d/%d", text, static_cast<int>(length), static_cast<int>(count));
    return 1;
  }

  int NeedsNumber(lua_State* const L)
  {
    lua_pushnumber(L, LuaState::CastState(L)->CheckNumber(1) + 1.0f);
    return 1;
  }

  int RaisesFormatted(lua_State* const L)
  {
    LuaState::Error(LuaState::CastState(L), "formatted %d %s", 5, "words");
    return 0;
  }

  int GetStringOfArgument(lua_State* const L)
  {
    const LuaObject value(LuaState::CastState(L), 1);
    lua_pushstring(L, value.GetString());
    return 1;
  }

  int GetNumberOfArgument(lua_State* const L)
  {
    const LuaObject value(LuaState::CastState(L), 1);
    lua_pushnumber(L, static_cast<lua_Number>(value.GetNumber()));
    return 1;
  }

  int GetBooleanOfArgument(lua_State* const L)
  {
    const LuaObject value(LuaState::CastState(L), 1);
    lua_pushboolean(L, value.GetBoolean() ? 1 : 0);
    return 1;
  }

  int WrapAsFunction(lua_State* const L)
  {
    const LuaPlus::LuaFunction<void> function(LuaObject(LuaState::CastState(L), 1));
    (void)function;
    lua_pushboolean(L, 1);
    return 1;
  }

  // ---------------------------------------------------------------------------------------------

  TEST_F(LuaObjectApi, TablesBySetterAndGetter)
  {
    LuaObject t = NewTable();
    t.SetString("name", "unit");
    t.SetNumber("health", 12.5f);
    t.SetInteger("count", 3);
    t.SetBoolean("alive", true);
    t.SetString(1, "first");
    t.SetNumber(2, 2.5f);
    t.SetInteger(3, -4);
    t.SetBoolean(4, false);

    EXPECT_STREQ(t["name"].GetString(), "unit");
    EXPECT_EQ(t.GetByName("health").GetNumber(), 12.5);
    EXPECT_EQ(t["count"].GetInteger(), 3);
    EXPECT_TRUE(t["alive"].GetBoolean());
    EXPECT_STREQ(t[1].GetString(), "first");
    EXPECT_EQ(t.GetByIndex(2).GetNumber(), 2.5);
    EXPECT_EQ(t[3].GetInteger(), -4);
    EXPECT_TRUE(t[4].IsBoolean());
    EXPECT_FALSE(t[4].GetBoolean());
    EXPECT_TRUE(t["missing"].IsNil());
    EXPECT_TRUE(t[99].IsNil());

    // The values are visible from Lua.
    state.GetGlobals().SetObject("api_t", t);
    EXPECT_EQ(Str("return api_t.name .. api_t[1] .. api_t.count"), "unitfirst3");

    t.SetNil("name");
    t.SetNil(1);
    EXPECT_TRUE(t["name"].IsNil());
    EXPECT_TRUE(t[1].IsNil());
    t.SetString("name", nullptr); // a null string writes nil
    EXPECT_TRUE(t["name"].IsNil());
  }

  TEST_F(LuaObjectApi, ObjectKeys)
  {
    LuaObject t = NewTable();
    LuaObject key = NewTable();
    LuaObject numberKey;
    numberKey.AssignNumber(&state, 7.0);
    LuaObject stringKey;
    stringKey.AssignString(&state, "s");

    t.SetString(key, "by table");
    t.SetNumber(numberKey, 1.5f);
    t.SetInteger(stringKey, 9);
    EXPECT_STREQ(t[key].GetString(), "by table");
    EXPECT_STREQ(t.GetByObject(key).GetString(), "by table");
    EXPECT_EQ(t[7].GetNumber(), 1.5);   // a number key reads back by index
    EXPECT_EQ(t["s"].GetInteger(), 9);  // a string key by name

    t.SetBoolean(key, true);
    EXPECT_TRUE(t[key].GetBoolean());
    t.SetNil(key);
    EXPECT_TRUE(t[key].IsNil());

    LuaObject value = NewTable();
    value.SetString("inner", "yes");
    t.SetObject(key, value);
    t.SetObject("named", value);
    t.SetObject(5, value);
    t.SetObject("pointer", &value);
    EXPECT_STREQ(t[key]["inner"].GetString(), "yes");
    EXPECT_TRUE(t["named"] == value);
    EXPECT_TRUE(t[5] == t["pointer"]);
  }

  TEST_F(LuaObjectApi, CreateTableAndLookup)
  {
    LuaObject root = NewTable();
    LuaObject a = root.CreateTable("a", 0, 0);
    LuaObject b = a.CreateTable("b", 4, 0);
    b.SetString(1, "one");
    b.SetNumber("x", 3.0f);
    LuaObject numbered = root.CreateTable(3, 0, 0);
    numbered.SetString("v", "three");
    LuaObject keyed = root.CreateTable(a, 0, 2);
    keyed.SetString("by", "object");

    EXPECT_STREQ(root.Lookup("a.b.1").GetString(), "one");
    EXPECT_EQ(root.Lookup("a.b.x").GetNumber(), 3.0);
    EXPECT_STREQ(root.Lookup("3.v").GetString(), "three");
    EXPECT_TRUE(root.Lookup("a.missing.deeper").IsNil());
    EXPECT_TRUE(root.Lookup("a..b").IsNil() || !root.Lookup("a..b").m_state);
    EXPECT_STREQ(root[a]["by"].GetString(), "object");
    EXPECT_TRUE(root.Lookup("").IsTable()); // an empty path is the object itself
  }

  TEST_F(LuaObjectApi, TypesAndTypeNames)
  {
    const LuaObject nilValue = Run("return nil");
    const LuaObject boolValue = Run("return false");
    const LuaObject numberValue = Run("return 1.5");
    const LuaObject stringValue = Run("return 'str'");
    const LuaObject tableValue = Run("return {}");
    const LuaObject luaFunction = Run("return function() end");
    const LuaObject cFunction = Run("return print");
    const LuaObject thread = Run("return coroutine.create(function() end)");

    EXPECT_TRUE(nilValue.IsNil());
    EXPECT_TRUE(boolValue.IsBoolean());
    EXPECT_TRUE(numberValue.IsNumber());
    EXPECT_TRUE(stringValue.IsString());
    EXPECT_TRUE(tableValue.IsTable());
    EXPECT_TRUE(luaFunction.IsFunction());
    EXPECT_TRUE(cFunction.IsFunction());
    EXPECT_FALSE(tableValue.IsFunction());
    EXPECT_FALSE(numberValue.IsString());
    EXPECT_FALSE(stringValue.IsNumber());

    EXPECT_STREQ(nilValue.TypeName(), "nil");
    EXPECT_STREQ(boolValue.TypeName(), "boolean");
    EXPECT_STREQ(numberValue.TypeName(), "number");
    EXPECT_STREQ(stringValue.TypeName(), "string");
    EXPECT_STREQ(tableValue.TypeName(), "table");
    EXPECT_STREQ(luaFunction.TypeName(), "function");
    EXPECT_STREQ(cFunction.TypeName(), "cfunction");
    EXPECT_STREQ(thread.TypeName(), "thread");

    EXPECT_EQ(numberValue.Type(), LUA_TNUMBER);
    EXPECT_EQ(stringValue.Type(), LUA_TSTRING);
    EXPECT_EQ(tableValue.Type(), LUA_TTABLE);
    EXPECT_EQ(luaFunction.Type(), LUA_TFUNCTION);
    EXPECT_EQ(cFunction.Type(), LUA_CFUNCTION);
    EXPECT_EQ(thread.Type(), LUA_TTHREAD);
  }

  TEST_F(LuaObjectApi, TruthinessAndComparison)
  {
    EXPECT_FALSE(static_cast<bool>(Run("return nil")));
    EXPECT_FALSE(static_cast<bool>(Run("return false")));
    EXPECT_TRUE(static_cast<bool>(Run("return 0")));
    EXPECT_TRUE(static_cast<bool>(Run("return ''")));
    EXPECT_FALSE(static_cast<bool>(LuaObject()));

    EXPECT_TRUE(Run("return 2") == Run("return 2"));
    EXPECT_FALSE(Run("return 2") == Run("return '2'"));
    EXPECT_TRUE(Run("return 'abc'") == Run("return 'ab' .. 'c'"));
    EXPECT_FALSE(Run("return {}") == Run("return {}"));
    EXPECT_TRUE(Run("return 1") < Run("return 2"));
    EXPECT_FALSE(Run("return 2") < Run("return 1"));
    EXPECT_TRUE(Run("return 'a'") < Run("return 'b'"));
  }

  TEST_F(LuaObjectApi, Conversions)
  {
    // ToNumber / ToInteger of a numeric string are not asserted: retail (0x009073B0, 0x00907380)
    // checks luaV_tonumber's answer but then reads the object's own payload (`fld [esi+10h]`,
    // `cvttss2si [esi+10h]`), the string pointer's bits, not the parsed number.
    LuaObject numericString = Run("return ' 12.5 '");
    EXPECT_TRUE(numericString.IsConvertibleToNumber());
    EXPECT_TRUE(numericString.IsConvertibleToInteger());
    EXPECT_TRUE(numericString.IsConvertibleToString());
    LuaObject realNumber = Run("return -12.75");
    EXPECT_EQ(realNumber.ToNumber(), -12.75);
    EXPECT_EQ(realNumber.ToInteger(), -12);

    LuaObject word = Run("return 'word'");
    EXPECT_FALSE(word.IsConvertibleToNumber());
    EXPECT_EQ(word.ToNumber(), 0.0);
    EXPECT_EQ(word.ToInteger(), 0);
    EXPECT_STREQ(word.ToString(), "word");
    EXPECT_EQ(word.ToStrLen(), 4);

    LuaObject number = Run("return 0.1");
    EXPECT_EQ(number.ToInteger(), 0);
    EXPECT_STREQ(number.ToString(), "0.10000000149012"); // converts in place, as luaV_tostring does
    EXPECT_TRUE(number.IsString());

    LuaObject integer = Run("return 42");
    EXPECT_EQ(integer.ToStrLen(), 2);
    EXPECT_STREQ(integer.GetString(), "42");

    LuaObject table = Run("return {}");
    EXPECT_FALSE(table.IsConvertibleToString());
    EXPECT_EQ(table.ToString(), nullptr);
    EXPECT_EQ(table.ToStrLen(), 0);
    EXPECT_FALSE(Run("return nil").IsConvertibleToNumber());

    LuaObject assigned;
    assigned.AssignInteger(&state, -7);
    EXPECT_EQ(assigned.GetNumber(), -7.0);
    assigned.AssignBoolean(&state, true);
    EXPECT_TRUE(assigned.GetBoolean());
    assigned.AssignNil(&state);
    EXPECT_TRUE(assigned.IsNil());
    EXPECT_FALSE(assigned.GetBoolean()); // nil reads as false
    assigned.AssignString(&state, nullptr);
    EXPECT_TRUE(assigned.IsNil());
  }

  TEST_F(LuaObjectApi, GettersRaiseTypeErrorsInsideLua)
  {
    LuaObject globals = state.GetGlobals();
    globals.Register("probe_string", GetStringOfArgument, 0);
    globals.Register("probe_number", GetNumberOfArgument, 0);
    globals.Register("probe_boolean", GetBooleanOfArgument, 0);
    globals.Register("probe_function", WrapAsFunction, 0);

    EXPECT_EQ(Str("return probe_string('ok')"), "ok");
    EXPECT_EQ(Num("return probe_number(4)"), 4.0);
    EXPECT_TRUE(Bool("return probe_boolean(true)"));
    EXPECT_TRUE(Bool("return probe_function(print)"));

    EXPECT_TRUE(Contains(Str("local ok, e = pcall(probe_string, 5) return e"), "get as string"));
    EXPECT_TRUE(Contains(Str("local ok, e = pcall(probe_number, 'x') return e"), "get as number"));
    EXPECT_TRUE(Contains(Str("local ok, e = pcall(probe_boolean, 1) return e"), "get as boolean"));
    EXPECT_TRUE(Contains(Str("local ok, e = pcall(probe_function, {}) return e"), "call"));
    EXPECT_FALSE(Bool("return pcall(probe_function, 3)"));
    EXPECT_EQ(Num("return 1"), 1.0); // the state recovered
  }

  TEST_F(LuaObjectApi, LengthsAndCounts)
  {
    LuaObject list = Run("return {10, 20, 30, n = 3, extra = true}");
    EXPECT_EQ(list.GetCount(), 3);
    EXPECT_EQ(list.GetN(), 3);
    EXPECT_EQ(list.GetTableCount(), 5);

    LuaObject plain = Run("return {1, 2, 3, 4}");
    EXPECT_EQ(plain.GetN(), 4);
    plain.SetN(2);
    EXPECT_EQ(plain.GetN(), 2);
    EXPECT_EQ(Run("return {}").GetTableCount(), 0);
  }

  TEST_F(LuaObjectApi, InsertRemoveSort)
  {
    LuaObject list = NewTable();
    for (const int value : {5, 3, 9}) {
      LuaObject item;
      item.AssignInteger(&state, value);
      list.Insert(item);
    }
    LuaObject front;
    front.AssignInteger(&state, 1);
    list.Insert(1, front);
    EXPECT_EQ(list.GetN(), 4);
    EXPECT_EQ(list[1].GetInteger(), 1);
    EXPECT_EQ(list[2].GetInteger(), 5);

    list.Sort();
    EXPECT_EQ(list[1].GetInteger(), 1);
    EXPECT_EQ(list[2].GetInteger(), 3);
    EXPECT_EQ(list[3].GetInteger(), 5);
    EXPECT_EQ(list[4].GetInteger(), 9);

    list.Remove(1);
    EXPECT_EQ(list.GetN(), 3);
    EXPECT_EQ(list[1].GetInteger(), 3);
    EXPECT_TRUE(list[4].IsNil());
  }

  TEST_F(LuaObjectApi, Metatables)
  {
    LuaObject object = NewTable();
    LuaObject meta = NewTable();
    LuaObject base = NewTable();
    base.SetString("inherited", "from base");
    meta.SetObject("__index", base);
    object.SetMetaTable(meta);

    EXPECT_TRUE(object.GetMetaTable() == meta);
    EXPECT_TRUE(object["inherited"].IsNil()); // operator[] reads raw
    state.GetGlobals().SetObject("api_obj", object);
    EXPECT_EQ(Str("return api_obj.inherited"), "from base");
    // A table with none of its own answers the shared default (see LuaMetatable.EveryValueHasAMetatable).
    EXPECT_TRUE(NewTable().GetMetaTable() == NewTable().GetMetaTable());
    EXPECT_FALSE(NewTable().GetMetaTable() == meta);
  }

  TEST_F(LuaObjectApi, RegisteredFunctions)
  {
    LuaObject globals = state.GetGlobals();
    globals.Register("twice", Twice, 0);
    globals.Register("describe", Describe, 0);
    globals.Register("needs_number", NeedsNumber, 0);
    globals.Register("raises_formatted", RaisesFormatted, 0);

    lua_pushnumber(L(), 100.0f); // the upvalue Register takes from the stack
    globals.Register("add_hundred", AddUpvalue, 1);

    EXPECT_EQ(Num("return twice(21)"), 42.0);
    EXPECT_EQ(Str("return type(twice)"), "cfunction");
    EXPECT_EQ(Num("return add_hundred(5)"), 105.0);
    EXPECT_EQ(Str("return describe('abc')"), "abc/3/7");
    EXPECT_EQ(Str("return describe('ab', 3)"), "ab/2/3");
    EXPECT_EQ(Str("return describe(12)"), "12/2/7"); // a number is a string to CheckString
    EXPECT_TRUE(Contains(ErrorOf("return describe({})"), "bad argument #1 to `describe' (string expected, got table)"));
    EXPECT_EQ(Num("return needs_number(1)"), 2.0);
    EXPECT_TRUE(Contains(ErrorOf("return needs_number('x')"), "bad argument #1 to `needs_number' (number expected, got string)"));
    EXPECT_TRUE(Contains(ErrorOf("raises_formatted()"), "formatted 5 words"));
  }

  TEST_F(LuaObjectApi, LuaFunctionCalls)
  {
    Run("function api_add(a, b) return a + b end "
        "function api_concat(a, b) return a .. b end "
        "function api_is_big(x) return x > 10 end "
        "function api_make(n) return {value = n} end "
        "api_calls = 0 function api_count() api_calls = api_calls + 1 end "
        "function api_echo(s) return s .. '!' end");

    const LuaPlus::LuaFunction<double> add(state.GetGlobal("api_add"));
    EXPECT_EQ(add(2, 3), 5.0);
    EXPECT_EQ(add(1.5, 0.25), 1.75);

    const LuaPlus::LuaFunction<bool> isBig(state.GetGlobal("api_is_big"));
    EXPECT_TRUE(isBig(11));
    EXPECT_FALSE(isBig(3));

    const LuaPlus::LuaFunction<LuaObject> make(state.GetGlobal("api_make"));
    const LuaObject made = make(8);
    EXPECT_EQ(made["value"].GetInteger(), 8);

    const LuaPlus::LuaFunction<LuaObject> concat(state.GetGlobal("api_concat"));
    const LuaObject joined = concat("ab", std::string("cd"));
    EXPECT_STREQ(joined.GetString(), "abcd");

    LuaObject table = NewTable();
    const LuaObject passed = make(table);
    EXPECT_TRUE(passed["value"] == table);

    const LuaPlus::LuaFunction<void> count(state.GetGlobal("api_count"));
    count();
    count.Call();
    EXPECT_EQ(Num("return api_calls"), 2.0);
    EXPECT_TRUE(count.Call_x_Bool() == false);

    const LuaPlus::LuaFunction<const char*> echo(state.GetGlobal("api_echo"));
    EXPECT_STREQ(echo("hey"), "hey!");
    EXPECT_EQ(lua_gettop(L()), 0); // every call restored the stack
  }

  TEST_F(LuaObjectApi, TableIteratorVisitsEveryEntry)
  {
    LuaObject t = Run("return {10, 20, a = 'x', b = 'y', [true] = 'bool'}");
    std::map<std::string, std::string> seen;
    int visits = 0;
    for (LuaPlus::LuaTableIterator it(t, 1); it; it.Next()) {
      ++visits;
      LuaObject key = it.GetKey();
      LuaObject value = it.GetValue();
      const std::string keyText = key.IsBoolean() ? "true" : std::string(key.ToString());
      seen[keyText] = value.ToString();
    }
    EXPECT_EQ(visits, 5);
    EXPECT_EQ(seen["1"], "10");
    EXPECT_EQ(seen["2"], "20");
    EXPECT_EQ(seen["a"], "x");
    EXPECT_EQ(seen["b"], "y");
    EXPECT_EQ(seen["true"], "bool");

    LuaObject emptyTable = Run("return {}");
    LuaPlus::LuaTableIterator empty(emptyTable, 1);
    EXPECT_FALSE(empty.IsValid());

    LuaPlus::LuaTableIterator again(t, 1);
    int count = 0;
    while (again.IsValid()) {
      ++count;
      ++again;
    }
    EXPECT_EQ(count, 5);
    again.Reset();
    EXPECT_TRUE(again.IsValid());
  }

  TEST_F(LuaObjectApi, CopiesShareTheValue)
  {
    LuaObject original = NewTable();
    LuaObject copy(original);
    LuaObject assigned;
    assigned = original;
    copy.SetInteger("x", 1);
    assigned.SetInteger("y", 2);
    EXPECT_EQ(original["x"].GetInteger(), 1);
    EXPECT_EQ(original["y"].GetInteger(), 2);
    EXPECT_TRUE(copy == assigned);

    assigned = LuaObject();
    EXPECT_EQ(assigned.m_state, nullptr);
    copy.Reset();
    EXPECT_EQ(copy.m_state, nullptr);
    EXPECT_FALSE(copy.IsNil()); // an unbound object is not even nil
    EXPECT_EQ(original["x"].GetInteger(), 1);
  }

  // A LuaObject is a root: what it holds survives collections with no Lua reference left, and goes
  // once the object lets go.
  TEST_F(LuaObjectApi, ReferencesSurviveCollection)
  {
    Run("api_weak = setmetatable({}, {__mode = 'v'})");
    LuaObject held = NewTable();
    held.SetString("v", "alive");
    state.GetGlobal("api_weak").SetObject(1, held);

    for (int i = 0; i < 3; ++i) {
      Run("local junk = {} for i = 1, 2000 do junk[i] = {i} end junk = nil collectgarbage()");
    }
    EXPECT_STREQ(held["v"].GetString(), "alive");
    EXPECT_TRUE(Bool("return api_weak[1] ~= nil and api_weak[1].v == 'alive'"));

    held.Reset();
    Run("collectgarbage() collectgarbage()");
    EXPECT_TRUE(Bool("return api_weak[1] == nil"));

    // Strings held only from C++ stay too.
    LuaObject text;
    text.AssignString(&state, "kept string value");
    Run("collectgarbage()");
    EXPECT_STREQ(text.GetString(), "kept string value");
  }

  TEST_F(LuaObjectApi, LightUserdataRoundTrip)
  {
    int marker = 0;
    LuaObject t = NewTable();
    t.SetLightUserData("p", &marker);
    t.SetLightUserData(1, &marker);
    LuaObject light;
    light.AssignLightUserData(&state, &marker);
    EXPECT_TRUE(light.IsLightUserData());
    EXPECT_TRUE(light.IsUserData());
    EXPECT_TRUE(t["p"].IsLightUserData());
    EXPECT_TRUE(t["p"] == light);
    EXPECT_TRUE(t[1] == light);

    light.PushStack(L());
    EXPECT_EQ(lua_touserdata(L(), -1), &marker);
    lua_settop(L(), 0);
    state.GetGlobals().SetObject("api_light", light);
    EXPECT_EQ(Str("return type(api_light)"), "userdata");
  }

  TEST_F(LuaObjectApi, StackObjectsAndStateQueries)
  {
    const LuaPlus::LuaStackObject number = state.PushNumber(3.5f);
    EXPECT_EQ(number.GetNumber(), 3.5);
    EXPECT_EQ(number.GetInteger(), 3);
    const LuaPlus::LuaStackObject nil = state.PushNil();
    EXPECT_TRUE(nil.IsNil());
    EXPECT_FALSE(nil.GetBoolean());
    const LuaPlus::LuaStackObject text = LuaPlus::PushStringAndCaptureStackObject(&state, "pushed");
    EXPECT_STREQ(text.GetString(), "pushed");
    EXPECT_EQ(state.GetTop(), 3);
    EXPECT_STREQ(state.Stack(3).GetString(), "pushed");

    LuaObject fromStack(number);
    EXPECT_EQ(fromStack.GetNumber(), 3.5);
    lua_settop(L(), 0);

    LuaObject table = Run("return {field = 'f'}");
    table.PushStack(L());
    const LuaPlus::LuaStackObject tableOnStack(&state, 1);
    EXPECT_STREQ(tableOnStack.GetByName("field").GetString(), "f");
    lua_settop(L(), 0);

    EXPECT_TRUE(state.IsRootState());
    EXPECT_EQ(state.GetRootState(), &state);
    EXPECT_EQ(LuaState::CastState(L()), &state);
    EXPECT_EQ(table.GetActiveState(), &state);
    EXPECT_EQ(table.GetActiveCState(), L());
    EXPECT_TRUE(state.GetGlobal("no_such_global").IsNil());
    EXPECT_TRUE(state.GetGlobal("string").IsTable());
  }

  // A thread state shares the root's globals and runs code of its own.
  TEST_F(LuaObjectApi, ThreadStatesShareGlobals)
  {
    LuaState thread(&state);
    EXPECT_FALSE(thread.IsRootState());
    EXPECT_EQ(thread.GetRootState(), &state);
    EXPECT_TRUE(thread.GetThreadObject() != nullptr);

    lua_State* const T = thread.GetCState();
    const char* const chunk = "shared_from_thread = 77 return 1";
    ASSERT_EQ(luaL_loadbuffer(T, chunk, std::char_traits<char>::length(chunk), "=thread"), 0);
    ASSERT_EQ(LuaCallProtected(T, 0, 1), 0);
    lua_settop(T, 0);
    EXPECT_EQ(Num("return shared_from_thread"), 77.0);
  }
} // namespace
