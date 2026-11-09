#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kIsKeyDownHelpText = "IsKeyDown(keyCode)";
  constexpr const char* kKeycodeMauiToMSWHelpText =
    "int KeycodeMauiToMSW(int) - given a char code from a key event, returns the MS Windows char code";
  constexpr const char* kKeycodeMSWToMauiHelpText =
    "int KeycodeMSWToMaui(int) - given a MS Windows char code, returns the Maui char code";
  constexpr const char* kINAddKeyMapTableHelpText = "IN_AddKeyMapTable(keyMapTable) - add a set of key mappings";
  constexpr const char* kINRemoveKeyMapTableHelpText =
    "IN_RemoveKeyMapTable(keyMapTable) - removes the keys from the key map";
  constexpr const char* kINClearKeyMapHelpText = "IN_ClearKeyMap() - clears all key mappings";

  UiKeyActionMap::~UiKeyActionMap()
  {
    ReleaseStrings();
  }

  UiKeyActionMap gUiKeyActionMap{};

  /**
   * Address: 0x00BE4810 (FUN_00BE4810)
   *
   * What it does:
   * Compiler-emitted CRT static-initializer stub for this global: calls
   * `UiKeyRepeatMap`'s default constructor (inlined in the binary rather
   * than emitted as a separate symbol -- `sub_83C220`/`buy_head`'s "third
   * split shape", already cited in `RbTree.h`, followed by the self-link +
   * `isNil=1` + `size=0` this member-initializer's constructor performs),
   * then `atexit`-registers the matching teardown (`sub_C06720`). No
   * hand-written call exists for this stub because none is needed: it is
   * purely a consequence of this global declaration existing, the same
   * "compiler-emitted, no source line" category as base-ctor chaining.
   * Registered in the binary's CRT static-init array (`__xc_a` lane).
   */
  UiKeyRepeatMap gUiKeyRepeatMap{};

  void AppendLegacyStringOrThrow(
    fa::string& destination,
    const char* const text,
    const std::size_t length
  )
  {
    if (length > fa::string::maxCapGuard - destination.size()) {
      throw std::length_error("legacy string too long");
    }
    if (!destination.append(text, length)) {
      throw std::bad_alloc{};
    }
  }

  void AppendLegacyStringOrThrow(
    fa::string& destination,
    const std::size_t count,
    const char value
  )
  {
    if (count > fa::string::maxCapGuard - destination.size()) {
      throw std::length_error("legacy string too long");
    }
    if (!destination.append(count, value)) {
      throw std::bad_alloc{};
    }
  }

  /**
   * Address: 0x00838FD0 (FUN_00838FD0, Moho::CUIKeyHandler::AddKeyMapTable)
   *
   * What it does:
   * Iterates one Lua key-map table, parses each key token to packed key-mask
   * form, stores the bound action string, and records optional key-repeat lanes.
   */
  void AddUiKeyMapEntries(
    const LuaPlus::LuaObject& keyMapTable
  )
  {
    if (!keyMapTable.IsTable()) {
      gpg::Warnf("CUIKeyHandler::AddKeyMapTable requires a table");
      return;
    }

    for (LuaPlus::LuaTableIterator iter(keyMapTable, 1); !iter.m_isDone; iter.Next()) {
      const char* const keyBindingSpecText = iter.m_keyObj.GetString();
      fa::scoped_string keyBindingSpec{keyBindingSpecText != nullptr ? keyBindingSpecText : ""};
      const UiKeyMask keyMask = static_cast<UiKeyMask>(moho::IN_ParseKeyModifiers(keyBindingSpec));

      const LuaPlus::LuaObject actionObject = iter.m_valueObj["action"];
      const char* const actionText = actionObject.GetString();
      gUiKeyActionMap[keyMask].assign_owned_strong(actionText != nullptr ? actionText : "");

      const LuaPlus::LuaObject keyRepeatObject = iter.m_valueObj["keyRepeat"];
      if (!keyRepeatObject.IsNil() && keyRepeatObject.GetBoolean()) {
        gUiKeyRepeatMap[keyMask] = true;
      }
    }
  }

  /**
   * Address: 0x00839270 (FUN_00839270, Moho::CUIKeyHandler::RemoveKeyMapTable)
   *
   * What it does:
   * Iterates one Lua key-map table, parses each key token, and erases matching
   * action/repeat entries from runtime key-map stores.
   */
  void RemoveUiKeyMapEntries(
    const LuaPlus::LuaObject& keyMapTable
  )
  {
    if (!keyMapTable.IsTable()) {
      gpg::Warnf("CUIKeyHandler::RemoveKeyMapTable requires a table");
      return;
    }

    for (LuaPlus::LuaTableIterator iter(keyMapTable, 1); !iter.m_isDone; iter.Next()) {
      const char* const keyBindingSpecText = iter.m_keyObj.GetString();
      fa::scoped_string keyBindingSpec{keyBindingSpecText != nullptr ? keyBindingSpecText : ""};
      const UiKeyMask keyMask = static_cast<UiKeyMask>(moho::IN_ParseKeyModifiers(keyBindingSpec));
      gUiKeyActionMap.erase(keyMask);
      gUiKeyRepeatMap.erase(keyMask);
    }
  }

  /**
   * Address: 0x00839440 (FUN_00839440, sub_839440)
   *
   * What it does:
   * Clears both runtime key-map stores and returns one success lane.
   */
  int ClearUiKeyMaps() noexcept
  {
    gUiKeyActionMap.clear();
    gUiKeyRepeatMap.clear();
    return 0;
  }
  /** Win32 `WM_KEYDOWN`/`WM_KEYUP` `lParam` bit 30: the key was already down. */
  constexpr std::uint32_t kWxKeyEventRawFlagPreviouslyDown = 0x40000000u;
}


/**
 * Address: 0x0079D7A0 (FUN_0079D7A0, cfunc_IsKeyDown)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsKeyDownL`.
 */
int moho::cfunc_IsKeyDown(
  lua_State* const luaContext
)
{
  return cfunc_IsKeyDownL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079D7C0 (FUN_0079D7C0, func_IsKeyDown_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IsKeyDown(keyCode)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IsKeyDown_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "IsKeyDown", &moho::cfunc_IsKeyDown, nullptr, "<global>", kIsKeyDownHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079D820 (FUN_0079D820, cfunc_IsKeyDownL)
 *
 * What it does:
 * Resolves one `EMauiKeyCode` enum string and pushes key-down boolean state.
 */
int moho::cfunc_IsKeyDownL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kIsKeyDownHelpText);

  gpg::RRef enumRef{};
  EMauiKeyCode keyCode = static_cast<EMauiKeyCode>(0);
  enumRef = gpg::MakeRRef<moho::EMauiKeyCode>(&keyCode);

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  const char* keyCodeName = lua_tostring(state->m_state, 1);
  if (keyCodeName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "string");
    keyCodeName = "";
  }

  SCR_GetEnum(state, keyCodeName, enumRef);
  lua_pushboolean(state->m_state, MAUI_KeyIsDown(keyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079D8D0 (FUN_0079D8D0, cfunc_KeycodeMauiToMSW)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_KeycodeMauiToMSWL`.
 */
int moho::cfunc_KeycodeMauiToMSW(
  lua_State* const luaContext
)
{
  return cfunc_KeycodeMauiToMSWL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079D8F0 (FUN_0079D8F0, func_KeycodeMauiToMSW_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `KeycodeMauiToMSW(int)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_KeycodeMauiToMSW_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "KeycodeMauiToMSW", &moho::cfunc_KeycodeMauiToMSW, nullptr, "<global>", kKeycodeMauiToMSWHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079D950 (FUN_0079D950, cfunc_KeycodeMauiToMSWL)
 *
 * What it does:
 * Converts one Maui key code to MS Windows key code and pushes numeric result.
 */
int moho::cfunc_KeycodeMauiToMSWL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kKeycodeMauiToMSWHelpText);

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
  }

  const int mauiKeyCode = static_cast<int>(lua_tonumber(state->m_state, 1));
  bool isSpecial = false;
  const int mswKeyCode = wxCharCodeWXToMSW(mauiKeyCode, &isSpecial);
  (void)isSpecial;

  lua_pushnumber(state->m_state, static_cast<float>(mswKeyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079D9F0 (FUN_0079D9F0, cfunc_KeycodeMSWToMaui)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_KeycodeMSWToMauiL`.
 */
int moho::cfunc_KeycodeMSWToMaui(
  lua_State* const luaContext
)
{
  return cfunc_KeycodeMSWToMauiL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079DA10 (FUN_0079DA10, func_KeycodeMSWToMaui_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `KeycodeMSWToMaui(int)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_KeycodeMSWToMaui_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "KeycodeMSWToMaui", &moho::cfunc_KeycodeMSWToMaui, nullptr, "<global>", kKeycodeMSWToMauiHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079DA70 (FUN_0079DA70, cfunc_KeycodeMSWToMauiL)
 *
 * What it does:
 * Converts one MS Windows key code to Maui key code and pushes numeric result.
 */
int moho::cfunc_KeycodeMSWToMauiL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kKeycodeMSWToMauiHelpText);

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
  }

  const int mswKeyCode = static_cast<int>(lua_tonumber(state->m_state, 1));
  const int mauiKeyCode = wxCharCodeMSWToWX(mswKeyCode);
  lua_pushnumber(state->m_state, static_cast<float>(mauiKeyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0083A190 (FUN_0083A190, cfunc_IN_AddKeyMapTable)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to `cfunc_IN_AddKeyMapTableL`.
 */
int moho::cfunc_IN_AddKeyMapTable(
  lua_State* const luaContext
)
{
  return cfunc_IN_AddKeyMapTableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083A210 (FUN_0083A210, cfunc_IN_AddKeyMapTableL)
 *
 * What it does:
 * Validates one key-map table argument and merges action/repeat entries into
 * the runtime key-map stores.
 */
int moho::cfunc_IN_AddKeyMapTableL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kINAddKeyMapTableHelpText);

  const LuaPlus::LuaObject keyMapTable(LuaPlus::LuaStackObject(state, 1));
  AddUiKeyMapEntries(keyMapTable);
  return 0;
}

/**
 * Address: 0x0083A1B0 (FUN_0083A1B0, func_IN_AddKeyMapTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_AddKeyMapTable(keyMapTable)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_AddKeyMapTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IN_AddKeyMapTable",
    &moho::cfunc_IN_AddKeyMapTable,
    nullptr,
    "<global>",
    kINAddKeyMapTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083A2B0 (FUN_0083A2B0, cfunc_IN_RemoveKeyMapTable)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to `cfunc_IN_RemoveKeyMapTableL`.
 */
int moho::cfunc_IN_RemoveKeyMapTable(
  lua_State* const luaContext
)
{
  return cfunc_IN_RemoveKeyMapTableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083A330 (FUN_0083A330, cfunc_IN_RemoveKeyMapTableL)
 *
 * What it does:
 * Validates one key-map table argument and removes each key binding from the
 * runtime action/repeat key-map stores.
 */
int moho::cfunc_IN_RemoveKeyMapTableL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kINRemoveKeyMapTableHelpText);

  const LuaPlus::LuaObject keyMapTable(LuaPlus::LuaStackObject(state, 1));
  RemoveUiKeyMapEntries(keyMapTable);
  return 0;
}

/**
 * Address: 0x0083A2D0 (FUN_0083A2D0, func_IN_RemoveKeyMapTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_RemoveKeyMapTable(keyMapTable)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_RemoveKeyMapTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IN_RemoveKeyMapTable",
    &moho::cfunc_IN_RemoveKeyMapTable,
    nullptr,
    "<global>",
    kINRemoveKeyMapTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083A3D0 (FUN_0083A3D0, cfunc_IN_ClearKeyMap)
 *
 * What it does:
 * Validates the zero-argument lane and clears all runtime key-map bindings.
 */
int moho::cfunc_IN_ClearKeyMap(
  lua_State* const luaContext
)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kINClearKeyMapHelpText);

  ClearUiKeyMaps();
  return 0;
}

/**
 * Address: 0x0083A410 (FUN_0083A410, func_IN_ClearKeyMap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_ClearKeyMap()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_ClearKeyMap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "IN_ClearKeyMap", &moho::cfunc_IN_ClearKeyMap, nullptr, "<global>", kINClearKeyMapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00838F30 (FUN_00838F30, Moho::IN_FindKeyNameIndex)
 *
 * What it does:
 * Case-sensitive linear scan of `in_keyNames` for one key name; returns the
 * matching wxKeyCode (0..255) or -1 when no slot matches. Mirrors the binary's
 * MSVC8 `std::string::compare(0, _Mysize, needlePtr, needleSize)` per-slot
 * equality test which returns 0 on match.
 */
int moho::IN_FindKeyNameIndex(
  const fa::string& needle
)
{
  const char* const needlePtr = needle.c_str();
  const std::size_t needleSize = needle.size();

  for (int index = 0; index < 256; ++index) {
    const fa::string& slot = in_keyNames[index];
    if (slot.compare(0u, slot.size(), needlePtr, needleSize) == 0) {
      return index;
    }
  }
  return -1;
}

/**
 * Address: 0x00838F80 (FUN_00838F80, Moho::IN_FindKeyNameIndexCi)
 *
 * What it does:
 * Case-insensitive linear scan of `in_keyNames` for one key name; returns the
 * matching wxKeyCode (0..255) or -1 when no slot matches. The binary uses
 * `stricmp` on the SSO-resolved character pointers of slot and needle.
 */
int moho::IN_FindKeyNameIndexCi(
  const fa::string& needle
)
{
  const char* const needlePtr = needle.c_str();

  for (int index = 0; index < 256; ++index) {
    if (_stricmp(in_keyNames[index].c_str(), needlePtr) == 0) {
      return index;
    }
  }
  return -1;
}
namespace
{
  /// Modifier bits `IN_ParseKeyModifiers` packs into a `UiKeyMask`. Named here
  /// for the two binding-description lanes below; the older key-event and
  /// parse lanes in this file still spell them numerically.
  constexpr UiKeyMask kUiKeyMaskShift = 0x80000000u;
  constexpr UiKeyMask kUiKeyMaskCtrl = 0x40000000u;
  constexpr UiKeyMask kUiKeyMaskAlt = 0x20000000u;
}


/**
 * Address: 0x00838E70 (FUN_00838E70, Moho::IN_GetKeyName)
 *
 * IDA signature:
 * std::string *__usercall sub_838E70@<eax>(std::string *out@<esi>, unsigned int keyCode);
 *
 * What it does:
 * Yields `in_keyNames[keyCode]`, or an empty string when the code falls
 * outside the 256-slot table. The binary indexes it as `28 * keyCode +
 * 0x010C1B48` -- stride `sizeof(fa::string) == 0x1C` over `in_keyNames`,
 * which is what fixes that global's element type -- and materialises a
 * temporary empty string for the out-of-range arm so both arms can share one
 * `assign` tail.
 */
fa::scoped_string moho::IN_GetKeyName(
  const unsigned int keyCode
)
{
  fa::scoped_string keyName{};
  if (keyCode < 256u) {
    const fa::string& slot = in_keyNames[keyCode];
    keyName.assign_owned(std::string_view{slot.c_str(), slot.size()});
  }
  return keyName;
}

/**
 * Address: 0x00839840 (FUN_00839840, Moho::IN_DescribeKeyBinding)
 *
 * IDA signature:
 * std::string *__usercall sub_839840@<eax>(std::string *out@<eax>, unsigned int keyMask@<ecx>);
 *
 * What it does:
 * Renders one packed key mask as the human-readable chord `IN_BindKey`
 * accepts -- modifier prefixes in the fixed order `Ctrl-`, `Alt-`, `Shift-`,
 * then the key name. The binary tests and clears each modifier bit in turn
 * (`& 0xBFFFFFFF`, then `& 0xDFFFFFFF`, then the sign test and `& 0x7FFFFFFF`)
 * so that what reaches `IN_GetKeyName` is the bare key code; testing each bit
 * against the original mask is equivalent, because clearing one modifier
 * never disturbs another.
 */
fa::scoped_string moho::IN_DescribeKeyBinding(
  const UiKeyMask keyMask
)
{
  fa::scoped_string description{};

  if ((keyMask & kUiKeyMaskCtrl) != 0u) {
    AppendLegacyStringOrThrow(description, "Ctrl-", 5u);
  }
  if ((keyMask & kUiKeyMaskAlt) != 0u) {
    AppendLegacyStringOrThrow(description, "Alt-", 4u);
  }
  if ((keyMask & kUiKeyMaskShift) != 0u) {
    AppendLegacyStringOrThrow(description, "Shift-", 6u);
  }

  const UiKeyMask keyCode = keyMask & ~(kUiKeyMaskCtrl | kUiKeyMaskAlt | kUiKeyMaskShift);
  const fa::scoped_string keyName = IN_GetKeyName(keyCode);
  AppendLegacyStringOrThrow(description, keyName.c_str(), keyName.size());

  return description;
}

/**
 * Address: 0x00839DC0 (FUN_00839DC0, Moho::IN_DumpKeyBindings)
 *
 * What it does:
 * The `IN_DumpKeyBindings` console command ("Shows all the key bindings"):
 * walks `gUiKeyActionMap` in key order and prints each entry as
 * `"<chord> :: <console command> :: repeat = <true|false>"`, where the repeat
 * flag is membership of the same mask in `gUiKeyRepeatMap`.
 *
 * The binary's shape is entirely the two containers': the walk is
 * `_Tree::_Inc` (0x0083C0B0) from `gUiKeyActionMap`'s leftmost node to its
 * head, and the repeat test is `_Tree::find` spelled as a lower-bound descent
 * (`_Left@0x00`, `_Right@0x08`, `_Myval@0x0C`, `_Isnil@0x15`) followed by the
 * `end()`-or-greater equivalence check. Both are `fa::map`'s already.
 */
void moho::IN_DumpKeyBindings(
  const fa::vector<fa::string>& /*args*/
)
{
  for (const auto& binding : gUiKeyActionMap) {
    const fa::scoped_string chord = IN_DescribeKeyBinding(binding.first);
    const bool repeats = gUiKeyRepeatMap.find(binding.first) != gUiKeyRepeatMap.end();
    CON_Printf("%s :: %s :: repeat = %s", chord.c_str(), binding.second.c_str(), repeats ? "true" : "false");
  }
}

/**
 * Address: 0x00839EE0 (FUN_00839EE0, Moho::IN_DumpKeyNames)
 *
 * What it does:
 * The `IN_DumpKeyNames` console command: prints every slot of
 * `in_keyNames[0..255]` as `"%04d = %s"`. The binary's raw SSO-vs-heap
 * pointer check on each slot's `_Bx`/`_Mysize`/`_Myres` triple is exactly
 * what `fa::string::c_str()` already resolves, so it is not reproduced
 * here.
 */
void moho::IN_DumpKeyNames(
  const fa::vector<fa::string>& /*args*/
)
{
  for (int index = 0; index < 256; ++index) {
    CON_Printf("%04d = %s", index, in_keyNames[index].c_str());
  }
}

/**
 * Address: 0x008394B0 (FUN_008394B0, Moho::CUIKeyHandler::SetKeyNameTable)
 *
 * What it does:
 * Iterates one Lua key-names table (string keys are hex code spellings like
 * "0x20", values are name strings) and overwrites `in_keyNames[parsedCode]`
 * for each entry. Skips entries whose parsed code is > 0xFF with a warning,
 * mirroring the binary's bounds check on `STR_Xtoi`.
 */
void moho::CUIKeyHandlerSetKeyNameTable(
  const LuaPlus::LuaObject& keyNamesTable
)
{
  if (!keyNamesTable.IsTable()) {
    gpg::Warnf("CUIKeyHandler::SetKeyNameTable wasn't passed a table");
    return;
  }

  for (LuaPlus::LuaTableIterator iter(keyNamesTable, 1); !iter.m_isDone; iter.Next()) {
    const char* const keyText = iter.m_keyObj.GetString();
    if (keyText == nullptr) {
      continue;
    }

    const unsigned int keyCode = gpg::STR_Xtoi(keyText);
    if (keyCode > 0xFFu) {
      gpg::Warnf("CUIKeyHandler::SetKeyNameTable found incorrect key code in key names: %s", keyText);
      continue;
    }

    const char* const valueText = iter.m_valueObj.GetString();
    if (valueText == nullptr) {
      continue;
    }

    in_keyNames[keyCode].assign_owned(std::string_view{valueText, std::strlen(valueText)});
  }
}

/**
 * Address: 0x00839690 (FUN_00839690, Moho::CUIKeyHandler::LoadKeyMappings)
 *
 * What it does:
 * Imports `/lua/keymap/keyNames.lua`, passes its `keyNames` sub-table to
 * `CUIKeyHandlerSetKeyNameTable` to populate `in_keyNames`, then imports
 * `/lua/keymap/keymapper.lua`, invokes `GetKeyMappings()`, and feeds the
 * returned table to `AddUiKeyMapEntries`. Warns and returns early when
 * `keyNames.lua` does not deliver a table; emits a similar warning when
 * `GetKeyMappings()` returns a non-table value.
 */
void moho::CUIKeyHandlerLoadKeyMappings()
{
  LuaPlus::LuaState* const state = USER_GetLuaState();
  if (state == nullptr) {
    gpg::Warnf("CUIKeyHandler::LoadKeyMappings unable to resolve user lua state.");
    return;
  }

  const LuaPlus::LuaObject keyNamesModule = SCR_Import(state, "/lua/keymap/keyNames.lua");
  if (!keyNamesModule.IsTable()) {
    gpg::Warnf("CUIKeyHandler::LoadKeyMappings unable to open default key names file.");
    return;
  }

  const LuaPlus::LuaObject keyNamesTable = keyNamesModule.GetByName("keyNames");
  CUIKeyHandlerSetKeyNameTable(keyNamesTable);

  const LuaPlus::LuaObject keymapperModule = SCR_Import(state, "/lua/keymap/keymapper.lua");
  const LuaPlus::LuaObject getKeyMappingsObject = keymapperModule["GetKeyMappings"];
  const LuaPlus::LuaFunction<LuaPlus::LuaObject> getKeyMappingsFn(getKeyMappingsObject);
  const LuaPlus::LuaObject keyMapTable = getKeyMappingsFn.Call_Obj();
  if (keyMapTable.IsTable()) {
    AddUiKeyMapEntries(keyMapTable);
  } else {
    gpg::Warnf("CUIKeyHandler::LoadKeyMappings unable to map keys, requires table.");
  }
}

/**
 * Address: 0x00838C70 (FUN_00838C70, Moho::IN_InitKeyHandler)
 *
 * What it does:
 * Initializes the 256-entry `in_keyNames` array with "Unknown%02X" placeholder
 * defaults (indexed by wxKeyCode), then loads Lua-side key name and key-map
 * tables via `CUIKeyHandlerLoadKeyMappings`. Returns `true` to signal the
 * caller (CUIManager::Init) that input wiring completed; the binary always
 * reports success and surfaces failure paths via warnings only.
 */
bool moho::IN_InitKeyHandler()
{
  for (int code = 0; code < 256; ++code) {
    const fa::string placeholder = gpg::STR_Printf("Unknown%02X", code);
    in_keyNames[code].assign(placeholder, 0u, fa::string::npos);
  }

  CUIKeyHandlerLoadKeyMappings();
  return true;
}

/**
 * Address: 0x00839920 (FUN_00839920, Moho::IN_ParseKeyModifiers)
 * Mangled: ?IN_ParseKeyModifiers@Moho@@... (thiscall on the spec legacy string)
 *
 * IDA signature:
 * int __thiscall Moho::IN_ParseKeyModifiers(std::string *this);
 *
 * What it does:
 * Parses one key-binding token string (`key[-modifier[-modifier...]]`) into a
 * single packed keycode/modifier mask. Tokens are split on '-' by
 * gpg::STR_GetToken and each is inserted at the FRONT of a small-buffer scratch
 * vector (gpg::fastvector_n<fa::string,4>), so after tokenizing, slot 0 holds
 * the LAST token (the key name) and slots 1..n hold the modifiers in reverse
 * order. Slot 0 is resolved through IN_FindKeyNameIndexCi against the
 * runtime-loaded in_keyNames table (unknown key names yield -1, preserving the
 * binary's signed return). Each modifier slot is compared case-insensitively
 * (SHIFT -> 0x80000000, CTRL -> 0x40000000, ALT -> 0x20000000); an
 * unrecognized modifier emits a gpg::Warnf. Returns 0 when the input string is
 * empty.
 *
 * The three modifier reference strings live in the binary as runtime-initialized
 * fa::string globals at 0x10C1D08 / 0x10C1D24 / 0x10C1D40; their initializer
 * is not in the recovered evidence set, so the literal spellings are modeled
 * here. See the reconstruction note for the CTRL-vs-CONTROL open item.
 */
int moho::IN_ParseKeyModifiers(
  const fa::string& keyBindingSpec
)
{
  // Binary reference strings @ 0x10C1D08 / 0x10C1D24 / 0x10C1D40, compared in
  // ALT -> CTRL -> SHIFT order. Their initializer is not in the recovered
  // evidence set, so the spellings come from the data instead: every binding
  // the shipped keymaps write is `Alt-`, `Ctrl-` or `Shift-`
  // (lua/keymap/defaultKeyMap.lua uses Ctrl 418 times, Shift 340, Alt 179).
  // The compare is case-insensitive, so ALT and SHIFT matched either way, but
  // the middle one had been modelled as "CONTROL" and so matched nothing -
  // every Ctrl binding in the game logged "unrecognized modifier string: Ctrl"
  // and silently lost its modifier bit, leaving it bound to the bare key.
  // Which spelling sits in which slot is fixed by the *other* end of this
  // lane. `CUIKeyHandler::OnKeyDown` builds the lookup key for this very map
  // out of the wxKeyEvent flag bytes, and the binary spells that packing out:
  //
  //   0x00838D2C  mov bl, [ebp+2Dh]   ; m_shiftDown
  //   0x00838D34  mov al, [ebp+2Ch]   ; m_controlDown
  //   0x00838D31  mov dl, [ebp+2Eh]   ; m_altDown
  //   0x00838D44  or ecx, 80000000h   ; <- shift
  //   0x00838D4E  or ecx, 40000000h   ; <- control
  //   0x00838D58  or ecx, 20000000h   ; <- alt
  //
  // (the flag-byte offsets are wxKeyEvent's own declaration order --
  // m_controlDown, m_shiftDown, m_altDown, m_metaDown -- and are asserted on
  // in wx/event.h.)
  //
  // So the first of the three reference strings must be SHIFT and the third
  // ALT. They had been modelled the other way round, which put every `Shift-`
  // and `Alt-` binding in the map under a mask `OnKeyDown` can never produce:
  // measured at runtime, `Shift-6` was stored as 0x20000036 and `Alt-F9` as
  // 0x80000078, while a real Shift-6 press looks up 0x80000036 and a real
  // Alt-F9 press looks up 0x20000078. Neither ever matched, so every modified
  // binding in the shipped keymap was dead (Ctrl-only ones happened to work,
  // since 0x40000000 was right in both places). Worse, the wrong masks
  // collided with each other -- `Shift-R` landed on `Alt-R`'s real mask -- so
  // 12 of the 196 shipped bindings were silently overwriting one another; the
  // map held 184 entries before this and holds 196 after.
  const fa::scoped_string shiftModifier{"SHIFT"};
  const fa::scoped_string controlModifier{"CTRL"};
  const fa::scoped_string altModifier{"ALT"};

  // SBO scratch: 4 inline fa::string slots, teardown frees heap only when the
  // token count spilled past the inline window (start != inline origin).
  gpg::fastvector_n<fa::scoped_string, 4> tokens{};
  fa::scoped_string token{};

  // Tokenize the spec, inserting each token at begin() so the final slot 0 is
  // the last (key) token and the modifiers follow in reverse token order.
  const char* cursor = keyBindingSpec.c_str();
  while (gpg::STR_GetToken(cursor, "-", token)) {
    tokens.InsertAt(tokens.begin(), &token, &token + 1);
  }

  // Guard on the ORIGINAL spec being non-empty (matches the binary's
  // `if (this->_Mysize)`), not on the token count.
  if (keyBindingSpec.empty()) {
    return 0;
  }

  int keyMask = IN_FindKeyNameIndexCi(tokens.Data()[0]);

  const std::size_t tokenCount = tokens.Size();
  for (std::size_t tokenIndex = 1u; tokenIndex < tokenCount; ++tokenIndex) {
    const fa::scoped_string& modifier = tokens.Data()[tokenIndex];
    if (_stricmp(modifier.c_str(), shiftModifier.c_str()) == 0) {
      keyMask |= static_cast<int>(0x80000000u);
    } else if (_stricmp(modifier.c_str(), controlModifier.c_str()) == 0) {
      keyMask |= static_cast<int>(0x40000000u);
    } else if (_stricmp(modifier.c_str(), altModifier.c_str()) == 0) {
      keyMask |= static_cast<int>(0x20000000u);
    } else {
      gpg::Warnf("Key map contains unrecognized modifier string: %s\n", modifier.c_str());
    }
  }

  return keyMask;
}

/**
 * Address: 0x00839F20 (FUN_00839F20, Moho::IN_BindKey)
 *
 * IDA signature:
 * void __cdecl Moho::IN_BindKey(std::vector<std::string>* commandArgs);
 *
 * What it does:
 * Validates the console-command token vector, parses token 1 as a key mask,
 * joins every command token from index 2 with one trailing space apiece, and
 * assigns the completed legacy string to the key-action map. A zero parse
 * result reports the original key token and leaves the map unchanged.
 */
void moho::IN_BindKey(
  const fa::vector<fa::string>& args
)
{
  if (args.size() < 3u) {
    CON_Printf("Syntax: IN_BindKey [key sequence] [console command]");
    return;
  }

  const fa::string* const keyBindingSpec = ConCommandArg(args, 1u);
  const int parsedKeyMask = IN_ParseKeyModifiers(*keyBindingSpec);
  if (parsedKeyMask == 0) {
    CON_Printf("Unrecognized key sequence: %s", keyBindingSpec->c_str());
    return;
  }

  fa::scoped_string actionText{};
  for (std::size_t argumentIndex = 2u; argumentIndex < args.size(); ++argumentIndex) {
    const fa::string* const argument = ConCommandArg(args, argumentIndex);
    AppendLegacyStringOrThrow(actionText, argument->c_str(), argument->size());
    AppendLegacyStringOrThrow(actionText, 1u, ' ');
  }

  gUiKeyActionMap[static_cast<UiKeyMask>(parsedKeyMask)].assign_owned_strong(actionText.view());
}

/**
 * Address: 0x0083A080 (FUN_0083A080, sub_83A080)
 *
 * IDA signature:
 * void __cdecl sub_83A080(std::vector<std::string>* commandArgs);
 *
 * What it does:
 * The `IN_SetKeyName` console command. Parses token 1 as a hex key code,
 * rejects codes above 0xFF, then either renames `in_keyNames[keyCode]`
 * (when token 2's name isn't already used by another key, checked
 * case-insensitively via `IN_FindKeyNameIndexCi`) or reports the collision.
 */
void moho::IN_SetKeyName(
  const fa::vector<fa::string>& args
)
{
  if (args.size() < 3u) {
    CON_Printf("Syntax: IN_SetKeyName keyCodeHex nameString");
    return;
  }

  const fa::string* const keyCodeArg = ConCommandArg(args, 1u);
  const unsigned int keyCode = gpg::STR_Xtoi(keyCodeArg->c_str());
  if (keyCode > 0xFFu) {
    CON_Printf("Invalid key code %02X, must be between 0x00 and 0xFF", keyCode);
    return;
  }

  const fa::string* const nameArg = ConCommandArg(args, 2u);
  if (IN_FindKeyNameIndexCi(*nameArg) == -1) {
    in_keyNames[keyCode].assign_owned(std::string_view{nameArg->c_str(), nameArg->size()});
    CON_Printf("Key code %02X name is %s", keyCode, in_keyNames[keyCode].c_str());
  } else {
    CON_Printf("Key name must be unique, %s already used", nameArg->c_str());
  }
}

/**
 * Address: 0x00838D10 (FUN_00838D10, Moho::CUIKeyHandler::OnKeyDown)
 *
 * See the class declaration in UiRuntimeTypes.h for the full evidence trail.
 */
void moho::CUIKeyHandler::OnKeyDown(
  wxKeyEvent& keyEvent
)
{
  if (moho::Maui_CurrentFocusControl.GetObjectPtr() != nullptr) {
    keyEvent.Skip();
    return;
  }

  const bool shiftDown = keyEvent.m_shiftDown;
  const bool ctrlDown = keyEvent.m_controlDown;
  const bool altDown = keyEvent.m_altDown;

  UiKeyMask packedKeyMask = static_cast<UiKeyMask>(keyEvent.m_rawCode);
  if (shiftDown) {
    packedKeyMask |= 0x80000000u;
  }
  if (ctrlDown) {
    packedKeyMask |= 0x40000000u;
  }
  if (altDown) {
    packedKeyMask |= 0x20000000u;
  }

  const bool keyIsTrackedForRepeat = gUiKeyRepeatMap.find(packedKeyMask) != gUiKeyRepeatMap.end();
  if (!keyIsTrackedForRepeat && (keyEvent.m_rawFlags & kWxKeyEventRawFlagPreviouslyDown) != 0) {
    // Stray Win32 auto-repeat for a key this handler never saw go down
    // (e.g. focus changed mid-press): drop it rather than firing a binding.
    keyEvent.Skip();
    return;
  }

  const auto boundCommand = gUiKeyActionMap.find(packedKeyMask);
  if (boundCommand != gUiKeyActionMap.end()) {
    CON_Execute(boundCommand->second.c_str());
    keyEvent.Skip();
    return;
  }

  // No user key binding claimed this chord: fall back to the two hardcoded
  // shortcuts. Neither branch marks the event skipped -- matches the binary
  // exactly, so wx keeps propagating the key afterward.
  constexpr std::int32_t kKeyCodeEnter = 13;
  constexpr std::int32_t kKeyCodeTilde = 0x7E; // '~'
  switch (keyEvent.m_keyCode) {
  case kKeyCodeEnter:
    UI_ActivateChat(shiftDown, ctrlDown, altDown);
    return;
  case kKeyCodeTilde:
    MAUI_ToggleConsole();
    return;
  default:
    keyEvent.Skip();
    return;
  }
}

/**
 * Address: 0x00838E30 (FUN_00838E30, sub_838E30)
 *
 * See the class declaration in UiRuntimeTypes.h for the full evidence trail.
 */
void moho::CUIKeyHandler::OnKeyUp(
  wxKeyEvent& keyEvent
)
{
  keyEvent.Skip();
}
