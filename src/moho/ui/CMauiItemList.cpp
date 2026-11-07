#include "moho/ui/UiPrivate.h"

namespace
{

  [[nodiscard]] std::int32_t GetItemListEntryCount(
    const moho::CMauiItemList& itemList
  ) noexcept
  {
    return itemList.mItems.data() != nullptr ? static_cast<std::int32_t>(itemList.mItems.size()) : 0;
  }

  /**
   * Address: 0x00799A10 (FUN_00799A10, Moho::CMauiItemList row-selection helper)
   *
   * What it does:
   * Writes one row index into the item-list current-selection lane when the
   * requested row is in `[0, count)`, otherwise clears the selection to `-1`.
   * Returns the current item count, matching the binary helper's return
   * shape so callers can use it as a clamped item count.
   */
  std::uint32_t SetItemListSelectionByRow(
    moho::CMauiItemList& itemList,
    const std::uint32_t requestedRow
  ) noexcept
  {
    const auto count = static_cast<std::uint32_t>(GetItemListEntryCount(itemList));
    if (count != 0u && requestedRow < count) {
      itemList.mCurSelection = static_cast<std::int32_t>(requestedRow);
    } else {
      itemList.mCurSelection = -1;
    }
    return count;
  }

  constexpr moho::EMauiScrollAxis kVerticalScrollAxis = static_cast<moho::EMauiScrollAxis>(0);
  constexpr const char* kInternalCreateItemListHelpText =
    "InternalCreateItemList(luaobj,parent) -- for internal use by CreateItemList()";
  constexpr const char* kCMauiItemListSetNewFontHelpText =
    "ItemList:SetNewFont(family, pointsize) -- set the font to use in this ItemList control";
  constexpr const char* kCMauiItemListAddItemHelpText =
    "itemlist = ItemList:AddItem('newitem')\n"
    "Add an new item to an itemlist. The new item must be a string.\n"
    "Returns the itemlist itself so you can chain calls.";
  constexpr const char* kCMauiItemListModifyItemHelpText = "itemlist = ItemList:ModifyItem(index, string)";
  constexpr const char* kCMauiItemListDeleteItemHelpText = "itemlist = ItemList:DeleteItem(index)";
  constexpr const char* kCMauiItemListDeleteAllItemsHelpText = "itemlist = ItemList:DeleteAllItems()";
  constexpr const char* kCMauiItemListGetSelectionHelpText = "index = ItemList:GetSelection()";
  constexpr const char* kCMauiItemListSetNewColorsHelpText =
    "CMauiItemList:SetNewColors(foreground, background, selectedForeground, selectedBackground, highlightForeground, "
    "highlightBackground)";
  constexpr const char* kCMauiItemListSetSelectionHelpText = "CMauiItemList:SetSelection(index)";
  constexpr const char* kCMauiItemListGetItemHelpText = "CMauiItemList:GetItem(index)";
  constexpr const char* kCMauiItemListGetItemCountHelpText = "int ItemList:GetItemCount()";
  constexpr const char* kCMauiItemListEmptyHelpText = "bool ItemList:Empty()";
  constexpr const char* kCMauiItemListScrollToTopHelpText = "ItemList:ScrollToTop()";
  constexpr const char* kCMauiItemListShowItemHelpText = "ItemList:ShowItem(index)";
  constexpr const char* kCMauiItemListGetRowHeightHelpText = "float ItemList:GetRowHeight()";
  constexpr const char* kCMauiItemListShowMouseoverItemHelpText =
    "ShowMouseoverItem(bool) - enable or disable the showing of the mouseover item";
  constexpr const char* kCMauiItemListShowSelectionHelpText =
    "ShowSelection(bool) - enable or disable the highlighting of the selected item";
  constexpr const char* kCMauiItemListNeedsScrollBarHelpText =
    "bool NeedsScrollBar() - returns true if a scrollbar is needed, else false";
  constexpr const char* kCMauiItemListGetStringAdvanceHelpText =
    "number ItemList:GetAdvance(string) - get the advance of a string using the same font as the control";

  /**
   * Address: 0x0079C8A0 (FUN_0079C8A0)
   *
   * What it does:
   * Removes one item-list entry, compacts the tail left by one slot, and keeps
   * the selection lane consistent with the post-delete vector size.
   */
  void RemoveItemListEntryAtIndex(
    moho::CMauiItemList* const itemList,
    const std::int32_t index
  )
  {
    if (itemList == nullptr || index < 0) {
      return;
    }
    const std::size_t count = itemList->mItems.size();
    if (static_cast<std::size_t>(index) >= count) {
      return;
    }

    for (std::size_t i = static_cast<std::size_t>(index) + 1u; i < count; ++i) {
      itemList->mItems[i - 1u] = itemList->mItems[i];
    }
    itemList->mItems.pop_back();

    const std::int32_t currentSelection = itemList->mCurSelection;
    if (index >= currentSelection) {
      if (currentSelection == GetItemListEntryCount(*itemList)) {
        itemList->mCurSelection = -1;
      }
    } else {
      itemList->mCurSelection = currentSelection - 1;
    }
  }
}

gpg::RType* moho::CMauiItemList::sType = nullptr;

/**
 * Address: 0x00799340 (FUN_00799340, Moho::CMauiItemList::CMauiItemList)
 *
 * What it does:
 * Constructs one item-list control from Lua object + parent lanes and
 * initializes palette, selection, and default font runtime state.
 */
moho::CMauiItemList::CMauiItemList(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "itemlist")
{
  mFont = nullptr;
  mForegroundColor = 0xFF808080u;
  mBackgroundColor = 0xFF000000u;
  mSelectedForegroundColor = 0xFF000000u;
  mSelectedBackgroundColor = 0xFF808080u;
  mHighlightForegroundColor = 0xFFA0A0A0u;
  mHighlightBackgroundColor = 0xFF202020u;
  mItems.release_storage_without_free();
  mCurSelection = -1;
  mHoverItem = -1;
  mShowSelection = true;
  mShowMouseoverItem = false;
  mScrollPosition = 0;

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(16, "New Times Roman");
  AssignIntrusiveFont(mFont, createdFont.px);
  createdFont.release();
}

/**
 * Address: 0x0079A960 (FUN_0079A960, cfunc_InternalCreateItemList)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateItemListL`.
 */
int moho::cfunc_InternalCreateItemList(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateItemListL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079A980 (FUN_0079A980, func_InternalCreateItemList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateItemList(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateItemList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateItemList",
    &moho::cfunc_InternalCreateItemList,
    nullptr,
    "<global>",
    kInternalCreateItemListHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079A9E0 (FUN_0079A9E0, cfunc_InternalCreateItemListL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiItemList`, dispatches
 * `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateItemListL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateItemListHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x158)`.
  auto* const itemList = AllocateZeroedUiObject<CMauiItemList>(0x158u);
  new (itemList) CMauiItemList(&luaObject, parentControl);
  itemList->DoInit();
  itemList->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079AB10 (FUN_0079AB10, cfunc_CMauiItemListSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetNewFontL`.
 */
int moho::cfunc_CMauiItemListSetNewFont(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079AB30 (FUN_0079AB30, func_CMauiItemListSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiItemListSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079AB90 (FUN_0079AB90, cfunc_CMauiItemListSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus `(family, pointsize)`, creates one font, and
 * applies it to item-list runtime state.
 */
int moho::cfunc_CMauiItemListSetNewFontL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kCMauiItemListSetNewFontHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    itemList->SetFont(createdFont.px);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x0079AD30 (FUN_0079AD30, cfunc_CMauiItemListSetNewColors)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetNewColorsL`.
 */
int moho::cfunc_CMauiItemListSetNewColors(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListSetNewColorsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079AD50 (FUN_0079AD50, func_CMauiItemListSetNewColors_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetNewColors(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetNewColors_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewColors",
    &moho::cfunc_CMauiItemListSetNewColors,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetNewColorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079ADB0 (FUN_0079ADB0, cfunc_CMauiItemListSetNewColorsL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus optional color lanes and updates the
 * item-list color palette runtime fields.
 */
int moho::cfunc_CMauiItemListSetNewColorsL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 7, kCMauiItemListSetNewColorsHelpText);

  auto itemListObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 2));
    itemList->mForegroundColor = SCR_DecodeColor(state, colorObject);
  }
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 3));
    itemList->mBackgroundColor = SCR_DecodeColor(state, colorObject);
  }
  if (lua_type(state->m_state, 4) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 4));
    itemList->mSelectedForegroundColor = SCR_DecodeColor(state, colorObject);
  }
  if (lua_type(state->m_state, 5) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 5));
    itemList->mSelectedBackgroundColor = SCR_DecodeColor(state, colorObject);
  }
  if (lua_type(state->m_state, 6) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 6));
    itemList->mHighlightForegroundColor = SCR_DecodeColor(state, colorObject);
  }
  if (lua_type(state->m_state, 7) != LUA_TNIL) {
    auto colorObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 7));
    itemList->mHighlightBackgroundColor = SCR_DecodeColor(state, colorObject);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B980 (FUN_0079B980, cfunc_CMauiItemListSetSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetSelectionL`.
 */
int moho::cfunc_CMauiItemListSetSelection(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListSetSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B9A0 (FUN_0079B9A0, func_CMauiItemListSetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetSelection(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetSelection",
    &moho::cfunc_CMauiItemListSetSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BA00 (FUN_0079BA00, cfunc_CMauiItemListSetSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and updates the current
 * selection lane when the index is in range.
 */
int moho::cfunc_CMauiItemListSetSelectionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListSetSelectionHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  if (index >= 0) {
    (void)SetItemListSelectionByRow(*itemList, static_cast<std::uint32_t>(index));
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B040 (FUN_0079B040, cfunc_CMauiItemListGetItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetItemL`.
 */
int moho::cfunc_CMauiItemListGetItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListGetItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B060 (FUN_0079B060, func_CMauiItemListGetItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetItem",
    &moho::cfunc_CMauiItemListGetItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B0C0 (FUN_0079B0C0, cfunc_CMauiItemListGetItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and returns the selected item
 * string lane to Lua.
 */
int moho::cfunc_CMauiItemListGetItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListGetItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  fa::string* const itemBase = itemList->mItems.data();
  const fa::string& itemName = itemBase[index];
  lua_pushstring(state->m_state, itemName.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BB40 (FUN_0079BB40, cfunc_CMauiItemListGetItemCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetItemCountL`.
 */
int moho::cfunc_CMauiItemListGetItemCount(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListGetItemCountL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BB60 (FUN_0079BB60, func_CMauiItemListGetItemCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetItemCount()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetItemCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetItemCount",
    &moho::cfunc_CMauiItemListGetItemCount,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetItemCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BBC0 (FUN_0079BBC0, cfunc_CMauiItemListGetItemCountL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns its current item count.
 */
int moho::cfunc_CMauiItemListGetItemCountL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListGetItemCountHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const int itemCount = GetItemListEntryCount(*itemList);

  lua_pushnumber(state->m_state, static_cast<float>(static_cast<std::uint32_t>(itemCount)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BCB0 (FUN_0079BCB0, cfunc_CMauiItemListEmpty)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiItemListEmptyL`.
 */
int moho::cfunc_CMauiItemListEmpty(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListEmptyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BCD0 (FUN_0079BCD0, func_CMauiItemListEmpty_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:Empty()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListEmpty_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Empty",
    &moho::cfunc_CMauiItemListEmpty,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BD30 (FUN_0079BD30, cfunc_CMauiItemListEmptyL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns whether the item storage is empty.
 */
int moho::cfunc_CMauiItemListEmptyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListEmptyHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const int itemCount = GetItemListEntryCount(*itemList);

  lua_pushboolean(state->m_state, itemCount == 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BE10 (FUN_0079BE10, cfunc_CMauiItemListScrollToTop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListScrollToTopL`.
 */
int moho::cfunc_CMauiItemListScrollToTop(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListScrollToTopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BE30 (FUN_0079BE30, func_CMauiItemListScrollToTop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ScrollToTop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListScrollToTop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ScrollToTop",
    &moho::cfunc_CMauiItemListScrollToTop,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListScrollToTopHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BE90 (FUN_0079BE90, cfunc_CMauiItemListScrollToTopL)
 *
 * What it does:
 * Reads one `CMauiItemList` and scrolls to top.
 */
int moho::cfunc_CMauiItemListScrollToTopL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListScrollToTopHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  itemList->ScrollSetTop(kVerticalScrollAxis, 0.0f);
  return 0;
}

/**
 * Address: 0x0079C070 (FUN_0079C070, cfunc_CMauiItemListShowItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowItemL`.
 */
int moho::cfunc_CMauiItemListShowItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListShowItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C090 (FUN_0079C090, func_CMauiItemListShowItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowItem(index)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowItem",
    &moho::cfunc_CMauiItemListShowItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C0F0 (FUN_0079C0F0, cfunc_CMauiItemListShowItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and scrolls when that row is
 * outside the current visible range.
 */
int moho::cfunc_CMauiItemListShowItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListShowItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    itemList->ShowItem(index);
  }

  return 0;
}

/**
 * Address: 0x0079C200 (FUN_0079C200, cfunc_CMauiItemListGetRowHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetRowHeightL`.
 */
int moho::cfunc_CMauiItemListGetRowHeight(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListGetRowHeightL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C220 (FUN_0079C220, func_CMauiItemListGetRowHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetRowHeight()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetRowHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetRowHeight",
    &moho::cfunc_CMauiItemListGetRowHeight,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetRowHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C280 (FUN_0079C280, cfunc_CMauiItemListGetRowHeightL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns line height from font metrics.
 */
int moho::cfunc_CMauiItemListGetRowHeightL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListGetRowHeightHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const CD3DFont* const font = itemList->mFont;

  lua_pushnumber(state->m_state, font->mExternalLeading + font->mHeight);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079C4E0 (FUN_0079C4E0, cfunc_CMauiItemListShowMouseoverItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowMouseoverItemL`.
 */
int moho::cfunc_CMauiItemListShowMouseoverItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListShowMouseoverItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C500 (FUN_0079C500, func_CMauiItemListShowMouseoverItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowMouseoverItem(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowMouseoverItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowMouseoverItem",
    &moho::cfunc_CMauiItemListShowMouseoverItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowMouseoverItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C560 (FUN_0079C560, cfunc_CMauiItemListShowMouseoverItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus boolean and toggles hover-item highlight.
 */
int moho::cfunc_CMauiItemListShowMouseoverItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListShowMouseoverItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject flagArg(state, 2);
  itemList->mShowMouseoverItem = LuaPlus::LuaStackObject::GetBoolean(&flagArg);
  return 0;
}

/**
 * Address: 0x0079C620 (FUN_0079C620, cfunc_CMauiItemListShowSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowSelectionL`.
 */
int moho::cfunc_CMauiItemListShowSelection(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListShowSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C640 (FUN_0079C640, func_CMauiItemListShowSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowSelection(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowSelection",
    &moho::cfunc_CMauiItemListShowSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C6A0 (FUN_0079C6A0, cfunc_CMauiItemListShowSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus boolean and toggles selection highlight.
 */
int moho::cfunc_CMauiItemListShowSelectionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListShowSelectionHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject flagArg(state, 2);
  itemList->mShowSelection = LuaPlus::LuaStackObject::GetBoolean(&flagArg);
  return 0;
}

/**
 * Address: 0x0079C760 (FUN_0079C760, cfunc_CMauiItemListNeedsScrollBar)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListNeedsScrollBarL`.
 */
int moho::cfunc_CMauiItemListNeedsScrollBar(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListNeedsScrollBarL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C780 (FUN_0079C780, func_CMauiItemListNeedsScrollBar_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:NeedsScrollBar()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListNeedsScrollBar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "NeedsScrollBar",
    &moho::cfunc_CMauiItemListNeedsScrollBar,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListNeedsScrollBarHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C7E0 (FUN_0079C7E0, cfunc_CMauiItemListNeedsScrollBarL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns whether visible rows are fewer than
 * total item count.
 */
int moho::cfunc_CMauiItemListNeedsScrollBarL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListNeedsScrollBarHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  lua_pushboolean(state->m_state, itemList->NeedsScrollBar());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007994C0 (FUN_007994C0, sub_7994C0)
 *
 * What it does:
 * Releases list-item string storage and one intrusive font reference, then
 * continues base `CMauiControl` teardown.
 */
moho::CMauiItemList::~CMauiItemList()
{
  mItems = fa::vector<fa::string>{};
  ReleaseIntrusiveFont(mFont);
}

/**
 * Address: 0x00799610 (FUN_00799610, Moho::CMauiItemList::SetFont)
 *
 * What it does:
 * Rebinds item-list font lane, falling back to default face/size when nil is
 * requested.
 */
void moho::CMauiItemList::SetFont(
  CD3DFont* const font
)
{
  if (font != nullptr) {
    AssignIntrusiveFont(mFont, font);
    return;
  }

  boost::SharedPtrRaw<CD3DFont> defaultFont = CD3DFont::Create(16, "New Times Roman");
  AssignIntrusiveFont(mFont, defaultFont.px);
  defaultFont.release();
}

/**
 * Address: 0x00799A50 (FUN_00799A50, Moho::CMauiItemList::Draw)
 *
 * IDA signature:
 * void __thiscall Moho::CMauiItemList::Draw(
 *     CMauiItemList* this, CD3DPrimBatcher* primBatcher, int drawMask);
 *
 * What it does:
 * Draws the item-list background quad, optional hover/selection highlight row
 * quads, then renders each visible item's text with the resolved foreground
 * color. All work is skipped when no font is bound.
 */
void moho::CMauiItemList::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t /*drawMask*/
)
{
  const CD3DFont* const font = mFont;
  if (font == nullptr) {
    return;
  }


  const std::int32_t visibleLineCount = LinesVisible();

  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);

  const std::uint32_t vertexColor = mVertexAlpha;

  // Background quad spanning the full control rectangle.
  {
    const boost::shared_ptr<CD3DBatchTexture> backgroundTexture =
      CD3DBatchTexture::FromSolidColor(mBackgroundColor);
    primBatcher->SetTexture(backgroundTexture);

    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, vertexColor, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, vertexColor, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, vertexColor, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, vertexColor, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  const float rowHeight = font->mHeight + font->mExternalLeading;

  // Mouse-over highlight row quad.
  if (mShowMouseoverItem) {
    const std::int32_t hoverItem = mHoverItem;
    const std::int32_t scrollPosition = mScrollPosition;
    if (hoverItem >= scrollPosition && hoverItem < scrollPosition + visibleLineCount) {
      const std::int32_t visibleRow = hoverItem - scrollPosition;
      const float rowTop = rowHeight * static_cast<float>(static_cast<std::uint32_t>(visibleRow)) + top;
      const float rowBottom = font->mHeight + rowTop;

      const boost::shared_ptr<CD3DBatchTexture> highlightTexture =
        CD3DBatchTexture::FromSolidColor(mHighlightBackgroundColor);
      primBatcher->SetTexture(highlightTexture);

      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, rowTop, vertexColor, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, rowTop, vertexColor, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, rowBottom, vertexColor, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, rowBottom, vertexColor, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }

  // Selection highlight row quad.
  if (mShowSelection) {
    const std::int32_t curSelection = mCurSelection;
    const std::int32_t scrollPosition = mScrollPosition;
    if (curSelection >= scrollPosition && curSelection < scrollPosition + visibleLineCount) {
      const std::int32_t visibleRow = curSelection - scrollPosition;
      const float rowTop = rowHeight * static_cast<float>(static_cast<std::uint32_t>(visibleRow)) + top;
      const float rowBottom = font->mHeight + rowTop;

      const boost::shared_ptr<CD3DBatchTexture> selectedTexture =
        CD3DBatchTexture::FromSolidColor(mSelectedBackgroundColor);
      primBatcher->SetTexture(selectedTexture);

      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, rowTop, vertexColor, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, rowTop, vertexColor, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, rowBottom, vertexColor, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, rowBottom, vertexColor, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }

  // Per-row item text.
  if (visibleLineCount <= 0) {
    return;
  }

  for (std::int32_t visibleRow = 0; visibleRow < visibleLineCount; ++visibleRow) {
    const fa::string* const itemStorage = mItems.data();
    const std::int32_t itemIndex = visibleRow + mScrollPosition;
    if (itemStorage == nullptr || static_cast<std::uint32_t>(itemIndex) >= mItems.size()) {
      break;
    }

    std::uint32_t textColor = mForegroundColor;
    if (itemIndex == mHoverItem && mShowMouseoverItem) {
      textColor = mHighlightForegroundColor;
    } else if (itemIndex == mCurSelection && mShowSelection) {
      textColor = mSelectedForegroundColor;
    }

    const float maxAdvance = CScriptLazyVar_float::GetValue(&mWidthLV);
    const float baselineY =
      rowHeight * static_cast<float>(static_cast<std::uint32_t>(visibleRow)) + font->mAscent + top;

    const fa::string& itemText = itemStorage[itemIndex];
    const Wm3::Vector3f origin{left, baselineY, 0.0f};
    const Wm3::Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Wm3::Vector3f yAxis{0.0f, -1.0f, 0.0f};
    (void)mFont->Render(itemText.c_str(), primBatcher, origin, xAxis, yAxis, textColor, 1.0f, maxAdvance);
  }
}

/**
 * Address: 0x00799780 (FUN_00799780, Moho::CMauiItemList::ModifyItem)
 *
 * What it does:
 * Replaces one existing item string lane by index and throws when index is
 * out of range.
 */
void moho::CMauiItemList::ModifyItem(
  const std::uint32_t index,
  fa::string text
)
{
  fa::string* const itemBase = mItems.data();
  const std::uint32_t itemCount = itemBase != nullptr ? static_cast<std::uint32_t>(mItems.size()) : 0u;

  if (itemBase == nullptr || index >= itemCount) {
    throw std::runtime_error(
      gpg::STR_Printf("ModifyItem: index %u out of range; must be < %u", index, itemCount).c_str()
    );
  }

  itemBase[index] = text;
}

/**
 * Address: 0x00799940 (FUN_00799940, Moho::CMauiItemList::DeleteItem)
 *
 * What it does:
 * Removes one item lane by index and adjusts current selection to preserve
 * post-delete selection semantics.
 */
void moho::CMauiItemList::DeleteItem(
  const std::int32_t index
)
{
  if (index < 0) {
    return;
  }

  fa::string* const itemBase = mItems.data();
  if (itemBase == nullptr || static_cast<std::size_t>(index) >= mItems.size()) {
    return;
  }

  RemoveItemListEntryAtIndex(this, index);
}

/**
 * Address: 0x00799870 (FUN_00799870, Moho::CMauiItemList::AddItem)
 *
 * What it does:
 * Appends one item string lane to the item-list storage vector.
 */
void moho::CMauiItemList::AddItem(
  fa::string text
)
{
  mItems.push_back(text);
}

/**
 * Address: 0x0079A0B0 (FUN_0079A0B0, Moho::CMauiItemList::GetItem)
 *
 * What it does:
 * Converts one Y-coordinate lane to an item index lane using top/scroll/font
 * metrics and returns `-1` when no item row is hit.
 */
std::int32_t moho::CMauiItemList::GetItem(
  const float yCoordinate
)
{
  const CD3DFont* const font = mFont;

  const float localY = yCoordinate - CScriptLazyVar_float::GetValue(&mTopLV);
  const float rowHeight = font->mExternalLeading + font->mHeight;

  const auto* const itemBase = mItems.data();
  const std::int32_t rowIndex = mScrollPosition + static_cast<std::int32_t>(localY / rowHeight);
  if (
    itemBase != nullptr && rowIndex >= 0 && static_cast<std::size_t>(rowIndex) < mItems.size() &&
    font->mHeight > static_cast<float>(fa::fmod(localY, rowHeight)) // 0x0079A126: _CIfmod
  ) {
    return rowIndex;
  }

  return -1;
}

/**
 * Address: 0x00799560 (FUN_00799560, Moho::CMauiItemList::Dump)
 *
 * What it does:
 * Logs item-list palette lanes and current-selection text state.
 */
void moho::CMauiItemList::Dump()
{
  CMauiControl::Dump();

  gpg::Logf("CMauiItemList");
  gpg::Logf(
    "FG Color = %#08X BG Color = %#08X HLFG Color = %#08X HLBG Color = %#08X MOFG Color = %#08X MOBG Color = %#08X",
    mForegroundColor,
    mBackgroundColor,
    mSelectedForegroundColor,
    mSelectedBackgroundColor,
    mHighlightForegroundColor,
    mHighlightBackgroundColor
  );

  const std::int32_t curSelection = mCurSelection;
  if (curSelection == -1) {
    gpg::Logf("Current Selection = %d Text = %s", curSelection, "");
    return;
  }

  const fa::string* const itemStorage = mItems.data();
  const fa::string& selectedItem = itemStorage[curSelection];
  gpg::Logf("Current Selection = %d Text = %s", curSelection, selectedItem.c_str());
}

/**
 * Address: 0x0079A560 (FUN_0079A560, Moho::CMauiItemList::GetScrollValues)
 *
 * What it does:
 * Computes current item-list scroll extents and visible-range window.
 */
moho::SMauiScrollValues moho::CMauiItemList::GetScrollValues(
  const EMauiScrollAxis /*axis*/
)
{
  const int visibleLineCount = LinesVisible();

  SMauiScrollValues scrollValues{};
  scrollValues.mMinRange = 0.0f;
  scrollValues.mMaxRange = static_cast<float>(GetItemListEntryCount(*this));
  scrollValues.mMinVisible = static_cast<float>(mScrollPosition);
  scrollValues.mMaxVisible = static_cast<float>(mScrollPosition + visibleLineCount);
  return scrollValues;
}

/**
 * Address: 0x0079A5F0 (FUN_0079A5F0, Moho::CMauiItemList::ScrollLines)
 *
 * What it does:
 * Applies line-scroll delta and clamps top-scroll lane to valid item-list
 * bounds.
 */
void moho::CMauiItemList::ScrollLines(
  const EMauiScrollAxis /*axis*/,
  const float amount
)
{
  const int visibleLineCount = LinesVisible();
  int clampedTop = GetItemListEntryCount(*this) - visibleLineCount;

  const int lineDelta = static_cast<int>(std::nearbyintf(amount));
  const int candidateTop = mScrollPosition + lineDelta;
  if (candidateTop < clampedTop) {
    clampedTop = candidateTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A6D0 (FUN_0079A6D0, Moho::CMauiItemList::ScrollSetTop)
 *
 * What it does:
 * Sets top-scroll lane from one absolute row index and clamps it to valid
 * item-list bounds.
 */
void moho::CMauiItemList::ScrollSetTop(
  const EMauiScrollAxis /*axis*/,
  const float amount
)
{
  const int visibleLineCount = LinesVisible();
  int clampedTop = GetItemListEntryCount(*this) - visibleLineCount;

  const int requestedTop = static_cast<int>(std::nearbyintf(amount));
  if (requestedTop < clampedTop) {
    clampedTop = requestedTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A650 (FUN_0079A650, Moho::CMauiItemList::ScrollLines2)
 *
 * What it does:
 * Applies page-scroll delta (`amount * visible-row-count`) and clamps
 * top-scroll lane to `[0, itemCount - visibleLineCount]`.
 */
void moho::CMauiItemList::ScrollPages(
  const EMauiScrollAxis /*axis*/,
  const float amount
)
{
  const int visibleLineCount = LinesVisible();
  int clampedTop = GetItemListEntryCount(*this) - visibleLineCount;

  const auto visibleLineCountUnsigned = static_cast<std::uint32_t>(visibleLineCount);
  const float scaledDelta = static_cast<float>(visibleLineCountUnsigned) * amount;
  const int pageDelta = static_cast<int>(std::nearbyintf(scaledDelta));
  const int candidateTop = mScrollPosition + pageDelta;
  if (candidateTop < clampedTop) {
    clampedTop = candidateTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A730 (FUN_0079A730, Moho::CMauiItemList::LinesVisible)
 *
 * What it does:
 * Computes one visible-row count from current control/font metrics and
 * clamps scroll-position lane against available item count.
 */
std::int32_t moho::CMauiItemList::LinesVisible()
{
  const CD3DFont* const font = mFont;
  const float controlHeight = CScriptLazyVar_float::GetValue(&mHeightLV);
  const float lineHeight = font->mHeight + font->mExternalLeading;
  const float visibleLineRatio = (font->mExternalLeading + controlHeight) / lineHeight;
  const int visibleLineCount = static_cast<std::int32_t>(std::floor(visibleLineRatio));

  const int itemCount = GetItemListEntryCount(*this);
  if (visibleLineCount > itemCount) {
    mScrollPosition = 0;
    return itemCount;
  }

  if (visibleLineCount + mScrollPosition > itemCount) {
    if (itemCount == 0) {
      mScrollPosition = -visibleLineCount;
      return visibleLineCount;
    }
    mScrollPosition = itemCount - visibleLineCount;
  }

  return visibleLineCount;
}

/**
 * Address: 0x0079A870 (FUN_0079A870, Moho::CMauiItemList::ScrollToBottom)
 *
 * What it does:
 * Scrolls to the bottommost list row by setting top-scroll to current
 * item count.
 */
void moho::CMauiItemList::ScrollToBottom()
{
  const int itemCount = GetItemListEntryCount(*this);
  ScrollSetTop(kVerticalScrollAxis, static_cast<float>(itemCount));
}

/**
 * Address: 0x0079A8C0 (FUN_0079A8C0, Moho::CMauiItemList::ShowItem)
 *
 * What it does:
 * Scrolls the item list so index is visible inside the current viewport.
 */
void moho::CMauiItemList::ShowItem(
  const std::int32_t index
)
{
  const std::int32_t visibleLineCount = LinesVisible();
  const std::int32_t scrollPosition = mScrollPosition;
  if (index < scrollPosition || index >= (scrollPosition + visibleLineCount)) {
    ScrollSetTop(kVerticalScrollAxis, static_cast<float>(index));
  }
}

/**
 * Address: 0x0079A160 (FUN_0079A160, Moho::CMauiItemList::HandleEvent)
 * Mangled: ?HandleEvent@CMauiItemList@Moho@@UAE_NABUSMauiEventData@2@@Z
 *
 * IDA signature:
 *   char __thiscall Moho::CMauiItemList::HandleEvent(
 *     Moho::CMauiItemList* this, Moho::SMauiEventData* eventData);
 *
 * What it does:
 * Dispatches the incoming MAUI event into list-control behavior. Defers first
 * to the base `CMauiControl::HandleEvent` Lua hook (which can fully consume
 * the event); otherwise switches on the event type:
 *   - MET_MouseMotion: when mouse-over highlighting is enabled, recompute the
 *     hover row from the cursor Y and emit `OnMouseoverItem(self,row)` when
 *     the hover row changes.
 *   - MET_MouseExit: clear any active hover row and emit
 *     `OnMouseoverItem(self,-1)` once.
 *   - MET_ButtonPress / MET_ButtonDClick: resolve the clicked row and emit
 *     `OnClick(self,row,event)` (or `OnDoubleClick`) when a row is hit.
 *   - MET_WheelRotation: scroll vertically by one line in the wheel direction.
 *   - MET_Char: route navigation keys (PRIOR/PAGEUP, NEXT/PAGEDOWN, HOME, END,
 *     UP, DOWN) into selection movement and emit `OnKeySelect(self,row)`;
 *     other character codes fall through to the same row-click path used by
 *     button events.
 */
bool moho::CMauiItemList::HandleEvent(
  const SMauiEventData& eventData
)
{
  if (CMauiControl::HandleEvent(eventData)) {
    return true;
  }

  CScriptObject* const scriptObject = this;

  const auto runClickRowCallback = [&]() {
    const std::int32_t clickedRow = GetItem(eventData.mMousePos.y);
    if (clickedRow < 0) {
      return;
    }

    const char* const callbackName = eventData.mEventType == MET_ButtonPress ? "OnClick" : "OnDoubleClick";
    LuaPlus::LuaState* const activeState =
      mLuaObj.GetActiveState();
    LuaPlus::LuaObject eventObject{};
    const LuaPlus::LuaObject* const createdEvent =
      CreateLuaEventObject(const_cast<SMauiEventData*>(&eventData), &eventObject, activeState);
    scriptObject->RunScriptIntObject(callbackName, clickedRow, *createdEvent);
  };

  switch (eventData.mEventType) {
  case MET_MouseMotion: {
    if (!mShowMouseoverItem) {
      return false;
    }

    const std::int32_t previousHover = mHoverItem;
    const std::int32_t newHover = GetItem(eventData.mMousePos.y);
    mHoverItem = newHover;
    if (previousHover != newHover) {
      scriptObject->CallbackInt("OnMouseoverItem", mHoverItem);
    }
    return true;
  }

  case MET_MouseExit: {
    if (mHoverItem != -1) {
      mHoverItem = -1;
      scriptObject->CallbackInt("OnMouseoverItem", mHoverItem);
    }
    return true;
  }

  case MET_ButtonPress:
  case MET_ButtonDClick: {
    runClickRowCallback();
    return true;
  }

  case MET_WheelRotation: {
    const float lineDelta = eventData.mWheelRotation <= 0 ? 1.0f : -1.0f;
    ScrollLines(kVerticalScrollAxis, lineDelta);
    return true;
  }

  case MET_Char: {
    switch (eventData.mKeyCode) {
    case MKEY_PRIOR:
    case MKEY_PAGEUP: {
      const std::int32_t cursorOffsetInPage = mCurSelection - mScrollPosition;
      const std::int32_t scrollBeforePage = mScrollPosition;
      ScrollPages(kVerticalScrollAxis, -1.0f);

      std::int32_t newRow = 0;
      if (scrollBeforePage != mScrollPosition) {
        newRow = mScrollPosition + cursorOffsetInPage;
      }
      (void)SetItemListSelectionByRow(*this, static_cast<std::uint32_t>(newRow));
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    case MKEY_NEXT:
    case MKEY_PAGEDOWN: {
      const std::int32_t cursorOffsetInPage = mCurSelection - mScrollPosition;
      const std::int32_t scrollBeforePage = mScrollPosition;
      ScrollPages(kVerticalScrollAxis, 1.0f);

      const std::int32_t lastRow = GetItemListEntryCount(*this) - 1;
      std::int32_t newRow = lastRow;
      if (scrollBeforePage != mScrollPosition) {
        const std::int32_t candidate = mScrollPosition + cursorOffsetInPage;
        newRow = candidate >= lastRow ? lastRow : candidate;
      }
      (void)SetItemListSelectionByRow(*this, static_cast<std::uint32_t>(newRow));
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    case MKEY_END: {
      ScrollToBottom();
      const std::int32_t lastRow = GetItemListEntryCount(*this) - 1;
      (void)SetItemListSelectionByRow(*this, static_cast<std::uint32_t>(lastRow));
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    case MKEY_HOME: {
      ScrollSetTop(kVerticalScrollAxis, 0.0f);
      (void)SetItemListSelectionByRow(*this, 0u);
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    case MKEY_UP: {
      const std::int32_t candidate = mCurSelection - 1;
      const std::int32_t newRow = candidate <= 0 ? 0 : candidate;
      (void)SetItemListSelectionByRow(*this, static_cast<std::uint32_t>(newRow));
      ShowItem(mCurSelection);
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    case MKEY_DOWN: {
      const std::int32_t lastRow = GetItemListEntryCount(*this) - 1;
      const std::int32_t candidate = mCurSelection + 1;
      const std::int32_t newRow = candidate >= lastRow ? lastRow : candidate;
      (void)SetItemListSelectionByRow(*this, static_cast<std::uint32_t>(newRow));
      ShowItem(mCurSelection);
      scriptObject->CallbackInt("OnKeySelect", mCurSelection);
      return true;
    }

    default: {
      // Mirrors the original `default: goto LABEL_25;` fall-through:
      // unhandled character codes route through the row-click helper, and
      // because the event type is MET_Char (not MET_ButtonPress) the helper
      // emits the `OnDoubleClick` callback name when a row is hit.
      runClickRowCallback();
      return true;
    }
    }
  }

  default:
    return false;
  }
}

/**
 * Address: 0x0079A8F0 (FUN_0079A8F0, Moho::CMauiItemList::NeedsScrollBar)
 *
 * What it does:
 * Returns whether visible-row capacity is smaller than item count.
 */
bool moho::CMauiItemList::NeedsScrollBar()
{
  const int visibleLineCount = LinesVisible();
  return visibleLineCount < GetItemListEntryCount(*this);
}

/**
 * Address: 0x0079B1E0 (FUN_0079B1E0, cfunc_CMauiItemListAddItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListAddItemL`.
 */
int moho::cfunc_CMauiItemListAddItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListAddItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B200 (FUN_0079B200, func_CMauiItemListAddItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:AddItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListAddItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AddItem",
    &moho::cfunc_CMauiItemListAddItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListAddItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B260 (FUN_0079B260, cfunc_CMauiItemListAddItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus string arg and appends one item.
 */
int moho::cfunc_CMauiItemListAddItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListAddItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* itemText = lua_tostring(state->m_state, 2);
  if (itemText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    itemText = "";
  }

  itemList->AddItem(fa::string(itemText));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B370 (FUN_0079B370, cfunc_CMauiItemListModifyItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListModifyItemL`.
 */
int moho::cfunc_CMauiItemListModifyItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListModifyItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B390 (FUN_0079B390, func_CMauiItemListModifyItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ModifyItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListModifyItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ModifyItem",
    &moho::cfunc_CMauiItemListModifyItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListModifyItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B560 (FUN_0079B560, cfunc_CMauiItemListDeleteItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListDeleteItemL`.
 */
int moho::cfunc_CMauiItemListDeleteItem(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListDeleteItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B580 (FUN_0079B580, func_CMauiItemListDeleteItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:DeleteItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListDeleteItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DeleteItem",
    &moho::cfunc_CMauiItemListDeleteItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListDeleteItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B6E0 (FUN_0079B6E0, cfunc_CMauiItemListDeleteAllItems)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListDeleteAllItemsL`.
 */
int moho::cfunc_CMauiItemListDeleteAllItems(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListDeleteAllItemsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B700 (FUN_0079B700, func_CMauiItemListDeleteAllItems_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:DeleteAllItems()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListDeleteAllItems_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DeleteAllItems",
    &moho::cfunc_CMauiItemListDeleteAllItems,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListDeleteAllItemsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B840 (FUN_0079B840, cfunc_CMauiItemListGetSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetSelectionL`.
 */
int moho::cfunc_CMauiItemListGetSelection(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListGetSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B860 (FUN_0079B860, func_CMauiItemListGetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetSelection()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSelection",
    &moho::cfunc_CMauiItemListGetSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B3F0 (FUN_0079B3F0, cfunc_CMauiItemListModifyItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus `(index,text)` and updates one list item
 * when the provided index is non-negative.
 */
int moho::cfunc_CMauiItemListModifyItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kCMauiItemListModifyItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    LuaPlus::LuaStackObject textArg(state, 3);
    const char* itemText = lua_tostring(state->m_state, 3);
    if (itemText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textArg, "string");
      itemText = "";
    }

    itemList->ModifyItem(static_cast<std::uint32_t>(index), fa::string(itemText));
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B5E0 (FUN_0079B5E0, cfunc_CMauiItemListDeleteItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus one index and deletes that item when index
 * is non-negative.
 */
int moho::cfunc_CMauiItemListDeleteItemL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListDeleteItemHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    itemList->DeleteItem(index);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B760 (FUN_0079B760, cfunc_CMauiItemListDeleteAllItemsL)
 *
 * What it does:
 * Clears all item lanes and resets current selection to no-selection.
 */
int moho::cfunc_CMauiItemListDeleteAllItemsL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListDeleteAllItemsHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  itemList->mItems.clear();
  itemList->mCurSelection = -1;

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B8C0 (FUN_0079B8C0, cfunc_CMauiItemListGetSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` and pushes current selected-index lane.
 */
int moho::cfunc_CMauiItemListGetSelectionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiItemListGetSelectionHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(itemList->mCurSelection));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079C350 (FUN_0079C350, cfunc_CMauiItemListGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetStringAdvanceL`.
 */
int moho::cfunc_CMauiItemListGetStringAdvance(
  lua_State* const luaContext
)
{
  return cfunc_CMauiItemListGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C370 (FUN_0079C370, func_CMauiItemListGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiItemListGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C3D0 (FUN_0079C3D0, cfunc_CMauiItemListGetStringAdvanceL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus string arg and returns measured text
 * advance from the item-list font lane.
 */
int moho::cfunc_CMauiItemListGetStringAdvanceL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiItemListGetStringAdvanceHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  CD3DFont* const font = itemList->mFont;
  const float advance = font != nullptr ? font->GetAdvance(text, 0) : 0.0f;
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00799050 (FUN_00799050, Moho::CMauiItemList::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiItemList`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiItemList::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiItemList));
  }
  return sType;
}

/**
 * Address: 0x00799070 (FUN_00799070, Moho::CMauiItemList::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiItemList::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
