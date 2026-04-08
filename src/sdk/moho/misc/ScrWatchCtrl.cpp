#include "moho/misc/ScrWatchCtrl.h"

#include <cstdint>
#include <sstream>
#include <string>

#include "gpg/core/containers/String.h"
#include "lua/LuaAssertion.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/TreeData.h"

namespace
{
  [[nodiscard]] wxStringRuntime BorrowUtf8AsWxString(const char* const text)
  {
    static thread_local std::wstring wideScratch{};
    wideScratch = gpg::STR_Utf8ToWide(text != nullptr ? text : "");
    return wxStringRuntime::Borrow(wideScratch.c_str());
  }

  [[nodiscard]] wxStringRuntime BorrowUtf8AsWxString(const msvc8::string& text)
  {
    return BorrowUtf8AsWxString(text.c_str());
  }

  void SortWatchRootChildren(moho::ScrWatchCtrl& control, const wxTreeItemIdRuntime& rootItem) noexcept
  {
    if (!rootItem.IsValid()) {
      return;
    }

    control.SortChildren(rootItem);
  }

  /**
   * Address: 0x004D7280 (FUN_004D7280, FormatWatchKeyForTree)
   *
   * What it does:
   * Converts one Lua table-key object into display text for watch-tree rows,
   * handling boolean/number/string lanes and using `<unknown>` fallback.
   */
  [[nodiscard]] msvc8::string FormatWatchKeyForTree(const LuaPlus::LuaObject& keyObject)
  {
    msvc8::string keyText{};

    if (keyObject.IsBoolean()) {
      keyText.assign_owned(keyObject.GetBoolean() ? "true" : "false");
      return keyText;
    }

    if (keyObject.IsNumber()) {
      std::ostringstream numberStream{};
      numberStream << static_cast<float>(keyObject.GetNumber());
      keyText.assign_owned(numberStream.str());
      return keyText;
    }

    if (keyObject.IsString()) {
      keyText.assign_owned(keyObject.GetString());
      return keyText;
    }

    keyText.assign_owned("<unknown>");
    return keyText;
  }
} // namespace

void* moho::ScrWatchCtrl::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x004D6FE0 (FUN_004D6FE0, Moho::ScrWatchCtrl::GetEventTable)
 *
 * What it does:
 * Returns this control's wx event-table lane.
 */
const void* moho::ScrWatchCtrl::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x004D7270 (FUN_004D7270, Moho::ScrWatchCtrl::Clear)
 *
 * What it does:
 * Clears watch rows under the root tree item lane.
 */
void moho::ScrWatchCtrl::Clear()
{
  mRootItem.Reset();
}

/**
 * Address: 0x004D7220 (FUN_004D7220, Moho::ScrWatchCtrl::Update)
 *
 * What it does:
 * Rebuilds this watch tree from one watch-vector snapshot.
 */
void moho::ScrWatchCtrl::Update(const msvc8::vector<ScrWatch>& watches)
{
  Clear();
  mRootItem = AddRoot(wxStringRuntime::Borrow(L""));

  for (const ScrWatch& watch : watches) {
    AddWatch(mRootItem, watch);
  }

  SortWatchRootChildren(*this, mRootItem);
}

/**
 * Address: 0x004D7380 (FUN_004D7380, Moho::ScrWatchCtrl::OnItemActivate)
 *
 * What it does:
 * Materializes child watch rows when an activated item contains a Lua table,
 * sorts those children, then toggles the expanded state.
 */
void moho::ScrWatchCtrl::OnItemActivate(wxTreeEventRuntime& event)
{
  wxTreeItemIdRuntime activatedItem{};
  event.GetItem(&activatedItem);
  if (!activatedItem.IsValid()) {
    return;
  }

  auto* const itemData = static_cast<TreeData*>(GetItemData(activatedItem));
  if (itemData == nullptr) {
    return;
  }

  LuaPlus::LuaObject& tableObject = itemData->mWatch.obj;
  if (!tableObject.IsTable()) {
    return;
  }

  if (!HasChildren(activatedItem)) {
    LuaPlus::LuaTableIterator iter(&tableObject, 1);
    if (!iter.m_isDone) {
      while (true) {
        const msvc8::string keyText = FormatWatchKeyForTree(iter.m_keyObj);
        if (!iter.IsValid()) {
          throw LuaPlus::LuaAssertion("IsValid()");
        }

        const ScrWatch childWatch(keyText, iter.m_valueObj);
        AddWatch(activatedItem, childWatch);

        iter.Next();
        if (iter.m_isDone) {
          break;
        }
      }
    }

    SortChildren(activatedItem);
  }

  if (IsExpanded(activatedItem)) {
    Collapse(activatedItem);
    return;
  }

  Expand(activatedItem);
}

/**
 * Address: 0x004D7580 (FUN_004D7580, Moho::ScrWatchCtrl::AddWatch)
 *
 * What it does:
 * Appends one watch row and fills name/type/value columns plus payload.
 */
void moho::ScrWatchCtrl::AddWatch(const wxTreeItemIdRuntime& parentItem, const ScrWatch& watch)
{
  const wxTreeItemIdRuntime item = AppendItem(parentItem, BorrowUtf8AsWxString(watch.name));
  SetItemData(item, new TreeData(watch));

  const msvc8::string watchType = watch.GetType();
  SetItemText(item, 1u, BorrowUtf8AsWxString(watchType));

  const msvc8::string watchValue = watch.GetValue();
  SetItemText(item, 2u, BorrowUtf8AsWxString(watchValue));
}
