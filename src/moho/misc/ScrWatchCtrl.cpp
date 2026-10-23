#include "moho/misc/ScrWatchCtrl.h"

#include <sstream>

#include "gpg/core/containers/String.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/TreeData.h"

namespace
{
  constexpr long kWatchTreeStyle = wxTR_HAS_BUTTONS | wxTR_LINES_AT_ROOT | wxTR_HIDE_ROOT | wxTR_FULL_ROW_HIGHLIGHT;

  /**
   * Address: 0x004D7280 (FUN_004D7280)
   *
   * What it does:
   * A table key as a row name: booleans and numbers printed, strings as they
   * are, anything else "<unknown>".
   */
  msvc8::string FormatWatchKeyForTree(const LuaPlus::LuaObject& key)
  {
    switch (key.Type()) {
      case LUA_TBOOLEAN:
        return key.GetBoolean() ? "true" : "false";
      case LUA_TNUMBER: {
        std::ostringstream stream;
        stream << static_cast<float>(key.GetNumber()); // FA's lua_Number is a float
        return stream.str().c_str();
      }
      case LUA_TSTRING:
        return key.GetString();
      default:
        return "<unknown>";
    }
  }
} // namespace

// Table 0x00DFF60C = {&wxTreeListCtrl::sm_eventTable (0x00D52EFC), rows 0x00F596D4};
// GetEventTable (0x004D6FE0) comes with it.
BEGIN_EVENT_TABLE(moho::ScrWatchCtrl, wxTreeListCtrl)
END_EVENT_TABLE()

/**
 * Address: 0x004D6FF0 (FUN_004D6FF0, ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z)
 */
moho::ScrWatchCtrl::ScrWatchCtrl(
  wxWindow* const parent,
  const int& id,
  const int nameWidth,
  const int typeWidth,
  const int valueWidth,
  const wxPoint& pos,
  const wxSize& size
)
  : wxTreeListCtrl(parent, id, pos, size, kWatchTreeStyle)
  , mRoot()
{
  AddColumn(wxT("Variable"), nameWidth, false);
  AddColumn(wxT("Type"), typeWidth, false);
  AddColumn(wxT("Value"), valueWidth, false);
  mRoot = AddRoot(wxT("VARIABLES"));

  Connect(
    GetId(), -1, wxEVT_COMMAND_TREE_ITEM_ACTIVATED,
    (wxObjectEventFunction)(wxEventFunction)(wxTreeEventFunction)&ScrWatchCtrl::OnItemActivate
  );
}

/**
 * Address: 0x004D7270 (FUN_004D7270, ?Clear@ScrWatchCtrl@Moho@@UAEXXZ)
 */
void moho::ScrWatchCtrl::Clear()
{
  DeleteChildren(mRoot);
}

/**
 * Address: 0x004D7220 (FUN_004D7220, ?Update@ScrWatchCtrl@Moho@@QAEXABV?$vector@VScrWatch@Moho@@V?$allocator@VScrWatch@Moho@@@std@@@std@@@Z)
 */
void moho::ScrWatchCtrl::Update(const msvc8::vector<ScrWatch>& watches)
{
  Clear();
  for (msvc8::vector<ScrWatch>::const_iterator watch = watches.begin(); watch != watches.end(); ++watch) {
    AddWatch(mRoot, *watch);
  }
  SortChildren(mRoot);
}

/**
 * Address: 0x004D7380 (FUN_004D7380, ?OnItemActivate@ScrWatchCtrl@Moho@@QAEXAAVwxTreeEvent@@@Z)
 */
void moho::ScrWatchCtrl::OnItemActivate(wxTreeEvent& event)
{
  const wxTreeItemId item = event.GetItem();
  if (!item.IsOk()) {
    return;
  }

  TreeData* const data = static_cast<TreeData*>(GetItemData(item));
  if (data == nullptr) {
    return;
  }

  LuaPlus::LuaObject& table = data->mWatch.obj;
  if (!table.IsTable()) {
    return;
  }

  if (!HasChildren(item)) {
    for (LuaPlus::LuaTableIterator field(table, true); field; field.Next()) {
      const msvc8::string name = FormatWatchKeyForTree(field.GetKey());
      AddWatch(item, ScrWatch(name, field.GetValue()));
    }
    SortChildren(item);
  }

  if (IsExpanded(item)) {
    Collapse(item);
  } else {
    Expand(item);
  }
}

/**
 * Address: 0x004D7580 (FUN_004D7580, ?AddWatch@ScrWatchCtrl@Moho@@AAEXABVwxTreeItemId@@ABVScrWatch@2@@Z)
 */
void moho::ScrWatchCtrl::AddWatch(const wxTreeItemId& parent, const ScrWatch& watch)
{
  const wxTreeItemId item = AppendItem(parent, gpg::STR_Utf8ToWide(watch.name.c_str()).c_str());
  SetItemData(item, new TreeData(watch));
  SetItemText(item, 1, gpg::STR_Utf8ToWide(watch.GetType().c_str()).c_str());
  SetItemText(item, 2, gpg::STR_Utf8ToWide(watch.GetValue().c_str()).c_str());
}
