#include "moho/misc/ScrWatchCtrl.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "imgui.h"

#include "gpg/core/containers/String.h"
#include "lua/LuaTableIterator.h"

namespace
{
  /**
   * Address: 0x004D7280 (FUN_004D7280)
   *
   * What it does:
   * A table key as a row name: booleans and numbers printed, strings as they
   * are, anything else "<unknown>".
   */
  fa::string FormatWatchKeyForTree(
    const LuaPlus::LuaObject& key
  )
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

/**
 * Address: 0x004D6FF0 (FUN_004D6FF0, ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z)
 */
moho::ScrWatchCtrl::ScrWatchCtrl(
  const int nameWidth,
  const int typeWidth,
  const int valueWidth
)
  : mWidths{nameWidth, typeWidth, valueWidth}
{}

/**
 * Address: 0x004D7270 (FUN_004D7270, ?Clear@ScrWatchCtrl@Moho@@UAEXXZ)
 */
void moho::ScrWatchCtrl::Clear()
{
  mRows.clear();
}

/**
 * Address: 0x004D7220 (FUN_004D7220)
 */
void moho::ScrWatchCtrl::Update(
  const fa::vector<ScrWatch>& watches
)
{
  Clear();
  for (fa::vector<ScrWatch>::const_iterator watch = watches.begin(); watch != watches.end(); ++watch) {
    AddWatch(mRows, *watch);
  }
  SortRows(mRows);
}

/**
 * Address: 0x004D7580 (FUN_004D7580)
 */
void moho::ScrWatchCtrl::AddWatch(
  std::vector<std::unique_ptr<Row>>& parent,
  const ScrWatch& watch
)
{
  auto row = std::make_unique<Row>();
  row->watch = watch;
  row->type = watch.GetType();
  row->value = watch.GetValue();
  parent.push_back(std::move(row));
}

// TreeCtrl::SortChildren: by the row's text, which is the watch's name.
void moho::ScrWatchCtrl::SortRows(
  std::vector<std::unique_ptr<Row>>& rows
)
{
  std::stable_sort(rows.begin(), rows.end(), [](const std::unique_ptr<Row>& left, const std::unique_ptr<Row>& right) {
    return std::strcmp(left->watch.name.c_str(), right->watch.name.c_str()) < 0;
  });
}

/**
 * Address: 0x004D7380 (FUN_004D7380)
 */
void moho::ScrWatchCtrl::ListFields(
  Row& row
)
{
  row.listed = true;
  LuaPlus::LuaObject& table = row.watch.obj;
  if (!table.IsTable()) {
    return;
  }
  for (LuaPlus::LuaTableIterator field(table, true); field; field.Next()) {
    const fa::string name = FormatWatchKeyForTree(field.GetKey());
    AddWatch(row.children, ScrWatch(name, field.GetValue()));
  }
  SortRows(row.children);
}

void moho::ScrWatchCtrl::DrawRow(
  Row& row
)
{
  ImGui::TableNextRow();
  ImGui::TableSetColumnIndex(0);
  ImGui::PushID(&row);
  const bool isTable = row.watch.obj.IsTable();
  ImGuiTreeNodeFlags flags =
    ImGuiTreeNodeFlags_SpanFullWidth | ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick;
  if (!isTable) {
    flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
  }
  const bool open = ImGui::TreeNodeEx("##watch", flags, "%s", row.watch.name.c_str());
  if (open && isTable && !row.listed) {
    ListFields(row);
  }
  ImGui::TableSetColumnIndex(1);
  ImGui::TextUnformatted(row.type.c_str());
  ImGui::TableSetColumnIndex(2);
  ImGui::TextUnformatted(row.value.c_str());
  if (open && isTable) {
    for (const std::unique_ptr<Row>& child : row.children) {
      DrawRow(*child);
    }
    ImGui::TreePop();
  }
  ImGui::PopID();
}

bool moho::ScrWatchCtrl::Draw(
  const char* const id,
  int widths[3]
)
{
  constexpr ImGuiTableFlags kFlags = ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
    ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
  bool resized = false;
  if (!ImGui::BeginTable(id, 3, kFlags)) {
    return false;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Variable", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mWidths[0]));
  ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mWidths[1]));
  ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mWidths[2]));
  ImGui::TableHeadersRow();
  for (const std::unique_ptr<Row>& row : mRows) {
    DrawRow(*row);
  }
  // The widths after a drag of a column's edge, for the preferences.
  if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
    for (int column = 0; column < 3; ++column) {
      ImGui::TableSetColumnIndex(column);
      const int width = static_cast<int>(ImGui::GetContentRegionAvail().x + ImGui::GetStyle().CellPadding.x * 2.0f);
      if (width > 0 && width != mWidths[column]) {
        mWidths[column] = width;
        resized = true;
      }
    }
  }
  ImGui::EndTable();
  for (int column = 0; column < 3; ++column) {
    widths[column] = mWidths[column];
  }
  return resized;
}
