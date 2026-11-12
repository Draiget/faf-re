#include "moho/misc/ScrFileCtrl.h"

#include <fstream>

#include "imgui.h"

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrDebugHooks.h"

namespace
{
  // ScrFileLine::mMarkerState is the row's image, in the order the binary's constructor loaded
  // the bitmaps (/coderes/engine/dbg_cursor.bmp, dbg_cursor_enabled, dbg_cursor_disabled,
  // dbg_break_enabled, dbg_break_disabled); -1 shows none. Draw paints them as shapes.
  constexpr int kNoMarker = -1;
  constexpr int kCursorMarker = 0;
  constexpr int kCursorOnBreakpointMarker = 1;
  constexpr int kCursorOnDisabledBreakpointMarker = 2;
  constexpr int kBreakpointMarker = 3;
  constexpr int kDisabledBreakpointMarker = 4;

  // The marker column's picture: a red disc for a breakpoint (hollow when disabled), a yellow
  // arrow for the cursor, over it when both.
  void DrawMarker(
    const int marker,
    const ImVec2 origin,
    const float height
  )
  {
    if (marker == kNoMarker) {
      return;
    }
    ImDrawList* const drawList = ImGui::GetWindowDrawList();
    const float radius = height * 0.32f;
    const ImVec2 centre(origin.x + radius + 2.0f, origin.y + height * 0.5f);
    const ImU32 red = IM_COL32(220, 40, 40, 255);
    if (marker == kBreakpointMarker || marker == kCursorOnBreakpointMarker) {
      drawList->AddCircleFilled(centre, radius, red);
    } else if (marker == kDisabledBreakpointMarker || marker == kCursorOnDisabledBreakpointMarker) {
      drawList->AddCircle(centre, radius, red, 0, 1.5f);
    }
    if (marker == kCursorMarker || marker == kCursorOnBreakpointMarker || marker == kCursorOnDisabledBreakpointMarker) {
      const float left = origin.x + 2.0f;
      const float top = origin.y + height * 0.2f;
      const float bottom = origin.y + height * 0.8f;
      drawList->AddTriangleFilled(
        ImVec2(left, top),
        ImVec2(left, bottom),
        ImVec2(left + height * 0.6f, origin.y + height * 0.5f),
        IM_COL32(255, 220, 40, 255)
      );
    }
  }
} // namespace

/**
 * Address: 0x004C1EE0 (FUN_004C1EE0)
 */
moho::ScrFileCtrl::ScrFileCtrl()
  : mCursorLine(0)
  , mSourcePath()
  , mLines()
{}

/**
 * Address: 0x004C26A0 (FUN_004C26A0)
 * Deleting: 0x004C2680 (FUN_004C2680)
 */
moho::ScrFileCtrl::~ScrFileCtrl() = default;

/**
 * Address: 0x004C2730 (FUN_004C2730)
 *
 * The loop stops on badbit or eofbit only: a line that fills the buffer sets
 * failbit alone, after which every getline fails without reaching either and
 * the loop keeps appending empty lines. A last line with no newline is
 * dropped. Both as shipped.
 */
bool moho::ScrFileCtrl::Load(
  const fa::string& fileName
)
{
  Clear();
  if (fileName.empty()) {
    return false;
  }

  fa::string diskPath;
  (void)DISK_GetVFS()->FindFile(&diskPath, fileName.c_str(), nullptr);
  if (diskPath.empty()) {
    return false;
  }

  std::fstream file(diskPath.c_str(), std::ios::in);
  if (!file.is_open()) {
    return false;
  }

  char buffer[1024];
  int lineNumber = 1;
  file.getline(buffer, sizeof(buffer));
  while (!file.bad() && !file.eof()) {
    mLines.push_back(ScrFileLine(lineNumber++, buffer));
    file.getline(buffer, sizeof(buffer));
  }

  mSourcePath = fileName;
  LoadBreakpoints();
  return true;
}

/**
 * Address: 0x004C2DA0 (FUN_004C2DA0)
 */
void moho::ScrFileCtrl::Clear()
{
  mLines.clear();
  mCursorLine = 0;
  mSelectedLine = -1;
  mScrollToLine = -1;
}

void moho::ScrFileCtrl::SelectLine(
  const int index
)
{
  mSelectedLine = index;
  mScrollToLine = index;
}

/**
 * Address: 0x004C2A40 (FUN_004C2A40)
 */
void moho::ScrFileCtrl::FindFirst(
  const fa::string& text
)
{
  const int lineCount = static_cast<int>(mLines.size());
  bool found = false;
  for (int index = 0; !found && index < lineCount; ++index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != fa::string::npos;
    if (found) {
      SelectLine(index);
    }
  }
}

/**
 * Address: 0x004C2AE0 (FUN_004C2AE0)
 */
void moho::ScrFileCtrl::FindNext(
  const fa::string& text
)
{
  const int selected = mSelectedLine;
  if (selected < 0) {
    return;
  }

  const int lineCount = static_cast<int>(mLines.size());
  bool found = false;
  for (int index = selected + 1; !found && index < lineCount; ++index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != fa::string::npos;
    if (found) {
      SelectLine(index);
    }
  }
}

/**
 * Address: 0x004C2B90 (FUN_004C2B90)
 */
void moho::ScrFileCtrl::FindPrevious(
  const fa::string& text
)
{
  const int selected = mSelectedLine;
  if (selected < 0) {
    return;
  }

  bool found = false;
  for (int index = selected - 1; !found && index > -1; --index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != fa::string::npos;
    if (found) {
      SelectLine(index);
    }
  }
}

/**
 * Address: 0x004C2C20 (FUN_004C2C20)
 */
void moho::ScrFileCtrl::GotoLine(
  const int line
)
{
  const int index = line - 1;
  if (index > -1 && index < static_cast<int>(mLines.size())) {
    SelectLine(index);
  }
}

/**
 * Address: 0x004C2C60 (FUN_004C2C60)
 */
void moho::ScrFileCtrl::EnableBreakpoints(
  const bool enable
)
{
  const int lineCount = static_cast<int>(mLines.size());
  for (int index = 0; index < lineCount; ++index) {
    ScrFileLine& fileLine = mLines[index];
    switch (fileLine.mMarkerState) {
    case kCursorOnBreakpointMarker:
    case kCursorOnDisabledBreakpointMarker:
      fileLine.mMarkerState = enable ? kCursorOnBreakpointMarker : kCursorOnDisabledBreakpointMarker;
      break;
    case kBreakpointMarker:
    case kDisabledBreakpointMarker:
      fileLine.mMarkerState = enable ? kBreakpointMarker : kDisabledBreakpointMarker;
      break;
    }
  }
}

/**
 * Address: 0x004C2CF0 (FUN_004C2CF0)
 */
void moho::ScrFileCtrl::RemoveBreakpoint(
  const int line
)
{
  const int index = line - 1;
  if (index < 0 || index >= static_cast<int>(mLines.size())) {
    return;
  }

  ScrFileLine& fileLine = mLines[index];
  switch (fileLine.mMarkerState) {
  case kCursorOnBreakpointMarker:
  case kCursorOnDisabledBreakpointMarker:
    fileLine.mMarkerState = kCursorMarker;
    break;
  case kBreakpointMarker:
  case kDisabledBreakpointMarker:
    fileLine.mMarkerState = kNoMarker;
    break;
  }
}

/**
 * Address: 0x004C2D60 (FUN_004C2D60)
 */
void moho::ScrFileCtrl::RemoveAllBreakpoints()
{
  const int lineCount = static_cast<int>(mLines.size());
  for (int index = 0; index < lineCount; ++index) {
    RemoveBreakpoint(index + 1);
  }
}

/**
 * Address: 0x004C2DE0 (FUN_004C2DE0)
 */
bool moho::ScrFileCtrl::SetCursorLine(
  const int line
)
{
  const int index = line - 1;
  if (index > -1 && index < static_cast<int>(mLines.size())) {
    ScrFileLine& fileLine = mLines[index];
    mCursorLine = line;
    switch (fileLine.mMarkerState) {
    case kNoMarker:
      fileLine.mMarkerState = kCursorMarker;
      break;
    case kBreakpointMarker:
      fileLine.mMarkerState = kCursorOnBreakpointMarker;
      break;
    case kDisabledBreakpointMarker:
      fileLine.mMarkerState = kCursorOnDisabledBreakpointMarker;
      break;
    }
    mScrollToLine = index;
    return true;
  }

  gpg::Warnf("invalid cursor location: %s(%i)", mSourcePath.c_str(), line);
  return false;
}

/**
 * Address: 0x004C2EA0 (FUN_004C2EA0)
 */
void moho::ScrFileCtrl::ClearCursor()
{
  if (mCursorLine < 1) {
    return;
  }

  const int index = mCursorLine - 1;
  ScrFileLine& fileLine = mLines[index];
  mCursorLine = 0;
  switch (fileLine.mMarkerState) {
  case kCursorMarker:
    fileLine.mMarkerState = kNoMarker;
    break;
  case kCursorOnBreakpointMarker:
    fileLine.mMarkerState = kBreakpointMarker;
    break;
  case kCursorOnDisabledBreakpointMarker:
    fileLine.mMarkerState = kDisabledBreakpointMarker;
    break;
  }
}

/**
 * Address: 0x004C3270 (FUN_004C3270, OnLineActivated)
 */
void moho::ScrFileCtrl::ToggleBreakpoint(
  const int item
)
{
  if (item < 0 || item >= static_cast<int>(mLines.size())) {
    return;
  }
  ScrFileLine& fileLine = mLines[item];
  switch (fileLine.mMarkerState) {
  case kNoMarker:
    fileLine.mMarkerState = kBreakpointMarker;
    SCR_AddBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
    break;
  case kCursorMarker:
    fileLine.mMarkerState = kCursorOnBreakpointMarker;
    SCR_AddBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
    break;
  case kCursorOnBreakpointMarker:
  case kCursorOnDisabledBreakpointMarker:
    fileLine.mMarkerState = kCursorMarker;
    SCR_RemoveBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
    break;
  case kBreakpointMarker:
  case kDisabledBreakpointMarker:
    fileLine.mMarkerState = kNoMarker;
    SCR_RemoveBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
    break;
  }
}

/**
 * Address: 0x004C3400 (FUN_004C3400)
 *
 * A breakpoint on line 0 or below passed the check and wrote in front of mLines in the binary;
 * it is reported as invalid here, as one past the end is.
 */
void moho::ScrFileCtrl::LoadBreakpoints()
{
  fa::vector<ScrBreakpoint> breakpoints;
  SCR_EnumerateBreakpoints(mSourcePath, breakpoints);
  for (const ScrBreakpoint& breakpoint : breakpoints) {
    const int index = breakpoint.line - 1;
    if (index >= 0 && index < static_cast<int>(mLines.size())) {
      mLines[index].mMarkerState = breakpoint.enabled ? kBreakpointMarker : kDisabledBreakpointMarker;
    } else {
      gpg::Warnf("Invalid breakpoint: %s(%d)", breakpoint.name.c_str(), breakpoint.line);
    }
  }
}

/**
 * Address: 0x004C2F10 (OnGetItemImage), 0x004C2F30 (OnGetItemText), 0x004C30B0 (OnGetItemAttr)
 *
 * What it does:
 * Draws the marker, the line number and the source of each row in view. The binary's rows were
 * striped (247, 247, 255 odd, 254, 254, 255 even) in 10-point Courier New; these follow the
 * window's dark style.
 */
void moho::ScrFileCtrl::Draw()
{
  constexpr ImGuiTableFlags kFlags =
    ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_SizingFixedFit;
  if (!ImGui::BeginTable("##lines", 3, kFlags)) {
    return;
  }
  const float rowHeight = ImGui::GetTextLineHeightWithSpacing();
  ImGui::TableSetupColumn("image", ImGuiTableColumnFlags_WidthFixed, rowHeight * 1.4f);
  ImGui::TableSetupColumn("line", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("00000").x);
  ImGui::TableSetupColumn("source", ImGuiTableColumnFlags_WidthStretch);

  if (mScrollToLine >= 0) {
    ImGui::SetScrollY(static_cast<float>(mScrollToLine) * rowHeight - ImGui::GetWindowHeight() * 0.4f);
    mScrollToLine = -1;
  }

  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>(mLines.size()), rowHeight);
  while (clipper.Step()) {
    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const ScrFileLine& line = mLines[static_cast<std::size_t>(row)];
      ImGui::TableNextRow(ImGuiTableRowFlags_None, rowHeight);
      ImGui::TableSetColumnIndex(0);
      DrawMarker(line.mMarkerState, ImGui::GetCursorScreenPos(), ImGui::GetTextLineHeight());
      ImGui::PushID(row);
      const bool selected = row == mSelectedLine;
      if (
        ImGui::Selectable(
          "##row", selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick
        )
      ) {
        mSelectedLine = row;
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          ToggleBreakpoint(row);
        }
      }
      ImGui::PopID();
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(line.mLineNumberText.c_str());
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(line.mSourceText.c_str());
    }
  }
  ImGui::EndTable();
}
