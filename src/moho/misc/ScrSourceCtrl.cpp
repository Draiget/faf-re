#include "moho/misc/ScrSourceCtrl.h"

#include <algorithm>

#include "gpg/core/containers/String.h"
#include "moho/misc/ScrFileCtrl.h"
#include "moho/misc/StartupHelpers.h"

#include "imgui.h"

namespace
{

  /**
   * The std::find_if predicate for a page by its file. Holds its own copy of
   * the name; find_if and _Find_if take it by value.
   */
  struct ScrFileCtrlHasPath
  {
    explicit ScrFileCtrlHasPath(
      const fa::string& sourcePath
    )
      : mSourcePath(sourcePath)
    {}

    bool operator()(
      const moho::ScrFileCtrl* const page
    ) const
    {
      return mSourcePath == page->mSourcePath;
    }

    fa::string mSourcePath;
  };
} // namespace

/**
 * Address: 0x004C3500 (FUN_004C3500)
 */
moho::ScrSourceCtrl::ScrSourceCtrl()
  : mPages()
{}

/**
 * Address: 0x004C3620 (FUN_004C3620)
 * Deleting: 0x004C35B0 (FUN_004C35B0)
 *
 * The notebook destroyed its pages with itself.
 */
moho::ScrSourceCtrl::~ScrSourceCtrl()
{
  for (ScrFileCtrl* const page : mPages) {
    delete page;
  }
  mPages.clear();
}

void moho::ScrSourceCtrl::SetSelection(
  const int page
)
{
  mSelection = page;
  mSelectionRequest = page;
}

// The notebook's DeletePage: the page goes, and the selection moves to a neighbour.
void moho::ScrSourceCtrl::DeletePage(
  const int page
)
{
  delete mPages[page];
  const int remaining = static_cast<int>(mPages.size()) - 1;
  if (mSelection >= remaining) {
    mSelection = remaining - 1;
  }
  mSelectionRequest = mSelection;
}

/**
 * Address: 0x004C3670 (FUN_004C3670)
 */
bool moho::ScrSourceCtrl::Open(
  const fa::string& fileName
)
{
  const fa::vector<ScrFileCtrl*>::iterator existing =
    std::find_if(mPages.begin(), mPages.end(), ScrFileCtrlHasPath(fileName));
  if (existing == mPages.end()) {
    ScrFileCtrl* const page = new ScrFileCtrl();
    if (!page->Load(fileName)) {
      delete page;
      return false;
    }
    mPages.push_back(page);
    SetSelection(static_cast<int>(mPages.size()) - 1);
    return true;
  }

  SetSelection(static_cast<int>(existing - mPages.begin()));
  return true;
}

/**
 * Address: 0x004C38A0 (FUN_004C38A0)
 */
void moho::ScrSourceCtrl::Close(
  const fa::string& fileName
)
{
  const fa::vector<ScrFileCtrl*>::iterator page =
    std::find_if(mPages.begin(), mPages.end(), ScrFileCtrlHasPath(fileName));
  if (page != mPages.end()) {
    DeletePage(static_cast<int>(page - mPages.begin()));
    mPages.erase(page);
  }
}

/**
 * Address: 0x004C3940 (FUN_004C3940)
 */
void moho::ScrSourceCtrl::CloseCurrent()
{
  const int selection = GetSelection();
  if (selection > -1) {
    DeletePage(selection);
    mPages.erase(mPages.begin() + selection);
  }
}

/**
 * Address: 0x004C39A0 (FUN_004C39A0)
 */
void moho::ScrSourceCtrl::ReloadAll()
{
  for (fa::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->Load((*page)->mSourcePath);
  }
}

/**
 * Address: 0x004C39E0 (FUN_004C39E0)
 */
fa::string moho::ScrSourceCtrl::GetCurrentFileName() const
{
  const int selection = GetSelection();
  if (selection > -1) {
    return mPages[selection]->mSourcePath;
  }
  return fa::string();
}

/**
 * Address: 0x004C3A40 (FUN_004C3A40)
 */
void moho::ScrSourceCtrl::FindFirst(
  const fa::string& text
)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindFirst(text);
  }
}

/**
 * Address: 0x004C3A70 (FUN_004C3A70)
 */
void moho::ScrSourceCtrl::FindNext(
  const fa::string& text
)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindNext(text);
  }
}

/**
 * Address: 0x004C3AA0 (FUN_004C3AA0)
 */
void moho::ScrSourceCtrl::FindPrevious(
  const fa::string& text
)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindPrevious(text);
  }
}

/**
 * Address: 0x004C3AD0 (FUN_004C3AD0)
 */
void moho::ScrSourceCtrl::GotoLine(
  const int line
)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->GotoLine(line);
  }
}

/**
 * Address: 0x004C3B00 (FUN_004C3B00)
 */
void moho::ScrSourceCtrl::EnableBreakpoints(
  const bool enable
)
{
  for (fa::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->EnableBreakpoints(enable);
  }
}

/**
 * Address: 0x004C3B30 (FUN_004C3B30)
 */
void moho::ScrSourceCtrl::RemoveBreakpoint(
  const fa::string& fileName,
  const int line
)
{
  const fa::vector<ScrFileCtrl*>::iterator page =
    std::find_if(mPages.begin(), mPages.end(), ScrFileCtrlHasPath(fileName));
  if (page != mPages.end()) {
    (*page)->RemoveBreakpoint(line);
  }
}

/**
 * Address: 0x004C3B90 (FUN_004C3B90)
 */
void moho::ScrSourceCtrl::RemoveAllBreakpoints()
{
  for (fa::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->RemoveAllBreakpoints();
  }
}

/**
 * Address: 0x004C3C00 (FUN_004C3C00)
 */
bool moho::ScrSourceCtrl::SetCursorLine(
  const fa::string& fileName,
  const int line
)
{
  ClearCursor();

  const fa::vector<ScrFileCtrl*>::iterator page =
    std::find_if(mPages.begin(), mPages.end(), ScrFileCtrlHasPath(gpg::STR_ToLower(fileName.c_str())));
  if (page == mPages.end()) {
    return false;
  }

  SetSelection(static_cast<int>(page - mPages.begin()));
  return (*page)->SetCursorLine(line);
}

/**
 * Address: 0x004C3D30 (FUN_004C3D30)
 */
void moho::ScrSourceCtrl::ClearCursor()
{
  for (fa::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->ClearCursor();
  }
}

/**
 * The notebook's tabs, each named by the file's base name (FILE_Base, as AddPage was given it),
 * and the selected page.
 */
void moho::ScrSourceCtrl::Draw()
{
  if (!ImGui::BeginTabBar("##sources", ImGuiTabBarFlags_FittingPolicyScroll)) {
    return;
  }
  for (int index = 0; index < static_cast<int>(mPages.size()); ++index) {
    ScrFileCtrl* const page = mPages[static_cast<std::size_t>(index)];
    const fa::string label = FILE_Base(page->mSourcePath.c_str(), false);
    ImGui::PushID(page);
    const ImGuiTabItemFlags flags = mSelectionRequest == index ? ImGuiTabItemFlags_SetSelected : 0;
    if (ImGui::BeginTabItem(label.c_str(), nullptr, flags)) {
      if (mSelectionRequest < 0) {
        mSelection = index;
      }
      page->Draw();
      ImGui::EndTabItem();
    }
    ImGui::PopID();
  }
  mSelectionRequest = -1;
  ImGui::EndTabBar();
}
