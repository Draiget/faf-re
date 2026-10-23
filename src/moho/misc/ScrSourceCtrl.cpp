#include "moho/misc/ScrSourceCtrl.h"

#include <algorithm>

#include "gpg/core/containers/String.h"
#include "moho/misc/ScrFileCtrl.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  constexpr int kSourceNotebookId = 202;

  /**
   * The std::find_if predicate for a page by its file. Holds its own copy of
   * the name; find_if and _Find_if take it by value.
   */
  struct ScrFileCtrlHasPath
  {
    explicit ScrFileCtrlHasPath(const msvc8::string& sourcePath)
      : mSourcePath(sourcePath)
    {
    }

    bool operator()(const moho::ScrFileCtrl* const page) const
    {
      return mSourcePath == page->mSourcePath;
    }

    msvc8::string mSourcePath;
  };
} // namespace

/**
 * Address: 0x004C3500 (FUN_004C3500)
 */
moho::ScrSourceCtrl::ScrSourceCtrl(wxWindow* const parent)
  : wxNotebook(parent, kSourceNotebookId, wxDefaultPosition, wxDefaultSize, 0, wxT("ScrSourceCtrl"))
  , mPages()
{
}

/**
 * Address: 0x004C3620 (FUN_004C3620)
 * Deleting: 0x004C35B0 (FUN_004C35B0)
 */
moho::ScrSourceCtrl::~ScrSourceCtrl() = default;

/**
 * Address: 0x004C3670 (FUN_004C3670)
 */
bool moho::ScrSourceCtrl::Open(const msvc8::string& fileName)
{
  const msvc8::vector<ScrFileCtrl*>::iterator existing =
    std::find_if(mPages.begin(), mPages.end(), ScrFileCtrlHasPath(fileName));
  if (existing == mPages.end()) {
    ScrFileCtrl* const page = new ScrFileCtrl(this);
    if (!page->Load(fileName)) {
      page->Destroy();
      return false;
    }

    mPages.push_back(page);
    AddPage(page, gpg::STR_Utf8ToWide(FILE_Base(fileName.c_str(), false).c_str()).c_str(), true);
    return true;
  }

  SetSelection(static_cast<int>(existing - mPages.begin()));
  return true;
}

/**
 * Address: 0x004C38A0 (FUN_004C38A0)
 */
void moho::ScrSourceCtrl::Close(const msvc8::string& fileName)
{
  const msvc8::vector<ScrFileCtrl*>::iterator page =
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
  for (msvc8::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->Load((*page)->mSourcePath);
  }
}

/**
 * Address: 0x004C39E0 (FUN_004C39E0)
 */
msvc8::string moho::ScrSourceCtrl::GetCurrentFileName() const
{
  const int selection = GetSelection();
  if (selection > -1) {
    return mPages[selection]->mSourcePath;
  }
  return msvc8::string();
}

/**
 * Address: 0x004C3A40 (FUN_004C3A40)
 */
void moho::ScrSourceCtrl::FindFirst(const msvc8::string& text)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindFirst(text);
  }
}

/**
 * Address: 0x004C3A70 (FUN_004C3A70)
 */
void moho::ScrSourceCtrl::FindNext(const msvc8::string& text)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindNext(text);
  }
}

/**
 * Address: 0x004C3AA0 (FUN_004C3AA0)
 */
void moho::ScrSourceCtrl::FindPrevious(const msvc8::string& text)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->FindPrevious(text);
  }
}

/**
 * Address: 0x004C3AD0 (FUN_004C3AD0)
 */
void moho::ScrSourceCtrl::GotoLine(const int line)
{
  const int selection = GetSelection();
  if (selection > -1) {
    mPages[selection]->GotoLine(line);
  }
}

/**
 * Address: 0x004C3B00 (FUN_004C3B00)
 */
void moho::ScrSourceCtrl::EnableBreakpoints(const bool enable)
{
  for (msvc8::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->EnableBreakpoints(enable);
  }
}

/**
 * Address: 0x004C3B30 (FUN_004C3B30)
 */
void moho::ScrSourceCtrl::RemoveBreakpoint(const msvc8::string& fileName, const int line)
{
  const msvc8::vector<ScrFileCtrl*>::iterator page =
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
  for (msvc8::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->RemoveAllBreakpoints();
  }
}

/**
 * Address: 0x004C3C00 (FUN_004C3C00)
 */
bool moho::ScrSourceCtrl::SetCursorLine(const msvc8::string& fileName, const int line)
{
  ClearCursor();

  const msvc8::vector<ScrFileCtrl*>::iterator page =
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
  for (msvc8::vector<ScrFileCtrl*>::iterator page = mPages.begin(); page != mPages.end(); ++page) {
    (*page)->ClearCursor();
  }
}
