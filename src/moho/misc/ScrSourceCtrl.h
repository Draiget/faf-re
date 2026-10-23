#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "platform/WxWidgets.h"
#include <wx/control.h>
#include <wx/notebook.h>

namespace moho
{
  class ScrFileCtrl;

  /**
   * VFTABLE: 0x00E08F54 (??_7ScrSourceCtrl@Moho@@6B@)
   *
   * The debugger's source notebook: one ScrFileCtrl page per open file, kept
   * in the notebook's page order in mPages. Files are found by their mounted
   * path with std::find_if (0x004C6240, over _Find_if 0x004C6750).
   *
   * Overrides nothing: slot 0 is wxNotebook::GetClassInfo (0x004C1B90), 134
   * wxNotebook::GetSelection (0x004C1B80) and 146 wxNotebookBase::RemovePage
   * (0x004C1B60), all inline copies, as are wxControl's 131-133.
   */
  class ScrSourceCtrl : public wxNotebook
  {
  public:
    /**
     * Address: 0x004C3500 (FUN_004C3500)
     *
     * What it does:
     * An empty notebook, id 202, named "ScrSourceCtrl".
     */
    explicit ScrSourceCtrl(wxWindow* parent);

    /**
     * Address: 0x004C3620 (FUN_004C3620)
     * Deleting: 0x004C35B0 (FUN_004C35B0)
     *
     * What it does:
     * Frees mPages, then the notebook, which destroys the pages. Nothing
     * calls the complete-object copy. 0x004C3610 is the constructor's unwind
     * into ~wxNotebook.
     */
    ~ScrSourceCtrl() override;

    /**
     * Address: 0x004C3670 (FUN_004C3670)
     *
     * What it does:
     * Selects the page already showing `fileName`, or loads a new page for it
     * and adds it selected, labelled with the file's base name. A file that
     * will not load gets no page and returns false.
     */
    bool Open(const msvc8::string& fileName);

    /**
     * Address: 0x004C38A0 (FUN_004C38A0)
     *
     * What it does:
     * Deletes the page showing `fileName`, if any. Nothing in the image
     * calls it.
     */
    void Close(const msvc8::string& fileName);

    /**
     * Address: 0x004C3940 (FUN_004C3940)
     *
     * What it does:
     * Deletes the selected page.
     */
    void CloseCurrent();

    /**
     * Address: 0x004C39A0 (FUN_004C39A0)
     *
     * What it does:
     * Loads every page again from its file.
     */
    void ReloadAll();

    /**
     * Address: 0x004C39E0 (FUN_004C39E0)
     *
     * What it does:
     * The selected page's file, or an empty string.
     */
    [[nodiscard]] msvc8::string GetCurrentFileName() const;

    /**
     * Address: 0x004C3A40 (FUN_004C3A40)
     *
     * What it does:
     * ScrFileCtrl::FindFirst on the selected page.
     */
    void FindFirst(const msvc8::string& text);

    /**
     * Address: 0x004C3A70 (FUN_004C3A70)
     *
     * What it does:
     * ScrFileCtrl::FindNext on the selected page.
     */
    void FindNext(const msvc8::string& text);

    /**
     * Address: 0x004C3AA0 (FUN_004C3AA0)
     *
     * What it does:
     * ScrFileCtrl::FindPrevious on the selected page.
     */
    void FindPrevious(const msvc8::string& text);

    /**
     * Address: 0x004C3AD0 (FUN_004C3AD0)
     *
     * What it does:
     * ScrFileCtrl::GotoLine on the selected page.
     */
    void GotoLine(int line);

    /**
     * Address: 0x004C3B00 (FUN_004C3B00)
     *
     * What it does:
     * ScrFileCtrl::EnableBreakpoints on every page.
     */
    void EnableBreakpoints(bool enable);

    /**
     * Address: 0x004C3B30 (FUN_004C3B30)
     *
     * What it does:
     * Takes the breakpoint marker off `line` of the page showing `fileName`.
     * Nothing in the image calls it.
     */
    void RemoveBreakpoint(const msvc8::string& fileName, int line);

    /**
     * Address: 0x004C3B90 (FUN_004C3B90)
     *
     * What it does:
     * ScrFileCtrl::RemoveAllBreakpoints on every page (inlined).
     */
    void RemoveAllBreakpoints();

    /**
     * Address: 0x004C3C00 (FUN_004C3C00)
     *
     * What it does:
     * Clears the cursor from every page, then selects the page showing the
     * lower-cased `fileName` and puts the cursor on `line`. False when no
     * page shows it or the line is out of range.
     */
    bool SetCursorLine(const msvc8::string& fileName, int line);

    /**
     * Address: 0x004C3D30 (FUN_004C3D30)
     *
     * What it does:
     * ScrFileCtrl::ClearCursor on every page. Inlined where it is used;
     * nothing in the image calls this copy.
     */
    void ClearCursor();

  public:
    msvc8::vector<ScrFileCtrl*> mPages; // +0x148
  };

  static_assert(offsetof(ScrSourceCtrl, mPages) == 0x148, "ScrSourceCtrl::mPages offset must be 0x148");
  static_assert(sizeof(ScrSourceCtrl) == 0x158, "ScrSourceCtrl size must be 0x158");
} // namespace moho
