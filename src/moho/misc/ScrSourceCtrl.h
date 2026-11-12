#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class ScrFileCtrl;

  /**
   * VFTABLE: 0x00E07B18 (??_7ScrSourceCtrl@Moho@@6B@)
   *
   * The debugger's open sources, one page each: a wxNotebook (id 202) in the binary, Dear ImGui
   * tabs since issue #413 (Draw).
   */
  class ScrSourceCtrl
  {
  public:
    /**
     * Address: 0x004C3500 (FUN_004C3500)
     */
    ScrSourceCtrl();

    /**
     * Address: 0x004C3620 (FUN_004C3620)
     */
    ~ScrSourceCtrl();

    ScrSourceCtrl(const ScrSourceCtrl&) = delete;
    ScrSourceCtrl& operator=(const ScrSourceCtrl&) = delete;

    /**
     * Address: 0x004C3670 (FUN_004C3670)
     *
     * What it does:
     * Selects the file's page, or loads it into a new one; false when it can't be read.
     */
    bool Open(const fa::string& fileName);

    /**
     * Address: 0x004C38A0 (FUN_004C38A0)
     */
    void Close(const fa::string& fileName);

    /**
     * Address: 0x004C3940 (FUN_004C3940)
     */
    void CloseCurrent();

    /**
     * Address: 0x004C39A0 (FUN_004C39A0)
     */
    void ReloadAll();

    /**
     * Address: 0x004C39E0 (FUN_004C39E0)
     */
    [[nodiscard]] fa::string GetCurrentFileName() const;

    /**
     * Address: 0x004C3A40 (FUN_004C3A40), 0x004C3A70 (FUN_004C3A70), 0x004C3AA0 (FUN_004C3AA0)
     */
    void FindFirst(const fa::string& text);
    void FindNext(const fa::string& text);
    void FindPrevious(const fa::string& text);

    /**
     * Address: 0x004C3AD0 (FUN_004C3AD0)
     */
    void GotoLine(int line);

    /**
     * Address: 0x004C3B00 (FUN_004C3B00)
     */
    void EnableBreakpoints(bool enable);

    /**
     * Address: 0x004C3B30 (FUN_004C3B30)
     */
    void RemoveBreakpoint(const fa::string& fileName, int line);

    /**
     * Address: 0x004C3B90 (FUN_004C3B90)
     */
    void RemoveAllBreakpoints();

    /**
     * Address: 0x004C3C00 (FUN_004C3C00)
     */
    bool SetCursorLine(const fa::string& fileName, int line);

    /**
     * Address: 0x004C3D30 (FUN_004C3D30)
     */
    void ClearCursor();

    // The tabs and the selected page.
    void Draw();

    // wxNotebook::GetSelection: the selected page, -1 when none.
    [[nodiscard]] int GetSelection() const
    {
      return mSelection;
    }

  public:
    fa::vector<ScrFileCtrl*> mPages;

  private:
    int mSelection = -1;
    // A selection made in code, which the tab bar is told on its next Draw.
    int mSelectionRequest = -1;

    void SetSelection(int page);
    void DeletePage(int page);
  };
} // namespace moho
