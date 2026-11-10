#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "editor/doc/EdVault.h"

namespace faf::editor
{
  class EdDocument;
  class EdPlay;

  /**
   * The map browser: every map the game has, with its picture, size, players and where it is on disk (the game's
   * folder, FAF's ProgramData folder, the vault), and maps from the FAF vault downloaded into the vault's maps folder,
   * mounted while the editor runs and opened.
   */
  class EdMapBrowser
  {
  public:
    EdMapBrowser(EdPlay& play, EdDocument& document);
    ~EdMapBrowser();
    EdMapBrowser(const EdMapBrowser&) = delete;
    EdMapBrowser& operator=(const EdMapBrowser&) = delete;

    /** Its ImGui window's name: a floating window (it doesn't dock), cut out of the game view's region like a popup. */
    static constexpr const char* kWindowName = "Maps###mapbrowser";
    void Show() noexcept { mOpen = true; }
    /** The list's filter text (`/browser <filter>` in test runs). */
    void SetFilter(const std::string& text);
    [[nodiscard]] bool& Open() noexcept { return mOpen; }
    /** Each frame, shown or not: a finished download mounted and opened. */
    void Update();
    void Draw();
    /** Downloads a vault map (its folder name or link) and opens it; `/vaultmap <name>` in test runs. */
    void Download(const std::string& name);

  private:
    struct Details
    {
      bool read = false;
      std::string title;
      std::string size;
      int players = 0;
      std::string version;
      std::string where;
      std::string disk;
      std::string scmap;
      bool pictureAsked = false;
      std::uint64_t picture = 0;
    };
    Details& DetailsOf(const std::string& scenario);
    void ReadDetails(const std::string& scenario, Details& details);
    void MakePicture(Details& details);
    void DrawLocal();
    void DrawVault();
    /** The scenario of a map folder the game lists (`/maps/<folder>/...`), or empty. */
    [[nodiscard]] std::string ListedScenario(const std::string& folder) const;
    void OpenMap(const std::string& scenario);

    EdPlay& mPlay;
    EdDocument& mDocument;
    bool mOpen = false;
    int mTab = 0;
    char mFilter[96]{};
    int mWhere = 0;
    char mVaultName[256]{};
    std::map<std::string, Details> mDetails;
    int mReadsThisFrame = 0;
    int mPicturesThisFrame = 0;
    EdVaultDownload mDownload;
    std::string mStatus;
  };
} // namespace faf::editor
