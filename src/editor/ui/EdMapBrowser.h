#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "editor/doc/EdFafApi.h"
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
    void Show() noexcept
    {
      mOpen = true;
    }
    /** Shown on its FAF vault tab. */
    void ShowVault() noexcept
    {
      mOpen = true;
      mSelectVault = true;
    }
    /** The list's filter text (`/browser <filter>` in test runs). */
    void SetFilter(const std::string& text);
    [[nodiscard]] bool& Open() noexcept
    {
      return mOpen;
    }
    /** Each frame, shown or not: a finished download mounted and opened. */
    void Update();
    void Draw();
    /** Downloads a vault map (its folder name or link) and opens it; `/vaultmap <name>` in test runs. */
    void Download(const std::string& name);
    /**
     * A map from any folder on disk, by its `_scenario.lua`: the folder mounted where the scenario says its files are
     * (`/maps/<folder>/`), then opened; `/openfolder <file>` in test runs. Refused when another folder has that name.
     */
    void OpenFromDisk(const std::filesystem::path& scenarioFile);
    /** The FAF login and vault search (its token file set by the app). */
    [[nodiscard]] EdFafSession& Faf() noexcept
    {
      return mFaf;
    }
    /** Test runs (`/vaultsearch <text>`): a search once logged in; its results go to the log. */
    void AskSearch(const std::string& text);
    /** Test runs (`/vaultquery <sort>,<players>,<size>,<ranked>`): the filters' choices by their index. */
    void SetFilters(int sort, int players, int size, bool ranked);
    /** The panel's "Open from a folder..." asked for a file (the app shows the dialog). */
    [[nodiscard]] bool TakeOpenFileAsk() noexcept
    {
      return std::exchange(mOpenFileAsk, false);
    }

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
    char mFilter[96]{};
    int mWhere = 0;
    char mVaultName[256]{};
    std::map<std::string, Details> mDetails;
    int mReadsThisFrame = 0;
    int mPicturesThisFrame = 0;
    EdVaultDownload mDownload;
    std::string mStatus;
    bool mOpenFileAsk = false;
    bool mSelectVault = false;
    void DrawVaultSearch();
    void DrawVaultByName();
    /** A link in the default browser; false (logged, and the panel shows the link instead) when it can't. */
    bool OpenLink(const std::string& url);
    bool mLinkFailed = false;
    /** A vault map's thumbnail (its PNG decoded), 0 until fetched. */
    std::uint64_t VaultPicture(const std::string& url);
    EdFafSession mFaf;
    bool mFafResumed = false;
    char mSearchText[128]{};
    std::string mSearchedText;
    int mSearchPage = 1;
    /**
     * The FAF client's map filters and order (its map vault's search bar): author, uploaded from/to, widths, heights,
     * max players from/to, review score from/to, only ranked, sort by and order; the name is the search box. With the
     * searched text, the query a search sends.
     */
    VaultQuery mFilters;
    char mAuthorText[64]{};
    char mFromText[16]{};
    char mToText[16]{};
    bool mShowQuery = false;
    /** The saved queries ("Favorites"): name and query text, kept in the editor's folder (vault_queries.txt). */
    std::vector<std::pair<std::string, std::string>> mSavedQueries;
    bool mSavedQueriesRead = false;
    char mSaveQueryName[64]{};
    void ReadSavedQueries();
    void WriteSavedQueries() const;
    /** The filters' row (DrawVaultSearch); true when a filter changed. */
    bool DrawVaultFilters();
    [[nodiscard]] VaultQuery Query() const;
    int mSearchPages = 0;
    std::vector<VaultMap> mFound;
    bool mSearchedOnce = false;
    std::string mAskedSearch;
    std::map<std::string, std::uint64_t> mVaultPictures;
    /** The links whose picture can't be had (shown as such, not as loading). */
    std::set<std::string> mVaultNoPicture;
    /** A progress bar of the download under way (`width` -1 for the available width). */
    void DrawDownloadProgress(float width);
  };
} // namespace faf::editor
