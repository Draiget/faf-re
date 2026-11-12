#pragma once

#include <atomic>
#include <functional>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace faf::editor
{
  /**
   * The FAF login and API as the FAF client uses them (downlords-faf-client: application-prod.yml, TokenRetriever):
   * Hydra's OAuth device flow, and the map API's JSON:API answers. The client id is the FAF client's own (the user's
   * choice, 2026-11-10: the editor presents itself to FAF as that client).
   */
  constexpr const char kFafClientId[] = "2e8808cf-5889-469b-b2c3-01f0cc58c4af";
  constexpr const char kFafOAuthUrl[] = "https://hydra.faforever.com";
  constexpr const char kFafApiUrl[] = "https://api.faforever.com";
  /** What the editor asks for: who you are, and staying logged in. Nothing that changes your account. */
  constexpr const char kFafScopes[] = "openid offline public_profile";

  /** Where the session's lines go (the editor's log); none by default. */
  void SetFafLog(void (*log)(const char*)) noexcept;

  /** A JSON value: what the API answers are made of. */
  struct JsonNode
  {
    enum class Kind
    {
      Null,
      Bool,
      Number,
      String,
      Array,
      Object,
    };
    Kind kind = Kind::Null;
    bool boolean = false;
    double number = 0.0;
    std::string text;
    std::vector<JsonNode> items;
    std::vector<std::pair<std::string, JsonNode>> members;

    [[nodiscard]] const JsonNode* Get(const std::string& key) const;
    [[nodiscard]] std::string String(const std::string& key) const;
    [[nodiscard]] double Number(const std::string& key, double fallback = 0.0) const;
    [[nodiscard]] bool Bool(const std::string& key) const;
  };

  /** `text` read as JSON (strings with their \u escapes as UTF-8); false with `error`. */
  bool ParseJson(const std::string& text, JsonNode& out, std::string& error);

  /** One map in the vault, as a search finds it (its latest version). */
  struct VaultMap
  {
    std::string name;
    std::string folder;
    std::string author;
    std::string description;
    std::string thumbnail;
    std::string version;
    int players = 0;
    /** Its size in height-field pixels (512 is 10 km). */
    int width = 0;
    int height = 0;
    int gamesPlayed = 0;
    bool ranked = false;
  };

  /** The map sizes the FAF client filters by (MapVaultController): height-field pixels, 1 km to 80 km. */
  inline constexpr int kVaultSizes[7] = {64, 128, 256, 512, 1024, 2048, 4096};
  inline constexpr const char* kVaultSizeNames[7] = {"1 km", "2 km", "5 km", "10 km", "20 km", "40 km", "80 km"};

  /** What a search can be ordered by: the FAF client's sortable map properties (SearchablePropertyMappings). */
  struct VaultSortKey
  {
    const char* property;
    const char* label;
  };
  inline constexpr VaultSortKey kVaultSortKeys[] = {
    {"gamesPlayed", "Times played"},
    {"displayName", "Name"},
    {"author.login", "Author"},
    {"latestVersion.createTime", "Uploaded"},
    {"latestVersion.updateTime", "Updated"},
    {"latestVersion.maxPlayers", "Max players"},
    {"latestVersion.width", "Width"},
    {"latestVersion.height", "Height"},
    {"latestVersion.folderName", "Folder name"},
    {"latestVersion.ranked", "Ranked"},
    {"latestVersion.description", "Description"},
    {"latestVersion.id", "Version id"},
  };

  /**
   * What a vault search asks for: the FAF client's map filters (MapVaultController::initSearchController) and its
   * order. Empty, 0 or false: any.
   */
  struct VaultQuery
  {
    std::string text;   // the name (anywhere in it)
    std::string author; // the author's login (anywhere in it)
    /** Uploaded (the latest version's update time, as the client's filter): after `from`, before `to`, YYYY-MM-DD. */
    std::string uploadedFrom;
    std::string uploadedTo;
    /** Widths and heights by bit: bit k is kVaultSizes[k]. */
    unsigned widths = 0;
    unsigned heights = 0;
    /** Max players from and to (the client's range is 0 to 16: 0 below, 16 above mean any). */
    int minPlayers = 0;
    int maxPlayers = 0;
    /** The average review score from and to (0 to 5). */
    float minScore = 0.0f;
    float maxScore = 5.0f;
    bool rankedOnly = false;
    std::string sortProperty = "gamesPlayed";
    bool descending = true;
    bool operator==(const VaultQuery& other) const = default;
  };
  /** The query's filter, as the FAF client writes it (RSQL; "Display search query"). */
  std::string VaultQueryFilter(const VaultQuery& query);
  /** The map API's link for a vault search, 30 maps a page. */
  std::string VaultSearchUrl(const VaultQuery& query, int page);
  /** A query as one line of text and back (the saved queries, "Favorites"); unknown keys are skipped. */
  std::string VaultQueryText(const VaultQuery& query);
  bool VaultQueryFromText(const std::string& text, VaultQuery& out);

  /** A map API answer (`data` maps, `included` versions and players) as maps; false with `error`. */
  bool ParseVaultSearch(const std::string& json, std::vector<VaultMap>& maps, int& pages, std::string& error);

  /**
   * The editor's FAF session: logs in with the device flow (FAF's page in the browser, with the code already in it),
   * keeps the refresh token in `tokenFile` encrypted for this Windows user (DPAPI), and searches the vault. Every
   * request runs on its own thread; the panel reads the state each frame.
   */
  class EdFafSession
  {
  public:
    enum class State
    {
      LoggedOut,
      Working,
      WaitingForApproval,
      LoggedIn,
    };

    ~EdFafSession();
    void SetTokenFile(std::filesystem::path file);
    /** Logs in with the kept refresh token, if there is one; else stays logged out. */
    void Resume();
    /** Starts the device flow: FAF's page opens in the browser; the session waits until it is approved there. */
    void StartLogin();
    void Logout();
    /** Stops waiting for the browser's approval. */
    void CancelLogin();
    /** The FAF name logged in with (from the API's /me), empty until known. */
    [[nodiscard]] std::string UserName() const;
    /** Seconds left before the login code runs out, while waiting for approval. */
    [[nodiscard]] int SecondsLeft() const;
    void Search(const VaultQuery& query, int page);
    /** A finished search's maps (once each search). */
    bool TakeResults(std::vector<VaultMap>& maps, int& pages);
    /**
     * A search kept by name, beside the vault page's (the start screen's "Your uploads", "Most played", its search
     * box): runs when asked while logged in, its first page kept to read until asked again.
     */
    void SearchNamed(const std::string& name, const VaultQuery& query);
    /** The named search's maps once it finished (`error` says why there are none); false before. */
    bool NamedResults(const std::string& name, std::vector<VaultMap>& maps, std::string& error) const;
    /** Whether it was asked (running or done). */
    [[nodiscard]] bool NamedAsked(const std::string& name) const;
    /**
     * The bytes behind a link (a map's picture): from the FAF client's preview cache (`%ProgramData%\FAForever\cache\
     * maps\large` or `small`, named after the link's last part, as its AssetService keeps them), else the editor's own
     * cache, else downloaded on a worker thread and kept in the editor's cache. Empty until here; one byte when the
     * picture can't be had.
     */
    std::string Picture(const std::string& url);
    /** Where the editor keeps the pictures it downloads. */
    void SetPictureCache(
      std::filesystem::path folder
    )
    {
      mPictureCache = std::move(folder);
    }

    [[nodiscard]] State GetState() const noexcept
    {
      return mState.load();
    }
    [[nodiscard]] std::string Message() const;
    [[nodiscard]] std::string UserCode() const;
    [[nodiscard]] std::string VerifyUrl() const;
    [[nodiscard]] bool Searching() const noexcept
    {
      return mSearching.load();
    }
    /** The sign-in's page should open in the browser now (once). */
    [[nodiscard]] bool TakeOpenPage() noexcept
    {
      return mOpenPage.exchange(false);
    }

  private:
    void Run(std::function<void()> job);
    void SetMessage(std::string text);
    bool RefreshAccess(std::string& error);
    void SaveRefreshToken() const;
    void FetchUserName();
    /** One page of a search (a new access token and again when the old one ran out); false with `error`. */
    bool FetchMaps(const VaultQuery& query, int page, std::vector<VaultMap>& maps, int& pages, std::string& error);
    struct Named
    {
      bool done = false;
      std::vector<VaultMap> maps;
      std::string error;
    };
    std::map<std::string, Named> mNamed;

    std::filesystem::path mTokenFile;
    std::atomic<State> mState{State::LoggedOut};
    std::atomic<bool> mSearching{false};
    std::atomic<bool> mStop{false};
    std::atomic<bool> mCancel{false};
    std::atomic<bool> mOpenPage{false};
    std::atomic<long long> mCodeExpires{0};
    std::string mUserName;
    mutable std::mutex mLock;
    std::string mMessage;
    std::string mUserCode;
    std::string mVerifyUrl;
    std::string mAccessToken;
    std::string mRefreshToken;
    bool mHaveResults = false;
    std::vector<VaultMap> mResults;
    int mPages = 0;
    std::vector<std::thread> mThreads;
    std::map<std::string, std::string> mPictures;
    std::vector<std::string> mPictureQueue;
    bool mPictureWorker = false;
    std::filesystem::path mPictureCache;
  };
} // namespace faf::editor
