#pragma once

// Engine addition (in-game launcher plan, WP1): signing in to FAF, shared by the map editor and the game's launcher.
// The sign-in of the editor's EdFafSession (src/editor/doc/EdFafApi before WP1), moved here with the same steps and
// texts; what differs between programs (server addresses, client id, scopes, names) is in FafEndpoints.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "online/Json.h"
#include "platform/Http.h"

namespace faf::online
{
  /** Where and as whom a program signs in. The defaults are FAF's main servers and the FAF client's id. */
  struct FafEndpoints
  {
    std::string oauthUrl = "https://hydra.faforever.com";
    std::string apiUrl = "https://api.faforever.com";
    std::string clientId = "2e8808cf-5889-469b-b2c3-01f0cc58c4af";
    std::string scopes = "openid offline public_profile";
    /** Kept in clear with the sealed token (the OS shows it as the secret's description). */
    std::string tokenDescription = "FAF login";
    /** Who the browser page approves, in the waiting message: "Approve <who> on FAF's page ...". */
    std::string approveWho = "the sign-in";
  };

  /**
   * One FAF account's sign-in: the device flow (FAF's page in the browser, with the code already in it), the refresh
   * token kept sealed for this OS user in a file, access tokens renewed from it. Each step runs on a thread of its own;
   * a UI reads the state each frame. The refresh token never leaves this class except sealed into its file.
   */
  class FafAuth
  {
  public:
    enum class State
    {
      LoggedOut,
      Working,
      WaitingForApproval,
      LoggedIn,
    };

    /** How requests are made: platform::http::Request by default; tests answer them themselves. */
    using Transport = std::function<
      std::expected<void, std::string>(const platform::http::Call& call, long& status, std::string& body)>;

    explicit FafAuth(FafEndpoints endpoints = {});
    ~FafAuth();
    FafAuth(const FafAuth&) = delete;
    FafAuth& operator=(const FafAuth&) = delete;

    [[nodiscard]] const FafEndpoints& Endpoints() const noexcept
    {
      return mEndpoints;
    }
    /** Where lines for a log go ("FAF: ..."); none by default. */
    void SetLog(std::function<void(const char*)> log);
    void SetTransport(Transport transport);
    /** The file the refresh token is kept in, sealed; reads the one kept there, if any. */
    void SetTokenFile(std::filesystem::path file);
    /** Signs in with the kept refresh token, if there is one; else stays signed out. */
    void Resume();
    /** Starts the device flow; the page should be opened (TakeOpenPage) and the code approved there. */
    void StartLogin();
    void Logout();
    /** Stops waiting for the browser's approval. */
    void CancelLogin();

    /**
     * A new access token from the refresh token (it lasts an hour). A refused one (400 or 401) signs out; a server
     * error or no answer keeps the sign-in for a later try.
     */
    [[nodiscard]] std::expected<void, std::string> RefreshAccess();
    /** The current access token, empty when signed out. */
    [[nodiscard]] std::string AccessToken() const;
    /**
     * The access token, refreshed first when it has under 5 minutes left. Refreshes run one at a time: FAF's login
     * hands out a new refresh token with each, and the old one is spent. May block on the network; never call it
     * from the game's main thread.
     */
    [[nodiscard]] std::expected<std::string, std::string> FreshAccessToken();
    /** For a caller that found the sign-in gone (a refresh refused during its own request). */
    void MarkLoggedOut() noexcept
    {
      mState = State::LoggedOut;
    }

    [[nodiscard]] State GetState() const noexcept
    {
      return mState.load();
    }
    /** The FAF name signed in with (from the API's /me), empty until known. */
    [[nodiscard]] std::string UserName() const;
    /** The last thing to tell the user; callers using this sign-in may set it too. */
    [[nodiscard]] std::string Message() const;
    void SetMessage(std::string text);
    [[nodiscard]] std::string UserCode() const;
    [[nodiscard]] std::string VerifyUrl() const;
    /** Seconds left before the sign-in code runs out, while waiting for approval. */
    [[nodiscard]] int SecondsLeft() const;
    /** The sign-in's page should open in the browser now (once). */
    [[nodiscard]] bool TakeOpenPage() noexcept
    {
      return mOpenPage.exchange(false);
    }
    /** Waits until every step started so far has ended (tests). */
    void Wait();

  private:
    void Run(std::function<void()> job);
    void Log(const std::string& line) const;
    [[nodiscard]] std::expected<void, std::string> PostForm(
      const std::string& path,
      const std::vector<std::pair<std::string, std::string>>& fields,
      long& status,
      JsonNode& answer
    );
    void SaveRefreshToken() const;
    void FetchUserName();
    [[nodiscard]] std::expected<void, std::string> RefreshAccessLocked(); ///< with mRefreshLock held

    FafEndpoints mEndpoints;
    std::function<void(const char*)> mLog;
    Transport mTransport;
    std::filesystem::path mTokenFile;
    std::atomic<State> mState{State::LoggedOut};
    std::atomic<bool> mStop{false};
    std::atomic<bool> mCancel{false};
    std::atomic<bool> mOpenPage{false};
    std::atomic<long long> mCodeExpires{0};
    mutable std::mutex mLock;
    std::string mUserName;
    std::string mMessage;
    std::string mUserCode;
    std::string mVerifyUrl;
    std::string mAccessToken;
    std::chrono::steady_clock::time_point mAccessExpires{}; ///< from the token answer's expires_in
    std::string mRefreshToken;
    std::mutex mRefreshLock;             ///< one refresh at a time
    std::uint64_t mSignInGeneration = 0; ///< under mLock; a sign-in or a logout moves it on
    std::vector<std::thread> mThreads;
  };
} // namespace faf::online
