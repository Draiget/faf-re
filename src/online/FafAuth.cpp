// Engine addition (in-game launcher plan, WP1): the map editor's FAF sign-in (src/editor/doc/EdFafApi.cpp before
// WP1), moved here: same requests, same order, same texts; the server addresses and names come from FafEndpoints.

#include "online/FafAuth.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>

#include "online/Url.h"
#include "platform/SecretStore.h"

namespace faf::online
{
  namespace
  {
    /** When a token answer's access token runs out: `expires_in` seconds from now, an hour when it doesn't say. */
    std::chrono::steady_clock::time_point AccessExpiry(
      const JsonNode& answer
    )
    {
      const double seconds = answer.Number("expires_in", 3600.0);
      const double clamped = seconds > 0.0 && seconds < 7.0 * 24 * 3600 ? seconds : 3600.0;
      return std::chrono::steady_clock::now() + std::chrono::seconds(static_cast<long long>(clamped));
    }
  } // namespace

  FafAuth::FafAuth(
    FafEndpoints endpoints
  )
    : mEndpoints(std::move(endpoints))
    , mTransport([](const platform::http::Call& call, long& status, std::string& body) {
      return platform::http::Request(call, status, body);
    })
  {}

  FafAuth::~FafAuth()
  {
    mStop = true;
    Wait();
  }

  void FafAuth::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void FafAuth::SetTransport(
    Transport transport
  )
  {
    mTransport = std::move(transport);
  }

  void FafAuth::Log(
    const std::string& line
  ) const
  {
    if (mLog) {
      mLog(line.c_str());
    }
  }

  void FafAuth::Run(
    std::function<void()> job
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    mThreads.emplace_back(std::move(job));
  }

  void FafAuth::Wait()
  {
    std::vector<std::thread> threads;
    {
      std::lock_guard<std::mutex> lock(mLock);
      threads.swap(mThreads);
    }
    for (std::thread& thread : threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }

  void FafAuth::SetMessage(
    std::string text
  )
  {
    if (!text.empty()) {
      Log("FAF: " + text);
    }
    std::lock_guard<std::mutex> lock(mLock);
    mMessage = std::move(text);
  }

  std::string FafAuth::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  std::string FafAuth::UserName() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mUserName;
  }

  std::string FafAuth::UserCode() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mUserCode;
  }

  std::string FafAuth::VerifyUrl() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mVerifyUrl;
  }

  std::string FafAuth::AccessToken() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mAccessToken;
  }

  int FafAuth::SecondsLeft() const
  {
    const long long now =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    return static_cast<int>(std::max<long long>(0, mCodeExpires.load() - now));
  }

  void FafAuth::CancelLogin()
  {
    mCancel = true;
  }

  std::expected<void, std::string> FafAuth::PostForm(
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& fields,
    long& status,
    JsonNode& answer
  )
  {
    platform::http::Call call;
    call.method = "POST";
    call.url = mEndpoints.oauthUrl + path;
    call.headers = "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";
    call.body = FormBody(fields);
    std::string body;
    if (const auto sent = mTransport(call, status, body); !sent) {
      return std::unexpected(sent.error());
    }
    auto parsed = ParseJson(body);
    if (!parsed) {
      return std::unexpected("FAF's login answered " + std::to_string(status) + " with text that isn't JSON");
    }
    answer = std::move(*parsed);
    return {};
  }

  void FafAuth::FetchUserName()
  {
    // The API's own record of who is signed in (the FAF client's /me).
    platform::http::Call call;
    call.url = mEndpoints.apiUrl + "/me";
    {
      std::lock_guard<std::mutex> lock(mLock);
      call.headers = "Accept: application/json\r\nAuthorization: Bearer " + mAccessToken + "\r\n";
    }
    long status = 0;
    std::string body;
    std::string error;
    std::expected<JsonNode, std::string> me = std::unexpected(std::string());
    if (const auto sent = mTransport(call, status, body); !sent) {
      error = sent.error();
    } else if (status == 200) {
      me = ParseJson(body);
      if (!me) {
        error = me.error();
      }
    }
    if (!me) {
      Log("FAF: /me answered " + std::to_string(status) + (error.empty() ? "" : ": ") + error);
      return;
    }
    std::string name;
    if (const JsonNode* const data = me->Get("data")) {
      if (const JsonNode* const attributes = data->Get("attributes")) {
        name = attributes->String("userName");
        if (name.empty()) {
          name = attributes->String("login");
        }
      }
    }
    Log("FAF: logged in as " + (name.empty() ? std::string("(no name in /me)") : name));
    std::lock_guard<std::mutex> lock(mLock);
    mUserName = name;
  }

  void FafAuth::SetTokenFile(
    std::filesystem::path file
  )
  {
    mTokenFile = std::move(file);
    std::ifstream in(mTokenFile, std::ios::binary);
    const std::string sealed((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (sealed.empty()) {
      return;
    }
    if (auto opened = platform::secret::Open(sealed)) {
      std::lock_guard<std::mutex> lock(mLock);
      mRefreshToken = std::move(*opened);
    }
  }

  void FafAuth::SaveRefreshToken() const
  {
    if (mTokenFile.empty()) {
      return;
    }
    std::string token;
    {
      std::lock_guard<std::mutex> lock(mLock);
      token = mRefreshToken;
    }
    std::ofstream out(mTokenFile, std::ios::binary | std::ios::trunc);
    // Owner only, before the token goes in: on POSIX that is what keeps it to this user (platform/SecretStore.h).
    std::error_code ignored;
    std::filesystem::permissions(
      mTokenFile,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace,
      ignored
    );
    if (token.empty()) {
      return;
    }
    if (const auto sealed = platform::secret::Seal(token, mEndpoints.tokenDescription)) {
      out.write(sealed->data(), static_cast<std::streamsize>(sealed->size()));
    }
  }

  std::expected<void, std::string> FafAuth::RefreshAccess()
  {
    std::lock_guard<std::mutex> refreshing(mRefreshLock);
    return RefreshAccessLocked();
  }

  std::expected<std::string, std::string> FafAuth::FreshAccessToken()
  {
    std::lock_guard<std::mutex> refreshing(mRefreshLock);
    const auto now = std::chrono::steady_clock::now();
    std::string token;
    std::chrono::steady_clock::time_point expires;
    bool canRefresh = false;
    {
      std::lock_guard<std::mutex> lock(mLock);
      token = mAccessToken;
      expires = mAccessExpires;
      canRefresh = !mRefreshToken.empty();
    }
    // Another caller may have refreshed while this one waited for the lock; then the token is fresh already.
    if (!token.empty() && now + std::chrono::minutes(5) < expires) {
      return token;
    }
    if (canRefresh) {
      const auto refreshed = RefreshAccessLocked();
      if (refreshed) {
        return AccessToken();
      }
      if (!token.empty() && now < expires) {
        return token; // the refresh failed, but the old token still works for a few minutes
      }
      return std::unexpected(refreshed.error());
    }
    if (!token.empty() && now < expires) {
      return token;
    }
    return std::unexpected(token.empty() ? "not signed in" : "the FAF sign-in ran out; sign in again");
  }

  std::expected<void, std::string> FafAuth::RefreshAccessLocked()
  {
    std::string refresh;
    std::uint64_t generation = 0;
    {
      std::lock_guard<std::mutex> lock(mLock);
      refresh = mRefreshToken;
      generation = mSignInGeneration;
    }
    if (refresh.empty()) {
      return std::unexpected("not logged in");
    }
    long status = 0;
    JsonNode answer;
    if (
      auto posted = PostForm(
        "/oauth2/token",
        {{"grant_type", "refresh_token"}, {"refresh_token", refresh}, {"client_id", mEndpoints.clientId}},
        status,
        answer
      );
      !posted
    ) {
      return std::unexpected(std::move(posted.error()));
    }
    if (status != 200 || answer.String("access_token").empty()) {
      // OAuth 2.0 (RFC 6749 5.2) refuses a spent or revoked refresh token with 400 (invalid_grant), or 401 for the
      // client. Anything else - a 5xx, a 429 from a proxy - says nothing about the login, so it is kept for later.
      if (status != 200 && status != 400 && status != 401) {
        return std::unexpected(
          "FAF's login didn't renew the sign-in (answer " + std::to_string(status) + "); try again later"
        );
      }
      bool same = false;
      {
        std::lock_guard<std::mutex> lock(mLock);
        same = generation == mSignInGeneration;
        if (same) {
          mRefreshToken.clear();
          mAccessToken.clear();
          mAccessExpires = {};
        }
      }
      if (same) {
        // Signed out, wherever the refresh ran: the state says so and the spent token leaves the file.
        mState = State::LoggedOut;
        SaveRefreshToken();
      }
      return std::unexpected("FAF's login refused the kept login (" + answer.String("error") + "); log in again");
    }
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (generation != mSignInGeneration) {
        // Logged out (or in again) while the answer was on its way: what it brought must not bring the old login back.
        return std::unexpected(std::string("signed out meanwhile"));
      }
      mAccessToken = answer.String("access_token");
      mAccessExpires = AccessExpiry(answer);
      if (!answer.String("refresh_token").empty()) {
        mRefreshToken = answer.String("refresh_token"); // Hydra hands out a new one each time
      }
    }
    SaveRefreshToken();
    return {};
  }

  void FafAuth::Resume()
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (mRefreshToken.empty() || mState.load() != State::LoggedOut) {
        return;
      }
    }
    mState = State::Working;
    SetMessage("Logging in to FAF...");
    Run([this] {
      if (const auto refreshed = RefreshAccess()) {
        FetchUserName();
        mState = State::LoggedIn;
        SetMessage("Logged in to FAF");
      } else {
        mState = State::LoggedOut;
        SetMessage(refreshed.error());
        SaveRefreshToken();
      }
    });
  }

  void FafAuth::StartLogin()
  {
    if (mState.load() == State::Working || mState.load() == State::WaitingForApproval) {
      return;
    }
    mState = State::Working;
    mCancel = false;
    SetMessage("Asking FAF for a login code...");
    Run([this] {
      long status = 0;
      JsonNode device;
      const auto posted = PostForm(
        "/oauth2/device/auth", {{"client_id", mEndpoints.clientId}, {"scope", mEndpoints.scopes}}, status, device
      );
      if (!posted || status != 200) {
        mState = State::LoggedOut;
        SetMessage(
          posted || posted.error().empty() ? "FAF's login answered " + std::to_string(status) : posted.error()
        );
        return;
      }
      const std::string deviceCode = device.String("device_code");
      {
        std::lock_guard<std::mutex> lock(mLock);
        mUserCode = device.String("user_code");
        mVerifyUrl = device.String("verification_uri_complete");
        if (mVerifyUrl.empty()) {
          mVerifyUrl = device.String("verification_uri");
        }
      }
      // FAF's page in the browser, the code already in it (as the FAF client opens it): the UI opens it on its own
      // thread, as ShellExecute needs COM set up where it runs.
      mOpenPage = true;
      mState = State::WaitingForApproval;
      SetMessage("Approve " + mEndpoints.approveWho + " on FAF's page in your browser (code " + UserCode() + ")");
      int interval = std::max(1, static_cast<int>(device.Number("interval", 5.0)));
      const auto until =
        std::chrono::steady_clock::now() + std::chrono::seconds(static_cast<int>(device.Number("expires_in", 600.0)));
      mCodeExpires = std::chrono::duration_cast<std::chrono::seconds>(until.time_since_epoch()).count();
      std::string lastPoll;
      while (!mStop.load() && !mCancel.load() && std::chrono::steady_clock::now() < until) {
        for (int i = 0; i < interval * 10 && !mStop.load() && !mCancel.load(); ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (mStop.load() || mCancel.load()) {
          break;
        }
        JsonNode token;
        const auto answered = PostForm(
          "/oauth2/token",
          {{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
           {"device_code", deviceCode},
           {"client_id", mEndpoints.clientId}},
          status,
          token
        );
        // Each new kind of answer once in the log, so a sign-in that never ends says why.
        const std::string poll = std::to_string(status) + " " + (answered ? token.String("error") : answered.error());
        if (poll != lastPoll) {
          Log("FAF: waiting for approval, the token endpoint answers " + poll);
          lastPoll = poll;
        }
        if (!answered) {
          continue; // a dropped answer: ask again
        }
        if (status == 200 && !token.String("access_token").empty()) {
          {
            std::lock_guard<std::mutex> lock(mLock);
            ++mSignInGeneration;
            mAccessToken = token.String("access_token");
            mAccessExpires = AccessExpiry(token);
            mRefreshToken = token.String("refresh_token");
          }
          SaveRefreshToken();
          FetchUserName();
          mState = State::LoggedIn;
          SetMessage("Logged in to FAF");
          return;
        }
        const std::string why = token.String("error");
        if (why == "slow_down") {
          interval += 5;
        } else if (why != "authorization_pending") {
          mState = State::LoggedOut;
          SetMessage(why == "access_denied" ? "The login was declined on FAF's page" : "FAF's login stopped: " + why);
          return;
        }
      }
      if (mCancel.load()) {
        mState = State::LoggedOut;
        SetMessage("Sign-in cancelled");
      } else if (!mStop.load()) {
        mState = State::LoggedOut;
        SetMessage("The sign-in code ran out before it was approved; sign in again");
      }
    });
  }

  void FafAuth::Logout()
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      ++mSignInGeneration;
      mAccessToken.clear();
      mAccessExpires = {};
      mRefreshToken.clear();
      mUserName.clear();
    }
    SaveRefreshToken();
    mState = State::LoggedOut;
    SetMessage("Logged out of FAF");
  }
} // namespace faf::online
