// Engine addition (in-game launcher plan, WP4): the live replay relay (src/online/ReplayRelay.h).

#include "online/ReplayRelay.h"

#include <algorithm>

#include "online/Json.h"

namespace faf::online
{
  namespace
  {
    constexpr std::size_t kChunk = 16384;
    /** How long the end of a game keeps trying to get its last bytes out (the Rust client's UPLOAD_FLUSH_TIMEOUT). */
    constexpr auto kFlushTime = std::chrono::seconds(60);
    constexpr auto kFirstBackoff = std::chrono::seconds(2);
    constexpr auto kMaxBackoff = std::chrono::seconds(30);
  } // namespace

  ReplayRelay::ReplayRelay(
    ReplayRelaySettings settings
  )
    : mSettings(std::move(settings))
  {
    (void)netbridge::SocketsInit();
  }

  ReplayRelay::~ReplayRelay()
  {
    Stop();
  }

  void ReplayRelay::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void ReplayRelay::Log(
    const std::string& line
  ) const
  {
    if (mLog) {
      mLog(("replay relay: " + line).c_str());
    }
  }

  std::expected<std::uint16_t, std::string> ReplayRelay::Listen()
  {
    if (mListener == netbridge::kInvalidSocket) {
      mListener = netbridge::ListenTcp("127.0.0.1", 0);
      if (mListener == netbridge::kInvalidSocket) {
        return std::unexpected(
          "no replay listener on 127.0.0.1 (error " + std::to_string(netbridge::LastSocketError()) + ")"
        );
      }
    }
    return netbridge::LocalPort(mListener);
  }

  void ReplayRelay::Start(
    TokenSource tokens
  )
  {
    mTokens = std::move(tokens);
    mStop = false;
    mThread = std::thread([this] {
      Run();
    });
  }

  bool ReplayRelay::Finish(
    const std::chrono::milliseconds limit
  )
  {
    std::unique_lock<std::mutex> lock(mDoneLock);
    mDoneSignal.wait_for(lock, limit, [this] {
      return mDone;
    });
    return mDone && mAllSent;
  }

  void ReplayRelay::Stop()
  {
    mStop = true;
    {
      std::lock_guard<std::mutex> lock(mDoneLock);
      netbridge::CloseSocket(mListener); // ends a waiting accept
      netbridge::CloseSocket(mGame);     // ends a waiting recv
    }
    mSocket.Close();
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  void ReplayRelay::Failed(
    const std::string& why
  )
  {
    if (why != mLastFailure) {
      Log(why);
      mLastFailure = why;
    }
    mBackoff = mBackoff.count() == 0 ? kFirstBackoff : std::min<std::chrono::seconds>(kMaxBackoff, mBackoff * 2);
    mNextTry = std::chrono::steady_clock::now() + mBackoff;
  }

  bool ReplayRelay::Forward()
  {
    if (!mConnected) {
      if (std::chrono::steady_clock::now() < mNextTry) {
        return false; // a failure a moment ago: the bytes wait for the next try
      }
      std::string url = mSettings.webSocketUrl;
      std::string token;
      if (url.empty() || mTokens) {
        const auto got = mTokens ? mTokens() : std::expected<std::string, std::string>(std::unexpected("no tokens"));
        if (!got) {
          Failed("no FAF sign-in: " + got.error());
          return false;
        }
        token = *got;
      }
      if (url.empty()) {
        platform::http::Call call;
        call.url = mSettings.userServiceUrl + "/replay/access";
        call.headers = "Accept: application/json\r\nAuthorization: Bearer " + token + "\r\n";
        call.userAgent = mSettings.userAgent;
        long status = 0;
        std::string body;
        const auto sent = platform::http::Request(call, status, body);
        const auto answer =
          sent ? ParseJson(body) : std::expected<JsonNode, std::string>(std::unexpected(sent.error()));
        if (!sent || status != 200 || !answer || answer->String("accessUrl").empty()) {
          Failed(
            "the replay service's address: " +
            (sent ? "the user service answered " + std::to_string(status) : sent.error())
          );
          return false;
        }
        url = answer->String("accessUrl");
      }
      if (const auto opened = mSocket.Open(url, {}, mSettings.userAgent); !opened) {
        Failed("the replay service: " + opened.error());
        return false;
      }
      mConnected = true;
      mSentHere = 0; // a new connection gets the stream from its start
      mBackoff = std::chrono::seconds(0);
      mLastFailure.clear();
      Log("sending the replay");
    }
    while (mSentHere < mStream.size()) {
      const std::size_t size = std::min(kChunk, mStream.size() - mSentHere);
      if (const auto sent = mSocket.SendBinary(std::string_view(mStream).substr(mSentHere, size)); !sent) {
        mSocket.Close();
        mConnected = false;
        Failed("the replay service dropped: " + sent.error());
        return false;
      }
      mSentHere += size;
      mSent = std::max<std::uint64_t>(mSent.load(), mSentHere);
    }
    return true;
  }

  void ReplayRelay::Run()
  {
    // In slices, so Stop is seen on every system (netbridge::WaitReadable).
    int ready = 0;
    while (!mStop.load() && (ready = netbridge::WaitReadable(mListener, 200)) == 0) {}
    const netbridge::SocketHandle game =
      mStop.load() || ready < 0 ? netbridge::kInvalidSocket : ::accept(mListener, nullptr, nullptr);
    netbridge::NoSigPipe(game);
    if (game == netbridge::kInvalidSocket) {
      std::lock_guard<std::mutex> lock(mDoneLock);
      mDone = true;
      mDoneSignal.notify_all();
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mDoneLock);
      mGame = game;
    }
    char buffer[65536];
    for (;;) {
      const int waited = netbridge::WaitReadable(game, 200);
      if (waited == 0 && !mStop.load()) {
        continue;
      }
      const int got = waited < 0 || mStop.load() ? -1 : static_cast<int>(::recv(game, buffer, sizeof(buffer), 0));
      if (got <= 0 || mStop.load()) {
        break;
      }
      if (mStream.size() + static_cast<std::size_t>(got) > mSettings.maxBytes) {
        Log("the replay grew past its limit; the rest isn't sent");
        break;
      }
      mStream.append(buffer, static_cast<std::size_t>(got));
      mFromGame = mStream.size();
      (void)Forward(); // a failure is retried with the next bytes, from the start
    }
    // The game's stream ended: the last bytes tell the service the game is over, so keep trying for a while.
    bool allSent = false;
    const auto until = std::chrono::steady_clock::now() + kFlushTime;
    while (!mStop.load() && !(allSent = Forward()) && std::chrono::steady_clock::now() < until) {
      for (int i = 0; i < 20 && !mStop.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    mSocket.Close();
    {
      std::lock_guard<std::mutex> lock(mDoneLock);
      netbridge::CloseSocket(mGame);
    }
    Log(
      std::string(allSent ? "sent " : "gave up after ") + std::to_string(mSent.load()) + " of " +
      std::to_string(mStream.size()) + " bytes"
    );
    std::lock_guard<std::mutex> lock(mDoneLock);
    mDone = true;
    mAllSent = allSent;
    mDoneSignal.notify_all();
  }
} // namespace faf::online
