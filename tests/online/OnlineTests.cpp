// faf_online (src/online, .plans/ingame-launcher WP1): JSON, URL encoding, the sealed token store, a WebSocket on
// 127.0.0.1, and FAF's sign-in against canned answers. No test reaches the network.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <cctype>
#include <clocale>
#include <cmath>
#include <condition_variable>
#include <random>
#include <string_view>

#include "mbedtls/sha1.h"
#include "netbridge/Socket.h"
#include "platform/PlatformDefines.h"

#if FAFRE_PLATFORM_POSIX
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "online/ControlService.h"
#include "online/FafAuth.h"
#include "online/FafChat.h"
#include "online/FafLobby.h"
#include "online/FafReplay.h"
#include "online/FafVault.h"
#include "online/GameLink.h"
#include "online/LaunchArgs.h"
#include "online/ReplayRelay.h"
#include "online/Json.h"
#include "online/Url.h"
#include "platform/Http.h"
#include "platform/Process.h"
#include "platform/SecretStore.h"
#include "zlib.h"
#include "zstd.h"

namespace
{
  namespace net = faf::netbridge;

  /** A connection to 127.0.0.1:<port>; receives give up after `receiveMs` (0: never). */
  net::SocketHandle ConnectLocal(
    const std::uint16_t port,
    const int receiveMs = 0
  )
  {
    (void)net::SocketsInit();
    net::SocketHandle socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == net::kInvalidSocket) {
      return socket;
    }
    net::NoSigPipe(socket);
    if (receiveMs > 0) {
#if FAFRE_PLATFORM_WINDOWS
      const DWORD timeout = static_cast<DWORD>(receiveMs);
#else
      const timeval timeout{receiveMs / 1000, (receiveMs % 1000) * 1000};
#endif
      (void)::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    }
    const sockaddr_in address = net::MakeAddress("127.0.0.1", port);
    if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      net::CloseSocket(socket);
    }
    return socket;
  }

  bool StartsWithNoCase(
    const std::string_view text,
    const std::string_view prefix
  )
  {
    if (text.size() < prefix.size()) {
      return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
      if (std::tolower(static_cast<unsigned char>(text[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
        return false;
      }
    }
    return true;
  }

  using faf::online::FafAuth;
  using faf::online::FafEndpoints;

  // --- A one-connection WebSocket server on 127.0.0.1 --------------------------------------------------------------

  std::string Base64(
    const unsigned char* data,
    std::size_t size
  )
  {
    static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < size; i += 3) {
      const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16) |
        (i + 1 < size ? static_cast<std::uint32_t>(data[i + 1]) << 8 : 0u) | (i + 2 < size ? data[i + 2] : 0u);
      out += kTable[(n >> 18) & 63];
      out += kTable[(n >> 12) & 63];
      out += i + 1 < size ? kTable[(n >> 6) & 63] : '=';
      out += i + 2 < size ? kTable[n & 63] : '=';
    }
    return out;
  }

  std::string AcceptKey(
    const std::string& key
  )
  {
    const std::string input = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char digest[20]{};
    (void)mbedtls_sha1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    return Base64(digest, sizeof(digest));
  }

  bool ReadExactly(
    net::SocketHandle socket,
    char* out,
    int size
  )
  {
    while (size > 0) {
      const int got = ::recv(socket, out, size, 0);
      if (got <= 0) {
        return false;
      }
      out += got;
      size -= got;
    }
    return true;
  }

  /** For a scripted server: the text messages to send back for one received (each a frame of its own). */
  using Reply = std::function<std::vector<std::string>(const std::string& received)>;

  /**
   * Accepts one client; `refuse` answers the upgrade with 403. Without `reply` it echoes every message until a close;
   * with it, it sends what `reply` returns for each text message, and keeps what it received.
   */
  class EchoServer
  {
  public:
    explicit EchoServer(
      bool refuse = false,
      Reply reply = {},
      std::string raw = {},
      bool binaryReplies = false
    )
      : rawAfterUpgrade(std::move(raw))
      , mRefuse(refuse)
      , mReply(std::move(reply))
      , mBinaryReplies(binaryReplies)
    {
      (void)net::SocketsInit();
      mListener = net::ListenTcp("127.0.0.1", 0);
      mPort = net::LocalPort(mListener);
      mThread = std::thread([this] {
        Serve();
      });
    }

    ~EchoServer()
    {
      net::CloseSocket(mListener);
      if (mThread.joinable()) {
        mThread.join();
      }
    }

    [[nodiscard]] std::string Url() const
    {
      return "ws://127.0.0.1:" + std::to_string(mPort) + "/lobby?verify=x";
    }

    std::string requestHead;
    const std::string rawAfterUpgrade; ///< bytes sent as they are right after the 101, before any echo

  private:
    void Serve()
    {
      net::SocketHandle client = ::accept(mListener, nullptr, nullptr);
      net::NoSigPipe(client);
      if (client == net::kInvalidSocket) {
        return;
      }
      std::string head;
      char c = 0;
      while (head.find("\r\n\r\n") == std::string::npos && ::recv(client, &c, 1, 0) == 1) {
        head += c;
      }
      requestHead = head;
      if (mRefuse) {
        const std::string answer = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        (void)net::SendAll(client, answer.data(), answer.size());
        net::CloseSocket(client);
        return;
      }
      std::string key;
      std::string protocol;
      for (std::size_t at = 0; at < head.size();) {
        const std::size_t end = head.find("\r\n", at);
        const std::string line = head.substr(at, end - at);
        if (StartsWithNoCase(line, "Sec-WebSocket-Key:")) {
          key = line.substr(18);
          key.erase(0, key.find_first_not_of(' '));
        }
        if (StartsWithNoCase(line, "Sec-WebSocket-Protocol:")) {
          protocol = line.substr(23);
          protocol.erase(0, protocol.find_first_not_of(' '));
        }
        at = end == std::string::npos ? head.size() : end + 2;
      }
      const std::string answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                 "Sec-WebSocket-Accept: " +
        AcceptKey(key) + "\r\n" + (protocol.empty() ? std::string() : "Sec-WebSocket-Protocol: " + protocol + "\r\n") +
        "\r\n";
      (void)net::SendAll(client, answer.data(), answer.size());
      if (!rawAfterUpgrade.empty()) {
        (void)net::SendAll(client, rawAfterUpgrade.data(), rawAfterUpgrade.size());
      }
      for (;;) {
        unsigned char header[2];
        if (!ReadExactly(client, reinterpret_cast<char*>(header), 2)) {
          break;
        }
        const int opcode = header[0] & 0x0F;
        std::uint64_t length = header[1] & 0x7F;
        if (length == 126) {
          unsigned char extended[2];
          if (!ReadExactly(client, reinterpret_cast<char*>(extended), 2)) {
            break;
          }
          length = (static_cast<std::uint64_t>(extended[0]) << 8) | extended[1];
        }
        unsigned char mask[4]{};
        if ((header[1] & 0x80) != 0 && !ReadExactly(client, reinterpret_cast<char*>(mask), 4)) {
          break;
        }
        std::string payload(static_cast<std::size_t>(length), '\0');
        if (length > 0 && !ReadExactly(client, payload.data(), static_cast<int>(length))) {
          break;
        }
        for (std::size_t i = 0; i < payload.size(); ++i) {
          payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
        }
        if (mReply && opcode == 0x2 && mBinaryReplies) {
          {
            std::lock_guard<std::mutex> guard(mLock);
            mReceived.push_back(payload);
          }
          for (const std::string& out : mReply(payload)) {
            SendFrame(client, 0x2, out);
          }
          continue;
        }
        if (mReply && opcode == 0x2) {
          std::lock_guard<std::mutex> guard(mLock);
          mReceivedBinary += payload;
          continue;
        }
        if (mReply && opcode == 0x1) {
          {
            std::lock_guard<std::mutex> guard(mLock);
            mReceived.push_back(payload);
          }
          for (const std::string& out : mReply(payload)) {
            SendFrame(client, 0x1, out);
          }
          continue;
        }
        SendFrame(client, opcode, payload);
        if (opcode == 0x8) {
          break;
        }
      }
      net::CloseSocket(client);
    }

    static void SendFrame(
      net::SocketHandle client,
      int opcode,
      const std::string& payload
    )
    {
      std::string frame;
      frame += static_cast<char>(0x80 | opcode);
      if (payload.size() < 126) {
        frame += static_cast<char>(payload.size());
      } else {
        frame += static_cast<char>(126);
        frame += static_cast<char>((payload.size() >> 8) & 0xFF);
        frame += static_cast<char>(payload.size() & 0xFF);
      }
      frame += payload;
      (void)net::SendAll(client, frame.data(), frame.size());
    }

  public:
    [[nodiscard]] std::vector<std::string> Received()
    {
      std::lock_guard<std::mutex> guard(mLock);
      return mReceived;
    }

    /** Every binary message's bytes, in order. */
    [[nodiscard]] std::string ReceivedBinary()
    {
      std::lock_guard<std::mutex> guard(mLock);
      return mReceivedBinary;
    }

  private:
    bool mRefuse = false;
    Reply mReply;
    bool mBinaryReplies = false; ///< binary messages answered by `reply` with binary frames (FAF's chat)
    std::mutex mLock;
    std::vector<std::string> mReceived;
    std::string mReceivedBinary;
    net::SocketHandle mListener = net::kInvalidSocket;
    unsigned short mPort = 0;
    std::thread mThread;
  };

  // --- Canned answers for FafAuth -----------------------------------------------------------------------------------

  /** Answers each request by its URL's path and its form body; records every request it saw. */
  struct FakeFaf
  {
    std::mutex lock;
    std::vector<platform::http::Call> calls;
    int pendingPolls = 1;
    std::string deviceTokenError; // "" to approve after the pending polls, else the error to send
    std::string refreshAnswerToken = "A2";
    std::string refreshAnswerRefresh = "R2";
    bool refuseRefresh = false;
    long refreshStatus = 0;       ///< not 0: the refresh answers this status and an error body
    std::string refreshExpiresIn; ///< not empty: the refresh answer's expires_in
    int refreshCalls = 0;

    std::expected<void, std::string> operator()(
      const platform::http::Call& call,
      long& status,
      std::string& body
    )
    {
      std::lock_guard<std::mutex> guard(lock);
      calls.push_back(call);
      const auto path = call.url.substr(call.url.find('/', 8));
      if (path == "/oauth2/device/auth") {
        status = 200;
        body =
          R"({"device_code":"DEV","user_code":"ABCD-1234","verification_uri":"https://faf.test/verify",)"
          R"("verification_uri_complete":"https://faf.test/verify?user_code=ABCD-1234","interval":1,"expires_in":30})";
      } else if (path == "/oauth2/token" && call.body.contains("device_code")) {
        if (pendingPolls > 0) {
          --pendingPolls;
          status = 400;
          body = R"({"error":"authorization_pending"})";
        } else if (!deviceTokenError.empty()) {
          status = 400;
          body = R"({"error":")" + deviceTokenError + R"("})";
        } else {
          status = 200;
          body = R"({"access_token":"A1","refresh_token":"R1","scope":"openid offline public_profile lobby"})";
        }
      } else if (path == "/oauth2/token") {
        ++refreshCalls;
        if (refreshStatus != 0) {
          status = refreshStatus;
          body = R"({"error":"temporarily_unavailable"})";
        } else if (refuseRefresh) {
          status = 400;
          body = R"({"error":"invalid_grant"})";
        } else {
          status = 200;
          body = R"({"access_token":")" + refreshAnswerToken + R"(","refresh_token":")" + refreshAnswerRefresh +
            R"(")" + (refreshExpiresIn.empty() ? "" : R"(,"expires_in":)" + refreshExpiresIn) + "}";
        }
      } else if (path == "/me") {
        status = 200;
        body = R"({"data":{"type":"me","id":"me","attributes":{"userName":"Tester","userId":"7"}}})";
      } else {
        status = 404;
        body = "{}";
      }
      return {};
    }
  };

  FafEndpoints TestEndpoints()
  {
    FafEndpoints endpoints;
    endpoints.oauthUrl = "https://hydra.faf.test";
    endpoints.apiUrl = "https://api.faf.test";
    endpoints.clientId = "test-client";
    endpoints.scopes = "openid offline public_profile lobby";
    endpoints.tokenDescription = "faf_online test";
    endpoints.approveWho = "the test";
    return endpoints;
  }

  std::filesystem::path TempFile(
    const char* name
  )
  {
    const auto path =
      std::filesystem::temp_directory_path() / ("faf_online_" + std::to_string(std::random_device{}()) + "_" + name);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return path;
  }

  std::string ReadAll(
    const std::filesystem::path& path
  )
  {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  }

  bool WaitFor(
    const FafAuth& auth,
    FafAuth::State state,
    std::chrono::seconds limit = std::chrono::seconds(15)
  )
  {
    const auto until = std::chrono::steady_clock::now() + limit;
    while (auth.GetState() != state && std::chrono::steady_clock::now() < until) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return auth.GetState() == state;
  }
} // namespace

TEST(
  OnlineJson,
  ReadsObjectsArraysAndEscapes
)
{
  const auto parsed = faf::online::ParseJson(R"({"a": [1, 2.5, "xé"], "b": {"c": true, "d": null}})");
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->Get("a")->items.size(), 3u);
  EXPECT_EQ(parsed->Get("a")->items[2].text, "x\xC3\xA9");
  EXPECT_TRUE(parsed->Get("b")->Bool("c"));
  EXPECT_FALSE(faf::online::ParseJson("{\"a\": 1} trailing"));
}

TEST(
  OnlineJson,
  ReadsUnicodeEscapesAsRfc8259Says
)
{
  const auto text = [](const std::string& json) {
    const auto parsed = faf::online::ParseJson(json);
    return parsed ? parsed->text : std::string("error: ") + parsed.error();
  };
  EXPECT_EQ(text(R"("\u00e9")"), "\xC3\xA9");
  EXPECT_EQ(text(R"("\uD83D\uDE00")"), "\xF0\x9F\x98\x80"); // a surrogate pair: U+1F600
  // A high half without its low half: U+FFFD, and the escape after it is its own character.
  EXPECT_EQ(text(R"("\uD83DA")"), std::string("\xEF\xBF\xBD") + "A");
  EXPECT_EQ(text(R"("\uD83D\u0041")"), std::string("\xEF\xBF\xBD") + "A");
  EXPECT_EQ(text(R"("\uDE00")"), "\xEF\xBF\xBD"); // a low half alone
  // Exactly four hex digits: a short escape doesn't swallow the closing quote.
  EXPECT_FALSE(faf::online::ParseJson(R"({"a":"\u12"})"));
  EXPECT_FALSE(faf::online::ParseJson(R"("\uZZZZ")"));
}

TEST(
  OnlineJson,
  ReadsAndWritesNumbersAsRfc8259Says
)
{
  const auto parsed = faf::online::ParseJson(R"({"a": -12.5e2, "b": 0, "c": 1e20, "d": 7})");
  ASSERT_TRUE(parsed) << parsed.error();
  EXPECT_EQ(parsed->Number("a", 0.0), -1250.0);
  EXPECT_EQ(parsed->String("d"), "7");
  EXPECT_EQ(parsed->String("c"), "1e20"); // past a long long: the digits as written
  // Past a double's range, as strtod reads them on every C++ library: a tiny number is 0, a huge one infinite.
  const auto range = faf::online::ParseJson("[1e-400, -1e-400, 1e400, -1e400]");
  ASSERT_TRUE(range) << range.error();
  EXPECT_EQ(range->items[0].number, 0.0);
  EXPECT_EQ(range->items[1].number, 0.0);
  EXPECT_TRUE(std::isinf(range->items[2].number) && range->items[2].number > 0.0);
  EXPECT_TRUE(std::isinf(range->items[3].number) && range->items[3].number < 0.0);
  for (const char* bad : {"01", "-", "1.", ".5", "1e", "+1", "0x10", "inf", "nan", "1.5.5"}) {
    const auto number = faf::online::ParseJson(std::string("[") + bad + "]");
    EXPECT_FALSE(number) << bad;
  }
  // Whatever the process's locale: Lua's os.setlocale can change it.
  const char* const before = std::setlocale(LC_NUMERIC, nullptr);
  const std::string saved = before != nullptr ? before : "C";
  bool comma = false;
  for (const char* name : {"de_DE.UTF-8", "de_DE.utf8", "German_Germany.1252", "de-DE"}) {
    if (std::setlocale(LC_NUMERIC, name) != nullptr) {
      comma = true;
      break;
    }
  }
  if (comma) {
    const auto local = faf::online::ParseJson(R"({"x": 2.5})");
    const std::string written = faf::online::ToJson(faf::online::JsonNumber(0.25));
    const double digits = faf::online::JsonDigits("2.5").number;
    std::setlocale(LC_NUMERIC, saved.c_str());
    ASSERT_TRUE(local) << local.error();
    EXPECT_EQ(local->Number("x", 0.0), 2.5);
    EXPECT_EQ(written, "0.25");
    EXPECT_EQ(digits, 2.5);
  } else {
    std::setlocale(LC_NUMERIC, saved.c_str());
  }
}

TEST(
  OnlineUrl,
  EncodesFormFields
)
{
  EXPECT_EQ(faf::online::UrlEncode("a b&c=d~"), "a%20b%26c%3Dd~");
  EXPECT_EQ(faf::online::FormBody({{"scope", "openid lobby"}, {"client_id", "x"}}), "scope=openid%20lobby&client_id=x");
}

TEST(
  OnlineSecretStore,
  SealsAndOpensForThisUser
)
{
  const auto sealed = platform::secret::Seal("refresh-token-value", "faf_online test");
  ASSERT_TRUE(sealed) << sealed.error();
#if FAFRE_PLATFORM_WINDOWS
  EXPECT_FALSE(sealed->contains("refresh-token-value")); // DPAPI; POSIX keeps it behind file permissions
#endif
  const auto opened = platform::secret::Open(*sealed);
  ASSERT_TRUE(opened) << opened.error();
  EXPECT_EQ(*opened, "refresh-token-value");
  EXPECT_FALSE(platform::secret::Open("not a sealed blob"));
}

TEST(
  OnlineWebSocket,
  UpgradesSendsAndReceivesTheEcho
)
{
  EchoServer server;
  platform::http::WebSocket socket;
  const auto opened = socket.Open(server.Url(), "X-Test: 1\r\n", "faf-re-client/test");
  ASSERT_TRUE(opened) << opened.error();
  EXPECT_TRUE(socket.IsOpen());
  const std::string message = "{\"command\":\"ask_session\",\"user_agent\":\"faf-re-client\"}\n";
  ASSERT_TRUE(socket.SendText(message));
  std::string echo;
  const auto received = socket.Receive(echo);
  ASSERT_TRUE(received) << received.error();
  EXPECT_EQ(*received, platform::http::WebSocket::Received::Message);
  EXPECT_EQ(echo, message);
  // A long message: more than one WinHTTP read and a 16-bit length on the wire.
  const std::string longMessage(40000, 'x');
  ASSERT_TRUE(socket.SendText(longMessage));
  ASSERT_TRUE(socket.Receive(echo));
  EXPECT_EQ(echo.size(), longMessage.size());
  socket.Close();
  EXPECT_FALSE(socket.IsOpen());
  EXPECT_TRUE(server.requestHead.contains("GET /lobby?verify=x "));
  EXPECT_TRUE(server.requestHead.contains("X-Test: 1"));
  EXPECT_TRUE(server.requestHead.contains("faf-re-client/test"));
}

TEST(
  OnlineWebSocket,
  ReportsARefusedUpgrade
)
{
  EchoServer server(true);
  platform::http::WebSocket socket;
  const auto opened = socket.Open(server.Url());
  ASSERT_FALSE(opened);
  EXPECT_TRUE(opened.error().contains("403")) << opened.error();
  EXPECT_FALSE(socket.IsOpen());
}

TEST(
  OnlineFafAuth,
  DeviceSignInKeepsTheTokenSealedAndResumesWithIt
)
{
  const auto tokenFile = TempFile("device.token");
  FakeFaf faf;
  {
    FafAuth auth(TestEndpoints());
    auth.SetTransport(std::ref(faf));
    auth.SetTokenFile(tokenFile);
    auth.StartLogin();
    ASSERT_TRUE(WaitFor(auth, FafAuth::State::LoggedIn)) << auth.Message();
    auth.Wait(); // the state comes before the message, as it always did in the editor
    EXPECT_TRUE(auth.TakeOpenPage());
    EXPECT_FALSE(auth.TakeOpenPage());
    EXPECT_EQ(auth.UserCode(), "ABCD-1234");
    EXPECT_EQ(auth.VerifyUrl(), "https://faf.test/verify?user_code=ABCD-1234");
    EXPECT_EQ(auth.AccessToken(), "A1");
    EXPECT_EQ(auth.UserName(), "Tester");
    EXPECT_EQ(auth.Message(), "Logged in to FAF");
  }
  {
    std::lock_guard<std::mutex> guard(faf.lock);
    ASSERT_GE(faf.calls.size(), 4u);
    EXPECT_EQ(faf.calls[0].url, "https://hydra.faf.test/oauth2/device/auth");
    EXPECT_EQ(faf.calls[0].body, "client_id=test-client&scope=openid%20offline%20public_profile%20lobby");
    EXPECT_EQ(faf.calls.back().url, "https://api.faf.test/me");
    EXPECT_TRUE(faf.calls.back().headers.contains("Authorization: Bearer A1"));
  }
  const std::string sealed = ReadAll(tokenFile);
  ASSERT_FALSE(sealed.empty());
#if FAFRE_PLATFORM_WINDOWS
  EXPECT_FALSE(sealed.contains("R1")); // DPAPI
#elif FAFRE_PLATFORM_POSIX
  // Owner only: on POSIX that is what keeps the token to this user (platform/SecretStore.h).
  const auto perms = std::filesystem::status(tokenFile).permissions();
  EXPECT_EQ(
    perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all), std::filesystem::perms::none
  );
#endif

  // A new program start: the kept token signs in, and the rotated one replaces it in the file.
  {
    FafAuth auth(TestEndpoints());
    auth.SetTransport(std::ref(faf));
    auth.SetTokenFile(tokenFile);
    auth.Resume();
    ASSERT_TRUE(WaitFor(auth, FafAuth::State::LoggedIn)) << auth.Message();
    EXPECT_EQ(auth.AccessToken(), "A2");
    auth.Wait();
  }
  {
    std::lock_guard<std::mutex> guard(faf.lock);
    bool sentKept = false;
    for (const auto& call : faf.calls) {
      sentKept = sentKept || call.body == "grant_type=refresh_token&refresh_token=R1&client_id=test-client";
    }
    EXPECT_TRUE(sentKept);
  }
  const auto reopened = platform::secret::Open(ReadAll(tokenFile));
  ASSERT_TRUE(reopened);
  EXPECT_EQ(*reopened, "R2");
  std::error_code ignored;
  std::filesystem::remove(tokenFile, ignored);
}

TEST(
  OnlineFafAuth,
  ARefusedTokenSignsOutAndEmptiesTheFile
)
{
  const auto tokenFile = TempFile("refused.token");
  {
    const auto sealed = platform::secret::Seal("R-dead", "faf_online test");
    ASSERT_TRUE(sealed);
    std::ofstream(tokenFile, std::ios::binary) << *sealed;
  }
  FakeFaf faf;
  faf.refuseRefresh = true;
  FafAuth auth(TestEndpoints());
  auth.SetTransport(std::ref(faf));
  auth.SetTokenFile(tokenFile);
  auth.Resume();
  auth.Wait();
  EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut);
  EXPECT_TRUE(auth.Message().contains("refused the kept login (invalid_grant)")) << auth.Message();
  EXPECT_TRUE(auth.AccessToken().empty());
  EXPECT_TRUE(ReadAll(tokenFile).empty());
  std::error_code ignored;
  std::filesystem::remove(tokenFile, ignored);
}

TEST(
  OnlineFafAuth,
  AServerErrorKeepsTheKeptLogin
)
{
  for (const long status : {500L, 503L, 429L}) {
    const auto tokenFile = TempFile("kept.token");
    {
      const auto sealed = platform::secret::Seal("R-kept", "faf_online test");
      ASSERT_TRUE(sealed);
      std::ofstream(tokenFile, std::ios::binary) << *sealed;
    }
    FakeFaf faf;
    faf.refreshStatus = status;
    FafAuth auth(TestEndpoints());
    auth.SetTransport(std::ref(faf));
    auth.SetTokenFile(tokenFile);
    auth.Resume();
    auth.Wait();
    EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut) << status;
    EXPECT_TRUE(auth.Message().contains("try again later")) << auth.Message();
    // Not signed out: the next start tries the same login again.
    const auto reopened = platform::secret::Open(ReadAll(tokenFile));
    ASSERT_TRUE(reopened) << status;
    EXPECT_EQ(*reopened, "R-kept") << status;
    std::error_code ignored;
    std::filesystem::remove(tokenFile, ignored);
  }
}

TEST(
  OnlineFafAuth,
  AFreshTokenIsRefreshedOnceNearItsEnd
)
{
  const auto tokenFile = TempFile("fresh.token");
  {
    const auto sealed = platform::secret::Seal("R1", "faf_online test");
    ASSERT_TRUE(sealed);
    std::ofstream(tokenFile, std::ios::binary) << *sealed;
  }
  FakeFaf faf;
  faf.refreshExpiresIn = "3600";
  FafAuth auth(TestEndpoints());
  auth.SetTransport(std::ref(faf));
  auth.SetTokenFile(tokenFile);
  auth.Resume();
  ASSERT_TRUE(WaitFor(auth, FafAuth::State::LoggedIn)) << auth.Message();
  auth.Wait();
  const auto callsAfter = [&faf] {
    std::lock_guard<std::mutex> guard(faf.lock);
    return faf.refreshCalls;
  };
  const int afterSignIn = callsAfter();

  // An hour left: handed out as it is.
  const auto fresh = auth.FreshAccessToken();
  ASSERT_TRUE(fresh) << fresh.error();
  EXPECT_EQ(*fresh, "A2");
  EXPECT_EQ(callsAfter(), afterSignIn);

  // A minute left: refreshed, and by one of four callers only, as each refresh spends the refresh token.
  {
    std::lock_guard<std::mutex> guard(faf.lock);
    faf.refreshExpiresIn = "60";
  }
  ASSERT_TRUE(auth.RefreshAccess());
  {
    std::lock_guard<std::mutex> guard(faf.lock);
    faf.refreshExpiresIn = "3600";
    faf.refreshAnswerToken = "A3";
    faf.refreshAnswerRefresh = "R3";
  }
  const int beforeRace = callsAfter();
  std::vector<std::string> got(4);
  std::vector<std::thread> callers;
  for (std::size_t i = 0; i < got.size(); ++i) {
    callers.emplace_back([&auth, &got, i] {
      const auto token = auth.FreshAccessToken();
      got[i] = token ? *token : "error: " + token.error();
    });
  }
  for (std::thread& caller : callers) {
    caller.join();
  }
  for (const std::string& token : got) {
    EXPECT_EQ(token, "A3");
  }
  EXPECT_EQ(callsAfter(), beforeRace + 1);
  std::error_code ignored;
  std::filesystem::remove(tokenFile, ignored);
}

TEST(
  OnlineFafAuth,
  ARefusalOnAWorkerSignsOutAndEmptiesTheFile
)
{
  const auto tokenFile = TempFile("worker.token");
  {
    const auto sealed = platform::secret::Seal("R1", "faf_online test");
    ASSERT_TRUE(sealed);
    std::ofstream(tokenFile, std::ios::binary) << *sealed;
  }
  FakeFaf faf;
  faf.refreshExpiresIn = "60"; // under 5 minutes: the next FreshAccessToken refreshes
  FafAuth auth(TestEndpoints());
  auth.SetTransport(std::ref(faf));
  auth.SetTokenFile(tokenFile);
  auth.Resume();
  ASSERT_TRUE(WaitFor(auth, FafAuth::State::LoggedIn)) << auth.Message();
  auth.Wait();
  {
    std::lock_guard<std::mutex> guard(faf.lock);
    faf.refuseRefresh = true;
  }
  std::expected<std::string, std::string> fresh;
  std::thread worker([&] {
    fresh = auth.FreshAccessToken();
  });
  worker.join();
  // The old token had a minute left, so the caller still gets it; the login itself is gone.
  ASSERT_TRUE(fresh) << fresh.error();
  EXPECT_EQ(*fresh, "A2");
  EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut);
  EXPECT_TRUE(ReadAll(tokenFile).empty());
  std::error_code ignored;
  std::filesystem::remove(tokenFile, ignored);
}

TEST(
  OnlineFafAuth,
  ALogoutDuringARefreshStaysLoggedOut
)
{
  const auto tokenFile = TempFile("logout.token");
  {
    const auto sealed = platform::secret::Seal("R1", "faf_online test");
    ASSERT_TRUE(sealed);
    std::ofstream(tokenFile, std::ios::binary) << *sealed;
  }
  FakeFaf faf;
  std::mutex gate;
  std::condition_variable opened;
  bool refreshing = false;
  bool release = true; // the sign-in's own refresh goes straight through
  FafAuth auth(TestEndpoints());
  auth.SetTransport([&](const platform::http::Call& call, long& status, std::string& body) {
    if (call.url.ends_with("/oauth2/token")) {
      std::unique_lock<std::mutex> lock(gate);
      refreshing = true;
      opened.notify_all();
      opened.wait(lock, [&] {
        return release;
      });
    }
    return faf(call, status, body);
  });
  auth.SetTokenFile(tokenFile);
  auth.Resume();
  ASSERT_TRUE(WaitFor(auth, FafAuth::State::LoggedIn)) << auth.Message();
  auth.Wait();
  {
    std::lock_guard<std::mutex> lock(gate);
    refreshing = false;
    release = false;
  }
  std::thread worker([&] {
    (void)auth.RefreshAccess();
  });
  {
    std::unique_lock<std::mutex> lock(gate);
    opened.wait(lock, [&] {
      return refreshing;
    });
  }
  auth.Logout(); // while the refresh's answer is on its way
  {
    std::lock_guard<std::mutex> lock(gate);
    release = true;
  }
  opened.notify_all();
  worker.join();
  EXPECT_TRUE(auth.AccessToken().empty());
  EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut);
  EXPECT_TRUE(ReadAll(tokenFile).empty()); // the answer's new refresh token wasn't saved
  std::error_code ignored;
  std::filesystem::remove(tokenFile, ignored);
}

TEST(
  OnlineFafAuth,
  ADeclinedApprovalSignsOut
)
{
  FakeFaf faf;
  faf.deviceTokenError = "access_denied";
  FafAuth auth(TestEndpoints());
  auth.SetTransport(std::ref(faf));
  auth.StartLogin();
  auth.Wait();
  EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut);
  EXPECT_EQ(auth.Message(), "The login was declined on FAF's page");
}

TEST(
  OnlineFafAuth,
  TheWaitingMessageNamesWhoIsApproved
)
{
  FakeFaf faf;
  faf.pendingPolls = 1000;
  FafAuth auth(TestEndpoints());
  auth.SetTransport(std::ref(faf));
  auth.StartLogin();
  ASSERT_TRUE(WaitFor(auth, FafAuth::State::WaitingForApproval));
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!auth.Message().starts_with("Approve") && std::chrono::steady_clock::now() < until) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // the state comes just before the message
  }
  EXPECT_EQ(auth.Message(), "Approve the test on FAF's page in your browser (code ABCD-1234)");
  EXPECT_GT(auth.SecondsLeft(), 0);
  auth.CancelLogin();
  auth.Wait();
  EXPECT_EQ(auth.GetState(), FafAuth::State::LoggedOut);
  EXPECT_EQ(auth.Message(), "Sign-in cancelled");
}

// --- WP2: JSON writing, helper programs, the lobby client -----------------------------------------------------------

TEST(
  OnlineJson,
  KeepsAnIdsDigitsAndWritesThemBack
)
{
  using namespace faf::online;
  const auto parsed = ParseJson(R"({"command":"session","session":9007199254740993})");
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->Get("session")->text, "9007199254740993"); // a double would read 9007199254740992
  const std::string written = ToJson(JsonObject({
    {"session", JsonDigits(parsed->Get("session")->text)},
    {"text", JsonString("a\"b\\c\n\x01")},
    {"n", JsonNumber(1500)},
    {"x", JsonNumber(0.5)},
    {"ok", JsonBool(true)},
    {"list", JsonArray({JsonNumber(1), JsonString("s")})},
  }));
  EXPECT_EQ(
    written, R"({"session":9007199254740993,"text":"a\"b\\c\n\u0001","n":1500,"x":0.5,"ok":true,"list":[1,"s"]})"
  );
  const auto again = ParseJson(written);
  ASSERT_TRUE(again);
  EXPECT_EQ(ToJson(*again), written);
}

TEST(
  OnlinePlatformProcess,
  RunsAProgramAndReadsItsOutput
)
{
#if FAFRE_PLATFORM_WINDOWS
  const char* const comspec = std::getenv("ComSpec");
  const std::string shell = comspec != nullptr ? comspec : "C:\\Windows\\System32\\cmd.exe";
  const std::vector<std::string> hello{"/c", "echo", "hello"};
  const std::vector<std::string> seven{"/c", "exit", "7"};
  const std::vector<std::string> slow{"/c", "ping", "-n", "6", "127.0.0.1"};
  const std::string missing = "C:\\no\\such\\program.exe";
#else
  const std::string shell = "/bin/sh";
  const std::vector<std::string> hello{"-c", "echo hello"};
  const std::vector<std::string> seven{"-c", "exit 7"};
  const std::vector<std::string> slow{"-c", "sleep 6; echo late"};
  const std::string missing = "/no/such/program";
#endif
  const auto echoed = platform::process::Run(shell, hello, std::chrono::seconds(20));
  ASSERT_TRUE(echoed) << echoed.error();
  EXPECT_EQ(echoed->exitCode, 0);
  EXPECT_TRUE(echoed->out.starts_with("hello")) << echoed->out;
  const auto failed = platform::process::Run(shell, seven, std::chrono::seconds(20));
  ASSERT_TRUE(failed) << failed.error();
  EXPECT_EQ(failed->exitCode, 7);
  // A timeout ends the program and what it started (ping or sleep, under the shell), so it returns soon after it.
  const auto started = std::chrono::steady_clock::now();
  EXPECT_FALSE(platform::process::Run(shell, slow, std::chrono::milliseconds(500)));
  EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(3));
  EXPECT_FALSE(platform::process::Run(missing, {}, std::chrono::seconds(5)));
}

// FAF's .fafreplay: a JSON header line, then the replay stream as zstd or as base64 of a big-endian length and zlib.
TEST(
  OnlineFafReplay,
  DecodesBothBodiesAndRefusesDamage
)
{
  std::string stream;
  for (int i = 0; i < 5000; ++i) {
    stream += static_cast<char>((i * 7) % 251);
  }
  stream += std::string("Supreme Commander v1.50.3841\0", 29);

  // Older files: base64(length, big-endian + zlib).
  uLongf packedSize = compressBound(static_cast<uLong>(stream.size()));
  std::string packed(packedSize, '\0');
  ASSERT_EQ(
    compress(
      reinterpret_cast<Bytef*>(packed.data()),
      &packedSize,
      reinterpret_cast<const Bytef*>(stream.data()),
      static_cast<uLong>(stream.size())
    ),
    Z_OK
  );
  packed.resize(packedSize);
  const std::uint32_t length = static_cast<std::uint32_t>(stream.size());
  std::string blob;
  blob += static_cast<char>((length >> 24) & 0xFF);
  blob += static_cast<char>((length >> 16) & 0xFF);
  blob += static_cast<char>((length >> 8) & 0xFF);
  blob += static_cast<char>(length & 0xFF);
  blob += packed;
  static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string base64;
  for (std::size_t i = 0; i < blob.size(); i += 3) {
    const std::uint32_t chunk = (static_cast<std::uint32_t>(static_cast<unsigned char>(blob[i])) << 16) |
      (i + 1 < blob.size() ? static_cast<unsigned char>(blob[i + 1]) << 8 : 0) |
      (i + 2 < blob.size() ? static_cast<unsigned char>(blob[i + 2]) : 0);
    base64 += kAlphabet[(chunk >> 18) & 63];
    base64 += kAlphabet[(chunk >> 12) & 63];
    base64 += i + 1 < blob.size() ? kAlphabet[(chunk >> 6) & 63] : '=';
    base64 += i + 2 < blob.size() ? kAlphabet[chunk & 63] : '=';
  }
  const std::string zlibFile =
    "{\"uid\": 12345, \"title\": \"test game\", \"mapname\": \"scmp_009\", \"featured_mod\": \"faf\"}\n" + base64;
  const auto older = faf::online::DecodeFafReplay(zlibFile);
  ASSERT_TRUE(older) << older.error();
  EXPECT_EQ(older->header.String("title"), "test game");
  EXPECT_EQ(older->header.String("uid"), "12345");
  EXPECT_EQ(older->stream, stream);

  // Newer files: a zstd frame, the header saying so.
  std::string frame(ZSTD_compressBound(stream.size()), '\0');
  const std::size_t frameSize = ZSTD_compress(frame.data(), frame.size(), stream.data(), stream.size(), 3);
  ASSERT_EQ(ZSTD_isError(frameSize), 0u);
  frame.resize(frameSize);
  const std::string zstdFile = "{\"uid\": 7, \"compression\": \"zstd\", \"mapname\": \"scmp_009\"}\n" + frame;
  const auto newer = faf::online::DecodeFafReplay(zstdFile);
  ASSERT_TRUE(newer) << newer.error();
  EXPECT_EQ(newer->stream, stream);
  const auto header = faf::online::ReadFafReplayHeader(zstdFile);
  ASSERT_TRUE(header);
  EXPECT_EQ(header->String("mapname"), "scmp_009");

  // Damage: cut short, no header, not base64.
  EXPECT_FALSE(faf::online::DecodeFafReplay(zstdFile.substr(0, zstdFile.size() - 20)));
  EXPECT_FALSE(faf::online::DecodeFafReplay(zlibFile.substr(0, zlibFile.size() - 40)));
  EXPECT_FALSE(faf::online::DecodeFafReplay("Supreme Commander replay"));
  EXPECT_FALSE(faf::online::DecodeFafReplay("{\"uid\": 1}\n!!!not base64!!!"));
}

// FAF's replay and mod vaults: the queries as the FAF clients send them, and their JSON:API answers read into rows.
TEST(
  OnlineFafVault,
  BuildsQueriesAndReadsPages
)
{
  faf::online::ReplayQuery replays;
  replays.player = "Seraphim\"-Noob*";
  replays.map = "seton";
  replays.ratedOnly = true;
  const std::string replayUrl = faf::online::ReplaySearchUrl("https://api.example", replays);
  EXPECT_TRUE(replayUrl.starts_with("https://api.example/data/game?sort=-startTime&page%5Bsize%5D=30")) << replayUrl;
  EXPECT_NE(replayUrl.find("page%5Btotals%5D&"), std::string::npos) << replayUrl;
  // The quote and the star from the search box are gone; the clauses are joined with ';' in parentheses.
  EXPECT_NE(replayUrl.find("playerStats.player.login%3D%3D%22%2ASeraphim-Noob%2A%22"), std::string::npos) << replayUrl;
  EXPECT_NE(replayUrl.find("validity%3D%3D%22VALID%22"), std::string::npos) << replayUrl;

  const std::string gamePage =
    R"({"data":[{"type":"game","id":"12345","attributes":{"name":"all welcome","startTime":"2026-01-01T12:00:00Z",)"
    R"("endTime":"2026-01-01T12:30:00Z","replayTicks":12345,"replayAvailable":true,"validity":"VALID"},)"
    R"("relationships":{"mapVersion":{"data":{"type":"mapVersion","id":"9"}},"featuredMod":{"data":{"type":)"
    R"("featuredMod","id":"1"}},"playerStats":{"data":[{"type":"gamePlayerStats","id":"100"},{"type":)"
    R"("gamePlayerStats","id":"101"}]},"reviewsSummary":{"data":{"type":"gameReviewsSummary","id":"12345"}}}}],)"
    R"("included":[{"type":"mapVersion","id":"9","attributes":{"folderName":"scmp_009"},"relationships":{"map":)"
    R"({"data":{"type":"map","id":"77"}}}},{"type":"map","id":"77","attributes":{"displayName":"Seton's Clutch"}},)"
    R"({"type":"featuredMod","id":"1","attributes":{"technicalName":"faf"}},{"type":"gamePlayerStats","id":"100",)"
    R"("attributes":{"team":2,"faction":1,"result":"VICTORY","score":3210},"relationships":{"player":{"data":)"
    R"({"type":"player","id":"500"}},"ratingChanges":{"data":[{"type":"leaderboardRatingJournal","id":"700"}]}}},)"
    R"({"type":"gamePlayerStats","id":"101","attributes":{"team":3,"faction":"CYBRAN","beforeMean":1500.0,)"
    R"("beforeDeviation":200.0},"relationships":{"player":{"data":{"type":"player","id":"501"}}}},)"
    R"({"type":"player","id":"500","attributes":{"login":"Seraphim-Noob"}},{"type":"player","id":"501",)"
    R"("attributes":{"login":"Other"}},{"type":"leaderboardRatingJournal","id":"700","attributes":{"meanBefore":)"
    R"(1600.0,"deviationBefore":100.0,"meanAfter":1615.0,"deviationAfter":98.0}},{"type":"gameReviewsSummary",)"
    R"("id":"12345","attributes":{"averageScore":4.5,"reviews":2}}],"meta":{"page":{"number":1,"totalPages":7,)"
    R"("totalRecords":201}}})";
  faf::online::VaultPage page;
  const auto games = faf::online::ReadReplayPage(gamePage, &page);
  ASSERT_TRUE(games) << games.error();
  ASSERT_EQ(games->size(), 1u);
  const auto& game = games->front();
  EXPECT_EQ(game.id, "12345");
  EXPECT_EQ(game.title, "all welcome");
  EXPECT_EQ(game.mapFolder, "scmp_009");
  EXPECT_EQ(game.mapName, "Seton's Clutch");
  EXPECT_EQ(game.featuredMod, "faf");
  EXPECT_NEAR(game.seconds, 1234.5, 0.01);
  EXPECT_TRUE(game.replayAvailable);
  EXPECT_NEAR(game.reviewScore, 4.5, 0.01);
  ASSERT_EQ(game.players.size(), 2u);
  EXPECT_EQ(game.players[0].login, "Seraphim-Noob");
  EXPECT_EQ(game.players[0].team, 2);
  EXPECT_EQ(game.players[0].rating, 1300); // the journal: 1600 - 3 * 100
  EXPECT_EQ(game.players[1].rating, 900);  // the stat's own: 1500 - 3 * 200
  EXPECT_TRUE(game.players[0].changed);
  EXPECT_EQ(game.players[0].ratingAfter, 1321); // the journal after the game: 1615 - 3 * 98
  EXPECT_FALSE(game.players[1].changed);
  EXPECT_NEAR(game.wallSeconds, 1800.0, 0.5); // 12:00 to 12:30
  EXPECT_NEAR(faf::online::IsoSeconds("1970-01-02T00:00:10Z"), 86410.0, 0.5);
  EXPECT_EQ(faf::online::IsoSeconds("not a time"), 0.0);
  EXPECT_EQ(game.players[1].faction, "CYBRAN");
  EXPECT_EQ(page.totalPages, 7);
  EXPECT_EQ(page.totalRecords, 201);
  EXPECT_EQ(faf::online::ReplayDownloadUrl("https://replay.example", "12345"), "https://replay.example/12345");

  faf::online::ModQuery mods;
  mods.name = "supreme economy";
  mods.type = "UI";
  const std::string modUrl = faf::online::ModSearchUrl("https://api.example", mods);
  EXPECT_NE(modUrl.find("latestVersion.hidden%3D%3D%22false%22"), std::string::npos) << modUrl;
  EXPECT_NE(modUrl.find("displayName%3D%3D%22%2Asupreme%2A%22"), std::string::npos) << modUrl;
  EXPECT_NE(modUrl.find("displayName%3D%3D%22%2Aeconomy%2A%22"), std::string::npos) << modUrl;
  EXPECT_NE(modUrl.find("latestVersion.type%3D%3D%22UI%22"), std::string::npos) << modUrl;

  const std::string modPage =
    R"({"data":[{"type":"mod","id":"3","attributes":{"displayName":"Supreme Economy","author":"Crotalus",)"
    R"("recommended":true},"relationships":{"latestVersion":{"data":{"type":"modVersion","id":"30"}},)"
    R"("uploader":{"data":{"type":"player","id":"9"}},"reviewsSummary":{"data":{"type":"modReviewsSummary",)"
    R"("id":"3"}}}}],"included":[{"type":"modVersion","id":"30","attributes":{"uid":"89BF1572-9EA8-11DC-1313-)"
    R"(635F56D89591","version":"4","description":"Economy at a glance","type":"UI","ranked":true,"downloadUrl":)"
    R"("https://content.example/mods/supreme_economy.v0004.zip","thumbnailUrl":"https://content.example/t.png"}},)"
    R"({"type":"player","id":"9","attributes":{"login":"uploader1"}},{"type":"modReviewsSummary","id":"3",)"
    R"("attributes":{"averageScore":4.8,"reviews":40}}]})";
  const auto found = faf::online::ReadModPage(modPage);
  ASSERT_TRUE(found) << found.error();
  ASSERT_EQ(found->size(), 1u);
  EXPECT_EQ(found->front().name, "Supreme Economy");
  EXPECT_EQ(found->front().uploader, "uploader1");
  EXPECT_EQ(found->front().uid, "89BF1572-9EA8-11DC-1313-635F56D89591");
  EXPECT_EQ(found->front().type, "UI");
  EXPECT_TRUE(found->front().recommended);
  EXPECT_EQ(found->front().reviews, 40);
  EXPECT_EQ(found->front().downloadUrl, "https://content.example/mods/supreme_economy.v0004.zip");

  EXPECT_FALSE(faf::online::ReadModPage("not json"));
  EXPECT_FALSE(faf::online::ReadReplayPage(R"({"errors":[{"detail":"bad filter"}]})"));
}

// The game starting itself again on another featured mod: its own path and switches, and a start that doesn't wait.
TEST(
  OnlinePlatformProcess,
  StartsAProgramWithoutWaitingAndKnowsItsOwnPath
)
{
  const auto self = platform::process::CurrentProgram();
  ASSERT_TRUE(self) << self.error();
  EXPECT_TRUE(std::filesystem::exists(*self)) << *self;
  EXPECT_NE(std::filesystem::path(*self).filename().string().find("faf_online_tests"), std::string::npos) << *self;
  for (const std::string& argument : platform::process::CurrentArgs()) {
    EXPECT_NE(argument, *self); // the program itself isn't among its arguments
  }

  const std::filesystem::path marker =
    std::filesystem::temp_directory_path() / ("faf-online-start-" + std::to_string(std::rand()) + ".txt");
  std::error_code ignored;
  std::filesystem::remove(marker, ignored);
#if FAFRE_PLATFORM_WINDOWS
  const char* const comspec = std::getenv("ComSpec");
  const std::string shell = comspec != nullptr ? comspec : "C:\\Windows\\System32\\cmd.exe";
  // cmd takes the rest of its line as it is: no quotes around the path (the temp folder has no spaces on the runners).
  const std::vector<std::string> write{"/c", "ping -n 2 127.0.0.1 >nul & echo started>" + marker.string()};
  const std::string missing = "C:\\no\\such\\program.exe";
#else
  const std::string shell = "/bin/sh";
  const std::vector<std::string> write{"-c", "sleep 1; echo started > '" + marker.string() + "'"};
  const std::string missing = "/no/such/program";
#endif
  const auto began = std::chrono::steady_clock::now();
  const auto started = platform::process::Start(shell, write);
  ASSERT_TRUE(started) << started.error();
  // Back before the program's one-second pause is over: it didn't wait.
  EXPECT_LT(std::chrono::steady_clock::now() - began, std::chrono::milliseconds(800));
  bool written = false;
  for (int i = 0; i < 100 && !written; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    written = std::filesystem::exists(marker);
  }
  EXPECT_TRUE(written) << marker.string();
  std::this_thread::sleep_for(std::chrono::milliseconds(200)); // the shell finishes its write
  std::filesystem::remove(marker, ignored);
  EXPECT_FALSE(platform::process::Start(missing, {}));
}

namespace
{
  template <class Done>
  bool WaitUntil(
    Done done,
    std::chrono::milliseconds limit = std::chrono::seconds(10)
  )
  {
    const auto until = std::chrono::steady_clock::now() + limit;
    while (!done() && std::chrono::steady_clock::now() < until) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return done();
  }
} // namespace

TEST(
  OnlineFafLobby,
  SignsInWithTheExactSessionAndKeepsTheGameList
)
{
  const std::string session = "9007199254740993";
  std::atomic<bool> ponged{false};
  EchoServer server(false, [&](const std::string& received) -> std::vector<std::string> {
    const auto message = faf::online::ParseJson(received.substr(0, received.find('\n')));
    if (!message) {
      return {};
    }
    const std::string command = message->String("command");
    if (command == "ask_session") {
      return {R"({"command":"session","session":)" + session + "}\n"};
    }
    if (command == "auth") {
      return {
        R"({"command":"welcome","me":{"id":346886,"login":"Tester"}})"
        "\n",
        R"({"command":"game_info","games":[)"
        R"({"uid":101,"title":"One","featured_mod":"faf","state":"open","num_players":1,"max_players":8,)"
        R"("mapname":"scmp_009","host":"Tester","rating_type":"global","visibility":"public","password_protected":false,)"
        R"("sim_mods":{}},)"
        R"({"uid":102,"title":"Two","featured_mod":"coop","state":"playing","num_players":2,"max_players":4,)"
        R"("mapname":"x","host":"B","rating_type":"global","visibility":"public","password_protected":true,)"
        R"("rating_min":800,"rating_max":null,"sim_mods":{"abc":"Mod A"}}]})"
        "\n",
        // Two messages in one frame: a game closes, and the lobby asks for a pong.
        R"({"command":"game_info","uid":101,"state":"closed"})"
        "\n"
        R"({"command":"ping"})"
        "\n",
        R"({"command":"notice","style":"info","text":"hello"})"
        "\n",
      };
    }
    if (command == "pong") {
      ponged = true;
      return {};
    }
    if (command == "game_host") {
      return {R"({"command":"game_launch","uid":103,"mod":"faf","args":["/numgames",5]})"
              "\n"};
    }
    return {};
  });
  faf::online::FafLobbySettings settings;
  settings.webSocketUrl = server.Url();
  settings.testUniqueId = "test-uid";
  settings.version = "1.2.3";
  faf::online::FafLobby lobby(settings);
  lobby.Connect([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  ASSERT_TRUE(
    WaitUntil([&] {
    return lobby.GetState() == faf::online::FafLobby::State::SignedIn;
  })
  ) << lobby.Message();
  EXPECT_EQ(lobby.Login(), "Tester");
  EXPECT_EQ(lobby.PlayerId(), "346886");
  ASSERT_TRUE(WaitUntil([&] {
    return ponged.load() && lobby.Games().size() == 1u;
  }));
  const auto games = lobby.Games();
  EXPECT_EQ(games[0].uid, "102");
  EXPECT_EQ(games[0].featuredMod, "coop");
  EXPECT_EQ(games[0].state, "playing");
  EXPECT_TRUE(games[0].passwordProtected);
  EXPECT_EQ(games[0].ratingMin, 800.0);
  EXPECT_FALSE(games[0].ratingMax);
  ASSERT_EQ(games[0].simMods.size(), 1u);
  EXPECT_EQ(games[0].simMods[0].second, "Mod A");

  faf::online::FafHostRequest request;
  request.title = "Mine";
  request.mapname = "scmp_009";
  ASSERT_TRUE(lobby.HostGame(request));
  std::vector<faf::online::JsonNode> messages;
  ASSERT_TRUE(WaitUntil([&] {
    for (auto& message : lobby.TakeMessages()) {
      messages.push_back(std::move(message));
    }
    return !messages.empty() && messages.back().String("command") == "game_launch";
  }));
  EXPECT_EQ(messages.front().String("command"), "welcome");
  EXPECT_EQ(messages.back().Get("uid")->text, "103");
  EXPECT_TRUE(lobby.Message().contains("hello")) << lobby.Message();
  lobby.Disconnect();

  const auto received = server.Received();
  ASSERT_GE(received.size(), 4u);
  EXPECT_EQ(received[0], "{\"command\":\"ask_session\",\"version\":\"1.2.3\",\"user_agent\":\"faf-re-client\"}\n");
  EXPECT_EQ(
    received[1], "{\"command\":\"auth\",\"token\":\"ACCESS\",\"unique_id\":\"test-uid\",\"session\":" + session + "}\n"
  );
  EXPECT_EQ(received[2], "{\"command\":\"pong\"}\n");
  EXPECT_EQ(
    received[3],
    "{\"command\":\"game_host\",\"title\":\"Mine\",\"mod\":\"faf\",\"mapname\":\"scmp_009\",\"visibility\":\"public\","
    "\"enforce_rating_range\":false}\n"
  );
}

TEST(
  OnlineFafLobby,
  NeverSendsATestUniqueIdToFafsServers
)
{
  faf::online::FafLobbySettings settings;
  settings.webSocketUrl = "wss://ws.faforever.com/?verify=x";
  settings.testUniqueId = "test-uid";
  faf::online::FafLobby lobby(settings);
  lobby.Connect([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  ASSERT_TRUE(WaitUntil([&] {
    return lobby.GetState() == faf::online::FafLobby::State::Failed;
  }));
  EXPECT_EQ(lobby.Message(), "a test unique_id is never sent to FAF's own servers");
}

// --- platform::http::Stream: a response read as it comes -------------------------------------------------------------

namespace
{
  /** One connection: reads the request head, answers `head`, then each part of `parts` after `pause`, then waits
   *  `hold` before it closes. */
  class PlainHttpServer
  {
  public:
    PlainHttpServer(
      std::string head,
      std::vector<std::string> parts,
      std::chrono::milliseconds pause,
      std::chrono::milliseconds hold
    )
    {
      (void)net::SocketsInit();
      mListener = net::ListenTcp("127.0.0.1", 0);
      mPort = net::LocalPort(mListener);
      mThread = std::thread([this, head = std::move(head), parts = std::move(parts), pause, hold] {
        net::SocketHandle client = ::accept(mListener, nullptr, nullptr);
        net::NoSigPipe(client);
        if (client == net::kInvalidSocket) {
          return;
        }
        std::string request;
        char c = 0;
        while (request.find("\r\n\r\n") == std::string::npos && ::recv(client, &c, 1, 0) == 1) {
          request += c;
        }
        {
          std::lock_guard<std::mutex> guard(mLock);
          mRequestHead = request;
        }
        (void)net::SendAll(client, head.data(), head.size());
        for (const std::string& part : parts) {
          std::this_thread::sleep_for(pause);
          (void)net::SendAll(client, part.data(), part.size());
        }
        std::this_thread::sleep_for(hold);
        net::CloseSocket(client);
      });
    }

    ~PlainHttpServer()
    {
      net::CloseSocket(mListener);
      if (mThread.joinable()) {
        mThread.join();
      }
    }

    [[nodiscard]] std::string Url() const
    {
      return "http://127.0.0.1:" + std::to_string(mPort) + "/api/v1/events";
    }

    [[nodiscard]] std::string RequestHead()
    {
      std::lock_guard<std::mutex> guard(mLock);
      return mRequestHead;
    }

  private:
    std::mutex mLock;
    std::string mRequestHead;
    net::SocketHandle mListener = net::kInvalidSocket;
    unsigned short mPort = 0;
    std::thread mThread;
  };
} // namespace

TEST(
  OnlineHttpStream,
  ReadsAnEventStreamAsItComes
)
{
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    {"event: snapshot\ndata: {}\n\n", ": keep-alive\n\n", "event: lobby\ndata: {\"key\":\"eu-1/l3\"}\n\n"},
    std::chrono::milliseconds(100),
    std::chrono::milliseconds(0)
  );
  platform::http::Stream stream;
  platform::http::Call call;
  call.url = server.Url();
  call.headers = "Accept: text/event-stream\r\nAuthorization: Bearer X\r\n";
  const auto status = stream.Open(call);
  ASSERT_TRUE(status) << status.error();
  EXPECT_EQ(*status, 200);
  std::string all;
  for (;;) {
    const auto part = stream.Read();
    ASSERT_TRUE(part) << part.error();
    if (part->empty()) {
      break;
    }
    all += *part;
  }
  EXPECT_EQ(all, "event: snapshot\ndata: {}\n\n: keep-alive\n\nevent: lobby\ndata: {\"key\":\"eu-1/l3\"}\n\n");
}

TEST(
  OnlineHttpStream,
  CloseEndsABlockedRead
)
{
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    {},
    std::chrono::milliseconds(0),
    std::chrono::milliseconds(3000)
  );
  platform::http::Stream stream;
  platform::http::Call call;
  call.url = server.Url();
  ASSERT_TRUE(stream.Open(call));
  std::atomic<bool> returned{false};
  std::thread reader([&] {
    (void)stream.Read();
    returned = true;
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  EXPECT_FALSE(returned.load());
  const auto closed = std::chrono::steady_clock::now();
  stream.Close();
  reader.join();
  EXPECT_TRUE(returned.load());
  EXPECT_LT(std::chrono::steady_clock::now() - closed, std::chrono::seconds(2));
}

// --- WP3: the control-service client ---------------------------------------------------------------------------------

TEST(
  OnlineControlService,
  FollowsTheLobbiesFromTheEventStream
)
{
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    {
      "event: snapshot\ndata: {\"hosts\":[],\"lobbies\":["
      "{\"key\":\"eu-1/l1\",\"host\":\"eu-1\",\"name\":\"Cup semi\",\"state\":\"lobby\",\"origin\":\"organised\","
      "\"map\":\"scmp_009\",\"seats\":[{\"seat\":1,\"kind\":\"human\",\"name\":\"Ann\",\"uid\":10},"
      "{\"seat\":2,\"kind\":\"human\",\"name\":\"\"}],\"you\":{\"seat\":1,\"join\":\"/connectserver 203.0.113.5:27200 "
      "/servertoken t /serveruid 10\"}},"
      "{\"key\":\"eu-1/l2\",\"host\":\"eu-1\",\"name\":\"Old\",\"state\":\"game\",\"seats\":[]}]}\n\n",
      ": keep-alive\n\n",
      "event: lobby\r\ndata: {\"key\":\"eu-1/l1\",\"host\":\"eu-1\",\"name\":\"Cup "
      "semi\",\"state\":\"game\",\"seats\":[]}\r\n\r\n",
      "event: lobby_removed\ndata: {\"key\":\"eu-1/l2\"}\n\n",
    },
    std::chrono::milliseconds(100),
    std::chrono::milliseconds(2000)
  );
  const std::string base = server.Url().substr(0, server.Url().find("/api/"));
  faf::online::ControlServiceClient client(base, "faf-re-client/test");
  client.SetTokens([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  client.Start();
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  for (;;) {
    const auto lobbies = client.Lobbies();
    if ((lobbies.size() == 1 && lobbies[0].state == "game") || std::chrono::steady_clock::now() > until) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  const auto lobbies = client.Lobbies();
  client.Stop();
  ASSERT_EQ(lobbies.size(), 1u) << client.Message();
  EXPECT_EQ(lobbies[0].key, "eu-1/l1");
  EXPECT_EQ(lobbies[0].state, "game");
  EXPECT_TRUE(server.RequestHead().starts_with("GET /api/v1/events ")) << server.RequestHead();
  EXPECT_TRUE(server.RequestHead().contains("Authorization: Bearer ACCESS"));
}

// A real service keeps the event stream open: the snapshot has to arrive while it stays open, not when it closes.
TEST(
  OnlineControlService,
  SeesTheSnapshotWhileTheStreamStaysOpen
)
{
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    {
      "event: snapshot\ndata: {\"hosts\":[],\"lobbies\":[{\"key\":\"eu-1/l1\",\"host\":\"eu-1\",\"name\":\"Open\","
      "\"state\":\"lobby\",\"seats\":[]}]}\n\n",
    },
    std::chrono::milliseconds(10),
    std::chrono::milliseconds(4000)
  );
  const std::string base = server.Url().substr(0, server.Url().find("/api/"));
  faf::online::ControlServiceClient client(base, "faf-re-client/test");
  client.SetTokens([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  client.Start();
  const auto start = std::chrono::steady_clock::now();
  while (client.Lobbies().empty() && std::chrono::steady_clock::now() - start < std::chrono::milliseconds(1500)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  const auto lobbies = client.Lobbies();
  client.Stop();
  ASSERT_EQ(lobbies.size(), 1u) << "no snapshot within 1.5 s while the stream stayed open: " << client.Message();
  EXPECT_EQ(lobbies[0].key, "eu-1/l1");
}

TEST(
  OnlineControlService,
  ReadsALobbysSeatsAndTheViewersJoinLine
)
{
  const auto parsed = faf::online::ParseJson(
    R"({"key":"eu-1/l1","state":"lobby","seats":[{"seat":1,"kind":"human","name":"Ann","uid":10},)"
    R"({"seat":2,"kind":"ai","ai":"rush"}],"you":{"seat":1,"join":"/connectserver a:1 /servertoken t /serveruid 10"}})"
  );
  ASSERT_TRUE(parsed);
  const auto lobby = faf::online::ReadServerLobby(*parsed);
  ASSERT_EQ(lobby.seats.size(), 2u);
  EXPECT_EQ(lobby.seats[0].uid, "10");
  EXPECT_EQ(lobby.seats[1].ai, "rush");
  EXPECT_TRUE(lobby.seats[1].uid.empty());
  EXPECT_EQ(lobby.join, "/connectserver a:1 /servertoken t /serveruid 10");
}

TEST(
  OnlineControlService,
  AsksForAGameThePlayerHosts
)
{
  const std::string answer =
    "{\"ok\":true,\"request\":{\"id\":\"r1\",\"state\":\"queued\",\"position\":1},\"ref\":\"eu-1/r1\"}";
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(answer.size()) +
      "\r\nConnection: close\r\n\r\n" + answer,
    {},
    std::chrono::milliseconds(0),
    std::chrono::milliseconds(0)
  );
  const std::string base = server.Url().substr(0, server.Url().find("/api/"));
  faf::online::ControlServiceClient client(base, "faf-re-client/test");
  client.SetTokens([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  faf::online::ServerGameRequest request;
  request.map = "scmp_007";
  request.otherSeats = {"human", "rush"};
  request.options = {{"UnitCap", "500"}};
  request.byPing = true;
  const auto result = client.RequestGame(request);
  ASSERT_TRUE(result) << result.error();
  EXPECT_EQ(result->String("ref"), "eu-1/r1");
  EXPECT_TRUE(server.RequestHead().starts_with("POST /api/v1/requests ")) << server.RequestHead();
  EXPECT_TRUE(server.RequestHead().contains("Content-Type: application/json"));
}

// --- WP4: the launcher's GPGNet side of a match ----------------------------------------------------------------------

namespace
{
  /** A fake game: connects to the link's port and speaks GPGNet. */
  class FakeGame
  {
  public:
    explicit FakeGame(
      std::uint16_t port
    )
    {
      mSocket = ConnectLocal(port, 5000);
      connected = mSocket != net::kInvalidSocket;
    }

    ~FakeGame()
    {
      net::CloseSocket(mSocket);
    }

    void Send(
      const faf::netbridge::GpgMessage& message
    )
    {
      const std::string bytes = faf::netbridge::EncodeGpg(message);
      (void)net::SendAll(mSocket, bytes.data(), bytes.size());
    }

    /** The next message from the link; an empty command after 5 s without one. */
    faf::netbridge::GpgMessage Next()
    {
      for (;;) {
        bool bad = false;
        if (auto message = mDecoder.Next(&bad)) {
          return *message;
        }
        char buffer[4096];
        const int got = ::recv(mSocket, buffer, sizeof(buffer), 0);
        if (got <= 0 || bad) {
          return {};
        }
        mDecoder.Feed(buffer, static_cast<std::size_t>(got));
      }
    }

    bool connected = false;

  private:
    net::SocketHandle mSocket = net::kInvalidSocket;
    faf::netbridge::GpgDecoder mDecoder;
  };
} // namespace

TEST(
  OnlineGameLink,
  CreatesTheLobbyOnIdleAndHoldsLobbyMessagesUntilTheGameIsInItsLobby
)
{
  using faf::netbridge::GpgArg;
  faf::online::GameLink link;
  const auto port = link.Listen();
  ASSERT_TRUE(port) << port.error();
  std::mutex lock;
  std::vector<std::string> toLobby;
  faf::online::GameLinkSettings settings;
  settings.login = "Tester";
  settings.playerId = 346886;
  settings.iceServersJson = R"({"id":"s1","forceRelay":false,"servers":[]})";
  link.Start(settings, [&](const faf::online::JsonNode& message) {
    std::lock_guard<std::mutex> guard(lock);
    toLobby.push_back(faf::online::ToJson(message));
  });
  // The lobby's HostGame before the game is in its lobby: held.
  link.FromLobby(*faf::online::ParseJson(R"({"command":"HostGame","target":"game","args":["scmp_009"]})"));

  FakeGame game(*port);
  ASSERT_TRUE(game.connected);
  game.Send({"GameState", {GpgArg::Str("Idle")}});
  const auto ice = game.Next();
  EXPECT_EQ(ice.command, "IceServers");
  ASSERT_EQ(ice.args.size(), 1u);
  EXPECT_EQ(ice.args[0].text, settings.iceServersJson);
  const auto create = game.Next();
  EXPECT_EQ(create.command, "CreateLobby");
  ASSERT_EQ(create.args.size(), 5u);
  EXPECT_EQ(create.args[0].number, 0);
  EXPECT_EQ(create.args[2].text, "Tester");
  EXPECT_EQ(create.args[3].number, 346886);
  EXPECT_EQ(create.args[4].number, 1);

  game.Send({"GameState", {GpgArg::Str("Lobby")}});
  const auto host = game.Next();
  EXPECT_EQ(host.command, "HostGame");
  ASSERT_EQ(host.args.size(), 1u);
  EXPECT_EQ(host.args[0].text, "scmp_009");

  // In the lobby: sent at once, the lobby's numbers as GPGNet ints.
  link.FromLobby(*faf::online::ParseJson(R"({"command":"ConnectToPeer","target":"game","args":["Bo",42,1]})"));
  const auto peer = game.Next();
  EXPECT_EQ(peer.command, "ConnectToPeer");
  ASSERT_EQ(peer.args.size(), 3u);
  EXPECT_EQ(peer.args[1].kind, GpgArg::Kind::Int);
  EXPECT_EQ(peer.args[1].number, 42);

  game.Send({"GameOption", {GpgArg::Str("Title"), GpgArg::Str("a/tb")}});
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;) {
    {
      std::lock_guard<std::mutex> guard(lock);
      if (toLobby.size() >= 3u || std::chrono::steady_clock::now() > until) {
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  link.Stop();
  std::lock_guard<std::mutex> guard(lock);
  ASSERT_EQ(toLobby.size(), 3u);
  EXPECT_EQ(toLobby[0], R"({"command":"GameState","target":"game","args":["Idle"]})");
  EXPECT_EQ(toLobby[1], R"({"command":"GameState","target":"game","args":["Lobby"]})");
  EXPECT_EQ(toLobby[2], R"({"command":"GameOption","target":"game","args":["Title","a\tb"]})");
}

TEST(
  OnlineFafLobby,
  MessagesForTheGameGoToTheGameHandler
)
{
  EchoServer server(false, [](const std::string& received) -> std::vector<std::string> {
    const auto message = faf::online::ParseJson(received.substr(0, received.find('\n')));
    if (!message) {
      return {};
    }
    if (message->String("command") == "ask_session") {
      return {"{\"command\":\"session\",\"session\":1}\n"};
    }
    if (message->String("command") == "auth") {
      return {"{\"command\":\"welcome\",\"me\":{\"id\":2,\"login\":\"Dostya\"}}\n"
              "{\"command\":\"HostGame\",\"target\":\"game\",\"args\":[\"scmp_009\"]}\n"};
    }
    return {};
  });
  faf::online::FafLobbySettings settings;
  settings.webSocketUrl = server.Url();
  settings.testUniqueId = "test-uid";
  faf::online::FafLobby lobby(settings);
  std::mutex lock;
  std::vector<std::string> forGame;
  lobby.SetGameHandler([&](const faf::online::JsonNode& message) {
    std::lock_guard<std::mutex> guard(lock);
    forGame.push_back(message.String("command"));
  });
  lobby.Connect([] {
    return std::expected<std::string, std::string>("ACCESS");
  });
  ASSERT_TRUE(WaitUntil([&] {
    std::lock_guard<std::mutex> guard(lock);
    return !forGame.empty();
  }));
  lobby.Disconnect();
  EXPECT_EQ(forGame.front(), "HostGame");
  for (const auto& message : lobby.TakeMessages()) {
    EXPECT_NE(message.String("command"), "HostGame");
  }
}

// --- WP4: a FAF match's switches
// ---------------------------------------------------------------------------------------

TEST(
  OnlineLaunchArgs,
  ACustomGameGetsTheServersArgsThePlayersAndTheLaunchersOwn
)
{
  using namespace faf::online;
  const auto launchMessage = ParseJson(
    R"({"command":"game_launch","args":["/numgames",12],"uid":51,"mod":"faf","name":"x","init_mode":0,)"
    R"("game_type":"custom","rating_type":"global"})"
  );
  const auto me = ParseJson(
    R"({"id":346886,"login":"Draiget","country":"RU","clan":"BC","ratings":{)"
    R"("global":{"rating":[1523.4,85.6],"number_of_games":321},"ladder_1v1":{"rating":[1400,90],"number_of_games":50}}})"
  );
  ASSERT_TRUE(launchMessage && me);
  const GameLaunch launch = ReadGameLaunch(*launchMessage);
  EXPECT_EQ(launch.uid, "51");
  const LaunchPlayer player = ReadLaunchPlayer(*me);
  EXPECT_EQ(player.id, "346886");
  ASSERT_EQ(player.ratings.size(), 2u);
  LaunchLocal local;
  local.gpgnetPort = 52114;
  local.replayPort = 52115;
  local.logFile = "C:\\logs\\game_51.log";
  local.forceRelay = true;
  const std::vector<std::string> expected{
    "/numgames",
    "12",
    "/mean",
    "1523",
    "/deviation",
    "86",
    "/country",
    "RU",
    "/clan",
    "BC",
    "/init",
    "init_faf.lua",
    "/nobugreport",
    "/savereplay",
    "gpgnet://127.0.0.1:52115/51/Draiget.SCFAreplay",
    "/gpgnet",
    "127.0.0.1:52114",
    "/log",
    "C:\\logs\\game_51.log",
    "/nativenet",
    "/nativenetrelay",
  };
  EXPECT_EQ(BuildLaunchArgs(launch, &player, local), expected);
}

TEST(
  OnlineLaunchArgs,
  TheRatingPairIsNeverLeftOut
)
{
  using namespace faf::online;
  GameLaunch launch;
  launch.uid = "7";
  launch.ratingType = "tmm_2v2";
  LaunchLocal local;
  local.gpgnetPort = 1;
  local.nativeNet = false;
  // No player record: the TrueSkill starting pair.
  auto args = BuildLaunchArgs(launch, nullptr, local);
  ASSERT_GE(args.size(), 4u);
  EXPECT_EQ(
    std::vector<std::string>(args.begin(), args.begin() + 4),
    (std::vector<std::string>{"/mean", "1500", "/deviation", "500"})
  );
  // A rating type the player has no rating in: their global one.
  LaunchPlayer player;
  player.login = "Bo";
  player.ratings["global"] = {1200.0, 150.0, 10};
  args = BuildLaunchArgs(launch, &player, local);
  EXPECT_EQ(
    std::vector<std::string>(args.begin(), args.begin() + 4),
    (std::vector<std::string>{"/mean", "1200", "/deviation", "150"})
  );
}

TEST(
  OnlineLaunchArgs,
  AMatchmakerGameGetsItsFactionTeamSpotAndOptions
)
{
  using namespace faf::online;
  const auto launchMessage = ParseJson(
    R"({"command":"game_launch","args":["/numgames",3],"uid":900,"mod":"faf","game_type":"matchmaker",)"
    R"("rating_type":"ladder_1v1","faction":3,"team":2,"expected_players":2,"map_position":1,)"
    R"("game_options":{"Share":"ShareUntilDeath"}})"
  );
  ASSERT_TRUE(launchMessage);
  const GameLaunch launch = ReadGameLaunch(*launchMessage);
  LaunchPlayer player;
  player.login = "Ann";
  player.ratings["ladder_1v1"] = {1650.0, 70.0, 40};
  LaunchLocal local;
  local.gpgnetPort = 2;
  local.nativeNet = false;
  const std::vector<std::string> expected{
    "/numgames",
    "3",
    "/mean",
    "1650",
    "/deviation",
    "70",
    "/cybran",
    "/team",
    "2",
    "/players",
    "2",
    "/startspot",
    "1",
    "/gameoptions",
    "Share:ShareUntilDeath",
    "/init",
    "init_faf.lua",
    "/nobugreport",
    "/gpgnet",
    "127.0.0.1:2",
  };
  EXPECT_EQ(BuildLaunchArgs(launch, &player, local), expected);
}

// --- WP4: the live replay relay
// ----------------------------------------------------------------------------------------

TEST(
  OnlineReplayRelay,
  PassesTheGamesStreamOnWithItsOpening
)
{
  EchoServer server(false, [](const std::string&) {
    return std::vector<std::string>{};
  });
  faf::online::ReplayRelaySettings settings;
  settings.webSocketUrl = server.Url();
  faf::online::ReplayRelay relay(settings);
  const auto port = relay.Listen();
  ASSERT_TRUE(port) << port.error();
  relay.Start({});

  // A fake game: the posting opening, then 100 KB of replay, then the end of the stream.
  std::string stream = std::string("P/51/Tester") + '\0';
  for (int i = 0; i < 100000; ++i) {
    stream += static_cast<char>((i * 7) & 0xFF);
  }
  {
    net::SocketHandle game = ConnectLocal(*port);
    ASSERT_NE(game, net::kInvalidSocket);
    for (std::size_t at = 0; at < stream.size(); at += 7000) {
      const std::size_t size = std::min<std::size_t>(7000, stream.size() - at);
      (void)net::SendAll(game, stream.data() + at, size);
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    net::CloseSocket(game);
  }
  EXPECT_TRUE(relay.Finish(std::chrono::seconds(20)));
  EXPECT_EQ(relay.BytesFromGame(), stream.size());
  EXPECT_EQ(relay.BytesSent(), stream.size());
  ASSERT_TRUE(WaitUntil([&] {
    return server.ReceivedBinary().size() >= stream.size();
  }));
  EXPECT_EQ(server.ReceivedBinary(), stream); // the opening kept, every byte in order
}

namespace
{
  /** Answers every request with 401 and counts them (a user service that refuses the replay service's address). */
  class RefusingHttpServer
  {
  public:
    RefusingHttpServer()
    {
      (void)net::SocketsInit();
      mListener = net::ListenTcp("127.0.0.1", 0);
      mPort = net::LocalPort(mListener);
      mThread = std::thread([this] {
        while (!mStop.load()) {
          const int ready = net::WaitReadable(mListener, 100);
          if (ready <= 0) {
            continue;
          }
          net::SocketHandle client = ::accept(mListener, nullptr, nullptr);
          net::NoSigPipe(client);
          if (client == net::kInvalidSocket) {
            continue;
          }
          std::string request;
          char c = 0;
          while (request.find("\r\n\r\n") == std::string::npos && ::recv(client, &c, 1, 0) == 1) {
            request += c;
          }
          const std::string answer = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
          (void)net::SendAll(client, answer.data(), answer.size());
          net::CloseSocket(client);
          ++mRequests;
        }
      });
    }

    ~RefusingHttpServer()
    {
      mStop = true;
      if (mThread.joinable()) {
        mThread.join();
      }
      net::CloseSocket(mListener);
    }

    [[nodiscard]] std::string Url() const
    {
      return "http://127.0.0.1:" + std::to_string(mPort);
    }

    [[nodiscard]] int Requests() const
    {
      return mRequests.load();
    }

  private:
    net::SocketHandle mListener = net::kInvalidSocket;
    unsigned short mPort = 0;
    std::atomic<bool> mStop{false};
    std::atomic<int> mRequests{0};
    std::thread mThread;
  };
} // namespace

TEST(
  OnlineReplayRelay,
  ARefusedAddressIsAskedAgainOnlyAfterAPause
)
{
  RefusingHttpServer userService;
  faf::online::ReplayRelaySettings settings;
  settings.userServiceUrl = userService.Url();
  faf::online::ReplayRelay relay(settings);
  std::mutex lock;
  std::vector<std::string> lines;
  relay.SetLog([&](const char* line) {
    std::lock_guard<std::mutex> guard(lock);
    lines.emplace_back(line);
  });
  const auto port = relay.Listen();
  ASSERT_TRUE(port) << port.error();
  relay.Start([] {
    return std::expected<std::string, std::string>("token");
  });

  // A game writes its replay many times a second: 30 writes, well inside the relay's 2 s pause.
  net::SocketHandle game = ConnectLocal(*port);
  ASSERT_NE(game, net::kInvalidSocket);
  const std::string piece(1000, 'r');
  for (int i = 0; i < 30; ++i) {
    (void)net::SendAll(game, piece.data(), piece.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  EXPECT_TRUE(WaitUntil([&] {
    return relay.BytesFromGame() == 30u * piece.size();
  }));
  // The first write asked and was refused; the rest came within the 2 s pause and didn't ask.
  EXPECT_EQ(userService.Requests(), 1);
  net::CloseSocket(game);
  relay.Stop();
  std::lock_guard<std::mutex> guard(lock);
  const auto refused = std::count_if(lines.begin(), lines.end(), [](const std::string& line) {
    return line.find("answered 401") != std::string::npos;
  });
  EXPECT_EQ(refused, 1);
}

// --- platform::http: answers a server can get wrong ---------------------------------------------------------------

TEST(
  OnlineHttp,
  ReadsAChunkedAnswer
)
{
  PlainHttpServer server(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    {"5\r\nhello\r\n", "7;name=value\r\n, world\r\n", "0\r\n\r\n"},
    std::chrono::milliseconds(20),
    std::chrono::milliseconds(0)
  );
  platform::http::Call call;
  call.url = server.Url();
  long status = 0;
  std::string body;
  const auto sent = platform::http::Request(call, status, body);
  ASSERT_TRUE(sent) << sent.error();
  EXPECT_EQ(status, 200);
  EXPECT_EQ(body, "hello, world");
}

// --- FAF's chat: IRC over a WebSocket -----------------------------------------------------------------------------

TEST(
  FafChat,
  ParsesTagsSenderCommandAndTrailing
)
{
  using faf::online::FafChat;
  const FafChat::IrcMessage message =
    FafChat::Parse("@time=2026-11-27T10:00:00.000Z;label=a\\sb :Other!user@host privmsg #aeolus :hello : world\r");
  EXPECT_EQ(message.tags.at("time"), "2026-11-27T10:00:00.000Z");
  EXPECT_EQ(message.tags.at("label"), "a b");
  EXPECT_EQ(message.nick, "Other");
  EXPECT_EQ(message.command, "PRIVMSG");
  ASSERT_EQ(message.params.size(), 2u);
  EXPECT_EQ(message.params[0], "#aeolus");
  EXPECT_EQ(message.params[1], "hello : world");
  const FafChat::IrcMessage ping = FafChat::Parse("PING :keepalive");
  EXPECT_EQ(ping.command, "PING");
  ASSERT_EQ(ping.params.size(), 1u);
  EXPECT_EQ(ping.params[0], "keepalive");
}

TEST(
  FafChat,
  SignsInWithSaslJoinsReadsHistoryAndSays
)
{
  using namespace faf::online;
  EchoServer server(false, [](const std::string& received) -> std::vector<std::string> {
    if (received == "CAP LS 302") {
      return {":srv CAP * LS :sasl=PLAIN server-time message-tags draft/chathistory batch"};
    }
    if (received.rfind("CAP REQ", 0) == 0) {
      return {":srv CAP * ACK :sasl server-time message-tags draft/chathistory batch"};
    }
    if (received == "AUTHENTICATE PLAIN") {
      return {"AUTHENTICATE +"};
    }
    if (received.rfind("AUTHENTICATE ", 0) == 0) {
      return {":srv 903 Tester :SASL authentication successful"};
    }
    if (received.rfind("USER ", 0) == 0) {
      return {":srv 001 Tester :Welcome to FAF's chat"};
    }
    if (received == "JOIN #aeolus") {
      return {
        ":Tester!u@h JOIN #aeolus",
        ":srv 353 Tester = #aeolus :Tester @Mod Other",
        ":srv 332 Tester #aeolus :Welcome to FAF"
      };
    }
    if (received.rfind("CHATHISTORY LATEST #aeolus", 0) == 0) {
      return {
        ":srv BATCH +b1 chathistory #aeolus",
        "@batch=b1;time=2026-11-27T10:00:00.000Z :Other!u@h PRIVMSG #aeolus :hello there",
        "@batch=b1;time=2026-11-27T10:01:00.000Z :Mod!u@h PRIVMSG #aeolus :\x01"
        "ACTION waves\x01",
        ":srv BATCH -b1"
      };
    }
    if (received.rfind("PRIVMSG #aeolus :", 0) == 0) {
      return {"@time=2026-11-27T10:02:00.000Z :Other!u@h PRIVMSG #aeolus :welcome back", "PING :keepalive"};
    }
    if (received == "PRIVMSG Other :psst") {
      return {
        ":Other!u@h PRIVMSG Tester :hi back", ":NickServ!s@services.faforever.com NOTICE Tester :you are identified"
      };
    }
    return {};
  }, {}, true);
  FafChatSettings settings;
  settings.webSocketUrl = server.Url();
  FafChat chat(settings);
  chat.Connect([] {
    return std::expected<std::string, std::string>("chat-token");
  }, "Tester");

  const auto waitFor = [&](const std::function<bool()>& done) {
    for (int i = 0; i < 300 && !done(); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return done();
  };
  std::size_t total = 0;
  ASSERT_TRUE(
    waitFor([&] {
    (void)chat.Lines("#aeolus", 0, total);
    return chat.GetState() == FafChat::State::Joined && total >= 2;
  })
  ) << chat.Message();
  auto lines = chat.Lines("#aeolus", 0, total);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0].from, "Other");
  EXPECT_EQ(lines[0].text, "hello there");
  EXPECT_EQ(lines[0].time, "2026-11-27T10:00:00.000Z");
  EXPECT_TRUE(lines[0].history);
  EXPECT_EQ(lines[1].from, "Mod");
  EXPECT_EQ(lines[1].text, "waves");
  EXPECT_TRUE(lines[1].action);
  EXPECT_EQ(chat.Channels(), std::vector<std::string>{"#aeolus"});
  EXPECT_EQ(chat.Topic("#aeolus"), "Welcome to FAF");
  const auto users = chat.Users("#aeolus");
  EXPECT_NE(std::find(users.begin(), users.end(), "@Mod"), users.end());
  EXPECT_NE(std::find(users.begin(), users.end(), "Other"), users.end());

  ASSERT_TRUE(chat.Say("#aeolus", "hi all"));
  ASSERT_TRUE(waitFor([&] {
    (void)chat.Lines("#aeolus", 0, total);
    return total >= 4;
  }));
  lines = chat.Lines("#aeolus", 2, total);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0].text, "hi all");
  EXPECT_TRUE(lines[0].self);
  EXPECT_EQ(lines[1].text, "welcome back");
  EXPECT_FALSE(lines[1].history);
  EXPECT_TRUE(waitFor([&] {
    const auto received = server.Received();
    return std::find(received.begin(), received.end(), "PONG :keepalive") != received.end();
  }));

  // A private message: a conversation named after the other player, both sides in it; the services' notice opens none.
  ASSERT_TRUE(chat.Say("Other", "psst"));
  ASSERT_TRUE(waitFor([&] {
    (void)chat.Lines("Other", 0, total);
    return total >= 2;
  }));
  lines = chat.Lines("Other", 0, total);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0].text, "psst");
  EXPECT_TRUE(lines[0].self);
  EXPECT_EQ(lines[1].from, "Other");
  EXPECT_EQ(lines[1].text, "hi back");
  EXPECT_EQ(chat.Channels(), (std::vector<std::string>{"#aeolus", "Other"}));
  // Closing it sends nothing: there is nothing to leave on the server.
  ASSERT_TRUE(chat.Part("Other"));
  EXPECT_EQ(chat.Channels(), std::vector<std::string>{"#aeolus"});
  const auto afterPart = server.Received();
  EXPECT_EQ(std::find(afterPart.begin(), afterPart.end(), "PART Other"), afterPart.end());

  // SASL PLAIN as FAF's clients send it: nick, nick, "token:" and the chat's token.
  const auto received = server.Received();
  EXPECT_NE(
    std::find(received.begin(), received.end(), "AUTHENTICATE VGVzdGVyAFRlc3RlcgB0b2tlbjpjaGF0LXRva2Vu"), received.end()
  );
  EXPECT_NE(server.requestHead.find("Sec-WebSocket-Protocol: binary.ircv3.net"), std::string::npos);
  chat.Disconnect();
}

#if FAFRE_PLATFORM_POSIX // our own HTTP/1.1 and WebSocket code; on Windows WinHTTP reads these

TEST(
  OnlineHttp,
  RefusesABrokenChunkSize
)
{
  // An empty size line used to read as the last chunk, a sign as a size near 2^64: both handed back a body as whole.
  for (const char* size : {"\r\n", "zz\r\n", "-5\r\n", "fffffffffffffffffff\r\n", "5 junk\r\n"}) {
    PlainHttpServer server(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
      {std::string("3\r\nabc\r\n") + size + "hello\r\n0\r\n\r\n"},
      std::chrono::milliseconds(0),
      std::chrono::milliseconds(0)
    );
    platform::http::Call call;
    call.url = server.Url();
    long status = 0;
    std::string body;
    const auto sent = platform::http::Request(call, status, body);
    EXPECT_FALSE(sent) << "size line '" << size << "' gave body '" << body << "'";
  }
}

TEST(
  OnlineHttp,
  ReachesAnIpv6AddressWithAPort
)
{
  const int listener = ::socket(AF_INET6, SOCK_STREAM, 0);
  sockaddr_in6 address{};
  address.sin6_family = AF_INET6;
  address.sin6_addr = in6addr_loopback;
  if (
    listener < 0 || ::bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
    ::listen(listener, 1) != 0
  ) {
    if (listener >= 0) {
      ::close(listener);
    }
    GTEST_SKIP() << "no IPv6 loopback here";
  }
  socklen_t length = sizeof(address);
  (void)::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length);
  const int port = ntohs(address.sin6_port);
  std::string requestHead;
  std::thread serve([listener, &requestHead] {
    const int client = ::accept(listener, nullptr, nullptr);
    if (client < 0) {
      return;
    }
    char c = 0;
    while (requestHead.find("\r\n\r\n") == std::string::npos && ::recv(client, &c, 1, 0) == 1) {
      requestHead += c;
    }
    const std::string answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    (void)::send(client, answer.data(), answer.size(), 0);
    ::close(client);
  });
  platform::http::Call call;
  call.url = "http://[::1]:" + std::to_string(port) + "/x";
  long status = 0;
  std::string body;
  const auto sent = platform::http::Request(call, status, body);
  ::shutdown(listener, SHUT_RDWR);
  serve.join();
  ::close(listener);
  ASSERT_TRUE(sent) << sent.error();
  EXPECT_EQ(body, "ok");
  EXPECT_TRUE(requestHead.contains("Host: [::1]:" + std::to_string(port) + "\r\n")) << requestHead;
}

TEST(
  OnlineHttpStream,
  CloseEndsAConnectThatGetsNoAnswer
)
{
  // An address in a range that drops packets: connect() waited for the system's timeout (about 2 minutes on Linux),
  // and Close from another thread couldn't end it. An unreachable network that refuses at once passes too.
  platform::http::Stream stream;
  platform::http::Call call;
  call.url = "http://192.0.2.1:81/api/v1/events";
  const auto started = std::chrono::steady_clock::now();
  std::thread opener([&stream, &call] {
    (void)stream.Open(call);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  stream.Close();
  opener.join();
  EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(3));
}

TEST(
  OnlineWebSocket,
  CloseEndsAConnectThatGetsNoAnswer
)
{
  // The lobby's Disconnect during its WebSocket's connect: the socket wasn't known to Close until it had opened.
  platform::http::WebSocket socket;
  const auto started = std::chrono::steady_clock::now();
  std::expected<void, std::string> opened;
  std::thread opener([&] {
    opened = socket.Open("ws://192.0.2.1:81/lobby", "", "faf-re-client/test");
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  socket.Close();
  opener.join();
  EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(3));
  EXPECT_FALSE(opened);
  EXPECT_FALSE(socket.IsOpen());
}

TEST(
  OnlineWebSocket,
  RefusesAFrameLongerThanAMessageMayBe
)
{
  // A final text frame with a 64-bit length of 2^64 - 10: the sum of header and length wrapped to 0, and Receive
  // handed back the same empty message forever without reading again.
  const std::string wrapping("\x81\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF6", 10);
  // 1 GB, under 2^63: the buffer grew toward it until memory ran out.
  const std::string huge("\x81\x7F\x00\x00\x00\x00\x40\x00\x00\x00", 10);
  for (const std::string& frame : {wrapping, huge}) {
    EchoServer server(false, {}, frame);
    platform::http::WebSocket socket;
    const auto opened = socket.Open(server.Url(), "", "faf-re-client/test");
    ASSERT_TRUE(opened) << opened.error();
    std::string message;
    const auto received = socket.Receive(message);
    EXPECT_FALSE(received);
    socket.Close();
  }
}

#endif
