// faf_online (src/online, .plans/ingame-launcher WP1): JSON, URL encoding, the sealed token store, a WebSocket on
// 127.0.0.1, and FAF's sign-in against canned answers. No test reaches the network.

#include <gtest/gtest.h>

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

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include "online/ControlService.h"
#include "online/FafAuth.h"
#include "online/FafLobby.h"
#include "online/GameLink.h"
#include "online/Json.h"
#include "online/Url.h"
#include "platform/Http.h"
#include "platform/Process.h"
#include "platform/SecretStore.h"

namespace
{
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
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    (void)::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    (void)::BCryptHash(
      algorithm,
      nullptr,
      0,
      reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
      static_cast<ULONG>(input.size()),
      digest,
      sizeof(digest)
    );
    (void)::BCryptCloseAlgorithmProvider(algorithm, 0);
    return Base64(digest, sizeof(digest));
  }

  bool ReadExactly(
    SOCKET socket,
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
      Reply reply = {}
    )
      : mRefuse(refuse)
      , mReply(std::move(reply))
    {
      WSADATA data{};
      (void)::WSAStartup(MAKEWORD(2, 2), &data);
      mListener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      (void)::bind(mListener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
      int length = sizeof(address);
      (void)::getsockname(mListener, reinterpret_cast<sockaddr*>(&address), &length);
      mPort = ntohs(address.sin_port);
      (void)::listen(mListener, 1);
      mThread = std::thread([this] {
        Serve();
      });
    }

    ~EchoServer()
    {
      ::closesocket(mListener);
      if (mThread.joinable()) {
        mThread.join();
      }
      ::WSACleanup();
    }

    [[nodiscard]] std::string Url() const
    {
      return "ws://127.0.0.1:" + std::to_string(mPort) + "/lobby?verify=x";
    }

    std::string requestHead;

  private:
    void Serve()
    {
      const SOCKET client = ::accept(mListener, nullptr, nullptr);
      if (client == INVALID_SOCKET) {
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
        (void)::send(client, answer.data(), static_cast<int>(answer.size()), 0);
        ::closesocket(client);
        return;
      }
      std::string key;
      for (std::size_t at = 0; at < head.size();) {
        const std::size_t end = head.find("\r\n", at);
        const std::string line = head.substr(at, end - at);
        if (_strnicmp(line.c_str(), "Sec-WebSocket-Key:", 18) == 0) {
          key = line.substr(18);
          key.erase(0, key.find_first_not_of(' '));
        }
        at = end == std::string::npos ? head.size() : end + 2;
      }
      const std::string answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                 "Sec-WebSocket-Accept: " +
        AcceptKey(key) + "\r\n\r\n";
      (void)::send(client, answer.data(), static_cast<int>(answer.size()), 0);
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
      ::closesocket(client);
    }

    static void SendFrame(
      SOCKET client,
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
      (void)::send(client, frame.data(), static_cast<int>(frame.size()), 0);
    }

  public:
    [[nodiscard]] std::vector<std::string> Received()
    {
      std::lock_guard<std::mutex> guard(mLock);
      return mReceived;
    }

  private:
    bool mRefuse = false;
    Reply mReply;
    std::mutex mLock;
    std::vector<std::string> mReceived;
    SOCKET mListener = INVALID_SOCKET;
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
        if (refuseRefresh) {
          status = 400;
          body = R"({"error":"invalid_grant"})";
        } else {
          status = 200;
          body =
            R"({"access_token":")" + refreshAnswerToken + R"(","refresh_token":")" + refreshAnswerRefresh + R"("})";
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
      std::filesystem::temp_directory_path() / ("faf_online_" + std::to_string(::GetCurrentProcessId()) + "_" + name);
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
  EXPECT_FALSE(sealed->contains("refresh-token-value"));
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
  EXPECT_FALSE(sealed.contains("R1"));

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
  const char* const comspec = std::getenv("ComSpec");
  const std::string cmd = comspec != nullptr ? comspec : "C:\\Windows\\System32\\cmd.exe";
  const auto echoed = platform::process::Run(cmd, {"/c", "echo", "hello"}, std::chrono::seconds(20));
  ASSERT_TRUE(echoed) << echoed.error();
  EXPECT_EQ(echoed->exitCode, 0);
  EXPECT_TRUE(echoed->out.starts_with("hello")) << echoed->out;
  const auto failed = platform::process::Run(cmd, {"/c", "exit", "7"}, std::chrono::seconds(20));
  ASSERT_TRUE(failed) << failed.error();
  EXPECT_EQ(failed->exitCode, 7);
  // A timeout ends the program and what it started (ping, under cmd), so it returns soon after it.
  const auto started = std::chrono::steady_clock::now();
  EXPECT_FALSE(platform::process::Run(cmd, {"/c", "ping", "-n", "6", "127.0.0.1"}, std::chrono::milliseconds(500)));
  EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(3));
  EXPECT_FALSE(platform::process::Run("C:\\no\\such\\program.exe", {}, std::chrono::seconds(5)));
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
      WSADATA data{};
      (void)::WSAStartup(MAKEWORD(2, 2), &data);
      mListener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      (void)::bind(mListener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
      int length = sizeof(address);
      (void)::getsockname(mListener, reinterpret_cast<sockaddr*>(&address), &length);
      mPort = ntohs(address.sin_port);
      (void)::listen(mListener, 1);
      mThread = std::thread([this, head = std::move(head), parts = std::move(parts), pause, hold] {
        const SOCKET client = ::accept(mListener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
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
        (void)::send(client, head.data(), static_cast<int>(head.size()), 0);
        for (const std::string& part : parts) {
          std::this_thread::sleep_for(pause);
          (void)::send(client, part.data(), static_cast<int>(part.size()), 0);
        }
        std::this_thread::sleep_for(hold);
        ::closesocket(client);
      });
    }

    ~PlainHttpServer()
    {
      ::closesocket(mListener);
      if (mThread.joinable()) {
        mThread.join();
      }
      ::WSACleanup();
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
    SOCKET mListener = INVALID_SOCKET;
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
      WSADATA data{};
      (void)::WSAStartup(MAKEWORD(2, 2), &data);
      mSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      DWORD timeout = 5000;
      (void)::setsockopt(mSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      address.sin_port = htons(port);
      connected = ::connect(mSocket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    }

    ~FakeGame()
    {
      ::closesocket(mSocket);
      ::WSACleanup();
    }

    void Send(
      const faf::netbridge::GpgMessage& message
    )
    {
      const std::string bytes = faf::netbridge::EncodeGpg(message);
      (void)::send(mSocket, bytes.data(), static_cast<int>(bytes.size()), 0);
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
    SOCKET mSocket = INVALID_SOCKET;
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
