// faf_online (src/online, .plans/ingame-launcher WP1): JSON, URL encoding, the sealed token store, a WebSocket on
// 127.0.0.1, and FAF's sign-in against canned answers. No test reaches the network.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
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

#include "online/FafAuth.h"
#include "online/Json.h"
#include "online/Url.h"
#include "platform/Http.h"
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

  /** Accepts one client; `refuse` answers the upgrade with 403, else it echoes every message until a close. */
  class EchoServer
  {
  public:
    explicit EchoServer(
      bool refuse = false
    )
      : mRefuse(refuse)
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
        if (opcode == 0x8) {
          break;
        }
      }
      ::closesocket(client);
    }

    bool mRefuse = false;
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
