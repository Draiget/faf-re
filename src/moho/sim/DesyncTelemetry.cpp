#include "moho/sim/DesyncTelemetry.h"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <winhttp.h>
#else
#include <cerrno>
#include <csignal>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/DesyncRecorder.h"

namespace moho
{
  bool telemetry_Enabled = false;

  TConVar<bool> gTConVar_telemetry_Enabled(
    "telemetry_Enabled",
    "Send one small record per desync and one per game end to telemetry_Endpoint (OTLP/HTTP JSON). "
    "No names, ids, paths or dump contents. Off by default.",
    &telemetry_Enabled
  );

  msvc8::string telemetry_Endpoint;

  TConVar<msvc8::string> gTConVar_telemetry_Endpoint(
    "telemetry_Endpoint",
    "OpenTelemetry collector base URL for telemetry_Enabled, e.g. http://127.0.0.1:4318 (/v1/logs is appended).",
    &telemetry_Endpoint
  );

  msvc8::string telemetry_Token;

  TConVar<msvc8::string> gTConVar_telemetry_Token(
    "telemetry_Token",
    "Ingest token sent as 'Authorization: Bearer <token>' with telemetry records; empty sends none.",
    &telemetry_Token
  );

  namespace
  {
    /// A record is posted when queued, with the next record (the game end), and at the next start.
    constexpr int kMaxAttempts = 3;
    constexpr int kTimeoutMs = 3000;
    constexpr std::size_t kMaxOutboxRecords = 32;
    /// One outbox per process (`faf_telemetry_outbox_<pid>.txt`), so two games logging to one
    /// folder don't overwrite each other's; a starting sender takes over every other one there.
    constexpr const char kOutboxPrefix[] = "faf_telemetry_outbox_";

    struct SOutboxEntry
    {
      int mAttempts = 0;
      std::string mBody; // one line of OTLP JSON
    };

    struct SEndpoint
    {
      bool mHttps = false;
      std::string mHost;
      int mPort = 0;
      std::string mPath;
    };

    [[nodiscard]] bool ParseEndpoint(const std::string& url, SEndpoint& out)
    {
      std::string rest;
      if (url.compare(0, 7, "http://") == 0) {
        rest = url.substr(7);
        out.mHttps = false;
        out.mPort = 80;
      } else if (url.compare(0, 8, "https://") == 0) {
        rest = url.substr(8);
        out.mHttps = true;
        out.mPort = 443;
      } else {
        return false;
      }
      const std::size_t slash = rest.find('/');
      std::string hostPort = rest.substr(0, slash);
      out.mPath = slash == std::string::npos ? std::string() : rest.substr(slash);
      while (!out.mPath.empty() && out.mPath.back() == '/') {
        out.mPath.pop_back();
      }
      constexpr const char kLogs[] = "/v1/logs";
      if (out.mPath.size() < sizeof(kLogs) - 1u
          || out.mPath.compare(out.mPath.size() - (sizeof(kLogs) - 1u), std::string::npos, kLogs) != 0) {
        out.mPath += kLogs;
      }
      if (const std::size_t colon = hostPort.rfind(':'); colon != std::string::npos) { // host names and IPv4 only
        out.mPort = std::atoi(hostPort.c_str() + colon + 1);
        hostPort.resize(colon);
      }
      out.mHost = hostPort;
      return !out.mHost.empty() && out.mPort > 0 && out.mPort < 65536;
    }

#if defined(_WIN32)
    /// WinHTTP, loaded at the first post: the import table stays as it is, so the headless exe's
    /// allowed-DLL check (cmake/HeadlessImports.cmake) still holds.
    struct SWinHttp
    {
      decltype(&::WinHttpOpen) Open = nullptr;
      decltype(&::WinHttpSetTimeouts) SetTimeouts = nullptr;
      decltype(&::WinHttpConnect) Connect = nullptr;
      decltype(&::WinHttpOpenRequest) OpenRequest = nullptr;
      decltype(&::WinHttpSendRequest) SendRequest = nullptr;
      decltype(&::WinHttpReceiveResponse) ReceiveResponse = nullptr;
      decltype(&::WinHttpQueryHeaders) QueryHeaders = nullptr;
      decltype(&::WinHttpCloseHandle) CloseHandle = nullptr;
      HINTERNET mSession = nullptr;

      [[nodiscard]] bool Load()
      {
        if (mSession != nullptr) {
          return true;
        }
        HMODULE const module = ::LoadLibraryW(L"winhttp.dll");
        if (module == nullptr) {
          return false;
        }
        Open = reinterpret_cast<decltype(Open)>(::GetProcAddress(module, "WinHttpOpen"));
        SetTimeouts = reinterpret_cast<decltype(SetTimeouts)>(::GetProcAddress(module, "WinHttpSetTimeouts"));
        Connect = reinterpret_cast<decltype(Connect)>(::GetProcAddress(module, "WinHttpConnect"));
        OpenRequest = reinterpret_cast<decltype(OpenRequest)>(::GetProcAddress(module, "WinHttpOpenRequest"));
        SendRequest = reinterpret_cast<decltype(SendRequest)>(::GetProcAddress(module, "WinHttpSendRequest"));
        ReceiveResponse = reinterpret_cast<decltype(ReceiveResponse)>(::GetProcAddress(module, "WinHttpReceiveResponse"));
        QueryHeaders = reinterpret_cast<decltype(QueryHeaders)>(::GetProcAddress(module, "WinHttpQueryHeaders"));
        CloseHandle = reinterpret_cast<decltype(CloseHandle)>(::GetProcAddress(module, "WinHttpCloseHandle"));
        if (!Open || !SetTimeouts || !Connect || !OpenRequest || !SendRequest || !ReceiveResponse || !QueryHeaders
            || !CloseHandle) {
          return false;
        }
        mSession = Open(L"faf-engine", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (mSession != nullptr) {
          (void)SetTimeouts(mSession, kTimeoutMs, kTimeoutMs, kTimeoutMs, kTimeoutMs);
        }
        return mSession != nullptr;
      }
    };

    [[nodiscard]] std::wstring Widen(const std::string& text)
    {
      const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring out(static_cast<std::size_t>(length > 0 ? length : 0), L'\0');
      if (length > 0) {
        (void)::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), length);
      }
      return out;
    }

    /// The HTTP status of one POST, or 0 when the request failed.
    [[nodiscard]] int Post(SWinHttp& http, const SEndpoint& endpoint, const std::string& token, const std::string& body)
    {
      if (!http.Load()) {
        return 0;
      }
      int status = 0;
      HINTERNET const connection =
        http.Connect(http.mSession, Widen(endpoint.mHost).c_str(), static_cast<INTERNET_PORT>(endpoint.mPort), 0);
      HINTERNET const request = connection == nullptr ? nullptr
                                                      : http.OpenRequest(
                                                          connection, L"POST", Widen(endpoint.mPath).c_str(), nullptr,
                                                          WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                          endpoint.mHttps ? WINHTTP_FLAG_SECURE : 0
                                                        );
      if (request != nullptr) {
        std::wstring headers = L"Content-Type: application/json\r\n";
        if (!token.empty()) {
          headers += L"Authorization: Bearer " + Widen(token) + L"\r\n";
        }
        if (http.SendRequest(
              request, headers.c_str(), static_cast<DWORD>(headers.size()), const_cast<char*>(body.data()),
              static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0
            )
            && http.ReceiveResponse(request, nullptr)) {
          DWORD code = 0;
          DWORD size = sizeof(code);
          if (http.QueryHeaders(
                request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code,
                &size, WINHTTP_NO_HEADER_INDEX
              )) {
            status = static_cast<int>(code);
          }
        }
        (void)http.CloseHandle(request);
      }
      if (connection != nullptr) {
        (void)http.CloseHandle(connection);
      }
      return status;
    }

    [[nodiscard]] std::string OsDescription()
    {
      using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
      OSVERSIONINFOW version{};
      version.dwOSVersionInfoSize = sizeof(version);
      if (HMODULE const ntdll = ::GetModuleHandleW(L"ntdll.dll")) {
        if (const auto fn = reinterpret_cast<RtlGetVersionFn>(::GetProcAddress(ntdll, "RtlGetVersion"))) {
          (void)fn(&version);
        }
      }
      char text[64];
      std::snprintf(
        text, sizeof(text), "Windows %lu.%lu.%lu", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber
      );
      return text;
    }
#else
    struct SWinHttp
    {};

    /// Plain HTTP over a socket; https needs the Windows build (no TLS library here).
    [[nodiscard]] int Post(SWinHttp&, const SEndpoint& endpoint, const std::string& token, const std::string& body)
    {
      if (endpoint.mHttps) {
        return 0;
      }
      addrinfo hints{};
      hints.ai_socktype = SOCK_STREAM;
      addrinfo* found = nullptr;
      if (::getaddrinfo(endpoint.mHost.c_str(), std::to_string(endpoint.mPort).c_str(), &hints, &found) != 0) {
        return 0;
      }
      int status = 0;
      for (addrinfo* address = found; address != nullptr && status == 0; address = address->ai_next) {
        const int fd = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
          continue;
        }
        timeval timeout{kTimeoutMs / 1000, 0};
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (::connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
          std::string request = "POST " + endpoint.mPath + " HTTP/1.1\r\nHost: " + endpoint.mHost + ":"
            + std::to_string(endpoint.mPort) + "\r\nContent-Type: application/json\r\nContent-Length: "
            + std::to_string(body.size()) + "\r\nConnection: close\r\n";
          if (!token.empty()) {
            request += "Authorization: Bearer " + token + "\r\n";
          }
          request += "\r\n" + body;
          if (::send(fd, request.data(), request.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(request.size())) {
            char reply[64] = {};
            const ssize_t got = ::recv(fd, reply, sizeof(reply) - 1u, 0);
            if (got > 12 && std::strncmp(reply, "HTTP/1.", 7) == 0) {
              status = std::atoi(reply + 9);
            }
          }
        }
        ::close(fd);
      }
      ::freeaddrinfo(found);
      return status;
    }

    [[nodiscard]] std::string OsDescription()
    {
      utsname name{};
      return ::uname(&name) == 0 ? std::string(name.sysname) + " " + name.release : std::string("Linux");
    }
#endif

    /// The folder of `/log <file>`, else the working folder.
    [[nodiscard]] std::filesystem::path OutboxFolder()
    {
      msvc8::vector<msvc8::string> args;
      if (CFG_GetArgOption("/log", 1u, &args) && !args.empty()) {
        std::error_code error;
        const std::filesystem::path folder = std::filesystem::path(args[0].c_str()).parent_path();
        if (!folder.empty() && std::filesystem::is_directory(folder, error)) {
          return folder;
        }
      }
      std::error_code error;
      return std::filesystem::current_path(error);
    }

    [[nodiscard]] std::vector<std::filesystem::path> OutboxFiles(const std::filesystem::path& folder)
    {
      std::vector<std::filesystem::path> files;
      std::error_code error;
      for (std::filesystem::directory_iterator it(folder, error), end; !error && it != end; it.increment(error)) {
        const std::string name = it->path().filename().string();
        if (name.compare(0, sizeof(kOutboxPrefix) - 1u, kOutboxPrefix) == 0) {
          files.push_back(it->path());
        }
      }
      return files;
    }

    /// Whether the process that owns `file` (its pid follows the prefix) still runs: two clients
    /// that share a /log folder must not take each other's records.
    [[nodiscard]] bool OwnerRunning(const std::filesystem::path& file, const unsigned long self)
    {
      const unsigned long pid = std::strtoul(file.filename().string().c_str() + sizeof(kOutboxPrefix) - 1u, nullptr, 10);
      if (pid == 0u || pid == self) {
        return false;
      }
#if defined(_WIN32)
      const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
      if (process == nullptr) {
        return false;
      }
      DWORD code = 0;
      const bool running = ::GetExitCodeProcess(process, &code) != FALSE && code == STILL_ACTIVE;
      ::CloseHandle(process);
      return running;
#else
      return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
    }

    /// The `resource` part every request carries: the process, not the player.
    [[nodiscard]] std::string ResourceJson()
    {
      CTelemetryAttributes resource;
      resource.Add("service.name", std::string("faf-engine"));
      resource.Add("service.version", std::string(gpg::diag::BuildCommit()));
      resource.Add("faf.engine.version", std::string(gpg::diag::BuildDescribe()));
      resource.AddBool("faf.engine.dirty", gpg::diag::BuildDirty());
      const std::string arch = gpg::diag::BuildArch();
      resource.Add("host.arch", std::string(arch == "x86" ? "x86" : "amd64"));
      resource.Add("faf.arch", arch);
#if defined(_WIN32)
      resource.Add("os.type", std::string("windows"));
#else
      resource.Add("os.type", std::string("linux"));
#endif
      resource.Add("os.description", OsDescription());
      resource.Add("faf.cpu.logical_count", static_cast<std::int64_t>(std::thread::hardware_concurrency()));
      return "{\"attributes\":[" + resource.Json() + "]}";
    }

    /// The sender: one thread, started by the first record or by a non-empty outbox at startup.
    class CSender
    {
    public:
      static CSender& Get()
      {
        static CSender* const sender = new CSender(); // never destroyed: the thread may outlive main
        return *sender;
      }

      void Queue(std::string body)
      {
        {
          std::lock_guard<std::mutex> lock(mMutex);
          mIncoming.push_back(std::move(body));
          StartLocked();
        }
        mSignal.notify_one();
      }

      /// Waits until every queued record had its attempt, or `timeout` passed.
      void WaitIdle(const std::chrono::milliseconds timeout)
      {
        std::unique_lock<std::mutex> lock(mMutex);
        (void)mIdle.wait_for(lock, timeout, [this] { return !mStarted || (mIncoming.empty() && !mWorking && !mRetryOutbox); });
      }

      void RetryOutbox()
      {
        {
          std::lock_guard<std::mutex> lock(mMutex);
          mRetryOutbox = true;
          StartLocked();
        }
        mSignal.notify_one();
      }

    private:
      void StartLocked()
      {
        if (!mStarted) {
          mStarted = true;
          std::thread([this] { Run(); }).detach();
        }
      }

      void Run()
      {
#if defined(_WIN32)
        const unsigned long pid = ::GetCurrentProcessId();
#else
        const unsigned long pid = static_cast<unsigned long>(::getpid());
#endif
        const std::filesystem::path folder = OutboxFolder();
        const std::filesystem::path path = folder / (kOutboxPrefix + std::to_string(pid) + ".txt");
        std::vector<SOutboxEntry> outbox;
        for (const std::filesystem::path& file : OutboxFiles(folder)) {
          if (OwnerRunning(file, pid)) {
            continue;
          }
          std::vector<SOutboxEntry> entries = Load(file);
          outbox.insert(outbox.end(), entries.begin(), entries.end());
          std::error_code error;
          std::filesystem::remove(file, error);
        }
        SWinHttp http;
        for (;;) {
          std::deque<std::string> incoming;
          {
            std::unique_lock<std::mutex> lock(mMutex);
            mSignal.wait(lock, [this] { return !mIncoming.empty() || mRetryOutbox; });
            incoming.swap(mIncoming);
            mRetryOutbox = false;
            mWorking = true;
          }
          Attempt(path, outbox, http, incoming);
          {
            std::lock_guard<std::mutex> lock(mMutex);
            mWorking = false;
          }
          mIdle.notify_all();
        }
      }

      void Attempt(
        const std::filesystem::path& path, std::vector<SOutboxEntry>& outbox, SWinHttp& http, std::deque<std::string>& incoming
      )
      {
        for (std::string& body : incoming) {
          outbox.push_back(SOutboxEntry{0, std::move(body)});
        }
        while (outbox.size() > kMaxOutboxRecords) {
          outbox.erase(outbox.begin());
        }
        Save(path, outbox); // on disk before the first attempt: a quit mid-request loses nothing

        SEndpoint endpoint;
        const std::string url = telemetry_Endpoint.c_str();
        const std::string token = telemetry_Token.c_str();
        if (!ParseEndpoint(url, endpoint)) {
          gpg::Warnf("Telemetry: endpoint \"%s\" is not http(s)://host[:port][/path]; %u record(s) kept", url.c_str(),
                     static_cast<unsigned>(outbox.size()));
          return;
        }
        std::vector<SOutboxEntry> kept;
        unsigned sent = 0;
        unsigned dropped = 0;
        int lastStatus = 0;
        for (SOutboxEntry& entry : outbox) {
          const std::string request =
            "{\"resourceLogs\":[{\"resource\":" + ResourceJson() + ",\"scopeLogs\":[" + entry.mBody + "]}]}";
          lastStatus = Post(http, endpoint, token, request);
          if (lastStatus >= 200 && lastStatus < 300) {
            ++sent;
          } else if (lastStatus >= 400 && lastStatus < 500 && lastStatus != 408 && lastStatus != 429) {
            ++dropped; // the collector refused this record; sending it again won't change that
          } else if (++entry.mAttempts >= kMaxAttempts) {
            ++dropped;
          } else {
            kept.push_back(std::move(entry));
          }
        }
        outbox.swap(kept);
        Save(path, outbox);
        gpg::Logf(
          "Telemetry: %u record(s) sent, %u dropped, %u kept for a retry (last HTTP status %d)", sent, dropped,
          static_cast<unsigned>(outbox.size()), lastStatus
        );
      }

      [[nodiscard]] static std::vector<SOutboxEntry> Load(const std::filesystem::path& path)
      {
        std::vector<SOutboxEntry> entries;
        std::ifstream file(path, std::ios::binary);
        std::string line;
        while (std::getline(file, line)) {
          const std::size_t tab = line.find('\t');
          if (tab != std::string::npos && tab > 0) {
            entries.push_back(SOutboxEntry{std::atoi(line.c_str()), line.substr(tab + 1u)});
          }
        }
        return entries;
      }

      static void Save(const std::filesystem::path& path, const std::vector<SOutboxEntry>& entries)
      {
        std::error_code error;
        if (entries.empty()) {
          std::filesystem::remove(path, error);
          return;
        }
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        for (const SOutboxEntry& entry : entries) {
          file << entry.mAttempts << '\t' << entry.mBody << '\n';
        }
      }

      std::mutex mMutex;
      std::condition_variable mSignal;
      std::condition_variable mIdle;
      std::deque<std::string> mIncoming;
      bool mRetryOutbox = false;
      bool mStarted = false;
      bool mWorking = false;
    };

    [[nodiscard]] std::uint64_t NowUnixNano()
    {
      return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()
      );
    }
  } // namespace

  std::string TELEMETRY_JsonString(const std::string& text)
  {
    std::string out = "\"";
    for (const char c : text) {
      switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20u) {
          char escaped[8];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += escaped;
        } else {
          out += c;
        }
      }
    }
    out += '"';
    return out;
  }

  void CTelemetryAttributes::Key(const char* const key)
  {
    if (!mJson.empty()) {
      mJson += ',';
    }
    mJson += "{\"key\":" + TELEMETRY_JsonString(key) + ",\"value\":";
  }

  void CTelemetryAttributes::Add(const char* const key, const std::string& value)
  {
    Key(key);
    mJson += "{\"stringValue\":" + TELEMETRY_JsonString(value) + "}}";
  }

  void CTelemetryAttributes::Add(const char* const key, const std::int64_t value)
  {
    Key(key);
    mJson += "{\"intValue\":\"" + std::to_string(value) + "\"}}"; // int64 is a JSON string in OTLP
  }

  void CTelemetryAttributes::AddBool(const char* const key, const bool value)
  {
    Key(key);
    mJson += value ? "{\"boolValue\":true}}" : "{\"boolValue\":false}}";
  }

  void CTelemetryAttributes::AddDouble(const char* const key, const double value)
  {
    Key(key);
    char text[32];
    std::snprintf(text, sizeof(text), "%.17g", value);
    mJson += std::string("{\"doubleValue\":") + text + "}}";
  }

  void TELEMETRY_Startup()
  {
    static bool sStarted = false;
    if (sStarted) {
      return;
    }
    sStarted = true;
    msvc8::vector<msvc8::string> args;
    if (CFG_GetArgOption("/telemetry", 0u, nullptr)) {
      telemetry_Enabled = true;
    }
    if (CFG_GetArgOption("/telemetryendpoint", 1u, &args) && !args.empty()) {
      telemetry_Endpoint = args[0];
    }
    args.clear();
    if (CFG_GetArgOption("/telemetrytoken", 1u, &args) && !args.empty()) {
      telemetry_Token = args[0];
    }
    CDesyncRecorder::NoteSwitchDefaults();
    if (TELEMETRY_IsOn()) {
      gpg::Logf("Telemetry: on, endpoint %s", telemetry_Endpoint.c_str());
      if (!OutboxFiles(OutboxFolder()).empty()) {
        CSender::Get().RetryOutbox();
      }
    }
  }

  void TELEMETRY_WaitIdle(const int timeoutMs)
  {
    CSender::Get().WaitIdle(std::chrono::milliseconds(timeoutMs));
  }

  bool TELEMETRY_IsOn()
  {
    return telemetry_Enabled && !telemetry_Endpoint.empty();
  }

  void TELEMETRY_Send(
    const char* const eventName, const int severityNumber, const char* const severityText,
    const CTelemetryAttributes& attributes
  )
  {
    if (!TELEMETRY_IsOn()) {
      return;
    }
    const std::string now = std::to_string(NowUnixNano());
    CTelemetryAttributes withName = attributes;
    withName.Add("event.name", std::string(eventName));
    std::string body = "{\"scope\":{\"name\":\"faf.desync\",\"version\":\"1\"},\"logRecords\":[{\"timeUnixNano\":\"" + now
      + "\",\"observedTimeUnixNano\":\"" + now + "\",\"severityNumber\":" + std::to_string(severityNumber)
      + ",\"severityText\":" + TELEMETRY_JsonString(severityText) + ",\"eventName\":" + TELEMETRY_JsonString(eventName)
      + ",\"body\":{\"stringValue\":" + TELEMETRY_JsonString(eventName) + "},\"attributes\":[" + withName.Json() + "]}]}";
    CSender::Get().Queue(std::move(body));
  }
} // namespace moho
