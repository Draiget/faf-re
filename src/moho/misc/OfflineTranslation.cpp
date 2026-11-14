#ifdef _WIN32
#include "moho/misc/OfflineTranslation.h"
#include <Windows.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "gpg/core/utils/Logging.h"

namespace {
  struct Request { unsigned id; std::string text; };
  struct Result { unsigned id; std::string language, text; };

  std::string Hex(const std::string& text) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : text) { out += digits[c >> 4]; out += digits[c & 15]; }
    return out;
  }
  std::string Unhex(const std::string& text) {
    if (text.size() % 2) return {};
    std::string out;
    int high = -1;
    for (char c : text) {
      int n = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
      if (n < 0) return {};
      if (high < 0) high = n;
      else { out += static_cast<char>((high << 4) | n); high = -1; }
    }
    return out;
  }

  // All process/pipe I/O belongs to this thread, never the UI/simulation thread.
  class Translator {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Request> requests;
    std::deque<Result> results;
    unsigned nextId = 0;
    HANDLE input = nullptr, output = nullptr, process = nullptr;

    void Close() {
      if (input) CloseHandle(input);
      if (output) CloseHandle(output);
      input = output = nullptr;
      if (process) {
        if (WaitForSingleObject(process, 100) == WAIT_TIMEOUT) TerminateProcess(process, 1);
        CloseHandle(process);
        process = nullptr;
      }
    }
    bool Start() {
      wchar_t local[32768];
      // Prefer the installer-recorded location rather than depending on the launcher environment.
      wchar_t module[32768];
      const DWORD moduleLength = GetModuleFileNameW(nullptr, module, 32768);
      std::wstring home;
      if (moduleLength && moduleLength < 32768) {
        const std::wstring executable(module, moduleLength);
        const auto slash = executable.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
          const auto config = executable.substr(0, slash + 1) + L"offline-translator.ini";
          const DWORD length = GetPrivateProfileStringW(L"runtime", L"home", L"", local, 32768, config.c_str());
          if (length && length < 32767) home.assign(local, length);
        }
      }
      const DWORD count = home.empty() ? GetEnvironmentVariableW(L"LOCALAPPDATA", local, 32768) : 0;
      if (home.empty()) {
      if (!count || count >= 32768) { gpg::Logf("OfflineTranslation: LOCALAPPDATA unavailable (%lu)", GetLastError()); return false; }
      home = std::wstring(local, count) + L"\\Microchip\\faf-translator";
      }
      const std::wstring exe = home + L"\\python\\Scripts\\python.exe";
      const std::wstring script = home + L"\\worker.py";
      char diagnosticPath[32768];
      if (WideCharToMultiByte(CP_UTF8, 0, exe.c_str(), -1, diagnosticPath, sizeof(diagnosticPath), nullptr, nullptr))
        gpg::Logf("OfflineTranslation: runtime path=%s", diagnosticPath);
      if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES ||
          GetFileAttributesW(script.c_str()) == INVALID_FILE_ATTRIBUTES) {
        gpg::Logf("OfflineTranslation: runtime files unavailable (%lu)", GetLastError()); return false;
      }
      SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
      HANDLE childInput = nullptr, childOutput = nullptr;
      if (!CreatePipe(&childInput, &input, &sa, 0)) return false;
      if (!CreatePipe(&output, &childOutput, &sa, 0)) {
        CloseHandle(childInput); Close(); return false;
      }
      SetHandleInformation(input, HANDLE_FLAG_INHERIT, 0);
      SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0);
      HANDLE error = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &sa, OPEN_EXISTING, 0, nullptr);
      STARTUPINFOEXW startup{};
      startup.StartupInfo.cb = sizeof(startup);
      startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      startup.StartupInfo.hStdInput = childInput;
      startup.StartupInfo.hStdOutput = childOutput;
      startup.StartupInfo.hStdError = error;
      SIZE_T bytes = 0;
      InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
      std::vector<unsigned char> attributes(bytes);
      startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
      bool initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes) != FALSE;
      HANDLE handles[]{childInput, childOutput, error};
      bool configured = initialized && error != INVALID_HANDLE_VALUE &&
        UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  handles, sizeof(handles), nullptr, nullptr);
      PROCESS_INFORMATION info{};
      std::wstring command = L"\"" + exe + L"\" -I -u \"" + script + L"\"";
      bool launched = configured && CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, home.c_str(), &startup.StartupInfo, &info);
      const DWORD launchError = launched ? 0 : GetLastError();
      if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
      CloseHandle(childInput); CloseHandle(childOutput);
      if (error != INVALID_HANDLE_VALUE) CloseHandle(error);
      if (!launched) { gpg::Logf("OfflineTranslation: worker launch failed (%lu)", launchError); Close(); return false; }
      process = info.hProcess;
      CloseHandle(info.hThread);
      gpg::Logf("OfflineTranslation: local worker started");
      return true;
    }
    Result Translate(const Request& request) {
      Result result{request.id, {}, {}};
      if (!process && !Start()) { result.language = "unavailable"; return result; }
      const std::string line = std::to_string(request.id) + "\t" + Hex(request.text) + "\n";
      DWORD written = 0;
      // A request is <=4108 bytes and the child consumes stdin before translating.
      if (!WriteFile(input, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) || written != line.size()) {
        Close(); result.language = "unavailable"; return result;
      }
      std::string response;
      const ULONGLONG deadline = GetTickCount64() + 30000;
      while (GetTickCount64() < deadline && response.size() < 16384) {
        DWORD available = 0;
        if (!PeekNamedPipe(output, nullptr, 0, nullptr, &available, nullptr)) break;
        if (!available) {
          if (WaitForSingleObject(process, 20) != WAIT_TIMEOUT) break;
          continue;
        }
        char buffer[1024]; DWORD received = 0;
        if (!ReadFile(output, buffer, (std::min)(available, DWORD(sizeof(buffer))), &received, nullptr)) break;
        response.append(buffer, received);
        if (response.find('\n') == std::string::npos) continue;
        const auto first = response.find('\t');
        const auto second = response.find('\t', first == std::string::npos ? 0 : first + 1);
        if (first != std::string::npos && second != std::string::npos &&
            response.substr(0, first) == std::to_string(request.id)) {
          result.language = response.substr(first + 1, second - first - 1);
          result.text = Unhex(response.substr(second + 1, response.find('\n') - second - 1));
          return result;
        }
        break;
      }
      DWORD exitCode = 0;
      GetExitCodeProcess(process, &exitCode);
      gpg::Logf("OfflineTranslation: worker response failed (exit=%lu, pipe=%lu)", exitCode, GetLastError());
      Close(); result.language = "unavailable"; return result;
    }
    void Run() {
      for (;;) {
        Request request;
        {
          std::unique_lock<std::mutex> lock(mutex);
          ready.wait(lock, [&] { return !requests.empty(); });
          request = std::move(requests.front()); requests.pop_front();
        }
        Result result;
        try { result = Translate(request); }
        catch (...) { Close(); result = {request.id, "unavailable", {}}; }
        std::lock_guard<std::mutex> lock(mutex);
        if (results.size() == 64) results.pop_front();
        results.push_back(std::move(result));
      }
    }
  public:
    Translator() { std::thread([this] { Run(); }).detach(); }
    unsigned Queue(std::string text) {
      std::lock_guard<std::mutex> lock(mutex);
      if (text.empty() || text.size() > 2048 || requests.size() >= 32) return 0;
      if (++nextId >= 8000000) nextId = 1;
      requests.push_back({nextId, std::move(text)}); ready.notify_one(); return nextId;
    }
    std::deque<Result> Poll() {
      std::lock_guard<std::mutex> lock(mutex);
      std::deque<Result> out; out.swap(results); return out;
    }
  };
  // Process-lifetime object: OS closes pipes on exit, causing the child to exit on EOF.
  Translator& Service() { static auto* service = new Translator; return *service; }

  int Queue(lua_State* raw) {
    const char* text = lua_gettop(raw) == 1 ? lua_tostring(raw, 1) : nullptr;
    lua_pushnumber(raw, text ? Service().Queue(text) : 0);
    return 1;
  }
  int Poll(lua_State* raw) {
    auto* state = raw->stateUserData;
    LuaPlus::LuaObject entries;
    entries.AssignNewTable(state, 0, 0);
    int index = 1;
    for (const auto& result : Service().Poll()) {
      LuaPlus::LuaObject entry;
      entry.AssignNewTable(state, 0, 0);
      entry.SetInteger("id", result.id);
      entry.SetString("language", result.language.c_str());
      entry.SetString("text", result.text.c_str());
      entries.SetObject(index++, entry);
    }
    entries.PushStack(state); return 1;
  }
}

void moho::RegisterOfflineTranslation() {
  auto* set = SCR_FindLuaInitFormSet("User");
  if (!set) return;
  static CScrLuaBinder queue(*set, "MicrochipQueueTranslation", &Queue, nullptr, "<global>", "Queue local offline translation");
  static CScrLuaBinder poll(*set, "MicrochipPollTranslations", &Poll, nullptr, "<global>", "Poll local offline translations");
}

#endif
