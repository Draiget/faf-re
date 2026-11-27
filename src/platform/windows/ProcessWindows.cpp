// Engine addition (in-game launcher plan, WP2): platform::process on CreateProcessW (src/platform/Process.h).

#include "platform/Process.h"

#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <objbase.h>
#include <shellapi.h>

namespace platform::process
{
  namespace
  {
    std::wstring Widen(
      const std::string& text
    )
    {
      if (text.empty()) {
        return {};
      }
      const int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring out(static_cast<std::size_t>(count), L'\0');
      (void)::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count);
      return out;
    }

    std::string Narrow(
      const std::wstring& text
    )
    {
      if (text.empty()) {
        return {};
      }
      const int count =
        ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
      std::string out(static_cast<std::size_t>(count), '\0');
      (void)::WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count, nullptr, nullptr
      );
      return out;
    }

    /** One argument as CommandLineToArgvW reads it back: quoted when needed, backslashes before quotes doubled. */
    void AppendQuoted(
      std::wstring& line,
      const std::wstring& argument
    )
    {
      if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        line += argument;
        return;
      }
      line += L'"';
      for (std::size_t i = 0;; ++i) {
        std::size_t backslashes = 0;
        while (i < argument.size() && argument[i] == L'\\') {
          ++i;
          ++backslashes;
        }
        if (i == argument.size()) {
          line.append(backslashes * 2, L'\\');
          break;
        }
        if (argument[i] == L'"') {
          line.append(backslashes * 2 + 1, L'\\');
        } else {
          line.append(backslashes, L'\\');
        }
        line += argument[i];
      }
      line += L'"';
    }

    void Drain(
      HANDLE pipe,
      std::string& out
    )
    {
      char buffer[4096];
      DWORD read = 0;
      while (::ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        out.append(buffer, read);
      }
    }
    /**
     * Runs the command registered for https links (HKEY_CLASSES_ROOT\https\shell\open\command, the browser that
     * registered itself) with `url` in place of its %1. False when there is none, or it doesn't start.
     */
    bool RunRegisteredBrowser(
      const std::wstring& url
    )
    {
      // The address goes into a command line inside quotes: one with a quote or a space in it is refused.
      if (url.find_first_of(L"\" \t\r\n") != std::wstring::npos) {
        return false;
      }
      wchar_t value[2048];
      DWORD size = sizeof(value);
      if (
        ::RegGetValueW(
          HKEY_CLASSES_ROOT,
          L"https\\shell\\open\\command",
          nullptr,
          RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
          nullptr,
          value,
          &size
        ) != ERROR_SUCCESS
      ) {
        return false;
      }
      std::wstring line = value;
      if (const std::size_t at = line.find(L"%1"); at != std::wstring::npos) {
        line.replace(at, 2, url);
      } else {
        line += L" \"" + url + L"\"";
      }
      STARTUPINFOW startup{};
      startup.cb = sizeof(startup);
      PROCESS_INFORMATION info{};
      if (!::CreateProcessW(nullptr, line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &info)) {
        return false;
      }
      ::CloseHandle(info.hThread);
      ::CloseHandle(info.hProcess);
      return true;
    }
  } // namespace

  std::expected<void, std::string> OpenInBrowser(
    const std::string& url
  )
  {
    if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0) {
      return std::unexpected("not a web address: " + url);
    }
    const std::wstring wide = Widen(url);
    // The shell runs its URL handlers through COM; this thread may not have it, so it is set up for the call.
    const HRESULT com = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    // NOASYNC: the hand-off ends before this returns (the thread may end right after); no error dialogs of its own.
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"open";
    info.lpFile = wide.c_str();
    info.nShow = SW_SHOWNORMAL;
    DWORD error = ::ShellExecuteExW(&info) ? 0 : ::GetLastError();
    // On an account that never chose a default browser, Windows 11 answers ERROR_NO_ASSOCIATION (1155) although a
    // browser registered its command for web links; that command takes the page then.
    if (error == ERROR_NO_ASSOCIATION && RunRegisteredBrowser(wide)) {
      error = 0;
    }
    const BOOL opened = error == 0;
    if (SUCCEEDED(com)) {
      ::CoUninitialize();
    }
    if (!opened) {
      if (error == ERROR_NO_ASSOCIATION) {
        return std::unexpected(std::string("Windows has no browser set for web links"));
      }
      return std::unexpected("Windows didn't open the browser (error " + std::to_string(error) + ")");
    }
    return {};
  }

  std::expected<std::string, std::string> CurrentProgram()
  {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
      const DWORD length = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
      if (length == 0) {
        return std::unexpected("no path for the running program (error " + std::to_string(::GetLastError()) + ")");
      }
      if (length < path.size()) {
        path.resize(length);
        return Narrow(path);
      }
      path.resize(path.size() * 2); // cut short: a longer buffer
    }
  }

  std::vector<std::string> CurrentArgs()
  {
    std::vector<std::string> args;
    int count = 0;
    LPWSTR* const list = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    if (list == nullptr) {
      return args;
    }
    for (int i = 1; i < count; ++i) {
      args.push_back(Narrow(list[i]));
    }
    ::LocalFree(list);
    return args;
  }

  std::expected<void, std::string> Start(
    const std::string& program,
    const std::vector<std::string>& args
  )
  {
    const std::wstring wideProgram = Widen(program);
    std::wstring line;
    AppendQuoted(line, wideProgram);
    for (const std::string& argument : args) {
      line += L' ';
      AppendQuoted(line, Widen(argument));
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    if (!::CreateProcessW(
          wideProgram.c_str(), line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &info
        )) {
      return std::unexpected("couldn't start " + program + " (error " + std::to_string(::GetLastError()) + ")");
    }
    ::CloseHandle(info.hThread);
    ::CloseHandle(info.hProcess);
    return {};
  }

  std::expected<Output, std::string> Run(
    const std::string& program,
    const std::vector<std::string>& args,
    const std::chrono::milliseconds timeout
  )
  {
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE outRead = nullptr;
    HANDLE outWrite = nullptr;
    HANDLE errRead = nullptr;
    HANDLE errWrite = nullptr;
    if (!::CreatePipe(&outRead, &outWrite, &inherit, 0) || !::CreatePipe(&errRead, &errWrite, &inherit, 0)) {
      return std::unexpected("no pipe for " + program);
    }
    (void)::SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    (void)::SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

    std::wstring line;
    AppendQuoted(line, Widen(program));
    for (const std::string& argument : args) {
      line += L' ';
      AppendQuoted(line, Widen(argument));
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = nullptr;
    startup.hStdOutput = outWrite;
    startup.hStdError = errWrite;
    PROCESS_INFORMATION info{};
    const std::wstring wideProgram = Widen(program);
    // A job holds the program and whatever it starts: on a timeout the whole tree ends, so no grandchild keeps the
    // pipes (and the reads below) open. Closing the job's handle ends what is left in it too.
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (job != nullptr) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      (void)::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    }
    const BOOL started = ::CreateProcessW(
      wideProgram.c_str(),
      line.data(),
      nullptr,
      nullptr,
      TRUE,
      CREATE_NO_WINDOW | CREATE_SUSPENDED,
      nullptr,
      nullptr,
      &startup,
      &info
    );
    const DWORD startError = ::GetLastError();
    if (started) {
      if (job != nullptr) {
        (void)::AssignProcessToJobObject(job, info.hProcess);
      }
      (void)::ResumeThread(info.hThread);
    }
    // Only the child holds the write ends now, so the reads below end when it does.
    ::CloseHandle(outWrite);
    ::CloseHandle(errWrite);
    if (!started) {
      ::CloseHandle(outRead);
      ::CloseHandle(errRead);
      if (job != nullptr) {
        ::CloseHandle(job);
      }
      return std::unexpected("couldn't start " + program + " (error " + std::to_string(startError) + ")");
    }
    Output output;
    std::thread outReader([&] {
      Drain(outRead, output.out);
    });
    std::thread errReader([&] {
      Drain(errRead, output.err);
    });
    const DWORD waited = ::WaitForSingleObject(info.hProcess, static_cast<DWORD>(timeout.count()));
    if (waited != WAIT_OBJECT_0) {
      if (job != nullptr) {
        (void)::TerminateJobObject(job, 1);
      } else {
        (void)::TerminateProcess(info.hProcess, 1);
      }
      (void)::WaitForSingleObject(info.hProcess, 5000);
    }
    outReader.join();
    errReader.join();
    if (job != nullptr) {
      ::CloseHandle(job);
    }
    DWORD code = 1;
    (void)::GetExitCodeProcess(info.hProcess, &code);
    ::CloseHandle(info.hThread);
    ::CloseHandle(info.hProcess);
    ::CloseHandle(outRead);
    ::CloseHandle(errRead);
    if (waited != WAIT_OBJECT_0) {
      return std::unexpected(program + " didn't finish within " + std::to_string(timeout.count()) + " ms");
    }
    output.exitCode = static_cast<int>(code);
    return output;
  }
} // namespace platform::process
