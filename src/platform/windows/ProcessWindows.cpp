// Engine addition (in-game launcher plan, WP2): platform::process on CreateProcessW (src/platform/Process.h).

#include "platform/Process.h"

#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

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
  } // namespace

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
