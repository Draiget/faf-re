#pragma once

/**
 * Engine addition (in-game launcher plan, WP2): running a helper program and reading what it prints, one interface
 * with one implementation per platform. The lobby client runs FAF's faf-uid with it.
 *
 * - Windows (src/platform/windows/ProcessWindows.cpp): CreateProcessW with no window, both outputs through pipes.
 * - POSIX (src/platform/posix/ProcessPosix.cpp): posix_spawn with both outputs through pipes.
 *
 * OpenInBrowser hands a web page to the system's browser: the FAF sign-in page. CurrentProgram, CurrentArgs and Start
 * let the game start itself again, on another featured mod's files.
 */

#include <chrono>
#include <expected>
#include <string>
#include <vector>

namespace platform::process
{
  struct Output
  {
    int exitCode = -1;
    std::string out;
    std::string err;
  };

  /**
   * Runs `program` with `args` (each one argument, quoted as needed), with no window, and waits for it to end. A
   * program still running after `timeout` is stopped, and that is an error, as is one that can't start.
   */
  [[nodiscard]] std::expected<Output, std::string>
  Run(const std::string& program, const std::vector<std::string>& args, std::chrono::milliseconds timeout);

  /**
   * Opens `url` (http or https only; anything else is refused) in the system's browser and returns once the system
   * took it or refused it. Windows: the shell, with COM set up on the calling thread for the call, as the shell's
   * handlers need, or on an account with no default browser the command a browser registered for https links; run it
   * off the game's thread, as it can take a moment. Linux: xdg-open; macOS: open.
   */
  [[nodiscard]] std::expected<void, std::string> OpenInBrowser(const std::string& url);

  /** The running program's own file, as a full path. */
  [[nodiscard]] std::expected<std::string, std::string> CurrentProgram();

  /**
   * The running program's arguments as it was started with them, without the program itself. Windows: the process's
   * own command line read as CommandLineToArgvW reads it (UTF-8 here); Linux: /proc/self/cmdline; macOS: the C
   * runtime's argv.
   */
  [[nodiscard]] std::vector<std::string> CurrentArgs();

  /**
   * Starts `program` with `args` (each one argument, quoted as needed) and doesn't wait for it: it runs on after this
   * program ends. Same working folder and environment; no handle or pipe is passed on.
   */
  [[nodiscard]] std::expected<void, std::string>
  Start(const std::string& program, const std::vector<std::string>& args);
} // namespace platform::process
