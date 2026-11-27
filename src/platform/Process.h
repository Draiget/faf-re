#pragma once

/**
 * Engine addition (in-game launcher plan, WP2): running a helper program and reading what it prints, one interface
 * with one implementation per platform. The lobby client runs FAF's faf-uid with it.
 *
 * - Windows (src/platform/windows/ProcessWindows.cpp): CreateProcessW with no window, both outputs through pipes.
 * - POSIX (src/platform/posix/ProcessPosix.cpp): posix_spawn with both outputs through pipes.
 *
 * OpenInBrowser hands a web page to the system's browser: the FAF sign-in page.
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
} // namespace platform::process
