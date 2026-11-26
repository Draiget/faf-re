#pragma once

/**
 * Engine addition (in-game launcher plan, WP2): running a helper program and reading what it prints, one interface
 * with one implementation per platform. The lobby client runs FAF's faf-uid with it.
 *
 * - Windows (src/platform/windows/ProcessWindows.cpp): CreateProcessW with no window, both outputs through pipes.
 * - POSIX: not written yet.
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
} // namespace platform::process
