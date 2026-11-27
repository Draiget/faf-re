// Engine addition (in-game launcher plan, WP2): platform::process on POSIX (src/platform/Process.h): posix_spawn
// with both outputs through pipes, in a process group of its own, so a timeout ends the program and what it started.

#include "platform/Process.h"
#include "platform/PlatformDefines.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace platform::process
{
  std::expected<void, std::string> OpenInBrowser(
    const std::string& url
  )
  {
    if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0) {
      return std::unexpected("not a web address: " + url);
    }
#if FAFRE_PLATFORM_MACOS
    const std::string program = "open"; // macOS's opener (LaunchServices)
#else
    const std::string program = "xdg-open";
#endif
    // The opener hands the page to the browser and ends; a browser that was already running keeps its own process.
    auto result = Run(program, {url}, std::chrono::seconds(20));
    if (!result) {
      return std::unexpected(result.error());
    }
    if (result->exitCode != 0) {
      return std::unexpected(program + " ended with " + std::to_string(result->exitCode));
    }
    return {};
  }

  std::expected<Output, std::string> Run(
    const std::string& program,
    const std::vector<std::string>& args,
    const std::chrono::milliseconds timeout
  )
  {
    int out[2] = {-1, -1};
    int err[2] = {-1, -1};
    if (::pipe(out) != 0 || ::pipe(err) != 0) {
      return std::unexpected("no pipe for " + program);
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    posix_spawn_file_actions_adddup2(&actions, err[1], 2);
    posix_spawn_file_actions_addclose(&actions, out[0]);
    posix_spawn_file_actions_addclose(&actions, err[0]);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0); // its own group: killpg ends what it started too

    std::vector<std::string> owned{program};
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (std::string& arg : owned) {
      argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    pid_t pid = 0;
    const int spawned = ::posix_spawn(&pid, program.c_str(), &actions, &attributes, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    ::close(out[1]);
    ::close(err[1]);
    if (spawned != 0) {
      ::close(out[0]);
      ::close(err[0]);
      return std::unexpected("couldn't start " + program + " (" + std::strerror(spawned) + ")");
    }

    Output output;
    pollfd pipes[2] = {{out[0], POLLIN, 0}, {err[0], POLLIN, 0}};
    std::string* targets[2] = {&output.out, &output.err};
    int open = 2;
    bool timedOut = false;
    const auto until = std::chrono::steady_clock::now() + timeout;
    while (open > 0) {
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now());
      if (left.count() <= 0) {
        timedOut = true;
        break;
      }
      const int ready = ::poll(pipes, 2, static_cast<int>(std::min<long long>(left.count(), 200)));
      if (ready < 0 && errno != EINTR) {
        break;
      }
      for (int i = 0; i < 2; ++i) {
        if (pipes[i].fd < 0 || (pipes[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
          continue;
        }
        char buffer[4096];
        const ssize_t got = ::read(pipes[i].fd, buffer, sizeof(buffer));
        if (got > 0) {
          targets[i]->append(buffer, static_cast<std::size_t>(got));
        } else {
          ::close(pipes[i].fd);
          pipes[i].fd = -1;
          --open;
        }
      }
    }
    if (timedOut) {
      ::killpg(pid, SIGKILL);
    }
    for (pollfd& pipe : pipes) {
      if (pipe.fd >= 0) {
        ::close(pipe.fd);
      }
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (timedOut) {
      return std::unexpected(program + " didn't finish within " + std::to_string(timeout.count()) + " ms");
    }
    output.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return output;
  }
} // namespace platform::process
