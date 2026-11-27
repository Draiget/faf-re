// Engine addition (in-game launcher plan, WP2): platform::process on POSIX (src/platform/Process.h): posix_spawn
// with both outputs through pipes, in a process group of its own, so a timeout ends the program and what it started.

#include "platform/Process.h"
#include "platform/PlatformDefines.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if FAFRE_PLATFORM_MACOS
#include <crt_externs.h> // _NSGetArgc, _NSGetArgv: macOS only
#include <mach-o/dyld.h> // _NSGetExecutablePath: macOS only
#endif

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

  std::expected<std::string, std::string> CurrentProgram()
  {
#if FAFRE_PLATFORM_MACOS
    char path[PATH_MAX];
    std::uint32_t size = sizeof(path);
    if (::_NSGetExecutablePath(path, &size) != 0) { // macOS only
      return std::unexpected(std::string("the running program's path is too long"));
    }
    char real[PATH_MAX];
    return std::string(::realpath(path, real) != nullptr ? real : path);
#else
    char path[PATH_MAX];
    const ssize_t length = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0) {
      return std::unexpected(std::string("no path for the running program (") + std::strerror(errno) + ")");
    }
    return std::string(path, static_cast<std::size_t>(length));
#endif
  }

  std::vector<std::string> CurrentArgs()
  {
    std::vector<std::string> args;
#if FAFRE_PLATFORM_MACOS
    const int count = *::_NSGetArgc(); // macOS only
    char** const values = *::_NSGetArgv();
    for (int i = 1; i < count && values != nullptr && values[i] != nullptr; ++i) {
      args.emplace_back(values[i]);
    }
#else
    std::ifstream in("/proc/self/cmdline", std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::size_t at = text.find('\0'); // past the program itself
    while (at != std::string::npos && at + 1 < text.size()) {
      const std::size_t end = text.find('\0', at + 1);
      args.push_back(text.substr(at + 1, (end == std::string::npos ? text.size() : end) - at - 1));
      at = end;
    }
#endif
    return args;
  }

  std::expected<void, std::string> Start(
    const std::string& program,
    const std::vector<std::string>& args
  )
  {
    // A program that can't run is an error here: after the fork only the child would know.
    if (::access(program.c_str(), X_OK) != 0) {
      return std::unexpected("couldn't start " + program + " (" + std::strerror(errno) + ")");
    }
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const std::string& argument : args) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    // Everything the child needs is made before the fork: between fork and exec it only closes descriptors, which is
    // safe in a copy of a program with threads. No descriptor of the game (sockets, files) reaches the new program.
    rlimit limit{};
    int highest = 1024;
    if (::getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY) {
      highest = static_cast<int>(std::min<rlim_t>(limit.rlim_cur, 65536));
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
      return std::unexpected("couldn't start " + program + " (" + std::strerror(errno) + ")");
    }
    if (pid == 0) {
      (void)::setpgid(0, 0); // its own group: not ended with this program's
      for (int fd = 3; fd < highest; ++fd) {
        (void)::close(fd);
      }
      ::execve(program.c_str(), argv.data(), environ);
      ::_exit(127);
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
