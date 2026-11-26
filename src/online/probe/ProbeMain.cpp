// faf-online-probe: signs in to FAF's lobby with faf_online and prints what it sees (in-game launcher plan, WP2).
// Engine addition, not recovered code. Prints no token and no unique_id.
//
//   faf-online-probe list [--seconds 15] [--games]
//   faf-online-probe host --title <text> --map <folder> [--mod faf] [--password <text>] [--seconds 15]
//   faf-online-probe join --uid <id> [--password <text>] [--seconds 15]
//
// Sign-in: --token-file <file> (a refresh token sealed for this user; default
// %LOCALAPPDATA%\faf-re\online\probe.token), signing in by device code when it holds none; --import-plain-token <file>
// seals the refresh token kept in that plain file into --token-file and empties it; --access-token-file <file> uses
// that access token as it is (a local FAF stack). --oauth <url>, --api <url>, --client-id <id> name another sign-in
// server. Lobby: --user-service <url>, --ws <url> (skip /lobby/access), --uid-program <faf-uid.exe>, --test-unique-id
// <text> (local stacks only), --version <text>.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <thread>

#include "online/FafAuth.h"
#include "online/FafLobby.h"
#include "platform/SecretStore.h"

namespace
{
  using faf::online::FafAuth;
  using faf::online::FafLobby;

  std::string ReadFile(
    const std::filesystem::path& path
  )
  {
    std::ifstream in(path, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
      text.pop_back();
    }
    return text;
  }

  std::filesystem::path DefaultTokenFile()
  {
    const char* const local = std::getenv("LOCALAPPDATA");
    return std::filesystem::path(local != nullptr ? local : ".") / "faf-re" / "online" / "probe.token";
  }

  void Print(
    const char* const line
  )
  {
    std::printf("%s\n", line);
    std::fflush(stdout);
  }

  int Usage()
  {
    std::printf(
      "usage: faf-online-probe list|host|join [--seconds N] [--games] [--title T --map M --mod faf] [--uid N]\n"
      "       [--password P] [--token-file F | --import-plain-token F | --access-token-file F]\n"
      "       [--uid-program faf-uid.exe | --test-unique-id X] [--user-service URL] [--ws URL]\n"
      "       [--oauth URL] [--api URL] [--client-id ID] [--version V]\n"
    );
    return 2;
  }
} // namespace

int main(
  int argc,
  char** argv
)
{
  if (argc < 2) {
    return Usage();
  }
  const std::string command = argv[1];
  if (command != "list" && command != "host" && command != "join") {
    return Usage();
  }
  std::map<std::string, std::string> options;
  for (int i = 2; i < argc; ++i) {
    const std::string key = argv[i];
    if (!key.starts_with("--")) {
      return Usage();
    }
    if (key == "--games") {
      options[key] = "1";
    } else if (i + 1 < argc) {
      options[key] = argv[++i];
    } else {
      return Usage();
    }
  }
  const auto option = [&](const std::string& key, const std::string& fallback = {}) {
    const auto found = options.find(key);
    return found != options.end() ? found->second : fallback;
  };

  faf::online::FafEndpoints endpoints;
  endpoints.oauthUrl = option("--oauth", endpoints.oauthUrl);
  endpoints.apiUrl = option("--api", endpoints.apiUrl);
  endpoints.clientId = option("--client-id", endpoints.clientId);
  endpoints.scopes = "openid offline public_profile lobby";
  endpoints.tokenDescription = "faf-online-probe login";
  endpoints.approveWho = "faf-online-probe";

  faf::online::FafLobbySettings settings;
  settings.userServiceUrl = option("--user-service", settings.userServiceUrl);
  settings.webSocketUrl = option("--ws");
  settings.uidProgram = option("--uid-program");
  settings.testUniqueId = option("--test-unique-id");
  settings.version = option("--version", "0.0.0-probe");

  // --- sign-in
  // --------------------------------------------------------------------------------------------------------
  FafAuth auth(endpoints);
  auth.SetLog(Print);
  FafLobby::TokenSource tokens;
  if (const std::string file = option("--access-token-file"); !file.empty()) {
    const std::string access = ReadFile(file);
    if (access.empty()) {
      std::printf("no access token in %s\n", file.c_str());
      return 1;
    }
    tokens = [access] {
      return std::expected<std::string, std::string>(access);
    };
    std::printf("using the access token from %s\n", file.c_str());
  } else {
    const std::filesystem::path tokenFile = option("--token-file", DefaultTokenFile().string());
    std::error_code ignored;
    std::filesystem::create_directories(tokenFile.parent_path(), ignored);
    if (const std::string plain = option("--import-plain-token"); !plain.empty()) {
      const std::string refresh = ReadFile(plain);
      const auto sealed = platform::secret::Seal(refresh, endpoints.tokenDescription);
      if (refresh.empty() || !sealed) {
        std::printf("nothing to import from %s\n", plain.c_str());
        return 1;
      }
      std::ofstream(tokenFile, std::ios::binary | std::ios::trunc) << *sealed;
      std::ofstream(plain, std::ios::binary | std::ios::trunc); // its token is the probe's alone now
      std::printf(
        "imported the refresh token into %s (sealed) and emptied %s\n", tokenFile.string().c_str(), plain.c_str()
      );
    }
    auth.SetTokenFile(tokenFile);
    auth.Resume();
    auth.Wait();
    if (auth.GetState() != FafAuth::State::LoggedIn) {
      auth.StartLogin();
      bool shown = false;
      while (auth.GetState() == FafAuth::State::Working || auth.GetState() == FafAuth::State::WaitingForApproval) {
        if (!shown && auth.GetState() == FafAuth::State::WaitingForApproval) {
          std::printf("open %s and approve code %s\n", auth.VerifyUrl().c_str(), auth.UserCode().c_str());
          std::fflush(stdout);
          shown = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
      auth.Wait();
    }
    if (auth.GetState() != FafAuth::State::LoggedIn) {
      std::printf("not signed in: %s\n", auth.Message().c_str());
      return 1;
    }
    std::printf("signed in to FAF as %s\n", auth.UserName().c_str());
    tokens = [&auth] {
      const std::string access = auth.AccessToken();
      return access.empty() ? std::expected<std::string, std::string>(std::unexpected("signed out"))
                            : std::expected<std::string, std::string>(access);
    };
  }

  // --- the lobby
  // ------------------------------------------------------------------------------------------------------
  FafLobby lobby(settings);
  lobby.SetLog(Print);
  lobby.Connect(tokens);
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(60);
  while (lobby.GetState() == FafLobby::State::Connecting && std::chrono::steady_clock::now() < until) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (lobby.GetState() != FafLobby::State::SignedIn) {
    std::printf("RESULT fail: %s\n", lobby.Message().c_str());
    lobby.Disconnect();
    return 1;
  }
  std::printf("welcome: %s (id %s)\n", lobby.Login().c_str(), lobby.PlayerId().c_str());

  if (command == "host") {
    faf::online::FafHostRequest request;
    request.title = option("--title", "faf-online-probe test");
    request.mapname = option("--map", "scmp_009");
    request.featuredMod = option("--mod", "faf");
    request.password = option("--password");
    if (const auto sent = lobby.HostGame(request); !sent) {
      std::printf("RESULT fail: game_host: %s\n", sent.error().c_str());
      return 1;
    }
    std::printf(
      "sent game_host (%s on %s, %s)\n", request.title.c_str(), request.mapname.c_str(), request.featuredMod.c_str()
    );
  } else if (command == "join") {
    if (const auto sent = lobby.JoinGame(option("--uid"), option("--password")); !sent) {
      std::printf("RESULT fail: game_join: %s\n", sent.error().c_str());
      return 1;
    }
    std::printf("sent game_join %s\n", option("--uid").c_str());
  }

  const int seconds = std::max(1, std::atoi(option("--seconds", "15").c_str()));
  std::map<std::string, int> launches;
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (std::chrono::steady_clock::now() < end && lobby.GetState() == FafLobby::State::SignedIn) {
    for (const auto& message : lobby.TakeMessages()) {
      const std::string name = message.String("command");
      if (name == "notice") {
        std::printf("notice (%s): %s\n", message.String("style").c_str(), message.String("text").c_str());
      } else if (name == "game_launch") {
        std::printf(
          "game_launch: uid %s, mod %s, %zu args\n",
          message.String("uid").c_str(),
          message.String("mod").c_str(),
          message.Get("args") != nullptr ? message.Get("args")->items.size() : 0u
        );
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  const auto games = lobby.Games();
  std::map<std::string, int> byModAndState;
  for (const auto& game : games) {
    ++byModAndState[game.featuredMod + "/" + game.state];
  }
  std::printf("games: %zu\n", games.size());
  for (const auto& [key, count] : byModAndState) {
    std::printf("  %s: %d\n", key.c_str(), count);
  }
  if (!option("--games").empty()) {
    for (const auto& game : games) {
      std::printf(
        "  %s [%s/%s] %d/%d %s (%s)\n",
        game.uid.c_str(),
        game.featuredMod.c_str(),
        game.state.c_str(),
        game.numPlayers,
        game.maxPlayers,
        game.title.c_str(),
        game.mapname.c_str()
      );
    }
  }
  std::printf("messages:");
  for (const auto& [name, count] : lobby.Counts()) {
    std::printf(" %s=%d", name.c_str(), count);
  }
  std::printf("\n");
  const bool stillIn = lobby.GetState() == FafLobby::State::SignedIn;
  lobby.Disconnect();
  std::printf(
    "RESULT %s: %s\n", stillIn ? "ok" : "fail", stillIn ? "signed in, listened, disconnected" : lobby.Message().c_str()
  );
  return stillIn ? 0 : 1;
}
