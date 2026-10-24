#include "remote/client/ServerConnect.h"

#include <algorithm>
#include <array>
#include <string_view>

#include "gpg/core/containers/String.h"
#include "moho/app/WinApp.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/Common.h"

namespace gpg
{
  void Logf(const char* fmt, ...);
} // namespace gpg

namespace faf::remote
{
  namespace
  {
    // The token is opaque to the client: the server checks it. These limits only keep a
    // malformed launch line from reaching the network.
    constexpr std::size_t kMaxTokenLength = 1024;

    constexpr std::array<const char*, 8> kLockstepStartupFlags{
      "/hostgame", "/joingame", "/gpgnet", "/replay", "/load", "/scenario", "/map", "/perf",
    };

    [[nodiscard]] bool IsTokenText(const std::string_view token)
    {
      return !token.empty() && token.size() <= kMaxTokenLength
          && std::ranges::all_of(token, [](const char c) { return c > ' ' && c < 0x7F; });
    }

    [[nodiscard]] bool ReadOneArg(const char* const option, std::string& value)
    {
      msvc8::vector<msvc8::string> args;
      if (!moho::CFG_GetArgOption(option, 1, &args) || args.empty()) {
        return false;
      }
      value = args[0].c_str();
      return true;
    }
  } // namespace

  EServerConnectArgs ReadServerConnectArgs(SServerConnectRequest& request, std::string& error)
  {
    if (!moho::CFG_GetArgOption("/connectserver", 0, nullptr)) {
      return EServerConnectArgs::Absent;
    }

    for (const char* const flag : kLockstepStartupFlags) {
      if (moho::CFG_GetArgOption(flag, 0, nullptr)) {
        error = std::string{"/connectserver cannot be combined with "} + flag + ".";
        return EServerConnectArgs::Invalid;
      }
    }

    if (!ReadOneArg("/connectserver", request.endpoint)) {
      error = "/connectserver needs the server's address as host:port.";
      return EServerConnectArgs::Invalid;
    }

    u_long address = 0;
    u_short port = 0;
    if (!moho::NET_GetAddrInfo(request.endpoint.c_str(), 0, false, address, port) || port == 0) {
      error = "Invalid address:port for the game server: \"" + request.endpoint + "\".";
      return EServerConnectArgs::Invalid;
    }
    request.address = address;
    request.port = port;

    if (!ReadOneArg("/servertoken", request.token) || !IsTokenText(request.token)) {
      error = "/connectserver needs /servertoken with the token the launcher was given.";
      return EServerConnectArgs::Invalid;
    }

    return EServerConnectArgs::Valid;
  }

  EServerSessionStart StartServerSessionFromCommandLine()
  {
    SServerConnectRequest request;
    std::string error;
    switch (ReadServerConnectArgs(request, error)) {
    case EServerConnectArgs::Absent:
      return EServerSessionStart::NotRequested;
    case EServerConnectArgs::Invalid:
      moho::WIN_OkBox("Ack!", error.c_str());
      return EServerSessionStart::Failed;
    case EServerConnectArgs::Valid:
      break;
    }

    gpg::Logf("Server session requested: %s", request.endpoint.c_str());

    // The connection to the server is not written yet. Until it is, a server launch line
    // ends here rather than in a lockstep session the player did not ask for.
    moho::WIN_OkBox("Ack!", "This build cannot join server games yet.");
    return EServerSessionStart::Failed;
  }
} // namespace faf::remote
