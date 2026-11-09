// faf-netbridge: launcher-compatible replacement for FAF's Java ICE adapter
// (issue #230). Takes the adapter's command line:
//
//   faf-netbridge --id <id> --game-id <id> --login <login> --rpc-port <port> --gpgnet-port <port>
//                 [--force-relay] [--lobby-port <port>] [--bind-address <ip>] [--log-file <path>]
//
// FAF_NETBRIDGE_BIND_ADDRESS and FAF_NETBRIDGE_GAME_ADDRESS stand in for
// --bind-address and --game-address (docs/NETBRIDGE.md).
//
// The log goes to stderr and to --log-file, else to $LOG_DIR/faf-netbridge.log
// when the launcher sets LOG_DIR. Engine addition, not recovered code.

#include "netbridge/Bridge.h"

#include <cstdlib>

int main(int argc, char** argv)
{
  using namespace faf::netbridge;
  BridgeOptions options = ParseBridgeArgs(argc, argv);
  // Test machines only: the launch shim passes the launcher's arguments, so
  // the two test addresses can also come from the environment.
  if (const char* bind = std::getenv("FAF_NETBRIDGE_BIND_ADDRESS"); bind != nullptr && options.bindAddress.empty()) {
    options.bindAddress = bind;
  }
  if (const char* game = std::getenv("FAF_NETBRIDGE_GAME_ADDRESS"); game != nullptr && *game != 0) {
    options.gameAddress = game;
  }
  if (const char* webrtc = std::getenv("FAF_NETBRIDGE_WEBRTC"); webrtc != nullptr && *webrtc == '1') {
    options.webrtc = true; // issue #239, for runs through the launch shim
  }
  if (const char* redundancy = std::getenv("FAF_NETBRIDGE_REDUNDANCY"); redundancy != nullptr) {
    options.redundancy = std::atoi(redundancy); // issue #240, for runs through the launch shim
  }
  if (const char* encrypt = std::getenv("FAF_NETBRIDGE_ENCRYPT"); encrypt != nullptr && *encrypt == '0') {
    options.encrypt = false; // issue #289, for runs through the launch shim
  }
  if (options.logPath.empty()) {
    if (const char* dir = std::getenv("LOG_DIR"); dir != nullptr && *dir != '\0') {
      options.logPath = std::string(dir) + "/faf-netbridge.log";
    }
  }
  Logger log(options.logPath);
  if (!SocketsInit()) {
    log.Write("socket initialisation failed");
    return 1;
  }
  if (options.rpcPort == 0 || options.gpgnetPort == 0) {
    log.Write("usage: faf-netbridge --id <id> --login <login> --rpc-port <port> --gpgnet-port <port> ...");
    return 2;
  }
  Bridge bridge(options, log);
  return bridge.Run();
}
