// Gathers ICE candidates with libjuice against one STUN/TURN server and checks
// that host, server-reflexive and (with credentials) relayed candidates come
// back (issue #228). The server is tools/turnsrv, e.g. as fafclient starts it.
//
//   faf_juice_gather <host> <port> [<turn user> <turn password>]
//
// Exit code 0 when every expected candidate type was gathered.

#include <juice/juice.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace
{
  struct Gathered
  {
    std::atomic<int> host{0};
    std::atomic<int> srflx{0};
    std::atomic<int> relay{0};
    std::atomic<bool> done{false};
  };

  void OnCandidate(juice_agent_t*, const char* sdp, void* user)
  {
    auto* g = static_cast<Gathered*>(user);
    std::printf("candidate: %s\n", sdp);
    if (std::strstr(sdp, " typ host") != nullptr) {
      ++g->host;
    } else if (std::strstr(sdp, " typ srflx") != nullptr) {
      ++g->srflx;
    } else if (std::strstr(sdp, " typ relay") != nullptr) {
      ++g->relay;
    }
  }

  void OnGatheringDone(juice_agent_t*, void* user)
  {
    static_cast<Gathered*>(user)->done = true;
  }
} // namespace

int main(int argc, char** argv)
{
  if (argc != 3 && argc != 5) {
    std::fprintf(stderr, "usage: %s <host> <port> [<turn user> <turn password>]\n", argv[0]);
    return 2;
  }
  const std::string host = argv[1];
  const auto port = static_cast<uint16_t>(std::atoi(argv[2]));
  const bool withTurn = argc == 5;

  juice_set_log_level(JUICE_LOG_LEVEL_WARN);

  Gathered gathered;
  juice_turn_server_t turn{};
  turn.host = host.c_str();
  turn.port = port;
  if (withTurn) {
    turn.username = argv[3];
    turn.password = argv[4];
  }

  juice_config_t config{};
  config.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
  config.stun_server_host = host.c_str();
  config.stun_server_port = port;
  config.turn_servers = withTurn ? &turn : nullptr;
  config.turn_servers_count = withTurn ? 1 : 0;
  config.cb_candidate = &OnCandidate;
  config.cb_gathering_done = &OnGatheringDone;
  config.user_ptr = &gathered;

  juice_agent_t* agent = juice_create(&config);
  if (agent == nullptr) {
    std::fprintf(stderr, "juice_create failed\n");
    return 1;
  }
  char sdp[JUICE_MAX_SDP_STRING_LEN];
  juice_get_local_description(agent, sdp, sizeof(sdp));
  std::printf("local description:\n%s", sdp);
  juice_gather_candidates(agent);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (!gathered.done && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  juice_destroy(agent);

  std::printf("gathering %s: host=%d srflx=%d relay=%d\n", gathered.done ? "done" : "timed out",
              gathered.host.load(), gathered.srflx.load(), gathered.relay.load());
  const bool ok = gathered.done && gathered.host > 0 && gathered.srflx > 0 && (!withTurn || gathered.relay > 0);
  std::printf("%s\n", ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
