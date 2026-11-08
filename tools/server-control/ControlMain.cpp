// faf_server_control: a client of the dedicated server's control API (plan WP17.2, research/WP17.2-control-api.md),
// for operators and tests. Linux.
//
//   faf_server_control --server <ip:port> --key <file> --op <status|force_start|pause|resume|eject|allow|disallow>
//                      [--uid <n>] [--reason <text>] [--address <a.b.c.d>] [--options <Key=Value,...>] [--results <army=victory|defeat|draw,...>] [--count <n>] [--token <text>] [--name <text>] [--watch <seconds>] [--wrong-key]
//
// Prints the reply, then the events (the server's console lines) until --watch seconds have passed. --wrong-key flips
// one bit of the key, to check the server refuses it. Exit: 0 the request was answered ok, 1 refused, 2 no
// connection or the handshake failed, 4 bad arguments.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <span>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "remote/net/Handshake.h"
#include "remote/net/UdpSocket.h"
#include "server/ControlChannel.h"

namespace
{
  using faf::server::CControlChannel;

  [[nodiscard]] bool ReadExactly(const int socket, std::uint8_t* out, std::size_t size)
  {
    while (size > 0u) {
      const ssize_t got = ::recv(socket, out, size, 0);
      if (got <= 0) {
        return false;
      }
      out += got;
      size -= static_cast<std::size_t>(got);
    }
    return true;
  }

  [[nodiscard]] bool SendAll(const int socket, const std::uint8_t* data, std::size_t size)
  {
    while (size > 0u) {
      const ssize_t sent = ::send(socket, data, size, MSG_NOSIGNAL);
      if (sent <= 0) {
        return false;
      }
      data += sent;
      size -= static_cast<std::size_t>(sent);
    }
    return true;
  }

  [[nodiscard]] std::string Quote(const std::string& text)
  {
    std::string out = "\"";
    for (const char c : text) {
      if (c == '"' || c == '\\') {
        out += '\\';
      }
      out += c;
    }
    return out + "\"";
  }
} // namespace

int main(int argc, char** argv)
{
  std::string server;
  std::string keyPath;
  std::string op;
  std::string reason;
  std::string addressText;
  std::string optionsText;
  std::string resultsText;
  std::string tokenText;
  std::string nameText;
  long long uid = 0;
  long long count = 0;
  double watch = 0.0;
  bool wrongKey = false;
  for (int i = 1; i < argc; ++i) {
    const std::string name = argv[i];
    if (name == "--wrong-key") {
      wrongKey = true;
      continue;
    }
    if (i + 1 >= argc) {
      std::fprintf(stderr, "%s needs a value\n", name.c_str());
      return 4;
    }
    const std::string value = argv[++i];
    if (name == "--server") {
      server = value;
    } else if (name == "--key") {
      keyPath = value;
    } else if (name == "--op") {
      op = value;
    } else if (name == "--uid") {
      uid = std::atoll(value.c_str());
    } else if (name == "--count") {
      count = std::atoll(value.c_str());
    } else if (name == "--reason") {
      reason = value;
    } else if (name == "--address") {
      addressText = value;
    } else if (name == "--options") {
      optionsText = value;
    } else if (name == "--results") {
      resultsText = value;
    } else if (name == "--token") {
      tokenText = value;
    } else if (name == "--name") {
      nameText = value;
    } else if (name == "--watch") {
      watch = std::atof(value.c_str());
    } else {
      std::fprintf(stderr, "unknown option %s\n", name.c_str());
      return 4;
    }
  }
  faf::remote::net::SEndpoint at;
  faf::server::ControlKey key{};
  std::ifstream keyFile(keyPath);
  std::stringstream keyText;
  keyText << keyFile.rdbuf();
  if (op.empty() || !faf::remote::net::ParseEndpoint(server, at) || !keyFile || !faf::server::ReadControlKey(keyText.str(), key)) {
    std::fprintf(stderr, "usage: faf_server_control --server <ip:port> --key <file> --op <op> [--uid n] [--reason text] [--watch s] [--wrong-key]\n");
    return 4;
  }
  if (wrongKey) {
    key[0] ^= 1u;
  }

  const int socket = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(at.port);
  address.sin_addr.s_addr = htonl(at.ip);
  if (socket < 0 || ::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
    std::printf("control: no connection to %s\n", server.c_str());
    return 2;
  }
  faf::server::ControlNonce nonce{};
  (void)faf::remote::net::FillRandom(nonce.data(), nonce.size());
  CControlChannel channel(key, faf::server::EControlRole::Service, nonce);
  faf::server::ControlNonce serverNonce{};
  faf::server::ControlProof serverProof{};
  if (!SendAll(socket, nonce.data(), nonce.size()) || !ReadExactly(socket, serverNonce.data(), serverNonce.size())) {
    std::printf("control: the server closed the connection before its nonce\n");
    return 2;
  }
  const faf::server::ControlProof proof = channel.Proof(serverNonce);
  if (!SendAll(socket, proof.data(), proof.size()) || !ReadExactly(socket, serverProof.data(), serverProof.size())) {
    std::printf("control: the server closed the connection during the handshake\n");
    return 2;
  }
  if (!channel.CheckPeerProof(serverProof)) {
    std::printf("control: the server's proof doesn't match this key: refused\n");
    return 2;
  }
  std::string request = "{\"id\":1,\"op\":" + Quote(op);
  if (uid != 0) {
    request += ",\"uid\":" + std::to_string(uid);
  }
  if (count != 0) {
    request += ",\"count\":" + std::to_string(count);
  }
  if (!reason.empty()) {
    request += ",\"reason\":" + Quote(reason);
  }
  if (!addressText.empty()) {
    request += ",\"address\":" + Quote(addressText);
  }
  if (!optionsText.empty()) {
    request += ",\"options\":" + Quote(optionsText);
  }
  if (!resultsText.empty()) {
    request += ",\"results\":" + Quote(resultsText);
  }
  if (!tokenText.empty()) {
    request += ",\"token\":" + Quote(tokenText);
  }
  if (!nameText.empty()) {
    request += ",\"name\":" + Quote(nameText);
  }
  request += "}";
  const std::vector<std::uint8_t> frame = channel.Seal(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(request.data()), request.size()));
  if (!SendAll(socket, frame.data(), frame.size())) {
    std::printf("control: the request didn't go\n");
    return 2;
  }

  int exitCode = 2;
  bool answered = false;
  const auto start = std::chrono::steady_clock::now();
  std::uint8_t buffer[16384];
  for (;;) {
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    const double limit = answered ? watch : std::max(watch, 10.0);
    if (elapsed >= limit) {
      break;
    }
    pollfd waiting{socket, POLLIN, 0};
    if (::poll(&waiting, 1, static_cast<int>((limit - elapsed) * 1000.0) + 1) <= 0) {
      continue;
    }
    const ssize_t got = ::recv(socket, buffer, sizeof(buffer), 0);
    if (got <= 0) {
      std::printf("control: the server closed the connection\n");
      break;
    }
    if (!channel.Feed(std::span<const std::uint8_t>(buffer, static_cast<std::size_t>(got)))) {
      std::printf("control: a frame from the server didn't open\n");
      break;
    }
    std::vector<std::uint8_t> message;
    while (channel.Take(message)) {
      const std::string text(message.begin(), message.end());
      std::printf("control: %s\n", text.c_str());
      if (!answered && text.rfind("{\"id\":1,", 0) == 0) {
        answered = true;
        exitCode = text.find("\"ok\":true") != std::string::npos ? 0 : 1;
      }
    }
    std::fflush(stdout);
  }
  ::close(socket);
  return exitCode;
}
