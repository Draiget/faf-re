#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Engine addition, dedicated server (plan WPR.45, WPR.47, WPR.48): the kernel's half of the address allowlist. The
// server writes an nftables ruleset for its port from the match's `MatchAddresses` (`--nftables-out <file>`,
// `--nftables-only` to write it and stop), which the deployment loads (`nft -f <file>`) before the server opens the
// port. The process keeps its own checks (`CGameLinks::AllowAddress`, the unlisted handshake budget, AEAD): the ruleset
// is what keeps a flood from an unlisted address from reaching the process at all.
//
// Listed addresses pass. Unlisted ones either never reach the process (`unlistedPerSourcePps` 0: a strict list) or
// pass two kernel rate limits, one per source address and one for all of them, into the server's stateless challenge,
// where a valid token admits a player whose address FAF didn't report (a VPN, plan R18). The limits are per source so
// one flooding address can't take what an admitted player's game traffic needs; a player's channel sends tens of
// datagrams a second. The server process isn't given the right to change the ruleset: an admitted player stays on the
// per-source limit, which a game's traffic fits.

namespace faf::server
{
  struct SNftablesConfig
  {
    std::uint16_t port = 0;
    std::vector<std::uint32_t> listed;      // IPv4, host order (`SEndpoint::ip`)
    std::uint32_t unlistedPerSourcePps = 0; // 0: unlisted addresses are dropped in the kernel
    std::uint32_t unlistedTotalPps = 0;     // all unlisted sources together; 0: no total cap
  };

  [[nodiscard]] inline std::string NftablesAddressText(
    const std::uint32_t ip
  )
  {
    return std::to_string((ip >> 24) & 0xFFu) + "." + std::to_string((ip >> 16) & 0xFFu) + "." +
      std::to_string((ip >> 8) & 0xFFu) + "." + std::to_string(ip & 0xFFu);
  }

  /**
   * The ruleset: its own table, `inet faf_server_<port>` (deleted and made again, so loading it twice is the same as
   * once), an input chain ahead of the usual filter (priority -10) that only looks at UDP to the port.
   */
  [[nodiscard]] inline std::string MakeNftablesRuleset(
    const SNftablesConfig& config
  )
  {
    const std::string port = std::to_string(config.port);
    const std::string table = "faf_server_" + port;
    std::string out;
    out += "# Written by the dedicated server for UDP port " + port +
      " (plan WPR.45): load with nft -f before the server starts.\n";
    out += "table inet " + table + "\n";
    out += "delete table inet " + table + "\n";
    out += "table inet " + table + " {\n";
    out += "  set listed4 {\n    type ipv4_addr\n";
    if (!config.listed.empty()) {
      out += "    elements = { ";
      for (std::size_t i = 0; i < config.listed.size(); ++i) {
        out += (i == 0 ? "" : ", ") + NftablesAddressText(config.listed[i]);
      }
      out += " }\n";
    }
    out += "  }\n";
    out += "  chain input {\n    type filter hook input priority -10; policy accept;\n";
    out += "    udp dport " + port + " ip saddr @listed4 counter accept comment \"listed\"\n";
    if (config.unlistedPerSourcePps > 0) {
      if (config.unlistedTotalPps > 0) {
        out += "    udp dport " + port + " limit rate over " + std::to_string(config.unlistedTotalPps) +
          "/second counter drop comment \"unlisted, over the total\"\n";
      }
      const std::string perSource = std::to_string(config.unlistedPerSourcePps);
      out += "    udp dport " + port + " meter " + table + "_unlisted4 { ip saddr limit rate " + perSource +
        "/second burst " + perSource + " packets } counter accept comment \"unlisted, into the challenge\"\n";
    }
    out += "    udp dport " + port + " counter drop comment \"unlisted\"\n";
    out += "  }\n}\n";
    return out;
  }
} // namespace faf::server
