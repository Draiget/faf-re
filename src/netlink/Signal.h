#pragma once

// Signalling of FAF's Java ICE adapter (java-ice-adapter 3.3.14,
// CandidatesMessage / CandidatePacket records) and the ICE server list of
// setIceServers, with their conversion to libjuice's SDP lines.
// docs/LAUNCHER_ADAPTER_CONTRACT.md §2 and §5. Engine addition.

#include "netlink/Json.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace faf::netlink
{
  // ice4j's CandidateType, written by Jackson as the enum name.
  enum class CandidateType
  {
    Host,           // HOST_CANDIDATE
    ServerReflexive, // SERVER_REFLEXIVE_CANDIDATE
    PeerReflexive,  // PEER_REFLEXIVE_CANDIDATE
    Relayed,        // RELAYED_CANDIDATE
    Local,          // LOCAL_CANDIDATE (old name of host, never sent)
    Stun            // STUN_CANDIDATE (old name of srflx, never sent)
  };

  const char* CandidateTypeName(CandidateType type);
  std::optional<CandidateType> ParseCandidateType(std::string_view name);

  struct Candidate
  {
    std::string foundation;
    std::string protocol = "udp";
    std::int64_t priority = 0;
    std::string ip;
    int port = 0;
    CandidateType type = CandidateType::Host;
    int generation = 0;
    std::string id;
    std::optional<std::string> relAddr; // null in JSON when absent
    int relPort = 0;
  };

  struct CandidatesMessage
  {
    std::int64_t srcId = 0;
    std::int64_t destId = 0;
    std::string password;
    std::string ufrag;
    std::vector<Candidate> candidates;
    // Issue #322, ours only: the path the sender's player picked ("auto", "relay",
    // "norelay"), for the receiver to follow on this attempt. Sent only to a peer
    // whose ufrag shows it runs our engine: the Java adapter rejects unknown fields.
    std::string fafPath;
  };

  // Jackson's output for the records: fields in declaration order, nothing
  // else (the Java side rejects unknown fields).
  std::string ToJson(const CandidatesMessage& msg);
  // Accepts what Jackson accepts and ignores unknown fields.
  std::optional<CandidatesMessage> CandidatesMessageFromJson(std::string_view text, std::string* error = nullptr);

  // libjuice's "a=candidate:<foundation> <component> <transport> <priority>
  // <ip> <port> typ <type> [raddr <ip> rport <port>]" line, with or without
  // the "a=" prefix.
  std::optional<Candidate> CandidateFromSdp(std::string_view line);
  std::string CandidateToSdp(const Candidate& c);

  struct IceServer
  {
    enum class Kind
    {
      Stun,
      Turn
    };
    Kind kind = Kind::Stun;
    std::string host;
    std::uint16_t port = 3478;
    std::string username;
    std::string credential;
  };

  // "host:port", as the network panel names a server (#322).
  [[nodiscard]] inline std::string IceServerName(const IceServer& s)
  {
    return s.host + ":" + std::to_string(s.port);
  }

  // setIceServers' list of {urls|url, username, credential}. Each URL may be
  // "turn:h:p?transport=udp" or "turn://h:p?transport=udp" (the Java adapter
  // only takes the second, contract §2); stun: likewise. TURN over TCP or TLS
  // (transport=tcp, turns:) is skipped: libjuice relays over UDP only.
  std::vector<IceServer> ParseIceServers(const JsonValue& list);
} // namespace faf::netlink
