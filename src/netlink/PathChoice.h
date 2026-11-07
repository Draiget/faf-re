#pragma once

// Issue #322: the path a player picked for one link in the network panel. Auto is
// the Java adapter's policy (every candidate type on the first attempt, then fewer
// as attempts fail within 2 minutes). The others hold for the link's later
// attempts too, until the player picks Auto again.

#include <cstdint>
#include <string>

namespace faf::netlink
{
  struct PathChoice
  {
    enum class Mode : std::uint8_t
    {
      Auto,
      RelayOnly, // relayed candidates only, ours and the peer's
      NoRelay,   // host and reflexive candidates only, whatever the attempt count
    };
    Mode mode = Mode::Auto;
    // With RelayOnly: only this TURN server's relay ("host:port"); empty: any of them.
    std::string turnServer;

    bool operator==(const PathChoice& other) const { return mode == other.mode && turnServer == other.turnServer; }
  };

  // "auto", "relay only", "relay via host:port", "no relay".
  [[nodiscard]] inline std::string PathChoiceText(const PathChoice& choice)
  {
    switch (choice.mode) {
      case PathChoice::Mode::RelayOnly:
        return choice.turnServer.empty() ? "relay only" : "relay via " + choice.turnServer;
      case PathChoice::Mode::NoRelay: return "no relay";
      default: return "auto";
    }
  }
} // namespace faf::netlink
