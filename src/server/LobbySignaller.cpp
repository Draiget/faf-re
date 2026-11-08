#include "server/LobbySignaller.h"

#include <algorithm>
#include <cctype>
#include <utility>

// Engine addition, dedicated server: see LobbySignaller.h.

namespace faf::server
{
  using remote::net::ELobbySignal;
  using remote::net::SLobbySignal;

  std::string CheckLaunch(const SLaunchFacts& requested, const SLaunchFacts& match)
  {
    const auto lower = [](std::string text) {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    };
    if (lower(requested.scenario) != lower(match.scenario)) {
      return "the map isn't the match's (" + match.scenario + ")";
    }
    std::vector<std::int32_t> asked = requested.humans;
    std::vector<std::int32_t> seats = match.humans;
    std::sort(asked.begin(), asked.end());
    std::sort(seats.begin(), seats.end());
    if (asked != seats) {
      return "the players in the slots aren't the match's";
    }
    if (requested.gameMods > 0) {
      return "a dedicated server runs no sim mods";
    }
    return {};
  }

  CLobbySignaller::CLobbySignaller(std::string scenario, const std::uint8_t flags)
    : mScenario(std::move(scenario))
    , mFlags(flags)
  {}

  void CLobbySignaller::AddParticipant(const std::int32_t uid, std::string name)
  {
    if (uid > 0 && Find(uid) == nullptr) {
      mParticipants.push_back(SParticipant{uid, std::move(name)});
    }
  }

  CLobbySignaller::SParticipant* CLobbySignaller::Find(const std::int32_t uid) noexcept
  {
    const auto found = std::find_if(mParticipants.begin(), mParticipants.end(), [uid](const SParticipant& p) { return p.uid == uid; });
    return found == mParticipants.end() ? nullptr : &*found;
  }

  std::int32_t CLobbySignaller::Host() const noexcept
  {
    return mParticipants.empty() || mHostLeft ? 0 : mParticipants[mHost].uid;
  }

  std::size_t CLobbySignaller::InLobby() const noexcept
  {
    return static_cast<std::size_t>(std::count_if(mParticipants.begin(), mParticipants.end(), [](const SParticipant& p) { return p.lobbied && !p.left; }));
  }

  std::vector<std::int32_t> CLobbySignaller::InLobbyUids() const
  {
    std::vector<std::int32_t> uids;
    for (const SParticipant& p : mParticipants) {
      if (p.lobbied && !p.left) {
        uids.push_back(p.uid);
      }
    }
    return uids;
  }

  void CLobbySignaller::Push(std::vector<SOutgoing>& out, const std::int32_t to, const SLobbySignal& signal)
  {
    out.push_back(SOutgoing{to, remote::net::EncodeLobbySignal(signal)});
  }

  void CLobbySignaller::GiveRole(SParticipant& participant, std::vector<SOutgoing>& out)
  {
    SParticipant& host = mParticipants[mHost];
    participant.lobbied = true;
    if (&participant == &host) {
      Push(out, host.uid, SLobbySignal{ELobbySignal::Host, mFlags, 0, host.name, mScenario});
      return;
    }
    // The host first learns whom to accept, then the joiner learns whom to join: its `Join` reaches the host after.
    Push(out, host.uid, SLobbySignal{ELobbySignal::ConnectToPeer, 0, participant.uid, participant.name, {}});
    Push(out, participant.uid, SLobbySignal{ELobbySignal::Join, mFlags, host.uid, participant.name, host.name});
    for (const SParticipant& other : mParticipants) {
      if (&other == &host || &other == &participant || !other.lobbied || other.left) {
        continue;
      }
      Push(out, other.uid, SLobbySignal{ELobbySignal::ConnectToPeer, 0, participant.uid, participant.name, {}});
      Push(out, participant.uid, SLobbySignal{ELobbySignal::ConnectToPeer, 0, other.uid, other.name, {}});
    }
  }

  void CLobbySignaller::GiveRoles(std::vector<SOutgoing>& out)
  {
    SParticipant& host = mParticipants[mHost];
    if (!host.in || host.left || host.away) {
      return; // the roles wait for the host
    }
    if (!host.lobbied) {
      GiveRole(host, out);
    }
    for (SParticipant& other : mParticipants) {
      if (&other != &host && other.in && !other.left && !other.away && !other.lobbied) {
        GiveRole(other, out);
      }
    }
  }

  void CLobbySignaller::Succeed(std::vector<SOutgoing>& out)
  {
    // The next in the match's order after the host who hasn't left: one whose channel is up, else one still to come,
    // else one that is away too (whose roles then wait for it to be heard again).
    const std::size_t count = mParticipants.size();
    std::size_t next = count;
    for (int pass = 0; pass < 3 && next == count; ++pass) {
      for (std::size_t step = 1; step < count && next == count; ++step) {
        const SParticipant& candidate = mParticipants[(mHost + step) % count];
        const bool fits = pass == 0 ? candidate.in && !candidate.away : pass == 1 ? !candidate.away : true;
        if (!candidate.left && fits) {
          next = (mHost + step) % count;
        }
      }
    }
    if (next == count) {
      // Nobody to take over: a host that's only away may still come back; one that left ends the lobby.
      mHostLeft = mParticipants[mHost].left;
      return;
    }
    mHost = next;
    ++mSuccessions;
    // Every lobby was the old host's: each participant starts its own again from its new role.
    for (SParticipant& participant : mParticipants) {
      participant.lobbied = false;
    }
    GiveRoles(out);
  }

  void CLobbySignaller::OnJoined(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->in || participant->left) {
      return;
    }
    participant->in = true;
    if (mHostLeft) {
      return;
    }
    const SParticipant& host = mParticipants[mHost];
    if (host.away) {
      Succeed(out); // a host gone quiet that nobody could take over from until now
      return;
    }
    if (IsHost(*participant)) {
      GiveRoles(out);
    } else if (host.lobbied) {
      GiveRole(*participant, out);
    }
    // Otherwise its role waits for the host.
  }

  void CLobbySignaller::OnLeft(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->left) {
      return;
    }
    const bool hadRole = participant->lobbied;
    participant->left = true;
    participant->lobbied = false;
    if (IsHost(*participant)) {
      Succeed(out); // the new roles replace the old host's lobby: no `DisconnectFromPeer` for it
      return;
    }
    if (!hadRole) {
      return;
    }
    for (const SParticipant& other : mParticipants) {
      if (&other != participant && other.lobbied && !other.left) {
        Push(out, other.uid, SLobbySignal{ELobbySignal::DisconnectFromPeer, 0, uid, participant->name, {}});
      }
    }
  }

  void CLobbySignaller::OnAway(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->left || participant->away) {
      return;
    }
    participant->away = true;
    if (IsHost(*participant) && !mHostLeft) {
      Succeed(out);
    }
  }

  void CLobbySignaller::OnBack(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->left || !participant->away) {
      return;
    }
    participant->away = false;
    if (mHostLeft) {
      return;
    }
    const SParticipant& host = mParticipants[mHost];
    if (host.away) {
      Succeed(out); // the host went quiet while nobody could take over: this one can
      return;
    }
    if (participant->lobbied || !participant->in) {
      return; // its role is still the current host's, or it isn't in yet
    }
    if (IsHost(*participant)) {
      GiveRoles(out);
    } else if (host.lobbied) {
      GiveRole(*participant, out); // roles went out while it was away: the old host joins the new one
    }
  }
} // namespace faf::server
