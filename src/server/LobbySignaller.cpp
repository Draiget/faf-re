#include "server/LobbySignaller.h"

#include <algorithm>
#include <utility>

// Engine addition, dedicated server: see LobbySignaller.h.

namespace faf::server
{
  using remote::net::ELobbySignal;
  using remote::net::SLobbySignal;

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

  std::size_t CLobbySignaller::InLobby() const noexcept
  {
    return static_cast<std::size_t>(std::count_if(mParticipants.begin(), mParticipants.end(), [](const SParticipant& p) { return p.lobbied && !p.left; }));
  }

  void CLobbySignaller::Push(std::vector<SOutgoing>& out, const std::int32_t to, const SLobbySignal& signal)
  {
    out.push_back(SOutgoing{to, remote::net::EncodeLobbySignal(signal)});
  }

  void CLobbySignaller::GiveRole(SParticipant& participant, std::vector<SOutgoing>& out)
  {
    SParticipant& host = mParticipants.front();
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

  void CLobbySignaller::OnJoined(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->in || participant->left) {
      return;
    }
    participant->in = true;
    SParticipant& host = mParticipants.front();
    if (mHostLeft || !host.in) {
      return; // its role waits for the host
    }
    if (participant == &host) {
      GiveRole(host, out);
      for (SParticipant& other : mParticipants) {
        if (&other != &host && other.in && !other.left && !other.lobbied) {
          GiveRole(other, out);
        }
      }
      return;
    }
    GiveRole(*participant, out);
  }

  void CLobbySignaller::OnLeft(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    SParticipant* const participant = Find(uid);
    if (participant == nullptr || participant->left) {
      return;
    }
    participant->left = true;
    if (participant == &mParticipants.front()) {
      mHostLeft = true;
    }
    if (!participant->lobbied) {
      return;
    }
    for (const SParticipant& other : mParticipants) {
      if (&other != participant && other.lobbied && !other.left) {
        Push(out, other.uid, SLobbySignal{ELobbySignal::DisconnectFromPeer, 0, uid, participant->name, {}});
      }
    }
  }
} // namespace faf::server
