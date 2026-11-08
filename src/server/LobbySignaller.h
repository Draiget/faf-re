#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "remote/net/LobbySignals.h"

// Engine addition, dedicated server (plan WP2.2, WP2.5, WP2.12, WPR.50; design research/WP2.13-lobby-relay-design.md):
// what the server tells each participant's game about the lobby, as FAF's lobby server does over GPGNet today. The
// match's first participant is the logical host: its unchanged FAF lobby runs the host's logic and its `CLobby` is the
// lobby's network host. A participant is "in" once its channel to the server is up; it gets its role once the logical
// host is in too: the host `Host`, every other `Join` with the host's uid. Then each pair of participants with a role
// is introduced both ways (`ConnectToPeer`), the logical host's introduction first, so the side that accepts a
// connection always knows it before the other side's first message arrives (the server's stream to a participant is
// in order). Whoever leaves is announced to the rest (`DisconnectFromPeer`). No sockets: what it returns goes out as
// `Lobby` frames from uid 0.
//
// Plan WPR.50, succession: when the logical host leaves, or goes quiet (`OnAway`), the next participant in the match's
// order who is here takes over (one whose channel is up first, else one still to come), and every participant gets its
// role again: a new `Host` or `Join` tells a game that already has a lobby to start it again (moho/app/ServerLobbyUi),
// as a lobby whose host is gone can't go on. A participant that was away when the roles were given out gets its role
// when it is heard again (`OnBack`), the old host as a joiner.

namespace faf::server
{
  /** What a launch check compares (plan WP2.14), read from a game configuration (`CLobby::LaunchGame`'s table). */
  struct SLaunchFacts
  {
    std::string scenario;             // GameOptions.ScenarioFile
    std::vector<std::int32_t> humans; // OwnerID of each human in PlayerOptions, sorted
    int gameMods = 0;                 // entries in GameMods: FAF's lobby puts only sim mods there
  };

  /**
   * Plan WP2.14: the host's launch against the match: the same scenario (case aside), the same human seats by uid,
   * no sim mods. Empty when it may launch, otherwise the reason, for the host's lobby.
   */
  [[nodiscard]] std::string CheckLaunch(const SLaunchFacts& requested, const SLaunchFacts& match);

  class CLobbySignaller
  {
  public:
    /** A signal for one participant. */
    struct SOutgoing
    {
      std::int32_t to = 0;
      std::vector<std::uint8_t> message;
    };

    /** `scenario`: the map the logical host's lobby starts with. `flags`: `ELobbySignalFlags` for `Host` and `Join`. */
    explicit CLobbySignaller(std::string scenario, std::uint8_t flags = 0);

    /** A participant of the match, in the match's order (the first is the logical host), by uid and FAF name. */
    void AddParticipant(std::int32_t uid, std::string name);

    /** `uid`'s channel is up for the first time. */
    void OnJoined(std::int32_t uid, std::vector<SOutgoing>& out);
    /** `uid` has left (out of the game, or its connection gone for good). */
    void OnLeft(std::int32_t uid, std::vector<SOutgoing>& out);
    /** Plan WPR.50: nothing has come from `uid` for a while; it may come back. A logical host that does is succeeded. */
    void OnAway(std::int32_t uid, std::vector<SOutgoing>& out);
    /** `uid` is heard again after `OnAway`: a role given out while it was away is given to it now. */
    void OnBack(std::int32_t uid, std::vector<SOutgoing>& out);

    /** The logical host's uid, or 0 without participants or once nobody can host. */
    [[nodiscard]] std::int32_t Host() const noexcept;
    /** Participants who have their role and haven't left. */
    [[nodiscard]] std::size_t InLobby() const noexcept;
    [[nodiscard]] std::vector<std::int32_t> InLobbyUids() const;
    /** The logical host left before launch and nobody is left to take over: the lobby can't go on. */
    [[nodiscard]] bool HostLeft() const noexcept { return mHostLeft; }
    /** Times the logical host has been succeeded. */
    [[nodiscard]] unsigned Successions() const noexcept { return mSuccessions; }

  private:
    struct SParticipant
    {
      std::int32_t uid = 0;
      std::string name;
      bool in = false;      // channel up
      bool lobbied = false; // has its role, from the current logical host
      bool left = false;
      bool away = false;    // quiet for a while (`OnAway`), not left
    };

    void GiveRole(SParticipant& participant, std::vector<SOutgoing>& out);
    /** Every participant here gets its role (from the current logical host), the host's first. */
    void GiveRoles(std::vector<SOutgoing>& out);
    /** The logical host has left or gone away: the next who can host takes over. */
    void Succeed(std::vector<SOutgoing>& out);
    static void Push(std::vector<SOutgoing>& out, std::int32_t to, const remote::net::SLobbySignal& signal);
    [[nodiscard]] SParticipant* Find(std::int32_t uid) noexcept;
    [[nodiscard]] bool IsHost(const SParticipant& participant) const noexcept { return &participant == &mParticipants[mHost]; }

    std::string mScenario;
    std::uint8_t mFlags = 0;
    std::vector<SParticipant> mParticipants; // in the match's order
    std::size_t mHost = 0;                   // the logical host's index
    bool mHostLeft = false;
    unsigned mSuccessions = 0;
  };
} // namespace faf::server
