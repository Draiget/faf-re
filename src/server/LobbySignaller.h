#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "remote/net/LobbySignals.h"

// Engine addition, dedicated server (plan WP2.2, WP2.5, WP2.12; design research/WP2.13-lobby-relay-design.md): what the
// server tells each participant's game about the lobby, as FAF's lobby server does over GPGNet today. The match's first
// participant is the logical host: its unchanged FAF lobby runs the host's logic and its `CLobby` is the lobby's network
// host. A participant is "in" once its channel to the server is up; it gets its role once the logical host is in too:
// the host `Host`, every other `Join` with the host's uid. Then each pair of participants with a role is introduced
// both ways (`ConnectToPeer`), the logical host's introduction first, so the side that accepts a connection always
// knows it before the other side's first message arrives (the server's stream to a participant is in order). Whoever
// leaves is announced to the rest (`DisconnectFromPeer`). No sockets: what it returns goes out as `Lobby` frames from
// uid 0.

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

    /** The logical host's uid, or 0 without participants. */
    [[nodiscard]] std::int32_t Host() const noexcept { return mParticipants.empty() ? 0 : mParticipants.front().uid; }
    /** Participants who have their role and haven't left. */
    [[nodiscard]] std::size_t InLobby() const noexcept;
    [[nodiscard]] std::vector<std::int32_t> InLobbyUids() const;
    /** The logical host left before launch: the lobby can't go on (no succession yet). */
    [[nodiscard]] bool HostLeft() const noexcept { return mHostLeft; }

  private:
    struct SParticipant
    {
      std::int32_t uid = 0;
      std::string name;
      bool in = false;     // channel up
      bool lobbied = false; // has its role
      bool left = false;
    };

    void GiveRole(SParticipant& participant, std::vector<SOutgoing>& out);
    static void Push(std::vector<SOutgoing>& out, std::int32_t to, const remote::net::SLobbySignal& signal);
    [[nodiscard]] SParticipant* Find(std::int32_t uid) noexcept;

    std::string mScenario;
    std::uint8_t mFlags = 0;
    std::vector<SParticipant> mParticipants; // in the match's order
    bool mHostLeft = false;
  };
} // namespace faf::server
