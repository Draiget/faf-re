#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"

namespace moho
{
  class CWldSession;
  class ISTIDriver;
  class STIMap;
  struct SWldSessionInfo;

  /**
   * Engine addition: moving through a replay in the viewer. All of it is on the main thread, except that
   * the sim driver's issue thread reads `gReplayFastForward`.
   *
   * Going forward plays the beats in between with the world not drawn, or restores a keyframe further on when
   * there is one. Going back keeps the session, with its map, UI and camera, and what it draws until the target
   * is reached, and replaces the sim behind it with one from the newest keyframe at or before the
   * target, or from the replay's start, then plays forward. The sim only ever runs recorded beats, from a state a
   * headless test proves identical, so nothing here decides what the game does.
   */

  /** While set, the driver issues beats as fast as the sim takes them, and the session applies them as they come. */
  inline std::atomic<bool> gReplayFastForward{false};

  /** `VCR_SetupReplaySession` for a viewer: remembers the file and its length, for the bar and for restarts. */
  [[nodiscard]] fa::auto_ptr<SWldSessionInfo> REPLAY_SetupViewerSession(const char* path, fa::string* failureReason);

  [[nodiscard]] std::int32_t REPLAY_TotalTicks();

  /** The ticks a move can start from without playing the replay from further back, in order. */
  [[nodiscard]] std::vector<std::int32_t> REPLAY_KeyframeTicks();

  /** Moves to `tick`, either way, keeping the session and its view. */
  void REPLAY_SeekTo(CWldSession& session, std::int32_t tick);

  enum class EReplaySeekKind
  {
    None,
    LoadKeyframe,
    PlayForward,
  };

  /** What `REPLAY_SeekTo` would do for `tick` now, by the same rule, for the bar to show before the click. */
  [[nodiscard]] EReplaySeekKind REPLAY_SeekKind(const CWldSession& session, std::int32_t tick);

  /** Stops a seek where it is. A restart already under way still finishes loading. */
  void REPLAY_CancelSeek();

  [[nodiscard]] bool REPLAY_IsSeeking();

  struct SReplaySeekProgress
  {
    std::int32_t targetTick = -1;
    std::int32_t currentTick = 0;
    float progress = 0.0f;
    bool restarting = false;
  };
  [[nodiscard]] SReplaySeekProgress REPLAY_SeekProgress(const CWldSession& session);

  /** Takes a keyframe when one is due, and starts a seek that had to wait. Before the session's frame. */
  void REPLAY_MainFrame(ISTIDriver& driver, CWldSession& session);

  /** The fast-forward's target tick, or -1. */
  [[nodiscard]] std::int32_t REPLAY_FastForwardTarget();

  /** After a frame's beats: ends the fast-forward once it reached its target or nothing more can come. */
  void REPLAY_AfterFastForwardFrame(const CWldSession& session, std::int32_t beatsApplied);

  /** The end of the replay: removes its keyframes. The teardown before its session starts changes nothing. */
  void REPLAY_OnTeardown();

  /** True when a seek wants a new sim behind the session. */
  [[nodiscard]] bool REPLAY_RestartWanted();

  /** What the new sim starts from: the replay, moved to the keyframe's beat when it has one. Null on failure. */
  [[nodiscard]] fa::auto_ptr<SWldSessionInfo> REPLAY_CreateRestartSession();

  /** Before the driver is created: makes this session load the keyframe, or start clean when it has none. */
  void REPLAY_PrepareSession(SWldSessionInfo& sessionInfo);

  /** The new sim's beat for this tick is being held until the move's target. */
  void REPLAY_NoteHeldTick(std::int32_t tick);

  /** True when the held beats should be applied: the target is reached, or holding more can't go on. */
  [[nodiscard]] bool REPLAY_HoldIsDone(std::size_t beatsHeld);

  /** The new sim's beats are applied: goes on to what is left of the seek. */
  void REPLAY_SimRestarted(const CWldSession& session);

  /** A copy of the map as it loaded, for a new sim; it owns the copy. */
  [[nodiscard]] STIMap* REPLAY_CloneStartMap();
} // namespace moho
