#pragma once

// Engine addition, server mode (plan WP11.6): `/sessionsummary` logs what a user session holds
// once a minute of game time and at game over: entities, units per army, orphans and the units'
// summed health. A replay watched through the remote driver (`/loopback`) and the same replay in
// the lockstep client give comparable lines. Without the flag it does nothing.

namespace moho
{
  class CWldSession;
  struct SSyncData;
}

namespace faf::remote::client
{
  /** Called by `CWldSession::DoBeat` once a beat's packet is applied. */
  void NoteSessionBeat(moho::CWldSession& session, const moho::SSyncData& beat);
} // namespace faf::remote::client
