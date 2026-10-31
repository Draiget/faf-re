#pragma once

// Engine addition, server mode (plan WP4.4): the visibility oracle's golden test, in the game
// client. `/oraclegolden <file>` makes a lockstep game (a replay, with its focus army set from
// the UI) compare, every beat, the entities the client draws with the oracle's answer for the
// same beat and army:
//
//   - on the sim's thread, after `Sim::Sync` (`Sim::SetSyncObserver`), the oracle's
//     `ViewShowsMesh` for the sync focus army over every entity, kept per beat;
//   - on the client's thread, after `CWldSession::DoBeat` has applied that beat and run its
//     orphan and visibility walks (`CWldSession::SetBeatObserver`), every client entity's
//     mesh state (`MeshInstance::isHidden`), compared entity by entity.
//
// Entities without a mesh on the client are left out (nothing to draw), and so are beats whose
// sim focus differs from the client's (the focus switch takes a beat to reach the sim). An
// entity the client draws that the sim no longer has (an orphaned prop, kept until the view
// sees its spot) is counted apart. One line per beat goes to the file; the running totals (every 500
// compared beats) and the first 30 differences go to the log as `ORACLEGOLDEN` lines.

namespace faf::remote::client
{
  /** Installs the check when the command line has `/oraclegolden <file>`; false otherwise. */
  bool InstallOracleGoldenFromCommandLine();
} // namespace faf::remote::client
