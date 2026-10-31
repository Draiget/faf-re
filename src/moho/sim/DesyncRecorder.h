#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace gpg
{
  struct MD5Digest;
}

namespace moho
{
  class CTelemetryAttributes;
  class ICommandSink;
  class Sim;

  /**
   * Engine addition (issue #216): `sim_DesyncRecorder`, a user-side switch seeded by
   * `/desyncrecorder` on the command line. Read when a sim is created, so a change takes effect at
   * the next game. It never reaches the sim: the recorder only reads state and writes text.
   */
  extern bool sim_DesyncRecorder;

  /// Engine addition (issue #216): memory cap in MB for the recorded beats; the oldest go first.
  extern int sim_DesyncRecorderMB;

  /**
   * Engine addition (issue #216), test only: at this beat, this client alone raises the health of
   * its lowest-id live unit by one float step, a real difference in hashed state that the other
   * clients don't have. -1, the default, does nothing. Seeded by `/desynctestbeat N`.
   */
  extern int sim_DesyncTestNudgeBeat;

  /**
   * Engine addition (issue #217): the recorder writes its dump at this beat whether or not a
   * checksum mismatched, so a headless replay can rebuild the side of a desync nobody sent. -1, the
   * default, waits for a mismatch. Seeded by `/desyncdumpbeat N`; read when a sim is created.
   */
  extern int sim_DesyncDumpBeat;

  /**
   * Engine addition (issue #216): the desync recorder. While a game runs it keeps the sync-log
   * text of recent beats in memory, one compressed buffer per beat, plus every player's reported
   * checksum. When a checksum mismatches it records on to the mismatched beat + 30 (the same beat
   * on every client) and then writes one zip next to the game log; nothing goes to disk before.
   *
   * The text is the `/synclog` text: `Sim::Logf` feeds both, and `Sim::IsSyncLogOn` makes the call
   * sites that format their lines only while logging run while either is on. Every `Sim::Logf`
   * call runs on the sim thread; compression and the dump run on the recorder's own thread.
   */
  class CDesyncRecorder
  {
  public:
    /// Creates the recorder for `sim` when `sim_DesyncRecorder` is on. Called once the sim exists.
    static void Attach(Sim& sim);

    /// Writes a dump still owed, waits for the recorder's thread and drops the recorder.
    static void Detach(const Sim& sim);

    /// The recorder recording `sim`, or null.
    [[nodiscard]] static CDesyncRecorder* For(const Sim* const sim) noexcept
    {
      return sim != nullptr && sim == sSim ? sInstance : nullptr;
    }

    /// The user side's session facts for the next dump header (map, game mods, replay or live game)
    /// and for telemetry, which is sent for live multiplayer games only.
    static void SetSessionInfo(const char* mapName, const char* gameMods, bool isReplay, bool isMultiplayer);

    /// Issue #218: `source`'s orders were proven altered on their way to this client.
    static void NoteOrdersAltered(int source);

    /// Issue #218: notes the console switch values as they are before `/con` runs, so telemetry
    /// can list the ones a player changed. Called by `TELEMETRY_Startup`.
    static void NoteSwitchDefaults();

    /// The dump file this game writes, empty until the first mismatch. Any thread.
    [[nodiscard]] static std::string DumpPath();

    /// Adds one line to the dump's notes, also after the dump is written. Any thread.
    static void AddNote(const std::string& line);

    /// True while beats are recorded (stops once the dump is taken).
    [[nodiscard]] bool IsRecording() const noexcept;

    /// One sync-log line, formatted. Sim thread.
    void Append(const char* format, va_list args);

    /// Raw sync-log text. Sim thread.
    void Append(const char* text, std::size_t length);

    /// Closes `beat`'s text (`Sim::FlushLog`); takes the dump when it is due. Sim thread.
    void EndBeat(Sim& sim, int beat);

    /// One command (not an advance, source switch or checksum) decoded for `sink`'s next beat.
    static void NoteCommandFor(const ICommandSink* sink) noexcept;

    /// One checksum report `VerifyChecksum` compared: who sent which hash for which beat.
    void NoteChecksum(Sim& sim, int beat, int source, const gpg::MD5Digest& reported, const gpg::MD5Digest& ours);

    CDesyncRecorder(const CDesyncRecorder&) = delete;
    CDesyncRecorder& operator=(const CDesyncRecorder&) = delete;
    ~CDesyncRecorder();

  private:
    explicit CDesyncRecorder(Sim& sim);

    /// Names the dump `desync_<game id>_<tag>_army<local army>.zip` next to the game log.
    void ChooseDumpPath(const Sim& sim, const std::string& tag);

    /// Issue #218: telemetry is on and this is a live multiplayer game.
    [[nodiscard]] bool TelemetryApplies() const;

    /// Issue #218: the attributes both telemetry records carry (game, settings, switches).
    void AddGameAttributes(const Sim& sim, CTelemetryAttributes& out) const;

    /// Issue #218: one `faf.desync` record per player that disagreed at the first mismatched beat,
    /// sent from the recorder's thread after the dump. Sim thread.
    void SendDesyncTelemetry(const Sim& sim);

    /// Issue #218: the `faf.game.end` record. Sim thread, from `Detach`.
    void SendGameEnd(const Sim& sim);

    /// Stops recording and hands the dump to the recorder's thread. Sim thread.
    void TakeDump(const Sim& sim);

    struct Impl;
    std::unique_ptr<Impl> mImpl;

    static const Sim* sSim;
    static CDesyncRecorder* sInstance;
  };

  /**
   * Engine addition (issue #216): every live entity (id, blueprint, army, health, position,
   * rotation and velocity with their float bits, layer, current command) and every army's
   * economy, as text. Sim.cpp, beside `Sim::UpdateChecksum`, whose field helpers it shares.
   */
  void SIM_DescribeStateForDesync(const Sim& sim, std::string& out);

  /// Engine addition (issue #216): applies `sim_DesyncTestNudgeBeat` when its beat comes.
  void SIM_ApplyDesyncTestNudge(Sim& sim);

  /// Engine addition (issue #216): the sim-side `sim_ChecksumPeriod`, for the dump header.
  [[nodiscard]] int SIM_GetChecksumPeriod(const Sim& sim);
} // namespace moho
