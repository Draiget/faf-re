#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Engine addition, server mode (plan WP2.6, WP1.4): what a player's game reports of its content once it has loaded
// the launch's rules, and the server's verdict on it. Server and client hash the same two things from the rules each
// loaded on its own: the blueprint tables a view frame names its entities by (ContentTables.h: every unit, prop,
// projectile and mesh blueprint id, in ordinal order), and the mod set the rules were built with (the uid of each sim
// mod in the launch's `GameMods`). A client whose tables differ would read the server's views wrong; the server's own
// are the reference (it plays the game). A blueprint whose values differ under the same id changes nothing a client
// computes: the server's sim is the game.

namespace moho
{
  class RRuleGameRules;
}

namespace faf::remote
{
  struct SContentReport
  {
    std::uint64_t blueprints = 0;
    std::uint64_t mods = 0;

    [[nodiscard]] bool operator==(const SContentReport&) const noexcept = default;
  };

  /**
   * The report for rules a session loaded. `gameMods`: the launch's `GameMods` in the Lua byte form `LaunchInfoBase::mGameMods` holds (`SCR_ToString`,
   * what the rules' `__active_mods` were made from).
   */
  [[nodiscard]] SContentReport MakeContentReport(moho::RRuleGameRules& rules, const std::string& gameMods);
  /** 64-bit FNV-1a over the uids, sorted, each with its terminator: the mod set whatever order it was listed in. */
  [[nodiscard]] std::uint64_t HashModUids(std::vector<std::string> uids) noexcept;
  /** The sim mods' uids in that byte form of `GameMods`: each entry's `uid` field, or its key when the entry has none. */
  [[nodiscard]] std::vector<std::string> ReadModUids(const std::string& gameMods);

  /** Plan WP17.8: one mod a player's game runs, as it reports it. */
  struct SModEntry
  {
    bool ui = false; // a UI mod (`ui_only`): it loads in the player's own game, not the sim
    std::string uid;
    std::string version;

    [[nodiscard]] bool operator==(const SModEntry&) const noexcept = default;
  };
  /** At most this many mods in one report, each uid and version at most `kMaxModText` bytes. */
  constexpr std::size_t kMaxReportedMods = 256;
  constexpr std::size_t kMaxModText = 200;

  /** The `ModReport` message (net/GameLinks.h). Mods past the limits are left out. */
  [[nodiscard]] std::vector<std::uint8_t> EncodeModReport(const std::vector<SModEntry>& mods);
  /** False unless `message` is a whole `ModReport` within the limits. */
  [[nodiscard]] bool DecodeModReport(std::span<const std::uint8_t> message, std::vector<SModEntry>& out);
  /** The UI mods of `mods` whose uid isn't in `allowed`, in report order. */
  [[nodiscard]] std::vector<std::string> UiModsOutside(const std::vector<SModEntry>& mods, const std::vector<std::string>& allowed);

  /** The `ContentReport` message (net/GameLinks.h): its kind, then the two hashes. */
  [[nodiscard]] std::vector<std::uint8_t> EncodeContentReport(const SContentReport& report);
  /** False unless `message` is a whole `ContentReport`. */
  [[nodiscard]] bool DecodeContentReport(std::span<const std::uint8_t> message, SContentReport& out);

  /** What the match says to do with a player whose content differs (the match file's `MatchContentCheck`). */
  enum class EContentCheck : std::uint8_t
  {
    Off,    // not compared
    Warn,   // compared, told to the console; the player plays
    Refuse, // compared; the player is out of the game, and so is one that loaded without reporting
  };

  /** "off", "warn" or "refuse"; nothing for any other text. */
  [[nodiscard]] std::optional<EContentCheck> ReadContentCheck(std::string_view text);

  enum class EContentVerdict : std::uint8_t
  {
    Same,
    Differs,
    Missing, // loaded with no report
  };

  /** A player's report (null: none came) against the server's own. */
  [[nodiscard]] EContentVerdict JudgeContent(const SContentReport& expected, const SContentReport* report) noexcept;
  /** Whether that verdict takes the player out of the game under `mode`. */
  [[nodiscard]] bool RefusesPlayer(EContentCheck mode, EContentVerdict verdict) noexcept;
} // namespace faf::remote
