#pragma once

#include <cstdint>
#include <string_view>

namespace moho
{
  /**
   * FAF game version: the build number the FAF client stamps into ForgedAlliance.exe for each
   * release of the `faf` featured mod. `lua/version.lua` `GetVersion()` returns the same number,
   * `GetEngineVersion` reports it as "1.5.<version>", and the replay header carries it as
   * "Supreme Commander v1.50.<version>".
   *
   * FAF ships its engine fixes (FAForever/FA-Binary-Patches) as a new exe with a game release, so
   * one game version always means one set of patches. A replay plays with the patches of the
   * version that recorded it; a live or single-player game uses the latest version.
   */
  inline constexpr int kFafGameVersionOldestSupported = 3835;
  inline constexpr int kFafGameVersionLatest = 3840;

  /**
   * Simulation behaviour that FA-Binary-Patches changed after game version 3835. Each entry is on
   * from the game version whose exe first carried it (see `FafGameVersion.cpp`).
   */
  enum class EFafSimFix : std::uint8_t
  {
    AimLeadOncePerTick = 0,         ///< #143: no velocity lead on a target that already moved this tick (3836)
    TargetPointCollisionCentre = 1, ///< #145/#157: unit with no target bones is aimed at its collision centre (3836)
    ProjectileImpactBelowZero = 2,  ///< #154: a projectile below height 0 impacts (3840)
    RefuelUndockAboveMaxHealth = 3, ///< #169: aircraft undock when health >= max health (3840)
    ShieldRepair = 4,               ///< #175: shield repair scales with resources, and needs the shield on (3840)
    Count = 5,
  };

  /// Fixes active in the current session, one bit per `EFafSimFix`; set by `FAF_BeginSession`.
  extern std::uint32_t gFafSessionSimFixes;

  /**
   * Whether one FA-Binary-Patches simulation fix applies to the current session. Constant for the
   * whole session, so every client and every replay run of one game takes the same branch.
   */
  [[nodiscard]] inline bool FAF_IsSimFixActive(const EFafSimFix fix) noexcept
  {
    return (gFafSessionSimFixes & (1u << static_cast<std::uint32_t>(fix))) != 0u;
  }

  /// The game version the current session runs as.
  [[nodiscard]] int FAF_GetSessionGameVersion() noexcept;

  /**
   * Remembers the game version a replay was recorded with; the next replay session that begins
   * plays with it. Called by `VCR_SetupReplaySession` after reading the header.
   */
  void FAF_SetReplayGameVersion(int gameVersion) noexcept;

  /**
   * Fixes the game version and the active simulation fixes for a session that is about to create
   * its sim: the recorded version for a replay, `kFafGameVersionLatest` otherwise, unless the
   * `sim_FafGameVersion` console variable names one. The `sim_Fix*` console variables can force a
   * single fix on or off. Logs the result.
   */
  void FAF_BeginSession(bool isReplay);

  /**
   * Reads the game version out of a replay header string ("Supreme Commander v1.50.3840"); 0 when
   * the string has another form.
   */
  [[nodiscard]] int FAF_ParseReplayGameVersion(std::string_view header) noexcept;
} // namespace moho
