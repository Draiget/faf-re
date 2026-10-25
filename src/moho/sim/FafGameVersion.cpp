#include "moho/sim/FafGameVersion.h"

#include <array>
#include <charconv>
#include <cstddef>
#include <string>
#include <system_error>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"

namespace moho
{
  std::uint32_t gFafSessionSimFixes = ~0u;

  namespace
  {
    /**
     * Engine addition: the game version a session runs as. 0 follows the session (the recorded
     * version for a replay, the game data's version for everything else); any other value is
     * used instead. Read when a session begins. In a multiplayer game every client must use the
     * same value.
     */
    int sim_FafGameVersion = 0;

    TConVar<int> gTConVar_sim_FafGameVersion(
      "sim_FafGameVersion",
      "FAF game version the next session runs as (0: the replay's recorded version, else the game data's "
      "/lua/version.lua). Every client of a multiplayer game must use the same value.",
      &sim_FafGameVersion
    );

    // One switch per fix: -1 follows the game version, 0 forces the 3835 behaviour, 1 forces the
    // fix. Read when a session begins, so a change takes effect with the next game.
    int sim_FixAimLeadOncePerTick = -1;
    int sim_FixTargetPointCollisionCentre = -1;
    int sim_FixProjectileImpactBelowZero = -1;
    int sim_FixRefuelUndockAboveMaxHealth = -1;
    int sim_FixShieldRepair = -1;

    TConVar<int> gTConVar_sim_FixAimLeadOncePerTick(
      "sim_FixAimLeadOncePerTick",
      "FA-Binary-Patches #143: no velocity lead on a target that already moved this tick (-1 game version, 0 off, 1 on).",
      &sim_FixAimLeadOncePerTick
    );
    TConVar<int> gTConVar_sim_FixTargetPointCollisionCentre(
      "sim_FixTargetPointCollisionCentre",
      "FA-Binary-Patches #145/#157: aim at the collision centre of a unit without target bones (-1 game version, 0 off, 1 on).",
      &sim_FixTargetPointCollisionCentre
    );
    TConVar<int> gTConVar_sim_FixProjectileImpactBelowZero(
      "sim_FixProjectileImpactBelowZero",
      "FA-Binary-Patches #154: a projectile below height 0 impacts (-1 game version, 0 off, 1 on).",
      &sim_FixProjectileImpactBelowZero
    );
    TConVar<int> gTConVar_sim_FixRefuelUndockAboveMaxHealth(
      "sim_FixRefuelUndockAboveMaxHealth",
      "FA-Binary-Patches #169: refuelled aircraft undock once health >= max health (-1 game version, 0 off, 1 on).",
      &sim_FixRefuelUndockAboveMaxHealth
    );
    TConVar<int> gTConVar_sim_FixShieldRepair(
      "sim_FixShieldRepair",
      "FA-Binary-Patches #175: shield repair scales with the builder's resources and needs the shield on (-1 game "
      "version, 0 off, 1 on).",
      &sim_FixShieldRepair
    );

    struct SFafSimFixInfo
    {
      const char* mName;       ///< console variable
      int mFirstGameVersion;   ///< first FAF game version whose exe carries the fix
      const int* mSwitch;      ///< -1 / 0 / 1
    };

    // Game versions from the FAForever/fa changelogs: 3836 (2026-05-16) shipped #143, #145 and
    // #157; 3840 (2026-10-20) shipped every engine patch merged since, #154, #169 and #175 among
    // them. 3837..3839 changed only Lua.
    const std::array<SFafSimFixInfo, static_cast<std::size_t>(EFafSimFix::Count)> kFafSimFixes{{
      {"sim_FixAimLeadOncePerTick", 3836, &sim_FixAimLeadOncePerTick},
      {"sim_FixTargetPointCollisionCentre", 3836, &sim_FixTargetPointCollisionCentre},
      {"sim_FixProjectileImpactBelowZero", 3840, &sim_FixProjectileImpactBelowZero},
      {"sim_FixRefuelUndockAboveMaxHealth", 3840, &sim_FixRefuelUndockAboveMaxHealth},
      {"sim_FixShieldRepair", 3840, &sim_FixShieldRepair},
    }};

    int sSessionGameVersion = kFafGameVersionLatest;
    int sReplayGameVersion = 0;
  } // namespace

  int FAF_GetSessionGameVersion() noexcept
  {
    return sSessionGameVersion;
  }

  void FAF_SetReplayGameVersion(const int gameVersion) noexcept
  {
    sReplayGameVersion = gameVersion;
  }

  int FAF_ParseLuaVersionFile(const std::string_view text) noexcept
  {
    constexpr std::string_view kKey = "local Version";
    for (std::size_t at = text.find(kKey); at != std::string_view::npos; at = text.find(kKey, at + 1)) {
      std::string_view rest = text.substr(at + kKey.size());
      const auto skipSpaces = [&rest] {
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
          rest.remove_prefix(1);
        }
      };
      skipSpaces();
      if (rest.empty() || rest.front() != '=') {
        continue;
      }
      rest.remove_prefix(1);
      skipSpaces();
      if (rest.empty() || (rest.front() != '"' && rest.front() != '\'')) {
        continue;
      }
      const char quote = rest.front();
      rest.remove_prefix(1);
      int gameVersion = 0;
      const auto [last, error] = std::from_chars(rest.data(), rest.data() + rest.size(), gameVersion);
      if (error == std::errc{} && last != rest.data() + rest.size() && *last == quote && gameVersion > 0) {
        return gameVersion;
      }
    }
    return 0;
  }

  int FAF_GetGameDataVersion()
  {
    msvc8::string diskPath{};
    if (CVirtualFileSystem* const vfs = DISK_GetVFS(); vfs != nullptr) {
      (void)vfs->FindFile(&diskPath, "/lua/version.lua", nullptr);
    }
    if (!diskPath.empty()) {
      const gpg::MemBuffer<const char> text = DISK_MemoryMapFile(diskPath.c_str());
      if (text.mBegin != nullptr) {
        const int gameVersion =
          FAF_ParseLuaVersionFile(std::string_view(text.mBegin, static_cast<std::size_t>(text.mEnd - text.mBegin)));
        if (gameVersion != 0) {
          return gameVersion;
        }
      }
    }
    return kFafGameVersionOldestSupported;
  }

  void FAF_BeginSession(const bool isReplay)
  {
    int gameVersion = 0;
    const char* source = "replay";
    if (sim_FafGameVersion != 0) {
      gameVersion = sim_FafGameVersion;
      source = "sim_FafGameVersion";
    } else if (isReplay && sReplayGameVersion != 0) {
      gameVersion = sReplayGameVersion;
    } else {
      gameVersion = FAF_GetGameDataVersion();
      source = "game data";
    }
    sSessionGameVersion = gameVersion;
    if (gameVersion > kFafGameVersionLatest) {
      gpg::Warnf(
        "FAF game version %d is newer than this engine's patches (up to %d); engine patches released after %d "
        "are missing, so a game with the FAF exe of %d may desync.",
        gameVersion,
        kFafGameVersionLatest,
        kFafGameVersionLatest,
        gameVersion
      );
    }

    std::uint32_t fixes = 0u;
    std::string forced;
    for (std::size_t index = 0; index < kFafSimFixes.size(); ++index) {
      const SFafSimFixInfo& fix = kFafSimFixes[index];
      bool active = gameVersion >= fix.mFirstGameVersion;
      if (*fix.mSwitch >= 0) {
        active = *fix.mSwitch != 0;
        forced += ' ';
        forced += fix.mName;
        forced += active ? "=1" : "=0";
      }
      if (active) {
        fixes |= 1u << index;
      }
    }
    gFafSessionSimFixes = fixes;

    gpg::Logf(
      "FAF game version %d (%s), sim fixes 0x%02X%s%s",
      gameVersion,
      source,
      fixes,
      forced.empty() ? "" : ", forced:",
      forced.c_str()
    );
  }

  int FAF_ParseReplayGameVersion(std::string_view header) noexcept
  {
    constexpr std::string_view kPrefix = "Supreme Commander v1.50.";
    if (header.substr(0, kPrefix.size()) != kPrefix) {
      return 0;
    }
    header.remove_prefix(kPrefix.size());
    // The writer formats the build with `%4i`, which pads with spaces below 1000.
    while (!header.empty() && header.front() == ' ') {
      header.remove_prefix(1);
    }

    int gameVersion = 0;
    const char* const end = header.data() + header.size();
    const auto [last, error] = std::from_chars(header.data(), end, gameVersion);
    if (error != std::errc{} || last != end || gameVersion <= 0) {
      return 0;
    }
    return gameVersion;
  }
} // namespace moho
