# Microchip Threat Alerts

Author: Microchip. Version 1. A separate UI-only mod for the rebuilt faf-re engine.

## What it does

Shows a local alert ping and a short on-screen notification when a major enemy threat first enters your current direct vision:

- Strategic nuclear launchers (NUKE + STRATEGIC).
- Experimentals, including strategic/economic experimentals.
- Stationary T3 artillery.
- Stationary T3 anti-missile defence.

The notification is visible only to you. No team ping, chat message, unit order, automatic camera move, or simulation callback is sent. Normal units and T2 tactical missile defence do not trigger it. Visible construction sites can trigger an alert because their unit type is already identifiable.

The detector checks once a second, emits at most one alert every eight seconds, and alerts once per entity per game. Pending contacts must still be in direct vision when their turn arrives. A local marker lasts six seconds at the observed position; it does not follow a unit after vision is lost. The notification does not interrupt the game's announcement system.

## Vision boundary

The read-only `MicrochipGetVisibleEnemies()` helper enumerates only the UI-side unit mirror. It requires an active, non-replay focus army, an enemy relationship, a live unit, current direct-vision flag 0x08, and a non-hidden visibility mode. It does not return radar-only contacts, historical fog-of-war building ghosts, allies, or dead units. Shared allied vision is included where the engine already makes it available to your army. Spectators and replays do not run alerts.

No sim-side hidden entity scan or new network data is used. This requires the included rebuilt-engine helper; classic FAF clients do not expose this helper, so the mod logs that alerts are disabled on those clients. Other players need no mod or engine update.

## Install

1. Close the game.
2. Put `Microchip-Threat-Alerts` in your normal Forged Alliance UI Mods folder.
3. Back up `FAForever/bin_x64/main_x64.exe`, then replace it with `engine-update/main_x64.exe` from this package. Preserve the existing init files, shader libraries and fafengine folder. Never overwrite classic `ForgedAlliance.exe`.
4. Enable **Microchip Threat Alerts** in the UI mod manager and start a new game.
5. Disable it in the UI mod manager to stop automatic local alerts.

The included engine retains the previous Microchip F11 wait-timing support. No BIOS, CPU-affinity, worker-count, or checksum settings are changed by this mod.

## Testing

Six Lua tests cover threat classes, priority, cooldown, repeat suppression, disappearing contacts, malformed positions, observer handling and absence of team-ping/simulation calls. The engine's 269-check network suite passes.

A private classic/x64 test map spawned a visible enemy nuke and radar-only enemy T3 artillery. The nuke produced one local alert. The artillery produced no alert until it was moved into direct vision twelve seconds later, then produced one local alert. The game completed without a reported crash or desync, and the alert script logged no errors. No public lobby was used.

## FAF rules

This mod is not officially approved by FAF moderation. Automatic scouting alerts have been discussed and disputed; local-only alerts and using visible information do not by themselves establish permission for competitive play. Check with FAF moderation before assuming it is allowed in rated games.

- Official rules: https://www.faforever.com/rules
- Related discussion: https://forum.faforever.com/topic/3206/small-suggestions-topic/273
