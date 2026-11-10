# GPGNet messages from the game

What the game sends to the FAF client and lobby server over GPGNet, with the full argument layout of `JsonStats`, `PlayerOption`, `AIOption` and `GameOption`, and a short list of the other messages.

Sources read for this page:

- FAF Lua: [FAForever/fa](https://github.com/FAForever/fa) `develop` at `55c5d6e49` (2026-11-06). Paths below starting with `lua/` are in that repository.
- Lobby server: [FAForever/server](https://github.com/FAForever/server) at `418da04` (2026-10-31). Paths starting with `server/` are in that repository.
- Engine: [src/moho/net/CGpgNetInterface.cpp](../src/moho/net/CGpgNetInterface.cpp), checked against the retail binary at `0x007B9F30` (`cfunc_GpgNetSendL`).
- How the adapter and client pass the messages on: [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md), sections 2 to 4.

## 1. Path and wire format

```
Lua GpgNetSend(cmd, ...)  ->  engine  --GPGNet TCP-->  ICE adapter  --onGpgNetMessageReceived-->  FAF client
    --> lobby server: {"command": cmd, "target": "game", "args": [...]}  ->  GameConnection.handle_<cmd>(*args)
```

On the GPGNet socket every message is, little-endian:

| Field | Type |
|---|---|
| command length | `uint32` |
| command name | that many bytes, no terminator |
| argument count | `uint32` |
| each argument | `uint8` tag, then the body |

| Tag | Body | Arrives at the server as |
|---|---|---|
| `0` int | `int32` | JSON number |
| `1` string | `uint32` length + bytes | JSON string |
| `2` data | `uint32` length + bytes | JSON string (not produced by `GpgNetSend`) |

How `GpgNetSend` turns Lua values into arguments ([CGpgNetInterface.cpp:681-717](../src/moho/net/CGpgNetInterface.cpp#L681-L717)):

- **number** → tag 0. The value is truncated to `int32`: retail calls `lua_tonumber` then the CRT `_ftol` (`0x007BA001`, `0x007BA009`). `1.9` arrives as `1`, `-0.5` as `0`.
- **boolean** → tag 0 with `1` or `0`. `true` never arrives as a string.
- **string** → tag 1.
- anything else (table, nil, function) → Lua error `invalid kind of argument to GpgNetSend(): can only deal with ints and strings.`

The Java ICE adapter turns `/t` and `/n` inside string arguments back into a tab and a newline (`FaDataInputStream.readChunks`).

FAF's Lua wraps `GpgNetSend` (`lua/ui/globals/GpgNetSend.lua`): every call is logged with `SPEW`, and during a live game also reported as a `ModeratorEvent` sim callback. The arguments are unchanged.

The server ignores `GameOption`, `PlayerOption`, `AIOption`, `ClearSlot` and `GameMods` unless they come from the game's host (`server/gameconnection.py`, `is_host()` checks).

## 2. `JsonStats`

```
JsonStats(json: string)
```

One string argument holding a JSON document. Sent once per game, by every non-replay client, on the sync after game over (`lua/UserSync.lua:94-97`). The table comes from `lua/sim/score.lua`: `Sync.StatsToSend = ArmyScore` in the game-over listener (line 352), after `GameOverScore()` has added the achievement fields. It is encoded with `lua/system/dkson.lua`.

### Shape

```jsonc
{
  "stats": [            // one entry per non-civilian army, in army index order
    {
      "name": "Player1",          // brain.Nickname
      "type": "Human",            // brain.BrainType: "Human" or "AI"
      "faction": 1,               // brain:GetFactionIndex(): 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim (5 Nomad on the server's enum)
      "Defeated": 312.4,          // optional: game seconds + 15 when the army was defeated, later -1
      "general": {
        "score": 5370,            // CalculateBrainScore(brain), integer
        "lastupdatetick": 18240,
        "currentunits": 87,       // army stat UnitCap_Current
        "currentcap": 1000,       // army stat UnitCap_MaxCap
        "kills": { "count": 11, "mass": 18483.28, "energy": 5002463 },  // Enemies_Killed, Enemies_MassValue_Destroyed, Enemies_EnergyValue_Destroyed
        "built": { "count": 19, "mass": 532, "energy": 4160 },          // Units_History, Units_MassValue_Built, Units_EnergyValue_Built
        "lost":  { "count": 1, "mass": 18000, "energy": 5000000 }       // Units_Killed, Units_MassValue_Lost, Units_EnergyValue_Lost
      },
      "units": {                  // each value: { "kills": n, "built": n, "lost": n }
        "land": {...}, "air": {...}, "naval": {...}, "cdr": {...},
        "experimental": {...}, "structures": {...},
        "transportation": {...}, "sacu": {...}, "engineer": {...},
        "tech1": {...}, "tech2": {...}, "tech3": {...}
      },
      "blueprints": {             // only units from the list below that the army has a record for
        "uel0001": { "built": 1, "kills": 1, "lost": 0, "lowest_health": 4210.5 }
      },
      "resources": {
        "massin":    { "total": 0, "rate": 0, "reclaimed": 0, "reclaimRate": 0 },
        "massout":   { "total": 0, "rate": 0, "excess": 0 },
        "energyin":  { "total": 0, "rate": 0, "reclaimed": 0, "reclaimRate": 0 },
        "energyout": { "total": 0, "rate": 0, "excess": 0 },
        "storage":   { "storedMass": 0, "storedEnergy": 0, "maxMass": 0, "maxEnergy": 0 }
      }
    }
  ]
}
```

Notes:

- **`units` categories.** `land`, `air`, `naval`, `cdr` (COMMAND), `experimental`, `structures` are updated during the game (`categoriesToCollect`). `transportation`, `sacu` (SUBCOMMANDER), `engineer`, `tech1`, `tech2`, `tech3` are added only at game over (`categoriesForAchievements`). `kills`/`built`/`lost` come from `GetBlueprintStat("Enemies_Killed" / "Units_History" / "Units_Killed", category)`.
- **`blueprints` units.** ACUs `ual0001 url0001 uel0001 xsl0001`; ASFs `uaa0303 ura0303 uea0303 xsa0303`; experimentals `xab1401 uaa0310 ual0401 uas0401 xab2307 ueb2401 uel0401 xeb2402 ues0401 ura0401 url0401 url0402 xrl0403 xsb2401 xsa0402 xsl0401`; `daa0206` (Mercy), `xrl0302` (Fire Beetle). `kills`, `built`, `lost` are filled with 0 when missing. `lowest_health` is written only for ACUs (`lua/sim/units/ACUUnit.lua:61,97`).
- **Number types.** Most counters are whole numbers; mass/energy values, rates and health are fractional. All are JSON numbers.
- **Array or object.** `stats` is a Lua table keyed by army index with civilian armies left out. dkson writes it as a JSON array when the keys are 1..n. A civilian army between two players leaves a hole that dkson writes as `null`. With more than 10 slots and more holes than entries, dkson would write an object keyed by index instead (`isarray`, dkson.lua:56-77). Civilians are normally the last armies, so in practice it is an array.
- **The server's sample is older.** `tests/data/game_stats_simple_win.json` in the server repo has `currentcap` and `currentunits` as `{ "count": n }` objects and top-level `general.mass` / `general.energy`. Today's Lua sends plain numbers and no `general.mass`/`general.energy`; the server reads neither field.

### What the server reads

`server/games/game.py` `report_army_stats` keeps `json.loads(s)["stats"]`. `server/stats/game_stats_service.py` then reads, per entry: `type`, `name`, `general.score`, `faction`, `units.<category>.built|lost|kills` for `air land naval experimental cdr tech1 tech2 tech3 engineer transportation sacu`, and `blueprints.<unit id>.built` / `.lowest_health`. Stats are skipped for games with an AI (other than one named `civilian`) or fewer than 2 humans. `game.py:535-538` also reads `units.cdr.kills` per army name. Everything else in the document (resources, `structures`, `general.kills` and so on) is not used by the server.

## 3. `PlayerOption`

```
PlayerOption(ownerId: string, key: string, value: string | int)
```

| Arg | Wire | Meaning |
|---|---|---|
| `ownerId` | string | the player's FAF user id as decimal text. The lobby's `OwnerID` is a string: `CLobby:GetLocalPlayerID()` and `SenderID` are formatted from the peer uid ([CLobby.cpp:1119](../src/moho/net/CLobby.cpp#L1119), [:2359](../src/moho/net/CLobby.cpp#L2359)). The server does `int(ownerId)`. |
| `key` | string | option name, see below |
| `value` | int or string | as the lobby holds it; booleans arrive as 0/1 |

Sent by the host only, for slots whose `Human` is true (`lua/ui/lobby/lobby.lua`):

| When | Keys and values |
|---|---|
| a slot is drawn on the host (`SetSlotInfo` → `HostUtils.SendPlayerSettingsToServer`, line 1275) | `Faction` = slot faction index, `Color` = `PlayerColor`, `Team` = team, `StartSpot` = slot number |
| random start spots placed players (line 1736), after random factions were resolved | the same four, with the final values |
| launch (`SendArmySettingsToServer`, line 7326) | `Army` = 1..n in slot order over occupied slots |
| the host applies a player's own `PlayerOptions` message (line 5219) | every key in that message, under its lobby name: `Ready` (0/1), `Faction`, `Team`, `PlayerColor`, … |
| a player is moved to observers (line 7000) | `Team` = -1, `Army` = -1, `StartSpot` = -(observer index) |

Values to expect:

- `Team`: the lobby's team number; -1 for observers.
- `Faction`: before launch it is the slot-local index, where the last index means random (for a slot with all four factions, 5 = random, the `PlayerData` default). At launch `AssignRandomFactions` and `FixFactionIndexes` turn it into the global index, and in the launch path only `AssignRandomStartSpots` re-sends it; that function returns early when `TeamSpawn` is `fixed` or `penguin_autobalance` (line 1635).
- `StartSpot`: slot number 1..16, negative for observers.
- The full key set of a lobby slot is in `lua/ui/lobby/data/playerdata.lua` (`DEFAULT_MAPPING`).

The server stores every key in `_player_options[id][key]` and uses `Team`, `Army`, `StartSpot` and `Faction` (`server/games/game.py`, `server/ladder_service/ladder_service.py:632-634`).

The automatch lobby sends the same message from `AutolobbyServerCommunicationsComponent.SendPlayerOptionToServer` with keys `Team`, `Army`, `StartSpot`, `Faction`.

## 4. `AIOption`

```
AIOption(aiName: string, key: string, value: string | int)
```

The same as `PlayerOption`, for slots whose `Human` is false. The first argument is the slot's `PlayerName` (the AI's display name), not an id. Sent from the same places as `PlayerOption` (lines 5221, 6912; autolobby `SendAIOptionToServer`). The server keeps `AIs[aiName][key] = value` and reads `StartSpot` when a slot is cleared (`server/games/game.py:630-657`).

## 5. `GameOption`

```
GameOption(key: string, value: string | int)
```

Sent by the host from `SetGameOptions` (`lua/ui/lobby/lobby.lua:6039-6078`) for every option it sets, plus:

| Key | Value |
|---|---|
| any lobby option (`lua/ui/lobby/lobbyOptions.lua`, map options, mod options) | the option's value; lobby option values are strings, for example `UnitCap` `"1000"`, `FogOfWar` `"explored"`, `Victory` `"demoralization"` |
| `RestrictedCategories` | `true`/`false` (arrives as 1/0) for "any unit restriction set"; the category list itself is never sent |
| `ScenarioFile` | map path, for example `/maps/scmp_009/scmp_009_scenario.lua` |
| `Slots` | int, number of armies in the map's `standard` configuration; sent right after `ScenarioFile` when the map exists |

The server (`server/games/game.py`, `GameOptions._set_option`) converts `Victory` to its enum (`DEMORALIZATION`, `DOMINATION`, `ERADICATION`, `SANDBOX`, `DECAPITATION`, case-insensitive; unknown values are ignored), `Slots` to int and `ScenarioFile` to a POSIX path, and stores the rest as received. Keys it checks before rating a game (`validate_game_settings`, line 676):

| Key | Rated value | Compared as |
|---|---|---|
| `AIReplacement`, `CheatsEnabled`, `PrebuiltUnits`, `NoRushOption`, `Unranked` | disabled | `false`, `"false"`, `"off"`, `"no"` or `0` (case-insensitive) |
| `FogOfWar` | `"explored"` | exact |
| `RestrictedCategories` | `0` | exact |
| `TeamLock` | `"locked"` | exact |
| `Victory` | depends on the game type | enum |

The automatch lobby sends `GameOption` from `SendGameOptionToServer`.

## 6. Other messages from the game

Arguments as the call sites pass them; the server handler is `GameConnection.handle_<name>` in `server/gameconnection.py`.

| Command | Arguments | Sent from |
|---|---|---|
| `GameState` | `"Idle"`, `"Lobby"` (engine), `"Launching"` (lobby) | engine ([CGpgNetInterface.cpp:1570](../src/moho/net/CGpgNetInterface.cpp#L1570), [:1678](../src/moho/net/CGpgNetInterface.cpp#L1678)), `lobby.lua:5787` |
| `GameResult` | army index (int), result (string `"<extra words…> <result> <score>"`, split on spaces by the server) | `UserSync.lua:89` |
| `GameEnded` | none | `UserSync.lua:126` |
| `EnforceRating` | none | `UserSync.lua:121` |
| `TeamkillHappened` | time, victim id, victim name, killer id, killer name | `UserSync.lua:111` |
| `TeamkillReport` | same as `TeamkillHappened` | `ui/dialogs/teamkill.lua:49` |
| `OperationComplete` | all primary done (bool → 0/1), all secondary done (bool → 0/1), `GetGameTime()` | `UserSync.lua:405` (co-op) |
| `GameMods` | `"activated"`, mod count; or `"uids"`, space-separated uids | `lobby.lua:7429-7432` |
| `ClearSlot` | slot (int) | `lobby.lua:1315` |
| `GameFull` | none | `lobby.lua:1629` (handled by the client) |
| `Chat` | text | `lobby.lua:4579` |
| `Disconnected` | uid as decimal string | `lobby.lua:873` |
| `Rehost` | none | `ui/game/tabs.lua:347` |
| `BEAT` | game tick, game speed | `ui/game/gamemain.lua:1212` |
| `LaunchStatus` | status string | autolobby |
| `EstablishedPeer`, `DisconnectedPeer` | peer id | autolobby |
| `Bottleneck` | type (`"nothing"`, `"readiness"`, `"data"`, `"ack"`), beat, owners, milliseconds | engine ([CGpgNetInterface.cpp:459](../src/moho/net/CGpgNetInterface.cpp#L459)) |
| `BottleneckCleared` | none | engine |
| `Desync` | beat, army, hash 1, hash 2 | engine ([CGpgNetInterface.cpp:502](../src/moho/net/CGpgNetInterface.cpp#L502)) |
