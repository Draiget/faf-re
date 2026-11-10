# GPGNet messages

Every message the game sends to and accepts from the FAF client, ICE adapter and lobby server over GPGNet, as a [JSON Schema (draft 2020-12)](https://json-schema.org/draft/2020-12) per message.

The machine-readable schema is [gpgnet/gpgnet-messages.schema.json](gpgnet/gpgnet-messages.schema.json). The schema blocks on this page are copied from it by `python docs/gpgnet/sync_doc.py`, which also checks the schema against the JSON Schema 2020-12 meta-schema and every `examples` entry against its message. Change the schema file, then run the script; `--check` only reports.

Sources read:

- FAF Lua: [FAForever/fa](https://github.com/FAForever/fa) `develop` at `55c5d6e49` (2026-11-06). Paths starting with `lua/` are in that repository.
- Lobby server: [FAForever/server](https://github.com/FAForever/server) at `418da04` (2026-10-31). Paths starting with `server/` are in that repository.
- ICE adapter: [FAForever/java-ice-adapter](https://github.com/FAForever/java-ice-adapter), `GPGNetServer`, `FaDataInputStream`, `IceAdapter`.
- Engine: [src/moho/net/CGpgNetInterface.cpp](../src/moho/net/CGpgNetInterface.cpp), checked against the retail binary at `0x007B9F30` (`cfunc_GpgNetSendL`).
- The adapter ↔ client RPC is in [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md), sections 2 to 4.

Contents:

1. [Format](#1-format)
2. [Common types](#2-common-types)
3. [Messages from the game](#3-messages-from-the-game)
4. [JsonStats payload](#4-jsonstats-payload)
5. [Messages to the game](#5-messages-to-the-game)
6. [Not covered](#6-not-covered)

## 1. Format

```
Lua GpgNetSend(cmd, ...)  ->  engine  --GPGNet TCP-->  ICE adapter  --onGpgNetMessageReceived-->  FAF client
    --> lobby server: {"command": cmd, "target": "game", "args": [...]}  ->  GameConnection.handle_<cmd>(*args)
```

The schemas describe the JSON form, `{"command", "target", "args"}`, which is what the lobby server receives and sends. On the GPGNet socket the same message is, little-endian:

| Field | Type |
|---|---|
| command length | `uint32` |
| command name | that many bytes, no terminator |
| argument count | `uint32` |
| each argument | `uint8` tag, then the body |

| Tag | Body | JSON | `x-gpgnet-tag` |
|---|---|---|---|
| int | `int32` | number | `0` |
| string | `uint32` length + bytes | string | `1` |
| data | `uint32` length + bytes | not sent as JSON | `2` |

`x-gpgnet-tag` is an annotation on each argument type in the schema (JSON Schema allows extra keywords); it says which tag the argument has on the socket.

How `GpgNetSend` turns Lua values into arguments ([CGpgNetInterface.cpp:681-717](../src/moho/net/CGpgNetInterface.cpp#L681-L717)):

- **number** → int. The value is truncated to `int32`: retail calls `lua_tonumber` then the CRT `_ftol` (`0x007BA001`, `0x007BA009`). `1.9` arrives as `1`, `-0.5` as `0`.
- **boolean** → int `1` or `0`.
- **string** → string.
- anything else (table, nil, function) → Lua error `invalid kind of argument to GpgNetSend(): can only deal with ints and strings.`

The Java ICE adapter turns `/t` and `/n` inside string arguments back into a tab and a newline (`FaDataInputStream.readChunks`).

FAF's Lua wraps `GpgNetSend` (`lua/ui/globals/GpgNetSend.lua`): every call is logged with `SPEW`, and during a live game also reported as a `ModeratorEvent` sim callback. The arguments are unchanged.

The lobby server ignores `GameOption`, `PlayerOption`, `AIOption`, `ClearSlot` and `GameMods` unless they come from the game's host (`server/gameconnection.py`, `is_host()`). Commands it has no handler for are logged as unrecognized.

## 2. Common types

Every message is an `Envelope` with a fixed `command` and its own `args`:

<!-- schema: Envelope -->
```json
{
  "type": "object",
  "required": ["command", "args"],
  "properties": {
    "command": {"type": "string"},
    "target": {"const": "game", "description": "Set when the message travels between the client and the lobby server."},
    "args": {"type": "array"}
  }
}
```
<!-- /schema -->

Argument types:

<!-- schema: Int32 -->
```json
{
  "description": "Wire tag 0. GpgNetSend truncates Lua numbers toward zero and sends booleans as 1 or 0.",
  "type": "integer",
  "minimum": -2147483648,
  "maximum": 2147483647,
  "x-gpgnet-tag": 0
}
```
<!-- /schema -->

<!-- schema: String -->
```json
{"description": "Wire tag 1: uint32 length and the bytes.", "type": "string", "x-gpgnet-tag": 1}
```
<!-- /schema -->

<!-- schema: Data -->
```json
{
  "description": "Wire tag 2: uint32 length and raw bytes. GpgNetSend never produces it.",
  "type": "string",
  "contentEncoding": "base64",
  "x-gpgnet-tag": 2
}
```
<!-- /schema -->

<!-- schema: Flag -->
```json
{"description": "A Lua boolean: 1 true, 0 false.", "$ref": "#/$defs/Int32", "enum": [0, 1]}
```
<!-- /schema -->

<!-- schema: UidText -->
```json
{
  "description": "A FAF user id as decimal text, as the lobby holds peer ids.",
  "$ref": "#/$defs/String",
  "pattern": "^[0-9]+$"
}
```
<!-- /schema -->

<!-- schema: Endpoint -->
```json
{"description": "host:port", "$ref": "#/$defs/String", "pattern": "^[^:]+:[0-9]+$"}
```
<!-- /schema -->

<!-- schema: OptionValue -->
```json
{
  "description": "The value as the lobby holds it: lobby option values are strings, slot fields are numbers or strings, booleans arrive as 1/0.",
  "oneOf": [{"$ref": "#/$defs/String"}, {"$ref": "#/$defs/Int32"}]
}
```
<!-- /schema -->

## 3. Messages from the game

| Command | Arguments | Sent by | Lobby server |
|---|---|---|---|
| [GameState](#gamestate) | state | engine, lobby | handled |
| [GameOption](#gameoption) | key, value | lobby (host) | handled |
| [PlayerOption](#playeroption) | ownerId, key, value | lobby (host) | handled |
| [AIOption](#aioption) | aiName, key, value | lobby (host) | handled |
| [ClearSlot](#clearslot) | slot | lobby (host) | handled |
| [GameMods](#gamemods) | "activated", count / "uids", list | lobby (host) | handled |
| [GameFull](#gamefull) | – | lobby | ignored |
| [Chat](#chat) | text | lobby | ignored |
| [Disconnected](#disconnected) | uid | lobby | logged |
| [LaunchStatus](#launchstatus) | status | automatch lobby | ignored |
| [EstablishedPeer](#establishedpeer) | peerId | automatch lobby | no handler |
| [DisconnectedPeer](#disconnectedpeer) | peerId | automatch lobby | no handler |
| [GameResult](#gameresult) | army, result | game UI | handled |
| [JsonStats](#jsonstats) | json | game UI | handled |
| [EnforceRating](#enforcerating) | – | game UI | handled |
| [GameEnded](#gameended) | – | game UI | handled |
| [TeamkillHappened](#teamkillhappened) | time, victim id, name, killer id, name | game UI | handled |
| [TeamkillReport](#teamkillreport) | same | game UI | ignored |
| [OperationComplete](#operationcomplete) | primary, secondary, time | game UI (co-op) | handled |
| [Rehost](#rehost) | – | game UI | ignored |
| [BEAT](#beat) | tick, speed | game UI | no handler |
| [Bottleneck](#bottleneck) | kind, beat, ids, ms | engine | logged |
| [BottleneckCleared](#bottleneckcleared) | – | engine | logged |
| [Desync](#desync) | beat, army, hash, hash | engine | handled |
| [Stats](#stats) | xml | engine | no handler |
| [ProcessNatPacket](#processnatpacket) | endpoint, data | engine | – (adapter) |

### GameState

`GameState(state: "Idle" | "Lobby" | "Launching")`

The engine sends `Idle` once the GPGNet connection is up ([CGpgNetInterface.cpp:1569](../src/moho/net/CGpgNetInterface.cpp#L1569)) and `Lobby` after `CreateLobby` ([:1677](../src/moho/net/CGpgNetInterface.cpp#L1677)). The lobby sends `Launching` (`lua/ui/lobby/lobby.lua:5787`; the automatch lobby drops every other value). The lobby server also accepts `Ended`, which the game never sends.

<!-- schema: FromGame.GameState -->
```json
{
  "title": "GameState",
  "description": "The game's state. The engine sends Idle when the GPGNet connection is up and Lobby after CreateLobby; the lobby sends Launching. The lobby server also accepts Ended, which the game itself never sends.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "GameState"},
    "args": {
      "prefixItems": [{"$ref": "#/$defs/String", "enum": ["Idle", "Lobby", "Launching"]}],
      "minItems": 1,
      "items": false
    }
  },
  "examples": [{"command": "GameState", "target": "game", "args": ["Launching"]}]
}
```
<!-- /schema -->

### GameOption

`GameOption(key: string, value: string | int)`

Sent by the host from `SetGameOptions` (`lua/ui/lobby/lobby.lua:6039-6078`) for every option it sets. Lobby option values are strings (`lua/ui/lobby/lobbyOptions.lua`), for example `UnitCap` `"1000"`, `FogOfWar` `"explored"`, `Victory` `"demoralization"`. Three keys are special:

- `RestrictedCategories`: `true`/`false` (arrives as 1/0) for "any unit restriction set"; the category list is never sent.
- `ScenarioFile`: the map path.
- `Slots`: int, the number of armies in the map's `standard` configuration, sent right after `ScenarioFile` when the map exists.

The server (`server/games/game.py`, `GameOptions._set_option`) converts `Victory` to its enum (`DEMORALIZATION`, `DOMINATION`, `ERADICATION`, `SANDBOX`, `DECAPITATION`, case-insensitive; an unknown value is ignored), `Slots` to int and `ScenarioFile` to a POSIX path, and stores the rest as received. Keys it checks before rating a game (`validate_game_settings`, line 676):

| Key | Rated value | Compared as |
|---|---|---|
| `AIReplacement`, `CheatsEnabled`, `PrebuiltUnits`, `NoRushOption`, `Unranked` | disabled | `false`, `"false"`, `"off"`, `"no"` or `0` (case-insensitive) |
| `FogOfWar` | `"explored"` | exact |
| `RestrictedCategories` | `0` | exact |
| `TeamLock` | `"locked"` | exact |
| `Victory` | depends on the game type | enum |

<!-- schema: FromGame.GameOption -->
```json
{
  "title": "GameOption",
  "description": "One game option set by the host.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "GameOption"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/String",
          "description": "key: a lobby option key, or ScenarioFile, Slots, RestrictedCategories"
        },
        {
          "$ref": "#/$defs/OptionValue",
          "description": "value: ScenarioFile is the map path, Slots an int, RestrictedCategories 1/0 for 'any restriction set'"
        }
      ],
      "minItems": 2,
      "items": false
    }
  },
  "examples": [
    {"command": "GameOption", "target": "game", "args": ["Victory", "demoralization"]},
    {
      "command": "GameOption",
      "target": "game",
      "args": ["ScenarioFile", "/maps/scmp_009/scmp_009_scenario.lua"]
    },
    {"command": "GameOption", "target": "game", "args": ["Slots", 8]},
    {"command": "GameOption", "target": "game", "args": ["RestrictedCategories", 0]}
  ]
}
```
<!-- /schema -->

### PlayerOption

`PlayerOption(ownerId: uid text, key: string, value: string | int)`

`ownerId` is the player's FAF user id as decimal text: the lobby's `OwnerID` comes from the engine's peer uid formatted as a string ([CLobby.cpp:1119](../src/moho/net/CLobby.cpp#L1119), [:2359](../src/moho/net/CLobby.cpp#L2359)). The server does `int(ownerId)`.

Sent by the host only, for slots whose `Human` is true (`lua/ui/lobby/lobby.lua`):

| When | Keys and values |
|---|---|
| a slot is drawn on the host (`SetSlotInfo` → `HostUtils.SendPlayerSettingsToServer`, line 1275) | `Faction` = slot faction index, `Color` = `PlayerColor`, `Team` = team, `StartSpot` = slot number |
| random start spots placed players (line 1736), after random factions were resolved | the same four, with the final values |
| launch (`SendArmySettingsToServer`, line 7326) | `Army` = 1..n in slot order over occupied slots |
| the host applies a player's own `PlayerOptions` message (line 5219) | every key in that message, under its lobby name: `Ready` (0/1), `Faction`, `Team`, `PlayerColor`, … |
| a player is moved to observers (line 7000) | `Team` = -1, `Army` = -1, `StartSpot` = -(observer index) |

- `Team`: the lobby's team number; -1 for observers.
- `Faction`: before launch it is the slot-local index, where the last index means random (for a slot with all four factions, 5 = random, the `PlayerData` default). At launch `AssignRandomFactions` and `FixFactionIndexes` turn it into the global index, and in the launch path only `AssignRandomStartSpots` re-sends it; that function returns early when `TeamSpawn` is `fixed` or `penguin_autobalance` (line 1635).
- `StartSpot`: slot number 1..16, negative for observers.
- The full key set of a slot is `DEFAULT_MAPPING` in `lua/ui/lobby/data/playerdata.lua`.

The server stores every key and uses `Team`, `Army`, `StartSpot` and `Faction` (`server/games/game.py`, `server/ladder_service/ladder_service.py:632-634`). The automatch lobby sends `Team`, `Army`, `StartSpot`, `Faction` (`AutolobbyServerCommunicationsComponent.SendPlayerOptionToServer`).

<!-- schema: FromGame.PlayerOption -->
```json
{
  "title": "PlayerOption",
  "description": "One field of a human player's slot, sent by the host.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "PlayerOption"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/UidText", "description": "ownerId: the player's FAF user id"},
        {
          "$ref": "#/$defs/String",
          "description": "key: Faction, Color, Team, StartSpot, Army, or any slot field the player changed (Ready, PlayerColor, ...)"
        },
        {"$ref": "#/$defs/OptionValue", "description": "value"}
      ],
      "minItems": 3,
      "items": false
    }
  },
  "examples": [
    {"command": "PlayerOption", "target": "game", "args": ["123456", "Faction", 2]},
    {"command": "PlayerOption", "target": "game", "args": ["123456", "StartSpot", -1]}
  ]
}
```
<!-- /schema -->

### AIOption

`AIOption(aiName: string, key: string, value: string | int)`

`PlayerOption` for slots whose `Human` is false. The first argument is the slot's `PlayerName` (the AI's display name), not an id. Sent from the same places (lines 5221, 6912; automatch `SendAIOptionToServer`). The server keeps `AIs[aiName][key] = value` and reads `StartSpot` when a slot is cleared (`server/games/game.py:630-657`).

<!-- schema: FromGame.AIOption -->
```json
{
  "title": "AIOption",
  "description": "One field of an AI slot, sent by the host.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "AIOption"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/String", "description": "aiName: the slot's PlayerName"},
        {"$ref": "#/$defs/String", "description": "key: same keys as PlayerOption"},
        {"$ref": "#/$defs/OptionValue", "description": "value"}
      ],
      "minItems": 3,
      "items": false
    }
  },
  "examples": [{"command": "AIOption", "target": "game", "args": ["AI: Adaptive", "Team", 3]}]
}
```
<!-- /schema -->

### ClearSlot

`ClearSlot(slot: int)` — `lua/ui/lobby/lobby.lua:1315`. The server sets `Team`, `Army`, `StartSpot` to -1 for players on that slot and removes AIs on it.

<!-- schema: FromGame.ClearSlot -->
```json
{
  "title": "ClearSlot",
  "description": "The host emptied a slot.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "ClearSlot"},
    "args": {
      "prefixItems": [{"$ref": "#/$defs/Int32", "description": "slot: 1..16", "minimum": 1, "maximum": 16}],
      "minItems": 1,
      "items": false
    }
  },
  "examples": [{"command": "ClearSlot", "target": "game", "args": [3]}]
}
```
<!-- /schema -->

### GameMods

`GameMods("activated", count: int)`, then `GameMods("uids", uids: string)` when count > 0 — `lua/ui/lobby/lobby.lua:7429-7432`. The uids are space-separated.

<!-- schema: FromGame.GameMods -->
```json
{
  "title": "GameMods",
  "description": "The host's sim mods: first the count, then (when there are any) their uids.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "GameMods"},
    "args": {
      "oneOf": [
        {
          "prefixItems": [
            {"$ref": "#/$defs/String", "const": "activated"},
            {"$ref": "#/$defs/Int32", "description": "count", "minimum": 0}
          ],
          "minItems": 2,
          "items": false
        },
        {
          "prefixItems": [
            {"$ref": "#/$defs/String", "const": "uids"},
            {"$ref": "#/$defs/String", "description": "space-separated mod uids"}
          ],
          "minItems": 2,
          "items": false
        }
      ]
    }
  },
  "examples": [
    {"command": "GameMods", "target": "game", "args": ["activated", 1]},
    {"command": "GameMods", "target": "game", "args": ["uids", "e7846e9b-23a4-4b95-ae3a-fb69b289a585"]}
  ]
}
```
<!-- /schema -->

### GameFull

`GameFull()` — `lua/ui/lobby/lobby.lua:1629`. Handled by the FAF client itself ([LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md), section 2).

<!-- schema: FromGame.GameFull -->
```json
{
  "title": "GameFull",
  "description": "Every open slot is taken. The FAF client handles it; the lobby server ignores it.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "GameFull"}, "args": {"maxItems": 0}},
  "examples": [{"command": "GameFull", "target": "game", "args": []}]
}
```
<!-- /schema -->

### Chat

`Chat(text: string)` — `lua/ui/lobby/lobby.lua:4579`.

<!-- schema: FromGame.Chat -->
```json
{
  "title": "Chat",
  "description": "A lobby chat line.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "Chat"},
    "args": {"prefixItems": [{"$ref": "#/$defs/String", "description": "text"}], "minItems": 1, "items": false}
  },
  "examples": [{"command": "Chat", "target": "game", "args": ["gl hf"]}]
}
```
<!-- /schema -->

### Disconnected

`Disconnected(uid: uid text)` — `lua/ui/lobby/lobby.lua:873`, formatted with `%d`.

<!-- schema: FromGame.Disconnected -->
```json
{
  "title": "Disconnected",
  "description": "A peer left the lobby. The lobby server only logs it.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "Disconnected"},
    "args": {"prefixItems": [{"$ref": "#/$defs/UidText", "description": "uid"}], "minItems": 1, "items": false}
  },
  "examples": [{"command": "Disconnected", "target": "game", "args": ["123456"]}]
}
```
<!-- /schema -->

### LaunchStatus

`LaunchStatus(status: string)` — automatch lobby (`AutolobbyServerCommunicationsComponent.lua`). The values are its `UIPeerLaunchStatus` list; `Unknown` is never sent.

<!-- schema: FromGame.LaunchStatus -->
```json
{
  "title": "LaunchStatus",
  "description": "Automatch lobby only: the local peer's launch status.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "LaunchStatus"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/String",
          "enum": ["Connecting", "Missing local peers", "Rejoining", "Ready", "Ejected", "Rejected", "Failed"]
        }
      ],
      "minItems": 1,
      "items": false
    }
  },
  "examples": [{"command": "LaunchStatus", "target": "game", "args": ["Ready"]}]
}
```
<!-- /schema -->

### EstablishedPeer

`EstablishedPeer(peerId: uid text)` — automatch lobby.

<!-- schema: FromGame.EstablishedPeer -->
```json
{
  "title": "EstablishedPeer",
  "description": "Automatch lobby only: connected to a peer. May repeat for the same peer.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "EstablishedPeer"},
    "args": {"prefixItems": [{"$ref": "#/$defs/UidText", "description": "peerId"}], "minItems": 1, "items": false}
  },
  "examples": [{"command": "EstablishedPeer", "target": "game", "args": ["123456"]}]
}
```
<!-- /schema -->

### DisconnectedPeer

`DisconnectedPeer(peerId: uid text)` — automatch lobby.

<!-- schema: FromGame.DisconnectedPeer -->
```json
{
  "title": "DisconnectedPeer",
  "description": "Automatch lobby only: lost a peer, which may be rejoining.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "DisconnectedPeer"},
    "args": {"prefixItems": [{"$ref": "#/$defs/UidText", "description": "peerId"}], "minItems": 1, "items": false}
  },
  "examples": [{"command": "DisconnectedPeer", "target": "game", "args": ["123456"]}]
}
```
<!-- /schema -->

### GameResult

`GameResult(army: int, result: string)` — `lua/UserSync.lua:89`, from `Sync.GameResult`. Today's Lua sends `"victory 10"`, `"defeat -10"` or `"draw 0"` (`lua/sim/VictoryCondition/AbstractVictoryCondition.lua:373,391,409`). The server takes the last two words as result and score and keeps any earlier words as metadata.

<!-- schema: FromGame.GameResult -->
```json
{
  "title": "GameResult",
  "description": "One army's result, sent by every client when the army is decided. The server splits the text on spaces: the last two words are result and score, any words before them are kept as metadata.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "GameResult"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Int32", "description": "army: 1-based army index", "minimum": 1},
        {
          "$ref": "#/$defs/String",
          "description": "result: what today's FAF Lua sends",
          "enum": ["victory 10", "defeat -10", "draw 0"]
        }
      ],
      "minItems": 2,
      "items": false
    }
  },
  "examples": [{"command": "GameResult", "target": "game", "args": [1, "victory 10"]}]
}
```
<!-- /schema -->

### JsonStats

`JsonStats(json: string)` — one string holding a JSON document, sent once per game by every client that is not watching a replay, on the sync after game over (`lua/UserSync.lua:94-97`). The document is described in [section 4](#4-jsonstats-payload); in the schema it is the argument's `contentSchema`.

<!-- schema: FromGame.JsonStats -->
```json
{
  "title": "JsonStats",
  "description": "End-of-game army statistics, sent once by every client.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "JsonStats"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/String",
          "description": "A JSON document",
          "contentMediaType": "application/json",
          "contentSchema": {"$ref": "#/$defs/JsonStatsPayload"}
        }
      ],
      "minItems": 1,
      "items": false
    }
  },
  "examples": [
    {
      "command": "JsonStats",
      "target": "game",
      "args": [
        "{\"stats\":[{\"name\":\"Player1\",\"type\":\"Human\",\"faction\":1,\"general\":{\"score\":5370,\"lastupdatetick\":18240,\"currentunits\":87,\"currentcap\":1000,\"kills\":{\"count\":11,\"mass\":18483.28,\"energy\":5002463},\"built\":{\"count\":19,\"mass\":532,\"energy\":4160},\"lost\":{\"count\":1,\"mass\":18000,\"energy\":5000000}},\"units\":{\"land\":{\"kills\":3,\"built\":12,\"lost\":1},\"cdr\":{\"kills\":1,\"built\":0,\"lost\":0},\"sacu\":{\"kills\":0,\"built\":0,\"lost\":0}},\"blueprints\":{\"uel0001\":{\"kills\":1,\"built\":0,\"lost\":0,\"lowest_health\":4210.5}},\"resources\":{\"massin\":{\"total\":1004.2,\"rate\":0.8,\"reclaimed\":120,\"reclaimRate\":0},\"massout\":{\"total\":950,\"rate\":0.7,\"excess\":12},\"energyin\":{\"total\":10129.7,\"rate\":4,\"reclaimed\":0,\"reclaimRate\":0},\"energyout\":{\"total\":9800,\"rate\":3.9,\"excess\":300},\"storage\":{\"storedMass\":54,\"storedEnergy\":330,\"maxMass\":650,\"maxEnergy\":4000}}}]}"
      ]
    }
  ]
}
```
<!-- /schema -->

### EnforceRating

`EnforceRating()` — `lua/UserSync.lua:121`.

<!-- schema: FromGame.EnforceRating -->
```json
{
  "title": "EnforceRating",
  "description": "Rate the game even if it ends early.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "EnforceRating"}, "args": {"maxItems": 0}},
  "examples": [{"command": "EnforceRating", "target": "game", "args": []}]
}
```
<!-- /schema -->

### GameEnded

`GameEnded()` — `lua/UserSync.lua:126`. The ICE adapter also reads it and stops reconnecting (`GPGNetServer.processGpgnetMessage`).

<!-- schema: FromGame.GameEnded -->
```json
{
  "title": "GameEnded",
  "description": "The simulation has ended.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "GameEnded"}, "args": {"maxItems": 0}},
  "examples": [{"command": "GameEnded", "target": "game", "args": []}]
}
```
<!-- /schema -->

### TeamkillHappened

`TeamkillHappened(time: int, victimId, victimName: string, killerId, killerName: string)` — `lua/UserSync.lua:111`. `time` is `GetGameTimeSeconds()` at the kill, truncated. An id is the player's uid as text from `GetSessionClients()`, or the int `0` when the army has no client; the server skips the record when either id is 0.

<!-- schema: FromGame.TeamkillHappened -->
```json
{
  "title": "TeamkillHappened",
  "description": "An ACU was killed by an ally. Sent by every client.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "TeamkillHappened"}, "args": {"$ref": "#/$defs/TeamkillArgs"}},
  "examples": [{"command": "TeamkillHappened", "target": "game", "args": [412, "123456", "Victim", "654321", "Killer"]}]
}
```
<!-- /schema -->

Shared argument list:

<!-- schema: TeamkillArgs -->
```json
{
  "prefixItems": [
    {"$ref": "#/$defs/Int32", "description": "time: game seconds, truncated"},
    {"$ref": "#/$defs/TeamkillPlayerId", "description": "victim id"},
    {"$ref": "#/$defs/String", "description": "victim name, or '-'"},
    {"$ref": "#/$defs/TeamkillPlayerId", "description": "killer id"},
    {"$ref": "#/$defs/String", "description": "killer name, or '-'"}
  ],
  "minItems": 5,
  "items": false
}
```
<!-- /schema -->

<!-- schema: TeamkillPlayerId -->
```json
{
  "description": "The player's FAF user id as text, or the int 0 when the army has no client (an AI).",
  "oneOf": [{"$ref": "#/$defs/UidText"}, {"$ref": "#/$defs/Int32", "const": 0}]
}
```
<!-- /schema -->

### TeamkillReport

`TeamkillReport(...)` — the arguments of `TeamkillHappened`, sent when the victim presses Report (`lua/ui/dialogs/teamkill.lua:49`).

<!-- schema: FromGame.TeamkillReport -->
```json
{
  "title": "TeamkillReport",
  "description": "The victim pressed Report in the teamkill dialog. Same arguments as TeamkillHappened; the lobby server ignores it.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "TeamkillReport"}, "args": {"$ref": "#/$defs/TeamkillArgs"}},
  "examples": [{"command": "TeamkillReport", "target": "game", "args": [412, "123456", "Victim", "654321", "Killer"]}]
}
```
<!-- /schema -->

### OperationComplete

`OperationComplete(primary: 0|1, secondary: 0|1, time: string)` — co-op, `lua/UserSync.lua:405`. `time` is `GetGameTime()`, which returns the game time as formatted text.

<!-- schema: FromGame.OperationComplete -->
```json
{
  "title": "OperationComplete",
  "description": "Co-op: the mission was completed.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "OperationComplete"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Flag", "description": "all primary objectives done"},
        {"$ref": "#/$defs/Flag", "description": "all secondary objectives done"},
        {"$ref": "#/$defs/String", "description": "time: GetGameTime(), the formatted game time"}
      ],
      "minItems": 3,
      "items": false
    }
  },
  "examples": [{"command": "OperationComplete", "target": "game", "args": [1, 0, "00:42:17"]}]
}
```
<!-- /schema -->

### Rehost

`Rehost()` — `lua/ui/game/tabs.lua:347`.

<!-- schema: FromGame.Rehost -->
```json
{
  "title": "Rehost",
  "description": "The player chose Rehost after the game. The lobby server ignores it.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "Rehost"}, "args": {"maxItems": 0}},
  "examples": [{"command": "Rehost", "target": "game", "args": []}]
}
```
<!-- /schema -->

### BEAT

`BEAT(tick: int, speed: int)` — `lua/ui/game/gamemain.lua:1212`, `GameTick()` and `GetGameSpeed()`.

<!-- schema: FromGame.BEAT -->
```json
{
  "title": "BEAT",
  "description": "Periodic game progress from the in-game UI. The lobby server has no handler for it.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "BEAT"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Int32", "description": "GameTick()"},
        {"$ref": "#/$defs/Int32", "description": "GetGameSpeed()"}
      ],
      "minItems": 2,
      "items": false
    }
  },
  "examples": [{"command": "BEAT", "target": "game", "args": [6000, 0]}]
}
```
<!-- /schema -->

### Bottleneck

`Bottleneck(kind, beat, ids, ms)` — engine ([CGpgNetInterface.cpp:404-460](../src/moho/net/CGpgNetInterface.cpp#L404-L460)). All four are strings, formatted with `%u`, `%u` (comma-joined) and `%.1f`.

<!-- schema: FromGame.Bottleneck -->
```json
{
  "title": "Bottleneck",
  "description": "The engine is waiting on other clients. All four arguments are strings.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "Bottleneck"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/String",
          "description": "kind",
          "enum": ["nothing", "readiness", "data", "ack", "unknown"]
        },
        {"$ref": "#/$defs/String", "description": "beat number", "pattern": "^[0-9]+$"},
        {
          "$ref": "#/$defs/String",
          "description": "comma-separated user ids of the clients waited on",
          "pattern": "^([0-9]+(,[0-9]+)*)?$"
        },
        {
          "$ref": "#/$defs/String",
          "description": "milliseconds, one decimal",
          "pattern": "^-?[0-9]+\\.[0-9]$"
        }
      ],
      "minItems": 4,
      "items": false
    }
  },
  "examples": [{"command": "Bottleneck", "target": "game", "args": ["data", "19508", "517268,516974,344419", "5980.1"]}]
}
```
<!-- /schema -->

### BottleneckCleared

`BottleneckCleared()` — engine.

<!-- schema: FromGame.BottleneckCleared -->
```json
{
  "title": "BottleneckCleared",
  "description": "The engine stopped waiting.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "BottleneckCleared"}, "args": {"maxItems": 0}},
  "examples": [{"command": "BottleneckCleared", "target": "game", "args": []}]
}
```
<!-- /schema -->

### Desync

`Desync(beat: int, army: int, hash: string, hash: string)` — engine ([CGpgNetInterface.cpp:486-503](../src/moho/net/CGpgNetInterface.cpp#L486-L503)). The hashes are MD5 digests as 32 lowercase hex characters.

<!-- schema: FromGame.Desync -->
```json
{
  "title": "Desync",
  "description": "The sim checksum differs from another client's. Repeats while the game stays desynced; the server records each player's first report.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "Desync"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Int32", "description": "beat"},
        {"$ref": "#/$defs/Int32", "description": "army: the index in the engine's desync record"},
        {"$ref": "#/$defs/String", "description": "MD5 checksum, hex", "pattern": "^[0-9a-f]{32}$"},
        {"$ref": "#/$defs/String", "description": "the other MD5 checksum, hex", "pattern": "^[0-9a-f]{32}$"}
      ],
      "minItems": 4,
      "items": false
    }
  },
  "examples": [
    {
      "command": "Desync",
      "target": "game",
      "args": [1234, 1, "9e107d9d372bb6826bd81d3542a419d6", "e4d909c290d0fb1ca068ffaddf22cbd0"]
    }
  ]
}
```
<!-- /schema -->

### Stats

`Stats(xml: string)` — engine ([CGpgNetInterface.cpp:512-523](../src/moho/net/CGpgNetInterface.cpp#L512-L523)), retail's statistics as XML, built when sim Lua calls `SubmitXMLArmyStats()`. FAF's Lua never calls it.

<!-- schema: FromGame.Stats -->
```json
{
  "title": "Stats",
  "description": "Retail's XML army statistics, sent when sim Lua calls SubmitXMLArmyStats(). FAF's Lua never calls it and the lobby server has no handler; JsonStats replaced it.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "Stats"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/String",
          "description": "<?xml ...?><GameStats>...</GameStats>",
          "contentMediaType": "application/xml"
        }
      ],
      "minItems": 1,
      "items": false
    }
  }
}
```
<!-- /schema -->

### ProcessNatPacket

`ProcessNatPacket(from: "ip:port", packet: data)` — engine ([CGpgNetInterface.cpp:906-924](../src/moho/net/CGpgNetInterface.cpp#L906-L924)).

<!-- schema: FromGame.ProcessNatPacket -->
```json
{
  "title": "ProcessNatPacket",
  "description": "A UDP packet that arrived on the game port and was not game traffic, handed to the adapter for NAT traversal.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "ProcessNatPacket"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Endpoint", "description": "sender, ip:port"},
        {"$ref": "#/$defs/Data", "description": "packet bytes"}
      ],
      "minItems": 2,
      "items": false
    }
  }
}
```
<!-- /schema -->

## 4. JsonStats payload

The table is `ArmyScore` from `lua/sim/score.lua`, handed over at game over (`Sync.StatsToSend = ArmyScore`, line 352) after `GameOverScore()` has added the achievement fields, and encoded with `lua/system/dkson.lua`.

<!-- schema: JsonStatsPayload -->
```json
{
  "title": "JsonStats payload",
  "description": "The JSON document inside JsonStats: lua/sim/score.lua's ArmyScore table at game over, encoded by lua/system/dkson.lua.",
  "type": "object",
  "required": ["stats"],
  "properties": {
    "stats": {
      "description": "One entry per non-civilian army in army index order. A civilian army between two players leaves a null.",
      "type": "array",
      "items": {"oneOf": [{"$ref": "#/$defs/ArmyStats"}, {"type": "null"}]}
    }
  }
}
```
<!-- /schema -->

<!-- schema: ArmyStats -->
```json
{
  "type": "object",
  "required": ["name", "type", "faction", "general", "units", "resources"],
  "properties": {
    "name": {"type": "string", "description": "brain.Nickname"},
    "type": {"enum": ["Human", "AI"], "description": "brain.BrainType"},
    "faction": {"type": "integer", "description": "brain:GetFactionIndex(): 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim"},
    "Defeated": {"type": "number", "description": "Present once the army is defeated: game seconds + 15, later -1."},
    "general": {
      "type": "object",
      "properties": {
        "score": {"type": "integer", "description": "CalculateBrainScore(brain)"},
        "lastupdatetick": {"type": "integer"},
        "currentunits": {"type": "number", "description": "army stat UnitCap_Current"},
        "currentcap": {"type": "number", "description": "army stat UnitCap_MaxCap"},
        "kills": {
          "$ref": "#/$defs/CountMassEnergy",
          "description": "Enemies_Killed, Enemies_MassValue_Destroyed, Enemies_EnergyValue_Destroyed"
        },
        "built": {
          "$ref": "#/$defs/CountMassEnergy",
          "description": "Units_History, Units_MassValue_Built, Units_EnergyValue_Built"
        },
        "lost": {
          "$ref": "#/$defs/CountMassEnergy",
          "description": "Units_Killed, Units_MassValue_Lost, Units_EnergyValue_Lost"
        }
      }
    },
    "units": {
      "type": "object",
      "description": "Per category. land, air, naval, cdr, experimental, structures are kept during the game; transportation, sacu, engineer, tech1, tech2, tech3 are added at game over.",
      "propertyNames": {
        "enum": [
          "land",
          "air",
          "naval",
          "cdr",
          "experimental",
          "structures",
          "transportation",
          "sacu",
          "engineer",
          "tech1",
          "tech2",
          "tech3"
        ]
      },
      "additionalProperties": {"$ref": "#/$defs/KillsBuiltLost"}
    },
    "blueprints": {
      "type": "object",
      "description": "Units the server's achievements count, only those the army has a record for: ACUs, T3 air superiority fighters, experimentals, Mercy, Fire Beetle.",
      "propertyNames": {
        "enum": [
          "ual0001",
          "url0001",
          "uel0001",
          "xsl0001",
          "uaa0303",
          "ura0303",
          "uea0303",
          "xsa0303",
          "xab1401",
          "uaa0310",
          "ual0401",
          "uas0401",
          "xab2307",
          "ueb2401",
          "uel0401",
          "xeb2402",
          "ues0401",
          "ura0401",
          "url0401",
          "url0402",
          "xrl0403",
          "xsb2401",
          "xsa0402",
          "xsl0401",
          "daa0206",
          "xrl0302"
        ]
      },
      "additionalProperties": {
        "allOf": [{"$ref": "#/$defs/KillsBuiltLost"}],
        "properties": {"lowest_health": {"type": "number", "description": "ACUs only: the lowest health the ACU had"}}
      }
    },
    "resources": {
      "type": "object",
      "properties": {
        "massin": {"$ref": "#/$defs/ResourceIn"},
        "energyin": {"$ref": "#/$defs/ResourceIn"},
        "massout": {"$ref": "#/$defs/ResourceOut"},
        "energyout": {"$ref": "#/$defs/ResourceOut"},
        "storage": {
          "type": "object",
          "properties": {
            "storedMass": {"type": "number"},
            "storedEnergy": {"type": "number"},
            "maxMass": {"type": "number"},
            "maxEnergy": {"type": "number"}
          }
        }
      }
    }
  }
}
```
<!-- /schema -->

<!-- schema: CountMassEnergy -->
```json
{
  "type": "object",
  "properties": {"count": {"type": "number"}, "mass": {"type": "number"}, "energy": {"type": "number"}}
}
```
<!-- /schema -->

<!-- schema: KillsBuiltLost -->
```json
{
  "type": "object",
  "required": ["kills", "built", "lost"],
  "properties": {"kills": {"type": "number"}, "built": {"type": "number"}, "lost": {"type": "number"}}
}
```
<!-- /schema -->

<!-- schema: ResourceIn -->
```json
{
  "type": "object",
  "properties": {
    "total": {"type": "number"},
    "rate": {"type": "number"},
    "reclaimed": {"type": "number"},
    "reclaimRate": {"type": "number"}
  }
}
```
<!-- /schema -->

<!-- schema: ResourceOut -->
```json
{
  "type": "object",
  "properties": {"total": {"type": "number"}, "rate": {"type": "number"}, "excess": {"type": "number"}}
}
```
<!-- /schema -->

Notes:

- **`units` categories.** `land`, `air`, `naval`, `cdr` (COMMAND), `experimental`, `structures` are updated during the game (`categoriesToCollect`). `transportation`, `sacu` (SUBCOMMANDER), `engineer`, `tech1`, `tech2`, `tech3` are added only at game over (`categoriesForAchievements`). Values come from `GetBlueprintStat("Enemies_Killed" / "Units_History" / "Units_Killed", category)`.
- **`blueprints`.** `kills`, `built`, `lost` are set to 0 when missing. `lowest_health` is written only for ACUs (`lua/sim/units/ACUUnit.lua:61,97`).
- **Numbers.** Counters are whole numbers; mass/energy values, rates and health are fractional.
- **Array or object.** `stats` is a Lua table keyed by army index with civilian armies left out. dkson writes it as an array when the keys are 1..n; a civilian army between two players leaves a `null`. With more than 10 slots and more holes than entries, dkson writes an object keyed by index instead (`isarray`, `dkson.lua:56-77`); the schema does not allow that case. Civilians are normally the last armies, so in practice it is an array.
- **The server's sample is older.** `tests/data/game_stats_simple_win.json` in the server repo has `currentcap` and `currentunits` as `{ "count": n }` objects and top-level `general.mass` / `general.energy`. Today's Lua sends plain numbers and neither of those fields; the server reads none of them.

What the server reads (`server/stats/game_stats_service.py`): per entry `type`, `name`, `general.score`, `faction`, `units.<category>.built|lost|kills` for `air land naval experimental cdr tech1 tech2 tech3 engineer transportation sacu`, and `blueprints.<unit id>.built` / `.lowest_health`. Stats are skipped for games with an AI (other than one named `civilian`) or fewer than 2 humans. `server/games/game.py:535-538` also reads `units.cdr.kills` per army name.

## 5. Messages to the game

The engine dispatches these in `CGpgNetInterface::PullTask` ([CGpgNetInterface.cpp:1449-1502](../src/moho/net/CGpgNetInterface.cpp#L1449-L1502)). A wrong argument count or type throws, and the message is dropped with `GPGNET: command processing failed` in the log. Int arguments must arrive as ints: a numeric string is refused (`ExpectIntArg`, line 97).

### Connected

`Connected()` ([:1551](../src/moho/net/CGpgNetInterface.cpp#L1551)). The engine queues this command to itself when the GPGNet socket connects ([:2042](../src/moho/net/CGpgNetInterface.cpp#L2042)); handling it is what sends `GameState Idle`. The ICE adapter never sends it.

<!-- schema: ToGame.Connected -->
```json
{
  "title": "Connected",
  "description": "The engine queues this to itself when the GPGNet socket connects and answers it with GameState Idle. Must have no arguments.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "Connected"}, "args": {"maxItems": 0}}
}
```
<!-- /schema -->

### CreateLobby

`CreateLobby(mode, port, name, uid, nat)` ([:1621](../src/moho/net/CGpgNetInterface.cpp#L1621)). The ICE adapter sends it when the game reports `Idle` (`GPGNetServer.processGpgnetMessage`), with mode from its `LobbyInitMode` (0 `normal`, 1 `auto`). The game loads `lua/ui/lobby/lobby.lua` or `autolobby.lua` (`lua/multiplayer/onlineprovider.lua`, `CreateLobby(autolaunch, ...)`) and answers `GameState Lobby`.

<!-- schema: ToGame.CreateLobby -->
```json
{
  "title": "CreateLobby",
  "description": "Open the lobby screen. The ICE adapter sends it when the game reports GameState Idle; the game answers GameState Lobby.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "CreateLobby"},
    "args": {
      "prefixItems": [
        {
          "$ref": "#/$defs/Int32",
          "description": "lobby mode: 0 normal lobby, 1 automatch lobby (Lua's autolaunch)",
          "enum": [0, 1]
        },
        {"$ref": "#/$defs/Int32", "description": "local UDP port for game traffic"},
        {"$ref": "#/$defs/String", "description": "player name"},
        {"$ref": "#/$defs/Int32", "description": "player's FAF user id"},
        {"$ref": "#/$defs/Int32", "description": "NAT traversal flag; the ICE adapter sends 1"}
      ],
      "minItems": 5,
      "items": false
    }
  },
  "examples": [{"command": "CreateLobby", "args": [0, 6112, "Player1", 123456, 1]}]
}
```
<!-- /schema -->

### HostGame

`HostGame(map?: string)` ([:1687](../src/moho/net/CGpgNetInterface.cpp#L1687)). The lobby server sends the map's folder name (`server/protocol/gpgnet.py`).

<!-- schema: ToGame.HostGame -->
```json
{
  "title": "HostGame",
  "description": "Host the game. The engine turns the map folder name into /maps/<name>/<name>_scenario.lua.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "HostGame"},
    "args": {
      "prefixItems": [{"$ref": "#/$defs/String", "description": "map folder name"}],
      "maxItems": 1,
      "items": false
    }
  },
  "examples": [{"command": "HostGame", "args": ["scmp_009"]}]
}
```
<!-- /schema -->

### JoinGame

`JoinGame(endpoint, hostName, hostUid)` ([:1717](../src/moho/net/CGpgNetInterface.cpp#L1717)). The lobby server sends `[hostName, hostUid]`; the ICE adapter puts its local endpoint for that peer in front (`IceAdapter.java`).

<!-- schema: ToGame.JoinGame -->
```json
{
  "title": "JoinGame",
  "description": "Join the host's lobby. The lobby server sends [hostName, hostUid]; the ICE adapter adds its local relay endpoint in front.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "JoinGame"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Endpoint", "description": "where the host can be reached"},
        {"$ref": "#/$defs/String", "description": "host's name"},
        {"$ref": "#/$defs/Int32", "description": "host's FAF user id"}
      ],
      "minItems": 3,
      "items": false
    }
  },
  "examples": [{"command": "JoinGame", "args": ["127.0.0.1:52001", "HostPlayer", 654321]}]
}
```
<!-- /schema -->

### ConnectToPeer

`ConnectToPeer(endpoint, name, uid)` ([:1744](../src/moho/net/CGpgNetInterface.cpp#L1744)). The lobby server sends `[name, uid, offer]`; the adapter keeps `offer` and sends the game `[endpoint, name, uid]`.

<!-- schema: ToGame.ConnectToPeer -->
```json
{
  "title": "ConnectToPeer",
  "description": "Connect to another player. The lobby server sends [name, uid, offer]; the ICE adapter sends the game [endpoint, name, uid].",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "ConnectToPeer"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Endpoint", "description": "where the peer can be reached"},
        {"$ref": "#/$defs/String", "description": "peer's name"},
        {"$ref": "#/$defs/Int32", "description": "peer's FAF user id"}
      ],
      "minItems": 3,
      "items": false
    }
  },
  "examples": [{"command": "ConnectToPeer", "args": ["127.0.0.1:52002", "OtherPlayer", 111111]}]
}
```
<!-- /schema -->

### DisconnectFromPeer

`DisconnectFromPeer(uid: int)` ([:1771](../src/moho/net/CGpgNetInterface.cpp#L1771)).

<!-- schema: ToGame.DisconnectFromPeer -->
```json
{
  "title": "DisconnectFromPeer",
  "description": "Drop the link to a player.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "DisconnectFromPeer"},
    "args": {
      "prefixItems": [{"$ref": "#/$defs/Int32", "description": "peer's FAF user id"}],
      "minItems": 1,
      "items": false
    }
  },
  "examples": [{"command": "DisconnectFromPeer", "args": [111111]}]
}
```
<!-- /schema -->

### HasSupcom

`HasSupcom(value: int)` ([:1795](../src/moho/net/CGpgNetInterface.cpp#L1795)).

<!-- schema: ToGame.HasSupcom -->
```json
{
  "title": "HasSupcom",
  "description": "Calls the lobby's SetHasSupcom(value).",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "HasSupcom"},
    "args": {"prefixItems": [{"$ref": "#/$defs/Int32"}], "minItems": 1, "items": false}
  }
}
```
<!-- /schema -->

### HasForgedAlliance

`HasForgedAlliance(value: int)` ([:1816](../src/moho/net/CGpgNetInterface.cpp#L1816)).

<!-- schema: ToGame.HasForgedAlliance -->
```json
{
  "title": "HasForgedAlliance",
  "description": "Calls the lobby's SetHasForgedAlliance(value).",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "HasForgedAlliance"},
    "args": {"prefixItems": [{"$ref": "#/$defs/Int32"}], "minItems": 1, "items": false}
  }
}
```
<!-- /schema -->

### SendNatPacket

`SendNatPacket(to: "ip:port", packet: data)` ([:1838](../src/moho/net/CGpgNetInterface.cpp#L1838)). The packet must have wire tag 2.

<!-- schema: ToGame.SendNatPacket -->
```json
{
  "title": "SendNatPacket",
  "description": "Send raw bytes from the game's UDP port, for NAT traversal.",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "SendNatPacket"},
    "args": {
      "prefixItems": [
        {"$ref": "#/$defs/Endpoint", "description": "destination ip:port"},
        {"$ref": "#/$defs/Data", "description": "packet bytes; must be wire tag 2"}
      ],
      "minItems": 2,
      "items": false
    }
  }
}
```
<!-- /schema -->

### EjectPlayer

`EjectPlayer(uid: int)` ([:1877](../src/moho/net/CGpgNetInterface.cpp#L1877)). Needs a running game.

<!-- schema: ToGame.EjectPlayer -->
```json
{
  "title": "EjectPlayer",
  "description": "During a game: eject the client with this user id (or disconnect, when it is the local one).",
  "$ref": "#/$defs/Envelope",
  "properties": {
    "command": {"const": "EjectPlayer"},
    "args": {"prefixItems": [{"$ref": "#/$defs/Int32", "description": "FAF user id"}], "minItems": 1, "items": false}
  },
  "examples": [{"command": "EjectPlayer", "args": [111111]}]
}
```
<!-- /schema -->

### Test

`Test(...)` ([:1510](../src/moho/net/CGpgNetInterface.cpp#L1510)). Any arguments; each is logged with its type.

<!-- schema: ToGame.Test -->
```json
{
  "title": "Test",
  "description": "Debug: the game logs each argument with its type.",
  "$ref": "#/$defs/Envelope",
  "properties": {"command": {"const": "Test"}}
}
```
<!-- /schema -->

## 6. Not covered

faf-re's own additions are not in the schema, and the stock FAF client, adapter and server don't use them: `RejoinOffer` (issue #275, off unless the game starts with `/rejoinoffer`; see [SWITCHES.md](SWITCHES.md) and [LAUNCHER_NATIVE_NETWORK.md](LAUNCHER_NATIVE_NETWORK.md)), the native-network messages (issue #274, [LAUNCHER_NATIVE_NETWORK.md](LAUNCHER_NATIVE_NETWORK.md)) and the `Netlink*` messages (issue #233, [LAUNCHER_ADAPTER_CONTRACT.md](LAUNCHER_ADAPTER_CONTRACT.md) section 8).
