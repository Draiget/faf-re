#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Engine addition, dedicated server (plan WPR.49): the lobby's script data as the relay reads it. FAF's lobby sends Lua
// tables between participants in `LuaObject::ToByteStream`'s form: a tag, then 0 a number as a 32-bit float, 1 a
// string up to its NUL, 2 nil, 3 a boolean byte, 4 a table's key/value pairs up to a 5. No Lua state: the relay runs on
// the network thread, and reads no more than a message's `Type` and its game options, which it may write back.

namespace faf::server
{
  struct SLuaBytesValue
  {
    enum class EKind : std::uint8_t
    {
      Number = 0,
      String = 1,
      Nil = 2,
      Boolean = 3,
      Table = 4,
    };

    EKind kind = EKind::Nil;
    std::uint8_t raw[4]{};                // a number's float, or a boolean's byte, as written
    std::string text;                     // a string's
    std::vector<SLuaBytesValue> keys;     // a table's, in the order written
    std::vector<SLuaBytesValue> values;   // likewise

    [[nodiscard]] bool IsString(std::string_view value) const noexcept { return kind == EKind::String && text == value; }
    /** The value under a string key of a table, or null. */
    [[nodiscard]] SLuaBytesValue* Field(std::string_view key) noexcept;
  };

  /** Tables nested deeper than this aren't read (a lobby message is a few levels deep). */
  constexpr int kLuaBytesMaxDepth = 32;

  /** `bytes` hold exactly one value. False for anything else. */
  [[nodiscard]] bool ParseLuaBytes(std::span<const std::uint8_t> bytes, SLuaBytesValue& out);
  /** Appends `value` in the same form. */
  void WriteLuaBytes(const SLuaBytesValue& value, std::vector<std::uint8_t>& out);

  /** Option key, and the bytes of its value (one value in the form above) as the match sets it. */
  using SPinnedOptions = std::map<std::string, std::vector<std::uint8_t>>;

  /**
   * Plan WPR.49: FAF's lobby script data (the payload of `LOBMSG_BroadcastScriptData` / `LOBMSG_DirectScriptData`) with
   * the match's pinned options put back. A `{Type = 'GameOptions', Options = {...}}` message (lobby.lua
   * `SetGameOptions`) gets the match's value for each pinned key it names; a `{Type = 'GameInfo', GameInfo = {...}}`
   * one (`SendCompleteGameStateToPeer`) gets every pinned key in its `GameOptions`. True when `payload` was rewritten;
   * anything else, unreadable bytes included, stays as it is.
   */
  [[nodiscard]] bool PinGameOptions(std::vector<std::uint8_t>& payload, const SPinnedOptions& pinned);

  /** What `LimitPlayerScript` did. */
  enum class EPlayerScript : std::uint8_t
  {
    Unchanged,
    Rewritten, // a `PlayerOptions` message kept only `Ready`
    Refused,   // a request to move, change colour or change sides, or `PlayerOptions` with nothing but those left
  };

  /**
   * Plan WP17.6: FAF's lobby script data from a player who isn't the lobby's host, in an organiser-run lobby, where the
   * organiser set slots, teams and the rest. `MovePlayer`, `RequestColor`, `RequestConvertToObserver` and
   * `RequestConvertToPlayer` (lobby.lua's requests to the host) are refused; `{Type = 'PlayerOptions', Options = {...}}`
   * (`SetPlayerOptions`, the player's own slot) keeps only `Ready`. Anything else, unreadable bytes included, stays.
   */
  [[nodiscard]] EPlayerScript LimitPlayerScript(std::vector<std::uint8_t>& payload);

  /** Plan WP17.2: what the control service reads from one lobby message (who sits where, who is ready). */
  struct SLobbyFacts
  {
    std::optional<bool> ready; // `{Type = 'PlayerOptions', Slot = n, Options = {Ready = ...}}`
    std::optional<int> slot;   // that message's `Slot`
    // (OwnerID, lobby slot) from the host's `SlotAssigned` (`Slot`), `SlotMove` (`NewSlot`) and `GameInfo`
    // (`GameInfo.PlayerOptions`, keyed by slot); lobby.lua `HostUtils.TryAddPlayer`, `MovePlayerToEmptySlot`,
    // `SendCompleteGameStateToPeer`. Each says where a player sits, so reading it once per recipient (a broadcast comes
    // as one message to each) says the same. `SwapPlayers` isn't read: applied once per recipient it would swap back,
    // and an organised lobby's host has no swap (plan WP17.6's screen); only an organised lobby's slots are the
    // control service's.
    std::vector<std::pair<std::int32_t, int>> seats;
  };
  [[nodiscard]] SLobbyFacts ReadLobbyFacts(std::span<const std::uint8_t> payload);

  /**
   * Plan WP15.4: `bytes` (one table in the form above) with the number under the string key `key` of the top table set to
   * `value`, into `out`. False, `out` untouched, when the bytes don't read or the key isn't a number there.
   */
  [[nodiscard]] bool SetTableNumber(std::span<const std::uint8_t> bytes, std::string_view key, float value, std::vector<std::uint8_t>& out);
} // namespace faf::server
