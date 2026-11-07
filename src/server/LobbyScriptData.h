#pragma once

#include <cstdint>
#include <map>
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
} // namespace faf::server
