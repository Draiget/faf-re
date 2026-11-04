#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan §8, WP7): the Lua lane of a player's beat: the player's `Sync`
// table as `LuaObject::ToByteStream` encodes it, which the client's `DoBeat` decodes as it does a
// lockstep packet's, and the player's print lines.

namespace faf::remote::wire
{
  inline constexpr std::uint32_t kMaxLuaSyncBytes = 1u << 24;
  inline constexpr std::uint32_t kMaxLuaSyncLines = 4096;
  inline constexpr std::uint32_t kMaxLuaSyncLineBytes = 1u << 16;

  /** False, with nothing useful written, past the limits above. */
  [[nodiscard]] bool EncodeLuaSyncLane(std::span<const std::uint8_t> table, const std::vector<std::string>& prints, BitWriter& writer);
  /** False, with the reader failed, past the limits above or on a short stream. */
  [[nodiscard]] bool DecodeLuaSyncLane(BitReader& reader, std::vector<std::uint8_t>& table, std::vector<std::string>& prints);
} // namespace faf::remote::wire
