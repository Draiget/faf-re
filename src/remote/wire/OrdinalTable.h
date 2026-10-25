#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Engine addition, server mode (plan WP7.2): blueprint, mesh and sound references travel as
// ordinals into tables that server and client build on their own at load from their loaded
// game data. Both sides sort the same names the same way, so the same content gives the
// same ordinals; the table hash goes into the handshake and a mismatch refuses the client.

namespace faf::remote::wire
{
  class COrdinalTable
  {
  public:
    static constexpr std::uint32_t kNone = 0xFFFFFFFFu;

    /**
     * Names are lower-cased (ASCII; blueprint ids and resource paths are case-insensitive in
     * the engine), duplicates dropped, then sorted bytewise; the ordinal is the position.
     */
    [[nodiscard]] static COrdinalTable Build(std::span<const std::string> names);

    [[nodiscard]] std::uint32_t Ordinal(std::string_view name) const;
    /** Empty for an ordinal out of range. */
    [[nodiscard]] std::string_view Name(std::uint32_t ordinal) const noexcept;
    [[nodiscard]] std::uint32_t Size() const noexcept { return static_cast<std::uint32_t>(mNames.size()); }
    /** 64-bit FNV-1a over the count and every name with its terminator, in ordinal order. */
    [[nodiscard]] std::uint64_t Hash() const noexcept { return mHash; }

  private:
    std::vector<std::string> mNames;
    std::unordered_map<std::string, std::uint32_t> mIndex;
    std::uint64_t mHash = 0;
  };

  /** The tables a view frame refers into. */
  struct SContentTables
  {
    COrdinalTable blueprints;
    COrdinalTable meshes;
    COrdinalTable sounds;

    /** Combines the three hashes in a fixed order. */
    [[nodiscard]] std::uint64_t Hash() const noexcept;
  };

  [[nodiscard]] std::string NormalizeContentName(std::string_view name);
} // namespace faf::remote::wire
