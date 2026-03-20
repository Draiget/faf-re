#pragma once

#include <cstdint>
#include <type_traits>

namespace moho
{
  /**
   * High-nibble family in packed entity ids:
   * [31..28] family, [27..20] source index, [19..0] serial.
   *
   * Notes:
   * - `ShieldLike` is intentionally conservative for nibble `3`; binary usage
   *   clearly treats it as a distinct family range (`0x30000000..0x3FFFFFFF`),
   *   but the exact gameplay object taxonomy is still being refined.
   * - Nibbles `4..E` are grouped as `Other`.
   */
  enum class EEntityIdFamily : std::uint8_t
  {
    Unit = 0x0u,
    Projectile = 0x1u,
    Prop = 0x2u,
    ShieldLike = 0x3u,
    Other = 0x4u,
    Invalid = 0xFu
  };

  /**
   * Packed-id bitmasks used for field extraction/composition.
   */
  enum class EEntityIdBitMask : std::uint32_t
  {
    None = 0u,
    Family = 0xF0000000u,
    Source = 0x0FF00000u,
    FamilySource = 0xFFF00000u,
    Serial = 0x000FFFFFu
  };

  enum class EEntityIdSentinel : std::uint32_t
  {
    Invalid = 0xF0000000u,
    FirstNonUnitFamily = 0x10000000u
  };

  [[nodiscard]] constexpr EEntityIdBitMask operator|(const EEntityIdBitMask lhs, const EEntityIdBitMask rhs) noexcept
  {
    return static_cast<EEntityIdBitMask>(static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
  }

  [[nodiscard]] constexpr EEntityIdBitMask operator&(const EEntityIdBitMask lhs, const EEntityIdBitMask rhs) noexcept
  {
    return static_cast<EEntityIdBitMask>(static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
  }

  constexpr std::uint32_t kEntityIdFamilyShift = 28u;
  constexpr std::uint32_t kEntityIdSourceShift = 20u;
  constexpr std::uint32_t kEntityIdSourceIndexMask = 0xFFu;
  constexpr std::uint8_t kEntityIdSourceIndexInvalid = 0xFFu;

  [[nodiscard]] constexpr std::uint32_t ToMask(const EEntityIdBitMask mask) noexcept
  {
    return static_cast<std::underlying_type_t<EEntityIdBitMask>>(mask);
  }

  [[nodiscard]] constexpr std::uint32_t ToRaw(const EEntityIdSentinel value) noexcept
  {
    return static_cast<std::underlying_type_t<EEntityIdSentinel>>(value);
  }

  [[nodiscard]] constexpr std::uint8_t ExtractEntityIdSourceIndex(const std::uint32_t entityId) noexcept
  {
    return static_cast<std::uint8_t>((entityId >> kEntityIdSourceShift) & kEntityIdSourceIndexMask);
  }

  [[nodiscard]] constexpr std::uint32_t ExtractEntityIdFamilyNibble(const std::uint32_t entityId) noexcept
  {
    return (entityId >> kEntityIdFamilyShift) & 0xFu;
  }

  [[nodiscard]] constexpr EEntityIdFamily ClassifyEntityIdFamily(const std::uint32_t entityId) noexcept
  {
    switch (ExtractEntityIdFamilyNibble(entityId)) {
    case 0u:
      return EEntityIdFamily::Unit;
    case 1u:
      return EEntityIdFamily::Projectile;
    case 2u:
      return EEntityIdFamily::Prop;
    case 3u:
      return EEntityIdFamily::ShieldLike;
    case 0xFu:
      return EEntityIdFamily::Invalid;
    default:
      return EEntityIdFamily::Other;
    }
  }

  [[nodiscard]] constexpr std::uint32_t
  MakeEntityIdFamilySourceBits(const EEntityIdFamily family, const std::uint8_t sourceIndex) noexcept
  {
    return (static_cast<std::uint32_t>(family) << kEntityIdFamilyShift) |
      (static_cast<std::uint32_t>(sourceIndex) << kEntityIdSourceShift);
  }

  [[nodiscard]] constexpr std::uint32_t
  MakeEntityId(const EEntityIdFamily family, const std::uint8_t sourceIndex, const std::uint32_t serial) noexcept
  {
    return MakeEntityIdFamilySourceBits(family, sourceIndex) | (serial & ToMask(EEntityIdBitMask::Serial));
  }
} // namespace moho
