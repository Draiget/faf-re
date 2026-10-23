#pragma once

#include <cstdint>
#include <type_traits>

namespace moho
{
  /**
   * Accept only enums with uint8_t underlying type.
   * SFINAE-safe for non-enum probes.
   */
  template <class E, class = void>
  struct IsU8Enum : std::false_type
  {};

  template <class E>
  struct IsU8Enum<E, std::enable_if_t<std::is_enum_v<E>>>
    : std::bool_constant<std::is_same_v<std::underlying_type_t<E>, std::uint8_t>>
  {};

  template <class E>
  inline constexpr bool IsU8EnumV = IsU8Enum<E>::value;

  template <class E>
  concept U8Enum = IsU8EnumV<E>;

  /**
   * Generic one-byte enum wrapper used by binary-facing headers.
   */
  struct EnumByte
  {
    std::uint8_t value{0};

    EnumByte() noexcept = default;

    explicit constexpr EnumByte(std::uint8_t v) noexcept
      : value(v)
    {}

    template <U8Enum E>
    constexpr EnumByte(E e) noexcept
      : value(static_cast<std::uint8_t>(e))
    {}

    template <U8Enum E>
    constexpr operator E() const noexcept
    {
      return static_cast<E>(value);
    }

    explicit constexpr operator std::uint8_t() const noexcept
    {
      return value;
    }

    constexpr std::uint8_t raw() const noexcept
    {
      return value;
    }

    template <U8Enum E>
    friend constexpr bool operator==(EnumByte t, E e) noexcept
    {
      return t.value == static_cast<std::uint8_t>(e);
    }
    template <U8Enum E>
    friend constexpr bool operator==(E e, EnumByte t) noexcept
    {
      return t == e;
    }
    template <U8Enum E>
    friend constexpr bool operator!=(EnumByte t, E e) noexcept
    {
      return !(t == e);
    }
    template <U8Enum E>
    friend constexpr bool operator!=(E e, EnumByte t) noexcept
    {
      return !(t == e);
    }
  };

  static_assert(sizeof(EnumByte) == 0x1, "EnumByte size must be 0x1");
} // namespace moho
