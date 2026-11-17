#pragma once

#include <utility>
#include <cstdint>
#include <type_traits>

namespace moho
{
  /**
   * Accept only enums with uint8_t underlying type. The conjunction stops at a non-enum, so
   * `underlying_type_t` is never asked of one.
   */
  template <class E>
  concept U8Enum = std::is_enum_v<E> && std::is_same_v<std::underlying_type_t<E>, std::uint8_t>;

  /**
   * Generic one-byte enum wrapper used by binary-facing headers.
   */
  struct EnumByte
  {
    std::uint8_t value{0};

    EnumByte() noexcept = default;

    explicit constexpr EnumByte(
      std::uint8_t v
    ) noexcept
      : value(v)
    {}

    template <U8Enum E>
    constexpr EnumByte(
      E e
    ) noexcept
      : value(std::to_underlying(e))
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
    friend constexpr bool operator==(
      EnumByte t,
      E e
    ) noexcept
    {
      return t.value == std::to_underlying(e);
    }
    template <U8Enum E>
    friend constexpr bool operator==(
      E e,
      EnumByte t
    ) noexcept
    {
      return t == e;
    }
    template <U8Enum E>
    friend constexpr bool operator!=(
      EnumByte t,
      E e
    ) noexcept
    {
      return !(t == e);
    }
    template <U8Enum E>
    friend constexpr bool operator!=(
      E e,
      EnumByte t
    ) noexcept
    {
      return !(t == e);
    }
  };

  static_assert(sizeof(EnumByte) == 0x1, "EnumByte size must be 0x1");
} // namespace moho
