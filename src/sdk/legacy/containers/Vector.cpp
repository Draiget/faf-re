#include "Vector.h"
using namespace msvc8;

namespace msvc8::detail
{
/**
 * Address: 0x00540F40 (FUN_00540F40, func_ArraySet)
 *
 * What it does:
 * Writes one dword value from `valuePtr` into `count` consecutive destination
 * dword lanes, preserving the original null-destination guard semantics.
 */
std::uint32_t FillDwordArrayFromValuePointerNullable(
  std::uint32_t count,
  const std::uint32_t* const valuePtr,
  std::uint32_t* destination
) noexcept
{
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (count != 0u) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<std::uint32_t*>(destinationAddress) = *valuePtr;
    }

    --count;
    destinationAddress += sizeof(std::uint32_t);
  }

  return count;
}

/**
 * Address: 0x0054F6B0 (FUN_0054F6B0, func_intp_memcpy)
 *
 * What it does:
 * Copies one half-open dword range `[sourceBegin, sourceEnd)` into
 * destination storage and returns one-past the last written destination lane,
 * preserving the original null-destination guard semantics.
 */
std::uint32_t* CopyDwordRangeNullable(
  std::uint32_t* destination,
  const std::uint32_t* sourceBegin,
  const std::uint32_t* sourceEnd
) noexcept
{
  const std::uint32_t* source = sourceBegin;
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (source != sourceEnd) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
    }

    ++source;
    destinationAddress += sizeof(std::uint32_t);
  }

  return reinterpret_cast<std::uint32_t*>(destinationAddress);
}
} // namespace msvc8::detail
