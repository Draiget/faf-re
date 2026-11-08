#pragma once

// Engine addition: wide-string range helpers `WinApp.cpp` and `WinPlatform.cpp` each had a copy of.

#include <cstddef>
#include <cstring>
#include <cwchar>
#include <string>

namespace moho
{
  /**
   * Address: 0x004A1AE0 (FUN_004A1AE0)
   * Mangled: ?append@wstring@std@@QAEAAV12@ABV12@II@Z
   *
   * What it does:
   * Appends a clamped substring range from `source` into `destination`.
   */
  inline std::wstring* AppendWideSubstringRangeClamped(
    std::wstring* const destination,
    const std::wstring& source,
    std::size_t count,
    const std::size_t sourceOffset
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    if (sourceOffset > source.size()) {
      throw std::out_of_range("wstring::append sourceOffset");
    }

    const std::size_t available = source.size() - sourceOffset;
    if (count > available) {
      count = available;
    }

    destination->append(source, sourceOffset, count);
    return destination;
  }

  /**
   * Address: 0x004A19E0 (FUN_004A19E0)
   * Mangled: ??Ywstring@std@@VQAEAAV01@PB_W@Z
   *
   * What it does:
   * Appends one wide source range into destination while preserving overlapping
   * source semantics.
   */
  inline std::wstring* AppendWideRangePreservingOverlap(
    std::wstring* const destination,
    const wchar_t* const source,
    const std::size_t sourceLength
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    const wchar_t* const destinationData = destination->data();
    const wchar_t* const destinationEnd = destinationData + destination->size();
    if (source >= destinationData && source < destinationEnd) {
      const std::size_t sourceOffset = static_cast<std::size_t>(source - destinationData);
      return AppendWideSubstringRangeClamped(destination, *destination, sourceLength, sourceOffset);
    }

    destination->append(source, sourceLength);
    return destination;
  }

  /**
   * Address: 0x004A1950 (FUN_004A1950)
   * Mangled: ?compare@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QBEHPB_W@Z
   *
   * What it does:
   * Lexicographically compares up to `lhsRequestedLength` characters from one
   * wide string against one raw wide range and returns `-1/0/1`.
   */
  inline int CompareWideStringPrefixRange(
    std::size_t lhsRequestedLength,
    const std::wstring* const lhs,
    const std::size_t rhsLength,
    const wchar_t* const rhs
  ) noexcept
  {
    if (lhs == nullptr || rhs == nullptr) {
      return (lhs == nullptr) ? ((rhs == nullptr) ? 0 : -1) : 1;
    }

    std::size_t lhsLength = lhsRequestedLength;
    if (lhs->size() < lhsLength) {
      lhsLength = lhs->size();
    }

    std::size_t compareCount = lhsLength;
    if (compareCount > rhsLength) {
      compareCount = rhsLength;
    }

    for (std::size_t i = 0; i < compareCount; ++i) {
      const wchar_t left = (*lhs)[i];
      const wchar_t right = rhs[i];
      if (left != right) {
        return (left < right) ? -1 : 1;
      }
    }

    if (lhsLength >= rhsLength) {
      return (lhsLength != rhsLength) ? 1 : 0;
    }
    return -1;
  }

  /**
   * Address: 0x004A1880 (FUN_004A1880, sub_4A1880)
   *
   * What it does:
   * Compares one wide string against one zero-terminated wide source.
   */
  inline int CompareWideStringWithNullTerminatedInput(
    const std::wstring* const lhs,
    const wchar_t* const rhs
  ) noexcept
  {
    const wchar_t* const safeRhs = (rhs != nullptr) ? rhs : L"";
    return CompareWideStringPrefixRange(
      (lhs != nullptr) ? lhs->size() : 0U,
      lhs,
      std::wcslen(safeRhs),
      safeRhs
    );
  }

  /**
   * Address: 0x004A1920 (FUN_004A1920, sub_4A1920)
   *
   * What it does:
   * Assigns one zero-terminated wide string into the destination string.
   */
  inline std::wstring* AssignWideStringFromNullTerminatedInput(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    const wchar_t* const safeSource = (source != nullptr) ? source : L"";
    destination->assign(safeSource, std::wcslen(safeSource));
    return destination;
  }
} // namespace moho
