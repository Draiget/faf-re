#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  constexpr std::uint32_t kSaveGameFileHeaderMagic = 0x484D4752U; // "RGMH"
  constexpr std::uint32_t kSaveGameFileHeaderVersion = 1U;
  constexpr std::size_t kSaveGameFileHeaderSize = 0x2028;
  constexpr std::size_t kSaveGameFileHeaderTextCapacity = 1024;
  constexpr std::size_t kSaveGameFileHeaderTextCopyLimit = 2047;

  /**
   * Address context:
   * - save write path (`CSaveGameRequestImpl::Save`, FUN_008813A0)
   * - save load path (`CSavedGame::CSavedGame`, FUN_00880330)
   *
   * What it is:
   * Fixed 0x2028-byte prelude block stored before serialized saved-game data.
   */
  struct SSaveGameFileHeader
  {
    std::uint32_t mMagic = kSaveGameFileHeaderMagic;      // +0x0000
    std::uint32_t mVersion = kSaveGameFileHeaderVersion;  // +0x0004
    std::uint32_t mByteSize = kSaveGameFileHeaderSize;    // +0x0008
    std::int32_t mPreviewOffsetLow = 0;                   // +0x000C
    std::int32_t mPreviewOffsetHigh = 0;                  // +0x0010
    std::uint32_t mPreviewByteSize = 0;                   // +0x0014
    std::uint32_t mGameIdPart1 = 0;                       // +0x0018
    std::uint32_t mGameIdPart3 = 0;                       // +0x001C
    std::uint32_t mGameIdPart4 = 0;                       // +0x0020
    std::uint32_t mGameIdPart2 = 0;                       // +0x0024
    wchar_t mAppNameUtf16[kSaveGameFileHeaderTextCapacity]{};     // +0x0028
    wchar_t mSessionNameUtf16[kSaveGameFileHeaderTextCapacity]{}; // +0x0828
    std::uint8_t mReservedTail[0x1000]{};                          // +0x1028
  };

  static_assert(sizeof(SSaveGameFileHeader) == 0x2028, "SSaveGameFileHeader size must be 0x2028");
  static_assert(
    offsetof(SSaveGameFileHeader, mAppNameUtf16) == 0x28, "SSaveGameFileHeader::mAppNameUtf16 offset must be 0x28"
  );
  static_assert(
    offsetof(SSaveGameFileHeader, mSessionNameUtf16) == 0x828,
    "SSaveGameFileHeader::mSessionNameUtf16 offset must be 0x828"
  );
} // namespace moho

