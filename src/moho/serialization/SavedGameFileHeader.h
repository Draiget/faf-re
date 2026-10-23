#pragma once

#include "moho/serialization/SaveGameFileHeader.h"

namespace moho
{
  // Compatibility aliases:
  // - canonical layout owner: `SSaveGameFileHeader` in `SaveGameFileHeader.h`
  // - this header is retained for legacy include paths/symbol names.
  constexpr std::uint32_t kSavedGameFileMagic = kSaveGameFileHeaderMagic;
  constexpr std::uint32_t kSavedGameFileVersion = kSaveGameFileHeaderVersion;
  constexpr std::size_t kSavedGameFileHeaderSize = kSaveGameFileHeaderSize;
  constexpr std::size_t kSavedGameHeaderTextCapacity = kSaveGameFileHeaderTextCapacity;

  /**
   * Address context:
   * - `CSaveGameRequestImpl::Save` (`0x008813A0`) rewrites this header at file offset 0.
   * - `CSavedGame::CSavedGame` (`0x00880330`) validates this header before archive reads.
   *
   * What it is:
   * Fixed-size savegame file header persisted before serialized archive payload.
   */
  using SavedGameFileHeader = SSaveGameFileHeader;

  static_assert(sizeof(SavedGameFileHeader) == kSavedGameFileHeaderSize, "SavedGameFileHeader size must be 0x2028");
  static_assert(
    offsetof(SavedGameFileHeader, mAppNameUtf16) == 0x28, "SavedGameFileHeader::mAppNameUtf16 offset must be 0x28"
  );
  static_assert(
    offsetof(SavedGameFileHeader, mSessionNameUtf16) == 0x828,
    "SavedGameFileHeader::mSessionNameUtf16 offset must be 0x828"
  );
} // namespace moho
