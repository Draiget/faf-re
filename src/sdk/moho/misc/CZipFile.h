#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  struct CZipFileEntry
  {
    std::uint16_t mGeneralPurposeFlags = 0; // +0x00
    std::uint16_t mCompressionMethod = 0;   // +0x02
    std::uint16_t mDosDate = 0;             // +0x04
    std::uint16_t mDosTime = 0;             // +0x06
    std::uint32_t mCompressedSize = 0;      // +0x08
    std::uint32_t mUncompressedSize = 0;    // +0x0C
    msvc8::string mName{};                  // +0x10
    std::uint32_t mLocalHeaderOffset = 0;   // +0x2C
    std::int32_t mCachedDataOffset = -1;    // +0x30
  };

  static_assert(offsetof(CZipFileEntry, mName) == 0x10, "CZipFileEntry::mName offset must be 0x10");
  static_assert(offsetof(CZipFileEntry, mLocalHeaderOffset) == 0x2C, "CZipFileEntry::mLocalHeaderOffset offset must be 0x2C");
  static_assert(offsetof(CZipFileEntry, mCachedDataOffset) == 0x30, "CZipFileEntry::mCachedDataOffset offset must be 0x30");
  static_assert(sizeof(CZipFileEntry) == 0x34, "CZipFileEntry size must be 0x34");

  struct SZipFileCachedEntry
  {
    boost::shared_ptr<CZipFileEntry> mEntry{}; // +0x00
    boost::shared_ptr<const char> mData{};     // +0x08
  };

  static_assert(offsetof(SZipFileCachedEntry, mData) == 0x08, "SZipFileCachedEntry::mData offset must be 0x08");
  static_assert(sizeof(SZipFileCachedEntry) == 0x10, "SZipFileCachedEntry size must be 0x10");

  /**
   * Zip entry names compare case-insensitively: every descent in the binary's
   * name index ends in a `_stricmp` of the two `c_str()`s (`_Lbound` at
   * 0x0046E5B0, `find` at 0x0046D960).
   */
  struct ZipEntryNameLess
  {
    [[nodiscard]] bool operator()(const msvc8::string& lhs, const msvc8::string& rhs) const
    {
      return gpg::STR_CompareNoCase(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  /**
   * Canonical entry name -> index into `CZipFile::mEntries`.
   *
   * IDA types the emissions `std::map_string_uint`. The node is 0x30 (its
   * allocator, 0x0046F170, computes `lea edx,[ecx+ecx*2]; shl edx,4`) with the
   * key at `node+0x0C` -- `find` reads `_Bx` at `node+0x10` and `_Myres` at
   * `node+0x24`, the plain 0x1C `msvc8::string` -- the index at `node+0x28`,
   * and colour/nil at `+0x2C`/`+0x2D`.
   */
  using SZipFileNameIndexMap = msvc8::map<msvc8::string, std::uint32_t, ZipEntryNameLess>;

  static_assert(sizeof(SZipFileNameIndexMap) == 0x0C, "SZipFileNameIndexMap size must be 0x0C");
  static_assert(
    sizeof(SZipFileNameIndexMap::value_type) == 0x20, "SZipFileNameIndexMap::value_type size must be 0x20"
  );

#pragma pack(push, 1)
  struct SZipLocalFileHeader
  {
    std::uint32_t mSignature = 0;           // +0x00
    std::uint16_t mVersionNeeded = 0;       // +0x04
    std::uint16_t mGeneralPurposeFlags = 0; // +0x06
    std::uint16_t mCompressionMethod = 0;   // +0x08
    std::uint16_t mDosTime = 0;             // +0x0A
    std::uint16_t mDosDate = 0;             // +0x0C
    std::uint32_t mCrc32 = 0;               // +0x0E
    std::uint32_t mCompressedSize = 0;      // +0x12
    std::uint32_t mUncompressedSize = 0;    // +0x16
    std::uint16_t mFileNameLength = 0;      // +0x1A
    std::uint16_t mExtraFieldLength = 0;    // +0x1C
  };
#pragma pack(pop)

  static_assert(offsetof(SZipLocalFileHeader, mFileNameLength) == 0x1A, "SZipLocalFileHeader::mFileNameLength offset must be 0x1A");
  static_assert(offsetof(SZipLocalFileHeader, mExtraFieldLength) == 0x1C, "SZipLocalFileHeader::mExtraFieldLength offset must be 0x1C");
  static_assert(sizeof(SZipLocalFileHeader) == 0x1E, "SZipLocalFileHeader size must be 0x1E");

  class CZipFile
  {
  public:
    static constexpr std::uint32_t kInvalidEntryIndex = 0xFFFFFFFFu;

    /**
     * Address: 0x0046BEF0 (FUN_0046BEF0, Moho::CZipFile::CZipFile)
     *
     * gpg::StrArg
     *
     * What it does:
     * Opens one zip archive path, parses central-directory metadata, and builds
     * entry-index lookup state used by the runtime read APIs.
     */
    explicit CZipFile(gpg::StrArg sourcePath);

    /**
     * Address: 0x0046C6E0 (FUN_0046C6E0, Moho::CZipFile::~CZipFile)
     *
     * What it does:
     * Releases map/vector-owned zip metadata and resets the owned path string.
     */
    ~CZipFile();

    /**
     * Address: 0x0046D2F0 (FUN_0046D2F0, Moho::CZipFile::FindFile)
     *
     * What it does:
     * Resolves one canonical zip entry name to entry index, or returns `0xFFFFFFFF`.
     */
    [[nodiscard]] std::uint32_t FindFile(const msvc8::string& canonicalPath) const;

    /**
     * Address: 0x0046D380 (FUN_0046D380, Moho::CZipFile::OpenFile)
     *
     * What it does:
     * Opens one zip entry by canonical path as a memory-backed read stream.
     */
    [[nodiscard]] msvc8::auto_ptr<gpg::Stream> OpenFile(const msvc8::string& canonicalPath) const;

    /**
     * Address: 0x0046D420 (FUN_0046D420, Moho::CZipFile::ReadFile)
     *
     * What it does:
     * Reads one zip entry by canonical path into immutable shared-memory bytes.
     */
    [[nodiscard]] gpg::MemBuffer<const char> ReadFile(const msvc8::string& canonicalPath) const;

    /**
     * Address: 0x0046D460 (FUN_0046D460, Moho::CZipFile::CopyFile)
     *
     * What it does:
     * Reads one zip entry by canonical path and returns a mutable byte copy.
     */
    [[nodiscard]] gpg::MemBuffer<char> CopyFile(const msvc8::string& canonicalPath) const;

    /**
     * Address: 0x0046C770 (FUN_0046C770, Moho::CZipFile::GetEntryName)
     *
     * What it does:
     * Returns the canonical zip-entry name for one validated entry index.
     */
    [[nodiscard]] const msvc8::string& GetEntryName(std::uint32_t entryIndex) const;

    /**
     * Address: 0x0046C810 (FUN_0046C810, Moho::CZipFile::GetEntrySize)
     *
     * What it does:
     * Returns uncompressed byte size for one validated zip entry.
     */
    [[nodiscard]] std::uint32_t GetEntrySize(std::uint32_t entryIndex) const;

    /**
     * Address: 0x0046C8B0 (FUN_0046C8B0, Moho::CZipFile::GetEntryLastModTime)
     *
     * What it does:
     * Converts the entry DOS date/time pair into Win32 FILETIME.
     */
    [[nodiscard]] FILETIME GetEntryLastModTime(std::uint32_t entryIndex) const;

    /**
     * Address: 0x0046CA80 (FUN_0046CA80, Moho::CZipFile::OpenEntry)
     *
     * What it does:
     * Opens one zip entry by index as a memory-backed read stream.
     */
    [[nodiscard]] msvc8::auto_ptr<gpg::Stream> OpenEntry(std::uint32_t entryIndex) const;

    /**
     * Address: 0x0046CB80 (FUN_0046CB80, Moho::CZipFile::ReadEntry)
     *
     * What it does:
     * Reads one zip entry by index, inflating method-8 entries when needed, and
     * caches immutable bytes for later reads.
     */
    [[nodiscard]] gpg::MemBuffer<const char> ReadEntry(std::uint32_t entryIndex) const;

    /**
     * Address: 0x0046D250 (FUN_0046D250, Moho::CZipFile::CopyEntry)
     *
     * What it does:
     * Reads one zip entry by index and returns a mutable byte copy.
     */
    [[nodiscard]] gpg::MemBuffer<char> CopyEntry(std::uint32_t entryIndex) const;

  private:
    [[nodiscard]] SZipFileCachedEntry& GetCachedEntryOrThrow(std::uint32_t entryIndex, const char* message) const;
    [[nodiscard]] const CZipFileEntry& GetEntryOrThrow(std::uint32_t entryIndex, const char* message) const;

  public:
    msvc8::string mPath{};                           // +0x00
    msvc8::vector<SZipFileCachedEntry> mEntries{};  // +0x1C
    SZipFileNameIndexMap mEntryByCanonicalPath{};   // +0x2C
  };

  static_assert(offsetof(CZipFile, mEntries) == 0x1C, "CZipFile::mEntries offset must be 0x1C");
  static_assert(offsetof(CZipFile, mEntryByCanonicalPath) == 0x2C, "CZipFile::mEntryByCanonicalPath offset must be 0x2C");
  static_assert(sizeof(CZipFile) == 0x38, "CZipFile size must be 0x38");
} // namespace moho
