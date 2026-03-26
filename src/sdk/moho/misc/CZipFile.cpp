#include "moho/misc/CZipFile.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/utils/Logging.h"

namespace
{
  constexpr std::uint32_t kZipLocalFileHeaderMagic = 0x04034B50u;
  constexpr std::uint32_t kZipCentralDirectoryFileHeaderMagic = 0x02014B50u;
  constexpr std::uint32_t kZipEndOfCentralDirectoryMagic = 0x06054B50u;
  constexpr std::uint32_t kInvalidZipOffset = 0xFFFFFFFFu;
  constexpr std::size_t kZipDirectoryScanTailLimit = 0x10016u;

  constexpr std::uint16_t kZipCompressionStored = 0u;
  constexpr std::uint16_t kZipCompressionDeflated = 8u;
  constexpr std::uint16_t kZipDataDescriptorFlag = 0x0008u;

#pragma pack(push, 1)
  struct SZipCentralDirectoryFileHeader
  {
    std::uint32_t mSignature = 0;
    std::uint16_t mVersionMadeBy = 0;
    std::uint16_t mVersionNeeded = 0;
    std::uint16_t mGeneralPurposeFlags = 0;
    std::uint16_t mCompressionMethod = 0;
    std::uint16_t mDosTime = 0;
    std::uint16_t mDosDate = 0;
    std::uint32_t mCrc32 = 0;
    std::uint32_t mCompressedSize = 0;
    std::uint32_t mUncompressedSize = 0;
    std::uint16_t mFileNameLength = 0;
    std::uint16_t mExtraFieldLength = 0;
    std::uint16_t mFileCommentLength = 0;
    std::uint16_t mDiskNumberStart = 0;
    std::uint16_t mInternalFileAttributes = 0;
    std::uint32_t mExternalFileAttributes = 0;
    std::uint32_t mLocalHeaderOffset = 0;
  };

  struct SZipEndOfCentralDirectoryRecord
  {
    std::uint32_t mSignature = 0;
    std::uint16_t mDiskNumber = 0;
    std::uint16_t mDiskWithCentralDirectory = 0;
    std::uint16_t mEntriesOnThisDisk = 0;
    std::uint16_t mTotalEntries = 0;
    std::uint32_t mCentralDirectorySize = 0;
    std::uint32_t mCentralDirectoryOffset = 0;
    std::uint16_t mCommentLength = 0;
  };
#pragma pack(pop)

  static_assert(sizeof(SZipCentralDirectoryFileHeader) == 0x2E, "SZipCentralDirectoryFileHeader size must be 0x2E");
  static_assert(sizeof(SZipEndOfCentralDirectoryRecord) == 0x16, "SZipEndOfCentralDirectoryRecord size must be 0x16");

  struct ZipFileEntrySharedDeleter
  {
    void operator()(moho::CZipFileEntry* const entry) const noexcept
    {
      if (entry != nullptr) {
        entry->mName.tidy(true, 0U);
        delete entry;
      }
    }
  };

  [[nodiscard]]
  int CompareCanonicalPathNoCase(const msvc8::string& lhs, const msvc8::string& rhs)
  {
    return gpg::STR_CompareNoCase(lhs.c_str(), rhs.c_str());
  }

  [[nodiscard]]
  bool IsNameIndexMapSentinel(const moho::SZipFileNameIndexMapNode* const node)
  {
    return node == nullptr || node->mIsNil != 0;
  }

  void SetNameIndexMapNodeBlack(moho::SZipFileNameIndexMapNode* const node)
  {
    if (!IsNameIndexMapSentinel(node)) {
      node->mColor = 1;
    }
  }

  void SetNameIndexMapNodeRed(moho::SZipFileNameIndexMapNode* const node)
  {
    if (!IsNameIndexMapSentinel(node)) {
      node->mColor = 0;
    }
  }

  [[nodiscard]]
  moho::SZipFileNameIndexMapNode* NameIndexMapRoot(const moho::SZipFileNameIndexMap& map)
  {
    if (IsNameIndexMapSentinel(map.mHead)) {
      return map.mHead;
    }
    return map.mHead->mParent;
  }

  void NameIndexMapRotateLeft(
    moho::SZipFileNameIndexMap& map, moho::SZipFileNameIndexMapNode* const pivot
  )
  {
    if (IsNameIndexMapSentinel(pivot) || IsNameIndexMapSentinel(pivot->mRight)) {
      return;
    }

    moho::SZipFileNameIndexMapNode* const head = map.mHead;
    moho::SZipFileNameIndexMapNode* const right = pivot->mRight;

    pivot->mRight = right->mLeft;
    if (!IsNameIndexMapSentinel(right->mLeft)) {
      right->mLeft->mParent = pivot;
    }

    right->mParent = pivot->mParent;
    if (IsNameIndexMapSentinel(pivot->mParent)) {
      head->mParent = right;
    } else if (pivot == pivot->mParent->mLeft) {
      pivot->mParent->mLeft = right;
    } else {
      pivot->mParent->mRight = right;
    }

    right->mLeft = pivot;
    pivot->mParent = right;
  }

  void NameIndexMapRotateRight(
    moho::SZipFileNameIndexMap& map, moho::SZipFileNameIndexMapNode* const pivot
  )
  {
    if (IsNameIndexMapSentinel(pivot) || IsNameIndexMapSentinel(pivot->mLeft)) {
      return;
    }

    moho::SZipFileNameIndexMapNode* const head = map.mHead;
    moho::SZipFileNameIndexMapNode* const left = pivot->mLeft;

    pivot->mLeft = left->mRight;
    if (!IsNameIndexMapSentinel(left->mRight)) {
      left->mRight->mParent = pivot;
    }

    left->mParent = pivot->mParent;
    if (IsNameIndexMapSentinel(pivot->mParent)) {
      head->mParent = left;
    } else if (pivot == pivot->mParent->mRight) {
      pivot->mParent->mRight = left;
    } else {
      pivot->mParent->mLeft = left;
    }

    left->mRight = pivot;
    pivot->mParent = left;
  }

  void NameIndexMapInsertFixup(
    moho::SZipFileNameIndexMap& map, moho::SZipFileNameIndexMapNode* node
  )
  {
    while (!IsNameIndexMapSentinel(node->mParent) && node->mParent->mColor == 0) {
      moho::SZipFileNameIndexMapNode* const parent = node->mParent;
      moho::SZipFileNameIndexMapNode* const grandparent = parent->mParent;
      if (parent == grandparent->mLeft) {
        moho::SZipFileNameIndexMapNode* uncle = grandparent->mRight;
        if (!IsNameIndexMapSentinel(uncle) && uncle->mColor == 0) {
          SetNameIndexMapNodeBlack(parent);
          SetNameIndexMapNodeBlack(uncle);
          SetNameIndexMapNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mRight) {
            node = parent;
            NameIndexMapRotateLeft(map, node);
          }
          SetNameIndexMapNodeBlack(node->mParent);
          SetNameIndexMapNodeRed(node->mParent->mParent);
          NameIndexMapRotateRight(map, node->mParent->mParent);
        }
      } else {
        moho::SZipFileNameIndexMapNode* uncle = grandparent->mLeft;
        if (!IsNameIndexMapSentinel(uncle) && uncle->mColor == 0) {
          SetNameIndexMapNodeBlack(parent);
          SetNameIndexMapNodeBlack(uncle);
          SetNameIndexMapNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            NameIndexMapRotateRight(map, node);
          }
          SetNameIndexMapNodeBlack(node->mParent);
          SetNameIndexMapNodeRed(node->mParent->mParent);
          NameIndexMapRotateLeft(map, node->mParent->mParent);
        }
      }
    }

    moho::SZipFileNameIndexMapNode* const root = NameIndexMapRoot(map);
    SetNameIndexMapNodeBlack(root);
    if (!IsNameIndexMapSentinel(root)) {
      root->mParent = map.mHead;
    }
  }

  void InitializeNameIndexMap(moho::SZipFileNameIndexMap& map)
  {
    moho::SZipFileNameIndexMapNode* const head = new moho::SZipFileNameIndexMapNode();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mColor = 1;
    head->mIsNil = 1;
    map.mHead = head;
    map.mSize = 0;
  }

  void DestroyNameIndexMapSubtree(
    moho::SZipFileNameIndexMapNode* const node, moho::SZipFileNameIndexMapNode* const head
  )
  {
    if (IsNameIndexMapSentinel(node) || node == head) {
      return;
    }

    DestroyNameIndexMapSubtree(node->mLeft, head);
    DestroyNameIndexMapSubtree(node->mRight, head);
    node->mCanonicalPath.tidy(true, 0U);
    delete node;
  }

  void ResetNameIndexMap(moho::SZipFileNameIndexMap& map)
  {
    moho::SZipFileNameIndexMapNode* const head = map.mHead;
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    DestroyNameIndexMapSubtree(head->mParent, head);
    head->mCanonicalPath.tidy(true, 0U);
    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

  [[nodiscard]]
  bool InsertNameIndexMapEntry(
    moho::SZipFileNameIndexMap& map, const msvc8::string& canonicalPath, const std::uint32_t entryIndex
  )
  {
    moho::SZipFileNameIndexMapNode* const head = map.mHead;
    if (IsNameIndexMapSentinel(head)) {
      return false;
    }

    moho::SZipFileNameIndexMapNode* parent = head;
    moho::SZipFileNameIndexMapNode* node = head->mParent;
    bool insertAsLeftChild = true;
    while (!IsNameIndexMapSentinel(node)) {
      parent = node;
      const int cmp = CompareCanonicalPathNoCase(canonicalPath, node->mCanonicalPath);
      if (cmp < 0) {
        node = node->mLeft;
        insertAsLeftChild = true;
      } else if (cmp > 0) {
        node = node->mRight;
        insertAsLeftChild = false;
      } else {
        return false;
      }
    }

    std::unique_ptr<moho::SZipFileNameIndexMapNode> insertedNodeOwner =
      std::make_unique<moho::SZipFileNameIndexMapNode>();
    moho::SZipFileNameIndexMapNode* const insertedNode = insertedNodeOwner.get();
    insertedNode->mLeft = head;
    insertedNode->mParent = parent;
    insertedNode->mRight = head;
    insertedNode->mCanonicalPath.assign_owned(canonicalPath.view());
    insertedNode->mEntryIndex = entryIndex;
    insertedNode->mColor = 0;
    insertedNode->mIsNil = 0;

    if (parent == head) {
      head->mParent = insertedNode;
      head->mLeft = insertedNode;
      head->mRight = insertedNode;
      insertedNode->mParent = head;
    } else if (insertAsLeftChild) {
      parent->mLeft = insertedNode;
      if (head->mLeft == parent ||
          CompareCanonicalPathNoCase(insertedNode->mCanonicalPath, head->mLeft->mCanonicalPath) < 0) {
        head->mLeft = insertedNode;
      }
    } else {
      parent->mRight = insertedNode;
      if (head->mRight == parent ||
          CompareCanonicalPathNoCase(insertedNode->mCanonicalPath, head->mRight->mCanonicalPath) > 0) {
        head->mRight = insertedNode;
      }
    }

    ++map.mSize;
    insertedNodeOwner.release();
    NameIndexMapInsertFixup(map, insertedNode);
    return true;
  }

  [[nodiscard]]
  const moho::SZipFileNameIndexMapNode* NameIndexMapLowerBound(
    const moho::SZipFileNameIndexMap& map, const msvc8::string& canonicalPath
  )
  {
    const moho::SZipFileNameIndexMapNode* result = map.mHead;
    if (result == nullptr) {
      return nullptr;
    }

    const moho::SZipFileNameIndexMapNode* parent = result->mParent;
    while (!IsNameIndexMapSentinel(parent)) {
      if (CompareCanonicalPathNoCase(parent->mCanonicalPath, canonicalPath) >= 0) {
        result = parent;
        parent = parent->mLeft;
      } else {
        parent = parent->mRight;
      }
    }
    return result;
  }

  [[nodiscard]]
  const moho::SZipFileNameIndexMapNode* NameIndexMapFind(
    const moho::SZipFileNameIndexMap& map, const msvc8::string& canonicalPath
  )
  {
    const moho::SZipFileNameIndexMapNode* const lowerBound = NameIndexMapLowerBound(map, canonicalPath);
    if (lowerBound == nullptr || lowerBound == map.mHead) {
      return map.mHead;
    }
    return CompareCanonicalPathNoCase(canonicalPath, lowerBound->mCanonicalPath) < 0 ? map.mHead : lowerBound;
  }

  [[nodiscard]]
  bool FindEndOfCentralDirectoryOffset(
    const std::vector<char>& tailBytes, std::size_t* const outOffsetInTail
  )
  {
    if (outOffsetInTail == nullptr || tailBytes.size() < sizeof(std::uint32_t)) {
      return false;
    }

    for (std::size_t offset = tailBytes.size() - sizeof(std::uint32_t);; --offset) {
      if (static_cast<unsigned char>(tailBytes[offset + 0]) == 0x50 &&
          static_cast<unsigned char>(tailBytes[offset + 1]) == 0x4B &&
          static_cast<unsigned char>(tailBytes[offset + 2]) == 0x05 &&
          static_cast<unsigned char>(tailBytes[offset + 3]) == 0x06) {
        *outOffsetInTail = offset;
        return true;
      }

      if (offset == 0) {
        break;
      }
    }

    return false;
  }

  [[nodiscard]]
  gpg::MemBuffer<const char> MakeConstMemBuffer(const boost::shared_ptr<const char>& sharedData, const std::size_t byteCount)
  {
    if (!sharedData) {
      return {};
    }

    return gpg::MemBuffer<const char>(sharedData, byteCount);
  }

  [[nodiscard]]
  std::unique_ptr<gpg::Stream> OpenZipBackingStream(const msvc8::string& zipPath)
  {
    try {
      return std::make_unique<gpg::FileStream>(
        zipPath.c_str(), gpg::Stream::ModeReceive, 0x0Bu, 0x1000
      );
    } catch (...) {
      return {};
    }
  }

  /**
   * Address: 0x0046C960 (FUN_0046C960, func_ReadZipDirectory)
   *
   * gpg::Stream &,Moho::CZipFileEntry &
   *
   * What it does:
   * Resolves and seeks one local-entry data payload offset for a central-directory
   * entry, caching the payload offset for later reads.
   */
  [[nodiscard]]
  bool ReadZipDirectory(gpg::Stream& stream, moho::CZipFileEntry& entry)
  {
    if (entry.mLocalHeaderOffset == kInvalidZipOffset) {
      return false;
    }

    if (entry.mCachedDataOffset >= 0) {
      (void)stream.VirtSeek(
        gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, static_cast<std::size_t>(entry.mCachedDataOffset)
      );
      return true;
    }

    (void)stream.VirtSeek(
      gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, static_cast<std::size_t>(entry.mLocalHeaderOffset)
    );

    moho::SZipLocalFileHeader localHeader{};
    const std::size_t signatureRead = stream.Read(
      reinterpret_cast<char*>(&localHeader.mSignature), sizeof(localHeader.mSignature)
    );
    if (signatureRead != sizeof(localHeader.mSignature) || localHeader.mSignature != kZipLocalFileHeaderMagic) {
      entry.mLocalHeaderOffset = kInvalidZipOffset;
      return false;
    }

    const std::size_t tailRead = stream.Read(
      reinterpret_cast<char*>(&localHeader.mVersionNeeded),
      sizeof(localHeader) - sizeof(localHeader.mSignature)
    );
    if (tailRead != sizeof(localHeader) - sizeof(localHeader.mSignature)) {
      entry.mLocalHeaderOffset = kInvalidZipOffset;
      return false;
    }

    const std::size_t dataOffset = stream.VirtTell(gpg::Stream::ModeReceive) +
                                   static_cast<std::size_t>(localHeader.mFileNameLength) +
                                   static_cast<std::size_t>(localHeader.mExtraFieldLength);
    if (dataOffset > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
      entry.mLocalHeaderOffset = kInvalidZipOffset;
      return false;
    }

    entry.mCachedDataOffset = static_cast<std::int32_t>(dataOffset);
    (void)stream.VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, dataOffset);
    return true;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0046BEF0 (FUN_0046BEF0, Moho::CZipFile::CZipFile)
   *
   * gpg::StrArg
   *
   * What it does:
   * Opens one zip archive path, parses central-directory metadata, and builds
   * entry-index lookup state used by the runtime read APIs.
   */
  CZipFile::CZipFile(const gpg::StrArg sourcePath)
  {
    const char* const archivePath = sourcePath != nullptr ? sourcePath : "";
    mPath.assign_owned(archivePath);
    InitializeNameIndexMap(mEntryByCanonicalPath);

    std::unique_ptr<gpg::Stream> zipStream = OpenZipBackingStream(mPath);
    if (zipStream == nullptr) {
      return;
    }

    const std::size_t fileSize = zipStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginEnd, 0);
    const std::size_t tailBytesToRead = std::min(fileSize, kZipDirectoryScanTailLimit);
    const std::size_t tailStartOffset = fileSize - tailBytesToRead;
    (void)zipStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, tailStartOffset);

    std::vector<char> tailBytes(tailBytesToRead);
    if (tailBytesToRead != 0) {
      (void)zipStream->Read(tailBytes.data(), tailBytesToRead);
    }

    std::size_t endOfCentralDirectoryOffsetInTail = 0;
    if (!FindEndOfCentralDirectoryOffset(tailBytes, &endOfCentralDirectoryOffsetInTail)) {
      gpg::Warnf("Couldn't locate zip directory for '%s'", archivePath);
      return;
    }

    const std::size_t endOfCentralDirectoryAbsoluteOffset =
      tailStartOffset + endOfCentralDirectoryOffsetInTail;
    (void)zipStream->VirtSeek(
      gpg::Stream::ModeReceive,
      gpg::Stream::OriginBegin,
      endOfCentralDirectoryAbsoluteOffset
    );

    gpg::BinaryReader reader(zipStream.get());
    SZipEndOfCentralDirectoryRecord endOfCentralDirectory{};
    reader.ReadExact(endOfCentralDirectory);
    if (endOfCentralDirectory.mSignature != kZipEndOfCentralDirectoryMagic) {
      gpg::Warnf("Couldn't locate zip directory for '%s'", archivePath);
      return;
    }

    if (endOfCentralDirectory.mDiskNumber != 0 || endOfCentralDirectory.mDiskWithCentralDirectory != 0) {
      gpg::Warnf("(%s): Disk spanning not supported.", archivePath);
      return;
    }

    if (endOfCentralDirectory.mEntriesOnThisDisk != endOfCentralDirectory.mTotalEntries) {
      gpg::Warnf("Error reading zip directory for '%s'", archivePath);
      return;
    }

    (void)zipStream->VirtSeek(
      gpg::Stream::ModeReceive,
      gpg::Stream::OriginBegin,
      static_cast<std::size_t>(endOfCentralDirectory.mCentralDirectoryOffset)
    );

    mEntries.reserve(endOfCentralDirectory.mTotalEntries);
    for (std::uint32_t entryOrdinal = 0; entryOrdinal < endOfCentralDirectory.mTotalEntries; ++entryOrdinal) {
      SZipCentralDirectoryFileHeader directoryHeader{};
      reader.ReadExact(directoryHeader);
      if (directoryHeader.mSignature != kZipCentralDirectoryFileHeaderMagic) {
        gpg::Warnf("Error reading zip directory entry for '%s'", archivePath);
        return;
      }

      boost::shared_ptr<CZipFileEntry> parsedEntry(new CZipFileEntry(), ZipFileEntrySharedDeleter{});
      parsedEntry->mGeneralPurposeFlags = directoryHeader.mGeneralPurposeFlags;
      parsedEntry->mCompressionMethod = directoryHeader.mCompressionMethod;
      parsedEntry->mDosDate = directoryHeader.mDosDate;
      parsedEntry->mDosTime = directoryHeader.mDosTime;
      parsedEntry->mCompressedSize = directoryHeader.mCompressedSize;
      parsedEntry->mUncompressedSize = directoryHeader.mUncompressedSize;
      parsedEntry->mLocalHeaderOffset = directoryHeader.mLocalHeaderOffset;
      parsedEntry->mCachedDataOffset = -1;

      if (directoryHeader.mFileNameLength != 0) {
        std::vector<char> fileNameBytes(directoryHeader.mFileNameLength);
        reader.ReadExactArray(fileNameBytes.data(), fileNameBytes.size());
        parsedEntry->mName.assign_owned(
          std::string_view(fileNameBytes.data(), fileNameBytes.size())
        );
      } else {
        parsedEntry->mName.clear();
      }

      const std::size_t trailingSkipSize = static_cast<std::size_t>(directoryHeader.mExtraFieldLength) +
                                           static_cast<std::size_t>(directoryHeader.mFileCommentLength);
      if (trailingSkipSize != 0) {
        (void)zipStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginCurr, trailingSkipSize);
      }

      if ((parsedEntry->mGeneralPurposeFlags & kZipDataDescriptorFlag) != 0) {
        gpg::Logf(
          "%s: local file header for %s uses a data descriptor -- feature unsupported, skipping rest of file.",
          archivePath,
          parsedEntry->mName.c_str()
        );
        continue;
      }

      const std::uint32_t newEntryIndex = static_cast<std::uint32_t>(mEntries.size());
      SZipFileCachedEntry cachedEntry{};
      cachedEntry.mEntry = parsedEntry;
      mEntries.push_back(cachedEntry);

      if (!InsertNameIndexMapEntry(mEntryByCanonicalPath, parsedEntry->mName, newEntryIndex)) {
        gpg::Logf("%s: duplicate entries for %s.", archivePath, parsedEntry->mName.c_str());
      }
    }
  }

  /**
   * Address: 0x0046C6E0 (FUN_0046C6E0, Moho::CZipFile::~CZipFile)
   *
   * What it does:
   * Releases map/vector-owned zip metadata and resets the owned path string.
   */
  CZipFile::~CZipFile()
  {
    ResetNameIndexMap(mEntryByCanonicalPath);
    mEntries = msvc8::vector<SZipFileCachedEntry>();
    mPath.tidy(true, 0U);
  }

  [[nodiscard]]
  SZipFileCachedEntry& CZipFile::GetCachedEntryOrThrow(const std::uint32_t entryIndex, const char* const message) const
  {
    if (entryIndex >= mEntries.size()) {
      throw std::range_error(message != nullptr ? message : "CZipFile entry index out of range");
    }

    return mEntries[entryIndex];
  }

  [[nodiscard]]
  const CZipFileEntry& CZipFile::GetEntryOrThrow(const std::uint32_t entryIndex, const char* const message) const
  {
    const SZipFileCachedEntry& cachedEntry = GetCachedEntryOrThrow(entryIndex, message);
    if (!cachedEntry.mEntry) {
      throw std::range_error(message != nullptr ? message : "CZipFile entry index out of range");
    }

    return *cachedEntry.mEntry.get();
  }

  /**
   * Address: 0x0046D2F0 (FUN_0046D2F0, Moho::CZipFile::FindFile)
   *
   * What it does:
   * Resolves one canonical zip entry name to entry index, or returns `0xFFFFFFFF`.
   */
  std::uint32_t CZipFile::FindFile(const msvc8::string& canonicalPath) const
  {
    const msvc8::string lookupPath(canonicalPath);
    const SZipFileNameIndexMapNode* const matchedNode = NameIndexMapFind(mEntryByCanonicalPath, lookupPath);
    if (matchedNode == nullptr || matchedNode == mEntryByCanonicalPath.mHead) {
      return kInvalidEntryIndex;
    }

    return matchedNode->mEntryIndex;
  }

  /**
   * Address: 0x0046D380 (FUN_0046D380, Moho::CZipFile::OpenFile)
   *
   * What it does:
   * Opens one zip entry by canonical path as a memory-backed read stream.
   */
  msvc8::auto_ptr<gpg::Stream> CZipFile::OpenFile(const msvc8::string& canonicalPath) const
  {
    const std::uint32_t entryIndex = FindFile(canonicalPath);
    if (entryIndex == kInvalidEntryIndex) {
      return msvc8::auto_ptr<gpg::Stream>();
    }

    return OpenEntry(entryIndex);
  }

  /**
   * Address: 0x0046D420 (FUN_0046D420, Moho::CZipFile::ReadFile)
   *
   * What it does:
   * Reads one zip entry by canonical path into immutable shared-memory bytes.
   */
  gpg::MemBuffer<const char> CZipFile::ReadFile(const msvc8::string& canonicalPath) const
  {
    const std::uint32_t entryIndex = FindFile(canonicalPath);
    if (entryIndex == kInvalidEntryIndex) {
      return {};
    }

    return ReadEntry(entryIndex);
  }

  /**
   * Address: 0x0046D460 (FUN_0046D460, Moho::CZipFile::CopyFile)
   *
   * What it does:
   * Reads one zip entry by canonical path and returns a mutable byte copy.
   */
  gpg::MemBuffer<char> CZipFile::CopyFile(const msvc8::string& canonicalPath) const
  {
    const std::uint32_t entryIndex = FindFile(canonicalPath);
    if (entryIndex == kInvalidEntryIndex) {
      return {};
    }

    return CopyEntry(entryIndex);
  }

  /**
   * Address: 0x0046C770 (FUN_0046C770, Moho::CZipFile::GetEntryName)
   *
   * What it does:
   * Returns the canonical zip-entry name for one validated entry index.
   */
  const msvc8::string& CZipFile::GetEntryName(const std::uint32_t entryIndex) const
  {
    return GetEntryOrThrow(entryIndex, "Out of bound access in CZipFile::GetEntryName()").mName;
  }

  /**
   * Address: 0x0046C810 (FUN_0046C810, Moho::CZipFile::GetEntrySize)
   *
   * What it does:
   * Returns uncompressed byte size for one validated zip entry.
   */
  std::uint32_t CZipFile::GetEntrySize(const std::uint32_t entryIndex) const
  {
    return GetEntryOrThrow(entryIndex, "Out of bound access in CZipFile::GetEntrySize()").mUncompressedSize;
  }

  /**
   * Address: 0x0046C8B0 (FUN_0046C8B0, Moho::CZipFile::GetEntryLastModTime)
   *
   * What it does:
   * Converts the entry DOS date/time pair into Win32 FILETIME.
   */
  FILETIME CZipFile::GetEntryLastModTime(const std::uint32_t entryIndex) const
  {
    const CZipFileEntry& entry = GetEntryOrThrow(entryIndex, "Out of bounds access in CZipFile::GetEntryName()");
    FILETIME fileTime{};
    (void)::DosDateTimeToFileTime(entry.mDosDate, entry.mDosTime, &fileTime);
    return fileTime;
  }

  /**
   * Address: 0x0046CA80 (FUN_0046CA80, Moho::CZipFile::OpenEntry)
   *
   * What it does:
   * Opens one zip entry by index as a memory-backed read stream.
   */
  msvc8::auto_ptr<gpg::Stream> CZipFile::OpenEntry(const std::uint32_t entryIndex) const
  {
    (void)GetEntryOrThrow(entryIndex, "Out of bound access in CZipFile::OpenEntry()");

    const gpg::MemBuffer<const char> entryBytes = ReadEntry(entryIndex);
    if (entryBytes.data() == nullptr) {
      return msvc8::auto_ptr<gpg::Stream>();
    }

    return msvc8::auto_ptr<gpg::Stream>(
      new gpg::MemBufferStream(entryBytes, static_cast<unsigned int>(-1))
    );
  }

  /**
   * Address: 0x0046CB80 (FUN_0046CB80, Moho::CZipFile::ReadEntry)
   *
   * What it does:
   * Reads one zip entry by index, inflating method-8 entries when needed, and
   * caches immutable bytes for later reads.
   */
  gpg::MemBuffer<const char> CZipFile::ReadEntry(const std::uint32_t entryIndex) const
  {
    SZipFileCachedEntry& cachedEntry = GetCachedEntryOrThrow(
      entryIndex, "Out of bound access in CZipFile::ReadEntry()"
    );
    if (!cachedEntry.mEntry) {
      throw std::range_error("Out of bound access in CZipFile::ReadEntry()");
    }

    CZipFileEntry& entry = *cachedEntry.mEntry.get();
    if (cachedEntry.mData) {
      return MakeConstMemBuffer(cachedEntry.mData, static_cast<std::size_t>(entry.mUncompressedSize));
    }

    std::unique_ptr<gpg::Stream> zipStream = OpenZipBackingStream(mPath);
    if (zipStream == nullptr) {
      return {};
    }

    if (!ReadZipDirectory(*zipStream, entry)) {
      return {};
    }

    if (entry.mCompressionMethod == kZipCompressionStored) {
      gpg::MemBuffer<char> uncompressedBytes = gpg::AllocMemBuffer(
        static_cast<std::size_t>(entry.mUncompressedSize)
      );
      if (entry.mUncompressedSize != 0 && uncompressedBytes.data() == nullptr) {
        return {};
      }

      if (entry.mUncompressedSize != 0) {
        (void)zipStream->Read(uncompressedBytes.data(), static_cast<std::size_t>(entry.mUncompressedSize));
      }

      cachedEntry.mData = uncompressedBytes.mData;
      return MakeConstMemBuffer(cachedEntry.mData, static_cast<std::size_t>(entry.mUncompressedSize));
    }

    if (entry.mCompressionMethod == kZipCompressionDeflated) {
      gpg::MemBuffer<char> compressedBytes = gpg::AllocMemBuffer(
        static_cast<std::size_t>(entry.mCompressedSize)
      );
      if (entry.mCompressedSize != 0 && compressedBytes.data() == nullptr) {
        return {};
      }

      if (entry.mCompressedSize != 0) {
        (void)zipStream->Read(compressedBytes.data(), static_cast<std::size_t>(entry.mCompressedSize));
      }

      gpg::MemBuffer<char> uncompressedBytes = gpg::AllocMemBuffer(
        static_cast<std::size_t>(entry.mUncompressedSize)
      );
      if (entry.mUncompressedSize != 0 && uncompressedBytes.data() == nullptr) {
        return {};
      }

      z_stream inflateState{};
      inflateState.next_in = reinterpret_cast<Bytef*>(compressedBytes.data());
      inflateState.avail_in = static_cast<uInt>(entry.mCompressedSize);
      inflateState.next_out = reinterpret_cast<Bytef*>(uncompressedBytes.data());
      inflateState.avail_out = static_cast<uInt>(entry.mUncompressedSize);

      if (inflateInit2_(&inflateState, -15, "1.2.3", sizeof(z_stream)) != Z_OK) {
        gpg::Logf("%s(%s): inflateInit2 failed", mPath.c_str(), entry.mName.c_str());
        return {};
      }

      const int inflateResult = inflate(&inflateState, Z_FINISH);
      if (inflateResult != Z_STREAM_END) {
        gpg::Logf("%s(%s): inflate failed (err=%d)", mPath.c_str(), entry.mName.c_str(), inflateResult);
        (void)inflateEnd(&inflateState);
        return {};
      }

      (void)inflateEnd(&inflateState);
      cachedEntry.mData = uncompressedBytes.mData;
      return MakeConstMemBuffer(cachedEntry.mData, static_cast<std::size_t>(entry.mUncompressedSize));
    }

    gpg::Logf(
      "%s(%s): unsupported compression method %d",
      mPath.c_str(),
      entry.mName.c_str(),
      static_cast<int>(entry.mCompressionMethod)
    );
    return {};
  }

  /**
   * Address: 0x0046D250 (FUN_0046D250, Moho::CZipFile::CopyEntry)
   *
   * What it does:
   * Reads one zip entry by index and returns a mutable byte copy.
   */
  gpg::MemBuffer<char> CZipFile::CopyEntry(const std::uint32_t entryIndex) const
  {
    const gpg::MemBuffer<const char> sourceBytes = ReadEntry(entryIndex);
    const std::size_t sourceSize = sourceBytes.Size();
    if (sourceBytes.data() == nullptr) {
      return {};
    }

    gpg::MemBuffer<char> copiedBytes = gpg::AllocMemBuffer(sourceSize);
    if (sourceSize != 0 && copiedBytes.data() == nullptr) {
      return {};
    }

    if (sourceSize != 0) {
      std::memcpy(copiedBytes.data(), sourceBytes.data(), sourceSize);
    }
    return copiedBytes;
  }
} // namespace moho
