#include "moho/render/textures/CD3DFileBatchTexture.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>

#include "boost/mutex.h"
#include "boost/weak_ptr.h"
#include "gpg/core/utils/Logging.h"
#include "moho/render/textures/SBatchTextureData.h"
#include "moho/render/textures/SBatchTextureDataFactory.h"
#include "moho/render/textures/detail/BatchTextureContainerHelpers.h"

namespace moho
{
  namespace
  {
    struct TextureLookup
    {
      msvc8::string mFileName;
      std::uint32_t mBorder = 0;

      TextureLookup() = default;

      TextureLookup(const msvc8::string& fileName, const std::uint32_t border)
        : mFileName()
        , mBorder(border)
      {
        mFileName.assign_owned(fileName.view());
      }

      TextureLookup(const char* const fileName, const std::uint32_t border)
        : mFileName()
        , mBorder(border)
      {
        mFileName.assign_owned(fileName != nullptr ? fileName : "");
      }

      TextureLookup(const TextureLookup& other)
        : mFileName()
        , mBorder(other.mBorder)
      {
        mFileName.assign_owned(other.mFileName.view());
      }

      TextureLookup& operator=(const TextureLookup& other)
      {
        if (this == &other) {
          return *this;
        }

        mFileName.tidy(true, 0U);
        mFileName.assign_owned(other.mFileName.view());
        mBorder = other.mBorder;
        return *this;
      }

      TextureLookup(TextureLookup&& other) noexcept
        : mFileName(other.mFileName)
        , mBorder(other.mBorder)
      {
        other.mFileName.myRes = 15U;
        other.mFileName.mySize = 0U;
        other.mFileName.bx.buf[0] = '\0';
        other.mBorder = 0U;
      }

      TextureLookup& operator=(TextureLookup&& other) noexcept
      {
        if (this == &other) {
          return *this;
        }

        mFileName.tidy(true, 0U);
        mFileName = other.mFileName;
        mBorder = other.mBorder;

        other.mFileName.myRes = 15U;
        other.mFileName.mySize = 0U;
        other.mFileName.bx.buf[0] = '\0';
        other.mBorder = 0U;
        return *this;
      }

      ~TextureLookup()
      {
        mFileName.tidy(true, 0U);
      }
    };

    /**
     * Address: 0x004483A0 (FUN_004483A0)
     * Address: 0x0044B6F0 (FUN_0044B6F0, comparator clone lane)
     *
     * What it does:
     * Compares two file-texture lookup keys by border and then filename text.
     */
    [[nodiscard]] bool IsTextureLookupLess(const TextureLookup& lhs, const TextureLookup& rhs)
    {
      if (lhs.mBorder != rhs.mBorder) {
        return lhs.mBorder < rhs.mBorder;
      }
      return lhs.mFileName.view() < rhs.mFileName.view();
    }

    struct TextureLookupLess
    {
      [[nodiscard]] bool operator()(const TextureLookup& lhs, const TextureLookup& rhs) const
      {
        return IsTextureLookupLess(lhs, rhs);
      }
    };

    using FileTextureHandle = boost::shared_ptr<CD3DFileBatchTexture>;
    using FileTextureWeakHandle = boost::weak_ptr<CD3DFileBatchTexture>;
    using TextureLookupMap = std::map<TextureLookup, FileTextureWeakHandle, TextureLookupLess>;
    using FileTextureRetainQueue = msvc8::vector<FileTextureHandle>;
    constexpr std::size_t kRetainQueueLimit = 30u;

    TextureLookupMap sTextureMap;
    FileTextureRetainQueue sFileTextures;

    /**
     * Address: 0x0044B3D0 (FUN_0044B3D0)
     * Address: 0x0044CC80 (FUN_0044CC80, clone lane)
     * Address: 0x0044DB00 (FUN_0044DB00, clone lane)
     * Address: 0x0044DD60 (FUN_0044DD60, clone lane)
     *
     * What it does:
     * Initializes file-texture lookup map storage/sentinel state.
     * In recovered C++, static storage construction already performs this once.
     */
    [[maybe_unused]] [[nodiscard]] TextureLookupMap& InitializeTextureLookupMapStorage()
    {
      return sTextureMap;
    }

    /**
     * Address: 0x0044C870 (FUN_0044C870)
     *
     * What it does:
     * Returns the leftmost/live iterator lane for the texture-lookup map.
     */
    [[maybe_unused]] [[nodiscard]] TextureLookupMap::iterator TextureLookupMapBegin()
    {
      return detail::ContainerBegin(sTextureMap);
    }

    /**
     * Address: 0x0044C880 (FUN_0044C880)
     *
     * What it does:
     * Returns live entry count for the texture-lookup cache map.
     */
    [[maybe_unused]] [[nodiscard]] std::size_t TextureLookupMapSize()
    {
      return sTextureMap.size();
    }

    /**
     * Address: 0x0044CC20 (FUN_0044CC20)
     *
     * What it does:
     * Returns the first texture-lookup entry whose key is not less than the
     * requested `(filename,border)` pair.
     */
    [[nodiscard]] TextureLookupMap::iterator TextureLookupMapLowerBound(const TextureLookup& lookup)
    {
      return detail::MapLowerBound(sTextureMap, lookup);
    }

    /**
     * Address: 0x0044B590 (FUN_0044B590)
     *
     * What it does:
     * Returns map sentinel/end iterator lane.
     */
    [[maybe_unused]] [[nodiscard]] TextureLookupMap::iterator TextureLookupMapEnd()
    {
      return sTextureMap.end();
    }

    /**
     * Address: 0x0044DBA0 (FUN_0044DBA0)
     *
     * What it does:
     * Moves one texture-lookup iterator to the previous in-order entry.
     * `end()` maps to the rightmost entry and `begin()` wraps to `end()`.
     */
    [[maybe_unused]] void RetreatTextureLookupIterator(TextureLookupMap::iterator& iterator)
    {
      detail::RetreatIterator(sTextureMap, iterator);
    }

    /**
     * Address: 0x0044DAC0 (FUN_0044DAC0)
     *
     * What it does:
     * Releases all texture-lookup map nodes and payload ownership lanes.
     */
    [[maybe_unused]] void ClearTextureLookupMapStorage()
    {
      sTextureMap.clear();
    }

    /**
     * Address: 0x0044B810 (FUN_0044B810)
     *
     * What it does:
     * Initializes fixed-capacity retain queue storage for file textures.
     */
    [[maybe_unused]] [[nodiscard]] FileTextureRetainQueue& InitializeFileTextureRetainQueueStorage()
    {
      return sFileTextures;
    }

    /**
     * Address: 0x0044B760 (FUN_0044B760)
     *
     * What it does:
     * Returns retain queue begin lane.
     */
    [[maybe_unused]] [[nodiscard]] FileTextureHandle* FileTextureRetainQueueBegin()
    {
      return detail::ContainerBegin(sFileTextures);
    }

    /**
     * Address: 0x0044B770 (FUN_0044B770)
     *
     * What it does:
     * Returns retain queue end lane.
     */
    [[maybe_unused]] [[nodiscard]] FileTextureHandle* FileTextureRetainQueueEnd()
    {
      return detail::ContainerEnd(sFileTextures);
    }

    using FileTextureRetainIterator = FileTextureHandle*;

    /**
     * Address: 0x0044ED70 (FUN_0044ED70)
     * Address: 0x00857520 (FUN_00857520)
     * Address: 0x00784760 (FUN_00784760)
     *
     * What it does:
     * Copies one contiguous retain-queue lane forward, preserving shared_ptr
     * reference-count semantics.
     */
    [[maybe_unused]] FileTextureRetainIterator CopyFileTextureRetainRange(
      FileTextureRetainIterator destination,
      FileTextureRetainIterator first,
      FileTextureRetainIterator last
    )
    {
      return detail::CopyRange(first, last, destination);
    }

    /**
     * Address: 0x00784690 (FUN_00784690)
     * Address: 0x00857130 (FUN_00857130)
     *
     * What it does:
     * Register-shape adapter that forwards one contiguous retain-queue copy
     * range (`first..last`) into destination storage.
     */
    [[maybe_unused]] FileTextureRetainIterator CopyFileTextureRetainRangeRegisterAdapterA(
      const FileTextureRetainIterator first,
      const FileTextureRetainIterator last,
      FileTextureRetainIterator destination
    )
    {
      return CopyFileTextureRetainRange(destination, first, last);
    }

    /**
     * Address: 0x0044EF80 (FUN_0044EF80)
     * Address: 0x0044F000 (FUN_0044F000, clone lane)
     *
     * What it does:
     * Copies one retain-queue lane backward, preserving shared_ptr
     * reference-count semantics.
     */
    [[maybe_unused]] FileTextureRetainIterator CopyFileTextureRetainRangeBackward(
      FileTextureRetainIterator first,
      FileTextureRetainIterator last,
      FileTextureRetainIterator destinationEnd
    )
    {
      return detail::CopyRangeBackward(first, last, destinationEnd);
    }

    struct LegacyBlockLane16
    {
      std::uint32_t word0 = 0;
      std::uint32_t word1 = 0;
      std::uint32_t word2 = 0;
      std::uint32_t word3 = 0;
    };

    struct LegacyBlockLaneVectorView
    {
      void* proxy = nullptr;
      LegacyBlockLane16* first = nullptr;
      LegacyBlockLane16* last = nullptr;
      LegacyBlockLane16* end = nullptr;
    };

    static_assert(offsetof(LegacyBlockLaneVectorView, first) == 0x04, "LegacyBlockLaneVectorView::first offset must be 0x04");
    static_assert(offsetof(LegacyBlockLaneVectorView, last) == 0x08, "LegacyBlockLaneVectorView::last offset must be 0x08");
    static_assert(offsetof(LegacyBlockLaneVectorView, end) == 0x0C, "LegacyBlockLaneVectorView::end offset must be 0x0C");
    static_assert(sizeof(LegacyBlockLane16) == 0x10, "LegacyBlockLane16 size must be 0x10");
    static_assert(sizeof(LegacyBlockLaneVectorView) == 0x10, "LegacyBlockLaneVectorView size must be 0x10");

    /**
     * Address: 0x0044EAB0 (FUN_0044EAB0)
     *
     * What it does:
     * Copies one legacy block-lane vector begin pointer into caller storage.
     */
    [[maybe_unused]] LegacyBlockLane16** CopyLegacyBlockLaneBeginCursor(
      LegacyBlockLane16** const outCursor,
      const LegacyBlockLaneVectorView& view
    )
    {
      *outCursor = view.first;
      return outCursor;
    }

    /**
     * Address: 0x0044EAC0 (FUN_0044EAC0)
     *
     * What it does:
     * Copies one legacy block-lane vector end pointer into caller storage.
     */
    [[maybe_unused]] LegacyBlockLane16** CopyLegacyBlockLaneEndCursor(
      LegacyBlockLane16** const outCursor,
      const LegacyBlockLaneVectorView& view
    )
    {
      *outCursor = view.last;
      return outCursor;
    }

    /**
     * Address: 0x0044ED10 (FUN_0044ED10)
     *
     * What it does:
     * Copies `count` 16-byte block lanes from source to destination and returns
     * the advanced destination cursor lane.
     */
    [[maybe_unused]] LegacyBlockLane16* CopyLegacyBlockLaneCount(
      LegacyBlockLane16* destination,
      const LegacyBlockLane16* source,
      std::size_t count
    )
    {
      std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
      const LegacyBlockLane16* readCursor = source;
      while (count != 0u) {
        if (destinationAddress != 0u) {
          *reinterpret_cast<LegacyBlockLane16*>(destinationAddress) = *readCursor;
        }
        destinationAddress += sizeof(LegacyBlockLane16);
        ++readCursor;
        --count;
      }
      return reinterpret_cast<LegacyBlockLane16*>(destinationAddress);
    }

    /**
     * Address: 0x0044ECA0 (FUN_0044ECA0)
     * Address: 0x0044ED60 (FUN_0044ED60, clone lane)
     * Address: 0x0044EE40 (FUN_0044EE40, clone lane)
     * Address: 0x0044EE90 (FUN_0044EE90, clone lane)
     * Address: 0x0044EF10 (FUN_0044EF10, clone lane)
     * Address: 0x0044EF70 (FUN_0044EF70, clone lane)
     *
     * What it does:
     * Returns the high byte lane from one 32-bit input value.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t ExtractHighByteLane(const std::uint32_t value)
    {
      return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
    }

    /**
     * Address: 0x0044F080 (FUN_0044F080)
     *
     * What it does:
     * Returns constant true.
     */
    [[maybe_unused]] [[nodiscard]] bool ReturnTrueLane()
    {
      return true;
    }

    /**
     * Address: 0x0044F090 (FUN_0044F090)
     * Address: 0x0044F0A0 (FUN_0044F0A0, clone lane)
     * Address: 0x0044F0B0 (FUN_0044F0B0, clone lane)
     *
     * What it does:
     * Swaps one 32-bit lane between two caller-provided pointers.
     */
    [[maybe_unused]] std::uint32_t* SwapWordLane(std::uint32_t* const lhs, std::uint32_t* const rhs)
    {
      std::swap(*lhs, *rhs);
      return lhs;
    }

    /**
     * Address: 0x0044A710 (FUN_0044A710)
     *
     * What it does:
     * Locks one weak file-texture cache handle into a shared handle if the
     * pointed object is still alive.
     */
    [[nodiscard]] FileTextureHandle LockFileTextureWeakHandle(const FileTextureWeakHandle& weakTexture)
    {
      const FileTextureHandle outTexture = weakTexture.lock();
      return detail::CopyResult(outTexture);
    }

    [[nodiscard]] TextureLookupMap::iterator FindTextureLookupEntry(const TextureLookup& lookup)
    {
      (void)TextureLookupMapBegin();
      (void)TextureLookupMapSize();
      const TextureLookupMap::iterator it = TextureLookupMapLowerBound(lookup);
      if (it == TextureLookupMapEnd()) {
        return it;
      }

      if (IsTextureLookupLess(lookup, it->first) || IsTextureLookupLess(it->first, lookup)) {
        return TextureLookupMapEnd();
      }

      return it;
    }

    /**
     * Address: 0x00449F50 (FUN_00449F50, Moho::AddFileBatchTexture)
     *
     * What it does:
     * Moves one file texture to the front of the deferred-delete keepalive queue,
     * deduplicating existing entries and trimming to the fixed retain limit.
     */
    void AddFileBatchTexture(const FileTextureHandle& fileTexture)
    {
      (void)InitializeFileTextureRetainQueueStorage();
      if (!fileTexture) {
        return;
      }

      for (FileTextureHandle* it = FileTextureRetainQueueBegin(); it != FileTextureRetainQueueEnd();) {
        if (it->get() == fileTexture.get()) {
          it = detail::EraseIterator(sFileTextures, it);
          continue;
        }
        ++it;
      }

      if (sFileTextures.size() >= kRetainQueueLimit && !sFileTextures.empty()) {
        detail::EraseIterator(sFileTextures, FileTextureRetainQueueEnd() - 1);
      }

      sFileTextures.push_back(fileTexture);
      for (std::size_t index = sFileTextures.size() - 1u; index != 0u; --index) {
        sFileTextures[index] = sFileTextures[index - 1u];
      }
      sFileTextures[0] = fileTexture;
    }

    /**
     * Address: 0x0044A010 (FUN_0044A010)
     *
     * What it does:
     * Removes one matching file texture pointer from the deferred keepalive queue.
     */
    void RemoveFileBatchTexture(const FileTextureHandle& fileTexture)
    {
      for (FileTextureHandle* it = FileTextureRetainQueueBegin(); it != FileTextureRetainQueueEnd(); ++it) {
        if (it->get() == fileTexture.get()) {
          detail::EraseIterator(sFileTextures, it);
          break;
        }
      }
    }

    /**
     * Address: 0x0044DF90 (FUN_0044DF90, func_GetD3DTextureData)
     *
     * What it does:
     * Loads one decoded `SBatchTextureData` payload through the texture-data factory.
     */
    [[nodiscard]] boost::shared_ptr<SBatchTextureData> GetD3DTextureData(const char* const filename)
    {
      boost::shared_ptr<SBatchTextureData> outData;
      SBatchTextureDataFactory* const factory = construct_SBatchTextureDataFactory();
      if (factory != nullptr) {
        factory->Load(outData, filename);
      }
      return outData;
    }
  } // namespace

  /**
   * Address: 0x00BC43A0 (FUN_00BC43A0, register_mTextureMap)
   */
  void register_mTextureMap()
  {
    (void)InitializeTextureLookupMapStorage();
  }

  /**
   * Address: 0x00BC43E0 (FUN_00BC43E0, register_sFileTextures)
   */
  void register_sFileTextures()
  {
    (void)InitializeFileTextureRetainQueueStorage();
  }

  /**
   * Address: 0x004483E0 (FUN_004483E0, Moho::CD3DFileBatchTexture::CD3DFileBatchTexture)
   */
  CD3DFileBatchTexture::CD3DFileBatchTexture(
    const DataHandle& data,
    const std::uint32_t border,
    const msvc8::string& filename
  )
    : CD3DRawBatchTexture(data, border)
    , mFilename()
    , mCanDelete(false)
  {
    mFilename.assign_owned(filename.view());
  }

  /**
   * Address: 0x00448490 (FUN_00448490, Moho::CD3DFileBatchTexture::dtr)
   * Address: 0x004484D0 (FUN_004484D0, non-deleting helper lane)
   */
  CD3DFileBatchTexture::~CD3DFileBatchTexture()
  {
    mFilename.tidy(true, 0U);
  }

  /**
   * Address: 0x00448450 (FUN_00448450)
   */
  bool CD3DFileBatchTexture::CanDelete() const
  {
    return mCanDelete;
  }

  /**
   * Address: 0x00448460 (FUN_00448460)
   */
  void CD3DFileBatchTexture::MarkCanDelete()
  {
    mCanDelete = true;
  }

  /**
   * Address: 0x00448470 (FUN_00448470)
   */
  void CD3DFileBatchTexture::ClearCanDelete()
  {
    mCanDelete = false;
  }

  /**
   * Address: 0x00448480 (FUN_00448480)
   */
  const msvc8::string& CD3DFileBatchTexture::GetFilename() const
  {
    return mFilename;
  }

  /**
   * Address: 0x00448500 (FUN_00448500, Moho::CD3DFileBatchTexture::OnClose)
   */
  void CD3DFileBatchTexture::OnClose(CD3DFileBatchTexture* const texture)
  {
    if (texture == nullptr) {
      return;
    }

    boost::mutex::scoped_lock scopedLock(sResourceLock);

    const TextureLookup lookup(texture->GetFilename(), texture->GetBorder());
    TextureLookupMap::iterator mapIt = FindTextureLookupEntry(lookup);

    if (texture->CanDelete()) {
      if (mapIt != TextureLookupMapEnd()) {
        detail::EraseIterator(sTextureMap, mapIt);
      }
      delete texture;
      return;
    }

    FileTextureHandle retainedTexture(texture, &CD3DFileBatchTexture::OnClose);
    texture->MarkCanDelete();
    AddFileBatchTexture(retainedTexture);

    if (mapIt != TextureLookupMapEnd()) {
      mapIt->second = retainedTexture;
      return;
    }

    detail::MapInsertAtHint(
      sTextureMap,
      TextureLookupMapLowerBound(lookup),
      TextureLookupMap::value_type(lookup, FileTextureWeakHandle(retainedTexture))
    );
  }

  /**
   * Address: 0x004486F0 (FUN_004486F0, Moho::CD3DBatchTexture::FromFile)
   * Address: 0x0044DF30 (FUN_0044DF30, shared_ptr assignment helper lane)
   * Address: 0x0044E050 (FUN_0044E050, shared_ptr raw-assign helper lane)
   * Address: 0x0044EC00 (FUN_0044EC00, shared_count with OnClose deleter lane)
   */
  boost::shared_ptr<CD3DBatchTexture> CD3DBatchTexture::FromFile(const gpg::StrArg filename, const std::uint32_t border)
  {
    (void)InitializeTextureLookupMapStorage();
    (void)InitializeFileTextureRetainQueueStorage();

    boost::shared_ptr<CD3DBatchTexture> outTexture;
    const char* const normalizedPath = filename != nullptr ? filename : "";

    boost::mutex::scoped_lock scopedLock(sResourceLock);

    const TextureLookup lookup(normalizedPath, border);
    const TextureLookupMap::iterator cachedIt = FindTextureLookupEntry(lookup);
    if (cachedIt != TextureLookupMapEnd()) {
      FileTextureHandle cachedFileTexture = LockFileTextureWeakHandle(cachedIt->second);
      if (cachedFileTexture) {
        if (cachedFileTexture->CanDelete()) {
          RemoveFileBatchTexture(cachedFileTexture);
          cachedFileTexture->ClearCanDelete();
        }

        outTexture = cachedFileTexture;
        return outTexture;
      }
    }

    boost::shared_ptr<SBatchTextureData> textureData = GetD3DTextureData(normalizedPath);
    if (!textureData) {
      gpg::Logf("Unable to load texture from file: %s", normalizedPath);
      return outTexture;
    }

    FileTextureHandle fileTexture(
      new CD3DFileBatchTexture(textureData, border, lookup.mFileName),
      &CD3DFileBatchTexture::OnClose
    );
    if (cachedIt != TextureLookupMapEnd()) {
      cachedIt->second = fileTexture;
    } else {
      detail::MapInsertAtHint(
        sTextureMap,
        TextureLookupMapLowerBound(lookup),
        TextureLookupMap::value_type(lookup, FileTextureWeakHandle(fileTexture))
      );
    }

    outTexture = fileTexture;
    return detail::CopyResult(outTexture);
  }
} // namespace moho

namespace
{
  struct FileBatchTextureCacheBootstrap
  {
    FileBatchTextureCacheBootstrap()
    {
      moho::register_mTextureMap();
      moho::register_sFileTextures();
    }
  };

  FileBatchTextureCacheBootstrap gFileBatchTextureCacheBootstrap;
} // namespace
