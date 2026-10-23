#include "moho/render/textures/CD3DFileBatchTexture.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>

#include "boost/mutex.h"
#include "boost/weak_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/resource/ResourceManager.h"
#include "moho/render/textures/SBatchTextureData.h"
#include "moho/render/textures/SBatchTextureDataFactory.h"

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
     * Address: 0x0044A710 (FUN_0044A710)
     *
     * What it does:
     * Locks one weak file-texture cache handle into a shared handle if the
     * pointed object is still alive.
     */
    [[nodiscard]] FileTextureHandle LockFileTextureWeakHandle(const FileTextureWeakHandle& weakTexture)
    {
      const FileTextureHandle outTexture = weakTexture.lock();
      return outTexture;
    }

    [[nodiscard]] TextureLookupMap::iterator FindTextureLookupEntry(const TextureLookup& lookup)
    {
      const TextureLookupMap::iterator it = sTextureMap.lower_bound(lookup);
      if (it == sTextureMap.end()) {
        return it;
      }

      if (IsTextureLookupLess(lookup, it->first) || IsTextureLookupLess(it->first, lookup)) {
        return sTextureMap.end();
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
      if (!fileTexture) {
        return;
      }

      for (FileTextureHandle* it = sFileTextures.begin(); it != sFileTextures.end();) {
        if (it->get() == fileTexture.get()) {
          it = sFileTextures.erase(it);
          continue;
        }
        ++it;
      }

      if (sFileTextures.size() >= kRetainQueueLimit && !sFileTextures.empty()) {
        (void)sFileTextures.erase(sFileTextures.end() - 1);
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
      for (FileTextureHandle* it = sFileTextures.begin(); it != sFileTextures.end(); ++it) {
        if (it->get() == fileTexture.get()) {
          (void)sFileTextures.erase(it);
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
      // Go through the resource manager, not straight at the factory. Calling
      // SBatchTextureDataFactory::Load here skips two things the manager does
      // first, and the second one is fatal: it resolves the path through the
      // mounted VFS. Every texture request arrives as a mount-point path such
      // as "/textures/ui/common/scx_menu/small-btn/small_btn_up.dds", while the
      // wait-handle set keys its zip entries by the archive-qualified physical
      // path ("...\gamedata\textures.scd\textures\ui\..."). Without the
      // resolve, DISK_MemoryMapFile misses the zip map, falls through to
      // CreateFileW on a path beginning with a backslash, and hands back an
      // empty buffer - so no texture in the game ever loaded, every Bitmap
      // control reported 0x0, and each dialog collapsed onto a single point
      // because MAUI lays controls out relative to one another's size.
      gpg::RType* resourceType = SBatchTextureData::sType;
      if (resourceType == nullptr) {
        resourceType = gpg::LookupRType(typeid(SBatchTextureData));
        SBatchTextureData::sType = resourceType;
      }

      return boost::static_pointer_cast<SBatchTextureData>(
        RES_GetResource(filename != nullptr ? filename : "", nullptr, resourceType)
      );
    }
  } // namespace

  /**
   * Address: 0x00BC43A0 (FUN_00BC43A0, register_mTextureMap)
   *
   * What it does:
   * Static-init registration hook for the file-texture lookup map; the map's
   * sentinel storage is constructed by its own static initializer.
   */
  void register_mTextureMap()
  {
    (void)sTextureMap;
  }

  /**
   * Address: 0x00BC43E0 (FUN_00BC43E0, register_sFileTextures)
   *
   * What it does:
   * Static-init registration hook for the deferred-delete retain queue; the
   * queue's storage is constructed by its own static initializer.
   */
  void register_sFileTextures()
  {
    (void)sFileTextures;
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
      if (mapIt != sTextureMap.end()) {
        (void)sTextureMap.erase(mapIt);
      }
      delete texture;
      return;
    }

    FileTextureHandle retainedTexture(texture, &CD3DFileBatchTexture::OnClose);
    texture->MarkCanDelete();
    AddFileBatchTexture(retainedTexture);

    if (mapIt != sTextureMap.end()) {
      mapIt->second = retainedTexture;
      return;
    }

    (void)sTextureMap.insert(
      sTextureMap.lower_bound(lookup),
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
    boost::shared_ptr<CD3DBatchTexture> outTexture;
    const char* const normalizedPath = filename != nullptr ? filename : "";

    boost::mutex::scoped_lock scopedLock(sResourceLock);

    const TextureLookup lookup(normalizedPath, border);
    const TextureLookupMap::iterator cachedIt = FindTextureLookupEntry(lookup);
    if (cachedIt != sTextureMap.end()) {
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
    if (cachedIt != sTextureMap.end()) {
      cachedIt->second = fileTexture;
    } else {
      (void)sTextureMap.insert(
        sTextureMap.lower_bound(lookup),
        TextureLookupMap::value_type(lookup, FileTextureWeakHandle(fileTexture))
      );
    }

    outTexture = fileTexture;
    return outTexture;
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
