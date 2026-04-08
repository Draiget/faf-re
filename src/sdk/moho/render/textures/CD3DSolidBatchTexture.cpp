#include "moho/render/textures/CD3DSolidBatchTexture.h"

#include <map>

#include "boost/mutex.h"
#include "boost/weak_ptr.h"

namespace moho
{
  namespace
  {
    using SolidTextureHandle = boost::shared_ptr<CD3DSolidBatchTexture>;
    using SolidTextureWeakHandle = boost::weak_ptr<CD3DSolidBatchTexture>;
    using SolidTextureMap = std::map<std::uint32_t, SolidTextureWeakHandle>;

    constexpr std::uint32_t kSolidTextureWidth = 2u;
    constexpr std::uint32_t kSolidTextureHeight = 2u;
    constexpr std::uint32_t kSolidTextureBorder = 1u;

    SolidTextureMap sSolidTextureMap;

    /**
     * Address: 0x0044DA80 (FUN_0044DA80)
     * Address: 0x0044DD50 (FUN_0044DD50, clone lane)
     *
     * What it does:
     * Returns the global solid-texture cache map.
     */
    [[nodiscard]] SolidTextureMap& GetSolidTextureMap()
    {
      return sSolidTextureMap;
    }

    /**
     * Address: 0x0044B030 (FUN_0044B030)
     *
     * What it does:
     * Initializes solid-texture map storage/sentinel state.
     * In recovered C++, static storage construction already performs this once.
     */
    [[maybe_unused]] [[nodiscard]] SolidTextureMap& InitializeSolidTextureMapStorage()
    {
      return GetSolidTextureMap();
    }

    /**
     * Address: 0x0044B1D0 (FUN_0044B1D0)
     *
     * What it does:
     * Returns the map sentinel/end iterator lane.
     */
    template <class Map>
    [[nodiscard]] typename Map::iterator GetMapEnd(Map& map)
    {
      return map.end();
    }

    [[nodiscard]] SolidTextureMap::iterator SolidTextureMapEnd()
    {
      return GetMapEnd(GetSolidTextureMap());
    }

    /**
     * Address: 0x0044B1A0 (FUN_0044B1A0)
     *
     * What it does:
     * Returns the first map entry whose key is not less than `color`.
     */
    template <class Map>
    [[nodiscard]] typename Map::iterator GetMapLowerBound(Map& map, const typename Map::key_type& key)
    {
      return map.lower_bound(key);
    }

    [[nodiscard]] SolidTextureMap::iterator LowerBoundSolidTextureEntry(const std::uint32_t color)
    {
      return GetMapLowerBound(GetSolidTextureMap(), color);
    }

    /**
     * Address: 0x0044D920 (FUN_0044D920)
     * Address: 0x0044DC20 (FUN_0044DC20, clone lane)
     *
     * What it does:
     * Returns an iterator/cursor result unchanged.
     */
    template <class Iterator>
    [[nodiscard]] Iterator CopyIteratorResult(Iterator iterator)
    {
      return iterator;
    }

    /**
     * Address: 0x0044DD80 (FUN_0044DD80)
     *
     * What it does:
     * Advances one solid-texture iterator to the next in-order entry. End
     * iterators stay at end.
     */
    template <class Map>
    void AdvanceMapIterator(Map& map, typename Map::iterator& iterator)
    {
      if (iterator != map.end()) {
        ++iterator;
      }
    }

    /**
     * Address: 0x0044DB40 (FUN_0044DB40)
     *
     * What it does:
     * Moves one solid-texture iterator to the previous in-order entry.
     * `end()` maps to the rightmost entry and `begin()` wraps to `end()`.
     */
    template <class Map>
    void RetreatMapIterator(Map& map, typename Map::iterator& iterator)
    {
      if (map.empty()) {
        iterator = map.end();
        return;
      }

      if (iterator == map.end()) {
        iterator = map.end();
        --iterator;
        return;
      }

      if (iterator == map.begin()) {
        iterator = map.end();
        return;
      }

      --iterator;
    }

    /**
     * Address: 0x0044B070 (FUN_0044B070)
     *
     * What it does:
     * Computes insertion hint lane for one solid-color cache key.
     */
    [[nodiscard]] SolidTextureMap::iterator FindSolidTextureInsertHint(const std::uint32_t color)
    {
      return CopyIteratorResult(LowerBoundSolidTextureEntry(color));
    }

    /**
     * Address: 0x0044D9D0 (FUN_0044D9D0)
     *
     * What it does:
     * Returns the rightmost (maximum-key) solid-texture cache entry.
     */
    template <class Map>
    [[nodiscard]] typename Map::iterator GetMapRightmost(Map& map)
    {
      if (map.empty()) {
        return map.end();
      }

      typename Map::iterator it = map.end();
      --it;
      return it;
    }

    /**
     * Address: 0x0044D9F0 (FUN_0044D9F0)
     *
     * What it does:
     * Returns the leftmost (minimum-key) solid-texture cache entry.
     */
    template <class Map>
    [[nodiscard]] typename Map::iterator GetMapLeftmost(Map& map)
    {
      if (map.empty()) {
        return map.end();
      }
      return map.begin();
    }

    /**
     * Address: 0x0044D950 (FUN_0044D950)
     * Address: 0x0044D960 (FUN_0044D960, clone lane)
     *
     * What it does:
     * Copies one `(iterator,inserted)` result lane used by map insert/find
     * helpers.
     */
    template <class Iterator>
    struct InsertCursorResult
    {
      Iterator iterator;
      bool inserted = false;
    };

    template <class Iterator>
    [[nodiscard]] InsertCursorResult<Iterator>& CopyInsertCursorResult(
      InsertCursorResult<Iterator>& destination,
      const InsertCursorResult<Iterator>& source
    )
    {
      destination = source;
      return destination;
    }

    [[maybe_unused]] [[nodiscard]] SolidTextureMap::iterator RightmostSolidTextureEntry()
    {
      return GetMapRightmost(GetSolidTextureMap());
    }

    [[maybe_unused]] [[nodiscard]] SolidTextureMap::iterator LeftmostSolidTextureEntry()
    {
      return GetMapLeftmost(GetSolidTextureMap());
    }

    [[maybe_unused]] void AdvanceSolidTextureIterator(SolidTextureMap::iterator& iterator)
    {
      AdvanceMapIterator(GetSolidTextureMap(), iterator);
    }

    [[maybe_unused]] void RetreatSolidTextureIterator(SolidTextureMap::iterator& iterator)
    {
      RetreatMapIterator(GetSolidTextureMap(), iterator);
    }

    [[nodiscard]] SolidTextureMap::iterator FindSolidTextureEntry(const std::uint32_t color)
    {
      SolidTextureMap& solidTextureMap = GetSolidTextureMap();
      SolidTextureMap::iterator it = GetMapLowerBound(solidTextureMap, color);
      const SolidTextureMap::iterator end = SolidTextureMapEnd();
      if (it == end || color < it->first) {
        return end;
      }
      return CopyIteratorResult(it);
    }

    /**
     * Address: 0x0044A280 (FUN_0044A280)
     *
     * What it does:
     * Locks one weak cached solid-texture handle into a shared handle only when
     * the control block still has live owners.
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture>
      LockSolidTextureWeakHandle(const SolidTextureWeakHandle& weakTexture)
    {
      const SolidTextureHandle lockedTexture = weakTexture.lock();
      boost::shared_ptr<CD3DBatchTexture> outTexture = lockedTexture;
      return outTexture;
    }

    /**
     * Address: 0x0044DE00 (FUN_0044DE00, shared_ptr-from-raw helper lane)
     * Address: 0x0044EAD0 (FUN_0044EAD0, shared_ptr enable_shared_from_this lane)
     * Address: 0x0044F300 (FUN_0044F300, shared_count<CD3DSolidBatchTexture> ctor lane)
     *
     * What it does:
     * Builds one owning shared handle from a raw solid-texture pointer.
     */
    [[nodiscard]] SolidTextureHandle BuildSolidTextureSharedHandle(CD3DSolidBatchTexture* const rawTexture)
    {
      return SolidTextureHandle(rawTexture);
    }

    /**
     * Address: 0x0044B2E0 (FUN_0044B2E0)
     *
     * What it does:
     * Address: 0x0044DA30 (FUN_0044DA30, recursive node release lane)
     *
     * Releases map-node storage and resets map size/sentinel lanes.
     * Recovered through full cache clear of typed map storage.
     */
    [[maybe_unused]] [[nodiscard]] int ReleaseSolidTextureMapStorage()
    {
      GetSolidTextureMap().clear();
      return 0;
    }

    /**
     * Address: 0x004471C0 (FUN_004471C0)
     * Address: 0x0044D3C0 (FUN_0044D3C0, clear/reset helper lane)
     *
     * What it does:
     * Clears the global solid-color texture cache map.
     */
    [[maybe_unused]] [[nodiscard]] int DestroySolidTextureMapStorage()
    {
      return ReleaseSolidTextureMapStorage();
    }
  } // namespace

  /**
   * Address: 0x00BC4360 (FUN_00BC4360, register_sSolidTextureMap)
   */
  void register_sSolidTextureMap()
  {
    (void)InitializeSolidTextureMapStorage();
  }

  /**
   * Address: 0x00447720 (FUN_00447720)
   *
   * std::uint32_t rgba
   *
   * What it does:
   * Initializes one 2x2 border-1 batch texture that stores one solid RGBA color.
   */
  CD3DSolidBatchTexture::CD3DSolidBatchTexture(const std::uint32_t rgba)
    : CD3DBatchTexture(kSolidTextureWidth, kSolidTextureHeight, kSolidTextureBorder)
    , mColor(rgba)
  {}

  /**
   * Address: 0x004478A0 (FUN_004478A0, deleting thunk)
   * Address: 0x00447760 (FUN_00447760, non-deleting body)
   *
   * What it does:
   * Removes this solid-color texture from the global color cache and then
   * releases base batch-texture ownership/list links.
   */
  CD3DSolidBatchTexture::~CD3DSolidBatchTexture()
  {
    boost::mutex::scoped_lock scopedLock(sResourceLock);

    SolidTextureMap& solidTextureMap = GetSolidTextureMap();
    const SolidTextureMap::iterator it = FindSolidTextureEntry(mColor);
    if (it != SolidTextureMapEnd()) {
      solidTextureMap.erase(it);
    }
  }

  /**
   * Address: 0x00447820 (FUN_00447820, Moho::CD3DSolidBatchTexture::Func1)
   *
   * void *,std::uint32_t
   *
   * What it does:
   * Writes one constant-color DXT-compatible 4x4 block into destination memory.
   */
  void CD3DSolidBatchTexture::BuildTextureData(void* const destination, const std::uint32_t pitch)
  {
    (void)pitch;
    if (destination == nullptr) {
      return;
    }

    std::uint16_t* const words = static_cast<std::uint16_t*>(destination);

    const std::uint8_t alpha = static_cast<std::uint8_t>((mColor >> 24u) & 0xFFu);
    const std::uint16_t alphaEndpoints = static_cast<std::uint16_t>(alpha | (static_cast<std::uint16_t>(alpha) << 8u));

    const std::uint8_t blue = static_cast<std::uint8_t>(mColor & 0xFFu);
    const std::uint8_t green = static_cast<std::uint8_t>((mColor >> 8u) & 0xFFu);
    const std::uint8_t red = static_cast<std::uint8_t>((mColor >> 16u) & 0xFFu);

    const std::uint16_t rgb565 = static_cast<std::uint16_t>(
      ((static_cast<std::uint16_t>(red) & 0xF8u) << 8u) |
      ((static_cast<std::uint16_t>(green) & 0xFCu) << 3u) |
      ((static_cast<std::uint16_t>(blue) >> 3u) & 0x1Fu)
    );

    words[0] = alphaEndpoints;
    words[1] = 0u;
    words[2] = 0u;
    words[3] = 0u;
    words[4] = rgb565;
    words[5] = rgb565;
    words[6] = 0u;
    words[7] = 0u;
  }

  /**
   * Address: 0x00447890 (FUN_00447890, Moho::CD3DSolidBatchTexture::GetAlphaAt)
   *
   * std::uint32_t,std::uint32_t
   *
   * What it does:
   * Returns the alpha byte from this solid RGBA color.
   */
  std::uint8_t CD3DSolidBatchTexture::GetAlphaAt(const std::uint32_t x, const std::uint32_t y) const
  {
    (void)x;
    (void)y;
    return static_cast<std::uint8_t>((mColor >> 24u) & 0xFFu);
  }

  /**
   * Address: 0x004478C0 (FUN_004478C0, Moho::CD3DBatchTexture::FromSolidColor)
   *
   * What it does:
   * Returns one cached shared batch-texture handle for a solid RGBA color,
   * creating/inserting a `CD3DSolidBatchTexture` instance on cache miss.
   */
  boost::shared_ptr<CD3DBatchTexture> CD3DBatchTexture::FromSolidColor(const std::uint32_t rgba)
  {
    boost::mutex::scoped_lock scopedLock(sResourceLock);
    (void)InitializeSolidTextureMapStorage();

    SolidTextureMap& solidTextureMap = GetSolidTextureMap();
    boost::shared_ptr<CD3DBatchTexture> outTexture;
    SolidTextureMap::iterator it = FindSolidTextureEntry(rgba);
    if (it != SolidTextureMapEnd()) {
      outTexture = LockSolidTextureWeakHandle(it->second);
    }

    if (!outTexture) {
      const SolidTextureHandle createdTexture = BuildSolidTextureSharedHandle(new CD3DSolidBatchTexture(rgba));
      const SolidTextureMap::iterator hint = FindSolidTextureInsertHint(rgba);
      if (hint != SolidTextureMapEnd() && hint->first == rgba) {
        hint->second = createdTexture;
      } else {
        solidTextureMap.insert(hint, SolidTextureMap::value_type(rgba, createdTexture));
      }
      outTexture = createdTexture;
    }

    return outTexture;
  }
} // namespace moho

namespace
{
  struct SolidBatchTextureCacheBootstrap
  {
    SolidBatchTextureCacheBootstrap()
    {
      moho::register_sSolidTextureMap();
    }
  };

  SolidBatchTextureCacheBootstrap gSolidBatchTextureCacheBootstrap;
} // namespace
