#include "CD3DFont.h"

#include <array>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/DXTCodec.h"

namespace moho
{
  namespace
  {
    struct FontLookup
    {
      std::int32_t mPointSize = 0;
      std::string mFace{};
    };

    struct FontLookupLess
    {
      /**
       * Address: 0x004271D0 (FUN_004271D0, Moho::FontInfo::cmp)
       *
       * What it does:
       * Orders font-cache lookup keys by point-size first, then face-name bytes.
       */
      [[nodiscard]] bool operator()(const FontLookup& lhs, const FontLookup& rhs) const noexcept
      {
        if (lhs.mPointSize != rhs.mPointSize) {
          return lhs.mPointSize < rhs.mPointSize;
        }
        return lhs.mFace < rhs.mFace;
      }
    };

    using FontCacheMap = std::map<FontLookup, CD3DFont*, FontLookupLess>;
    struct DxtWordPair
    {
      std::uint32_t mLo = 0;
      std::uint32_t mHi = 0;
    };

    using DxtWordPairVector = std::vector<DxtWordPair>;
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntryChecked(FontCacheMap& cache, const FontLookup& lookup, CD3DFont* font);
    [[nodiscard]] constexpr std::size_t GetDxtWordPairMaxCount() noexcept;
    [[noreturn]] void ThrowVectorTooLong();

    /**
     * Address: 0x004251C0 (FUN_004251C0)
     *
     * What it does:
     * Builds one font-cache lookup key from point-size and face-name text.
     */
    [[nodiscard]] FontLookup MakeFontLookup(const std::int32_t pointSize, const char* const faceName)
    {
      FontLookup lookup{};
      lookup.mPointSize = pointSize;
      lookup.mFace = (faceName != nullptr) ? faceName : "";
      return lookup;
    }

    /**
     * Address: 0x00426A50 (FUN_00426A50)
     *
     * What it does:
     * Releases one intrusive `CD3DFont` owner lane and clears on last-owner.
     */
    void ReleaseIntrusiveFont(CD3DFont* const font) noexcept
    {
      if (font == nullptr) {
        return;
      }

      --font->mRefCount;
      if (font->mRefCount == 0) {
        font->Release(1);
      }
    }

    /**
     * Address: 0x00425490 (FUN_00425490)
     *
     * What it does:
     * Releases one font-cache entry payload (intrusive CD3DFont reference) and
     * resets the stored pointer lane.
     */
    void ReleaseFontCacheEntry(CD3DFont*& font) noexcept
    {
      ReleaseIntrusiveFont(font);
      font = nullptr;
    }

    /**
     * Address: 0x00427C20 (FUN_00427C20)
     * Address: 0x00428780 (FUN_00428780)
     * Address: 0x00428C00 (FUN_00428C00)
     * Address: 0x00428CC0 (FUN_00428CC0)
     *
     * What it does:
     * Returns the process-static D3D font-cache map singleton.
     */
    [[nodiscard]] FontCacheMap& GetFontCache() noexcept
    {
      static FontCacheMap sD3DFontMap{};
      return sD3DFontMap;
    }

    /**
     * Address: 0x004268F0 (FUN_004268F0)
     *
     * What it does:
     * Returns the end/sentinel iterator for the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheEnd() noexcept
    {
      return GetFontCache().end();
    }

    /**
     * Address: 0x00427AD0 (FUN_00427AD0)
     *
     * What it does:
     * Returns the map head/sentinel lane represented as `end()`.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheHead() noexcept
    {
      return GetFontCacheEnd();
    }

    /**
     * Address: 0x00426F60 (FUN_00426F60)
     *
     * What it does:
     * Returns the begin/leftmost iterator for the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheBegin() noexcept
    {
      return GetFontCache().begin();
    }

    /**
     * Address: 0x00427A70 (FUN_00427A70, std::map_FontLookup_CD3DFont::_Lbound)
     *
     * What it does:
     * Returns lower-bound iterator for one font-cache lookup key.
     */
    [[nodiscard]] FontCacheMap::iterator LowerBoundCachedFont(const FontLookup& lookup)
    {
      return GetFontCache().lower_bound(lookup);
    }

    /**
     * Address: 0x004269E0 (FUN_004269E0, std::map_FontLookup_CD3DFont::find)
     *
     * What it does:
     * Performs key lookup in the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator FindCachedFont(const FontLookup& lookup)
    {
      FontCacheMap& cache = GetFontCache();
      const auto lowerBound = LowerBoundCachedFont(lookup);
      if (lowerBound == cache.end()) {
        return lowerBound;
      }

      const FontLookupLess less{};
      if (less(lookup, lowerBound->first) || less(lowerBound->first, lookup)) {
        return cache.end();
      }

      return lowerBound;
    }

    /**
     * Address: 0x00426900 (FUN_00426900)
     *
     * What it does:
     * Inserts one key/value record in the static font-cache map when missing and
     * reports iterator + insertion status.
     */
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntry(const FontLookup& lookup, CD3DFont* const font)
    {
      FontCacheMap& cache = GetFontCache();
      return InsertFontCacheEntryChecked(cache, lookup, font);
    }

    /**
     * Address: 0x00426F80 (FUN_00426F80)
     *
     * What it does:
     * Inserts one cache record with map-size guard semantics.
     */
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntryChecked(FontCacheMap& cache, const FontLookup& lookup, CD3DFont* const font)
    {
      constexpr std::size_t kMaxMapSize = 0x071C71C6u;
      if (cache.size() >= kMaxMapSize) {
        throw std::length_error("map/set<T> too long");
      }

      return cache.emplace(lookup, font);
    }

    /**
     * Address: 0x00426CE0 (FUN_00426CE0)
     * Address: 0x00429140 (FUN_00429140)
     * Address: 0x00429500 (FUN_00429500)
     *
     * What it does:
     * Initializes glyph-page storage with 256 page slots.
     */
    void InitializeGlyphPageCache(CD3DFont::SCharInfoPages& pages)
    {
      pages = CD3DFont::SCharInfoPages(256);
    }

    /**
     * Address: 0x004283E0 (FUN_004283E0)
     *
     * What it does:
     * Tail-thunk adapter that forwards one glyph-page cache init lane into
     * `FUN_00429140`.
     */
    [[maybe_unused]] void InitializeGlyphPageCacheThunk(CD3DFont::SCharInfoPages& pages)
    {
      InitializeGlyphPageCache(pages);
    }

    /**
     * Address: 0x00426D70 (FUN_00426D70)
     * Address: 0x004294B0 (FUN_004294B0)
     * Address: 0x004298C0 (FUN_004298C0)
     * Address: 0x00429A20 (FUN_00429A20)
     *
     * What it does:
     * Clears glyph-page storage and releases owned page vectors.
     */
    void DestroyGlyphPageCache(CD3DFont::SCharInfoPages& pages)
    {
      pages = CD3DFont::SCharInfoPages{};
    }

    /**
     * Address: 0x00426C60 (FUN_00426C60)
     *
     * What it does:
     * Returns begin pointer for one kerning-pair vector storage lane.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairsBegin(CD3DFont::KerningPairVector& pairs)
    {
      return pairs.begin();
    }

    /**
     * Address: 0x00426810 (FUN_00426810)
     *
     * What it does:
     * Returns end pointer for one kerning-pair vector storage lane.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairsEnd(CD3DFont::KerningPairVector& pairs)
    {
      return pairs.end();
    }

    /**
     * Address: 0x00426860 (FUN_00426860)
     * Address: 0x00426B50 (FUN_00426B50)
     *
     * What it does:
     * Computes element pointer for one indexed kerning-pair slot.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairAt(CD3DFont::SKerningPair* const begin, const std::size_t index)
    {
      return begin + index;
    }

    /**
     * Address: 0x00426BF0 (FUN_00426BF0)
     *
     * What it does:
     * Computes element pointer for one indexed glyph-info slot.
     */
    [[nodiscard]] CD3DFont::SCharInfo* GetGlyphInfoAt(CD3DFont::SCharInfo* const begin, const std::size_t index)
    {
      return begin + index;
    }

    /**
     * Address: 0x00426DD0 (FUN_00426DD0)
     *
     * What it does:
     * Resizes kerning-pair storage to requested element count.
     */
    void ResizeKerningPairStorage(
      CD3DFont::KerningPairVector& pairs, const std::size_t requestedCount, const CD3DFont::SKerningPair& fillValue
    )
    {
      pairs.resize(requestedCount, fillValue);
    }

    /**
     * Address: 0x00426820 (FUN_00426820)
     *
     * What it does:
     * Resizes kerning-pair storage with zero/default fill elements.
     */
    void ResizeKerningPairStorageZeroFill(CD3DFont::KerningPairVector& pairs, const std::size_t requestedCount)
    {
      const CD3DFont::SKerningPair fill{};
      ResizeKerningPairStorage(pairs, requestedCount, fill);
    }

    /**
     * Address: 0x00427270 (FUN_00427270)
     * Address: 0x00427C90 (FUN_00427C90)
     * Address: 0x00429210 (FUN_00429210)
     * Address: 0x00429670 (FUN_00429670)
     * Address: 0x004298A0 (FUN_004298A0)
     * Address: 0x0042A6F0 (FUN_0042A6F0)
     *
     * What it does:
     * Initializes one kerning-pair buffer to requested count + fill value.
     */
    [[nodiscard]] bool InitKerningPairBuffer(
      const std::size_t count, CD3DFont::KerningPairVector& out, const CD3DFont::SKerningPair& fillValue
    )
    {
      out = CD3DFont::KerningPairVector{};
      if (count == 0u) {
        return false;
      }

      if (count > GetDxtWordPairMaxCount()) {
        ThrowVectorTooLong();
      }

      const CD3DFont::SKerningPair zero{};
      if (fillValue.mLeft == zero.mLeft && fillValue.mRight == zero.mRight && fillValue.mAmount == zero.mAmount) {
        ResizeKerningPairStorageZeroFill(out, count);
      }
      else {
        ResizeKerningPairStorage(out, count, fillValue);
      }
      return true;
    }

    /**
     * Address: 0x00426B00 (FUN_00426B00)
     *
     * What it does:
     * Initializes one kerning-pair buffer to requested count with zero fill.
     */
    void InitKerningPairBufferZeroFill(const std::size_t count, CD3DFont::KerningPairVector& out)
    {
      const CD3DFont::SKerningPair fill{};
      (void)InitKerningPairBuffer(count, out, fill);
    }

    /**
     * Address: 0x004272F0 (FUN_004272F0)
     *
     * What it does:
     * Releases kerning-pair storage and resets vector lanes to empty.
     */
    void ResetKerningPairBuffer(CD3DFont::KerningPairVector& pairs)
    {
      pairs = CD3DFont::KerningPairVector{};
    }

    /**
     * Address: 0x00427490 (FUN_00427490)
     *
     * What it does:
     * Returns current glyph-entry count for one glyph page.
     */
    [[nodiscard]] std::size_t GetGlyphPageEntryCount(const CD3DFont::SCharInfoPage& page) noexcept
    {
      return page.size();
    }

    /**
     * Address: 0x00427980 (FUN_00427980)
     * Address: 0x00428790 (FUN_00428790)
     * Address: 0x00428900 (FUN_00428900)
     * Address: 0x00428C70 (FUN_00428C70)
     *
     * What it does:
     * Returns the allocator max-count constant for 0x24-byte glyph entries.
     */
    [[nodiscard]] constexpr std::size_t GetGlyphPageMaxCount() noexcept
    {
      return 0x071C71C7u;
    }

    /**
     * Address: 0x004273A0 (FUN_004273A0)
     * Address: 0x00427D80 (FUN_00427D80)
     * Address: 0x00427E70 (FUN_00427E70)
     * Address: 0x00428930 (FUN_00428930)
     * Address: 0x004292A0 (FUN_004292A0)
     * Address: 0x004296B0 (FUN_004296B0)
     * Address: 0x00429780 (FUN_00429780)
     * Address: 0x00429910 (FUN_00429910)
     * Address: 0x00429E90 (FUN_00429E90)
     * Address: 0x0042A710 (FUN_0042A710)
     * Address: 0x0042A960 (FUN_0042A960)
     *
     * What it does:
     * Normalizes one glyph page to exactly 256 entries, appending fill records
     * or trimming trailing records as needed.
     */
    void NormalizeGlyphPageTo256(
      CD3DFont::SCharInfoPage& page, const CD3DFont::SCharInfo& fillValue
    )
    {
      constexpr std::size_t kGlyphEntriesPerPage = 256u;
      if (kGlyphEntriesPerPage > GetGlyphPageMaxCount()) {
        throw std::length_error("vector<T> too long");
      }

      const std::size_t count = GetGlyphPageEntryCount(page);
      if (count < kGlyphEntriesPerPage) {
        page.resize(kGlyphEntriesPerPage, fillValue);
      }
      else if (count > kGlyphEntriesPerPage) {
        page.erase(page.begin() + static_cast<std::ptrdiff_t>(kGlyphEntriesPerPage), page.end());
      }
    }

    /**
     * Address: 0x00426B60 (FUN_00426B60)
     *
     * What it does:
     * Normalizes one glyph page to 256 entries using zero/default glyph fill.
     */
    void NormalizeGlyphPageTo256ZeroFill(CD3DFont::SCharInfoPage& page)
    {
      const CD3DFont::SCharInfo fill{};
      NormalizeGlyphPageTo256(page, fill);
    }

    /**
     * Address: 0x004275F0 (FUN_004275F0)
     * Address: 0x00428C80 (FUN_00428C80)
     * Address: 0x00428430 (FUN_00428430)
     * Address: 0x00428820 (FUN_00428820)
     * Address: 0x00428A10 (FUN_00428A10)
     * Address: 0x00428C40 (FUN_00428C40)
     *
     * What it does:
     * Returns the allocator max-count constant for 8-byte word-pair lanes.
     */
    [[nodiscard]] constexpr std::size_t GetDxtWordPairMaxCount() noexcept
    {
      return 0x1FFFFFFFu;
    }

    /**
     * Address: 0x004278A0 (FUN_004278A0)
     * Address: 0x00428370 (FUN_00428370)
     * Address: 0x00428830 (FUN_00428830)
     * Address: 0x00428960 (FUN_00428960)
     * Address: 0x00428A20 (FUN_00428A20)
     *
     * What it does:
     * Throws the legacy vector length_error used by DXT scratch growth paths.
     */
    [[noreturn]] void ThrowVectorTooLong()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x004274B0 (FUN_004274B0)
     * Address: 0x00428220 (FUN_00428220)
     * Address: 0x004292F0 (FUN_004292F0)
     *
     * What it does:
     * Resizes one DXT scratch lane as 8-byte word-pairs with fill pattern.
     */
    void ResizeDxtWordPairScratch(
      const std::size_t count, DxtWordPairVector& scratch, const DxtWordPair& fillValue
    )
    {
      if (count > GetDxtWordPairMaxCount()) {
        ThrowVectorTooLong();
      }
      scratch.assign(count, fillValue);
    }

    /**
     * Address: 0x00426C00 (FUN_00426C00)
     *
     * What it does:
     * Resizes one DXT scratch lane as zero-filled 8-byte word-pairs.
     */
    void ResizeDxtWordPairScratchZeroFill(const std::size_t count, DxtWordPairVector& scratch)
    {
      const DxtWordPair fill{};
      ResizeDxtWordPairScratch(count, scratch, fill);
    }

    /**
     * Address: 0x00427990 (FUN_00427990)
     * Address: 0x00428440 (FUN_00428440)
     * Address: 0x00428700 (FUN_00428700)
     * Address: 0x00428B80 (FUN_00428B80)
     * Address: 0x00428BC0 (FUN_00428BC0)
     * Address: 0x00428BE0 (FUN_00428BE0)
     *
     * What it does:
     * Releases intrusive font ownership payload for one map iterator range and
     * erases matching cache nodes.
     */
    void ReleaseFontCacheRange(FontCacheMap& cache, FontCacheMap::iterator begin, const FontCacheMap::iterator end)
    {
      if (begin == cache.begin() && end == GetFontCacheHead()) {
        for (auto& [lookup, cachedFont] : cache) {
          (void)lookup;
          ReleaseFontCacheEntry(cachedFont);
        }
        cache.clear();
        return;
      }

      while (begin != end) {
        ReleaseFontCacheEntry(begin->second);
        begin = cache.erase(begin);
      }
    }

    /**
     * Address: 0x00425240 (FUN_00425240)
     *
     * What it does:
     * Clears and tears down the static D3D font-cache map at process shutdown.
     */
    void ShutdownFontCache()
    {
      FontCacheMap& cache = GetFontCache();
      ReleaseFontCacheRange(cache, GetFontCacheBegin(), GetFontCacheHead());
    }

    void RegisterFontCacheTeardown()
    {
      static const bool registered = []() {
        std::atexit(ShutdownFontCache);
        return true;
      }();
      (void)registered;
    }

    [[nodiscard]] boost::SharedPtrRaw<CD3DFont> MakeFontHandle(CD3DFont* const font)
    {
      return boost::SharedPtrRaw<CD3DFont>::with_deleter(font, [](CD3DFont* const ptr) { ReleaseIntrusiveFont(ptr); });
    }

    [[nodiscard]] std::uint32_t PackKerningKey(const CD3DFont::SKerningPair& pair) noexcept
    {
      const auto left = static_cast<std::uint16_t>(pair.mLeft);
      const auto right = static_cast<std::uint16_t>(pair.mRight);
      return static_cast<std::uint32_t>(left) | (static_cast<std::uint32_t>(right) << 16u);
    }

    /**
     * Address: 0x004293B0 (FUN_004293B0)
     * Address: 0x00429AF0 (FUN_00429AF0)
     * Address: 0x00429DA0 (FUN_00429DA0)
     * Address: 0x0042A2A0 (FUN_0042A2A0)
     * Address: 0x0042A3A0 (FUN_0042A3A0)
     * Address: 0x0042A3F0 (FUN_0042A3F0)
     * Address: 0x0042A520 (FUN_0042A520)
     * Address: 0x0042A5E0 (FUN_0042A5E0)
     * Address: 0x0042A7C0 (FUN_0042A7C0)
     * Address: 0x0042A860 (FUN_0042A860)
     *
     * What it does:
     * Orders one kerning-pair lane by packed (left,right) key.
     */
    void SortKerningPairsByPackedKey(CD3DFont::KerningPairVector& pairs)
    {
      std::sort(
        GetKerningPairsBegin(pairs),
        GetKerningPairsEnd(pairs),
        [](const CD3DFont::SKerningPair& lhs, const CD3DFont::SKerningPair& rhs) {
          return PackKerningKey(lhs) < PackKerningKey(rhs);
        }
      );
    }

    /**
     * Address: 0x00429D90 (FUN_00429D90)
     *
     * What it does:
     * Tail-thunk adapter that forwards one kerning-pair sort lane into
     * `FUN_0042A3F0`.
     */
    [[maybe_unused]] void SortKerningPairsByPackedKeyThunk(CD3DFont::KerningPairVector& pairs)
    {
      SortKerningPairsByPackedKey(pairs);
    }
  } // namespace

  /**
   * Address: 0x00425290 (FUN_00425290, ?Create@CD3DFont@Moho@@SA?AV?$CountedPtr@VCD3DFont@Moho@@@2@HVStrArg@gpg@@@Z)
   *
   * What it does:
   * Looks up or creates one cached D3D font object for point-size + face-name.
   */
  boost::SharedPtrRaw<CD3DFont> CD3DFont::Create(const std::int32_t pointSize, const gpg::StrArg faceName)
  {
    RegisterFontCacheTeardown();

    const FontLookup lookup = MakeFontLookup(pointSize, faceName);
    const auto existingIt = FindCachedFont(lookup);
    if (existingIt != GetFontCacheEnd()) {
      CD3DFont* const existingFont = existingIt->second;
      if (existingFont != nullptr) {
        ++existingFont->mRefCount;
      }
      return MakeFontHandle(existingFont);
    }

    const HFONT createdWin32Font = CreateFontA(-pointSize, 0, 0, 0, 0, 0, 0, 0, 1u, 0, 0, 4u, 0, lookup.mFace.c_str());
    if (createdWin32Font == nullptr) {
      return {};
    }

    CD3DFont* const createdFont = new (std::nothrow) CD3DFont(createdWin32Font);
    if (createdFont == nullptr) {
      DeleteObject(createdWin32Font);
      return {};
    }

    ++createdFont->mRefCount; // cache-owned reference
    const auto [insertedIt, inserted] = InsertFontCacheEntry(lookup, createdFont);
    if (!inserted) {
      ReleaseIntrusiveFont(createdFont);
      CD3DFont* const racedFont = insertedIt->second;
      if (racedFont != nullptr) {
        ++racedFont->mRefCount;
      }
      return MakeFontHandle(racedFont);
    }

    ++createdFont->mRefCount; // returned-handle reference
    return MakeFontHandle(createdFont);
  }

  /**
   * Address: 0x00425500 (FUN_00425500, ??0CD3DFont@Moho@@AAE@PAX@Z)
   *
   * What it does:
   * Initializes D3D font metrics, glyph-page cache lanes, and kerning pairs
   * from one Win32 font handle.
   */
  CD3DFont::CD3DFont(const HFONT font)
    : CountedObject()
    , mFont(font)
    , mIsTruetype(false)
    , mPad0D{}
    , mHeight(0.0f)
    , mAscent(0.0f)
    , mDescent(0.0f)
    , mInternalLeading(0.0f)
    , mExternalLeading(0.0f)
    , mAveCharWidth(0.0f)
    , mOverhang(0.0f)
    , mCharInfo()
    , mKerningPairs()
    , mDeviceContext(nullptr)
    , mBitmap(nullptr)
  {
    InitializeGlyphPageCache(mCharInfo);

    mDeviceContext = CreateCompatibleDC(nullptr);
    if (mDeviceContext == nullptr) {
      return;
    }

    mBitmap = CreateBitmap(128, 128, 1u, 0x20u, nullptr);
    SelectObject(mDeviceContext, mBitmap);
    SelectObject(mDeviceContext, mFont);

    TEXTMETRICW metrics{};
    GetTextMetricsW(mDeviceContext, &metrics);

    mHeight = static_cast<float>(metrics.tmHeight);
    mAscent = static_cast<float>(metrics.tmAscent);
    mDescent = static_cast<float>(metrics.tmDescent);
    mInternalLeading = static_cast<float>(metrics.tmInternalLeading);
    mExternalLeading = static_cast<float>(metrics.tmExternalLeading);
    mAveCharWidth = static_cast<float>(metrics.tmAveCharWidth);
    mOverhang = static_cast<float>(metrics.tmOverhang);
    mIsTruetype = (metrics.tmPitchAndFamily & TMPF_TRUETYPE) != 0;

    const int kerningPairCount = GetKerningPairsW(mDeviceContext, 0, nullptr);
    if (kerningPairCount <= 0) {
      return;
    }

    std::vector<KERNINGPAIR> kerningPairs(static_cast<std::size_t>(kerningPairCount));
    GetKerningPairsW(mDeviceContext, static_cast<DWORD>(kerningPairCount), kerningPairs.data());

    InitKerningPairBufferZeroFill(static_cast<std::size_t>(kerningPairCount), mKerningPairs);
    SKerningPair* const kerningPairBegin = GetKerningPairsBegin(mKerningPairs);
    for (std::size_t index = 0; index < kerningPairs.size(); ++index) {
      const KERNINGPAIR& source = kerningPairs[index];
      SKerningPair& dest = *GetKerningPairAt(kerningPairBegin, index);
      dest.mLeft = source.wFirst;
      dest.mRight = source.wSecond;
      dest.mAmount = static_cast<float>(source.iKernAmount);
    }

    SortKerningPairsByPackedKey(mKerningPairs);
  }

  /**
   * Address: 0x00425840 (FUN_00425840, Moho::CD3DFont::dtr)
   *
   * What it does:
   * Executes the scalar-deleting-dtor thunk path used by intrusive release
   * callsites.
   */
  CD3DFont* CD3DFont::Release(const std::int32_t destroyNow)
  {
    this->~CD3DFont();
    if ((destroyNow & 1) != 0) {
      ::operator delete(this);
    }
    return this;
  }

  /**
   * Address: 0x00425860 (FUN_00425860, ??1CD3DFont@Moho@@UAE@XZ)
   *
   * What it does:
   * Releases Win32 font/DC/bitmap resources and tears down glyph + kerning
   * container ownership lanes.
   */
  CD3DFont::~CD3DFont()
  {
    ResetKerningPairBuffer(mKerningPairs);
    DestroyGlyphPageCache(mCharInfo);

    if (mFont != nullptr) {
      DeleteObject(mFont);
      mFont = nullptr;
    }

    if (mBitmap != nullptr) {
      DeleteObject(mBitmap);
      mBitmap = nullptr;
    }

    if (mDeviceContext != nullptr) {
      DeleteObject(mDeviceContext);
      mDeviceContext = nullptr;
    }
  }

  /**
   * Address: 0x00425940 (FUN_00425940, ?GetCharInfo@CD3DFont@Moho@@QAEABUSCharInfo@12@_W@Z)
   *
   * What it does:
   * Returns cached glyph metrics/texture info for one UTF-16 codepoint,
   * building the glyph page/atlas data on first use.
   */
  const CD3DFont::SCharInfo& CD3DFont::GetCharInfo(const wchar_t chText)
  {
    constexpr int kGlyphScratchWidth = 128;
    constexpr int kGlyphScratchHeight = 128;
    constexpr std::uint32_t kDxtOpaqueColorBlock = 0x000000000000FFFFull;

    const std::uint8_t pageIndex = static_cast<std::uint8_t>((static_cast<std::uint16_t>(chText) >> 8u) & 0xFFu);
    SCharInfoPage& page = mCharInfo[pageIndex];
    if (page.size() != 256u) {
      NormalizeGlyphPageTo256ZeroFill(page);
    }

    SCharInfo& charInfo = page[static_cast<std::uint8_t>(chText & 0xFFu)];
    if (charInfo.mTex || mDeviceContext == nullptr) {
      return charInfo;
    }

    (void)SetTextAlign(mDeviceContext, 0x18u);
    const int baselineAscent = static_cast<int>(std::ceil(mAscent + 1.0f));
    const int baselineDescent = static_cast<int>(std::ceil(mDescent));

    RECT textRect{};
    (void)DrawTextW(mDeviceContext, &chText, 1, &textRect, 0xC20u);
    const float advance = static_cast<float>(textRect.right - textRect.left);

    int glyphWidth = (static_cast<int>((mAveCharWidth * 2.0f) + advance) + 3) & ~3;
    int glyphHeight = (baselineAscent + baselineDescent + 4) & ~3;
    const int baselineX = static_cast<int>(mAveCharWidth);

    if (glyphWidth > kGlyphScratchWidth) {
      gpg::Warnf("Clamping character u+%04x to MAX_CHAR_WIDTH", static_cast<unsigned int>(chText));
      glyphWidth = kGlyphScratchWidth;
    }
    if (glyphHeight > kGlyphScratchHeight) {
      gpg::Warnf("Clamping character u+%04x to MAX_CHAR_HEIGHT", static_cast<unsigned int>(chText));
      glyphHeight = kGlyphScratchHeight;
    }

    RECT clearRect{};
    clearRect.right = glyphWidth + 4;
    clearRect.bottom = glyphHeight + 4;
    (void)FillRect(mDeviceContext, &clearRect, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    (void)SetBkColor(mDeviceContext, RGB(0, 0, 0));
    (void)SetTextColor(mDeviceContext, RGB(255, 255, 255));

    RECT drawRect{};
    drawRect.left = baselineX;
    drawRect.right = baselineX;
    drawRect.top = baselineAscent;
    drawRect.bottom = baselineAscent;
    (void)DrawTextW(mDeviceContext, &chText, 1, &drawRect, 0x920u);

    std::array<COLORREF, static_cast<std::size_t>(kGlyphScratchWidth * kGlyphScratchHeight)> pixels{};
    const int sampleWidth = (std::min)(glyphWidth + 4, kGlyphScratchWidth);
    const int sampleHeight = (std::min)(glyphHeight + 4, kGlyphScratchHeight);
    for (int y = 0; y < sampleHeight; ++y) {
      for (int x = 0; x < sampleWidth; ++x) {
        pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] = GetPixel(mDeviceContext, x, y);
      }
    }

    auto isColumnBlack = [&pixels](const int x, const int yMin, const int yMaxExclusive) noexcept {
      for (int y = yMin; y < yMaxExclusive; ++y) {
        if (pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] != 0u) {
          return false;
        }
      }
      return true;
    };
    auto isRowBlack = [&pixels](const int y, const int xMin, const int xMaxExclusive) noexcept {
      for (int x = xMin; x < xMaxExclusive; ++x) {
        if (pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] != 0u) {
          return false;
        }
      }
      return true;
    };

    if (!isRowBlack(0, 0, glyphWidth)) {
      gpg::Warnf("Top edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
    }
    if (!isColumnBlack(0, 0, glyphHeight)) {
      gpg::Warnf("Left edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
    }
    {
      const int rightEdgeX = (std::min)(glyphWidth + 1, kGlyphScratchWidth - 1);
      if (!isColumnBlack(rightEdgeX, 0, glyphHeight)) {
        gpg::Warnf("Right edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
      }
    }
    {
      const int bottomEdgeY = (std::min)(glyphHeight, kGlyphScratchHeight - 1);
      if (!isRowBlack(bottomEdgeY, 0, glyphWidth)) {
        gpg::Warnf("Bottom edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
      }
    }

    int xMin = 0;
    for (int x = 1; x < glyphWidth; ++x) {
      if (isColumnBlack(x, 0, glyphHeight)) {
        ++xMin;
      } else {
        break;
      }
    }

    int xMaxExclusive = glyphWidth;
    while (xMaxExclusive > 1) {
      const int sampleX = (std::min)(xMaxExclusive, kGlyphScratchWidth - 1);
      if (!isColumnBlack(sampleX, 0, glyphHeight)) {
        break;
      }
      --xMaxExclusive;
    }
    if (xMaxExclusive <= xMin) {
      xMaxExclusive = xMin + 1;
    }

    int blockWidth = (xMaxExclusive - xMin + 3) & ~3;
    if (blockWidth <= 0) {
      blockWidth = 4;
      xMin = 0;
    }
    if (xMin + blockWidth > kGlyphScratchWidth) {
      blockWidth = ((kGlyphScratchWidth - xMin) & ~3);
      if (blockWidth <= 0) {
        xMin = 0;
        blockWidth = kGlyphScratchWidth & ~3;
      }
    }

    int yMin = 0;
    int yMaxExclusive = glyphHeight;
    while (yMaxExclusive > 1) {
      if (!isRowBlack(yMaxExclusive - 1, xMin, xMin + blockWidth)) {
        break;
      }
      --yMaxExclusive;
    }
    while ((yMin + 1) < yMaxExclusive) {
      if (!isRowBlack(yMin + 1, xMin, xMin + blockWidth)) {
        break;
      }
      ++yMin;
    }

    int blockHeight = (yMaxExclusive - yMin + 3) & ~3;
    if (blockHeight <= 0) {
      blockHeight = 4;
      yMin = 0;
    }
    if (yMin + blockHeight > kGlyphScratchHeight) {
      blockHeight = ((kGlyphScratchHeight - yMin) & ~3);
      if (blockHeight <= 0) {
        yMin = 0;
        blockHeight = kGlyphScratchHeight & ~3;
      }
    }

    const std::uint32_t blockCount = static_cast<std::uint32_t>((blockWidth / 4) * (blockHeight / 4));
    std::vector<std::uint64_t> dxt5Blocks;
    dxt5Blocks.reserve(static_cast<std::size_t>(blockCount) * 2u);

    for (int y = yMin; y < (yMin + blockHeight); y += 4) {
      for (int x = xMin; x < (xMin + blockWidth); x += 4) {
        const auto* const source = reinterpret_cast<const std::uint8_t*>(
          &pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)]
        );
        dxt5Blocks.push_back(DXT_EncodeAlphaBlock(source, static_cast<int>(sizeof(COLORREF)), kGlyphScratchWidth * 4));
        dxt5Blocks.push_back(kDxtOpaqueColorBlock);
      }
    }

    const std::uint32_t sourcePitchBytes = static_cast<std::uint32_t>(16u * (static_cast<std::uint32_t>(blockWidth) / 4u));
    charInfo.mTex = CD3DBatchTexture::FromDXT5(
      static_cast<std::uint32_t>(blockWidth),
      static_cast<std::uint32_t>(blockHeight),
      dxt5Blocks.data(),
      sourcePitchBytes
    );

    charInfo.mV2 = static_cast<float>(xMin - baselineX);
    charInfo.mV3 = static_cast<float>(baselineAscent - (yMin + blockHeight));
    charInfo.mV4 = static_cast<float>((xMin + blockWidth) - baselineX);
    charInfo.mV5 = static_cast<float>(baselineAscent - yMin);
    charInfo.mAdvance = advance;
    return charInfo;
  }

  /**
   * Address: 0x00426470 (FUN_00426470, ?Render@CD3DFont@Moho@@QAE?AV?$Vector3@M@Wm3@@VStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV34@22IMM@Z)
   *
   * What it does:
   * Draws one UTF-8 string along caller-provided axis vectors and returns the
   * final pen position.
   */
  Vector3f CD3DFont::Render(
    const gpg::StrArg text,
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& origin,
    const Vector3f& xAxis,
    const Vector3f& yAxis,
    const std::uint32_t color,
    const float glyphScale,
    const float maxAdvance
  )
  {
    Vector3f cursor = origin;
    float totalAdvance = 0.0f;

    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      const SCharInfo& charInfo = GetCharInfo(codepoint);
      totalAdvance += charInfo.mAdvance;
      if (std::isfinite(maxAdvance) && totalAdvance > maxAdvance) {
        break;
      }

      primBatcher->DrawChar(xAxis, yAxis, charInfo, cursor, color);

      cursor.x += xAxis.x * charInfo.mAdvance;
      cursor.y += xAxis.y * charInfo.mAdvance;
      cursor.z += xAxis.z * charInfo.mAdvance;

      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }

    (void)glyphScale;
    return cursor;
  }

  /**
   * Address: 0x00426580 (FUN_00426580, ?Render2D@CD3DFont@Moho@@QAEXVStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV?$Vector2@M@Wm3@@IMM@Z)
   *
   * What it does:
   * Projects one 2D text draw into 3D render space and dispatches to
   * `Render(...)` with screen-space axes.
   */
  void CD3DFont::Render2D(
    const gpg::StrArg text,
    CD3DPrimBatcher* const primBatcher,
    const Wm3::Vector2f& origin,
    const std::uint32_t color,
    const float glyphScale,
    const float /*maxAdvance*/
  )
  {
    const Vector3f origin3D{origin.x, origin.y, 0.0f};
    const Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Vector3f yAxis{0.0f, -1.0f, 0.0f};
    (void)Render(
      text,
      primBatcher,
      origin3D,
      xAxis,
      yAxis,
      color,
      glyphScale,
      std::numeric_limits<float>::quiet_NaN()
    );
  }

  /**
   * Address: 0x00426610 (FUN_00426610, ?GetAdvance@CD3DFont@Moho@@QAEMVStrArg@gpg@@H@Z)
   *
   * What it does:
   * Returns cumulative glyph advance for one UTF-8 string.
   */
  float CD3DFont::GetAdvance(const gpg::StrArg text, const std::int32_t /*flags*/)
  {
    float advance = 0.0f;
    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      advance += GetCharInfo(codepoint).mAdvance;
      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }
    return advance;
  }

  /**
   * Address: 0x00426680 (FUN_00426680, ?GetNearestCharacterIndex@CD3DFont@Moho@@QAEHVStrArg@gpg@@M@Z)
   *
   * What it does:
   * Returns the UTF-8 character index closest to the caller-provided advance.
   */
  std::int32_t CD3DFont::GetNearestCharacterIndex(const gpg::StrArg text, const float targetAdvance)
  {
    std::int32_t index = 0;
    float cumulativeAdvance = 0.0f;

    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      cumulativeAdvance += GetCharInfo(codepoint).mAdvance;
      if (cumulativeAdvance > targetAdvance) {
        break;
      }

      ++index;
      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }
    return index;
  }

  /**
   * Address: 0x00BC3C50 (FUN_00BC3C50, register_sD3DFontMap)
   *
   * What it does:
   * Materializes the process D3D font-cache map during startup.
   */
  void RegisterD3DFontCacheMapStartup()
  {
    (void)GetFontCache();
  }
} // namespace moho

namespace
{
  struct CD3DFontStartupRegistrations
  {
    CD3DFontStartupRegistrations()
    {
      moho::RegisterD3DFontCacheMapStartup();
    }
  };

  [[maybe_unused]] CD3DFontStartupRegistrations gCD3DFontStartupRegistrations;
} // namespace
