#include "CAnimTexture.h"

#include <cmath>
#include <map>
#include <stdexcept>
#include <string>

namespace
{
  using AnimTextureCacheMap = std::map<std::string, moho::CAnimTexture*>;

  /**
   * Address: 0x004246C0 (FUN_004246C0)
   * Address: 0x00424B20 (FUN_00424B20)
   * Address: 0x004248D0 (FUN_004248D0)
   * Address: 0x00424A00 (FUN_00424A00)
   *
   * What it does:
   * Returns the process-wide animation-texture cache registry.
   */
  [[nodiscard]] AnimTextureCacheMap* AnimTextureCacheRegistry()
  {
    static AnimTextureCacheMap cache;
    return &cache;
  }

  [[nodiscard]] std::int32_t FloorToIndex(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  /**
   * Address: 0x00423E80 (FUN_00423E80)
   * Address: 0x00424780 (FUN_00424780)
   *
   * What it does:
   * Returns the legacy vector growth cap used by frame-reference storage.
   */
  [[nodiscard]] std::size_t MaxAnimTextureFrameCount() noexcept
  {
    return 0x1FFFFFFFu;
  }

  /**
   * Address: 0x00424790 (FUN_00424790)
   * Address: 0x00424A10 (FUN_00424A10)
   *
   * What it does:
   * Returns the legacy tree node-count growth cap for map/set internals.
   */
  [[nodiscard]] std::size_t MaxAnimTextureCacheNodeCount() noexcept
  {
    return 0x07FFFFFFu;
  }

  [[noreturn]] void ThrowAnimTextureCacheTooLong()
  {
    throw std::length_error("map/set<T> too long");
  }

  /**
   * Address: 0x004241C0 (FUN_004241C0)
   *
   * What it does:
   * Throws the same length-error lane used by legacy vector growth paths when
   * frame storage would exceed the hard cap.
   */
  [[noreturn]] void ThrowAnimTextureFrameVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x00422940 (FUN_00422940)
   *
   * What it does:
   * Computes `value mod range` with the same positive-wrap behavior used by
   * animation frame sampling paths.
   */
  [[nodiscard]] float WrapPositiveModulo(const float value, const float range) noexcept
  {
    if (range == 0.0f) {
      return 0.0f;
    }

    float wrapped = std::fmod(value, range);
    if ((wrapped < 0.0f) != (range < 0.0f)) {
      wrapped += range;
    }
    return wrapped;
  }

  [[nodiscard]] std::string ToCacheKey(const msvc8::string& value)
  {
    return std::string(value.data(), value.size());
  }

  [[nodiscard]] AnimTextureCacheMap& AnimTextureCache()
  {
    return *AnimTextureCacheRegistry();
  }

  /**
   * Address: 0x00423C50 (FUN_00423C50)
   *
   * What it does:
   * Returns the map head/sentinel lane represented by `end()`.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator AnimTextureCacheHead(AnimTextureCacheMap& cache)
  {
    return cache.end();
  }

  /**
   * Address: 0x00424290 (FUN_00424290)
   *
   * What it does:
   * Returns the first map node lane represented by `begin()`.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator AnimTextureCacheBegin(AnimTextureCacheMap& cache)
  {
    return cache.begin();
  }

  /**
   * Address: 0x00424910 (FUN_00424910)
   *
   * What it does:
   * Advances one cache iterator to its in-order successor when not at head.
   */
  void AdvanceAnimTextureCacheIterator(
    const AnimTextureCacheMap& cache, AnimTextureCacheMap::iterator& cursor
  )
  {
    if (cursor != cache.end()) {
      ++cursor;
    }
  }

  /**
   * Address: 0x004242A0 (FUN_004242A0)
   *
   * What it does:
   * Returns the current cache entry count.
   */
  [[nodiscard]] std::size_t AnimTextureCacheSize(const AnimTextureCacheMap& cache)
  {
    return cache.size();
  }

  /**
   * Address: 0x004249A0 (FUN_004249A0)
   *
   * What it does:
   * Clears all cached animation-texture nodes and owned key/value storage.
   */
  void ClearAnimTextureCacheNodes(AnimTextureCacheMap& cache)
  {
    cache.clear();
  }

  /**
   * Address: 0x004247A0 (FUN_004247A0)
   *
   * What it does:
   * Resets the animation-texture map to an empty sentinel-only state.
   */
  void ResetAnimTextureCacheStorage(AnimTextureCacheMap& cache)
  {
    ClearAnimTextureCacheNodes(cache);
  }

  /**
   * Address: 0x00423A00 (FUN_00423A00)
   *
   * What it does:
   * Compares two cache keys with the same strict-weak ordering used by map
   * insertion/find lanes.
   */
  [[nodiscard]] bool IsAnimTextureCacheKeyLess(const std::string& lhs, const std::string& rhs)
  {
    return lhs < rhs;
  }

  /**
   * Address: 0x00424670 (FUN_00424670)
   *
   * What it does:
   * Finds the lower-bound node for `key` in the animation-texture cache.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator
  LowerBoundAnimTextureCacheEntry(AnimTextureCacheMap& cache, const std::string& key)
  {
    return cache.lower_bound(key);
  }

  [[nodiscard]] bool IsAnimTextureCacheExactKeyMatch(
    const std::string& key, const AnimTextureCacheMap::iterator candidate, const AnimTextureCacheMap::iterator head
  )
  {
    if (candidate == head) {
      return false;
    }

    if (IsAnimTextureCacheKeyLess(key, candidate->first)) {
      return false;
    }

    return !IsAnimTextureCacheKeyLess(candidate->first, key);
  }

  /**
   * Address: 0x004242B0 (FUN_004242B0)
   *
   * What it does:
   * Inserts one missing cache key at a lower-bound hint and returns the slot.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator InsertAnimTextureCacheEntryUnique(
    AnimTextureCacheMap& cache, const std::string& key, const AnimTextureCacheMap::iterator hint
  )
  {
    return cache.emplace_hint(hint, key, nullptr);
  }

  /**
   * Address: 0x00423AD0 (FUN_00423AD0)
   *
   * What it does:
   * Resolves the cache slot used by `operator[]`: reuses an exact key match or
   * inserts one missing key at the lower-bound position.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator
  ResolveAnimTextureCacheIndexSlot(AnimTextureCacheMap& cache, const std::string& key)
  {
    const auto head = AnimTextureCacheHead(cache);
    if (AnimTextureCacheSize(cache) >= MaxAnimTextureCacheNodeCount()) {
      ThrowAnimTextureCacheTooLong();
    }

    if (AnimTextureCacheSize(cache) == 0U) {
      return InsertAnimTextureCacheEntryUnique(cache, key, head);
    }

    const auto lower = LowerBoundAnimTextureCacheEntry(cache, key);
    if (IsAnimTextureCacheExactKeyMatch(key, lower, head)) {
      return lower;
    }

    return InsertAnimTextureCacheEntryUnique(cache, key, lower);
  }

  /**
   * Address: 0x004237C0 (FUN_004237C0)
   *
   * What it does:
   * Looks up the cache entry for a texture name with the same ordered key path as
   * the original map search.
   */
  [[nodiscard]] AnimTextureCacheMap::iterator FindAnimTextureCacheEntry(AnimTextureCacheMap& cache, const std::string& key)
  {
    const auto head = AnimTextureCacheHead(cache);
    const auto lower = LowerBoundAnimTextureCacheEntry(cache, key);
    if (!IsAnimTextureCacheExactKeyMatch(key, lower, head)) {
      return head;
    }
    return lower;
  }

  /**
   * Address: 0x004233D0 (FUN_004233D0)
   *
   * What it does:
   * Returns the cached texture slot for a name, inserting an empty entry when
   * the key is not present yet.
   */
  [[nodiscard]] moho::CAnimTexture*& EnsureAnimTextureCacheSlot(AnimTextureCacheMap& cache, const std::string& key)
  {
    auto slot = ResolveAnimTextureCacheIndexSlot(cache, key);
    return slot->second;
  }

  [[nodiscard]] moho::CAnimTexture::FrameResolver& AnimTextureResolver()
  {
    static moho::CAnimTexture::FrameResolver resolver = nullptr;
    return resolver;
  }

  [[nodiscard]] moho::CAnimTexture::FrameRef ResolveFrameTexture(const char* const textureName)
  {
    const auto resolver = AnimTextureResolver();
    if (!resolver) {
      return {};
    }

    return resolver(textureName ? textureName : "");
  }

  using AnimTextureFrameRef = moho::CAnimTexture::FrameRef;

  /**
   * Address: 0x004250E0 (FUN_004250E0)
   *
   * What it does:
   * Copies one range of frame refs into uninitialized output storage and
   * retains every copied shared-control lane.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* CopyConstructAnimTextureFrameRefRange(
    AnimTextureFrameRef* out, const AnimTextureFrameRef* begin, const AnimTextureFrameRef* end
  )
  {
    AnimTextureFrameRef* cursor = out;
    for (const AnimTextureFrameRef* it = begin; it != end; ++it, ++cursor) {
      cursor->px = it->px;
      cursor->pi = it->pi;
      if (cursor->pi != nullptr) {
        cursor->pi->add_ref_copy();
      }
    }
    return cursor;
  }

  /**
   * Address: 0x00424D90 (FUN_00424D90)
   * Address: 0x008140C0 (FUN_008140C0)
   * Address: 0x008575A0 (FUN_008575A0)
   *
   * What it does:
   * Fills `count` frame-ref slots from one source ref while retaining each copied
   * shared-control lane.
   */
  [[maybe_unused]] void FillAnimTextureFrameRefRange(
    AnimTextureFrameRef* out, const std::size_t count, const AnimTextureFrameRef& source
  )
  {
    for (std::size_t index = 0; index < count; ++index) {
      out[index].px = source.px;
      out[index].pi = source.pi;
      if (out[index].pi != nullptr) {
        out[index].pi->add_ref_copy();
      }
    }
  }

  /**
   * Address: 0x00424E30 (FUN_00424E30)
   * Address: 0x00814160 (FUN_00814160)
   * Address: 0x00813E70 (FUN_00813E70)
   * Address: 0x008576A0 (FUN_008576A0)
   * Address: 0x00857220 (FUN_00857220)
   *
   * What it does:
   * Assigns a source frame-ref sequence into initialized destination storage
   * with retain/release semantics preserved per slot.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* AssignAnimTextureFrameRefRange(
    AnimTextureFrameRef* outBegin, AnimTextureFrameRef* outEnd, const AnimTextureFrameRef* srcBegin
  )
  {
    const AnimTextureFrameRef* src = srcBegin;
    for (AnimTextureFrameRef* dst = outBegin; dst != outEnd; ++dst, ++src) {
      dst->assign_retain(*src);
    }
    return outEnd;
  }

  /**
   * Address: 0x00424FA0 (FUN_00424FA0)
   * Address: 0x00814340 (FUN_00814340)
   * Address: 0x0084FA80 (FUN_0084FA80)
   * Address: 0x0084FB20 (FUN_0084FB20)
   * Address: 0x00857880 (FUN_00857880)
   *
   * What it does:
   * Backward-assigns one frame-ref range with retain/release ownership updates.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* CopyBackwardAssignAnimTextureFrameRefRange(
    AnimTextureFrameRef* outEnd, const AnimTextureFrameRef* srcBegin, const AnimTextureFrameRef* srcEnd
  )
  {
    AnimTextureFrameRef* dst = outEnd;
    const AnimTextureFrameRef* src = srcEnd;
    while (src != srcBegin) {
      --dst;
      --src;
      dst->assign_retain(*src);
    }
    return dst;
  }

  /**
   * Address: 0x008141E0 (FUN_008141E0)
   *
   * What it does:
   * Adapter lane that forwards backward frame-ref assignment into the canonical
   * `CopyBackwardAssignAnimTextureFrameRefRange` helper and returns the updated
   * destination cursor.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* CopyBackwardAssignAnimTextureFrameRefRangeAdapterA(
    AnimTextureFrameRef* const outEnd,
    const AnimTextureFrameRef* const srcBegin,
    [[maybe_unused]] const AnimTextureFrameRef* const unusedSourceProbe,
    const AnimTextureFrameRef* const srcEnd
  )
  {
    return CopyBackwardAssignAnimTextureFrameRefRange(outEnd, srcBegin, srcEnd);
  }

  /**
   * Address: 0x00813E80 (FUN_00813E80)
   *
   * What it does:
   * Adapter lane that forwards one backward shared-pair assignment range
   * (`sourceBegin..sourceEnd`) into destination-end storage.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* CopyBackwardAssignAnimTextureFrameRefRangeAdapterB(
    const AnimTextureFrameRef* const sourceBegin,
    const AnimTextureFrameRef* const sourceEnd,
    AnimTextureFrameRef* const destinationEnd
  )
  {
    return CopyBackwardAssignAnimTextureFrameRefRange(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0084F740 (FUN_0084F740)
   * Address: 0x0084F770 (FUN_0084F770)
   * Address: 0x00857720 (FUN_00857720)
   *
   * What it does:
   * Register-shape adapter lane that forwards one backward frame-ref assignment
   * range (`sourceBegin..sourceEnd`) into destination-end storage.
   */
  [[maybe_unused]] [[nodiscard]] AnimTextureFrameRef* CopyBackwardAssignAnimTextureFrameRefRangeAdapterC(
    const AnimTextureFrameRef* const sourceBegin,
    const AnimTextureFrameRef* const sourceEnd,
    AnimTextureFrameRef* const destinationEnd
  )
  {
    return CopyBackwardAssignAnimTextureFrameRefRange(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00424DC0 (FUN_00424DC0)
   *
   * What it does:
   * Releases every frame-ref slot in `[begin, end)` with legacy shared-control
   * dispose/destroy behavior.
   */
  void ReleaseAnimTextureFrameRefRange(AnimTextureFrameRef* begin, AnimTextureFrameRef* end)
  {
    for (AnimTextureFrameRef* cursor = begin; cursor != end; ++cursor) {
      cursor->release();
    }
  }

  /**
   * Address: 0x00423EB0 (FUN_00423EB0)
   *
   * What it does:
   * Appends one retained frame reference into storage, growing the legacy
   * vector as needed and enforcing the recovered hard size cap.
   */
  void AppendAnimTextureFrameStorage(
    msvc8::vector<moho::CAnimTexture::FrameRef>& frames, const moho::CAnimTexture::FrameRef& retainedFrame
  )
  {
    if (frames.size() >= MaxAnimTextureFrameCount()) {
      ThrowAnimTextureFrameVectorTooLong();
    }

    frames.push_back(retainedFrame);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00422D20 (FUN_00422D20)
   *
   * What it does:
   * Initializes intrusive refcount/name storage and loads numbered texture frames.
   */
  CAnimTexture::CAnimTexture(const char* const baseTextureName)
  {
    mRefCount = 0;
    LoadFramesFromBaseName(baseTextureName);
  }

  /**
   * Address: 0x00422D00 (FUN_00422D00 thunk) and 0x00422D90 (FUN_00422D90 body)
   * Mangled: ??_GCAnimTexture@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Removes this instance from the global animation-texture cache and releases
   * owned frame/name storage.
   */
  CAnimTexture::~CAnimTexture()
  {
    auto& cache = AnimTextureCache();
    const auto key = ToCacheKey(mBaseTextureName);
    auto cached = FindAnimTextureCacheEntry(cache, key);
    if (cached != cache.end() && cached->second == this) {
      if (AnimTextureCacheSize(cache) == 1U) {
        ResetAnimTextureCacheStorage(cache);
      } else {
        cache.erase(cached);
      }
    } else {
      for (auto it = AnimTextureCacheBegin(cache); it != AnimTextureCacheHead(cache);) {
        if (it->second == this) {
          if (AnimTextureCacheSize(cache) == 1U) {
            ResetAnimTextureCacheStorage(cache);
          } else {
            cache.erase(it);
          }
          break;
        }

        AdvanceAnimTextureCacheIterator(cache, it);
      }
    }

    ReleaseAnimTextureFrameRefRange(mFrames.begin(), mFrames.end());
    mFrames.clear();
    mBaseTextureName.tidy(true, 0U);
  }

  /**
   * Address: 0x00422E50 (FUN_00422E50)
   *
   * What it does:
   * Finds a cached animation texture by name or constructs/caches a new one.
   * Returned pointer carries one intrusive reference (`mRefCount` incremented).
   */
  CAnimTexture* CAnimTexture::FindOrCreate(const char* const baseTextureName)
  {
    const char* const keyText = baseTextureName ? baseTextureName : "";
    const std::string key{keyText};

    auto& cache = AnimTextureCache();
    const auto cached = FindAnimTextureCacheEntry(cache, key);
    if (cached != cache.end()) {
      if (cached->second != nullptr) {
        ++cached->second->mRefCount;
      }
      return cached->second;
    }

    auto* const created = new CAnimTexture(keyText);
    if (!created) {
      return nullptr;
    }

    EnsureAnimTextureCacheSlot(cache, key) = created;
    ++created->mRefCount;
    return created;
  }

  /**
   * Address: 0x00423190 (FUN_00423190)
   *
   * What it does:
   * Samples a frame pointer by positive-wrapped frame index and returns an intrusive
   * `SharedPtrRaw` copy (`pi` refcount retained on success).
   */
  void CAnimTexture::GetFrameAt(FrameRef& outFrame, const float frameIndex) const
  {
    outFrame = {};
    if (mFrames.empty()) {
      return;
    }

    const auto count = static_cast<std::int32_t>(mFrames.size());
    const float wrappedFrame = WrapPositiveModulo(frameIndex, static_cast<float>(count));
    const std::int32_t index = FloorToIndex(wrappedFrame);
    if (index < 0) {
      return;
    }

    if (index >= count) {
      return;
    }

    outFrame = mFrames[static_cast<std::size_t>(index)];
    outFrame.add_ref_copy();
  }

  void CAnimTexture::SetFrameResolver(const FrameResolver resolver)
  {
    AnimTextureResolver() = resolver;
  }

  const msvc8::string& CAnimTexture::GetBaseTextureName() const noexcept
  {
    return mBaseTextureName;
  }

  /**
   * Address: 0x00422FA0 (FUN_00422FA0)
   *
   * What it does:
   * Stores source texture name and loads sequential numbered frames.
   */
  void CAnimTexture::LoadFramesFromBaseName(const char* const baseTextureName)
  {
    ReleaseAnimTextureFrameRefRange(mFrames.begin(), mFrames.end());
    mFrames.clear();
    mBaseTextureName.assign_owned(baseTextureName);

    msvc8::string frameName{};
    frameName.tidy(false, 0U);
    frameName.assign_owned(baseTextureName);

    while (true) {
      FrameRef loadedFrame = ResolveFrameTexture(frameName.data());
      if (loadedFrame.px == nullptr && loadedFrame.pi == nullptr) {
        break;
      }

      AppendFrameRef(loadedFrame);
      loadedFrame.release();

      if (!IncrementFrameNameSuffix(frameName)) {
        break;
      }
    }

    frameName.tidy(true, 0U);
  }

  /**
   * Address: 0x00422BC0 (FUN_00422BC0)
   *
   * What it does:
   * Increments the trailing numeric suffix in-place and wraps carries to `0`.
   * Returns false only when no suitable numeric suffix exists.
   */
  bool CAnimTexture::IncrementFrameNameSuffix(msvc8::string& textureName)
  {
    if (!textureName.basic_sanity() || textureName.empty()) {
      return false;
    }

    char* const chars = textureName.raw_data_mut_unsafe();
    std::int32_t digitIndex = static_cast<std::int32_t>(textureName.size()) - 1;
    while (digitIndex >= 0) {
      const char c = chars[digitIndex];
      if (c >= '0' && c <= '9') {
        break;
      }
      --digitIndex;
    }

    if (digitIndex < 0) {
      return false;
    }

    if (static_cast<std::size_t>(digitIndex + 1) < textureName.size() && chars[digitIndex + 1] == '.') {
      return false;
    }

    while (digitIndex >= 0) {
      const char current = chars[digitIndex];
      if (current < '0' || current > '9') {
        return true;
      }

      if (current < '9') {
        chars[digitIndex] = static_cast<char>(current + 1);
        return true;
      }

      chars[digitIndex] = '0';
      --digitIndex;
    }

    return true;
  }

  /**
   * Address: 0x00423310 (FUN_00423310)
   *
   * What it does:
   * Appends one frame reference to internal storage, retaining `pi`.
   */
  void CAnimTexture::AppendFrameRef(const FrameRef& frame)
  {
    FrameRef retainedFrame = frame;
    retainedFrame.add_ref_copy();
    AppendAnimTextureFrameStorage(mFrames, retainedFrame);
  }

  /**
   * Address: 0x00BC3BA0 (FUN_00BC3BA0, register_sAnimTextureMap)
   *
   * What it does:
   * Materializes the process animation-texture cache map during startup.
   */
  void RegisterAnimTextureMapStartup()
  {
    (void)AnimTextureCache();
  }
} // namespace moho

namespace
{
  struct CAnimTextureStartupRegistrations
  {
    CAnimTextureStartupRegistrations()
    {
      moho::RegisterAnimTextureMapStartup();
    }
  };

  [[maybe_unused]] CAnimTextureStartupRegistrations gCAnimTextureStartupRegistrations;
} // namespace
