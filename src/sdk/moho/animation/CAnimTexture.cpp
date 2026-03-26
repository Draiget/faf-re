#include "CAnimTexture.h"

#include <cmath>
#include <map>
#include <string>

namespace
{
  [[nodiscard]] std::int32_t FloorToIndex(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  [[nodiscard]] std::string ToCacheKey(const msvc8::string& value)
  {
    return std::string(value.data(), value.size());
  }

  [[nodiscard]] std::map<std::string, moho::CAnimTexture*>& AnimTextureCache()
  {
    static std::map<std::string, moho::CAnimTexture*> cache;
    return cache;
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
    auto cached = cache.find(key);
    if (cached != cache.end() && cached->second == this) {
      cache.erase(cached);
    } else {
      for (auto it = cache.begin(); it != cache.end(); ++it) {
        if (it->second == this) {
          cache.erase(it);
          break;
        }
      }
    }

    for (FrameRef* frame = mFrames.begin(); frame != mFrames.end(); ++frame) {
      frame->release();
    }
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

    auto& cache = AnimTextureCache();
    const auto cached = cache.find(keyText);
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

    cache.emplace(std::string(keyText), created);
    ++created->mRefCount;
    return created;
  }

  /**
   * Address: 0x00423190 (FUN_00423190)
   *
   * What it does:
   * Samples a frame pointer by floored frame index and returns an intrusive
   * `SharedPtrRaw` copy (`pi` refcount retained on success).
   */
  void CAnimTexture::GetFrameAt(FrameRef& outFrame, const float frameIndex) const
  {
    outFrame = {};
    if (mFrames.empty()) {
      return;
    }

    const std::int32_t index = FloorToIndex(frameIndex);
    if (index < 0) {
      return;
    }

    const auto count = static_cast<std::int32_t>(mFrames.size());
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
    for (FrameRef* frame = mFrames.begin(); frame != mFrames.end(); ++frame) {
      frame->release();
    }
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
    mFrames.push_back(retainedFrame);
  }
} // namespace moho
