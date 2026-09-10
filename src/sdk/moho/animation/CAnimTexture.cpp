#include "CAnimTexture.h"

#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"

#include <cmath>

#include "legacy/containers/Map.h"

namespace moho
{
  /**
   * Address: 0x00BC3BA0 (FUN_00BC3BA0, register_sAnimTextureMap)
   *
   * `Moho::sAnimTextureMap` at 0x010A77F8: the 0x0C `{proxy, head, size}`
   * head, node 0x30 with the key at `node+0x0C` (the lower bound at
   * 0x00424670 reads `_Bx` at `node+0x10` and `_Myres` at `node+0x24`, the
   * plain 0x1C layout), the texture pointer at `node+0x28` and colour/nil at
   * `+0x2C`/`+0x2D`. 0x00BC3BA0 is the dynamic initializer MSVC emits for it:
   * buy the header sentinel (0x004247E0), mark it nil, self-link all three
   * links, zero the size and `atexit` the destructor.
   */
  msvc8::map<msvc8::string, CAnimTexture*> sAnimTextureMap;
} // namespace moho

namespace
{
  [[nodiscard]] std::int32_t FloorToIndex(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
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
    // Drop this texture's cache entry, by name first and by a full scan when
    // the name no longer resolves to this instance. `mFrames` and
    // `mBaseTextureName` are torn down by their own destructors afterwards.
    const auto cached = sAnimTextureMap.find(mBaseTextureName);
    if (cached != sAnimTextureMap.end() && cached->second == this) {
      if (sAnimTextureMap.size() == 1U) {
        sAnimTextureMap.clear();
      } else {
        sAnimTextureMap.erase(cached);
      }
      return;
    }

    for (auto it = sAnimTextureMap.begin(); it != sAnimTextureMap.end(); ++it) {
      if (it->second != this) {
        continue;
      }

      if (sAnimTextureMap.size() == 1U) {
        sAnimTextureMap.clear();
      } else {
        sAnimTextureMap.erase(it);
      }
      break;
    }
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
    const msvc8::string key(keyText);

    const auto cached = sAnimTextureMap.find(key);
    if (cached != sAnimTextureMap.end()) {
      if (cached->second != nullptr) {
        ++cached->second->mRefCount;
      }
      return cached->second;
    }

    auto* const created = new CAnimTexture(keyText);
    if (!created) {
      return nullptr;
    }

    sAnimTextureMap[key] = created;
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
    mFrames.clear();
    mBaseTextureName.assign_owned(baseTextureName);

    msvc8::string frameName{};
    frameName.tidy(false, 0U);
    frameName.assign_owned(baseTextureName);

    // 0x00422FA0: every frame goes through the device resource cache with the
    // fallback texture allowed, so a frame is appended unconditionally; the
    // loop only stops when the name has no numeric suffix left to bump or the
    // next numbered file is not on the virtual file system.
    while (true) {
      ID3DDeviceResources::TextureResourceHandle textureResource{};
      D3D_GetDevice()->GetResources()->GetTexture(textureResource, frameName.c_str(), nullptr, true);
      FrameRef loadedFrame{};
      loadedFrame.reset_from_owner(boost::static_pointer_cast<ID3DTextureSheet>(textureResource));
      AppendFrameRef(loadedFrame);
      loadedFrame.release();

      if (!IncrementFrameNameSuffix(frameName)) {
        break;
      }
      const FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr
          || !waitHandleSet->mHandle->GetFileInfo(frameName.c_str(), nullptr)) {
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

    // 0x00422BC0: the digit run must sit directly before the extension (or at
    // the very end) - `find_last_of("0123456789")`, then `buf[last + 1] != '.'`
    // returns false. "flare_0001.dds" advances; "eg_boulder006_albedo.dds" is
    // one frame, never an animation through its numbered siblings.
    if (static_cast<std::size_t>(digitIndex + 1) < textureName.size() && chars[digitIndex + 1] != '.') {
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
