#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CountedObject.h"

namespace moho
{
  class ID3DTextureSheet;

  class CAnimTexture final : public CountedObject
  {
  public:
    using FrameRef = boost::SharedPtrRaw<ID3DTextureSheet>;
    using FrameResolver = FrameRef (*)(const char* textureName);

    /**
     * Address: 0x00422D20 (FUN_00422D20)
     *
     * What it does:
     * Initializes intrusive refcount/name storage and loads numbered texture frames.
     */
    explicit CAnimTexture(const char* baseTextureName);

    /**
     * Address: 0x00422D00 (FUN_00422D00 thunk) and 0x00422D90 (FUN_00422D90 body)
     * Mangled: ??_GCAnimTexture@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Removes this instance from the global animation-texture cache and releases
     * owned frame/name storage.
     */
    ~CAnimTexture() override;

    /**
     * Address: 0x00422E50 (FUN_00422E50)
     *
     * What it does:
     * Finds a cached animation texture by name or constructs/caches a new one.
     * Returned pointer carries one intrusive reference (`mRefCount` incremented).
     */
    [[nodiscard]] static CAnimTexture* FindOrCreate(const char* baseTextureName);

    /**
     * Address: 0x00423190 (FUN_00423190)
     *
     * What it does:
     * Samples a frame pointer by positive-wrapped frame index and returns an intrusive
     * `SharedPtrRaw` copy (`pi` refcount retained on success).
     */
    void GetFrameAt(FrameRef& outFrame, float frameIndex) const;

    /**
     * Hook to connect reconstructed logic with engine texture loading once the
     * owning texture manager interface is recovered.
     */
    static void SetFrameResolver(FrameResolver resolver);

    [[nodiscard]] const msvc8::string& GetBaseTextureName() const noexcept;

    CAnimTexture(const CAnimTexture&) = delete;
    CAnimTexture& operator=(const CAnimTexture&) = delete;
    CAnimTexture(CAnimTexture&&) = delete;
    CAnimTexture& operator=(CAnimTexture&&) = delete;

  private:
    /**
     * Address: 0x00422FA0 (FUN_00422FA0)
     *
     * What it does:
     * Stores source texture name and loads sequential numbered frames.
     */
    void LoadFramesFromBaseName(const char* baseTextureName);

    /**
     * Address: 0x00422BC0 (FUN_00422BC0)
     *
     * What it does:
     * Increments the trailing numeric suffix in-place and wraps carries to `0`.
     * Returns false only when no suitable numeric suffix exists.
     */
    static bool IncrementFrameNameSuffix(msvc8::string& textureName);

    /**
     * Address: 0x00423310 (FUN_00423310)
     *
     * What it does:
     * Appends one frame reference to internal storage, retaining `pi`.
     */
    void AppendFrameRef(const FrameRef& frame);

  public:
    msvc8::vector<FrameRef> mFrames; // +0x08
    msvc8::string mBaseTextureName;  // +0x18
  };

  static_assert(sizeof(CAnimTexture::FrameRef) == 0x08, "CAnimTexture::FrameRef size must be 0x08");
  static_assert(offsetof(CAnimTexture, mFrames) == 0x08, "CAnimTexture::mFrames offset must be 0x08");
  static_assert(offsetof(CAnimTexture, mBaseTextureName) == 0x18, "CAnimTexture::mBaseTextureName offset must be 0x18");
  static_assert(sizeof(CAnimTexture) == 0x34, "CAnimTexture size must be 0x34");
} // namespace moho
