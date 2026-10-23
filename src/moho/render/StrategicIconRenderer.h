#pragma once

// Engine addition, not in the shipped binary: GPU-driven strategic icons
// (`ren_GpuIcons`).
//
// The CPU path (`CWldSession::RenderStrategicIcons` -> `RenderUnitIcon`)
// builds four 24-byte vertices and six indices per icon quad through
// `CD3DPrimBatcher` - over 100,000 quads per frame with tens of thousands of
// units zoomed out - and uploads all of them every frame. Here each icon is one
// 16-byte record (screen point, tint, the atlas slots of its up to four layers)
// in a persistent structured buffer; only the 4 KB blocks of records that
// changed since the previous frame of the same view are uploaded, and one
// instanced draw expands the quads in the vertex shader (StrategicIconShader.h).
//
// The textures stay in the prim batcher's own atlas (`CD3DTextureBatcher`),
// with the same UV rectangles `CD3DPrimBatcher::SetTexture` computes, so the
// sampled texels are the same. Records keep the CPU path's order (ground, air,
// high-priority, selected; underlay, base, paused, stunned within an icon), and
// a draw rasterises its primitives in order, so the blended result is the same.

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/render/GpuArrayStream.h"

namespace gpg::gal
{
  class GpuBuffer;
  class GpuProgram;
  class Texture;
} // namespace gpg::gal

namespace moho
{
  class CD3DBatchTexture;
  class CD3DPrimBatcher;

  /// `ren_GpuIcons`: draw strategic icons through StrategicIconRenderer when the backend can.
  extern int ren_GpuIcons;
  /// `ren_GpuIconClassify`: also classify them on the GPU (with `ren_GpuIcons` and `ui_IconRecords`).
  extern int ren_GpuIconClassify;

  struct StrategicIconSourceRecord;
  struct StrategicIconClassifyConstants;

  /** One icon as the GPU reads it (`IconInstance` in StrategicIconShader.h). */
  struct StrategicIconInstance
  {
    std::uint32_t mPosition = 0U; ///< x low 16 bits, y high 16 bits, signed whole pixels
    std::uint32_t mColor = 0U;    ///< ARGB tint of the base icon
    std::uint32_t mLayers01 = 0xFFFFFFFFU;
    std::uint32_t mLayers23 = 0xFFFFFFFFU;

    static constexpr std::uint16_t kNoLayer = 0xFFFFU;
    static constexpr std::uint32_t kLayerCount = 4U; ///< underlay, base, paused, stunned

    void SetPosition(float screenX, float screenY) noexcept;
    void SetLayer(std::uint32_t layer, std::uint16_t slot) noexcept;
  };
  static_assert(sizeof(StrategicIconInstance) == 16, "StrategicIconInstance must match IconInstance");

  class StrategicIconRenderer
  {
  public:
    [[nodiscard]] static StrategicIconRenderer& Get();

    /** `ren_GpuIcons` is on and the active backend can draw this path (creates it on first use). */
    [[nodiscard]] bool IsActive();

    /**
     * The atlas slot of `texture`, or `StrategicIconInstance::kNoLayer` when it
     * has none yet. Read-only, so workers may call it while nothing registers.
     */
    [[nodiscard]] std::uint16_t FindSlot(const CD3DBatchTexture* texture) const noexcept;

    /** Main thread: the slot of `texture`, registering it on first use. */
    [[nodiscard]] std::uint16_t AddSlot(const boost::shared_ptr<CD3DBatchTexture>& texture);

    /**
     * Main thread, after the records of a frame are built: draws `instances` for
     * the view `viewKey` through `batcher`'s atlas and matrices. Returns false,
     * having drawn nothing, when the atlas cannot hold the icon textures or a
     * texture is too large for it; the caller then draws through the CPU path.
     */
    [[nodiscard]] bool Draw(CD3DPrimBatcher& batcher, const void* viewKey, std::span<const StrategicIconInstance> instances);

    /**
     * `IsActive()`, `ren_GpuIconClassify` is on and the backend has compute
     * shaders and indirect draws (creates the classification programs on first use).
     */
    [[nodiscard]] bool IsClassifyActive();

    /**
     * Main thread: classifies `sources` on the GPU (StrategicIconClassifyShader.h)
     * against `constants` (whose `mCount` is set here) and `selectionBits` (one
     * bit per source), and draws the records it produces for the view
     * `viewKey` with one indirect draw. Each array is compared and uploaded
     * again only when its version differs from the one this view last drew
     * with. Returns false, having drawn nothing, when the renderer declines;
     * the caller then classifies on the CPU.
     */
    [[nodiscard]] bool DrawClassified(
      CD3DPrimBatcher& batcher,
      const void* viewKey,
      std::span<const StrategicIconSourceRecord> sources,
      std::uint64_t sourcesVersion,
      std::span<const std::uint32_t> selectionBits,
      std::uint64_t selectionVersion,
      const StrategicIconClassifyConstants& constants
    );

    /**
     * Diagnostics (FAF_ICON_GPU_CHECK): the records the last `DrawClassified`
     * drew, in draw order, read back from the GPU. Waits for the GPU; false when
     * the backend cannot read buffers back.
     */
    [[nodiscard]] bool ReadBackClassified(std::vector<StrategicIconInstance>& out);

  private:
    struct Slot
    {
      boost::shared_ptr<CD3DBatchTexture> mTexture; // keeps the address from being reused
      float mUv[4] = {};                            // origin and extent in the atlas
      float mHalfSize[2] = {};
      float mUnused[2] = {};
    };

    /** The GPU copy of one view's records, kept between frames. */
    struct ViewStream
    {
      const void* mViewKey = nullptr;
      std::uint64_t mLastUsedFrame = 0U;
      GpuArrayStream mRecords{"StrategicIcons", sizeof(StrategicIconInstance)};
      // `DrawClassified`: the view's sources and selection bits, and the versions they hold.
      GpuArrayStream mSources{"StrategicIconSources", 64U};
      GpuArrayStream mSelection{"StrategicIconSelection", sizeof(std::uint32_t)};
      std::uint64_t mSourcesVersion = ~0ULL;
      std::uint64_t mSelectionVersion = ~0ULL;
    };

    bool CreateResources();
    bool CreateClassifyResources();
    /** The classification work buffers, grown to hold `count` sources. */
    bool EnsureClassifyCapacity(std::uint32_t count);
    /** Re-reads every slot's atlas rectangle; false when the atlas cannot hold them. */
    bool RefreshAtlasSlots(CD3DPrimBatcher& batcher);
    void UploadSlots();
    /** Everything both draws need first: the atlas slots, the batcher flushed, the atlas texture. */
    [[nodiscard]] gpg::gal::Texture* PrepareDraw(CD3DPrimBatcher& batcher);
    ViewStream& StreamFor(const void* viewKey);

    bool mInitialized = false;
    bool mSupported = false;
    std::uint64_t mFrame = 0U;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mSlotBuffer;
    std::uint32_t mSlotCapacity = 0U;
    bool mSlotsDirty = false;
    std::vector<Slot> mSlots;
    std::unordered_map<const CD3DBatchTexture*, std::uint16_t> mSlotByTexture;
    std::vector<ViewStream> mStreams;

    bool mClassifyInitialized = false;
    bool mClassifySupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mClassifyProgram;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompactProgram;
    std::uint32_t mClassifyCapacity = 0U;
    boost::shared_ptr<gpg::gal::GpuBuffer> mStaged;  // one record per source
    boost::shared_ptr<gpg::gal::GpuBuffer> mRunOf;   // one run per source
    boost::shared_ptr<gpg::gal::GpuBuffer> mOutput;  // the records in draw order
    boost::shared_ptr<gpg::gal::GpuBuffer> mDrawArgs;
    std::uint32_t mLastClassifiedSources = 0U;
  };
} // namespace moho
