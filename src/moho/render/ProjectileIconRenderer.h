#pragma once

// Engine addition, not in the shipped binary: GPU-instanced projectile icons
// (`ren_GpuProjectileIcons`).
//
// `CWldSession::RenderProjectileIcons` draws one batcher quad per visible
// projectile, in the main view and again in the minimap; in a large air fight
// that is thousands of quads, a texture bind and an atlas lookup each, and a
// few hundred KB of vertices uploaded per view per frame. Here the pass
// collects one 20-byte record per icon (ProjectileIconShader.h) and draws them
// with one instanced draw, in the same order, through the same atlas.

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/render/GpuArrayStream.h"
#include "moho/render/ProjectileIconShader.h"

namespace gpg::gal
{
  class GpuBuffer;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  class CD3DBatchTexture;
  class CD3DPrimBatcher;

  /// `ren_GpuProjectileIcons`: draw projectile icons through ProjectileIconRenderer when the backend can.
  extern int ren_GpuProjectileIcons;

  class ProjectileIconRenderer
  {
  public:
    [[nodiscard]] static ProjectileIconRenderer& Get();

    /** `ren_GpuProjectileIcons` is on and the backend can draw this path (creates it on first use). */
    [[nodiscard]] bool IsActive();

    /** Starts a view's icon list. */
    void Begin(const void* viewKey);

    /** Appends one icon: the quad `DrawQuad` would draw around `(centerX, centerY)` with `texture`. */
    void Add(const boost::shared_ptr<CD3DBatchTexture>& texture, float centerX, float centerY, float halfWidth, float halfHeight);

    /**
     * Draws the icons added since `Begin` (or the last `Flush`) through
     * `batcher`'s atlas, matrices and alpha multiplier, and empties the list.
     * Returns false, having drawn nothing and kept the list, when a texture
     * cannot go into the atlas; `DrawWithBatcher` then draws them on the CPU.
     */
    [[nodiscard]] bool Flush(CD3DPrimBatcher& batcher);

    /** The CPU fallback: the pending icons as the original batcher quads, then empties the list. */
    void DrawWithBatcher(CD3DPrimBatcher& batcher);

  private:
    struct ViewStream
    {
      const void* mViewKey = nullptr;
      std::uint64_t mLastUsedDraw = 0U;
      GpuArrayStream mRecords{"ProjectileIcons", sizeof(ProjectileIconInstance)};
    };

    ViewStream& StreamFor(const void* viewKey);

    bool mInitialized = false;
    bool mSupported = false;
    std::uint64_t mDraws = 0U;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mSlotBuffer;
    std::uint32_t mSlotCapacity = 0U;
    std::vector<ViewStream> mStreams;

    // The pending icons and the textures they use, by first use.
    const void* mViewKey = nullptr;
    std::vector<ProjectileIconInstance> mPending;
    std::vector<boost::shared_ptr<CD3DBatchTexture>> mTextures;
    std::unordered_map<const CD3DBatchTexture*, std::uint32_t> mSlotOf;
    std::vector<ProjectileIconSlot> mSlots;
    const CD3DBatchTexture* mLastTexture = nullptr;
    std::uint32_t mLastSlot = 0U;
  };
} // namespace moho
