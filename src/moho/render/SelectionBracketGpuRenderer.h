#pragma once

// Engine addition, not in the shipped binary: GPU-instanced selection brackets
// (`ren_GpuSelectBrackets`).
//
// `RenUI` draws every selected entity's four bracket tiles as four
// `CD3DPrimBatcher::DrawQuad` calls, one entity after another; with thousands
// selected that is tens of thousands of batcher quads per view per frame. Here
// the per-entity bracket geometry is computed on workers into one compact
// record per entity (SelectionBracketShader.h), the records go to a persistent
// GPU buffer (only changed blocks are uploaded), and one instanced draw expands
// them in the same order with the same texture, colour, blend and alpha test.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/render/GpuArrayStream.h"
#include "moho/render/SelectionBracketShader.h"

namespace gpg::gal
{
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  class CD3DBatchTexture;
  class CD3DPrimBatcher;

  /// `ren_GpuSelectBrackets`: draw selection brackets through SelectionBracketGpuRenderer when the backend can.
  extern int ren_GpuSelectBrackets;

  class SelectionBracketGpuRenderer
  {
  public:
    [[nodiscard]] static SelectionBracketGpuRenderer& Get();

    /** `ren_GpuSelectBrackets` is on and the backend can draw this path (creates it on first use). */
    [[nodiscard]] bool IsActive();

    /**
     * Main thread: draws `instances` with `texture` through `batcher`'s atlas,
     * matrices and alpha multiplier, tinted `color` (ARGB), for the view
     * `viewKey`. Returns false, having drawn nothing, when the texture cannot go
     * into the atlas; the caller then draws through the batcher.
     */
    [[nodiscard]] bool Draw(
      CD3DPrimBatcher& batcher,
      const void* viewKey,
      const boost::shared_ptr<CD3DBatchTexture>& texture,
      std::uint32_t color,
      std::span<const SelectionBracketInstance> instances
    );

  private:
    struct ViewStream
    {
      const void* mViewKey = nullptr;
      std::uint64_t mLastUsedDraw = 0U;
      GpuArrayStream mInstances{"SelectionBrackets", sizeof(SelectionBracketInstance)};
    };

    ViewStream& StreamFor(const void* viewKey);

    bool mInitialized = false;
    bool mSupported = false;
    std::uint64_t mDraws = 0U;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    std::vector<ViewStream> mStreams;
  };
} // namespace moho
