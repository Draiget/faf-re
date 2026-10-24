#pragma once

// Engine addition, not in the shipped binary: the drawing side of FAF's world
// shapes, UI_DrawLine / UI_DrawRect / UI_DrawCircle (FAF FA-Binary-Patches,
// section/DrawFunc.cpp; the Lua side is moho/ui/UiWorldShapes.cpp).
//
// Every shape is first reduced to one `WorldShapeRecord` (WorldShapeShader.h):
// the corner points, or a circle's centre and axes, exactly as the patch
// computes them. `DrawWorldShape` draws a record through `CD3DPrimBatcher` the
// way the patch does (`DrawQuad`, `DRAW_Rect`'s four quads, `DRAW_Oval`).
// `WorldShapeGpuRenderer` (`ren_GpuShapes`) instead collects a pass's records
// into a persistent GPU buffer and draws them with one instanced draw per run
// of same-kind shapes, in the same order and with the same state.

#include <cstdint>
#include <span>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/render/GpuArrayStream.h"
#include "moho/render/WorldShapeShader.h"

namespace gpg::gal
{
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  class CD3DPrimBatcher;

  /// `ren_GpuShapes`: draw FAF's UI_Draw* world shapes through WorldShapeGpuRenderer when the backend can.
  extern int ren_GpuShapes;

  /**
   * FAF FA-Binary-Patches (section/DrawFunc.cpp): draws one shape through the
   * prim batcher as the patch does - a line as one `DrawQuad`, a rectangle as
   * `DRAW_Rect`'s four quads (no height field), a circle as `DRAW_Oval`.
   */
  void DrawWorldShape(CD3DPrimBatcher& batcher, const WorldShapeRecord& record);

  class WorldShapeGpuRenderer
  {
  public:
    [[nodiscard]] static WorldShapeGpuRenderer& Get();

    /** `ren_GpuShapes` is on and the backend can draw this path (creates it on first use). */
    [[nodiscard]] bool IsActive();

    /**
     * Main thread: draws `records` in order through `batcher`'s atlas (the
     * solid white texture), matrices and alpha multiplier, for the view
     * `viewKey`. Returns false, having drawn nothing, when the texture or the
     * buffer is not available; the caller then draws through the batcher.
     */
    [[nodiscard]] bool Draw(CD3DPrimBatcher& batcher, const void* viewKey, std::span<const WorldShapeRecord> records);

  private:
    struct ViewStream
    {
      const void* mViewKey = nullptr;
      std::uint64_t mLastUsedDraw = 0U;
      GpuArrayStream mRecords{"WorldShapes", sizeof(WorldShapeRecord)};
    };

    ViewStream& StreamFor(const void* viewKey);

    bool mInitialized = false;
    bool mSupported = false;
    std::uint64_t mDraws = 0U;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    std::vector<ViewStream> mStreams;
  };
} // namespace moho
