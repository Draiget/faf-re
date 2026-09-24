#pragma once

#include <cstdint>

namespace gpg::gal
{
  /**
   * FAF instrumentation - not part of the recovered GAL.
   *
   * What the active backend's DrawPrimitive / DrawIndexedPrimitive submitted
   * since the last `TakeDrawStatistics()`. `CD3DDevice::PublishDrawStatistics`
   * feeds one frame's worth into the engine's own `Render_DrawPrimCalls`,
   * `Render_PrimitiveCount` and `Render_VertexCount` stats (`ShowStats render`).
   * The shipped engine resets those every frame and displays them, but its
   * release build never increments them: nothing in the binary reaches
   * `CD3DDevice::AddPrimStats` / `AddVertexStats`, and nothing writes
   * `Render_DrawPrimCalls` at all.
   *
   * Counts are per submission. An instanced draw adds its mesh's primitives
   * and vertices once, however many instances it covers, so `drawCalls` is the
   * figure that tracks the renderer's D3D9 CPU cost. Draws D3DX issues on its
   * own (ID3DXFont text) never reach the backend's entry points and are not
   * counted. Every draw is issued from the render thread, so the counters are
   * plain integers.
   */
  struct DrawStatistics
  {
    std::uint32_t drawCalls = 0;
    std::uint32_t primitives = 0;
    std::uint32_t vertices = 0;
  };

  [[nodiscard]] inline DrawStatistics& PendingDrawStatistics() noexcept
  {
    static DrawStatistics sPending{};
    return sPending;
  }

  /** Called by a backend after each successful draw submission. */
  inline void RecordDraw(const std::uint32_t primitiveCount, const std::uint32_t vertexCount) noexcept
  {
    DrawStatistics& pending = PendingDrawStatistics();
    ++pending.drawCalls;
    pending.primitives += primitiveCount;
    pending.vertices += vertexCount;
  }

  /** Returns everything recorded since the previous call and starts a new tally. */
  [[nodiscard]] inline DrawStatistics TakeDrawStatistics() noexcept
  {
    DrawStatistics& pending = PendingDrawStatistics();
    const DrawStatistics taken = pending;
    pending = DrawStatistics{};
    return taken;
  }
} // namespace gpg::gal
