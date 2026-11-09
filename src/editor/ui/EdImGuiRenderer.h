#pragma once

#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"

struct ImDrawData;
struct ImDrawVert;
struct ImTextureData;

namespace gpg::gal
{
  class GpuBuffer;
  class GpuProgram;
}

namespace faf::editor
{
  /**
   * Draws Dear ImGui's frames through gal's GPU-program path (gpg/gal/GpuDriven.h), so the same
   * code runs on Direct3D 12 and Vulkan: the frame's vertices and indices go into two structured
   * buffers, and each draw command is one non-indexed draw whose vertex shader reads its index,
   * then its vertex. Clip rectangles are applied in the pixel shader (the GPU-program path has no
   * scissor). Textures follow ImGui 1.92's protocol (`ImGuiBackendFlags_RendererHasTextures`):
   * ImGui asks for each one to be created, updated or destroyed through `ImDrawData::Textures`.
   */
  class EdImGuiRenderer
  {
  public:
    /** Compiles the program and registers as ImGui's renderer; false when the device can't pull vertices. */
    [[nodiscard]] bool Init();

    /** Releases every texture ImGui handed over and the GPU resources. */
    void Shutdown();

    /** Draws one ImGui frame into the bound target. */
    void Render(ImDrawData* drawData);

    /**
     * An image of the editor's own for `ImGui::Image` (thumbnails): `width` x `height` BGRA pixels, row by
     * row. Returns its ImTextureID (0 when it can't be made); it lives until DestroyImage.
     */
    static std::uint64_t CreateImage(int width, int height, const std::uint32_t* bgra);
    static void DestroyImage(std::uint64_t image);

  private:
    void UpdateTexture(ImTextureData* texture);
    void EnsureCapacity(std::uint32_t vertexCount, std::uint32_t indexCount);

    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mVertices;
    boost::shared_ptr<gpg::gal::GpuBuffer> mIndices;
    std::uint32_t mVertexCapacity = 0U;
    std::uint32_t mIndexCapacity = 0U;
    std::vector<std::uint8_t> mVertexStage;
    std::vector<std::uint32_t> mIndexStage;
  };
} // namespace faf::editor
