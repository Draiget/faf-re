#include "moho/render/BoxRenderer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"

namespace
{
  struct BoxVertex
  {
    float x;
    float y;
    float z;
  };

  static_assert(sizeof(BoxVertex) == 0x0C, "BoxVertex size must be 0x0C");

  constexpr std::array<BoxVertex, 8> kUnitBoxVertices = {{
    {-1.0f, -1.0f, -1.0f},
    {1.0f, -1.0f, -1.0f},
    {1.0f, 1.0f, -1.0f},
    {-1.0f, 1.0f, -1.0f},
    {-1.0f, -1.0f, 1.0f},
    {1.0f, -1.0f, 1.0f},
    {1.0f, 1.0f, 1.0f},
    {-1.0f, 1.0f, 1.0f},
  }};

  constexpr std::array<std::uint16_t, 36> kUnitBoxIndices = {{
    0, 1, 2, 0, 2, 3,
    4, 6, 5, 4, 7, 6,
    0, 4, 5, 0, 5, 1,
    3, 2, 6, 3, 6, 7,
    1, 5, 6, 1, 6, 2,
    0, 3, 7, 0, 7, 4,
  }};
}

namespace moho
{
  /**
   * Address: 0x007D04C0 (FUN_007D04C0, Moho::BoxRenderer::dtr)
   * Address: 0x007D04E0 (FUN_007D04E0, Moho::BoxRenderer::~BoxRenderer)
   */
  BoxRenderer::~BoxRenderer()
  {
    ResetRenderResources();
  }

  /**
   * Address: 0x007D0820 (FUN_007D0820, sub_7D0820)
   */
  void BoxRenderer::ResetRenderResources() noexcept
  {
    mGeometry.Reset();
  }

  void BoxRenderer::InitializeGeometryResources()
  {
    ResetRenderResources();

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    if (!device) {
      return;
    }

    device->CreateVertexFormat(&mGeometry.mVertexFormat, 1u);

    gpg::gal::VertexBufferContext vertexBufferContext{};
    vertexBufferContext.width_ = static_cast<std::uint32_t>(kUnitBoxVertices.size());
    vertexBufferContext.height_ = sizeof(BoxVertex);
    vertexBufferContext.type_ = 1u;
    vertexBufferContext.usage_ = 1u;
    device->CreateVertexBuffer(&mGeometry.mVertexBuffer, &vertexBufferContext);

    gpg::gal::IndexBufferContext indexBufferContext{};
    indexBufferContext.size_ = static_cast<std::uint32_t>(kUnitBoxIndices.size());
    indexBufferContext.format_ = 1u;
    indexBufferContext.type_ = 1u;
    device->CreateIndexBuffer(&mGeometry.mIndexBuffer, &indexBufferContext);

    if (mGeometry.mVertexBuffer) {
      void* const vertexStorage =
        mGeometry.mVertexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
      if (vertexStorage) {
        std::memcpy(vertexStorage, kUnitBoxVertices.data(), sizeof(kUnitBoxVertices));
      }
      mGeometry.mVertexBuffer->Unlock();
    }

    if (mGeometry.mIndexBuffer) {
      std::int16_t* const indexStorage =
        mGeometry.mIndexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
      if (indexStorage) {
        std::memcpy(indexStorage, kUnitBoxIndices.data(), sizeof(kUnitBoxIndices));
      }
      mGeometry.mIndexBuffer->Unlock();
    }
  }
} // namespace moho
