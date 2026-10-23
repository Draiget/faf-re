#include "moho/render/BoxRenderer.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/VertexBuffer.hpp"

namespace
{
  struct BoxVertex
  {
    float x;
    float y;
    float z;
  };

  static_assert(sizeof(BoxVertex) == 0x0C, "BoxVertex size must be 0x0C");

  // .rdata 0x00DFEA50, copied into the vertex buffer by 0x007D05D0
  // (`rep movsd`, 0x18 dwords, at 0x007D072B).
  constexpr std::array<BoxVertex, 8> kUnitBoxVertices = {{
    {-1.0f, -1.0f, -1.0f},
    {1.0f, -1.0f, -1.0f},
    {1.0f, -1.0f, 1.0f},
    {-1.0f, -1.0f, 1.0f},
    {-1.0f, 1.0f, -1.0f},
    {1.0f, 1.0f, -1.0f},
    {1.0f, 1.0f, 1.0f},
    {-1.0f, 1.0f, 1.0f},
  }};

  // .rdata 0x00DFEAB0, copied into the index buffer by 0x007D05D0
  // (`rep movsd`, 0x12 dwords, at 0x007D07F2). The winding matters:
  // CastBoundaryCW/CCW select faces by cull mode, while vision.fx and range.fx
  // leave D3DRS_TWOSIDEDSTENCILMODE on (BeginTechnique, 0x00946260, never
  // resets it). The reversed winding this table used to have sent the box's
  // far faces through the leaked CCW stencil ops, so the Boundary pass blacked
  // out the whole playable area once fog of war had drawn a frame.
  constexpr std::array<std::uint16_t, 36> kUnitBoxIndices = {{
    4, 1, 0, 1, 4, 5,
    5, 2, 1, 2, 5, 6,
    6, 3, 2, 3, 6, 7,
    0, 3, 7, 7, 4, 0,
    7, 5, 4, 7, 6, 5,
    0, 2, 3, 0, 1, 2,
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

    auto* const device = gpg::gal::Device::GetInstance();
    if (!device) {
      return;
    }

    mGeometry.mVertexFormat = device->CreateVertexFormat(1u);

    gpg::gal::VertexBufferContext vertexBufferContext{};
    vertexBufferContext.vertexCount_ = static_cast<std::uint32_t>(kUnitBoxVertices.size());
    vertexBufferContext.stride_ = sizeof(BoxVertex);
    vertexBufferContext.type_ = 1u;
    vertexBufferContext.usage_ = 1u;
    mGeometry.mVertexBuffer = device->CreateVertexBuffer(&vertexBufferContext);

    gpg::gal::IndexBufferContext indexBufferContext{};
    indexBufferContext.size_ = static_cast<std::uint32_t>(kUnitBoxIndices.size());
    indexBufferContext.format_ = 1u;
    indexBufferContext.type_ = 1u;
    mGeometry.mIndexBuffer = device->CreateIndexBuffer(&indexBufferContext);

    if (mGeometry.mVertexBuffer) {
      void* const vertexStorage =
        mGeometry.mVertexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
      if (vertexStorage) {
        // Raw GPU upload: static unit-box vertex blob into the locked buffer.
        std::copy(kUnitBoxVertices.begin(), kUnitBoxVertices.end(), static_cast<decltype(kUnitBoxVertices)::value_type*>(vertexStorage));
      }
      mGeometry.mVertexBuffer->Unlock();
    }

    if (mGeometry.mIndexBuffer) {
      std::int16_t* const indexStorage =
        mGeometry.mIndexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
      if (indexStorage) {
        // Raw GPU upload: static unit-box index blob into the locked buffer.
        std::copy(kUnitBoxIndices.begin(), kUnitBoxIndices.end(), indexStorage);
      }
      mGeometry.mIndexBuffer->Unlock();
    }
  }
} // namespace moho
