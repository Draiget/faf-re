#include "moho/render/VisionRenderer.h"

#include <array>
#include <cmath>
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
  constexpr std::uint32_t kVisionSegmentCount = 45u;
  constexpr std::uint32_t kVisionVertexCount = (kVisionSegmentCount * 2u) + 2u; // 92
  constexpr std::uint32_t kVisionIndexCount = kVisionSegmentCount * 12u;         // 540
  constexpr float kVisionAngleStep = 0.13962634f;                                 // 2*pi/45
  constexpr float kVisionMaxMapHeight = 256.0f;
  constexpr float kVisionMinMapHeight = -256.0f;
}

namespace moho
{
  /**
   * Address: 0x0081BF10 (FUN_0081BF10, Moho::VisionRenderer::VisionRenderer)
   */
  VisionRenderer::VisionRenderer()
    : mIndexCount(0)
    , mVertexCount(0)
    , mGeometry()
    , mUnknown24(0)
    , mVertexBuffer2()
    , mFrame()
  {}

  /**
   * Address: 0x0081BF70 (FUN_0081BF70, Moho::VisionRenderer::dtr)
   * Address: 0x0081BF90 (FUN_0081BF90, Moho::VisionRenderer::~VisionRenderer)
   */
  VisionRenderer::~VisionRenderer()
  {
    ResetRenderResources();
  }

  /**
   * Address: 0x0081C550 (FUN_0081C550, sub_81C550)
   */
  void VisionRenderer::ResetRenderResources() noexcept
  {
    mFrame.ResetTransientResources();
    mGeometry.Reset();
    mVertexBuffer2.reset();
    mIndexCount = 0;
    mVertexCount = 0;
  }

  /**
   * Address: 0x0081C0C0 (FUN_0081C0C0, Moho::VisionRenderer::Init)
   */
  void VisionRenderer::Init()
  {
    ResetRenderResources();

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    if (!device) {
      return;
    }

    device->CreateVertexFormat(&mGeometry.mVertexFormat, 18u);

    mVertexCount = kVisionVertexCount;
    mIndexCount = kVisionIndexCount;

    gpg::gal::VertexBufferContext vertexBuffer1Context{};
    vertexBuffer1Context.width_ = mVertexCount;
    vertexBuffer1Context.height_ = 12u;
    vertexBuffer1Context.type_ = 2u;
    vertexBuffer1Context.usage_ = 1u;
    device->CreateVertexBuffer(&mGeometry.mVertexBuffer, &vertexBuffer1Context);

    gpg::gal::VertexBufferContext vertexBuffer2Context{};
    vertexBuffer2Context.width_ = 12288u;
    vertexBuffer2Context.height_ = 12u;
    vertexBuffer2Context.type_ = 3u;
    vertexBuffer2Context.usage_ = 2u;
    device->CreateVertexBuffer(&mVertexBuffer2, &vertexBuffer2Context);

    mUnknown24 = 0;

    gpg::gal::IndexBufferContext indexBufferContext{};
    indexBufferContext.format_ = 1u;
    indexBufferContext.size_ = mIndexCount;
    indexBufferContext.type_ = 1u;
    device->CreateIndexBuffer(&mGeometry.mIndexBuffer, &indexBufferContext);

    if (mGeometry.mVertexBuffer) {
      float* const vertexData = static_cast<float*>(
        mGeometry.mVertexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0))
      );
      if (vertexData) {
        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const float angle = static_cast<float>(i) * kVisionAngleStep;
          const float cosValue = std::cos(angle);
          const float sinValue = std::sin(angle);

          const std::uint32_t topBase = i * 3u;
          vertexData[topBase + 0u] = cosValue;
          vertexData[topBase + 1u] = kVisionMaxMapHeight;
          vertexData[topBase + 2u] = sinValue;

          const std::uint32_t bottomBase = (kVisionSegmentCount * 3u) + (i * 3u);
          vertexData[bottomBase + 0u] = cosValue;
          vertexData[bottomBase + 1u] = kVisionMinMapHeight;
          vertexData[bottomBase + 2u] = sinValue;
        }

        const std::uint32_t topCenterBase = (kVisionSegmentCount * 2u) * 3u;
        vertexData[topCenterBase + 0u] = 0.0f;
        vertexData[topCenterBase + 1u] = kVisionMaxMapHeight;
        vertexData[topCenterBase + 2u] = 0.0f;

        const std::uint32_t bottomCenterBase = topCenterBase + 3u;
        vertexData[bottomCenterBase + 0u] = 0.0f;
        vertexData[bottomCenterBase + 1u] = kVisionMinMapHeight;
        vertexData[bottomCenterBase + 2u] = 0.0f;
      }

      mGeometry.mVertexBuffer->Unlock();
    }

    if (mGeometry.mIndexBuffer) {
      std::int16_t* const indexData = mGeometry.mIndexBuffer->Lock(
        0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0)
      );
      if (indexData) {
        std::uint32_t outIndex = 0u;

        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const std::uint16_t next = static_cast<std::uint16_t>((i + 1u) % kVisionSegmentCount);
          const std::uint16_t current = static_cast<std::uint16_t>(i);
          const std::uint16_t currentBottom = static_cast<std::uint16_t>(i + kVisionSegmentCount);
          const std::uint16_t nextBottom = static_cast<std::uint16_t>(next + kVisionSegmentCount);

          indexData[outIndex++] = static_cast<std::int16_t>(current);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(nextBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
        }

        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const std::uint16_t next = static_cast<std::uint16_t>((i + 1u) % kVisionSegmentCount);
          const std::uint16_t current = static_cast<std::uint16_t>(i);
          const std::uint16_t nextBottom = static_cast<std::uint16_t>(next + kVisionSegmentCount);
          const std::uint16_t currentBottom = static_cast<std::uint16_t>(i + kVisionSegmentCount);

          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(90u);
          indexData[outIndex++] = static_cast<std::int16_t>(current);
          indexData[outIndex++] = static_cast<std::int16_t>(nextBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(91u);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
        }
      }

      mGeometry.mIndexBuffer->Unlock();
    }
  }
} // namespace moho
