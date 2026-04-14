#include "moho/render/SkyDome.h"

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
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DVertexFormat.h"

namespace
{
  struct SkyDomeVertex
  {
    float x;
    float y;
    float z;
    float u;
    float v;
  };

  static_assert(sizeof(SkyDomeVertex) == 0x14, "SkyDomeVertex size must be 0x14");

  constexpr float kHalfPi = 1.5707964f;
  constexpr float kTwoPi = 6.2831855f;

  constexpr std::array<float, 8> kDecalBillboardQuadVertices = {
    -1.0f, 1.0f,
    -1.0f, -1.0f,
    1.0f, 1.0f,
    1.0f, -1.0f,
  };

  constexpr std::array<std::int16_t, 6> kDecalQuadIndices = {
    0, 1, 2,
    2, 1, 3,
  };
} // namespace

namespace moho
{
  /**
   * Address: 0x008149E0 (FUN_008149E0, ??0SkyDome@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes all sky dome rendering state to defaults — horizon/sky colors,
   * texture paths, zero-initialized shared_ptr resource handles, and copies
   * static cirrus data.
   */
  SkyDome::SkyDome()
    : mHorizonLookupPath("/textures/environment/horizonLookup.dds")
    , mCirrusTexPath("/textures/environment/cirrus000.dds")
  {
  }

  /**
   * Address: 0x008177B0 (FUN_008177B0, ?CreateRenderAbility@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Loads all textures, creates the dome vertex format, builds dome and decal
   * vertex/index buffers from the current sky parameters.
   */
  void SkyDome::CreateRenderAbility()
  {
    CreateTextures();
    CreateDomeFormat();
    CreateDomeVertexBuffer(mDomeShapeParams.x, mDomeShapeParams.y, mDomeShapeParams.z, mWidth, mHeight);
    CreateDomeIndexBuffer(mWidth, mHeight);
    CreateDecalFormat();
    CreateDecalVertexBuffers();
    CreateDecalIndexBuffer();
  }

  /**
   * Address: 0x00817810 (FUN_00817810, ?GetEffect@SkyDome@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Looks up the "sky" shader effect from the active D3D device resources.
   */
  boost::shared_ptr<gpg::gal::Effect> SkyDome::GetEffect()
  {
    // The binary returns the same shared_ptr backing-store that
    // CD3DEffect::GetBaseEffect() does, but the recovered SDK currently models
    // EffectD3D9 and Effect as unrelated `gpg::gal::*` classes (no shared
    // base) so the implicit upcast of `shared_ptr<EffectD3D9>` to
    // `shared_ptr<Effect>` doesn't compile. Re-enable the lookup once the
    // Effect / EffectD3D9 inheritance is recovered.
    (void)D3D_GetDevice()->GetResources()->FindEffect("sky");
    return {};
  }

  /**
   * Address: 0x008180A0 (FUN_008180A0, ?CreateDomeFormat@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates one dome vertex-format descriptor (format token `3`) when it is
   * not already present.
   */
  void SkyDome::CreateDomeFormat()
  {
    if (!mDomeFormat) {
      mDomeFormat = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(3U));
    }
  }

  /**
   * Address: 0x00818630 (FUN_00818630, ?CreateDecalFormat@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates the two sky-decal vertex-format descriptors (format tokens `20`
   * and `21`) when they are not already present.
   */
  void SkyDome::CreateDecalFormat()
  {
    if (!mDecalFormat1) {
      mDecalFormat1 = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(20U));
      mDecalFormat2 = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(21U));
    }
  }

  /**
   * Address: 0x00818170 (FUN_00818170, ?CreateDomeVertexBuffer@SkyDome@Moho@@AAEXMMMHH@Z)
   *
   * What it does:
   * Creates and fills the sky dome vertex buffer from polar rings and one apex
   * vertex, using the serialized dome origin/shape parameters.
   */
  void SkyDome::CreateDomeVertexBuffer(
    const float verticalOffset,
    const float domeRadius,
    const float startAngleRadians,
    const int widthSegments,
    const int heightSegments
  )
  {
    if (mDomeVertBuf) {
      return;
    }

    const float invWidth = 1.0f / static_cast<float>(widthSegments);
    const float verticalStep = (kHalfPi - startAngleRadians) / static_cast<float>(heightSegments);
    const float radiusDivCos = domeRadius / std::cos(startAngleRadians);
    const float baseHeight = radiusDivCos * std::sin(startAngleRadians);

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const int widthPlusOne = widthSegments + 1;
    mDomeVertexCount = (heightSegments * widthPlusOne) + 1;

    gpg::gal::VertexBufferContext context{};
    context.width_ = static_cast<std::uint32_t>(mDomeVertexCount);
    context.height_ = sizeof(SkyDomeVertex);
    context.type_ = 1u;
    context.usage_ = 1u;
    device->CreateVertexBuffer(&mDomeVertBuf, &context);

    auto* const vertices = static_cast<SkyDomeVertex*>(
      mDomeVertBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0))
    );

    int vertexWriteIndex = 0;
    for (int row = 0; row < heightSegments; ++row) {
      const float rowAngle = startAngleRadians + (static_cast<float>(row) * verticalStep);
      const float ringRadius = std::cos(rowAngle) * radiusDivCos;
      const float ringHeight = (std::sin(rowAngle) * radiusDivCos) - baseHeight;

      for (int column = 0; column < widthPlusOne; ++column) {
        const float azimuth = (static_cast<float>(column) * invWidth) * kTwoPi;
        SkyDomeVertex& vertex = vertices[vertexWriteIndex++];
        vertex.x = (std::cos(azimuth) * ringRadius) + mDomeOrigin.x;
        vertex.y = ringHeight + mDomeOrigin.y + verticalOffset;
        vertex.z = (std::sin(azimuth) * ringRadius) + mDomeOrigin.z;
        vertex.u = azimuth;
        vertex.v = 0.0f;
      }
    }

    SkyDomeVertex& apex = vertices[vertexWriteIndex];
    apex.x = mDomeOrigin.x;
    apex.y = (radiusDivCos - baseHeight) + mDomeOrigin.y + verticalOffset;
    apex.z = mDomeOrigin.z;
    apex.u = 0.0f;
    apex.v = 0.0f;

    mDomeVertBuf->Unlock();
  }

  /**
   * Address: 0x00818410 (FUN_00818410, ?CreateDomeIndexBuffer@SkyDome@Moho@@AAEXHH@Z)
   *
   * What it does:
   * Creates one 16-bit index buffer for dome strips and one apex fan.
   */
  void SkyDome::CreateDomeIndexBuffer(const int widthSegments, const int heightSegments)
  {
    if (mDomeIndexBuf) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    mDomeIndexCount = widthSegments * ((6 * (heightSegments - 1)) + 3);

    gpg::gal::IndexBufferContext context{};
    context.size_ = static_cast<std::uint32_t>(mDomeIndexCount);
    context.format_ = 1u;
    context.type_ = 1u;
    device->CreateIndexBuffer(&mDomeIndexBuf, &context);

    std::int16_t* const indices = mDomeIndexBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    int writeIndex = 0;

    for (int ring = 0; ring < heightSegments - 1; ++ring) {
      const int base = ring * (widthSegments + 1);
      std::int16_t topLeft = static_cast<std::int16_t>(base + 1);
      std::int16_t topRight = static_cast<std::int16_t>(base + widthSegments + 1);
      std::int16_t bottomRight = static_cast<std::int16_t>(base + widthSegments + 2);

      for (int column = 0; column < widthSegments; ++column) {
        const std::int16_t bottomLeft = static_cast<std::int16_t>(base + column);
        indices[writeIndex++] = topLeft;
        indices[writeIndex++] = topRight;
        indices[writeIndex++] = bottomLeft;
        indices[writeIndex++] = topRight;
        indices[writeIndex++] = topLeft;
        indices[writeIndex++] = bottomRight;
        ++topLeft;
        ++topRight;
        ++bottomRight;
      }
    }

    const int capBase = (heightSegments - 1) * (widthSegments + 1);
    for (int column = 0; column < widthSegments; ++column) {
      indices[writeIndex++] = static_cast<std::int16_t>(capBase + column + 1);
      indices[writeIndex++] = static_cast<std::int16_t>(mDomeVertexCount - 1);
      indices[writeIndex++] = static_cast<std::int16_t>(capBase + column);
    }

    mDomeIndexBuf->Unlock();
  }

  /**
   * Address: 0x00818780 (FUN_00818780, ?CreateDecalVertexBuffers@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates three decal vertex buffers and seeds the first one with the static
   * billboard quad coordinates used by sky decal rendering.
   */
  void SkyDome::CreateDecalVertexBuffers()
  {
    if (mDecalVertBuf1 && mDecalVertBuf2) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    gpg::gal::VertexBufferContext quadContext{};
    quadContext.width_ = 4u;
    quadContext.height_ = 8u;
    quadContext.type_ = 2u;
    quadContext.usage_ = 1u;
    device->CreateVertexBuffer(&mDecalVertBuf1, &quadContext);

    void* const quadVertices = mDecalVertBuf1->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    std::memcpy(quadVertices, kDecalBillboardQuadVertices.data(), sizeof(kDecalBillboardQuadVertices));
    mDecalVertBuf1->Unlock();

    gpg::gal::VertexBufferContext cumulusContext{};
    cumulusContext.width_ = 1024u;
    cumulusContext.height_ = 40u;
    cumulusContext.type_ = 3u;
    cumulusContext.usage_ = 2u;
    device->CreateVertexBuffer(&mDecalVertBuf2, &cumulusContext);

    gpg::gal::VertexBufferContext cirrusContext{};
    cirrusContext.width_ = 10000u;
    cirrusContext.height_ = 60u;
    cirrusContext.type_ = 3u;
    cirrusContext.usage_ = 2u;
    device->CreateVertexBuffer(&mDecalVertBuf3, &cirrusContext);
  }

  /**
   * Address: 0x00818A10 (FUN_00818A10, ?CreateDecalIndexBuffer@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates and fills the static six-index quad list used by decal rendering.
   */
  void SkyDome::CreateDecalIndexBuffer()
  {
    if (mDecalIndexBuf) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    gpg::gal::IndexBufferContext context{};
    context.size_ = 6u;
    context.format_ = 1u;
    context.type_ = 1u;
    device->CreateIndexBuffer(&mDecalIndexBuf, &context);

    std::int16_t* const indices = mDecalIndexBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    std::memcpy(indices, kDecalQuadIndices.data(), sizeof(kDecalQuadIndices));
    mDecalIndexBuf->Unlock();
  }
} // namespace moho
