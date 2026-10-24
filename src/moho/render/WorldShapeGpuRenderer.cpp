// Engine addition, not in the shipped binary (see WorldShapeGpuRenderer.h).

#include "WorldShapeGpuRenderer.h"

#include <algorithm>
#include <cmath>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Texture.hpp"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/GpuPathSettings.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  int ren_GpuShapes = -1;

  TConVar<int> gTConVar_ren_GpuShapes(
    "ren_GpuShapes",
    "Draw FAF's UI_DrawLine/UI_DrawRect/UI_DrawCircle shapes with instanced draws from a GPU buffer instead of the "
    "prim batcher. -1 (auto, the default) turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuShapes
  );

  namespace
  {
    // A view not drawn for this many draws gives its buffer back.
    constexpr std::uint64_t kStreamIdleDraws = 600U;

    struct DrawConstants
    {
      VMatrix4 composite;
      float uvTransform[4];
      float alphaMultiplier;
      std::uint32_t baseRecord;
      std::uint32_t kind;
      std::uint32_t unused;
      float ovalCosSin[kDrawOvalSegmentCount * 2U];
    };
    static_assert(sizeof(DrawConstants) % 16 == 0, "constant blocks are whole float4s");
    static_assert(sizeof(DrawConstants) <= gpg::gal::kGpuMaxConstantBytes, "constant block too large");

    gpg::gal::Device* sDeviceOfResources = nullptr;

    [[nodiscard]] Vector3f PointOf(const WorldShapeRecord& record, const std::size_t index) noexcept
    {
      return {record.mPoints[index][0], record.mPoints[index][1], record.mPoints[index][2]};
    }
  } // namespace

  void DrawWorldShape(CD3DPrimBatcher& batcher, const WorldShapeRecord& record)
  {
    switch (record.mKind) {
      case WorldShapeKind::Line:
        batcher.DrawQuad(PointOf(record, 0), PointOf(record, 1), PointOf(record, 2), PointOf(record, 3), record.mColor);
        break;
      case WorldShapeKind::Rect: {
        // `DRAW_Rect` without a height field (0x00455D84..0x00455E10).
        const Vector3f outer[4] = {PointOf(record, 0), PointOf(record, 1), PointOf(record, 2), PointOf(record, 3)};
        const Vector3f inner[4] = {PointOf(record, 4), PointOf(record, 5), PointOf(record, 6), PointOf(record, 7)};
        batcher.DrawQuad(outer[0], inner[0], inner[1], outer[1], record.mColor);
        batcher.DrawQuad(outer[1], inner[1], inner[2], outer[2], record.mColor);
        batcher.DrawQuad(inner[3], outer[3], outer[2], inner[2], record.mColor);
        batcher.DrawQuad(outer[0], outer[3], inner[3], inner[0], record.mColor);
        break;
      }
      case WorldShapeKind::Circle:
        DRAW_Oval(
          &batcher, PointOf(record, 0), PointOf(record, 1), PointOf(record, 2), PointOf(record, 3), PointOf(record, 4),
          record.mColor
        );
        break;
    }
  }

  WorldShapeGpuRenderer& WorldShapeGpuRenderer::Get()
  {
    static WorldShapeGpuRenderer sRenderer;
    return sRenderer;
  }

  bool WorldShapeGpuRenderer::IsActive()
  {
    if (!GpuPathEnabled(ren_GpuShapes, gpg::gal::kGpuPathWorldShapes, gpg::gal::kGpuFeatureVertexPulling)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (mInitialized && device != sDeviceOfResources) {
      // A new device: everything built on the old one is gone.
      *this = WorldShapeGpuRenderer();
    }
    if (!mInitialized) {
      mInitialized = true;
      sDeviceOfResources = device;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "WorldShape";
        desc.source = kWorldShapeShaderSource;
        desc.sourceBytes = sizeof(kWorldShapeShaderSource) - 1U;
        desc.vertexEntry = "WorldShapeVS";
        desc.pixelEntry = "WorldShapePS";
        // TAlphaBlendLinearSampleNoDepth: AlphaBlend_SrcAlpha_InvSrcAlpha_Write_RGB,
        // Depth_Disable, Rasterizer_Cull_None, LinearSampler (clamp).
        desc.blend = gpg::gal::GpuBlend::AlphaBlend;
        desc.colorWriteMask = 0x07U;
        desc.depthTest = false;
        desc.depthWrite = false;
        desc.cullBackFaces = false;
        desc.sampler = gpg::gal::GpuSampler::LinearClamp;
        mProgram = device->CreateGpuProgram(desc);
      }
      mSupported = mProgram != nullptr;
      if (mSupported) {
        gpg::Logf("World shapes: GPU-instanced path (ren_GpuShapes)");
      }
    }
    return mSupported;
  }

  WorldShapeGpuRenderer::ViewStream& WorldShapeGpuRenderer::StreamFor(const void* const viewKey)
  {
    for (ViewStream& stream : mStreams) {
      if (stream.mViewKey == viewKey) {
        stream.mLastUsedDraw = mDraws;
        return stream;
      }
    }
    std::erase_if(mStreams, [this](const ViewStream& stream) { return mDraws - stream.mLastUsedDraw > kStreamIdleDraws; });
    ViewStream& stream = mStreams.emplace_back();
    stream.mViewKey = viewKey;
    stream.mLastUsedDraw = mDraws;
    return stream;
  }

  bool WorldShapeGpuRenderer::Draw(
    CD3DPrimBatcher& batcher, const void* const viewKey, const std::span<const WorldShapeRecord> records
  )
  {
    if (!mSupported || batcher.mTextureBatcher == nullptr) {
      return false;
    }
    ++mDraws;
    if (records.empty()) {
      return true;
    }

    // The solid white texture the pass bound with `SetTexture`; its atlas
    // rectangle gives the same uv transform the batcher applies.
    const boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFU);
    CD3DTextureBatcher& atlas = *batcher.mTextureBatcher;
    if (!texture || texture->mWidth >= (static_cast<std::uint32_t>(atlas.mWidth) >> 1U) ||
        texture->mHeight >= (static_cast<std::uint32_t>(atlas.mHeight) >> 1U)) {
      return false;
    }
    const gpg::Rect2f* rect = atlas.AddTexture(texture);
    if (rect == nullptr) {
      // Full: start the atlas over, as `SetTexture` does, after drawing what the batcher holds.
      batcher.Flush();
      atlas.Reset();
      rect = atlas.AddTexture(texture);
      if (rect == nullptr) {
        return false;
      }
    }

    // Anything the batcher still holds was submitted before the shapes.
    batcher.Flush();
    const boost::shared_ptr<ID3DTextureSheet> sheet = atlas.GetCompositeTexture();
    if (sheet.get() == nullptr) {
      return false;
    }
    ID3DTextureSheet::TextureHandle atlasTexture;
    (void)sheet->GetTexture(atlasTexture);
    if (atlasTexture.get() == nullptr) {
      return false;
    }

    ViewStream& stream = StreamFor(viewKey);
    gpg::gal::GpuBuffer* const buffer = stream.mRecords.Update(records.data(), records.size());
    if (buffer == nullptr) {
      return false;
    }

    DrawConstants constants{};
    constants.composite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);
    constants.uvTransform[0] = rect->x1 - rect->x0;
    constants.uvTransform[1] = rect->z1 - rect->z0;
    constants.uvTransform[2] = rect->x0;
    constants.uvTransform[3] = rect->z0;
    constants.alphaMultiplier = batcher.mAlphaMultiplier;
    // `DRAW_Oval`'s own cos/sin of each segment angle, so the vertex shader
    // places every circle vertex where the batcher path does.
    for (std::uint32_t segment = 0; segment < kDrawOvalSegmentCount; ++segment) {
      const float angle = DRAW_OvalSegmentAngle(segment);
      constants.ovalCosSin[segment * 2U] = std::cos(angle);
      constants.ovalCosSin[segment * 2U + 1U] = std::sin(angle);
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.readBuffers[0] = buffer;
    call.bindings.textures[0] = atlasTexture.get();

    // One draw per run of same-kind records keeps the submission order.
    std::size_t runStart = 0U;
    while (runStart < records.size()) {
      const WorldShapeKind kind = records[runStart].mKind;
      std::size_t runEnd = runStart + 1U;
      while (runEnd < records.size() && records[runEnd].mKind == kind) {
        ++runEnd;
      }
      constants.baseRecord = static_cast<std::uint32_t>(runStart);
      constants.kind = static_cast<std::uint32_t>(kind);
      call.bindings.constants = &constants;
      call.bindings.constantBytes = sizeof(constants);
      call.vertexCountPerInstance = WorldShapeQuadCount(kind) * 6U;
      call.instanceCount = static_cast<std::uint32_t>(runEnd - runStart);
      device->DrawGpuProgram(call);
      runStart = runEnd;
    }
    return true;
  }
} // namespace moho
