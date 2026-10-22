// Engine addition, not in the shipped binary (see ProjectileIconRenderer.h).

#include "ProjectileIconRenderer.h"

#include <algorithm>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Texture.hpp"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  bool ren_GpuProjectileIcons = false;

  TConVar<bool> gTConVar_ren_GpuProjectileIcons(
    "ren_GpuProjectileIcons",
    "Draw projectile icons with one instanced draw per view (Direct3D 11 and later). Same icons, same "
    "order, same atlas. 0, the default, draws them through the prim batcher as the original does.",
    &ren_GpuProjectileIcons
  );

  namespace
  {
    // A view not drawn for this many draws gives its buffer back.
    constexpr std::uint64_t kStreamIdleDraws = 600U;
    /// The projectile pass's vertex colour (`kProjectileIconColor`).
    constexpr std::uint32_t kIconVertexColor = 0xFFFFFFFFU;

    struct DrawConstants
    {
      VMatrix4 composite;
      float alphaMultiplier;
      float unused[3];
    };
    static_assert(sizeof(DrawConstants) % 16 == 0, "constant blocks are whole float4s");

    gpg::gal::Device* sDeviceOfResources = nullptr;
  } // namespace

  ProjectileIconRenderer& ProjectileIconRenderer::Get()
  {
    static ProjectileIconRenderer sRenderer;
    return sRenderer;
  }

  bool ProjectileIconRenderer::IsActive()
  {
    if (!ren_GpuProjectileIcons) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (mInitialized && device != sDeviceOfResources) {
      *this = ProjectileIconRenderer();
    }
    if (!mInitialized) {
      mInitialized = true;
      sDeviceOfResources = device;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "ProjectileIcon";
        desc.source = kProjectileIconShaderSource;
        desc.sourceBytes = sizeof(kProjectileIconShaderSource) - 1U;
        desc.vertexEntry = "ProjectileIconVS";
        desc.pixelEntry = "ProjectileIconPS";
        // TAlphaBlendLinearSampleNoDepth: AlphaBlend_SrcAlpha_InvSrcAlpha_Write_RGB,
        // Rasterizer_Cull_None, Depth_Disable, LinearSampler (clamp).
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
        gpg::Logf("Projectile icons: GPU-instanced path (ren_GpuProjectileIcons)");
      }
    }
    return mSupported;
  }

  void ProjectileIconRenderer::Begin(const void* const viewKey)
  {
    mViewKey = viewKey;
    mPending.clear();
    mTextures.clear();
    mSlotOf.clear();
    mLastTexture = nullptr;
    mLastSlot = 0U;
  }

  void ProjectileIconRenderer::Add(
    const boost::shared_ptr<CD3DBatchTexture>& texture,
    const float centerX,
    const float centerY,
    const float halfWidth,
    const float halfHeight
  )
  {
    // Runs of one texture are the common case (one army colour after another).
    std::uint32_t slot = mLastSlot;
    if (texture.get() != mLastTexture || mTextures.empty()) {
      auto [found, inserted] = mSlotOf.emplace(texture.get(), static_cast<std::uint32_t>(mTextures.size()));
      if (inserted) {
        mTextures.push_back(texture);
      }
      slot = found->second;
      mLastTexture = texture.get();
      mLastSlot = slot;
    }
    ProjectileIconInstance& record = mPending.emplace_back();
    record.mCenter[0] = centerX;
    record.mCenter[1] = centerY;
    record.mHalfExtent[0] = halfWidth;
    record.mHalfExtent[1] = halfHeight;
    record.mSlot = slot;
  }

  ProjectileIconRenderer::ViewStream& ProjectileIconRenderer::StreamFor(const void* const viewKey)
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

  bool ProjectileIconRenderer::Flush(CD3DPrimBatcher& batcher)
  {
    if (mPending.empty()) {
      return true;
    }
    if (!mSupported || batcher.mTextureBatcher == nullptr) {
      return false;
    }
    ++mDraws;

    // The atlas rectangle `CD3DPrimBatcher::SetTexture` uses for each texture; a
    // texture the batcher would send around the atlas is left to the batcher.
    CD3DTextureBatcher& atlas = *batcher.mTextureBatcher;
    const auto atlasHalfWidth = static_cast<std::uint32_t>(atlas.mWidth) >> 1U;
    const auto atlasHalfHeight = static_cast<std::uint32_t>(atlas.mHeight) >> 1U;
    const auto refresh = [&]() -> bool {
      mSlots.resize(mTextures.size());
      for (std::size_t index = 0; index < mTextures.size(); ++index) {
        const boost::shared_ptr<CD3DBatchTexture>& texture = mTextures[index];
        if (!texture || texture->mWidth >= atlasHalfWidth || texture->mHeight >= atlasHalfHeight) {
          return false;
        }
        const gpg::Rect2f* const rect = atlas.AddTexture(texture);
        if (rect == nullptr) {
          return false;
        }
        mSlots[index].mUv[0] = rect->x0;
        mSlots[index].mUv[1] = rect->z0;
        mSlots[index].mUv[2] = rect->x1 - rect->x0;
        mSlots[index].mUv[3] = rect->z1 - rect->z0;
      }
      return true;
    };
    // Anything the batcher still holds was submitted before these icons.
    batcher.Flush();
    if (!refresh()) {
      // Full: start the atlas over, as `SetTexture` does when it runs out.
      atlas.Reset();
      if (!refresh()) {
        return false;
      }
    }
    const boost::shared_ptr<ID3DTextureSheet> sheet = atlas.GetCompositeTexture();
    if (sheet.get() == nullptr) {
      return false;
    }
    ID3DTextureSheet::TextureHandle atlasTexture;
    (void)sheet->GetTexture(atlasTexture);
    if (atlasTexture.get() == nullptr) {
      return false;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const auto slotCount = static_cast<std::uint32_t>(mSlots.size());
    if (slotCount > mSlotCapacity || mSlotBuffer == nullptr) {
      mSlotCapacity = std::max<std::uint32_t>(64U, slotCount * 2U);
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "ProjectileIconSlots";
      desc.stride = sizeof(ProjectileIconSlot);
      desc.capacity = mSlotCapacity;
      mSlotBuffer = device->CreateGpuBuffer(desc);
      if (mSlotBuffer == nullptr) {
        return false;
      }
    }
    device->UpdateGpuBuffer(*mSlotBuffer, 0U, slotCount, mSlots.data());

    ViewStream& stream = StreamFor(mViewKey);
    gpg::gal::GpuBuffer* const records = stream.mRecords.Update(mPending.data(), mPending.size());
    if (records == nullptr) {
      return false;
    }

    DrawConstants constants{};
    constants.composite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);
    constants.alphaMultiplier = batcher.mAlphaMultiplier;

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = records;
    call.bindings.readBuffers[1] = mSlotBuffer.get();
    call.bindings.textures[0] = atlasTexture.get();
    call.vertexCountPerInstance = kProjectileIconVerticesPerInstance;
    call.instanceCount = static_cast<std::uint32_t>(mPending.size());
    device->DrawGpuProgram(call);

    mPending.clear();
    return true;
  }

  void ProjectileIconRenderer::DrawWithBatcher(CD3DPrimBatcher& batcher)
  {
    for (const ProjectileIconInstance& record : mPending) {
      batcher.SetTexture(mTextures[record.mSlot]);
      const float left = record.mCenter[0] - record.mHalfExtent[0];
      const float right = record.mCenter[0] + record.mHalfExtent[0];
      const float top = record.mCenter[1] - record.mHalfExtent[1];
      const float bottom = record.mCenter[1] + record.mHalfExtent[1];
      const CD3DPrimBatcher::Vertex topLeft{left, top, 1.0f, kIconVertexColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex topRight{left, bottom, 1.0f, kIconVertexColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 1.0f, kIconVertexColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{right, top, 1.0f, kIconVertexColor, 1.0f, 1.0f};
      batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
    mPending.clear();
  }
} // namespace moho
