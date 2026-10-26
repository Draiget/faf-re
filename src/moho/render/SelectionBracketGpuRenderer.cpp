// Engine addition, not in the shipped binary (see SelectionBracketGpuRenderer.h).

#include "SelectionBracketGpuRenderer.h"

#include <algorithm>

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
  int ren_GpuSelectBrackets = -1;

  TConVar<int> gTConVar_ren_GpuSelectBrackets(
    "ren_GpuSelectBrackets",
    "Draw selection brackets with one instanced draw per view from a persistent GPU buffer instead of the "
    "prim batcher. -1 (auto, the default) turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuSelectBrackets
  );

  namespace
  {
    // A view not drawn for this many draws gives its buffer back.
    constexpr std::uint64_t kStreamIdleDraws = 600U;

    struct DrawConstants
    {
      VMatrix4 composite;
      float atlasRect[4];
      float color[4];
      float alphaMultiplier;
      float unused[3];
    };
    static_assert(sizeof(DrawConstants) % 16 == 0, "constant blocks are whole float4s");

    gpg::gal::Device* sDeviceOfResources = nullptr;
  } // namespace

  SelectionBracketGpuRenderer& SelectionBracketGpuRenderer::Get()
  {
    static SelectionBracketGpuRenderer sRenderer;
    return sRenderer;
  }

  bool SelectionBracketGpuRenderer::IsActive()
  {
    if (!GpuPathEnabled(ren_GpuSelectBrackets, gpg::gal::kGpuPathSelectBrackets, gpg::gal::kGpuFeatureVertexPulling)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (mInitialized && device != sDeviceOfResources) {
      // A new device: everything built on the old one is gone.
      *this = SelectionBracketGpuRenderer();
    }
    if (!mInitialized) {
      mInitialized = true;
      sDeviceOfResources = device;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "SelectionBracket";
        desc.source = kSelectionBracketShaderSource;
        desc.sourceBytes = sizeof(kSelectionBracketShaderSource) - 1U;
        desc.vertexEntry = "SelectionBracketVS";
        desc.pixelEntry = "SelectionBracketPS";
        // TAlphaBlendLinearSample: AlphaBlend_SrcAlpha_InvSrcAlpha_Write_RGB,
        // Rasterizer_Cull_None, LinearSampler (clamp). Its pass sets no depth
        // state, so the batcher draws it with the technique's begin pack:
        // depth test LESS_EQUAL with writes, no stencil. Not the state the
        // previous pass left bound - this draw runs before the batcher begins
        // the technique, and on Dual Gap that leftover state hid every bracket.
        desc.blend = gpg::gal::GpuBlend::AlphaBlend;
        desc.colorWriteMask = 0x07U;
        desc.depthTest = true;
        desc.depthWrite = true;
        desc.depthFunc = gpg::gal::GpuCompare::LessEqual;
        desc.cullBackFaces = false;
        desc.sampler = gpg::gal::GpuSampler::LinearClamp;
        mProgram = device->CreateGpuProgram(desc);
      }
      mSupported = mProgram != nullptr;
      if (mSupported) {
        gpg::Logf("Selection brackets: GPU-instanced path (ren_GpuSelectBrackets)");
      }
    }
    return mSupported;
  }

  SelectionBracketGpuRenderer::ViewStream& SelectionBracketGpuRenderer::StreamFor(const void* const viewKey)
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

  bool SelectionBracketGpuRenderer::Draw(
    CD3DPrimBatcher& batcher,
    const void* const viewKey,
    const boost::shared_ptr<CD3DBatchTexture>& texture,
    const std::uint32_t color,
    const std::span<const SelectionBracketInstance> instances
  )
  {
    if (!mSupported || batcher.mTextureBatcher == nullptr || !texture) {
      return false;
    }
    ++mDraws;
    if (instances.empty()) {
      return true;
    }

    // The atlas rectangle `CD3DPrimBatcher::SetTexture` would use; a texture
    // the batcher sends around the atlas is left to the batcher.
    CD3DTextureBatcher& atlas = *batcher.mTextureBatcher;
    if (texture->mWidth >= (static_cast<std::uint32_t>(atlas.mWidth) >> 1U) ||
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
    const float atlasRect[4] = {rect->x0, rect->z0, rect->x1 - rect->x0, rect->z1 - rect->z0};

    // Anything the batcher still holds was submitted before the brackets.
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
    gpg::gal::GpuBuffer* const records = stream.mInstances.Update(instances.data(), instances.size());
    if (records == nullptr) {
      return false;
    }

    DrawConstants constants{};
    constants.composite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);
    std::copy_n(atlasRect, 4, constants.atlasRect);
    // The vertex colour as D3DCOLOR (ARGB) reaches the pixel shader.
    constants.color[0] = static_cast<float>((color >> 16U) & 0xFFU) / 255.0f;
    constants.color[1] = static_cast<float>((color >> 8U) & 0xFFU) / 255.0f;
    constants.color[2] = static_cast<float>(color & 0xFFU) / 255.0f;
    constants.color[3] = static_cast<float>(color >> 24U) / 255.0f;
    constants.alphaMultiplier = batcher.mAlphaMultiplier;

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = records;
    call.bindings.textures[0] = atlasTexture.get();
    call.vertexCountPerInstance = kSelectionBracketVerticesPerInstance;
    call.instanceCount = static_cast<std::uint32_t>(instances.size());
    gpg::gal::Device::GetInstance()->DrawGpuProgram(call);
    return true;
  }
} // namespace moho
