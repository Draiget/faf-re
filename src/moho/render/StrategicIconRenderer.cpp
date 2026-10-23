// Engine addition, not in the shipped binary (see StrategicIconRenderer.h).

#include "StrategicIconRenderer.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <optional>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/Texture.hpp"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/GpuPathSettings.h"
#include "moho/render/StrategicIconClassifyShader.h"
#include "moho/render/StrategicIconShader.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  int ren_GpuIcons = -1;
  int ren_GpuIconClassify = -1;

  TConVar<int> gTConVar_ren_GpuIcons(
    "ren_GpuIcons",
    "Draw strategic icons with one instanced draw per view from a persistent GPU buffer instead of the "
    "prim batcher. -1 (auto, the default) turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuIcons
  );

  TConVar<int> gTConVar_ren_GpuIconClassify(
    "ren_GpuIconClassify",
    "With ren_GpuIcons and ui_IconRecords: decide which units get a strategic icon, in which run, and "
    "where, in a compute shader from per-unit records uploaded when a sync beat changes them, then draw "
    "them with one indirect draw per view. Same icons in the same order as the CPU classification. -1 (auto, the default) turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuIconClassify
  );

  namespace
  {
    constexpr std::uint32_t kVerticesPerIcon = 6U * StrategicIconInstance::kLayerCount;
    // A view not drawn for this many draws gives its buffer back.
    constexpr std::uint64_t kStreamIdleDraws = 600U;

    struct SlotRecord
    {
      float uv[4];
      float halfSize[2];
      float unused[2];
    };
    static_assert(sizeof(SlotRecord) == 32, "SlotRecord must match IconSlot");

    struct DrawConstants
    {
      VMatrix4 composite;
    };
    static_assert(sizeof(DrawConstants) % 16 == 0, "constant blocks are whole float4s");

    gpg::gal::Device* sDeviceOfResources = nullptr;
  } // namespace

  void StrategicIconInstance::SetPosition(const float screenX, const float screenY) noexcept
  {
    // The CPU path's corners are floored screen points; whole pixels fit 16 bits
    // for anything near the viewport, and farther points draw nothing either way.
    const auto clamp16 = [](const float value) -> std::uint32_t {
      const float clamped = std::clamp(value, -32768.0f, 32767.0f);
      return static_cast<std::uint32_t>(static_cast<std::int32_t>(clamped)) & 0xFFFFU;
    };
    mPosition = clamp16(screenX) | (clamp16(screenY) << 16U);
  }

  void StrategicIconInstance::SetLayer(const std::uint32_t layer, const std::uint16_t slot) noexcept
  {
    std::uint32_t& packed = layer < 2U ? mLayers01 : mLayers23;
    const std::uint32_t shift = (layer & 1U) * 16U;
    packed = (packed & ~(0xFFFFU << shift)) | (static_cast<std::uint32_t>(slot) << shift);
  }

  StrategicIconRenderer& StrategicIconRenderer::Get()
  {
    static StrategicIconRenderer sRenderer;
    return sRenderer;
  }

  bool StrategicIconRenderer::IsActive()
  {
    if (!GpuPathEnabled(ren_GpuIcons, gpg::gal::kGpuPathStrategicIcons, gpg::gal::kGpuFeatureVertexPulling)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (mInitialized && device != sDeviceOfResources) {
      // A new device: everything built on the old one is gone.
      *this = StrategicIconRenderer();
    }
    if (!mInitialized) {
      mInitialized = true;
      sDeviceOfResources = device;
      mSupported = (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0U && CreateResources();
      if (mSupported) {
        gpg::Logf("Strategic icons: GPU-driven path (ren_GpuIcons)");
      }
    }
    return mSupported;
  }

  bool StrategicIconRenderer::CreateResources()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::GpuProgramDesc desc{};
    desc.name = "StrategicIcon";
    desc.source = kStrategicIconShaderSource;
    desc.sourceBytes = sizeof(kStrategicIconShaderSource) - 1U;
    desc.vertexEntry = "StrategicIconVS";
    desc.pixelEntry = "StrategicIconPS";
    // TStrategicIcon: AlphaBlend_SrcAlpha_InvSrcAlpha_Write_RGB, Depth_Disable,
    // Rasterizer_Cull_None, PointSampler (clamp).
    desc.blend = gpg::gal::GpuBlend::AlphaBlend;
    desc.colorWriteMask = 0x07U;
    desc.depthTest = false;
    desc.depthWrite = false;
    desc.cullBackFaces = false;
    desc.sampler = gpg::gal::GpuSampler::PointClamp;
    mProgram = device->CreateGpuProgram(desc);
    return mProgram != nullptr;
  }

  std::uint16_t StrategicIconRenderer::FindSlot(const CD3DBatchTexture* const texture) const noexcept
  {
    const auto found = mSlotByTexture.find(texture);
    return found != mSlotByTexture.end() ? found->second : StrategicIconInstance::kNoLayer;
  }

  std::uint16_t StrategicIconRenderer::AddSlot(const boost::shared_ptr<CD3DBatchTexture>& texture)
  {
    if (!texture) {
      return StrategicIconInstance::kNoLayer;
    }
    if (const std::uint16_t existing = FindSlot(texture.get()); existing != StrategicIconInstance::kNoLayer) {
      return existing;
    }
    if (mSlots.size() >= StrategicIconInstance::kNoLayer) {
      return StrategicIconInstance::kNoLayer;
    }
    const auto slot = static_cast<std::uint16_t>(mSlots.size());
    Slot& added = mSlots.emplace_back();
    added.mTexture = texture;
    added.mHalfSize[0] = static_cast<float>(texture->mWidth >> 1U);
    added.mHalfSize[1] = static_cast<float>(texture->mHeight >> 1U);
    mSlotByTexture.emplace(texture.get(), slot);
    mSlotsDirty = true;
    return slot;
  }

  bool StrategicIconRenderer::RefreshAtlasSlots(CD3DPrimBatcher& batcher)
  {
    CD3DTextureBatcher& atlas = *batcher.mTextureBatcher;
    // CD3DPrimBatcher::SetTexture sends a texture this large around the atlas.
    const std::uint32_t atlasHalfWidth = static_cast<std::uint32_t>(atlas.mWidth) >> 1U;
    const std::uint32_t atlasHalfHeight = static_cast<std::uint32_t>(atlas.mHeight) >> 1U;

    const auto refresh = [&]() -> bool {
      for (Slot& slot : mSlots) {
        if (slot.mTexture->mWidth >= atlasHalfWidth || slot.mTexture->mHeight >= atlasHalfHeight) {
          return false;
        }
        const gpg::Rect2f* const rect = atlas.AddTexture(slot.mTexture);
        if (rect == nullptr) {
          return false;
        }
        // The lanes `SetTexture` derives for the atlas branch.
        const float uv[4] = {rect->x0, rect->z0, rect->x1 - rect->x0, rect->z1 - rect->z0};
        if (std::memcmp(uv, slot.mUv, sizeof(uv)) != 0) {
          std::memcpy(slot.mUv, uv, sizeof(uv));
          mSlotsDirty = true;
        }
      }
      return true;
    };

    if (refresh()) {
      return true;
    }
    // Full: start the atlas over, as `SetTexture` does when it runs out, after
    // drawing whatever the batcher still holds from the old one.
    batcher.Flush();
    atlas.Reset();
    mSlotsDirty = true;
    return refresh();
  }

  void StrategicIconRenderer::UploadSlots()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const auto count = static_cast<std::uint32_t>(mSlots.size());
    if (count > mSlotCapacity || mSlotBuffer == nullptr) {
      mSlotCapacity = std::max<std::uint32_t>(256U, count * 2U);
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "StrategicIconSlots";
      desc.stride = sizeof(SlotRecord);
      desc.capacity = mSlotCapacity;
      mSlotBuffer = device->CreateGpuBuffer(desc);
    }
    std::vector<SlotRecord> records(count);
    for (std::uint32_t index = 0U; index < count; ++index) {
      const Slot& slot = mSlots[index];
      std::memcpy(records[index].uv, slot.mUv, sizeof(slot.mUv));
      std::memcpy(records[index].halfSize, slot.mHalfSize, sizeof(slot.mHalfSize));
      records[index].unused[0] = 0.0f;
      records[index].unused[1] = 0.0f;
    }
    if (mSlotBuffer != nullptr && count != 0U) {
      device->UpdateGpuBuffer(*mSlotBuffer, 0U, count, records.data());
    }
    mSlotsDirty = false;
  }

  StrategicIconRenderer::ViewStream& StrategicIconRenderer::StreamFor(const void* const viewKey)
  {
    for (ViewStream& stream : mStreams) {
      if (stream.mViewKey == viewKey) {
        stream.mLastUsedFrame = mFrame;
        return stream;
      }
    }
    std::erase_if(mStreams, [this](const ViewStream& stream) { return mFrame - stream.mLastUsedFrame > kStreamIdleDraws; });
    ViewStream& stream = mStreams.emplace_back();
    stream.mViewKey = viewKey;
    stream.mLastUsedFrame = mFrame;
    return stream;
  }

  gpg::gal::Texture* StrategicIconRenderer::PrepareDraw(CD3DPrimBatcher& batcher)
  {
    if (!RefreshAtlasSlots(batcher)) {
      return nullptr;
    }
    if (mSlotsDirty) {
      UploadSlots();
    }
    // Anything the batcher still holds was submitted before the icons.
    batcher.Flush();
    const boost::shared_ptr<ID3DTextureSheet> sheet = batcher.mTextureBatcher->GetCompositeTexture();
    if (sheet.get() == nullptr) {
      return nullptr;
    }
    ID3DTextureSheet::TextureHandle atlasTexture;
    (void)sheet->GetTexture(atlasTexture);
    // The sheet keeps the texture alive; the handle only borrows it for the draw.
    return atlasTexture.get();
  }

  bool StrategicIconRenderer::Draw(
    CD3DPrimBatcher& batcher, const void* const viewKey, const std::span<const StrategicIconInstance> instances
  )
  {
    if (!mSupported || batcher.mTextureBatcher == nullptr) {
      return false;
    }
    ++mFrame;
    if (instances.empty()) {
      return RefreshAtlasSlots(batcher);
    }
    gpg::gal::Texture* const atlasTexture = PrepareDraw(batcher);
    if (atlasTexture == nullptr) {
      return false;
    }

    ViewStream& stream = StreamFor(viewKey);
    gpg::gal::GpuBuffer* const records = stream.mRecords.Update(instances.data(), instances.size());
    if (records == nullptr || mSlotBuffer == nullptr) {
      return false;
    }

    // `Flush`'s composite: view * projection.
    DrawConstants constants{};
    constants.composite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = records;
    call.bindings.readBuffers[1] = mSlotBuffer.get();
    call.bindings.textures[0] = atlasTexture;
    call.vertexCountPerInstance = kVerticesPerIcon;
    call.instanceCount = static_cast<std::uint32_t>(instances.size());
    gpg::gal::Device::GetInstance()->DrawGpuProgram(call);
    return true;
  }

  bool StrategicIconRenderer::IsClassifyActive()
  {
    constexpr std::uint32_t kClassifyFeatures =
      gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute | gpg::gal::kGpuFeatureIndirectDraw;
    if (!GpuPathEnabled(ren_GpuIconClassify, gpg::gal::kGpuPathIconClassify, kClassifyFeatures) || !IsActive()) {
      return false;
    }
    if (!mClassifyInitialized) {
      mClassifyInitialized = true;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureCompute | gpg::gal::kGpuFeatureIndirectDraw;
      mClassifySupported =
        (gpg::gal::Device::GetInstance()->GetGpuDrivenFeatures() & kNeeded) == kNeeded && CreateClassifyResources();
      if (mClassifySupported) {
        gpg::Logf("Strategic icons: GPU classification (ren_GpuIconClassify)");
      }
    }
    return mClassifySupported;
  }

  bool StrategicIconRenderer::CreateClassifyResources()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::GpuProgramDesc desc{};
    desc.source = kStrategicIconClassifyShaderSource;
    desc.sourceBytes = sizeof(kStrategicIconClassifyShaderSource) - 1U;
    desc.name = "StrategicIconClassify";
    desc.computeEntry = "ClassifyIconsCS";
    mClassifyProgram = device->CreateGpuProgram(desc);
    desc.name = "StrategicIconCompact";
    desc.computeEntry = "CompactIconsCS";
    mCompactProgram = device->CreateGpuProgram(desc);

    gpg::gal::GpuBufferDesc argsDesc{};
    argsDesc.name = "StrategicIconDrawArgs";
    argsDesc.kind = gpg::gal::GpuBufferKind::IndirectArgs;
    argsDesc.stride = 16U;
    argsDesc.capacity = 1U;
    argsDesc.shaderWrite = true;
    mDrawArgs = device->CreateGpuBuffer(argsDesc);
    return mClassifyProgram != nullptr && mCompactProgram != nullptr && mDrawArgs != nullptr;
  }

  bool StrategicIconRenderer::EnsureClassifyCapacity(const std::uint32_t count)
  {
    if (count <= mClassifyCapacity && mStaged != nullptr) {
      return true;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const std::uint32_t capacity = std::max<std::uint32_t>(4096U, count + count / 2U);
    const auto create = [&](const char* const name, const std::uint32_t stride) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = name;
      desc.stride = stride;
      desc.capacity = capacity;
      desc.shaderWrite = true;
      return device->CreateGpuBuffer(desc);
    };
    mStaged = create("StrategicIconStaged", sizeof(StrategicIconInstance));
    mRunOf = create("StrategicIconRunOf", sizeof(std::uint32_t));
    mOutput = create("StrategicIconOutput", sizeof(StrategicIconInstance));
    if (mStaged == nullptr || mRunOf == nullptr || mOutput == nullptr) {
      mStaged.reset();
      mClassifyCapacity = 0U;
      return false;
    }
    mClassifyCapacity = capacity;
    return true;
  }

  bool StrategicIconRenderer::DrawClassified(
    CD3DPrimBatcher& batcher,
    const void* const viewKey,
    const std::span<const StrategicIconSourceRecord> sources,
    const std::uint64_t sourcesVersion,
    const std::span<const std::uint32_t> selectionBits,
    const std::uint64_t selectionVersion,
    const StrategicIconClassifyConstants& constants
  )
  {
    if (!mClassifySupported || batcher.mTextureBatcher == nullptr) {
      return false;
    }
    ++mFrame;
    const auto count = static_cast<std::uint32_t>(sources.size());
    mLastClassifiedSources = 0U;
    if (count == 0U) {
      return RefreshAtlasSlots(batcher);
    }
    gpg::gal::Texture* const atlasTexture = PrepareDraw(batcher);
    if (atlasTexture == nullptr || mSlotBuffer == nullptr || !EnsureClassifyCapacity(count)) {
      return false;
    }

    ViewStream& stream = StreamFor(viewKey);
    if (stream.mSourcesVersion != sourcesVersion || stream.mSources.Buffer() == nullptr) {
      if (stream.mSources.Update(sources.data(), sources.size()) == nullptr) {
        return false;
      }
      stream.mSourcesVersion = sourcesVersion;
    }
    if (stream.mSelectionVersion != selectionVersion || stream.mSelection.Buffer() == nullptr) {
      // Never empty, so the buffer always exists.
      static const std::uint32_t kNoSelection = 0U;
      const bool empty = selectionBits.empty();
      if (stream.mSelection.Update(empty ? &kNoSelection : selectionBits.data(), empty ? 1U : selectionBits.size()) == nullptr) {
        return false;
      }
      stream.mSelectionVersion = selectionVersion;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    StrategicIconClassifyConstants frame = constants;
    frame.mCount = count;

    std::optional<gpg::gal::RenderProfileScope> profileCompute(std::in_place, "IconCompute"); // FAF instrumentation
    gpg::gal::GpuDispatch classify{};
    classify.program = mClassifyProgram.get();
    classify.bindings.constants = &frame;
    classify.bindings.constantBytes = sizeof(frame);
    classify.bindings.readBuffers[0] = stream.mSources.Buffer();
    classify.bindings.readBuffers[1] = stream.mSelection.Buffer();
    classify.bindings.writeBuffers[0] = mStaged.get();
    classify.bindings.writeBuffers[1] = mRunOf.get();
    classify.groupsX = (count + kIconClassifyGroupSize - 1U) / kIconClassifyGroupSize;
    device->DispatchGpuProgram(classify);

    gpg::gal::GpuDispatch compact{};
    compact.program = mCompactProgram.get();
    compact.bindings.constants = &frame;
    compact.bindings.constantBytes = sizeof(frame);
    compact.bindings.readBuffers[0] = mStaged.get();
    compact.bindings.readBuffers[1] = mRunOf.get();
    compact.bindings.writeBuffers[0] = mOutput.get();
    compact.bindings.writeBuffers[1] = mDrawArgs.get();
    compact.groupsX = 1U;
    device->DispatchGpuProgram(compact);
    profileCompute.reset();

    DrawConstants drawConstants{};
    drawConstants.composite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);
    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &drawConstants;
    call.bindings.constantBytes = sizeof(drawConstants);
    call.bindings.readBuffers[0] = mOutput.get();
    call.bindings.readBuffers[1] = mSlotBuffer.get();
    call.bindings.textures[0] = atlasTexture;
    call.indirectArgs = mDrawArgs.get();
    device->DrawGpuProgram(call);
    mLastClassifiedSources = count;
    return true;
  }

  bool StrategicIconRenderer::ReadBackClassified(std::vector<StrategicIconInstance>& out)
  {
    out.clear();
    if (!mClassifySupported || mLastClassifiedSources == 0U) {
      return mClassifySupported;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    std::uint32_t args[4] = {};
    if (!device->ReadGpuBuffer(*mDrawArgs, 0U, 1U, args)) {
      return false;
    }
    const std::uint32_t drawn = std::min(args[1], mLastClassifiedSources);
    out.resize(drawn);
    return drawn == 0U || device->ReadGpuBuffer(*mOutput, 0U, drawn, out.data());
  }
} // namespace moho
