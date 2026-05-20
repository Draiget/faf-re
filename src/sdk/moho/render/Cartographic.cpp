#include "moho/render/Cartographic.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "legacy/containers/String.h"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace
{
  constexpr std::size_t kCartographicNodeStorageSize = 0x7C;
  constexpr std::size_t kCartographicDecalNodeStorageSize = 0x30;

  /**
   * Address: 0x007D4000 (FUN_007D4000, sub_7D4000)
   *
   * What it does:
   * Allocates one or more fixed-size cartographic runtime nodes and raises
   * `std::bad_alloc` when multiplication overflows the 32-bit lane.
   */
  [[nodiscard]] void* AllocateCartographicNodeStorage(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < kCartographicNodeStorageSize) {
      throw std::bad_alloc();
    }

    return ::operator new(static_cast<std::size_t>(count) * kCartographicNodeStorageSize);
  }

  /**
   * Address: 0x007D3EC0 (FUN_007D3EC0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one cartographic node-storage
   * element through the checked allocator helper.
   */
  [[maybe_unused]] [[nodiscard]] void* AllocateSingleCartographicNodeStorageAdapter()
  {
    return AllocateCartographicNodeStorage(1u);
  }

  /**
   * Address: 0x007D3C90 (FUN_007D3C90, sub_7D3C90)
   *
   * What it does:
   * Allocates one cartographic node and resets its intrusive prev/next lanes
   * to a self-linked singleton.
   */
  [[nodiscard]] moho::CartographicListNode* CreateCartographicListSentinel()
  {
    auto* const sentinel = static_cast<moho::CartographicListNode*>(AllocateCartographicNodeStorage(1u));
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    return sentinel;
  }

  [[nodiscard]] moho::CartographicDecalBatch* CopyConstructCartographicDecalBatchIfPresent(
    moho::CartographicDecalBatch* const destination,
    const moho::CartographicDecalBatch* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) moho::CartographicDecalBatch(*source);
  }

  /**
   * Address: 0x007D3F40 (FUN_007D3F40)
   *
   * What it does:
   * Adapter lane for nullable `CartographicDecalBatch` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::CartographicDecalBatch* CopyConstructCartographicDecalBatchIfPresentAdapter(
    moho::CartographicDecalBatch* const destination,
    const moho::CartographicDecalBatch* const source
  )
  {
    return CopyConstructCartographicDecalBatchIfPresent(destination, source);
  }

  struct CartographicEffectAliasDeleter
  {
    explicit CartographicEffectAliasDeleter(const boost::shared_ptr<gpg::gal::EffectD3D9>& ownerEffect)
      : owner(ownerEffect)
    {
    }

    void operator()(gpg::gal::Effect*) const
    {
    }

    boost::shared_ptr<gpg::gal::EffectD3D9> owner;
  };

  constexpr std::array<float, 8> kCartographicQuadVertices{
    -1.0f, 1.0f,
    -1.0f, -1.0f,
    1.0f, 1.0f,
    1.0f, -1.0f,
  };

  constexpr std::array<std::uint32_t, 3> kCartographicQuadIndexWords{
    0x00010000u,
    0x00030002u,
    0x00010002u,
  };

  constexpr std::uint32_t kCartographicVertexFormatToken = 22U;
  constexpr std::uint32_t kCartographicTopologyTriangleList = 4U;
  constexpr std::uint32_t kCartographicQuadVertexCount = 4U;
  constexpr std::uint32_t kCartographicQuadPrimitiveCountInput = 6U;
  constexpr std::uint32_t kCartographicMaxDecalInstances = 1024U;
  constexpr std::uint32_t kCartographicInstanceFloatCount = 9U;

  /**
   * Address: 0x007D5B50 (FUN_007D5B50, sub_7D5B50)
   *
   * What it does:
   * Resolves the `"cartographic"` effect from device resources and returns its
   * base D3D9 GAL effect handle.
   */
  [[nodiscard]] boost::shared_ptr<gpg::gal::EffectD3D9> GetCartographicBaseEffectD3D9()
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DDeviceResources* const resources = device->GetResources();
    moho::CD3DEffect* const effect = resources->FindEffect("cartographic");
    return effect->GetBaseEffect();
  }

  /**
   * Address: 0x007D4380 (FUN_007D4380)
   *
   * What it does:
   * Clears one cartographic decal intrusive-list payload lane, relinks the
   * sentinel to itself, and deletes all detached nodes.
   */
  void ClearCartographicDecalList(moho::CartographicDecalList* const list) noexcept
  {
    if (list == nullptr || list->mDecalSentinel == nullptr) {
      return;
    }

    moho::CartographicDecalNode* const sentinel = list->mDecalSentinel;
    moho::CartographicDecalNode* node = sentinel->mNext;

    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    list->mDecalCount = 0;

    while (node != nullptr && node != sentinel) {
      moho::CartographicDecalNode* const next = node->mNext;
      node->mDecal.~CartographicDecal();
      ::operator delete(node);
      node = next;
    }
  }

  [[nodiscard]] void* AllocateCartographicDecalNodeStorage(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < kCartographicDecalNodeStorageSize) {
      throw std::bad_alloc();
    }

    return ::operator new(static_cast<std::size_t>(count) * kCartographicDecalNodeStorageSize);
  }

  [[nodiscard]] moho::CartographicDecalNode* CreateCartographicDecalSentinelNode()
  {
    auto* const sentinel = static_cast<moho::CartographicDecalNode*>(AllocateCartographicDecalNodeStorage(1u));
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    return sentinel;
  }

  [[nodiscard]] moho::CartographicDecalNode* CreateCartographicDecalNodeBefore(
    moho::CartographicDecalNode* const next,
    moho::CartographicDecalNode* const prev,
    const moho::CartographicDecal& decal
  )
  {
    auto* const node = static_cast<moho::CartographicDecalNode*>(AllocateCartographicDecalNodeStorage(1u));
    node->mNext = next;
    node->mPrev = prev;
    try {
      ::new (static_cast<void*>(&node->mDecal)) moho::CartographicDecal(decal);
    } catch (...) {
      ::operator delete(node);
      throw;
    }

    return node;
  }

  /**
   * Address: 0x007D4550 (FUN_007D4550, sub_7D4550)
   *
   * What it does:
   * Inner copy-loop body that the binary emitted as a separate symbol.
   * Walks the source `[first, sentinel)` range and, for each source decal
   * node, creates a new decal node before the destination sentinel's
   * `mPrev` lane using the shared `CreateCartographicDecalNodeBefore`
   * helper, then patches the sentinel/new-node link pair and increments
   * the destination count.
   *
   * Wired into `CopyCartographicDecalList` to preserve the binary's per-T
   * symbol shape even when the modern compiler would inline the loop.
   */
  void CopyCartographicDecalNodesIntoSentinel(
    moho::CartographicDecalList& destination,
    const moho::CartographicDecalNode* const sourceFirst,
    const moho::CartographicDecalNode* const sourceSentinel)
  {
    for (const moho::CartographicDecalNode* sourceNode = sourceFirst;
         sourceNode != sourceSentinel;
         sourceNode = sourceNode->mNext) {
      moho::CartographicDecalNode* const sentinel = destination.mDecalSentinel;
      moho::CartographicDecalNode* const node =
        CreateCartographicDecalNodeBefore(sentinel, sentinel->mPrev, sourceNode->mDecal);
      sentinel->mPrev = node;
      node->mPrev->mNext = node;
      ++destination.mDecalCount;
    }
  }

  /**
   * Address: 0x007D4230 (FUN_007D4230, sub_7D4230)
   *
   * What it does:
   * Initializes a destination cartographic decal list with a fresh sentinel
   * and deep-copies every source decal node in list order. Routes the inner
   * per-element copy loop through the canonical helper
   * `CopyCartographicDecalNodesIntoSentinel` (FUN_007D4550) to preserve the
   * binary's symbol shape.
   */
  void CopyCartographicDecalList(
    moho::CartographicDecalList& destination,
    const moho::CartographicDecalList& source
  )
  {
    destination.mAllocatorCookie = nullptr;
    destination.mDecalSentinel = CreateCartographicDecalSentinelNode();
    destination.mDecalCount = 0;

    try {
      const moho::CartographicDecalNode* const sourceSentinel = source.mDecalSentinel;
      if (sourceSentinel != nullptr) {
        CopyCartographicDecalNodesIntoSentinel(
          destination, sourceSentinel->mNext, sourceSentinel);
      }
    } catch (...) {
      ClearCartographicDecalList(&destination);
      ::operator delete(destination.mDecalSentinel);
      destination.mDecalSentinel = nullptr;
      throw;
    }
  }

  /**
   * Address: 0x007D3BC0 (FUN_007D3BC0, sub_7D3BC0)
   *
   * What it does:
   * Clears the cartographic decal-batch intrusive list, relinks the sentinel
   * to itself, destroys every batch node, and resets the owner count.
   */
  void ClearCartographicBatchList(moho::Cartographic& owner) noexcept
  {
    moho::CartographicListNode* const sentinel = owner.mListSentinel;
    if (sentinel == nullptr) {
      owner.mRuntimeLane60 = 0;
      return;
    }

    moho::CartographicListNode* node = sentinel->mNext;
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    owner.mRuntimeLane60 = 0;

    while (node != nullptr && node != sentinel) {
      moho::CartographicListNode* const next = node->mNext;
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x007D3D70 (FUN_007D3D70, sub_7D3D70)
   *
   * What it does:
   * Allocates one cartographic batch-list node, installs caller-provided
   * intrusive links, and copy-constructs the embedded decal batch.
   */
  [[nodiscard]] moho::CartographicListNode* CreateCartographicBatchNode(
    moho::CartographicListNode* const next,
    moho::CartographicListNode* const prev,
    const moho::CartographicDecalBatch& sourceBatch
  )
  {
    auto* const node = static_cast<moho::CartographicListNode*>(AllocateCartographicNodeStorage(1u));
    node->mNext = next;
    node->mPrev = prev;

    try {
      ::new (static_cast<void*>(&node->mBatch)) moho::CartographicDecalBatch(sourceBatch);
    } catch (...) {
      ::operator delete(node);
      throw;
    }

    return node;
  }

  /**
   * Address: 0x007D4A70 (FUN_007D4A70, sub_7D4A70)
   *
   * What it does:
   * Serializes one decal payload lane as five fixed write segments
   * (`8 + 4 + 8 + 8 + 8` bytes) into the writer stream.
   */
  void WriteCartographicDecalPayload(
    gpg::BinaryWriter& writer,
    const moho::CartographicDecal& decal
  )
  {
    for (const float value : decal.mVertexData) {
      writer.Write(value);
    }
  }

  struct HeightFieldKernelSampleRuntimeView
  {
    const std::uint16_t* samples = nullptr; // +0x00
    std::int32_t width = 0;                 // +0x04
    std::int32_t height = 0;                // +0x08
  };
  static_assert(
    offsetof(HeightFieldKernelSampleRuntimeView, samples) == 0x00,
    "HeightFieldKernelSampleRuntimeView::samples offset must be 0x00"
  );
  static_assert(
    offsetof(HeightFieldKernelSampleRuntimeView, width) == 0x04,
    "HeightFieldKernelSampleRuntimeView::width offset must be 0x04"
  );
  static_assert(
    offsetof(HeightFieldKernelSampleRuntimeView, height) == 0x08,
    "HeightFieldKernelSampleRuntimeView::height offset must be 0x08"
  );
  static_assert(sizeof(HeightFieldKernelSampleRuntimeView) == 0x0C, "HeightFieldKernelSampleRuntimeView size must be 0x0C");

  /**
   * Address: 0x007D0F70 (FUN_007D0F70)
   *
   * What it does:
   * Samples one clamped terrain-height lane, applies the legacy 3x3 kernel
   * weights (`0,1,0 / 1,3,1 / 0,1,0`), then normalizes by `1/7`.
   */
  [[maybe_unused]] float CartographicSampleHeightKernelRuntime(
    const HeightFieldKernelSampleRuntimeView* const field,
    const std::int32_t xIndex,
    const std::int32_t yIndex,
    const float baseline,
    const float scale
  ) noexcept
  {
    if (field == nullptr || field->samples == nullptr || field->width <= 0 || field->height <= 0) {
      return 0.0f;
    }

    constexpr float kHeightScale = 0.0078125f;
    constexpr float kKernelWeights[9] = {
      0.0f, 1.0f, 0.0f,
      1.0f, 3.0f, 1.0f,
      0.0f, 1.0f, 0.0f,
    };
    constexpr float kKernelNormalize = 0.142857149f;

    const std::int32_t clampedX = std::max(0, std::min(xIndex - 1, field->width - 1));
    const std::int32_t clampedY = std::max(0, std::min(yIndex - 1, field->height - 1));
    const std::uint16_t packedHeight = field->samples[(clampedY * field->width) + clampedX];
    const float normalizedHeight = (static_cast<float>(packedHeight) * kHeightScale) - baseline;

    float weightedHeight = 0.0f;
    for (float weight : kKernelWeights) {
      weightedHeight += (normalizedHeight * weight) * scale;
    }

    return weightedHeight * kKernelNormalize;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007D4A00 (FUN_007D4A00, sub_7D4A00)
   *
   * What it does:
   * Initializes one cartographic decal payload object and installs the
   * decal runtime vtable lane.
  */
  CartographicDecal::CartographicDecal() = default;

  /**
   * Address: 0x007D40E0 (FUN_007D40E0, ??0CartographicDecalBatch@Moho@@QAE@@Z)
   *
   * IDA signature:
   * int __thiscall Moho::CartographicDecalBatch::CartographicDecalBatch(int source, int destination);
   *
   * What it does:
   * Copy-constructs one cartographic decal batch, retaining shared render
   * handles and deep-copying the intrusive decal payload list.
   */
  CartographicDecalBatch::CartographicDecalBatch(const CartographicDecalBatch& other)
    : mTechniqueName(),
      mTexturePath(),
      mDecalTexture(other.mDecalTexture),
      mVertexFormat(other.mVertexFormat),
      mQuadVertexBuffer(other.mQuadVertexBuffer),
      mInstanceVertexBuffer(other.mInstanceVertexBuffer),
      mIndexBuffer(other.mIndexBuffer),
      mNeedsVertexUpload(other.mNeedsVertexUpload),
      mPadding65_67{},
      mDecals{}
  {
    mTechniqueName.reset_and_assign(other.mTechniqueName);
    mTexturePath.reset_and_assign(other.mTexturePath);
    CopyCartographicDecalList(mDecals, other.mDecals);
  }

  /**
   * Address: 0x007D4E60 (FUN_007D4E60, ?Shutdown@CartographicDecalBatch@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears both batch name/string lanes, releases retained shared resource
   * handles, clears intrusive decal nodes, and marks the vertex upload lane dirty.
   */
  void CartographicDecalBatch::Shutdown()
  {
    mTechniqueName.clear();
    mTexturePath.clear();

    mDecalTexture.reset();
    mVertexFormat.reset();
    mQuadVertexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mIndexBuffer.reset();

    ClearCartographicDecalList(&mDecals);
    mNeedsVertexUpload = true;
  }

  /**
   * Address: 0x007D4C80 (FUN_007D4C80, ??1CartographicDecalBatch@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs the shutdown lane, clears/deletes the intrusive decal sentinel, and
   * tidies both embedded legacy string lanes back to inline-empty form.
   */
  CartographicDecalBatch::~CartographicDecalBatch()
  {
    Shutdown();
    ClearCartographicDecalList(&mDecals);

    if (mDecals.mDecalSentinel != nullptr) {
      ::operator delete(mDecals.mDecalSentinel);
      mDecals.mDecalSentinel = nullptr;
    }

    mIndexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mQuadVertexBuffer.reset();
    mVertexFormat.reset();
    mDecalTexture.reset();

    mTexturePath.tidy(true, 0U);
    mTechniqueName.tidy(true, 0U);
  }

  /**
   * Address: 0x007D10C0 (FUN_007D10C0, ??0Cartographic@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes cartographic render-state defaults, color lanes, and one
   * self-linked list sentinel used by cartographic runtime storage.
   */
  Cartographic::Cartographic()
  {
    constexpr std::int32_t kOpaqueBlack = static_cast<std::int32_t>(0xFF000000u);

    mInitialized = false;
    for (float& value : mProjectionParams) {
      value = 0.0f;
    }

    mFeatureToggle34 = false;
    mProjectionScaleX = 0.0f;
    mProjectionScaleY = 0.0f;
    mProjectionScaleZ = 0.0f;

    for (std::int32_t& color : mColorLanes) {
      color = kOpaqueBlack;
    }

    mListSentinel = CreateCartographicListSentinel();
    mRuntimeLane60 = 0;

    for (boost::shared_ptr<void>& handle : mRuntimeHandles) {
      handle.reset();
    }
  }

  /**
   * Address: 0x007D11B0 (FUN_007D11B0, ??1Cartographic@Moho@@UAE@XZ)
   *
   * IDA signature:
   * void __thiscall Moho::Cartographic::~Cartographic(Moho::Cartographic* this);
   *
   * What it does:
   * Shuts down all cartographic render resources, releases retained handles,
   * clears decal-batch storage, and deletes the list sentinel.
   */
  Cartographic::~Cartographic()
  {
    Shutdown();
    ClearCartographicBatchList(*this);
    ::operator delete(mListSentinel);
    mListSentinel = nullptr;
  }

  /**
   * Address: 0x007D14B0 (FUN_007D14B0, ?Shutdown@Cartographic@Moho@@QAEXXZ)
   *
   * IDA signature:
   * void __stdcall Moho::Cartographic::Shutdown(Moho::Cartographic* this);
   *
   * What it does:
   * Clears cartographic decal batches, releases render/runtime handles, resets
   * projection state, and marks the runtime uninitialized.
   */
  void Cartographic::Shutdown()
  {
    ClearCartographicBatchList(*this);

    for (boost::shared_ptr<void>& handle : mRuntimeHandles) {
      handle.reset();
    }

    mProjectionScaleX = 0.0f;
    mProjectionScaleY = 0.0f;
    mProjectionScaleZ = 0.0f;
    mInitialized = false;
  }

  /**
   * Address: 0x007D1700 (FUN_007D1700, ?IsInitialized@Cartographic@Moho@@QBE_NXZ)
   *
   * What it does:
   * Returns whether the cartographic runtime lane has been initialized.
   */
  bool Cartographic::IsInitialized() const
  {
    return mInitialized;
  }

  /**
   * Address: 0x007D1710 (FUN_007D1710)
   *
   * What it does:
   * Builds one copied decal-batch node from source storage, then increments
   * owner count with legacy list overflow guard before relinking list heads.
   */
  std::int32_t InsertCartographicDecalBatchCopy(const CartographicDecalBatch& sourceBatch, Cartographic& owner)
  {
    CartographicListNode* const sentinel = owner.mListSentinel;
    CartographicListNode* const node = CreateCartographicBatchNode(sentinel, sentinel->mPrev, sourceBatch);

    constexpr std::int32_t kMaxNodeCountBeforeOverflow = 0x0234F72C;
    if (owner.mRuntimeLane60 == kMaxNodeCountBeforeOverflow) {
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      throw std::length_error("list<T> too long");
    }

    const std::int32_t newCount = owner.mRuntimeLane60 + 1;
    owner.mRuntimeLane60 = newCount;

    sentinel->mPrev = node;
    node->mPrev->mNext = node;
    return newCount;
  }

  /**
   * Address: 0x007D1740 (FUN_007D1740)
   *
   * What it does:
   * Unlinks and destroys one non-sentinel decal-batch node and returns the
   * successor node used by the legacy iterator-erase lane.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* const node)
  {
    CartographicListNode* const successor = node->mNext;
    if (node != owner.mListSentinel) {
      node->mPrev->mNext = successor;
      successor->mPrev = node->mPrev;
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      --owner.mRuntimeLane60;
    }

    return successor;
  }

  /**
   * Address: 0x007D1DF0 (FUN_007D1DF0, ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   * Mangled: ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
   *
   * What it does:
   * Writes the batch-count lane first, then serializes each intrusive
   * cartographic decal-batch node through its runtime payload view.
   */
  void Cartographic::WriteDecals(gpg::BinaryWriter& writer)
  {
    writer.Write(mRuntimeLane60);

    CartographicListNode* const sentinel = mListSentinel;
    for (CartographicListNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      node->mBatch.Write(writer);
    }
  }

  /**
   * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   * Mangled: ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
   *
   * What it does:
   * Writes batch header lanes, emits one decal-count dword, then serializes
   * each decal payload from the intrusive entry list.
  */
  void CartographicDecalBatch::Write(gpg::BinaryWriter& writer)
  {
    writer.Write(reinterpret_cast<const char*>(&mTechniqueName), sizeof(mTechniqueName));
    writer.Write(reinterpret_cast<const char*>(&mTexturePath), sizeof(mTexturePath));
    writer.Write(mDecals.mDecalCount);

    const CartographicDecalNode* const sentinel = mDecals.mDecalSentinel;
    for (const CartographicDecalNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      WriteCartographicDecalPayload(writer, node->mDecal);
    }
  }

  /**
   * Address: 0x007D56C0 (FUN_007D56C0, sub_7D56C0)
   *
   * What it does:
   * Lazily creates the cartographic decal vertex declaration, quad vertex
   * buffer, dynamic decal-instance buffer, and quad index buffer.
   */
  void CartographicDecalBatch::InitializeRenderResources()
  {
    if (mVertexFormat) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    boost::shared_ptr<gpg::gal::VertexFormatD3D9> vertexFormat;
    device->CreateVertexFormat(&vertexFormat, kCartographicVertexFormatToken);
    mVertexFormat = vertexFormat;

    gpg::gal::VertexBufferContext quadVertexContext{};
    quadVertexContext.type_ = 2U;
    quadVertexContext.usage_ = 1U;
    quadVertexContext.width_ = kCartographicQuadVertexCount;
    quadVertexContext.height_ = static_cast<std::uint32_t>(sizeof(float) * 2U);

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> quadVertexBuffer;
    device->CreateVertexBuffer(&quadVertexBuffer, &quadVertexContext);
    mQuadVertexBuffer = quadVertexBuffer;

    void* const quadVertexData = mQuadVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None);
    std::memcpy(quadVertexData, kCartographicQuadVertices.data(), sizeof(kCartographicQuadVertices));
    (void)mQuadVertexBuffer->Unlock();

    gpg::gal::VertexBufferContext instanceVertexContext{};
    instanceVertexContext.type_ = 3U;
    instanceVertexContext.usage_ = 2U;
    instanceVertexContext.width_ = kCartographicMaxDecalInstances;
    instanceVertexContext.height_ = static_cast<std::uint32_t>(sizeof(float) * kCartographicInstanceFloatCount);

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> instanceVertexBuffer;
    device->CreateVertexBuffer(&instanceVertexBuffer, &instanceVertexContext);
    mInstanceVertexBuffer = instanceVertexBuffer;

    gpg::gal::IndexBufferContext indexContext{};
    indexContext.type_ = 1U;
    indexContext.format_ = 1U;
    indexContext.size_ = kCartographicQuadPrimitiveCountInput;

    boost::shared_ptr<gpg::gal::IndexBufferD3D9> indexBuffer;
    device->CreateIndexBuffer(&indexBuffer, &indexContext);
    mIndexBuffer = indexBuffer;

    auto* const indexWords = reinterpret_cast<std::uint32_t*>(
      mIndexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None)
    );
    std::memcpy(indexWords, kCartographicQuadIndexWords.data(), sizeof(kCartographicQuadIndexWords));
    (void)mIndexBuffer->Unlock();
  }

  /**
   * Address: 0x007D59C0 (FUN_007D59C0, sub_7D59C0)
   *
   * What it does:
   * Lazily resolves the decal texture resource named by the texture-path
   * string lane and retains its base GAL texture handle.
   */
  void CartographicDecalBatch::ResolveDecalTexture()
  {
    if (mDecalTexture) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    ID3DDeviceResources::TextureResourceHandle textureResource;
    resources->GetTexture(textureResource, mTexturePath.c_str(), 0, true);
    if (textureResource) {
      textureResource->GetTexture(mDecalTexture);
    }
  }

  /**
   * Address: 0x007D5AD0 (FUN_007D5AD0, sub_7D5AD0)
   *
   * What it does:
   * Uploads each decal node's nine-float instance payload into the dynamic
   * decal vertex buffer when the dirty flag is set.
   */
  void CartographicDecalBatch::UploadDecalVerticesIfDirty()
  {
    if (!mNeedsVertexUpload) {
      return;
    }

    float* writeCursor = static_cast<float*>(mInstanceVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None));
    CartographicDecalNode* const sentinel = mDecals.mDecalSentinel;
    for (CartographicDecalNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      std::memcpy(writeCursor, node->mDecal.mVertexData, sizeof(node->mDecal.mVertexData));
      writeCursor += kCartographicInstanceFloatCount;
    }

    (void)mInstanceVertexBuffer->Unlock();
    mNeedsVertexUpload = false;
  }

  /**
   * Address: 0x007D50D0 (FUN_007D50D0, sub_7D50D0)
   *
   * What it does:
   * Ensures cartographic decal GPU resources and texture state exist, uploads
   * dirty decal instance vertices, binds the cartographic effect, and draws
   * one instanced quad pass for each technique pass.
   */
  void CartographicDecalBatch::Render(const bool enabled, const std::int32_t tick, const GeomCamera3& camera)
  {
    (void)enabled;
    (void)tick;

    InitializeRenderResources();
    const std::int32_t decalCount = mDecals.mDecalCount;
    ResolveDecalTexture();

    if (decalCount == 0 || !mDecalTexture) {
      return;
    }

    UploadDecalVerticesIfDirty();

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = GetCartographicBaseEffectD3D9();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique(mTechniqueName.c_str());

    device->SetVertexDeclaration(mVertexFormat);
    device->SetVertexBuffer(0U, mQuadVertexBuffer, decalCount, 0);
    device->SetVertexBuffer(1U, mInstanceVertexBuffer, 1, 0);
    device->SetBufferIndices(mIndexBuffer);

    effect->SetMatrix("viewMatrix")->SetMatrix4x4(&camera.view);
    effect->SetMatrix("projMatrix")->SetMatrix4x4(&camera.projection);
    effect->SetMatrix("decalTexture")->SetTexture(mDecalTexture);

    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));
      gpg::gal::DrawIndexedContext drawContext(
        static_cast<int>(kCartographicTopologyTriangleList),
        static_cast<int>(kCartographicQuadVertexCount),
        static_cast<int>(kCartographicQuadPrimitiveCountInput),
        0,
        0
      );
      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x007D1E50 (FUN_007D1E50, ?GetEffect@Cartographic@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Looks up the `"cartographic"` D3D effect from the active device resources
   * and aliases its base effect handle into the public GAL effect type.
   */
  boost::shared_ptr<gpg::gal::Effect> Cartographic::GetEffect()
  {
    boost::shared_ptr<gpg::gal::EffectD3D9> baseEffect = GetCartographicBaseEffectD3D9();
    return boost::shared_ptr<gpg::gal::Effect>(
      reinterpret_cast<gpg::gal::Effect*>(baseEffect.get()),
      CartographicEffectAliasDeleter(baseEffect)
    );
  }

  /**
   * Address: 0x007D2E40 (FUN_007D2E40, ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z)
   * Mangled: ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
   *
   * What it does:
   * Forwards one cartographic particle pass to `sWorldParticles::RenderEffects`
   * with fixed flags `(renderWaterSurface=0, suppressTLight=1)`.
   */
  void Cartographic::RenderParticles(const std::int32_t tick, const float frameAlpha, const GeomCamera3& camera)
  {
    (void)moho::sWorldParticles.RenderEffects(const_cast<GeomCamera3*>(&camera), 0, 1, tick, frameAlpha);
  }
} // namespace moho
