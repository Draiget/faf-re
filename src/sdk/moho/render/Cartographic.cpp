#include "moho/render/Cartographic.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <new>
#include <stdexcept>

#include "gpg/core/streams/BinaryWriter.h"
#include "legacy/containers/String.h"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"

namespace
{
  constexpr std::size_t kCartographicNodeStorageSize = 0x7C;

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
    sentinel->mPrev = sentinel;
    sentinel->mNext = sentinel;
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

  struct CartographicDecalPayloadView final
  {
    std::uint32_t mUnknown00; // +0x00
    std::uint32_t mRange04[2]; // +0x04
    std::uint32_t mLayer0C; // +0x0C
    std::uint32_t mRange10[2]; // +0x10
    std::uint32_t mRange18[2]; // +0x18
    std::uint32_t mRange20[2]; // +0x20
  };

  static_assert(sizeof(CartographicDecalPayloadView) == 0x28, "CartographicDecalPayloadView size must be 0x28");

  struct CartographicDecalNodeView final
  {
    CartographicDecalNodeView* mPrev; // +0x00
    CartographicDecalNodeView* mNext; // +0x04
    CartographicDecalPayloadView mPayload; // +0x08
  };

  static_assert(offsetof(CartographicDecalNodeView, mPayload) == 0x08, "CartographicDecalNodeView::mPayload offset must be 0x08");
  static_assert(sizeof(CartographicDecalNodeView) == 0x30, "CartographicDecalNodeView size must be 0x30");

  struct CartographicDecalListRuntimeView final
  {
    void* mAllocatorCookie; // +0x00
    CartographicDecalNodeView* mDecalSentinel; // +0x04
    std::int32_t mDecalCount; // +0x08
  };

  static_assert(
    offsetof(CartographicDecalListRuntimeView, mDecalSentinel) == 0x04,
    "CartographicDecalListRuntimeView::mDecalSentinel offset must be 0x04"
  );
  static_assert(
    offsetof(CartographicDecalListRuntimeView, mDecalCount) == 0x08,
    "CartographicDecalListRuntimeView::mDecalCount offset must be 0x08"
  );
  static_assert(sizeof(CartographicDecalListRuntimeView) == 0x0C, "CartographicDecalListRuntimeView size must be 0x0C");

  struct CartographicDecalBatchRuntimeView final
  {
    void* mVtable; // +0x00
    msvc8::string mNameLane04; // +0x04
    msvc8::string mNameLane20; // +0x20
    boost::shared_ptr<void> mHandleLane3C; // +0x3C
    boost::shared_ptr<void> mHandleLane44; // +0x44
    boost::shared_ptr<void> mHandleLane4C; // +0x4C
    boost::shared_ptr<void> mHandleLane54; // +0x54
    boost::shared_ptr<void> mHandleLane5C; // +0x5C
    bool mIsShutdown; // +0x64
    std::uint8_t mPad65_67[3]; // +0x65
    CartographicDecalListRuntimeView mDecals; // +0x68
  };

  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mNameLane04) == 0x04,
    "CartographicDecalBatchRuntimeView::mNameLane04 offset must be 0x04"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mNameLane20) == 0x20,
    "CartographicDecalBatchRuntimeView::mNameLane20 offset must be 0x20"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mHandleLane3C) == 0x3C,
    "CartographicDecalBatchRuntimeView::mHandleLane3C offset must be 0x3C"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mHandleLane44) == 0x44,
    "CartographicDecalBatchRuntimeView::mHandleLane44 offset must be 0x44"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mHandleLane4C) == 0x4C,
    "CartographicDecalBatchRuntimeView::mHandleLane4C offset must be 0x4C"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mHandleLane54) == 0x54,
    "CartographicDecalBatchRuntimeView::mHandleLane54 offset must be 0x54"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mHandleLane5C) == 0x5C,
    "CartographicDecalBatchRuntimeView::mHandleLane5C offset must be 0x5C"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mIsShutdown) == 0x64,
    "CartographicDecalBatchRuntimeView::mIsShutdown offset must be 0x64"
  );
  static_assert(
    offsetof(CartographicDecalBatchRuntimeView, mDecals) == 0x68,
    "CartographicDecalBatchRuntimeView::mDecals offset must be 0x68"
  );
  static_assert(sizeof(CartographicDecalBatchRuntimeView) == 0x74, "CartographicDecalBatchRuntimeView size must be 0x74");

  [[nodiscard]] CartographicDecalBatchRuntimeView* AsCartographicDecalBatchRuntimeView(
    moho::CartographicDecalBatch* const batch
  ) noexcept
  {
    return reinterpret_cast<CartographicDecalBatchRuntimeView*>(batch);
  }

  [[nodiscard]] const CartographicDecalBatchRuntimeView* AsCartographicDecalBatchRuntimeView(
    const moho::CartographicDecalBatch* const batch
  ) noexcept
  {
    return reinterpret_cast<const CartographicDecalBatchRuntimeView*>(batch);
  }

  /**
   * Address: 0x007D4380 (FUN_007D4380)
   *
   * What it does:
   * Clears one cartographic decal intrusive-list payload lane, relinks the
   * sentinel to itself, and deletes all detached nodes.
   */
  void ClearCartographicDecalList(CartographicDecalListRuntimeView* const list) noexcept
  {
    if (list == nullptr || list->mDecalSentinel == nullptr) {
      return;
    }

    CartographicDecalNodeView* const sentinel = list->mDecalSentinel;
    CartographicDecalNodeView* node = sentinel->mNext;

    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    list->mDecalCount = 0;

    while (node != nullptr && node != sentinel) {
      CartographicDecalNodeView* const next = node->mNext;
      ::operator delete(node);
      node = next;
    }
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
    const CartographicDecalPayloadView& payload
  )
  {
    writer.Write(payload.mRange04[0]);
    writer.Write(payload.mRange04[1]);
    writer.Write(payload.mLayer0C);
    writer.Write(payload.mRange10[0]);
    writer.Write(payload.mRange10[1]);
    writer.Write(payload.mRange18[0]);
    writer.Write(payload.mRange18[1]);
    writer.Write(payload.mRange20[0]);
    writer.Write(payload.mRange20[1]);
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
   * Address: 0x007D4E60 (FUN_007D4E60, ?Shutdown@CartographicDecalBatch@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears both batch name/string lanes, releases retained shared resource
   * handles, clears intrusive decal nodes, and marks this batch as shut down.
   */
  void CartographicDecalBatch::Shutdown()
  {
    auto* const batch = AsCartographicDecalBatchRuntimeView(this);
    batch->mNameLane04.clear();
    batch->mNameLane20.clear();

    batch->mHandleLane3C.reset();
    batch->mHandleLane44.reset();
    batch->mHandleLane4C.reset();
    batch->mHandleLane54.reset();
    batch->mHandleLane5C.reset();

    ClearCartographicDecalList(&batch->mDecals);
    batch->mIsShutdown = true;
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
    auto* const batch = AsCartographicDecalBatchRuntimeView(this);
    Shutdown();
    ClearCartographicDecalList(&batch->mDecals);

    if (batch->mDecals.mDecalSentinel != nullptr) {
      ::operator delete(batch->mDecals.mDecalSentinel);
      batch->mDecals.mDecalSentinel = nullptr;
    }

    batch->mHandleLane5C.reset();
    batch->mHandleLane54.reset();
    batch->mHandleLane4C.reset();
    batch->mHandleLane44.reset();
    batch->mHandleLane3C.reset();

    batch->mNameLane20.tidy(true, 0U);
    batch->mNameLane04.tidy(true, 0U);
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
    auto* const node = static_cast<CartographicListNode*>(AllocateCartographicNodeStorage(1u));
    node->mPrev = sentinel;
    node->mNext = sentinel->mNext;
    ::new (static_cast<void*>(&node->mBatch)) CartographicDecalBatch(sourceBatch);

    constexpr std::int32_t kMaxNodeCountBeforeOverflow = 0x0234F72C;
    if (owner.mRuntimeLane60 == kMaxNodeCountBeforeOverflow) {
      throw std::length_error("list<T> too long");
    }

    const std::int32_t newCount = owner.mRuntimeLane60 + 1;
    owner.mRuntimeLane60 = newCount;

    sentinel->mNext = node;
    node->mNext->mPrev = node;
    return newCount;
  }

  /**
   * Address: 0x007D1740 (FUN_007D1740)
   *
   * What it does:
   * Unlinks and destroys one non-sentinel decal-batch node and returns the
   * predecessor node used by the legacy iterator-erase lane.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* const node)
  {
    CartographicListNode* const predecessor = node->mPrev;
    if (node != owner.mListSentinel) {
      node->mNext->mPrev = predecessor;
      predecessor->mNext = node->mNext;
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      --owner.mRuntimeLane60;
    }

    return predecessor;
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
    const auto* const batch = AsCartographicDecalBatchRuntimeView(this);
    writer.Write(reinterpret_cast<const char*>(&batch->mNameLane04), sizeof(batch->mNameLane04));
    writer.Write(reinterpret_cast<const char*>(&batch->mNameLane20), sizeof(batch->mNameLane20));
    writer.Write(batch->mDecals.mDecalCount);

    const CartographicDecalNodeView* const sentinel = batch->mDecals.mDecalSentinel;
    for (const CartographicDecalNodeView* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      WriteCartographicDecalPayload(writer, node->mPayload);
    }
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
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DEffect* const effect = resources->FindEffect("cartographic");
    boost::shared_ptr<gpg::gal::EffectD3D9> baseEffect = effect->GetBaseEffect();
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
