#include "moho/render/Cartographic.h"

#include <cstddef>
#include <limits>
#include <new>

#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
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

  struct CartographicDecalBatchView final
  {
    std::uint8_t mUnknown00_03[0x04];
    std::uint8_t mHeader04_1F[0x1C];
    std::uint8_t mHeader20_3B[0x1C];
    std::uint8_t mUnknown3C_6B[0x30];
    CartographicDecalNodeView* mDecalSentinel; // +0x6C
    std::int32_t mDecalCount; // +0x70
  };

  static_assert(offsetof(CartographicDecalBatchView, mDecalSentinel) == 0x6C, "CartographicDecalBatchView::mDecalSentinel offset must be 0x6C");
  static_assert(offsetof(CartographicDecalBatchView, mDecalCount) == 0x70, "CartographicDecalBatchView::mDecalCount offset must be 0x70");
  static_assert(sizeof(CartographicDecalBatchView) == 0x74, "CartographicDecalBatchView size must be 0x74");

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
} // namespace

namespace moho
{
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
    const auto& batch = *reinterpret_cast<const CartographicDecalBatchView*>(this);
    writer.Write(reinterpret_cast<const char*>(batch.mHeader04_1F), sizeof(batch.mHeader04_1F));
    writer.Write(reinterpret_cast<const char*>(batch.mHeader20_3B), sizeof(batch.mHeader20_3B));
    writer.Write(batch.mDecalCount);

    const CartographicDecalNodeView* const sentinel = batch.mDecalSentinel;
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
} // namespace moho
