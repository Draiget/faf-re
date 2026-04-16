#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"

namespace gpg
{
  class BinaryWriter;
}

namespace moho
{
  struct GeomCamera3;

  /**
   * VFTABLE: 0x00E3F710
   * COL:     0x00E97F88
   */
  class CartographicDecal
  {
  public:
    /**
     * Address: 0x007D4A00 (FUN_007D4A00, sub_7D4A00)
     *
     * What it does:
     * Initializes one cartographic decal payload object and installs the
     * decal runtime vtable lane.
     */
    CartographicDecal();
    virtual ~CartographicDecal() = default;

  public:
    std::uint8_t mSerializedPayload[0x24]{}; // +0x04
  };

  static_assert(sizeof(CartographicDecal) == 0x28, "CartographicDecal size must be 0x28");

  class CartographicDecalBatch
  {
  public:
    /**
     * Address: 0x007D4C80 (FUN_007D4C80, ??1CartographicDecalBatch@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down one cartographic decal-batch lane by clearing active decal
     * nodes, releasing retained resource handles, and restoring inline string
     * lanes to empty state.
     */
    virtual ~CartographicDecalBatch();

    /**
     * Address: 0x007D4E60 (FUN_007D4E60, ?Shutdown@CartographicDecalBatch@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears one cartographic decal-batch payload in place, releasing
     * retained handles and intrusive decal nodes without freeing the batch
     * storage itself.
     */
    void Shutdown();

    /**
     * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Serializes one cartographic decal-batch payload into the binary writer.
     */
    void Write(gpg::BinaryWriter& writer);

  private:
    std::uint8_t mOpaqueStorage[0x70]; // +0x04
  };

  static_assert(sizeof(CartographicDecalBatch) == 0x74, "CartographicDecalBatch size must be 0x74");

  struct CartographicListNode
  {
    CartographicListNode* mPrev;      // +0x00
    CartographicListNode* mNext;      // +0x04
    CartographicDecalBatch mBatch;    // +0x08
  };

  static_assert(offsetof(CartographicListNode, mBatch) == 0x08, "CartographicListNode::mBatch offset must be 0x08");
  static_assert(sizeof(CartographicListNode) == 0x7C, "CartographicListNode size must be 0x7C");

  class Cartographic
  {
  public:
    /**
     * Address: 0x007D10C0 (FUN_007D10C0, ??0Cartographic@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes cartographic render-state defaults, color lanes, and one
     * self-linked list sentinel used by cartographic runtime storage.
     */
    Cartographic();

    virtual ~Cartographic() = default;

    /**
     * Address: 0x007D1700 (FUN_007D1700, ?IsInitialized@Cartographic@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns whether the cartographic runtime lane has been initialized.
     */
    [[nodiscard]] bool IsInitialized() const;

    /**
     * Address: 0x007D1DF0 (FUN_007D1DF0, ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     * Mangled: ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
     *
     * What it does:
     * Writes the cartographic decal-batch count lane and then serializes each
     * intrusive decal batch node in list order.
     */
    void WriteDecals(gpg::BinaryWriter& writer);

    /**
     * Address: 0x007D1E50 (FUN_007D1E50, ?GetEffect@Cartographic@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
     *
     * What it does:
     * Resolves the cartographic shader from the active D3D device resources
     * and returns the backing GAL effect handle.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::Effect> GetEffect();

  private:
    /**
     * Address: 0x007D2E40 (FUN_007D2E40, ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z)
     * Mangled: ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
     *
     * What it does:
     * Forwards one cartographic particle-render pass into the global world
     * particle renderer with fixed water/suppress flags.
     */
    void RenderParticles(std::int32_t tick, float frameAlpha, const GeomCamera3& camera);

  public:
    bool mInitialized;                            // +0x04
    std::uint8_t mPadding05_07[0x03];            // +0x05
    float mProjectionParams[11];                 // +0x08
    bool mFeatureToggle34;                       // +0x34
    std::uint8_t mPadding35_37[0x03];            // +0x35
    float mProjectionScaleX;                     // +0x38
    float mProjectionScaleY;                     // +0x3C
    float mProjectionScaleZ;                     // +0x40
    std::int32_t mColorLanes[5];                 // +0x44
    std::int32_t mUninitializedLane58;           // +0x58
    CartographicListNode* mListSentinel;         // +0x5C
    std::int32_t mRuntimeLane60;                 // +0x60
    boost::shared_ptr<void> mRuntimeHandles[8];  // +0x64
  };

  static_assert(offsetof(Cartographic, mInitialized) == 0x04, "Cartographic::mInitialized offset must be 0x04");
  static_assert(offsetof(Cartographic, mProjectionParams) == 0x08, "Cartographic::mProjectionParams offset must be 0x08");
  static_assert(offsetof(Cartographic, mColorLanes) == 0x44, "Cartographic::mColorLanes offset must be 0x44");
  static_assert(offsetof(Cartographic, mListSentinel) == 0x5C, "Cartographic::mListSentinel offset must be 0x5C");
  static_assert(offsetof(Cartographic, mRuntimeHandles) == 0x64, "Cartographic::mRuntimeHandles offset must be 0x64");
  static_assert(sizeof(Cartographic) == 0xA4, "Cartographic size must be 0xA4");

  /**
   * Address: 0x007D1710 (FUN_007D1710)
   *
   * What it does:
   * Copy-inserts one decal-batch node after the cartographic list sentinel and
   * increments the owning batch count with VC8 list-overflow protection.
   */
  std::int32_t InsertCartographicDecalBatchCopy(const CartographicDecalBatch& sourceBatch, Cartographic& owner);

  /**
   * Address: 0x007D1740 (FUN_007D1740)
   *
   * What it does:
   * Unlinks and destroys one decal-batch node (when not sentinel), decrements
   * count, and returns the predecessor node.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* node);
} // namespace moho
