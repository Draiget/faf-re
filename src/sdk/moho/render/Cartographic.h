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
  class CartographicDecalBatch
  {
  public:
    /**
     * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Serializes one cartographic decal-batch payload into the binary writer.
     */
    void Write(gpg::BinaryWriter& writer);

  private:
    std::uint8_t mOpaqueStorage[0x74]; // +0x00
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
} // namespace moho
