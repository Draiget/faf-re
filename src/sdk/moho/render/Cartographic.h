#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"
#include "legacy/containers/String.h"

namespace gpg
{
  class BinaryWriter;
}

namespace gpg::gal
{
  class IndexBufferD3D9;
  class TextureD3D9;
  class VertexBufferD3D9;
  class VertexFormatD3D9;
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
    float mVertexData[9]{}; // +0x04
  };

  static_assert(sizeof(CartographicDecal) == 0x28, "CartographicDecal size must be 0x28");

  struct CartographicDecalNode
  {
    CartographicDecalNode* mNext; // +0x00
    CartographicDecalNode* mPrev; // +0x04
    CartographicDecal mDecal;     // +0x08
  };

  static_assert(offsetof(CartographicDecalNode, mDecal) == 0x08, "CartographicDecalNode::mDecal offset must be 0x08");
  static_assert(sizeof(CartographicDecalNode) == 0x30, "CartographicDecalNode size must be 0x30");

  struct CartographicDecalList
  {
    void* mAllocatorCookie;                  // +0x00
    CartographicDecalNode* mDecalSentinel;   // +0x04
    std::int32_t mDecalCount;                // +0x08
  };

  static_assert(offsetof(CartographicDecalList, mDecalSentinel) == 0x04, "CartographicDecalList::mDecalSentinel offset must be 0x04");
  static_assert(offsetof(CartographicDecalList, mDecalCount) == 0x08, "CartographicDecalList::mDecalCount offset must be 0x08");
  static_assert(sizeof(CartographicDecalList) == 0x0C, "CartographicDecalList size must be 0x0C");

  class CartographicDecalBatch
  {
  public:
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
    CartographicDecalBatch(const CartographicDecalBatch& other);

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
     * retained handles and intrusive decal nodes, then marks the decal vertex
     * stream dirty for the next resource rebuild.
     */
    void Shutdown();

    /**
     * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Serializes one cartographic decal-batch payload into the binary writer.
     */
    void Write(gpg::BinaryWriter& writer);

    /**
     * Address: 0x007D50D0 (FUN_007D50D0, sub_7D50D0)
     *
     * What it does:
     * Ensures cartographic decal GPU resources and texture state exist, uploads
     * dirty decal instance vertices, binds the cartographic effect, and draws
     * one instanced quad pass for each technique pass.
     */
    void Render(bool enabled, std::int32_t tick, const GeomCamera3& camera);

    /**
     * Address: 0x007D56C0 (FUN_007D56C0, sub_7D56C0)
     *
     * What it does:
     * Lazily creates the cartographic decal vertex declaration, quad vertex
     * buffer, dynamic decal-instance buffer, and quad index buffer.
     */
    void InitializeRenderResources();

    /**
     * Address: 0x007D59C0 (FUN_007D59C0, sub_7D59C0)
     *
     * What it does:
     * Lazily resolves the decal texture resource named by the texture-path
     * string lane and retains its base GAL texture handle.
     */
    void ResolveDecalTexture();

    /**
     * Address: 0x007D5AD0 (FUN_007D5AD0, sub_7D5AD0)
     *
     * What it does:
     * Uploads each decal node's nine-float instance payload into the dynamic
     * decal vertex buffer when the dirty flag is set.
     */
    void UploadDecalVerticesIfDirty();

  public:
    msvc8::string mTechniqueName;                                         // +0x04
    msvc8::string mTexturePath;                                           // +0x20
    boost::shared_ptr<gpg::gal::TextureD3D9> mDecalTexture;               // +0x3C
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mVertexFormat;          // +0x44
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mQuadVertexBuffer;      // +0x4C
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mInstanceVertexBuffer;  // +0x54
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mIndexBuffer;            // +0x5C
    bool mNeedsVertexUpload;                                              // +0x64
    std::uint8_t mPadding65_67[0x03];                                     // +0x65
    CartographicDecalList mDecals;                                        // +0x68
  };

  static_assert(offsetof(CartographicDecalBatch, mTechniqueName) == 0x04, "CartographicDecalBatch::mTechniqueName offset must be 0x04");
  static_assert(offsetof(CartographicDecalBatch, mTexturePath) == 0x20, "CartographicDecalBatch::mTexturePath offset must be 0x20");
  static_assert(offsetof(CartographicDecalBatch, mDecalTexture) == 0x3C, "CartographicDecalBatch::mDecalTexture offset must be 0x3C");
  static_assert(offsetof(CartographicDecalBatch, mVertexFormat) == 0x44, "CartographicDecalBatch::mVertexFormat offset must be 0x44");
  static_assert(offsetof(CartographicDecalBatch, mQuadVertexBuffer) == 0x4C, "CartographicDecalBatch::mQuadVertexBuffer offset must be 0x4C");
  static_assert(offsetof(CartographicDecalBatch, mInstanceVertexBuffer) == 0x54, "CartographicDecalBatch::mInstanceVertexBuffer offset must be 0x54");
  static_assert(offsetof(CartographicDecalBatch, mIndexBuffer) == 0x5C, "CartographicDecalBatch::mIndexBuffer offset must be 0x5C");
  static_assert(offsetof(CartographicDecalBatch, mNeedsVertexUpload) == 0x64, "CartographicDecalBatch::mNeedsVertexUpload offset must be 0x64");
  static_assert(offsetof(CartographicDecalBatch, mDecals) == 0x68, "CartographicDecalBatch::mDecals offset must be 0x68");
  static_assert(sizeof(CartographicDecalBatch) == 0x74, "CartographicDecalBatch size must be 0x74");

  struct CartographicListNode
  {
    CartographicListNode* mNext;      // +0x00
    CartographicListNode* mPrev;      // +0x04
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
    virtual ~Cartographic();

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
    void Shutdown();

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
   * count, and returns the successor node.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* node);
} // namespace moho
