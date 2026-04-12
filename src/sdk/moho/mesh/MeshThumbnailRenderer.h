#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/mesh/MeshThumbnail.h"
#include "wm3/Vector3.h"

namespace moho
{
  class ID3DDepthStencil;
  class ID3DRenderTarget;
  class ID3DTextureSheet;
  class TextureD3D9;
  class MeshInstance;
  struct RMeshBlueprint;

  struct MeshThumbnailNode
  {
    MeshThumbnailNode* next; // +0x00
    MeshThumbnailNode* prev; // +0x04
    MeshThumbnail value;     // +0x08
  };

  struct MeshThumbnailQueue
  {
    void* proxy;             // +0x00
    MeshThumbnailNode* head; // +0x04
    std::uint32_t size;      // +0x08
  };

  class MeshThumbnailRenderer
  {
  public:
    /**
     * Address: 0x007EA920 (FUN_007EA920)
     *
     * What it does:
     * Initializes thumbnail renderer resources and both intrusive request queues.
     */
    MeshThumbnailRenderer();

    /**
     * Address: 0x007EA9C0 (FUN_007EA9C0)
     * Deleting thunk: 0x007EA9A0 (FUN_007EA9A0)
     *
     * What it does:
     * Releases render-target state and tears down pending/completed request queues.
     */
    virtual ~MeshThumbnailRenderer();

    /**
     * Address: 0x007EAE40 (FUN_007EAE40)
     *
     * What it does:
     * Assigns one monotonic request id, snapshots request payload, and pushes it
     * onto the pending thumbnail queue.
     */
    [[nodiscard]] std::uint32_t EnqueuePreparedRequest(
      MeshInstance* meshInstance,
      const GeomCamera3& camera,
      const Wm3::Quatf& orientation,
      std::uint32_t color,
      const gpg::Rect2f& outputRect,
      const boost::shared_ptr<ID3DTextureSheet>& outputSheet
    );

    /**
     * Address: 0x007EB150 (FUN_007EB150)
     *
     * What it does:
     * Builds a mesh instance from blueprint input, derives one thumbnail camera
     * transform, then forwards to prepared-request enqueue.
     */
    [[nodiscard]] std::uint32_t PushRequest(
      const RMeshBlueprint* blueprint,
      const Wm3::Quatf& orientation,
      std::uint32_t color,
      const Wm3::Vec3f& viewOffsetHint,
      const boost::shared_ptr<ID3DTextureSheet>& outputSheet,
      const gpg::Rect2f& outputRect
    );

    /**
     * Address: 0x007EB6B0 (FUN_007EB6B0)
     *
     * What it does:
     * Processes all currently pending requests and moves successfully rendered
     * entries to the completed queue.
     */
    void ProcessPendingRequests();

    /**
     * Address: 0x007EBB60 (FUN_007EBB60)
     *
     * What it does:
     * Clears and destroys all currently completed thumbnail requests.
     */
    void ClearCompletedRequests();

  private:
    /**
     * Address: 0x007EAAF0 (FUN_007EAAF0)
     *
     * What it does:
     * Lazily initializes thumbnail texture/render-target/depth-stencil resources.
     */
    void EnsureTargets();

    /**
     * Address: 0x007EAD80 (FUN_007EAD80)
     *
     * What it does:
     * Releases render-target/depth-stencil ownership and marks targets as uninitialized.
     */
    void ReleaseTargets();

    /**
     * Address: 0x007EB740 (FUN_007EB740)
     *
     * What it does:
     * Renders one queued thumbnail entry and writes it into the destination texture sheet.
     */
    [[nodiscard]] bool RenderThumbnail(MeshThumbnail& request);

    void ClearQueue(MeshThumbnailQueue& queue);

  public:
    std::uint8_t mRenderResourcesInitialized; // +0x04
    std::uint8_t mPad05_07[0x03]{};
    boost::shared_ptr<TextureD3D9> mThumbnailTexture;  // +0x08
    boost::shared_ptr<ID3DRenderTarget> mColorTarget;  // +0x10
    boost::shared_ptr<ID3DDepthStencil> mDepthStencil; // +0x18
    std::uint32_t mNextRequestId;                      // +0x20
    MeshThumbnailQueue mPendingRequests;               // +0x24
    MeshThumbnailQueue mCompletedRequests;             // +0x30
  };

  static_assert(sizeof(boost::shared_ptr<TextureD3D9>) == 0x08, "boost::shared_ptr<TextureD3D9> size must be 0x08");
  static_assert(
    sizeof(boost::shared_ptr<ID3DRenderTarget>) == 0x08, "boost::shared_ptr<ID3DRenderTarget> size must be 0x08"
  );
  static_assert(
    sizeof(boost::shared_ptr<ID3DDepthStencil>) == 0x08, "boost::shared_ptr<ID3DDepthStencil> size must be 0x08"
  );
  static_assert(offsetof(MeshThumbnailNode, next) == 0x00, "MeshThumbnailNode::next offset must be 0x00");
  static_assert(offsetof(MeshThumbnailNode, prev) == 0x04, "MeshThumbnailNode::prev offset must be 0x04");
  static_assert(offsetof(MeshThumbnailNode, value) == 0x08, "MeshThumbnailNode::value offset must be 0x08");
  static_assert(sizeof(MeshThumbnailNode) == 0x310, "MeshThumbnailNode size must be 0x310");
  static_assert(offsetof(MeshThumbnailQueue, proxy) == 0x00, "MeshThumbnailQueue::proxy offset must be 0x00");
  static_assert(offsetof(MeshThumbnailQueue, head) == 0x04, "MeshThumbnailQueue::head offset must be 0x04");
  static_assert(offsetof(MeshThumbnailQueue, size) == 0x08, "MeshThumbnailQueue::size offset must be 0x08");
  static_assert(sizeof(MeshThumbnailQueue) == 0x0C, "MeshThumbnailQueue size must be 0x0C");
  static_assert(
    offsetof(MeshThumbnailRenderer, mRenderResourcesInitialized) == 0x04,
    "MeshThumbnailRenderer::mRenderResourcesInitialized offset must be 0x04"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mThumbnailTexture) == 0x08,
    "MeshThumbnailRenderer::mThumbnailTexture offset must be 0x08"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mColorTarget) == 0x10, "MeshThumbnailRenderer::mColorTarget offset must be 0x10"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mDepthStencil) == 0x18, "MeshThumbnailRenderer::mDepthStencil offset must be 0x18"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mNextRequestId) == 0x20, "MeshThumbnailRenderer::mNextRequestId offset must be 0x20"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mPendingRequests) == 0x24,
    "MeshThumbnailRenderer::mPendingRequests offset must be 0x24"
  );
  static_assert(
    offsetof(MeshThumbnailRenderer, mCompletedRequests) == 0x30,
    "MeshThumbnailRenderer::mCompletedRequests offset must be 0x30"
  );
  static_assert(sizeof(MeshThumbnailRenderer) == 0x3C, "MeshThumbnailRenderer size must be 0x3C");
} // namespace moho
