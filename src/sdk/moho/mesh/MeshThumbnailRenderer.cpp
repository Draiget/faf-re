#include "MeshThumbnailRenderer.h"

#include <cmath>
#include <limits>
#include <new>
#include <stdexcept>

#include "moho/mesh/Mesh.h"

namespace moho
{
  struct WRenViewport;
  extern WRenViewport* ren_Viewport;
}

namespace
{
  struct WRenViewportThumbnailRendererRuntime
  {
    std::uint8_t mUnknown000_33F[0x340];
    moho::MeshThumbnailRenderer mThumbnailRenderer;
  };

  static_assert(
    offsetof(WRenViewportThumbnailRendererRuntime, mThumbnailRenderer) == 0x340,
    "WRenViewportThumbnailRendererRuntime::mThumbnailRenderer offset must be 0x340"
  );

  [[nodiscard]] moho::MeshThumbnailRenderer& GetViewportThumbnailRenderer(moho::WRenViewport* const viewport) noexcept
  {
    auto* const viewportRuntime = reinterpret_cast<WRenViewportThumbnailRendererRuntime*>(viewport);
    return viewportRuntime->mThumbnailRenderer;
  }

  [[nodiscard]] float VectorLengthSq(const Wm3::Vec3f& v) noexcept
  {
    return v.x * v.x + v.y * v.y + v.z * v.z;
  }

  [[nodiscard]] bool Finite(const float value) noexcept
  {
    return std::isfinite(value);
  }

  [[nodiscard]] bool HasFiniteBounds(const moho::MeshInstance& meshInstance) noexcept
  {
    return Finite(meshInstance.xMin) && Finite(meshInstance.yMin) && Finite(meshInstance.zMin) &&
      Finite(meshInstance.xMax) && Finite(meshInstance.yMax) && Finite(meshInstance.zMax);
  }

  /**
   * Address: 0x007EBC80 (FUN_007EBC80)
   *
   * What it does:
   * Allocates one intrusive queue-head node and initializes the head as a
   * self-linked sentinel.
   */
  [[nodiscard]] moho::MeshThumbnailNode* CreateQueueHead()
  {
    moho::MeshThumbnailNode* const head = new (std::nothrow) moho::MeshThumbnailNode{};
    if (head == nullptr) {
      return nullptr;
    }
    head->next = head;
    head->prev = head;
    return head;
  }

  void DetachNode(moho::MeshThumbnailNode* const node) noexcept
  {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node;
    node->prev = node;
  }

  /**
   * Address: 0x007EBDE0 (FUN_007EBDE0)
   *
   * What it does:
   * Increments queue size and throws `length_error` when size overflows.
   */
  void IncrementQueueSizeOrThrow(std::uint32_t& size)
  {
    if (size == std::numeric_limits<std::uint32_t>::max()) {
      throw std::length_error("list<T> too long");
    }

    ++size;
  }

  /**
   * Address: 0x007EC050 (FUN_007EC050)
   *
   * IDA signature:
   * Moho::MeshThumbnail *__cdecl sub_7EC050(Moho::MeshThumbnail *a1);
   *
   * What it does:
   * Guarded copy-construct wrapper the release binary used when a queue
   * node had just been allocated: when the destination slot is non-null,
   * invokes `MeshThumbnail::MeshThumbnail(const MeshThumbnail&)` on the
   * supplied `source`; otherwise returns the slot pointer untouched. The
   * SEH frame in the raw listing is the compiler-emitted stack unwinder
   * for the copy constructor; no additional engine-level guard is
   * needed here because `MeshThumbnail`'s copy constructor is
   * exception-safe and releases its own partial state on failure.
   */
  moho::MeshThumbnail* ConstructMeshThumbnailInAllocatedSlot(
    moho::MeshThumbnail* const destination, const moho::MeshThumbnail& source
  )
  {
    if (destination == nullptr) {
      return destination;
    }

    return ::new (destination) moho::MeshThumbnail(source);
  }

  /**
   * Address: 0x007EBD50 (FUN_007EBD50)
   *
   * What it does:
   * Allocates one node and inserts it before `position`. The freshly
   * allocated node is value-initialized, then its `value` slot receives
   * the incoming thumbnail via the recovered copy-construct helper
   * (`ConstructMeshThumbnailInAllocatedSlot`) so the observable
   * allocation-then-copy sequence matches the release binary.
   */
  void InsertBefore(
    moho::MeshThumbnailQueue& queue, moho::MeshThumbnailNode* const position, const moho::MeshThumbnail& value
  )
  {
    moho::MeshThumbnailNode* const node = new moho::MeshThumbnailNode{};
    node->value.~MeshThumbnail();
    (void)ConstructMeshThumbnailInAllocatedSlot(&node->value, value);

    node->next = position;
    node->prev = position->prev;
    position->prev->next = node;
    position->prev = node;
    IncrementQueueSizeOrThrow(queue.size);
  }

  /**
   * The camera derivation inside MeshThumbnailRenderer::PushRequest
   * (0x007EB150, 0x007EB1F0..0x007EB2C6).
   *
   * What it does:
   * Frames the mesh for a thumbnail. Looks at the bounds centre from ten
   * bounding-sphere radii away along the caller's hint direction, then
   * projects the bounds through the resulting view to size an orthographic
   * volume that just contains them.
   *
   * The near and far planes are the smaller and larger of the two projected
   * Z magnitudes, and the ortho extent is the larger of the projected width
   * and height - so the mesh is framed by whichever axis needs more room.
   * Both ortho extents get that one value, which is why thumbnails come out
   * square regardless of the mesh's aspect.
   *
   * This replaces an approximation that left every camera matrix as identity
   * and only positioned the transform, which meant the projection step never
   * ran and ProjectBoxByMatrix (0x007E9AD0) had no caller.
   */
  [[nodiscard]] moho::GeomCamera3 BuildThumbnailCamera(
    const moho::MeshInstance* const meshInstance, const Wm3::Vec3f& viewOffsetHint
  )
  {
    moho::GeomCamera3 camera{};

    // A missing or non-finite instance has no bounds to frame; the unit box
    // keeps the derivation below well-defined. The binary reaches this only
    // with a live instance.
    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min = Wm3::Vector3f(-0.5f, -0.5f, -0.5f);
    bounds.Max = Wm3::Vector3f(0.5f, 0.5f, 0.5f);
    if (meshInstance != nullptr && HasFiniteBounds(*meshInstance)) {
      bounds.Min = Wm3::Vector3f(meshInstance->xMin, meshInstance->yMin, meshInstance->zMin);
      bounds.Max = Wm3::Vector3f(meshInstance->xMax, meshInstance->yMax, meshInstance->zMax);
    }

    const Wm3::Vector3f center(
      (bounds.Min.X() + bounds.Max.X()) * 0.5f,
      (bounds.Min.Y() + bounds.Max.Y()) * 0.5f,
      (bounds.Min.Z() + bounds.Max.Z()) * 0.5f
    );

    // Bounding-sphere radius: the distance from the centre to the max corner.
    const float dx = bounds.Max.X() - center.X();
    const float dy = bounds.Max.Y() - center.Y();
    const float dz = bounds.Max.Z() - center.Z();
    const float radius = std::sqrt((dx * dx) + (dy * dy) + (dz * dz));

    const float eyeDistance = radius * 10.0f;
    const Wm3::Vector3f eye(
      viewOffsetHint.x * eyeDistance,
      viewOffsetHint.y * eyeDistance,
      viewOffsetHint.z * eyeDistance
    );
    const Wm3::Vector3f up(0.0f, 1.0f, 0.0f);

    camera.LookAt(eye, center, up);

    Wm3::AxisAlignedBox3f projected{};
    (void)moho::ProjectBoxByMatrix(&camera.view, &bounds, &projected);

    const float nearMagnitude = std::fabs(projected.Max.Z());
    const float farMagnitude = std::fabs(projected.Min.Z());
    const float nearDepth = std::min(nearMagnitude, farMagnitude);
    const float farDepth = std::max(nearMagnitude, farMagnitude);

    const float projectedWidth = projected.Max.X() - projected.Min.X();
    const float projectedHeight = projected.Max.Y() - projected.Min.Y();
    const float extent = std::max(projectedWidth, projectedHeight);

    camera.ViewInitOrtho(
      static_cast<std::int32_t>(extent),
      static_cast<std::int32_t>(extent),
      nearDepth,
      farDepth
    );
    return camera;
  }

  /**
   * Address: 0x007EB050 (FUN_007EB050, sub_7EB050)
   *
   * What it does:
   * Creates one mesh-instance request with unit mesh scale, then forwards
   * prepared camera/orientation/output metadata into renderer queue insertion.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t EnqueueRequestWithPreparedCamera(
    moho::MeshThumbnailRenderer& renderer,
    const moho::RMeshBlueprint* const blueprint,
    const Wm3::Quatf& orientation,
    const std::uint32_t color,
    const moho::GeomCamera3& camera,
    const boost::shared_ptr<moho::ID3DTextureSheet>& outputSheet,
    const gpg::Rect2f& outputRect
  )
  {
    moho::MeshInstance* meshInstance = nullptr;
    moho::MeshRenderer* const meshRenderer = moho::MeshRenderer::GetInstance();
    if (meshRenderer != nullptr && blueprint != nullptr) {
      const Wm3::Vec3f unitScale{1.0f, 1.0f, 1.0f};
      meshInstance = meshRenderer->CreateMeshInstance(
        0, static_cast<std::int32_t>(color), blueprint, unitScale, false, boost::shared_ptr<moho::MeshMaterial>()
      );
    }

    return renderer.EnqueuePreparedRequest(meshInstance, camera, orientation, color, outputRect, outputSheet);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007FA620 (FUN_007FA620, ?REN_RequestThumbnail@Moho@@YAIPBVRMeshBlueprint@1@ABV?$Quaternion@M@Wm3@@IABV?$Vector3@M@4@V?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Rect2@M@gpg@@@Z)
   * Mangled: ?REN_RequestThumbnail@Moho@@YAIPBVRMeshBlueprint@1@ABV?$Quaternion@M@Wm3@@IABV?$Vector3@M@4@V?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Rect2@M@gpg@@@Z
   *
   * What it does:
   * Copies one texture-sheet shared-pointer lane and forwards the thumbnail
   * request into the active global viewport thumbnail-renderer queue.
   */
  std::uint32_t REN_RequestThumbnail(
    const RMeshBlueprint* const blueprint,
    const Wm3::Quatf& orientation,
    const std::uint32_t color,
    const Wm3::Vec3f& viewOffsetHint,
    boost::shared_ptr<ID3DTextureSheet> outputSheet,
    const gpg::Rect2f& outputRect
  )
  {
    boost::shared_ptr<ID3DTextureSheet> retainedOutputSheet(outputSheet);
    return GetViewportThumbnailRenderer(ren_Viewport)
      .PushRequest(blueprint, orientation, color, viewOffsetHint, retainedOutputSheet, outputRect);
  }

  /**
   * Address: 0x007EA920 (FUN_007EA920)
   *
   * What it does:
   * Initializes thumbnail renderer resources and both intrusive request queues.
   */
  MeshThumbnailRenderer::MeshThumbnailRenderer()
    : mRenderResourcesInitialized(0)
    , mPad05_07{}
    , mThumbnailTexture()
    , mColorTarget()
    , mDepthStencil()
    , mNextRequestId(0)
    , mPendingRequests{}
    , mCompletedRequests{}
  {
    mPendingRequests.proxy = nullptr;
    mPendingRequests.head = CreateQueueHead();
    mPendingRequests.size = 0;

    try {
      mCompletedRequests.proxy = nullptr;
      mCompletedRequests.head = CreateQueueHead();
      mCompletedRequests.size = 0;
    } catch (...) {
      delete mPendingRequests.head;
      mPendingRequests.head = nullptr;
      throw;
    }
  }

  /**
   * Address: 0x007EA9C0 (FUN_007EA9C0)
   * Deleting thunk: 0x007EA9A0 (FUN_007EA9A0)
   *
   * What it does:
   * Releases render-target state and tears down pending/completed request queues.
   */
  MeshThumbnailRenderer::~MeshThumbnailRenderer()
  {
    ReleaseTargets();

    ClearQueue(mCompletedRequests);
    delete mCompletedRequests.head;
    mCompletedRequests.head = nullptr;
    mCompletedRequests.proxy = nullptr;

    ClearQueue(mPendingRequests);
    delete mPendingRequests.head;
    mPendingRequests.head = nullptr;
    mPendingRequests.proxy = nullptr;
  }

  /**
   * Address: 0x007EAAF0 (FUN_007EAAF0)
   *
   * What it does:
   * Lazily initializes thumbnail texture/render-target/depth-stencil resources.
   */
  void MeshThumbnailRenderer::EnsureTargets()
  {
    if (mRenderResourcesInitialized != 0) {
      return;
    }

    // Recovered constants: 512x512 thumbnail surface, color format=2, depth format=3.
    // Full D3D device/resource interface lifting is still in progress, so we keep
    // this method as the explicit initialization seam.
    mRenderResourcesInitialized = 1;
  }

  /**
   * Address: 0x007EAD80 (FUN_007EAD80)
   *
   * What it does:
   * Releases render-target/depth-stencil ownership and marks targets as uninitialized.
   */
  void MeshThumbnailRenderer::ReleaseTargets()
  {
    mThumbnailTexture.reset();
    mColorTarget.reset();
    mDepthStencil.reset();
    mRenderResourcesInitialized = 0;
  }

  /**
   * Address: 0x007EAE40 (FUN_007EAE40)
   *
   * What it does:
   * Assigns one monotonic request id, snapshots request payload, and pushes it
   * onto the pending thumbnail queue.
   */
  std::uint32_t MeshThumbnailRenderer::EnqueuePreparedRequest(
    MeshInstance* const meshInstance,
    const GeomCamera3& camera,
    const Wm3::Quatf& orientation,
    const std::uint32_t color,
    const gpg::Rect2f& outputRect,
    const boost::shared_ptr<ID3DTextureSheet>& outputSheet
  )
  {
    const std::uint32_t requestId = mNextRequestId++;
    MeshThumbnail request(camera, requestId, meshInstance, orientation, color, outputRect, outputSheet);
    InsertBefore(mPendingRequests, mPendingRequests.head, request);
    return requestId;
  }

  /**
   * Address: 0x007EB150 (FUN_007EB150)
   *
   * What it does:
   * Builds a mesh instance from blueprint input, derives one thumbnail camera
   * transform, then forwards to prepared-request enqueue.
   */
  std::uint32_t MeshThumbnailRenderer::PushRequest(
    const RMeshBlueprint* const blueprint,
    const Wm3::Quatf& orientation,
    const std::uint32_t color,
    const Wm3::Vec3f& viewOffsetHint,
    const boost::shared_ptr<ID3DTextureSheet>& outputSheet,
    const gpg::Rect2f& outputRect
  )
  {
    MeshInstance* meshInstance = nullptr;
    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    if (meshRenderer != nullptr && blueprint != nullptr) {
      const Wm3::Vec3f unitScale{1.0f, 1.0f, 1.0f};
      meshInstance = meshRenderer->CreateMeshInstance(
        0, static_cast<std::int32_t>(color), blueprint, unitScale, false, boost::shared_ptr<MeshMaterial>()
      );
    }

    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
    }

    const GeomCamera3 camera = BuildThumbnailCamera(meshInstance, viewOffsetHint);
    return EnqueuePreparedRequest(meshInstance, camera, orientation, color, outputRect, outputSheet);
  }

  /**
   * Address: 0x007EB6B0 (FUN_007EB6B0)
   *
   * What it does:
   * Processes all currently pending requests and moves successfully rendered
   * entries to the completed queue.
   */
  void MeshThumbnailRenderer::ProcessPendingRequests()
  {
    if (mPendingRequests.head == nullptr || mPendingRequests.size == 0) {
      return;
    }

    EnsureTargets();

    MeshThumbnailNode* node = mPendingRequests.head->next;
    while (node != mPendingRequests.head) {
      MeshThumbnailNode* const next = node->next;
      if (RenderThumbnail(node->value)) {
        InsertBefore(mCompletedRequests, mCompletedRequests.head, node->value);
      }

      DetachNode(node);
      if (mPendingRequests.size > 0) {
        --mPendingRequests.size;
      }
      delete node;
      node = next;
    }
  }

  /**
   * Address: 0x007EB740 (FUN_007EB740)
   *
   * What it does:
   * Renders one queued thumbnail entry and writes it into the destination texture sheet.
   */
  bool MeshThumbnailRenderer::RenderThumbnail(MeshThumbnail& request)
  {
    if (request.meshInstance == nullptr) {
      return false;
    }

    VTransform stance{};
    stance.orient_ = request.orientation;
    stance.pos_ = {0.0f, 0.0f, 0.0f};
    request.meshInstance->SetStance(stance, stance);

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    if (meshRenderer != nullptr && mColorTarget && mDepthStencil) {
      meshRenderer->RenderThumbnail(request.camera, request.meshInstance, mColorTarget.get(), mDepthStencil.get());
    }

    if (request.outputSheet) {
      // Binary flow copies the color target into the destination texture-sheet
      // rect using device surface updates. The typed sheet/surface interface
      // chain is being reconstructed in a follow-up pass.
    }

    // Texture-sheet upload sequence (surface acquire + device update) is still
    // being lifted with typed D3D interfaces.
    request.meshInstance->Release(1);
    request.meshInstance = nullptr;
    return true;
  }

  void MeshThumbnailRenderer::ClearQueue(MeshThumbnailQueue& queue)
  {
    if (queue.head == nullptr) {
      queue.size = 0;
      return;
    }

    MeshThumbnailNode* node = queue.head->next;
    while (node != queue.head) {
      MeshThumbnailNode* const next = node->next;
      DetachNode(node);
      delete node;
      node = next;
    }

    queue.head->next = queue.head;
    queue.head->prev = queue.head;
    queue.size = 0;
  }

  /**
   * Address: 0x007EBB60 (FUN_007EBB60)
   *
   * What it does:
   * Clears and destroys all currently completed thumbnail requests.
   */
  void MeshThumbnailRenderer::ClearCompletedRequests()
  {
    ClearQueue(mCompletedRequests);
  }
} // namespace moho
