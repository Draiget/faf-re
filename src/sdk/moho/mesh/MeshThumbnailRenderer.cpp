#include "MeshThumbnailRenderer.h"

#include <cmath>
#include <limits>
#include <stdexcept>

#include "moho/mesh/Mesh.h"

namespace
{
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

  [[nodiscard]] moho::MeshThumbnailNode* CreateQueueHead()
  {
    moho::MeshThumbnailNode* const head = new moho::MeshThumbnailNode{};
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
   * Address: 0x007EBD50 (FUN_007EBD50)
   *
   * What it does:
   * Allocates one node and inserts it before `position`.
   */
  void InsertBefore(
    moho::MeshThumbnailQueue& queue, moho::MeshThumbnailNode* const position, const moho::MeshThumbnail& value
  )
  {
    moho::MeshThumbnailNode* const node = new moho::MeshThumbnailNode{};
    node->value = value;

    node->next = position;
    node->prev = position->prev;
    position->prev->next = node;
    position->prev = node;
    IncrementQueueSizeOrThrow(queue.size);
  }

  [[nodiscard]] moho::GeomCamera3 BuildApproximateThumbnailCamera(
    const moho::MeshInstance* const meshInstance, const Wm3::Vec3f& viewOffsetHint
  ) noexcept
  {
    moho::GeomCamera3 camera{};
    camera.tranform.orient_ = Wm3::Quatf::Identity();
    camera.projection = moho::VMatrix4::Identity();
    camera.view = moho::VMatrix4::Identity();
    camera.viewProjection = moho::VMatrix4::Identity();
    camera.inverseProjection = moho::VMatrix4::Identity();
    camera.inverseView = moho::VMatrix4::Identity();
    camera.inverseViewProjection = moho::VMatrix4::Identity();
    camera.viewport = moho::VMatrix4::Identity();

    Wm3::Vec3f boundsMin{-0.5f, -0.5f, -0.5f};
    Wm3::Vec3f boundsMax{0.5f, 0.5f, 0.5f};
    if (meshInstance && HasFiniteBounds(*meshInstance)) {
      boundsMin = {meshInstance->xMin, meshInstance->yMin, meshInstance->zMin};
      boundsMax = {meshInstance->xMax, meshInstance->yMax, meshInstance->zMax};
    }

    const Wm3::Vec3f center{
      (boundsMin.x + boundsMax.x) * 0.5f, (boundsMin.y + boundsMax.y) * 0.5f, (boundsMin.z + boundsMax.z) * 0.5f
    };
    const Wm3::Vec3f halfExtents{
      (boundsMax.x - boundsMin.x) * 0.5f, (boundsMax.y - boundsMin.y) * 0.5f, (boundsMax.z - boundsMin.z) * 0.5f
    };

    float halfDiagonal = std::sqrt(VectorLengthSq(halfExtents));
    if (!Finite(halfDiagonal) || halfDiagonal < 0.001f) {
      halfDiagonal = 1.0f;
    }

    Wm3::Vec3f viewDir = viewOffsetHint;
    if (!Finite(viewDir.x) || !Finite(viewDir.y) || !Finite(viewDir.z) || VectorLengthSq(viewDir) <= 1.0e-6f) {
      viewDir = {1.0f, 1.0f, 1.0f};
    }

    const float cameraDistance = halfDiagonal * 10.0f;
    camera.tranform.pos_ = {
      center.x + viewDir.x * cameraDistance,
      center.y + viewDir.y * cameraDistance,
      center.z + viewDir.z * cameraDistance
    };
    camera.lodScale = halfDiagonal;
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

    const GeomCamera3 camera = BuildApproximateThumbnailCamera(meshInstance, viewOffsetHint);
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
