#include "Mesh.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"

namespace
{
  [[nodiscard]] float NanValue() noexcept
  {
    return std::numeric_limits<float>::quiet_NaN();
  }

  [[nodiscard]] bool FloatEqual(const float lhs, const float rhs) noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] bool Vec3EqualExact(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    return FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] bool QuatEqualExact(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return FloatEqual(lhs.w, rhs.w) && FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] bool Finite(const float value) noexcept
  {
    return std::isfinite(value);
  }

  [[nodiscard]] bool HasFiniteWorldBounds(const moho::MeshInstance& instance) noexcept
  {
    return Finite(instance.xMin) && Finite(instance.yMin) && Finite(instance.zMin) && Finite(instance.xMax) &&
      Finite(instance.yMax) && Finite(instance.zMax);
  }

  [[nodiscard]] float Clamp01(const float value) noexcept
  {
    return std::clamp(value, 0.0f, 1.0f);
  }

  void UpdateFallbackWorldBounds(moho::MeshInstance& instance) noexcept
  {
    float maxScale = std::max(instance.scale.x, std::max(instance.scale.y, instance.scale.z));
    if (!(maxScale > 0.0f)) {
      maxScale = 1.0f;
    }

    const float halfExtent = maxScale * 0.5f;
    instance.sphere.Center = instance.interpolatedPosition;
    instance.sphere.Radius = halfExtent;

    instance.xMin = instance.interpolatedPosition.x - halfExtent;
    instance.yMin = instance.interpolatedPosition.y - halfExtent;
    instance.zMin = instance.interpolatedPosition.z - halfExtent;
    instance.xMax = instance.interpolatedPosition.x + halfExtent;
    instance.yMax = instance.interpolatedPosition.y + halfExtent;
    instance.zMax = instance.interpolatedPosition.z + halfExtent;

    instance.renderMinX = instance.xMin;
    instance.renderMinY = instance.yMin;
    instance.renderMinZ = instance.zMin;
    instance.renderMaxX = instance.xMax;
    instance.renderMaxY = instance.yMax;
    instance.renderMaxZ = instance.zMax;

    instance.box.Center[0] = instance.interpolatedPosition.x;
    instance.box.Center[1] = instance.interpolatedPosition.y;
    instance.box.Center[2] = instance.interpolatedPosition.z;
    instance.box.Axis[0][0] = 1.0f;
    instance.box.Axis[0][1] = 0.0f;
    instance.box.Axis[0][2] = 0.0f;
    instance.box.Axis[1][0] = 0.0f;
    instance.box.Axis[1][1] = 1.0f;
    instance.box.Axis[1][2] = 0.0f;
    instance.box.Axis[2][0] = 0.0f;
    instance.box.Axis[2][1] = 0.0f;
    instance.box.Axis[2][2] = 1.0f;
    instance.box.Extent[0] = halfExtent;
    instance.box.Extent[1] = halfExtent;
    instance.box.Extent[2] = halfExtent;
    instance.boundsValid = 1;
  }

  [[nodiscard]] std::uintptr_t PointerOrderKey(const void* const ptr) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ptr);
  }

  constexpr float kMeshDissolveDistanceBias = 0.0f;
  constexpr std::int32_t kMeshSpatialDbRoutingMask = 0x800;

  struct SpatialDbStorageRootView
  {
    std::uint8_t pad_00_83[0x84];
    void* orderedEntryRoot;     // +0x84
    void* orderedEntrySentinel; // +0x88
  };

  static_assert(
    offsetof(SpatialDbStorageRootView, orderedEntryRoot) == 0x84,
    "SpatialDbStorageRootView::orderedEntryRoot offset must be 0x84"
  );
  static_assert(
    offsetof(SpatialDbStorageRootView, orderedEntrySentinel) == 0x88,
    "SpatialDbStorageRootView::orderedEntrySentinel offset must be 0x88"
  );
  static_assert(sizeof(SpatialDbStorageRootView) == 0x8C, "SpatialDbStorageRootView size must be 0x8C");

  struct SpatialDbEntryPayload
  {
    std::uint32_t words[10];
  };

  static_assert(sizeof(SpatialDbEntryPayload) == 0x28, "SpatialDbEntryPayload size must be 0x28");

  constexpr std::size_t kSpatialDbEntryPayloadOffset = 0x0C;
  constexpr std::size_t kSpatialDbEntryTreeNodeOffset = 0x28;
  constexpr std::size_t kSpatialDbPayloadRoutingMaskWord = 6;
  constexpr std::size_t kSpatialDbPayloadKeyMetricWord = 8;
  constexpr std::size_t kSpatialDbPayloadOwnerWord = 9;

  [[nodiscard]] std::uint8_t* EntryBytes(const std::int32_t entry) noexcept
  {
    if (entry == 0) {
      return nullptr;
    }

    return reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(entry)));
  }

  void SeedSpatialPayload(SpatialDbEntryPayload& payload, const std::int32_t routingMask, void* const owner) noexcept
  {
    std::memset(&payload, 0, sizeof(payload));
    payload.words[kSpatialDbPayloadRoutingMaskWord] = static_cast<std::uint32_t>(routingMask);
    payload.words[kSpatialDbPayloadOwnerWord] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(owner));
  }

  void SetPayloadKeyMetric(SpatialDbEntryPayload& payload, const float keyMetric) noexcept
  {
    std::memcpy(&payload.words[kSpatialDbPayloadKeyMetricWord], &keyMetric, sizeof(keyMetric));
  }

  [[nodiscard]] moho::VTransform IdentityTransform() noexcept
  {
    moho::VTransform transform{};
    transform.orient_.w = 1.0f;
    transform.orient_.x = 0.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
    return transform;
  }

  [[nodiscard]] boost::shared_ptr<moho::RScmResource>
  ResolveMeshResourceForLod(const msvc8::string& meshPath, moho::Mesh* const ownerWatcher)
  {
    // Address chain: 0x007DCED0 -> 0x00539BA0 -> 0x004ABEE0 -> 0x004AA220.
    // Full resource-manager lifting is pending; keep the API seam typed.
    (void)meshPath;
    (void)ownerWatcher;
    return {};
  }

  [[nodiscard]] msvc8::string ResolveShaderAnnotationName(const msvc8::string& shaderName)
  {
    // Address chain: 0x007DC1B0 -> 0x007DBDB0.
    // Full ShaderDictionary remap semantics are pending; keep default behavior:
    // empty shader picks "Unit", otherwise keep provided shader key.
    if (shaderName.empty()) {
      return msvc8::string("Unit");
    }

    return msvc8::string(shaderName.view());
  }

  [[nodiscard]] boost::shared_ptr<moho::CD3DDynamicTextureSheet>
  ResolveMaterialTextureSheet(const msvc8::string& textureName, void* const resourceWatcher)
  {
    // Address chain: 0x007DC1B0 -> D3D_GetDevice/GetResources -> resource lookup vfunc.
    // Device/resource interfaces are still being reconstructed; keep this seam typed.
    (void)textureName;
    (void)resourceWatcher;
    return {};
  }

  void AssignMaterialTextureSheet(
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>& destination,
    const msvc8::string& textureName,
    void* const resourceWatcher
  )
  {
    if (textureName.empty()) {
      return;
    }

    destination = ResolveMaterialTextureSheet(textureName, resourceWatcher);
  }

  void MaybeRunExtraSoundWork()
  {
    // Address chain: 0x007DC1B0 -> gpg::time::Timer::ElapsedMilliseconds -> SND_Frame.
    // Sound-system globals are not yet reconstructed in this pass.
  }

  [[nodiscard]] boost::shared_ptr<const moho::CAniSkel>
  ResolveInitialPoseSkeleton(const boost::shared_ptr<moho::Mesh>& mesh, const bool isStaticPose)
  {
    if (!isStaticPose || !mesh) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<moho::RScmResource> resource = mesh->GetResource(0);
    if (!resource) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<const moho::CAniSkel> skeleton = resource->GetSkeleton();
    if (skeleton) {
      return skeleton;
    }

    return moho::CAniSkel::GetDefaultSkeleton();
  }

  [[nodiscard]] float ComputeSpatialDissolveCutoff(const boost::shared_ptr<moho::Mesh>& mesh)
  {
    if (!mesh) {
      return -1.0f;
    }

    moho::MeshLOD* const* const begin = mesh->lods.begin();
    moho::MeshLOD* const* const end = mesh->lods.end();
    if (!begin || !end || begin == end) {
      return -1.0f;
    }

    const moho::MeshLOD* const lastLod = *(end - 1);
    if (!lastLod || lastLod->cutoff <= 0.0f) {
      return -1.0f;
    }

    return lastLod->cutoff + kMeshDissolveDistanceBias;
  }

  constexpr std::uint8_t kRbNodeRed = 0;
  constexpr std::uint8_t kRbNodeBlack = 1;
  constexpr std::uint8_t kRbNodeSentinel = 1;

  [[nodiscard]] moho::MeshInstance::ListLink* MeshInstanceLink(moho::MeshInstance* const instance) noexcept
  {
    if (!instance) {
      return nullptr;
    }

    return reinterpret_cast<moho::MeshInstance::ListLink*>(&instance->linkPrev);
  }

  [[nodiscard]] moho::MeshInstance* MeshInstanceFromLink(moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!link) {
      return nullptr;
    }

    return reinterpret_cast<moho::MeshInstance*>(
      reinterpret_cast<std::uint8_t*>(link) - offsetof(moho::MeshInstance, linkPrev)
    );
  }

  void RemoveLinkFromList(moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!link || !link->prev || !link->next) {
      return;
    }

    link->prev->next = link->next;
    link->next->prev = link->prev;
    link->prev = link;
    link->next = link;
  }

  void InsertLinkBefore(moho::MeshInstance::ListLink* const position, moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!position || !link || !position->prev) {
      return;
    }

    link->prev = position->prev;
    link->next = position;
    position->prev->next = link;
    position->prev = link;
  }

  [[nodiscard]] bool IsMeshCacheSentinelNode(const moho::MeshRendererMeshCacheNode* const node) noexcept
  {
    return node == nullptr || node->isSentinel == kRbNodeSentinel;
  }

  [[nodiscard]] bool IsMeshBatchSentinelNode(const moho::MeshBatchBucketNode* const node) noexcept
  {
    return node == nullptr || node->isSentinel == kRbNodeSentinel;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* CreateMeshCacheNode(
    const moho::MeshKey& key,
    const boost::shared_ptr<moho::Mesh>& mesh,
    moho::MeshRendererMeshCacheNode* const left,
    moho::MeshRendererMeshCacheNode* const parent,
    moho::MeshRendererMeshCacheNode* const right,
    const std::uint8_t color,
    const std::uint8_t isSentinel
  )
  {
    void* const raw = ::operator new(sizeof(moho::MeshRendererMeshCacheNode));
    auto* const node = static_cast<moho::MeshRendererMeshCacheNode*>(raw);

    node->left = left;
    node->parent = parent;
    node->right = right;
    new (&node->entry.key) moho::MeshKey(key);
    new (&node->entry.mesh) boost::shared_ptr<moho::Mesh>(mesh);
    node->color = color;
    node->isSentinel = isSentinel;
    node->pad_26_27[0] = 0;
    node->pad_26_27[1] = 0;
    return node;
  }

  void DestroyMeshCacheNode(moho::MeshRendererMeshCacheNode* const node) noexcept
  {
    if (!node) {
      return;
    }

    node->entry.mesh.~shared_ptr<moho::Mesh>();
    node->entry.key.~MeshKey();
    ::operator delete(node);
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* CreateMeshCacheTreeSentinel()
  {
    const boost::shared_ptr<moho::MeshMaterial> emptyMaterial;
    const boost::shared_ptr<moho::Mesh> emptyMesh;
    moho::MeshKey sentinelKey(nullptr, emptyMaterial);
    moho::MeshRendererMeshCacheNode* const head =
      CreateMeshCacheNode(sentinelKey, emptyMesh, nullptr, nullptr, nullptr, kRbNodeBlack, kRbNodeSentinel);
    head->left = head;
    head->parent = head;
    head->right = head;
    return head;
  }

  void MeshCacheRotateLeft(moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    moho::MeshRendererMeshCacheNode* const pivot = node->right;
    node->right = pivot->left;
    if (!IsMeshCacheSentinelNode(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      if (node == parent->left) {
        parent->left = pivot;
      } else {
        parent->right = pivot;
      }
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void MeshCacheRotateRight(moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    moho::MeshRendererMeshCacheNode* const pivot = node->left;
    node->left = pivot->right;
    if (!IsMeshCacheSentinelNode(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      if (node == parent->right) {
        parent->right = pivot;
      } else {
        parent->left = pivot;
      }
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void
  RebalanceMeshCacheAfterInsert(moho::MeshRendererMeshCacheTree& tree, moho::MeshRendererMeshCacheNode* node) noexcept
  {
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    while (!IsMeshCacheSentinelNode(node->parent) && node->parent->color == kRbNodeRed) {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      moho::MeshRendererMeshCacheNode* const grandParent = parent->parent;
      if (parent == grandParent->left) {
        moho::MeshRendererMeshCacheNode* const uncle = grandParent->right;
        if (!IsMeshCacheSentinelNode(uncle) && uncle->color == kRbNodeRed) {
          parent->color = kRbNodeBlack;
          uncle->color = kRbNodeBlack;
          grandParent->color = kRbNodeRed;
          node = grandParent;
        } else {
          if (node == parent->right) {
            node = parent;
            MeshCacheRotateLeft(node, tree);
          }
          node->parent->color = kRbNodeBlack;
          node->parent->parent->color = kRbNodeRed;
          MeshCacheRotateRight(node->parent->parent, tree);
        }
      } else {
        moho::MeshRendererMeshCacheNode* const uncle = grandParent->left;
        if (!IsMeshCacheSentinelNode(uncle) && uncle->color == kRbNodeRed) {
          parent->color = kRbNodeBlack;
          uncle->color = kRbNodeBlack;
          grandParent->color = kRbNodeRed;
          node = grandParent;
        } else {
          if (node == parent->left) {
            node = parent;
            MeshCacheRotateRight(node, tree);
          }
          node->parent->color = kRbNodeBlack;
          node->parent->parent->color = kRbNodeRed;
          MeshCacheRotateLeft(node->parent->parent, tree);
        }
      }
    }

    if (!IsMeshCacheSentinelNode(head->parent)) {
      head->parent->color = kRbNodeBlack;
    }
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode*
  MeshCacheTreeLowerBound(const moho::MeshRendererMeshCacheTree& tree, const moho::MeshKey& key) noexcept
  {
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    moho::MeshRendererMeshCacheNode* candidate = head;
    for (moho::MeshRendererMeshCacheNode* node = head->parent; !IsMeshCacheSentinelNode(node);) {
      if (node->entry.key.LessThan(key)) {
        node = node->right;
      } else {
        candidate = node;
        node = node->left;
      }
    }

    return candidate;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode*
  MeshCacheTreeFind(const moho::MeshRendererMeshCacheTree& tree, const moho::MeshKey& key) noexcept
  {
    moho::MeshRendererMeshCacheNode* const candidate = MeshCacheTreeLowerBound(tree, key);
    if (!candidate || candidate == tree.head) {
      return nullptr;
    }

    return candidate->entry.key.Equals(key) ? candidate : nullptr;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* MeshCacheTreeInsertUnique(
    moho::MeshRendererMeshCacheTree& tree,
    const moho::MeshKey& key,
    const boost::shared_ptr<moho::Mesh>& mesh,
    bool& inserted
  )
  {
    inserted = false;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    moho::MeshRendererMeshCacheNode* parent = head;
    moho::MeshRendererMeshCacheNode* node = head->parent;
    bool insertLeft = true;
    while (!IsMeshCacheSentinelNode(node)) {
      parent = node;
      if (key.LessThan(node->entry.key)) {
        insertLeft = true;
        node = node->left;
        continue;
      }

      if (node->entry.key.LessThan(key)) {
        insertLeft = false;
        node = node->right;
        continue;
      }

      return node;
    }

    moho::MeshRendererMeshCacheNode* const insertedNode =
      CreateMeshCacheNode(key, mesh, head, parent, head, kRbNodeRed, 0);
    if (parent == head) {
      head->parent = insertedNode;
      head->left = insertedNode;
      head->right = insertedNode;
    } else if (insertLeft) {
      parent->left = insertedNode;
      if (parent == head->left) {
        head->left = insertedNode;
      }
    } else {
      parent->right = insertedNode;
      if (parent == head->right) {
        head->right = insertedNode;
      }
    }

    ++tree.size;
    RebalanceMeshCacheAfterInsert(tree, insertedNode);
    inserted = true;
    return insertedNode;
  }

  void ClearMeshCacheTreeNodes(
    moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheNode* const head
  ) noexcept
  {
    if (!node || node == head || IsMeshCacheSentinelNode(node)) {
      return;
    }

    ClearMeshCacheTreeNodes(node->left, head);
    ClearMeshCacheTreeNodes(node->right, head);
    DestroyMeshCacheNode(node);
  }

  void ResetMeshCacheTree(moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      return;
    }

    ClearMeshCacheTreeNodes(tree.head->parent, tree.head);
    tree.head->parent = tree.head;
    tree.head->left = tree.head;
    tree.head->right = tree.head;
    tree.size = 0;
  }

  void DestroyMeshCacheTree(moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      tree.proxy = nullptr;
      return;
    }

    ResetMeshCacheTree(tree);
    DestroyMeshCacheNode(tree.head);
    tree.head = nullptr;
    tree.size = 0;
    tree.proxy = nullptr;
  }

  [[nodiscard]] moho::MeshBatchBucketNode* CreateMeshBatchTreeSentinel()
  {
    auto* const head = new moho::MeshBatchBucketNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = kRbNodeBlack;
    head->isSentinel = kRbNodeSentinel;
    head->bucket.instances.proxy = nullptr;
    head->bucket.instances.first = nullptr;
    head->bucket.instances.last = nullptr;
    head->bucket.instances.end = nullptr;
    return head;
  }

  void ReleaseMeshBatchInstanceVector(moho::MeshBatchInstanceVector& vector) noexcept
  {
    if (vector.first) {
      ::operator delete(vector.first);
    }

    vector.proxy = nullptr;
    vector.first = nullptr;
    vector.last = nullptr;
    vector.end = nullptr;
  }

  void ClearMeshBatchTreeNodes(moho::MeshBatchBucketNode* const node, moho::MeshBatchBucketNode* const head) noexcept
  {
    if (!node || node == head || IsMeshBatchSentinelNode(node)) {
      return;
    }

    ClearMeshBatchTreeNodes(node->left, head);
    ClearMeshBatchTreeNodes(node->right, head);
    ReleaseMeshBatchInstanceVector(node->bucket.instances);
    delete node;
  }

  void ResetMeshBatchTree(moho::MeshBatchBucketTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      return;
    }

    ClearMeshBatchTreeNodes(tree.head->parent, tree.head);
    tree.head->parent = tree.head;
    tree.head->left = tree.head;
    tree.head->right = tree.head;
    tree.size = 0;
  }

  void DestroyMeshBatchTree(moho::MeshBatchBucketTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      tree.proxy = nullptr;
      return;
    }

    ResetMeshBatchTree(tree);
    delete tree.head;
    tree.head = nullptr;
    tree.size = 0;
    tree.proxy = nullptr;
  }

  void ResetLodBatchesForInstanceLinkList(moho::MeshInstance::ListLink& head) noexcept
  {
    for (moho::MeshInstance::ListLink* link = head.next; link && link != &head; link = link->next) {
      moho::MeshInstance* const instance = MeshInstanceFromLink(link);
      if (!instance || !instance->mesh) {
        continue;
      }

      for (moho::MeshLOD** lod = instance->mesh->lods.begin(); lod && lod != instance->mesh->lods.end(); ++lod) {
        if (*lod) {
          (*lod)->ResetBatches();
        }
      }
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00501A80 (FUN_00501A80, sub_501A80)
   *
   * What it does:
   * Registers one mesh-instance owner in the spatial-db storage and seeds entry state.
   */
  void SpatialDB_MeshInstance::Register(void* const spatialDbStorage, void* const owner, const std::int32_t routingMask)
  {
    if (db) {
      ClearRegistration();
    }

    db = spatialDbStorage;
    entry = 0;
    if (!db) {
      return;
    }

    SpatialDbEntryPayload payload{};
    SeedSpatialPayload(payload, routingMask, owner);

    // The ordered-tree insertion chain (func_CurPOI4/sub_504A10 and dependencies)
    // remains under recovery. We still keep the registration owner pointer and
    // routing key materialized in a typed payload here.
    const auto* const root = reinterpret_cast<const SpatialDbStorageRootView*>(db);
    (void)root;
    (void)payload;
  }

  /**
   * Address: 0x00501B00 (FUN_00501B00, sub_501B00)
   *
   * What it does:
   * Updates dissolve-cutoff payload in the current spatial-db entry.
   */
  void SpatialDB_MeshInstance::UpdateDissolveCutoff(const float cutoff)
  {
    if (!db || entry == 0) {
      return;
    }

    std::uint8_t* const entryBytes = EntryBytes(entry);
    if (!entryBytes) {
      return;
    }

    SpatialDbEntryPayload payload{};
    std::memcpy(&payload, entryBytes + kSpatialDbEntryPayloadOffset, sizeof(payload));
    SetPayloadKeyMetric(payload, cutoff);
    std::memcpy(entryBytes + kSpatialDbEntryPayloadOffset, &payload, sizeof(payload));

    // Reinsert/rebalance paths (sub_10102340/sub_502200/sub_5043B0/sub_10104A10)
    // are still pending full typed recovery.
  }

  void SpatialDB_MeshInstance::ClearRegistration() noexcept
  {
    if (!db) {
      entry = 0;
      return;
    }

    const std::uint8_t* const entryBytes = EntryBytes(entry);
    if (entryBytes) {
      // Binary branches on node-side tree-link presence at +0x28.
      const void* const treeNode = *reinterpret_cast<void* const*>(entryBytes + kSpatialDbEntryTreeNodeOffset);
      (void)treeNode;
    }

    // Full unlink paths are still pending; keep state reset deterministic.
    db = nullptr;
    entry = 0;
  }

  /**
   * Address: 0x00501BC0 (FUN_00501BC0, ??1SpatialDB_MeshInstance@Moho@@QAE@XZ)
   *
   * What it does:
   * Clears mesh-instance spatial-db registration state.
   */
  SpatialDB_MeshInstance::~SpatialDB_MeshInstance()
  {
    ClearRegistration();
  }

  /**
   * Address: 0x007DBEE0 (FUN_007DBEE0, ??0MeshMaterial@Moho@@QAE@XZ)
   */
  MeshMaterial::MeshMaterial()
    : mShaderAnnotation()
    , mAlbedoSheet()
    , mNormalsSheet()
    , mSpecularSheet()
    , mLookupSheet()
    , mSecondarySheet()
    , mEnvironmentSheet()
    , mShaderIndex(-1)
    , mAuxTag0()
    , mAuxTag1()
    , mRuntimeFlag0(0)
    , mRuntimeFlag1(0)
    , mPad8E_8F{}
  {}

  /**
   * Address: 0x007DBFC0 (FUN_007DBFC0, ??1MeshMaterial@Moho@@UAE@XZ)
   * Deleting thunk: 0x007DBFA0 (FUN_007DBFA0)
   */
  MeshMaterial::~MeshMaterial()
  {
    mAuxTag1.tidy(true, 0U);
    mAuxTag0.tidy(true, 0U);
    mEnvironmentSheet.reset();
    mSecondarySheet.reset();
    mLookupSheet.reset();
    mSpecularSheet.reset();
    mNormalsSheet.reset();
    mAlbedoSheet.reset();
    mShaderAnnotation.tidy(true, 0U);
  }

  /**
   * Address: 0x007DCBF0 (FUN_007DCBF0, ??4MeshMaterial@Moho@@QAEAAV01@ABV01@@Z)
   *
   * What it does:
   * Copies annotation/texture-sheet handles and runtime tags from one material.
   */
  MeshMaterial& MeshMaterial::operator=(const MeshMaterial& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    mShaderAnnotation.assign_owned(rhs.mShaderAnnotation.view());
    mAlbedoSheet = rhs.mAlbedoSheet;
    mNormalsSheet = rhs.mNormalsSheet;
    mSpecularSheet = rhs.mSpecularSheet;
    mLookupSheet = rhs.mLookupSheet;
    mSecondarySheet = rhs.mSecondarySheet;
    mEnvironmentSheet = rhs.mEnvironmentSheet;
    mShaderIndex = rhs.mShaderIndex;
    mAuxTag0.assign_owned(rhs.mAuxTag0.view());
    mAuxTag1.assign_owned(rhs.mAuxTag1.view());
    mRuntimeFlag0 = rhs.mRuntimeFlag0;
    mRuntimeFlag1 = rhs.mRuntimeFlag1;
    return *this;
  }

  /**
   * Address: 0x007DC760 (FUN_007DC760,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABVRMeshBlueprintLOD@2@PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Builds one material from one mesh LOD blueprint descriptor.
   */
  boost::shared_ptr<MeshMaterial>
  MeshMaterial::Create(const RMeshBlueprintLOD& blueprintLod, void* const resourceWatcher)
  {
    return Create(
      blueprintLod.mShaderName,
      blueprintLod.mAlbedoName,
      blueprintLod.mNormalsName,
      blueprintLod.mSpecularName,
      blueprintLod.mLookupName,
      blueprintLod.mSecondaryName,
      resourceWatcher
    );
  }

  /**
   * Address: 0x007DC1B0 (FUN_007DC1B0,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00000PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Creates one mesh material and resolves per-texture sheet handles from paths.
   */
  boost::shared_ptr<MeshMaterial> MeshMaterial::Create(
    const msvc8::string& shaderName,
    const msvc8::string& albedoName,
    const msvc8::string& normalsName,
    const msvc8::string& specularName,
    const msvc8::string& lookupName,
    const msvc8::string& secondaryName,
    void* const resourceWatcher
  )
  {
    boost::shared_ptr<MeshMaterial> material(new MeshMaterial());
    const msvc8::string resolvedShaderName = ResolveShaderAnnotationName(shaderName);
    material->mShaderAnnotation.assign_owned(resolvedShaderName.view());
    AssignMaterialTextureSheet(material->mAlbedoSheet, albedoName, resourceWatcher);
    AssignMaterialTextureSheet(material->mNormalsSheet, normalsName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSpecularSheet, specularName, resourceWatcher);
    AssignMaterialTextureSheet(material->mLookupSheet, lookupName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSecondarySheet, secondaryName, resourceWatcher);
    MaybeRunExtraSoundWork();
    return material;
  }

  /**
   * Address: 0x007DC8C0 (FUN_007DC8C0,
   * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@ABVRMeshBlueprintLOD@1@V?$shared_ptr@VMeshMaterial@Moho@@@3@PAVCResourceWatcher@1@@Z)
   *
   * What it does:
   * Initializes one runtime LOD from blueprint/material/resource fallback state.
   */
  MeshLOD::MeshLOD(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    Mesh* const ownerWatcher
  )
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res()
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {
    Load(blueprintLod, previousResourceArg, materialArg, ownerWatcher);
  }

  /**
   * Address: 0x007DD4D0 (FUN_007DD4D0)
   *
   * What it does:
   * Releases loaded resource/material state for this LOD.
   */
  void MeshLOD::Clear()
  {
    res.reset();
    lodBlueprintCopy.reset();
    mat = MeshMaterial();
    ResetBatches();
    cutoff = 1000.0f;
  }

  /**
   * Address: 0x007DD190 (FUN_007DD190)
   *
   * What it does:
   * Clears cached batch handles for this LOD.
   */
  void MeshLOD::ResetBatches()
  {
    staticBatch.reset();
    dynamicBatch.reset();
  }

  /**
   * Address: 0x007DCED0 (FUN_007DCED0)
   *
   * What it does:
   * Reloads model/material resources from one blueprint LOD entry.
   */
  void MeshLOD::Load(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    Mesh* const ownerWatcher
  )
  {
    Clear();

    lodBlueprintCopy.reset(new RMeshBlueprintLOD(blueprintLod));
    res = ResolveMeshResourceForLod(blueprintLod.mMeshName, ownerWatcher);
    previousResource = previousResourceArg ? previousResourceArg : res;
    cutoff = blueprintLod.mLodCutoff;
    scrolling = blueprintLod.mScrolling;
    occlude = blueprintLod.mOcclude;
    silhouette = blueprintLod.mSilhouette;

    if (materialArg) {
      mat = *materialArg;
    } else {
      const boost::shared_ptr<MeshMaterial> createdMaterial = MeshMaterial::Create(blueprintLod, ownerWatcher);
      if (createdMaterial) {
        mat = *createdMaterial;
      }
    }
  }

  /**
   * Address: 0x007DCD60 (FUN_007DCD60, ??1MeshLOD@Moho@@UAE@XZ)
   */
  MeshLOD::~MeshLOD()
  {
    Clear();
  }

  /**
   * Address: 0x007DD680 (FUN_007DD680,
   * ??0Mesh@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  Mesh::Mesh(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
    : watcherFlags(0)
    , watchedBegin(watchedInlineStorage)
    , watchedEnd(watchedInlineStorage)
    , watchedStorageEnd(watchedInlineStorage + sizeof(watchedInlineStorage))
    , watchedStorageOrigin(watchedInlineStorage)
    , watchedInlineStorage{}
    , bp(nullptr)
    , material()
    , unk2C(0)
    , lods()
    , unk3C(0)
  {
    Load(blueprint, materialArg);
  }

  /**
   * Address: 0x007DDAC0 (FUN_007DDAC0)
   */
  void Mesh::Clear()
  {
    for (MeshLOD** it = lods.begin(); it && it != lods.end(); ++it) {
      delete *it;
    }
    lods.clear();
    material.reset();
    bp = nullptr;
  }

  /**
   * Address: 0x007DE030 (FUN_007DE030)
   *
   * What it does:
   * Resets cached batch handles for every loaded LOD.
   */
  void Mesh::ResetBatches()
  {
    for (MeshLOD** it = lods.begin(); it && it != lods.end(); ++it) {
      if (*it) {
        (*it)->ResetBatches();
      }
    }
  }

  /**
   * Address: 0x007DD880 (FUN_007DD880, ??1Mesh@Moho@@UAE@XZ)
   */
  Mesh::~Mesh()
  {
    Clear();
  }

  /**
   * Address: 0x007DDB50 (FUN_007DDB50,
   * ?Load@Mesh@Moho@@AAEXPBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  void Mesh::Load(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    Clear();
    bp = blueprint;
    material = materialArg;

    if (!bp) {
      return;
    }

    const RMeshBlueprintLOD* const begin = bp->mLods.begin();
    if (!begin) {
      return;
    }

    for (const RMeshBlueprintLOD* lod = begin; lod != bp->mLods.end(); ++lod) {
      CreateLOD(*lod, materialArg);
    }

    if (!lods.empty() && lods.back()) {
      lods.back()->useDissolve = 1;
    }
  }

  /**
   * Address: 0x007DDC50 (FUN_007DDC50,
   * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@ABVRMeshBlueprintLOD@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshLOD* Mesh::CreateLOD(const RMeshBlueprintLOD& blueprintLod, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    boost::shared_ptr<RScmResource> previousResource;
    if (!lods.empty() && lods.front()) {
      previousResource = lods.front()->res;
    }

    MeshLOD* const lod = new MeshLOD(blueprintLod, previousResource, materialArg, this);
    lods.push_back(lod);
    return lod;
  }

  /**
   * Address: 0x007DD950 (FUN_007DD950, ?GetResource@Mesh@Moho@@QBE?AV?$shared_ptr@VRScmResource@Moho@@@boost@@H@Z)
   */
  boost::shared_ptr<RScmResource> Mesh::GetResource(const std::int32_t /*lodIndex*/) const
  {
    MeshLOD* const* const begin = lods.begin();
    if (!begin || begin == lods.end() || !*begin) {
      return {};
    }

    return (*begin)->res;
  }

  /**
   * Address: 0x007DDFC0 (FUN_007DDFC0, ?OnResourceChanged@Mesh@Moho@@EAEXVStrArg@gpg@@@Z)
   */
  void Mesh::OnResourceChanged(const gpg::StrArg /*resourcePath*/)
  {
    // Binary path may resync global resource manager before reloading watched assets.
    Load(bp, material);
  }

  /**
   * Address: 0x007DAF00 (FUN_007DAF00,
   * ??0MeshKey@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshKey::MeshKey(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> meshMaterial)
    : blueprint(blueprint)
    , meshMaterial(meshMaterial)
  {}

  /**
   * Address: 0x007DF6E0 (FUN_007DF6E0, copy ctor)
   */
  MeshKey::MeshKey(const MeshKey& rhs)
    : blueprint(rhs.blueprint)
    , meshMaterial(rhs.meshMaterial)
  {}

  /**
   * Address: 0x007DAF60 (FUN_007DAF60, ??1MeshKey@Moho@@QAE@XZ)
   * Deleting thunk: 0x007DAFC0 (FUN_007DAFC0, sub_7DAFC0)
   */
  MeshKey::~MeshKey() = default;

  bool MeshKey::Equals(const MeshKey& rhs) const noexcept
  {
    return !LessThan(rhs) && !rhs.LessThan(*this);
  }

  /**
   * Address chain: 0x007E5B20 / 0x007E5C00 comparator logic
   *
   * What it does:
   * Orders keys lexicographically by (blueprint pointer, material object pointer).
   */
  bool MeshKey::LessThan(const MeshKey& rhs) const noexcept
  {
    const std::uintptr_t lhsBlueprint = PointerOrderKey(blueprint);
    const std::uintptr_t rhsBlueprint = PointerOrderKey(rhs.blueprint);
    if (lhsBlueprint < rhsBlueprint) {
      return true;
    }
    if (lhsBlueprint > rhsBlueprint) {
      return false;
    }

    return PointerOrderKey(meshMaterial.get()) < PointerOrderKey(rhs.meshMaterial.get());
  }

  std::uint8_t MeshInstance::sFrameCounter = 0;
  float MeshInstance::sCurrentInterpolant = 0.0f;

  /**
   * Address: 0x007DE060 (FUN_007DE060,
   * ??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@HIV?$shared_ptr@VMesh@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_N@Z)
   */
  MeshInstance::MeshInstance(
    const Wm3::Vec3f& scaleArg,
    void* const spatialDbStorage,
    const std::int32_t gameTickArg,
    const std::int32_t colorArg,
    const bool isStaticPoseArg,
    const boost::shared_ptr<Mesh> meshArg
  )
    : linkPrev(nullptr)
    , linkNext(nullptr)
    , db{nullptr, 0}
    , mesh(meshArg)
    , color(colorArg)
    , meshColor(0.0f)
    , unk24(0)
    , isHidden(0)
    , isReflected(1)
    , pad_2A_2B{}
    , gameTick(gameTickArg)
    , uniformScale(1.0f)
    , scale(scaleArg)
    , endTransform(IdentityTransform())
    , startTransform(IdentityTransform())
    , curOrientation(1.0f, 0.0f, 0.0f, 0.0f)
    , interpolatedPosition(0.0f, 0.0f, 0.0f)
    , scroll1(0.0f, 0.0f)
    , scroll2(0.0f, 0.0f)
    , hasStanceUpdatePending(1)
    , isStaticPose(static_cast<std::uint8_t>(isStaticPoseArg ? 1 : 0))
    , isLocked(0)
    , pad_A7(0)
    , startPose()
    , endPose()
    , curPose()
    , dissolve(1.0f)
    , parameters(0.0f)
    , fractionCompleteParameter(1.0f)
    , fractionHealthParameter(1.0f)
    , lifetimeParameter(0.0f)
    , auxiliaryParameter(0.0f)
    , frameCounter(-1)
    , interpolationStateFresh(0)
    , pad_DA_DB{}
    , currInterpolant(-1.0f)
    , sphere{}
    , xMin(NanValue())
    , yMin(NanValue())
    , zMin(NanValue())
    , xMax(NanValue())
    , yMax(NanValue())
    , zMax(NanValue())
    , box{}
    , renderMinX(NanValue())
    , renderMinY(NanValue())
    , renderMinZ(NanValue())
    , renderMaxX(NanValue())
    , renderMaxY(NanValue())
    , renderMaxZ(NanValue())
    , boundsValid(1)
    , pad_15D_15F{}
  {
    sphere.Center = {NanValue(), NanValue(), NanValue()};
    sphere.Radius = NanValue();
    MeshInstance::ListLink* const selfLink = MeshInstanceLink(this);
    linkPrev = selfLink;
    linkNext = selfLink;

    const boost::shared_ptr<const CAniSkel> skeleton = ResolveInitialPoseSkeleton(meshArg, isStaticPoseArg);
    curPose.reset(new CAniPose(skeleton, 1.0f));

    db.Register(spatialDbStorage, this, kMeshSpatialDbRoutingMask);
    const float dissolveCutoff = ComputeSpatialDissolveCutoff(meshArg);
    db.UpdateDissolveCutoff(dissolveCutoff);
  }

  /**
   * Address: 0x007DE550 (FUN_007DE550, ??1MeshInstance@Moho@@QAE@XZ)
   */
  MeshInstance::~MeshInstance()
  {
    curPose.reset();
    endPose.reset();
    startPose.reset();
    mesh.reset();
    db.ClearRegistration();
    RemoveLinkFromList(MeshInstanceLink(this));
  }

  /**
   * Address: 0x007DE510 (FUN_007DE510, deleting thunk)
   *
   * What it does:
   * Runs destructor and conditionally frees memory when low flag bit is set.
   */
  void MeshInstance::Release(const std::int32_t destroyNow)
  {
    if ((destroyNow & 0x01) != 0) {
      delete this;
      return;
    }

    this->~MeshInstance();
  }

  /**
   * Address: 0x007DADD0 (FUN_007DADD0, ?GetMesh@MeshInstance@Moho@@QBE?AV?$shared_ptr@VMesh@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<Mesh> MeshInstance::GetMesh() const
  {
    return mesh;
  }

  /**
   * Address: 0x007DE930 (FUN_007DE930, ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0@Z)
   *
   * What it does:
   * Applies start/end stance transforms, flags interpolation refresh, and
   * marks stance/bounds state dirty when transform data changed.
   */
  void MeshInstance::SetStance(const VTransform& startTransformArg, const VTransform& endTransformArg)
  {
    const bool changed = !Vec3EqualExact(endTransform.pos_, endTransformArg.pos_) ||
      !QuatEqualExact(endTransform.orient_, endTransformArg.orient_) ||
      !Vec3EqualExact(startTransform.pos_, startTransformArg.pos_) ||
      !QuatEqualExact(startTransform.orient_, startTransformArg.orient_);
    if (!changed) {
      hasStanceUpdatePending = 0;
      return;
    }

    hasStanceUpdatePending = 1;
    endTransform = endTransformArg;
    startTransform = startTransformArg;
    frameCounter = static_cast<std::int8_t>(sFrameCounter);
    currInterpolant = -1.0f;
    boundsValid = 1;
  }

  /**
   * Address: 0x007DEC80 (FUN_007DEC80, ?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ)
   *
   * What it does:
   * Recomputes interpolated transform fields for the current global
   * interpolant and refreshes fallback runtime bounds.
   */
  void MeshInstance::UpdateInterpolatedFields()
  {
    if (sCurrentInterpolant == currInterpolant) {
      return;
    }

    float interpolation = uniformScale * sCurrentInterpolant;
    interpolation = Clamp01(interpolation);
    currInterpolant = sCurrentInterpolant;
    interpolationStateFresh = 1;

    const Wm3::Vec3f startPos = startTransform.pos_;
    const Wm3::Vec3f endPos = endTransform.pos_;
    interpolatedPosition.x = endPos.x + (startPos.x - endPos.x) * interpolation;
    interpolatedPosition.y = endPos.y + (startPos.y - endPos.y) * interpolation;
    interpolatedPosition.z = endPos.z + (startPos.z - endPos.z) * interpolation;

    // Binary path uses QuatLERP helper with start/end transforms; using normalized
    // lerp keeps the same intent while avoiding low-level helper dispatch.
    curOrientation = Wm3::Quatf::Nlerp(startTransform.orient_, endTransform.orient_, 1.0f - interpolation);

    if (hasStanceUpdatePending == 0) {
      return;
    }

    if (!HasFiniteWorldBounds(*this)) {
      UpdateFallbackWorldBounds(*this);
      return;
    }

    // When existing bounds are valid, keep size and recenter around the current
    // interpolated position. This mirrors the binary intent (bounds follow stance)
    // without requiring unrecovered mesh-resource box helpers.
    const float halfX = std::max(0.0f, (xMax - xMin) * 0.5f);
    const float halfY = std::max(0.0f, (yMax - yMin) * 0.5f);
    const float halfZ = std::max(0.0f, (zMax - zMin) * 0.5f);
    xMin = interpolatedPosition.x - halfX;
    xMax = interpolatedPosition.x + halfX;
    yMin = interpolatedPosition.y - halfY;
    yMax = interpolatedPosition.y + halfY;
    zMin = interpolatedPosition.z - halfZ;
    zMax = interpolatedPosition.z + halfZ;
    renderMinX = xMin;
    renderMinY = yMin;
    renderMinZ = zMin;
    renderMaxX = xMax;
    renderMaxY = yMax;
    renderMaxZ = zMax;

    const float radius = std::sqrt(halfX * halfX + halfY * halfY + halfZ * halfZ);
    sphere.Center = interpolatedPosition;
    sphere.Radius = radius;
    boundsValid = 1;
  }

  namespace
  {
    MeshRenderer* gMeshRendererInstance = nullptr;
  }

  /**
   * Address: 0x007DF150 (FUN_007DF150, ??0MeshRenderer@Moho@@QAE@XZ)
   */
  MeshRenderer::MeshRenderer()
    : meshEnvironment()
    , meshCacheTree{nullptr, nullptr, 0}
    , dissolveTex()
    , meshEnvironmentTex()
    , anisotropiclookupTex()
    , insectlookupTex()
    , instanceListHead{nullptr, nullptr}
    , instanceListSize(0)
    , deltaFrame(0.0f)
    , instanceListStateFlags(0)
    , meshes{nullptr, nullptr, 0}
    , meshSpatialDb{nullptr, 0}
  {
    meshCacheTree.head = CreateMeshCacheTreeSentinel();
    meshes.head = CreateMeshBatchTreeSentinel();
    instanceListHead.prev = &instanceListHead;
    instanceListHead.next = &instanceListHead;
    gMeshRendererInstance = this;
  }

  /**
   * Address: 0x007DF330 (FUN_007DF330, ??1MeshRenderer@Moho@@QAE@XZ)
   */
  MeshRenderer::~MeshRenderer()
  {
    Reset();
    meshSpatialDb.ClearRegistration();
    DestroyMeshBatchTree(meshes);
    RemoveLinkFromList(&instanceListHead);
    DestroyMeshCacheTree(meshCacheTree);
    if (gMeshRendererInstance == this) {
      gMeshRendererInstance = nullptr;
    }
  }

  /**
   * Address: 0x007E16C0 (FUN_007E16C0, ?GetInstance@MeshRenderer@Moho@@SAPAV12@XZ)
   */
  MeshRenderer* MeshRenderer::GetInstance()
  {
    if (!gMeshRendererInstance) {
      static MeshRenderer sMeshRenderer;
      gMeshRendererInstance = &sMeshRenderer;
    }

    return gMeshRendererInstance;
  }

  /**
   * Address: 0x007E1370 (FUN_007E1370, ?Reset@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Releases global sheet handles, clears per-instance LOD batches, and resets batch-bucket state.
   */
  void MeshRenderer::Reset()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetLodBatchesForInstanceLinkList(instanceListHead);
    ResetMeshBatchTree(meshes);
  }

  /**
   * Address: 0x007E1510 (FUN_007E1510, ?Shutdown@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Performs reset-time cleanup and detaches the intrusive instance-list sentinel.
   */
  void MeshRenderer::Shutdown()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetLodBatchesForInstanceLinkList(instanceListHead);
    RemoveLinkFromList(&instanceListHead);
    ResetMeshBatchTree(meshes);
  }

  boost::shared_ptr<Mesh> MeshRenderer::FindOrCreateMesh(
    const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    MeshKey key(blueprint, materialArg);
    MeshRendererMeshCacheNode* const foundNode = MeshCacheTreeFind(meshCacheTree, key);
    if (foundNode) {
      return foundNode->entry.mesh;
    }

    boost::shared_ptr<Mesh> mesh(new Mesh(blueprint, materialArg));
    bool inserted = false;
    MeshRendererMeshCacheNode* const insertedNode = MeshCacheTreeInsertUnique(meshCacheTree, key, mesh, inserted);
    if (!insertedNode) {
      return {};
    }

    if (inserted || !insertedNode->entry.mesh) {
      insertedNode->entry.mesh = mesh;
    }

    return insertedNode->entry.mesh;
  }

  /**
   * Address: 0x007DF530 (FUN_007DF530,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIPBVRMeshBlueprint@2@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const RMeshBlueprint* const blueprint,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    if (!blueprint) {
      return nullptr;
    }

    const RMeshBlueprintLOD* const lodBegin = blueprint->mLods.begin();
    if (!lodBegin || lodBegin == blueprint->mLods.end()) {
      return nullptr;
    }

    if (lodBegin->mMeshName.empty()) {
      return nullptr;
    }

    boost::shared_ptr<Mesh> mesh = FindOrCreateMesh(blueprint, materialArg);
    return CreateMeshInstance(gameTick, color, scale, isStaticPose, mesh);
  }

  /**
   * Address: 0x007DF8E0 (FUN_007DF8E0,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMesh@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<Mesh> meshArg
  )
  {
    if (!meshArg) {
      return nullptr;
    }

    MeshInstance* const instance = new MeshInstance(scale, &meshSpatialDb, gameTick, color, isStaticPose, meshArg);
    MeshInstance::ListLink* const instanceLink = MeshInstanceLink(instance);
    RemoveLinkFromList(instanceLink);
    InsertLinkBefore(&instanceListHead, instanceLink);
    return instance;
  }

  /**
   * Address: 0x007E11C0 (FUN_007E11C0,
   * ?RenderThumbnail@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@PAVMeshInstance@2@PAVID3DRenderTarget@2@PAVID3DDepthStencil@2@@Z)
   *
   * What it does:
   * Renders one mesh instance with one thumbnail camera into caller-provided
   * color/depth targets.
   */
  void MeshRenderer::RenderThumbnail(
    const GeomCamera3& camera,
    MeshInstance* const meshInstance,
    ID3DRenderTarget* const renderTarget,
    ID3DDepthStencil* const depthStencil
  )
  {
    if (!meshInstance || !renderTarget || !depthStencil) {
      return;
    }

    // Full draw-call/material state chain is still under active recovery.
    // Keep this typed seam so thumbnail paths can call the proper owner API.
    (void)camera;
    (void)meshInstance->GetMesh();
  }
} // namespace moho
