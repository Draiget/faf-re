#include "moho/render/Clutter.h"

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/mesh/Mesh.h"
#include "moho/math/MathReflection.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"

#include <boost/mutex.h>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace
{
  struct RegionKeyVtableResetTag
  {
    virtual ~RegionKeyVtableResetTag() = default;
  };

  struct RegionRuntimeVtableResetTag
  {
    virtual ~RegionRuntimeVtableResetTag() = default;
  };

  struct DestroyInstanceVtableTag
  {
    virtual ~DestroyInstanceVtableTag() = default;
  };

  struct SurfaceVtableResetTag
  {
    virtual ~SurfaceVtableResetTag() = default;
  };

  struct SeedVtableResetTag
  {
    virtual ~SeedVtableResetTag() = default;
  };

  struct DestroyInstanceRuntimeLane
  {
    void* vtable;
    moho::MeshRenderer* instance;
  };

  struct CWldTerrainResRuntimeView
  {
    void* vtable;
    moho::STIMap* map;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x8, "CWldTerrainResRuntimeView size must be 0x8");
  static_assert(offsetof(CWldTerrainResRuntimeView, map) == 0x4, "CWldTerrainResRuntimeView::map offset must be 0x4");

  RegionKeyVtableResetTag gRegionKeyVtableResetTag{};
  RegionRuntimeVtableResetTag gRegionRuntimeVtableResetTag{};
  DestroyInstanceVtableTag gDestroyInstanceVtableTag{};
  SurfaceVtableResetTag gSurfaceVtableResetTag{};
  SeedVtableResetTag gSeedVtableResetTag{};

  [[nodiscard]] void* RegionKeyVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gRegionKeyVtableResetTag);
  }

  [[nodiscard]] void* RegionRuntimeVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gRegionRuntimeVtableResetTag);
  }

  [[nodiscard]] void* DestroyInstanceVtableToken()
  {
    return *reinterpret_cast<void**>(&gDestroyInstanceVtableTag);
  }

  [[nodiscard]] void* SurfaceVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gSurfaceVtableResetTag);
  }

  [[nodiscard]] void* SeedVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gSeedVtableResetTag);
  }

  [[nodiscard]] moho::RRuleGameRules* GetActiveRules() noexcept
  {
    const moho::CWldSession* const session = moho::WLD_GetActiveSession();
    return session ? session->mRules : nullptr;
  }

  [[nodiscard]] moho::STIMap* GetTerrainTypeMap() noexcept
  {
    const moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (!session || !session->mWldMap || !session->mWldMap->mTerrainRes) {
      return nullptr;
    }

    const auto* const terrainView = reinterpret_cast<const CWldTerrainResRuntimeView*>(session->mWldMap->mTerrainRes);
    return terrainView ? terrainView->map : nullptr;
  }

  [[nodiscard]] float NextGlobalRandomSignedUnit()
  {
    boost::mutex::scoped_lock randomLock(moho::math_GlobalRandomMutex);
    const std::uint32_t randomWord = moho::math_GlobalRandomStream.twister.NextUInt32();
    constexpr double kInvTwoTo31 = 4.656612873077392578125e-10;
    return static_cast<float>(static_cast<double>(randomWord) * kInvTwoTo31 - 1.0);
  }

  [[nodiscard]] float NextGlobalRandomUnit()
  {
    boost::mutex::scoped_lock randomLock(moho::math_GlobalRandomMutex);
    const std::uint32_t randomWord = moho::math_GlobalRandomStream.twister.NextUInt32();
    constexpr double kInvTwoTo32 = 2.3283064365386962890625e-10;
    return static_cast<float>(static_cast<double>(randomWord) * kInvTwoTo32);
  }

  [[nodiscard]] bool IsTreeNil(
    const moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKeyNode* const node
  )
  {
    return (node == nullptr) || (tree && tree->head && node == tree->head) || (node && node->isNil != 0u);
  }

  [[nodiscard]] bool IsTreeBlack(
    const moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKeyNode* const node
  )
  {
    return IsTreeNil(tree, node) || node->color == 1u;
  }

  [[nodiscard]] bool RegionKeyLess(
    const moho::ClutterRegionKey& lhs,
    const moho::ClutterRegionKey& rhs
  )
  {
    return (lhs.mX < rhs.mX) || (lhs.mX == rhs.mX && lhs.mZ < rhs.mZ);
  }

  [[nodiscard]] moho::ClutterRegionKeyNode* TreeMinimum(
    const moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* node
  )
  {
    while (!IsTreeNil(tree, node) && !IsTreeNil(tree, node->left)) {
      node = node->left;
    }
    return node;
  }

  [[nodiscard]] moho::ClutterRegionKeyNode* TreeMaximum(
    const moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* node
  )
  {
    while (!IsTreeNil(tree, node) && !IsTreeNil(tree, node->right)) {
      node = node->right;
    }
    return node;
  }

  void RefreshTreeEndpoints(moho::ClutterRegionKeyTreeState* const tree)
  {
    if (!tree || !tree->head) {
      return;
    }

    moho::ClutterRegionKeyNode* const head = tree->head;
    moho::ClutterRegionKeyNode* const root = head->parent;
    if (IsTreeNil(tree, root)) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    root->parent = head;
    head->left = TreeMinimum(tree, root);
    head->right = TreeMaximum(tree, root);
  }

  void RotateTreeLeft(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* const pivot
  )
  {
    moho::ClutterRegionKeyNode* const right = pivot->right;
    pivot->right = right->left;
    if (!IsTreeNil(tree, right->left)) {
      right->left->parent = pivot;
    }

    right->parent = pivot->parent;
    if (pivot == tree->head->parent) {
      tree->head->parent = right;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = right;
    } else {
      pivot->parent->right = right;
    }

    right->left = pivot;
    pivot->parent = right;
  }

  void RotateTreeRight(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* const pivot
  )
  {
    moho::ClutterRegionKeyNode* const left = pivot->left;
    pivot->left = left->right;
    if (!IsTreeNil(tree, left->right)) {
      left->right->parent = pivot;
    }

    left->parent = pivot->parent;
    if (pivot == tree->head->parent) {
      tree->head->parent = left;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = left;
    } else {
      pivot->parent->left = left;
    }

    left->right = pivot;
    pivot->parent = left;
  }

  void ReplaceTreeNode(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* const target,
    moho::ClutterRegionKeyNode* const replacement
  )
  {
    if (target->parent == tree->head) {
      tree->head->parent = replacement;
    } else if (target == target->parent->left) {
      target->parent->left = replacement;
    } else {
      target->parent->right = replacement;
    }

    if (!IsTreeNil(tree, replacement)) {
      replacement->parent = target->parent;
    }
  }

  void FixupAfterTreeErase(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* node,
    moho::ClutterRegionKeyNode* parent
  )
  {
    while (node != tree->head->parent && IsTreeBlack(tree, node)) {
      if (parent == tree->head) {
        break;
      }

      if (node == parent->left) {
        moho::ClutterRegionKeyNode* sibling = parent->right;
        if (!IsTreeBlack(tree, sibling)) {
          sibling->color = 1;
          parent->color = 0;
          RotateTreeLeft(tree, parent);
          sibling = parent->right;
        }

        const bool siblingLeftBlack = IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->left);
        const bool siblingRightBlack = IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->right);
        if (siblingLeftBlack && siblingRightBlack) {
          if (!IsTreeNil(tree, sibling)) {
            sibling->color = 0;
          }
          node = parent;
          parent = parent->parent;
        } else {
          if (IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->right)) {
            if (!IsTreeNil(tree, sibling->left)) {
              sibling->left->color = 1;
            }
            if (!IsTreeNil(tree, sibling)) {
              sibling->color = 0;
            }
            if (!IsTreeNil(tree, sibling)) {
              RotateTreeRight(tree, sibling);
            }
            sibling = parent->right;
          }

          if (!IsTreeNil(tree, sibling)) {
            sibling->color = parent->color;
          }
          parent->color = 1;
          if (!IsTreeNil(tree, sibling->right)) {
            sibling->right->color = 1;
          }
          RotateTreeLeft(tree, parent);
          node = tree->head->parent;
          break;
        }
      } else {
        moho::ClutterRegionKeyNode* sibling = parent->left;
        if (!IsTreeBlack(tree, sibling)) {
          sibling->color = 1;
          parent->color = 0;
          RotateTreeRight(tree, parent);
          sibling = parent->left;
        }

        const bool siblingRightBlack = IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->right);
        const bool siblingLeftBlack = IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->left);
        if (siblingRightBlack && siblingLeftBlack) {
          if (!IsTreeNil(tree, sibling)) {
            sibling->color = 0;
          }
          node = parent;
          parent = parent->parent;
        } else {
          if (IsTreeNil(tree, sibling) || IsTreeBlack(tree, sibling->left)) {
            if (!IsTreeNil(tree, sibling->right)) {
              sibling->right->color = 1;
            }
            if (!IsTreeNil(tree, sibling)) {
              sibling->color = 0;
            }
            if (!IsTreeNil(tree, sibling)) {
              RotateTreeLeft(tree, sibling);
            }
            sibling = parent->left;
          }

          if (!IsTreeNil(tree, sibling)) {
            sibling->color = parent->color;
          }
          parent->color = 1;
          if (!IsTreeNil(tree, sibling->left)) {
            sibling->left->color = 1;
          }
          RotateTreeRight(tree, parent);
          node = tree->head->parent;
          break;
        }
      }
    }

    if (!IsTreeNil(tree, node)) {
      node->color = 1;
    } else {
      tree->head->color = 1;
    }
  }

  /**
   * Address: 0x007D8DE0 (FUN_007D8DE0)
   */
  [[nodiscard]] moho::ClutterRegionKeyNode* FindLowerBound(
    moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKey& key
  )
  {
    moho::ClutterRegionKeyNode* result = tree->head;
    moho::ClutterRegionKeyNode* node = tree->head->parent;

    while (!IsTreeNil(tree, node)) {
      if (RegionKeyLess(node->key, key)) {
        node = node->right;
      } else {
        result = node;
        node = node->left;
      }
    }

    return result;
  }

  /**
   * Address: 0x007D9100 (FUN_007D9100)
   */
  [[nodiscard]] moho::ClutterRegionKeyNode* FindUpperBound(
    moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKey& key
  )
  {
    moho::ClutterRegionKeyNode* result = tree->head;
    moho::ClutterRegionKeyNode* node = tree->head->parent;

    while (!IsTreeNil(tree, node)) {
      if (RegionKeyLess(key, node->key)) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return result;
  }

  /**
   * Address: 0x007D9340 (FUN_007D9340)
   */
  void AdvanceRegionKeyIterator(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode*& iteratorNode
  )
  {
    if (IsTreeNil(tree, iteratorNode)) {
      return;
    }

    if (!IsTreeNil(tree, iteratorNode->right)) {
      iteratorNode = iteratorNode->right;
      while (!IsTreeNil(tree, iteratorNode->left)) {
        iteratorNode = iteratorNode->left;
      }
      return;
    }

    moho::ClutterRegionKeyNode* parent = iteratorNode->parent;
    while (!IsTreeNil(tree, parent) && iteratorNode == parent->right) {
      iteratorNode = parent;
      parent = parent->parent;
    }
    iteratorNode = parent;
  }

  /**
   * Address: 0x007D8AE0 (FUN_007D8AE0)
   */
  void EraseRegionKeyNode(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode* const eraseNode
  )
  {
    moho::ClutterRegionKeyNode* target = eraseNode;
    moho::ClutterRegionKeyNode* replacement = tree->head;
    moho::ClutterRegionKeyNode* fixupParent = tree->head;
    bool removedBlack = IsTreeBlack(tree, target);

    if (IsTreeNil(tree, eraseNode->left)) {
      replacement = eraseNode->right;
      fixupParent = eraseNode->parent;
      ReplaceTreeNode(tree, eraseNode, eraseNode->right);
    } else if (IsTreeNil(tree, eraseNode->right)) {
      replacement = eraseNode->left;
      fixupParent = eraseNode->parent;
      ReplaceTreeNode(tree, eraseNode, eraseNode->left);
    } else {
      target = TreeMinimum(tree, eraseNode->right);
      removedBlack = IsTreeBlack(tree, target);
      replacement = target->right;

      if (target->parent == eraseNode) {
        fixupParent = target;
      } else {
        fixupParent = target->parent;
        ReplaceTreeNode(tree, target, target->right);
        target->right = eraseNode->right;
        target->right->parent = target;
      }

      ReplaceTreeNode(tree, eraseNode, target);
      target->left = eraseNode->left;
      target->left->parent = target;
      target->color = eraseNode->color;
    }

    if (removedBlack) {
      FixupAfterTreeErase(tree, replacement, fixupParent);
    }

    moho::ResetRegionKeyVtable(&eraseNode->key);
    ::operator delete(eraseNode);
    if (tree->size != 0u) {
      --tree->size;
    }

    RefreshTreeEndpoints(tree);
  }

  /**
   * Address: 0x007D80D0 (FUN_007D80D0)
   */
  moho::ClutterRegionKeyNode** __stdcall EraseRegionKeyNodeRange(
    moho::ClutterRegionKeyTreeState* const tree,
    moho::ClutterRegionKeyNode** const outNext,
    moho::ClutterRegionKeyNode* first,
    moho::ClutterRegionKeyNode* const last
  )
  {
    moho::ClutterRegionKeyNode* const head = tree->head;
    if (first == head->left && last == head) {
      moho::DestroyRegionKeySubtree(nullptr, head->parent);
      head->parent = head;
      tree->size = 0;
      head->left = head;
      head->right = head;
      *outNext = head->left;
      return outNext;
    }

    while (first != last) {
      moho::ClutterRegionKeyNode* const eraseNode = first;
      if (first->isNil == 0u) {
        AdvanceRegionKeyIterator(tree, first);
      }
      EraseRegionKeyNode(tree, eraseNode);
    }

    *outNext = first;
    return outNext;
  }

  /**
   * Address: 0x007D7A10 (FUN_007D7A10)
   */
  void ClearIntrusiveListNodes(moho::ClutterIntrusiveListState* const list)
  {
    moho::ClutterListNode* const head = list->head;
    moho::ClutterListNode* node = head->next;
    head->next = head;
    head->prev = head;
    list->size = 0;

    while (node != head) {
      moho::ClutterListNode* const next = node->next;
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x007D61B0 (FUN_007D61B0)
   */
  void ClearRegionKeyTreeStorage(moho::ClutterRegionKeyTreeState* const tree)
  {
    moho::ClutterRegionKeyNode* iterator = nullptr;
    (void)EraseRegionKeyNodeRange(tree, &iterator, tree->head->left, tree->head);
    ::operator delete(tree->head);
    tree->head = nullptr;
    tree->size = 0;
  }

  /**
   * Address: 0x007D7820 (FUN_007D7820)
   */
  moho::ClutterRegionMapState* ClearRegionMapList(moho::ClutterRegionMapState* const map)
  {
    moho::ClutterListNode* const head = map->head;
    moho::ClutterListNode* node = head->next;

    head->next = head;
    head->prev = head;
    map->size = 0;

    while (node != head) {
      moho::ClutterListNode* const next = node->next;
      ::operator delete(node);
      node = next;
    }

    return map;
  }

  /**
   * Address: 0x007D9390 (FUN_007D9390)
   */
  void ApplyDestroyInstanceToRegionPayloads(
    moho::ClutterListNode* begin,
    moho::ClutterListNode* const endSentinel,
    DestroyInstanceRuntimeLane& destroyLane,
    moho::MeshRenderer* const instance
  )
  {
    for (moho::ClutterListNode* node = begin; node != endSentinel; node = node->next) {
      auto* const payload = static_cast<moho::ClutterRegionMapPayloadHeader*>(node->payload);
      payload->vtable->destroy(payload, 1);
    }

    destroyLane.instance = instance;
    destroyLane.vtable = DestroyInstanceVtableToken();
  }

  /**
   * Address: 0x007D7FD0 (FUN_007D7FD0)
   */
  [[nodiscard]] moho::ClutterListNode* AllocateListSentinelNode()
  {
    auto* const node = static_cast<moho::ClutterListNode*>(::operator new(sizeof(moho::ClutterListNode)));
    node->next = node;
    node->prev = node;
    node->payload = nullptr;
    return node;
  }

  /**
   * Address: 0x007D9140 (FUN_007D9140)
   */
  [[nodiscard]] moho::ClutterRegionKeyNode* AllocateRegionKeyNode()
  {
    auto* const node =
      static_cast<moho::ClutterRegionKeyNode*>(::operator new(sizeof(moho::ClutterRegionKeyNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->key.vtable = nullptr;
    node->key.mX = 0;
    node->key.mZ = 0;
    node->color = 1;
    node->isNil = 0;
    node->reserved1A[0] = 0;
    node->reserved1A[1] = 0;
    return node;
  }

  /**
   * Address: 0x007D9530 (FUN_007D9530)
   */
  [[nodiscard]] void* AllocatePointerListStorageChecked(const std::uint32_t count)
  {
    if (count != 0u && (0xFFFFFFFFu / count) < sizeof(moho::ClutterListNode)) {
      throw std::bad_alloc();
    }
    return ::operator new(sizeof(moho::ClutterListNode) * count);
  }

  /**
   * Address: 0x007D84D0 (FUN_007D84D0)
   */
  moho::ClutterListNode* __stdcall AllocatePointerListNode(
    moho::ClutterListNode* const next,
    moho::ClutterListNode* const prev,
    void* const* const valueRef
  )
  {
    auto* const node = static_cast<moho::ClutterListNode*>(AllocatePointerListStorageChecked(1u));
    node->next = next;
    node->prev = prev;
    node->payload = *valueRef;
    return node;
  }

  /**
   * Address: 0x007D8510 (FUN_007D8510)
   */
  std::uint32_t IncrementPointerListSizeChecked(moho::ClutterIntrusiveListState* const listState)
  {
    if (listState->size == 0x3FFFFFFFu) {
      throw std::length_error("list<T> too long");
    }

    ++listState->size;
    return listState->size;
  }

  /**
   * Address: 0x007D7CD0 (FUN_007D7CD0)
   */
  std::uint32_t __stdcall AppendPointerListTail(
    void* const* const valueRef,
    moho::ClutterIntrusiveListState* const listState,
    moho::ClutterListNode* const tailSentinel
  )
  {
    moho::ClutterListNode* const node =
      AllocatePointerListNode(tailSentinel, tailSentinel->prev, valueRef);
    const std::uint32_t nextSize = IncrementPointerListSizeChecked(listState);
    tailSentinel->prev = node;
    node->prev->next = node;
    return nextSize;
  }

  /**
   * Address: 0x007D60C0 (FUN_007D60C0)
   */
  void ResetClutterSeedVtable(moho::ClutterSurfaceElement* const seed)
  {
    seed->vtable = reinterpret_cast<moho::ClutterSurfaceElementVTable*>(SeedVtableResetToken());
  }

  /**
   * Address: 0x007D5FE0 (FUN_007D5FE0)
   */
  moho::ClutterSurfaceElement* InitializeClutterSeedFromBlueprintPath(
    moho::ClutterSurfaceElement* const seed,
    const float selectionWeight,
    const msvc8::string& meshBlueprintId
  )
  {
    ResetClutterSeedVtable(seed);
    seed->selectionWeight = selectionWeight;
    seed->uniformScale = 1.0f;
    seed->meshBlueprint = nullptr;

    moho::RRuleGameRules* const rules = GetActiveRules();
    if (!rules) {
      return seed;
    }

    msvc8::string normalizedPath{};
    gpg::STR_CopyFilename(&normalizedPath, &meshBlueprintId);
    moho::RPropBlueprint* const propBlueprint = rules->GetPropBlueprint(normalizedPath);
    if (!propBlueprint) {
      return seed;
    }

    seed->uniformScale = propBlueprint->Display.UniformScale;
    seed->meshBlueprint = rules->GetMeshBlueprint(propBlueprint->Display.MeshBlueprint);
    return seed;
  }

  /**
   * Address: 0x007D9970 (FUN_007D9970)
   */
  moho::ClutterSurfaceElement* CopyClutterSeedRange(
    moho::ClutterSurfaceElement* destination,
    const moho::ClutterSurfaceElement* source,
    int count
  )
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (; count > 0; --count, destinationAddress += sizeof(moho::ClutterSurfaceElement)) {
      if (destinationAddress != 0u) {
        auto* const out = reinterpret_cast<moho::ClutterSurfaceElement*>(destinationAddress);
        ResetClutterSeedVtable(out);
        out->selectionWeight = source->selectionWeight;
        out->uniformScale = source->uniformScale;
        out->meshBlueprint = source->meshBlueprint;
      }
    }

    return reinterpret_cast<moho::ClutterSurfaceElement*>(destinationAddress);
  }

  /**
   * Address: 0x007D78B0 (FUN_007D78B0)
   */
  std::uint32_t AppendSurfaceSeed(
    moho::ClutterSurfaceEntry* const surface,
    const moho::ClutterSurfaceElement& seed
  )
  {
    auto* const begin = surface->eraseLane.begin;
    auto* const end = surface->eraseLane.end;
    auto* const cap = surface->capacity;
    const std::uint32_t size = begin ? static_cast<std::uint32_t>(end - begin) : 0u;

    if (begin != nullptr && end != cap) {
      (void)CopyClutterSeedRange(end, &seed, 1);
      surface->eraseLane.end = end + 1;
      return static_cast<std::uint32_t>(surface->eraseLane.end - surface->eraseLane.begin);
    }

    constexpr std::uint32_t kMaxSurfaceSeedCount = 0x0FFFFFFFu;
    if (size == kMaxSurfaceSeedCount) {
      throw std::length_error("vector<T> too long");
    }

    std::uint32_t targetCapacity = size + (size / 2u);
    if (targetCapacity < size + 1u) {
      targetCapacity = size + 1u;
    }

    if (targetCapacity > kMaxSurfaceSeedCount) {
      targetCapacity = kMaxSurfaceSeedCount;
    }

    auto* const nextStorage =
      static_cast<moho::ClutterSurfaceElement*>(::operator new(sizeof(moho::ClutterSurfaceElement) * targetCapacity));
    moho::ClutterSurfaceElement* write = CopyClutterSeedRange(nextStorage, begin, static_cast<int>(size));
    write = CopyClutterSeedRange(write, &seed, 1);

    if (begin != nullptr) {
      ::operator delete(begin);
    }

    surface->eraseLane.begin = nextStorage;
    surface->eraseLane.end = write;
    surface->capacity = nextStorage + targetCapacity;
    return static_cast<std::uint32_t>(surface->eraseLane.end - surface->eraseLane.begin);
  }

  /**
   * Address: 0x007D7EB0 (FUN_007D7EB0, ??1Surface@Clutter@Moho@@QAE@@Z)
   */
  void DestroySurfacePayloadLane(
    moho::ClutterSurfaceEraseLane* const lane,
    moho::ClutterSurfaceElement*& capacity
  )
  {
    moho::ClutterSurfaceElement* const begin = lane->begin;
    if (begin) {
      moho::ClutterSurfaceElement* const finish = lane->end;
      for (moho::ClutterSurfaceElement* element = begin; element != finish; ++element) {
        element->DestroyInPlace();
      }
      ::operator delete(begin);
    }

    lane->begin = nullptr;
    lane->end = nullptr;
    capacity = nullptr;
  }
} // namespace

namespace moho
{
  float ren_ClutterRadius = 0.0f;

  void ClutterSurfaceElement::DestroyInPlace()
  {
    vtable->destroy(this, 0);
  }

  /**
   * Address: 0x007D5EE0 (FUN_007D5EE0, ??0Region@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes region links and key coordinates, then allocates one empty
   * region-map list sentinel.
   */
  ClutterRegion::ClutterRegion()
  {
    vtable = RegionRuntimeVtableResetToken();
    mNext = nullptr;
    mPrev = nullptr;
    mX = -1;
    mZ = -1;
    mMap.lane00 = nullptr;
    mMap.head = AllocateListSentinelNode();
    mMap.size = 0;
  }

  /**
   * Address: 0x007D5F20 (FUN_007D5F20, ??1Region@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets region runtime links/payloads, clears map-node list storage, then
   * releases the map-list sentinel allocation.
   */
  ClutterRegion::~ClutterRegion()
  {
    vtable = RegionRuntimeVtableResetToken();
    (void)ResetRegionRuntimeState(this);
    (void)ClearRegionMapList(&mMap);
    ::operator delete(mMap.head);
    mMap.head = nullptr;
  }

  /**
   * Address: 0x007D5CF0 (FUN_007D5CF0, ??0Surface@Clutter@Moho@@QAE@@Z)
   */
  static ClutterSurfaceEntry* InitializeSurfaceEntry(ClutterSurfaceEntry* const surface)
  {
    surface->vtable = SurfaceVtableResetToken();
    surface->density = 0;
    surface->eraseLane.allocatorCookie = 0;
    surface->eraseLane.begin = nullptr;
    surface->eraseLane.end = nullptr;
    surface->capacity = nullptr;
    return surface;
  }

  /**
   * Address: 0x007D5D10 (FUN_007D5D10)
   */
  static void DestroySurfaceEntryWrapper(ClutterSurfaceEntry* const surface)
  {
    surface->vtable = SurfaceVtableResetToken();
    DestroySurfacePayloadLane(&surface->eraseLane, surface->capacity);
  }

  /**
   * Address: 0x007D60D0 (FUN_007D60D0, ??0Clutter@Moho@@QAE@XZ)
   */
  Clutter::Clutter()
  {
    mList1.head = AllocateListSentinelNode();
    mList1.size = 0;

    mList2.head = reinterpret_cast<ClutterRegionListNode*>(AllocateListSentinelNode());
    mList2.size = 0;

    for (ClutterSurfaceEntry& surface : mSurfaces) {
      (void)InitializeSurfaceEntry(&surface);
    }

    mKeys.head = AllocateRegionKeyNode();
    mKeys.head->isNil = 1;
    mKeys.head->parent = mKeys.head;
    mKeys.head->left = mKeys.head;
    mKeys.head->right = mKeys.head;
    mKeys.size = 0;
    mCurRegion = nullptr;

    std::memset(mBuffer, 0, sizeof(mBuffer));
  }

  /**
   * Address: 0x007D61E0 (FUN_007D61E0, ??1Clutter@Moho@@UAE@XZ)
   */
  Clutter::~Clutter()
  {
    Shutdown();

    if (mKeys.head) {
      ClearRegionKeyTreeStorage(&mKeys);
    }

    for (ClutterSurfaceEntry& surface : mSurfaces) {
      DestroySurfaceEntryWrapper(&surface);
    }

    if (mList2.head) {
      ClearIntrusiveListNodes(reinterpret_cast<ClutterIntrusiveListState*>(&mList2));
      ::operator delete(mList2.head);
      mList2.head = nullptr;
    }

    if (mList1.head) {
      ClearIntrusiveListNodes(&mList1);
      ::operator delete(mList1.head);
      mList1.head = nullptr;
    }
  }

  /**
   * Address: 0x007D6410 (FUN_007D6410, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@ABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * What it does:
   * Returns whether one region AABB is close enough to the camera and inside
   * the camera frustum-solid lane.
   */
  bool Clutter::IsVisible(const GeomCamera3* const camera, const Wm3::AxisAlignedBox3f& regionBox)
  {
    const float centerX = (regionBox.Min.x + regionBox.Max.x) * 0.5f;
    const float centerY = (regionBox.Min.y + regionBox.Max.y) * 0.5f;
    const float centerZ = (regionBox.Min.z + regionBox.Max.z) * 0.5f;

    const float deltaX = centerX - camera->inverseView.r[3].x;
    const float deltaY = centerY - camera->inverseView.r[3].y;
    const float deltaZ = centerZ - camera->inverseView.r[3].z;
    const float centerDistance = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));
    if (centerDistance > ren_ClutterRadius) {
      return false;
    }

    return camera->solid2.Intersects(regionBox);
  }

  /**
   * Address: 0x007D6510 (FUN_007D6510, ?UpdateCurrent@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Walks the active-region chain and destroys regions that are outside clutter
   * distance radius or no longer intersect the camera frustum solid.
   */
  void Clutter::UpdateCurrent(const GeomCamera3* const camera)
  {
    ClutterRegion* currentRegion = mCurRegion;
    while (currentRegion != nullptr) {
      ClutterRegion* const previousRegion = currentRegion->mPrev;
      if (!IsVisible(camera, currentRegion->mBox)) {
        DestroyRegion(currentRegion);
      }

      currentRegion = previousRegion;
    }
  }

  /**
   * Address: 0x007D5CC0 (FUN_007D5CC0)
   */
  void ResetRegionKeyVtable(ClutterRegionKey* const key)
  {
    key->vtable = RegionKeyVtableResetToken();
  }

  /**
   * Address: 0x007D94B0 (FUN_007D94B0)
   */
  ClutterSurfaceElement* CompactSurfaceElements(
    ClutterSurfaceElement* destination,
    ClutterSurfaceElement* sourceBegin,
    ClutterSurfaceElement* sourceEnd
  )
  {
    ClutterSurfaceElement* out = destination;
    for (ClutterSurfaceElement* src = sourceBegin; src != sourceEnd; ++src, ++out) {
      out->selectionWeight = src->selectionWeight;
      out->uniformScale = src->uniformScale;
      out->meshBlueprint = src->meshBlueprint;
    }
    return out;
  }

  /**
   * Address: 0x007D7E00 (FUN_007D7E00)
   */
  ClutterSurfaceElement** __stdcall ResetSurfaceEntryRange(
    ClutterSurfaceEraseLane* const lane,
    ClutterSurfaceElement** const outBegin,
    ClutterSurfaceElement* const eraseBegin,
    ClutterSurfaceElement* const eraseEnd
  )
  {
    if (eraseBegin == eraseEnd) {
      *outBegin = eraseBegin;
      return outBegin;
    }

    ClutterSurfaceElement* const oldEnd = lane->end;
    ClutterSurfaceElement* const newEnd = CompactSurfaceElements(eraseBegin, eraseEnd, oldEnd);
    for (ClutterSurfaceElement* it = newEnd; it != oldEnd; ++it) {
      it->DestroyInPlace();
    }

    lane->end = newEnd;
    *outBegin = eraseBegin;
    return outBegin;
  }

  /**
   * Address: 0x007D9400 (FUN_007D9400)
   */
  std::uint8_t ReleaseRegionListPayloads(
    ClutterListNode* begin,
    ClutterListNode* const endSentinel,
    const std::uint8_t passthrough
  )
  {
    for (ClutterListNode* it = begin; it != endSentinel; it = it->next) {
      auto* const payload = static_cast<ClutterPayloadHeader*>(it->payload);
      if (!payload) {
        continue;
      }

      auto* const refLane = reinterpret_cast<std::uint32_t*>(payload) - 1;
      if (*refLane != 0u) {
        payload->vtable->destroy(payload, 3);
      } else {
        ::operator delete[](refLane);
      }
    }

    return passthrough;
  }

  /**
   * Address: 0x007D81C0 (FUN_007D81C0)
   */
  void DestroyRegionKeySubtree(Clutter* const owner, ClutterRegionKeyNode* node)
  {
    (void)owner;

    ClutterRegionKeyNode* deleteCursor = node;
    ClutterRegionKeyNode* walk = node;

    while (walk && walk->isNil == 0u) {
      DestroyRegionKeySubtree(owner, walk->right);
      walk = walk->left;
      ResetRegionKeyVtable(&deleteCursor->key);
      ::operator delete(deleteCursor);
      deleteCursor = walk;
    }
  }

  /**
   * Address: 0x007D5F80 (FUN_007D5F80)
   */
  ClutterRegionMapState* ResetRegionRuntimeState(ClutterRegion* const region)
  {
    region->mPrev = nullptr;
    region->mNext = nullptr;
    region->mZ = -1;
    region->mX = -1;

    DestroyInstanceRuntimeLane destroyLane{};
    destroyLane.vtable = DestroyInstanceVtableToken();
    destroyLane.instance = nullptr;

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    ApplyDestroyInstanceToRegionPayloads(region->mMap.head->next, region->mMap.head, destroyLane, meshRenderer);
    return ClearRegionMapList(&region->mMap);
  }

  /**
   * Address: 0x007D7B90 (FUN_007D7B90)
   */
  std::uint32_t EraseRegionKeyRange(
    ClutterRegionKey* const key,
    ClutterRegionKeyTreeState* const tree
  )
  {
    ClutterRegionKeyNode* const first = FindLowerBound(tree, *key);
    ClutterRegionKeyNode* const end = FindUpperBound(tree, *key);
    ClutterRegionKeyNode* countCursor = first;

    std::uint32_t removedCount = 0;
    while (countCursor != end) {
      ++removedCount;
      AdvanceRegionKeyIterator(tree, countCursor);
    }

    ClutterRegionKeyNode* outCursor = nullptr;
    (void)EraseRegionKeyNodeRange(tree, &outCursor, first, end);
    return removedCount;
  }

  /**
   * Address: 0x007D8980 (FUN_007D8980)
   */
  ClutterRegionListNode* __stdcall AllocateRegionListNode(
    ClutterRegionListNode* const next,
    ClutterRegionListNode* const prev,
    ClutterRegion* const* const valueRef
  )
  {
    return reinterpret_cast<ClutterRegionListNode*>(AllocatePointerListNode(
      reinterpret_cast<ClutterListNode*>(next),
      reinterpret_cast<ClutterListNode*>(prev),
      reinterpret_cast<void* const*>(valueRef)
    ));
  }

  /**
   * Address: 0x007D89C0 (FUN_007D89C0)
   */
  std::uint32_t IncrementListSizeChecked(ClutterRegionListState* const listState)
  {
    return IncrementPointerListSizeChecked(reinterpret_cast<ClutterIntrusiveListState*>(listState));
  }

  /**
   * Address: 0x007D7150 (FUN_007D7150, ?GetSurface@Clutter@Moho@@AAEABVSurface@12@E@Z)
   */
  const ClutterSurfaceEntry& Clutter::GetSurface(const std::uint8_t terrainType)
  {
    if (mBuffer[terrainType] != 0u) {
      return mSurfaces[terrainType];
    }

    mBuffer[terrainType] = 1u;
    ClutterSurfaceEntry& surface = mSurfaces[terrainType];

    STIMap* const terrainTypeMap = GetTerrainTypeMap();
    if (!terrainTypeMap) {
      return surface;
    }

    LuaPlus::LuaObject terrainTypeObject = terrainTypeMap->GetTerrainType(terrainType);
    if (!terrainTypeObject.IsTable()) {
      return surface;
    }

    LuaPlus::LuaObject clutterTable = terrainTypeObject["Clutter"];
    if (!clutterTable.IsTable()) {
      return surface;
    }

    surface.density = clutterTable["density"].GetInteger();

    LuaPlus::LuaObject seedsTable = clutterTable["Seeds"];
    if (!seedsTable.IsTable()) {
      return surface;
    }

    for (LuaPlus::LuaTableIterator iter(&seedsTable, 1); !iter.m_isDone; iter.Next()) {
      LuaPlus::LuaObject seedObject(iter.GetValue());
      const char* const meshBlueprintPath = seedObject[2].GetString();
      const float selectionWeight = static_cast<float>(seedObject[1].GetNumber());

      msvc8::string meshBlueprintId(meshBlueprintPath ? meshBlueprintPath : "");
      ClutterSurfaceElement seed{};
      (void)InitializeClutterSeedFromBlueprintPath(&seed, selectionWeight, meshBlueprintId);
      (void)AppendSurfaceSeed(&surface, seed);
      ResetClutterSeedVtable(&seed);
    }

    return surface;
  }

  /**
   * Address: 0x007D7430 (FUN_007D7430, ?ClutterRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@ABVCHeightField@2@PAVRegion@12@MABVSurface@12@@Z)
   */
  void Clutter::PopulateRegionClutter(
    const GeomCamera3* const camera,
    const CHeightField& heightField,
    ::moho::ClutterRegion* const region,
    const float densityScale,
    const ClutterSurfaceEntry& surface
  )
  {
    (void)camera;
    if (!region) {
      return;
    }

    ClutterSurfaceElement* const seedBegin = surface.eraseLane.begin;
    ClutterSurfaceElement* const seedEnd = surface.eraseLane.end;
    if (!seedBegin || seedEnd <= seedBegin) {
      return;
    }

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    if (!meshRenderer) {
      return;
    }

    const int seedCount = static_cast<int>(seedEnd - seedBegin);
    const int spawnCount = static_cast<int>(static_cast<float>(surface.density) * densityScale);
    if (spawnCount <= 0) {
      return;
    }

    const float regionBaseX = static_cast<float>(region->mX + 1);
    const float regionBaseZ = static_cast<float>(region->mZ + 1);

    for (int spawnIndex = 0; spawnIndex < spawnCount; ++spawnIndex) {
      const float spawnX = regionBaseX + NextGlobalRandomSignedUnit();
      const float spawnZ = regionBaseZ + NextGlobalRandomSignedUnit();
      const float terrainY = heightField.GetElevation(spawnX, spawnZ);
      const float selection = NextGlobalRandomUnit();

      float weightAccumulator = 0.0f;
      for (int seedIndex = 0; seedIndex < seedCount; ++seedIndex) {
        const ClutterSurfaceElement& seed = seedBegin[seedIndex];
        weightAccumulator += seed.selectionWeight;
        if (weightAccumulator <= selection || !seed.meshBlueprint) {
          continue;
        }

        const Wm3::Vec3f scale(seed.uniformScale, seed.uniformScale, seed.uniformScale);
        MeshInstance* const meshInstance =
          meshRenderer->CreateMeshInstance(0, -1, seed.meshBlueprint, scale, false, {});
        if (!meshInstance) {
          break;
        }

        VTransform stance{};
        stance.orient_.w = 1.0f;
        stance.pos_.x = spawnX;
        stance.pos_.y = terrainY;
        stance.pos_.z = spawnZ;
        meshInstance->SetStance(stance, stance);
        meshInstance->unk24 = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&heightField));

        (void)AppendPointerListTail(
          reinterpret_cast<void* const*>(&meshInstance),
          reinterpret_cast<ClutterIntrusiveListState*>(&region->mMap),
          region->mMap.head
        );
        break;
      }
    }
  }

  /**
   * Address: 0x007D7080 (FUN_007D7080, ?DestroyRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
   */
  void Clutter::DestroyRegion(ClutterRegion* const region)
  {
    ClutterRegionKey regionKey{};
    regionKey.vtable = RegionKeyVtableResetToken();
    regionKey.mX = region->mX;
    regionKey.mZ = region->mZ;
    (void)EraseRegionKeyRange(&regionKey, &mKeys);

    if (mCurRegion == region) {
      mCurRegion = region->mPrev;
    }

    if (region->mNext) {
      region->mNext->mPrev = region->mPrev;
    }
    if (region->mPrev) {
      region->mPrev->mNext = region->mNext;
    }

    (void)ResetRegionRuntimeState(region);

    (void)AppendPointerListTail(
      reinterpret_cast<void* const*>(&region),
      reinterpret_cast<ClutterIntrusiveListState*>(&mList2),
      reinterpret_cast<ClutterListNode*>(mList2.head)
    );
  }

  /**
   * Address: 0x007D63A0 (FUN_007D63A0, ?Clear@Clutter@Moho@@QAEXXZ)
   */
  void Clutter::Clear()
  {
    ClutterRegion* currentRegion = mCurRegion;
    while (currentRegion) {
      ClutterRegion* const previous = currentRegion->mPrev;
      DestroyRegion(currentRegion);
      currentRegion = previous;
    }
    mCurRegion = nullptr;

    if (!mKeys.head) {
      mKeys.size = 0;
      return;
    }

    DestroyRegionKeySubtree(this, mKeys.head->parent);
    mKeys.head->parent = mKeys.head;
    mKeys.size = 0;
    mKeys.head->left = mKeys.head;
    mKeys.head->right = mKeys.head;
  }

  /**
   * Address: 0x007D62C0 (FUN_007D62C0, ?Shutdown@Clutter@Moho@@QAEXXZ)
   */
  void Clutter::Shutdown()
  {
    Clear();
    std::memset(mBuffer, 0, sizeof(mBuffer));

    for (ClutterSurfaceEntry& surface : mSurfaces) {
      ClutterSurfaceElement* beginCopy = nullptr;
      (void)ResetSurfaceEntryRange(&surface.eraseLane, &beginCopy, surface.eraseLane.begin, surface.eraseLane.end);
    }

    if (mList2.head) {
      ClutterRegionListNode* node = mList2.head->next;
      mList2.head->next = mList2.head;
      mList2.head->prev = mList2.head;
      mList2.size = 0;

      while (node != mList2.head) {
        ClutterRegionListNode* const nextNode = node->next;
        ::operator delete(node);
        node = nextNode;
      }
    } else {
      mList2.size = 0;
    }

    if (!mList1.head) {
      mList1.size = 0;
      return;
    }

    ClutterListNode* const head = mList1.head;
    ClutterListNode* node = head->next;
    (void)ReleaseRegionListPayloads(node, head, 0);

    head->next = head;
    head->prev = head;
    mList1.size = 0;

    while (node != head) {
      ClutterListNode* const nextNode = node->next;
      ::operator delete(node);
      node = nextNode;
    }
  }
} // namespace moho
