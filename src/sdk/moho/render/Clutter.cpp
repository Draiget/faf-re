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

#include <algorithm>
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

  struct UpdateInstanceVtableTag
  {
    virtual ~UpdateInstanceVtableTag() = default;
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

  struct UpdateInstanceRuntimeLane
  {
    void* vtable;
    std::int32_t ownerToken;
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
  UpdateInstanceVtableTag gUpdateInstanceVtableTag{};
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

  [[nodiscard]] void* UpdateInstanceVtableToken()
  {
    return *reinterpret_cast<void**>(&gUpdateInstanceVtableTag);
  }

  /**
   * Address: 0x007D5C90 (FUN_007D5C90)
   *
   * What it does:
   * Initializes one region-key runtime lane from explicit `(x,z)` coordinates.
   */
  [[maybe_unused]] moho::ClutterRegionKey* InitializeRegionKeyFromCoordinates(
    moho::ClutterRegionKey* const outKey,
    const std::int32_t x,
    const std::int32_t z
  ) noexcept
  {
    if (outKey == nullptr) {
      return nullptr;
    }

    outKey->vtable = RegionKeyVtableResetToken();
    outKey->mX = x;
    outKey->mZ = z;
    return outKey;
  }

  /**
   * Address: 0x007D5CA0 (FUN_007D5CA0)
   *
   * What it does:
   * Initializes one region-key runtime lane by copying `(x,z)` from one
   * clutter-region lane.
   */
  [[maybe_unused]] moho::ClutterRegionKey* InitializeRegionKeyFromRegion(
    moho::ClutterRegionKey* const outKey,
    const moho::ClutterRegion* const region
  ) noexcept
  {
    if (outKey == nullptr) {
      return nullptr;
    }

    outKey->vtable = RegionKeyVtableResetToken();
    outKey->mX = region != nullptr ? region->mX : 0;
    outKey->mZ = region != nullptr ? region->mZ : 0;
    return outKey;
  }

  /**
   * Address: 0x007D92A0 (FUN_007D92A0)
   *
   * What it does:
   * Initializes one region-key runtime lane by copying coordinates from one
   * source region-key lane.
   */
  [[maybe_unused]] moho::ClutterRegionKey* InitializeRegionKeyFromSourceKey(
    moho::ClutterRegionKey* const outKey,
    const moho::ClutterRegionKey* const sourceKey
  ) noexcept
  {
    if (outKey == nullptr) {
      return nullptr;
    }

    outKey->vtable = RegionKeyVtableResetToken();
    outKey->mX = sourceKey != nullptr ? sourceKey->mX : 0;
    outKey->mZ = sourceKey != nullptr ? sourceKey->mZ : 0;
    return outKey;
  }

  /**
   * Address: 0x007D5E30 (FUN_007D5E30)
   *
   * What it does:
   * Initializes one update-instance helper lane with owner token payload.
   */
  [[maybe_unused]] UpdateInstanceRuntimeLane* InitializeUpdateInstanceLane(
    UpdateInstanceRuntimeLane* const outLane,
    const std::int32_t ownerToken
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = UpdateInstanceVtableToken();
    outLane->ownerToken = ownerToken;
    return outLane;
  }

  /**
   * Address: 0x007D5E40 (FUN_007D5E40)
   *
   * What it does:
   * Resets one update-instance helper lane to the `UpdateInstance` vtable.
   */
  [[maybe_unused]] void ResetUpdateInstanceLaneVtable(UpdateInstanceRuntimeLane* const lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    lane->vtable = UpdateInstanceVtableToken();
  }

  /**
   * Address: 0x007D9820 (FUN_007D9820)
   *
   * What it does:
   * Initializes one destroy-instance lane from another lane's payload while
   * restoring the destroy-instance vtable token.
   */
  [[maybe_unused]] DestroyInstanceRuntimeLane* InitializeDestroyInstanceLaneFromSource(
    DestroyInstanceRuntimeLane* const outLane,
    const DestroyInstanceRuntimeLane* const sourceLane
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = DestroyInstanceVtableToken();
    outLane->instance = sourceLane != nullptr ? sourceLane->instance : nullptr;
    return outLane;
  }

  /**
   * Address: 0x007D9830 (FUN_007D9830)
   *
   * What it does:
   * Initializes one update-instance lane from another lane's owner-token
   * payload while restoring the update-instance vtable token.
   */
  [[maybe_unused]] UpdateInstanceRuntimeLane* InitializeUpdateInstanceLaneFromSource(
    UpdateInstanceRuntimeLane* const outLane,
    const UpdateInstanceRuntimeLane* const sourceLane
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = UpdateInstanceVtableToken();
    outLane->ownerToken = sourceLane != nullptr ? sourceLane->ownerToken : 0;
    return outLane;
  }

  /**
   * Address: 0x007D5EA0 (FUN_007D5EA0)
   *
   * What it does:
   * Resets one destroy-instance helper lane to the `DestroyInstance` vtable.
   */
  void ResetDestroyInstanceLaneVtable(DestroyInstanceRuntimeLane* const lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    lane->vtable = DestroyInstanceVtableToken();
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

  [[nodiscard]] int AlignDownToEven(const int value) noexcept
  {
    return (value % 2 != 0) ? (value - 1) : value;
  }

  [[nodiscard]] int AlignUpToEven(const int value) noexcept
  {
    return (value % 2 != 0) ? (value + 1) : value;
  }

  [[nodiscard]] float SampleHeightWordAsWorldUnits(
    const moho::CHeightField& heightField,
    const int x,
    const int z
  ) noexcept
  {
    if (heightField.data == nullptr || heightField.width <= 0 || heightField.height <= 0) {
      return 0.0f;
    }

    const int clampedX = std::clamp(x, 0, heightField.width - 1);
    const int clampedZ = std::clamp(z, 0, heightField.height - 1);
    const std::size_t sampleIndex =
      static_cast<std::size_t>(clampedZ) * static_cast<std::size_t>(heightField.width)
      + static_cast<std::size_t>(clampedX);

    constexpr float kHeightWordScale = 0.0078125f;
    return static_cast<float>(heightField.data[sampleIndex]) * kHeightWordScale;
  }

  [[nodiscard]] Wm3::AxisAlignedBox3f BuildRegionBoundsFromHeightField(
    const moho::CHeightField& heightField,
    const int x,
    const int z
  )
  {
    const float h00 = SampleHeightWordAsWorldUnits(heightField, x, z);
    const float h01 = SampleHeightWordAsWorldUnits(heightField, x, z + 2);
    const float h10 = SampleHeightWordAsWorldUnits(heightField, x + 2, z);
    const float h11 = SampleHeightWordAsWorldUnits(heightField, x + 2, z + 2);

    const float minHeight = std::min(std::min(h00, h01), std::min(h10, h11));
    const float maxHeight = std::max(std::max(h00, h01), std::max(h10, h11));

    Wm3::AxisAlignedBox3f regionBounds{};
    regionBounds.Min.x = static_cast<float>(x);
    regionBounds.Min.y = minHeight;
    regionBounds.Min.z = static_cast<float>(z);
    regionBounds.Max.x = static_cast<float>(x + 2);
    regionBounds.Max.y = maxHeight;
    regionBounds.Max.z = static_cast<float>(z + 2);
    return regionBounds;
  }

  [[nodiscard]] std::uint8_t GetTerrainTypeAtOrDefault(
    const moho::STIMap& map,
    const int x,
    const int z
  ) noexcept
  {
    if (map.mTerrainType.data == nullptr || map.mTerrainType.width <= 1 || map.mTerrainType.height <= 1) {
      return 1u;
    }

    const int maxSampleX = map.mTerrainType.width - 1;
    const int maxSampleZ = map.mTerrainType.height - 1;
    if (x < 0 || z < 0 || x >= maxSampleX || z >= maxSampleZ) {
      return 1u;
    }

    const std::size_t terrainIndex =
      static_cast<std::size_t>(z) * static_cast<std::size_t>(map.mTerrainType.width)
      + static_cast<std::size_t>(x);
    return map.mTerrainType.data[terrainIndex];
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
   * Address: 0x007D7C20 (FUN_007D7C20)
   *
   * What it does:
   * Finds one exact region-key match and stores either that node or the tree
   * head sentinel (miss) into `outNode`.
   */
  moho::ClutterRegionKeyNode** FindRegionKeyExactOrHead(
    moho::ClutterRegionKeyNode** const outNode,
    moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKey& key
  )
  {
    if (outNode == nullptr || tree == nullptr || tree->head == nullptr) {
      return outNode;
    }

    moho::ClutterRegionKeyNode* const candidate = FindLowerBound(tree, key);
    if (candidate == tree->head || RegionKeyLess(key, candidate->key)) {
      *outNode = tree->head;
    } else {
      *outNode = candidate;
    }
    return outNode;
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
   * Address: 0x007D7A80 (FUN_007D7A80)
   *
   * What it does:
   * Erases all region-key nodes, releases the tree head sentinel lane, and
   * resets the owner state to an empty/null tree.
   */
  std::int32_t ClearRegionKeyTreeStorageLaneA(moho::ClutterRegionKeyTreeState* const tree)
  {
    moho::ClutterRegionKeyNode* outNext = nullptr;
    (void)EraseRegionKeyNodeRange(tree, &outNext, tree->head->left, tree->head);
    ::operator delete(tree->head);
    tree->head = nullptr;
    tree->size = 0;
    return 0;
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
    ResetDestroyInstanceLaneVtable(&destroyLane);
  }

  /**
   * Address: 0x007D9440 (FUN_007D9440)
   *
   * What it does:
   * Rebinds each region-map mesh instance to the provided clutter owner and
   * refreshes one update-instance helper lane to the update vtable token.
   */
  UpdateInstanceRuntimeLane* BindRegionMeshInstancesToOwner(
    UpdateInstanceRuntimeLane* const lane,
    moho::ClutterListNode* begin,
    moho::ClutterListNode* const endSentinel,
    const std::int32_t ownerToken
  ) noexcept
  {
    if (lane == nullptr) {
      return nullptr;
    }

    for (moho::ClutterListNode* node = begin; node != endSentinel; node = node->next) {
      auto* const meshInstance = static_cast<moho::MeshInstance*>(node->payload);
      meshInstance->unk24 = ownerToken;
    }

    lane->ownerToken = ownerToken;
    lane->vtable = UpdateInstanceVtableToken();
    return lane;
  }

  [[nodiscard]] void* AllocatePointerListStorageChecked(std::uint32_t count);

  /**
   * Address: 0x007D7D00 (FUN_007D7D00)
   *
   * What it does:
   * Allocates one 12-byte intrusive-list sentinel node and self-links its
   * `next/prev` lanes.
   */
  [[nodiscard]] moho::ClutterListNode* AllocateRegionMapSentinelNode()
  {
    auto* const node = static_cast<moho::ClutterListNode*>(AllocatePointerListStorageChecked(1u));
    node->next = node;
    node->prev = node;
    return node;
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
   * Address: 0x007D8EC0 (FUN_007D8EC0)
   *
   * What it does:
   * Allocates one region-key RB-tree node and initializes parent/child links,
   * key payload, and red/non-nil color flags.
   */
  [[nodiscard]] moho::ClutterRegionKeyNode* AllocateRegionKeyTreeNode(
    moho::ClutterRegionKeyNode* const left,
    moho::ClutterRegionKeyNode* const parent,
    moho::ClutterRegionKeyNode* const right,
    const moho::ClutterRegionKey& key
  )
  {
    moho::ClutterRegionKeyNode* const node = AllocateRegionKeyNode();
    if (node == nullptr) {
      return nullptr;
    }

    node->left = left;
    node->parent = parent;
    node->right = right;
    node->key.vtable = RegionKeyVtableResetToken();
    node->key.mX = key.mX;
    node->key.mZ = key.mZ;
    node->color = 0;
    node->isNil = 0;
    return node;
  }

  [[nodiscard]] bool InsertRegionKeyIntoTree(
    moho::ClutterRegionKeyTreeState* const tree,
    const moho::ClutterRegionKey& key
  )
  {
    if (tree == nullptr || tree->head == nullptr) {
      return false;
    }

    constexpr std::uint32_t kMaxRegionKeyCount = 0x15555554u;
    if (tree->size >= kMaxRegionKeyCount) {
      throw std::length_error("map/set<T> too long");
    }

    moho::ClutterRegionKeyNode* parent = tree->head;
    moho::ClutterRegionKeyNode* probe = tree->head->parent;
    bool insertOnLeft = true;

    while (!IsTreeNil(tree, probe)) {
      parent = probe;
      if (RegionKeyLess(key, probe->key)) {
        probe = probe->left;
        insertOnLeft = true;
      } else if (RegionKeyLess(probe->key, key)) {
        probe = probe->right;
        insertOnLeft = false;
      } else {
        return false;
      }
    }

    moho::ClutterRegionKeyNode* inserted =
      AllocateRegionKeyTreeNode(tree->head, parent, tree->head, key);
    if (inserted == nullptr) {
      return false;
    }

    if (parent == tree->head) {
      tree->head->parent = inserted;
      tree->head->left = inserted;
      tree->head->right = inserted;
    } else if (insertOnLeft) {
      parent->left = inserted;
    } else {
      parent->right = inserted;
    }

    ++tree->size;

    while (inserted != tree->head->parent && !IsTreeBlack(tree, inserted->parent)) {
      moho::ClutterRegionKeyNode* parentNode = inserted->parent;
      moho::ClutterRegionKeyNode* grandParent = parentNode->parent;

      if (parentNode == grandParent->left) {
        moho::ClutterRegionKeyNode* const uncle = grandParent->right;
        if (!IsTreeBlack(tree, uncle)) {
          parentNode->color = 1;
          uncle->color = 1;
          grandParent->color = 0;
          inserted = grandParent;
        } else {
          if (inserted == parentNode->right) {
            inserted = parentNode;
            RotateTreeLeft(tree, inserted);
            parentNode = inserted->parent;
            grandParent = parentNode->parent;
          }

          parentNode->color = 1;
          grandParent->color = 0;
          RotateTreeRight(tree, grandParent);
        }
      } else {
        moho::ClutterRegionKeyNode* const uncle = grandParent->left;
        if (!IsTreeBlack(tree, uncle)) {
          parentNode->color = 1;
          uncle->color = 1;
          grandParent->color = 0;
          inserted = grandParent;
        } else {
          if (inserted == parentNode->left) {
            inserted = parentNode;
            RotateTreeRight(tree, inserted);
            parentNode = inserted->parent;
            grandParent = parentNode->parent;
          }

          parentNode->color = 1;
          grandParent->color = 0;
          RotateTreeLeft(tree, grandParent);
        }
      }
    }

    tree->head->parent->color = 1;
    RefreshTreeEndpoints(tree);
    return true;
  }

  [[nodiscard]] moho::ClutterRegion* AllocateRegionPoolBlock()
  {
    constexpr std::uint32_t kRegionPoolCount = 128u;

    auto* const rawStorage = static_cast<std::uint8_t*>(
      ::operator new(sizeof(std::uint32_t) + sizeof(moho::ClutterRegion) * kRegionPoolCount)
    );
    *reinterpret_cast<std::uint32_t*>(rawStorage) = kRegionPoolCount;

    auto* const regionBase =
      reinterpret_cast<moho::ClutterRegion*>(rawStorage + sizeof(std::uint32_t));
    std::uint32_t constructedCount = 0u;

    try {
      for (; constructedCount < kRegionPoolCount; ++constructedCount) {
        ::new (static_cast<void*>(regionBase + constructedCount)) moho::ClutterRegion();
      }
    } catch (...) {
      while (constructedCount > 0u) {
        --constructedCount;
        regionBase[constructedCount].~ClutterRegion();
      }
      ::operator delete(rawStorage);
      throw;
    }

    return regionBase;
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
   * Address: 0x007D85C0 (FUN_007D85C0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one clutter list node storage
   * record through the checked allocator.
   */
  [[maybe_unused]] [[nodiscard]] void* AllocateSinglePointerListStorageCheckedAdapter()
  {
    return AllocatePointerListStorageChecked(1u);
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
   * Address: 0x007D94F0 (FUN_007D94F0)
   *
   * What it does:
   * Register-shape adapter that forwards one clutter-seed range copy into the
   * canonical count-based copy lane.
   */
  [[maybe_unused]] moho::ClutterSurfaceElement* CopyClutterSeedRangeAdapterA(
    moho::ClutterSurfaceElement* const destination,
    const moho::ClutterSurfaceElement* const source,
    const std::uint32_t count
  )
  {
    return CopyClutterSeedRange(destination, source, static_cast<int>(count));
  }

  /**
   * Address: 0x007D7F00 (FUN_007D7F00)
   *
   * What it does:
   * Copies `count` repeated `ClutterSurfaceElement` values from one seed value
   * lane and returns one-past-end destination.
   */
  [[maybe_unused]] moho::ClutterSurfaceElement* CopyClutterSeedValueRange(
    moho::ClutterSurfaceElement* const destination,
    const moho::ClutterSurfaceElement& seedValue,
    const std::int32_t count
  )
  {
    if (count <= 0) {
      return destination;
    }

    return CopyClutterSeedRange(destination, &seedValue, count);
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
    mMap.head = AllocateRegionMapSentinelNode();
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
   * Address: 0x007D6380 (FUN_007D6380, ?Update@Clutter@Moho@@QAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Runs one clutter update frame by culling stale regions first, then
   * generating new visible region clutter from terrain data.
   */
  void Clutter::Update(const GeomCamera3* const camera)
  {
    UpdateCurrent(camera);
    GenerateNew(camera);
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
   * Address: 0x007D64C0 (FUN_007D64C0, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@PBVRegion@12@@Z)
   *
   * What it does:
   * Returns visibility state for one clutter region by delegating to AABB
   * visibility test using the region's box lane.
   */
  bool Clutter::IsVisible(const GeomCamera3* const camera, const ClutterRegion* const region)
  {
    return region != nullptr && IsVisible(camera, region->mBox);
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
      if (!IsVisible(camera, currentRegion)) {
        DestroyRegion(currentRegion);
      }

      currentRegion = previousRegion;
    }
  }

  /**
   * Address: 0x007D6640 (FUN_007D6640, ?GenerateNew@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Scans 2x2 terrain tiles around the camera clutter radius, creates missing
   * visible regions, and populates each region from four sampled terrain types.
   */
  void Clutter::GenerateNew(const GeomCamera3* const camera)
  {
    (void)MeshRenderer::GetInstance();

    if (GetActiveRules() == nullptr) {
      return;
    }

    STIMap* const terrainMap = GetTerrainTypeMap();
    if (terrainMap == nullptr) {
      return;
    }

    CHeightField* const heightField = terrainMap->GetHeightField();
    if (heightField == nullptr) {
      return;
    }

    const float radius = ren_ClutterRadius;
    const float originX = camera->inverseView.r[3].x;
    const float originZ = camera->inverseView.r[3].z;

    const float probeX0 = originX - radius * camera->view.r[0].z;
    const float probeX1 = originX + radius * camera->view.r[0].x;
    const float probeX2 = originX - radius * camera->view.r[0].x;

    const float probeZ0 = originZ - radius * camera->view.r[2].z;
    const float probeZ1 = originZ + radius * camera->view.r[2].x;
    const float probeZ2 = originZ - radius * camera->view.r[2].x;

    const int xBegin = AlignDownToEven(static_cast<int>(std::min(std::min(probeX0, probeX1), probeX2)));
    const int xEnd = AlignUpToEven(static_cast<int>(std::max(std::max(probeX0, probeX1), probeX2)));
    const int zBegin = AlignDownToEven(static_cast<int>(std::min(std::min(probeZ0, probeZ1), probeZ2)));
    const int zEnd = AlignUpToEven(static_cast<int>(std::max(std::max(probeZ0, probeZ1), probeZ2)));

    for (int x = xBegin; x < xEnd; x += 2) {
      for (int z = zBegin; z < zEnd; z += 2) {
        if (IsCluttered(x, z)) {
          continue;
        }

        const Wm3::AxisAlignedBox3f regionBounds = BuildRegionBoundsFromHeightField(*heightField, x, z);
        if (!IsVisible(camera, regionBounds)) {
          continue;
        }

        ClutterRegion* const region = CreateRegion(x, z, regionBounds);
        if (region == nullptr) {
          continue;
        }

        const std::uint8_t terrain00 = GetTerrainTypeAtOrDefault(*terrainMap, x, z);
        const std::uint8_t terrain01 = GetTerrainTypeAtOrDefault(*terrainMap, x, z + 1);
        const std::uint8_t terrain10 = GetTerrainTypeAtOrDefault(*terrainMap, x + 1, z);
        const std::uint8_t terrain11 = GetTerrainTypeAtOrDefault(*terrainMap, x + 1, z + 1);

        const float density00 = static_cast<float>(
                                  (terrain00 == terrain01) + (terrain00 == terrain10) + (terrain00 == terrain11) + 1
                                )
                              * 0.25f;
        const float density01 = static_cast<float>(
                                  (terrain01 == terrain00) + (terrain01 == terrain10) + (terrain01 == terrain11) + 1
                                )
                              * 0.25f;
        const float density10 = static_cast<float>(
                                  (terrain10 == terrain00) + (terrain10 == terrain01) + (terrain10 == terrain11) + 1
                                )
                              * 0.25f;
        const float density11 = static_cast<float>(
                                  (terrain11 == terrain00) + (terrain11 == terrain01) + (terrain11 == terrain10) + 1
                                )
                              * 0.25f;

        PopulateRegionClutter(camera, *heightField, region, density00, GetSurface(terrain00));
        PopulateRegionClutter(camera, *heightField, region, density01, GetSurface(terrain01));
        PopulateRegionClutter(camera, *heightField, region, density10, GetSurface(terrain10));
        PopulateRegionClutter(camera, *heightField, region, density11, GetSurface(terrain11));
      }
    }
  }

  /**
   * Address: 0x007D7050 (FUN_007D7050, ?UpdateRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@PAVRegion@12@@Z)
   *
   * What it does:
   * Rebinds each mesh-instance payload in one region map to this clutter
   * owner lane.
   */
  void Clutter::UpdateRegion(const GeomCamera3* const camera, ClutterRegion* const region)
  {
    (void)camera;

    ClutterListNode* const head = region->mMap.head;
    UpdateInstanceRuntimeLane updateLane{};
    const auto ownerToken = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(this));
    (void)BindRegionMeshInstancesToOwner(&updateLane, head->next, head, ownerToken);
  }

  /**
   * Address: 0x007D64D0 (FUN_007D64D0, ?IsCluttered@Clutter@Moho@@AAE_NHH@Z)
   *
   * What it does:
   * Probes the region-key RB-tree for one exact `(x,z)` key match.
   */
  bool Clutter::IsCluttered(const int x, const int z)
  {
    ClutterRegionKey lookupKey{};
    lookupKey.vtable = RegionKeyVtableResetToken();
    lookupKey.mX = x;
    lookupKey.mZ = z;

    ClutterRegionKeyNode* candidate = mKeys.head;
    (void)FindRegionKeyExactOrHead(&candidate, &mKeys, lookupKey);
    return candidate != nullptr && candidate != mKeys.head;
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
    ResetDestroyInstanceLaneVtable(&destroyLane);
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
   * Address: 0x007D7F70 (FUN_007D7F70)
   *
   * What it does:
   * Allocates one region-list node at the tail sentinel position, increments
   * list size with VC8 overflow semantics, and links the new tail node.
   */
  std::uint32_t __stdcall AppendRegionListTailLaneA(
    ClutterRegion* const* const valueRef,
    ClutterRegionListState* const sizeState,
    ClutterRegionListState* const linkState
  )
  {
    ClutterRegionListNode* const node = AllocateRegionListNode(linkState->head, linkState->head->prev, valueRef);
    const std::uint32_t nextSize = IncrementListSizeChecked(sizeState);
    linkState->head->prev = node;
    node->prev->next = node;
    return nextSize;
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
   * Address: 0x007D6E10 (FUN_007D6E10, ?UnlinkRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
   *
   * What it does:
   * Detaches one region node from the active doubly-linked chain and updates
   * `mCurRegion` when it points at the removed node.
   */
  void Clutter::UnlinkRegion(ClutterRegion* const region)
  {
    if (mCurRegion == region) {
      mCurRegion = region->mNext;
    }

    if (region->mPrev != nullptr) {
      region->mPrev->mNext = region->mNext;
    }

    if (region->mNext != nullptr) {
      region->mNext->mPrev = region->mPrev;
    }
  }

  /**
   * Address: 0x007D6E40
   * (FUN_007D6E40, ?CreateRegion@Clutter@Moho@@AAEPAVRegion@12@HHABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * What it does:
   * Expands the recycle pool in 128-region blocks when needed, takes one
   * recycled region, links it as current, writes coordinates/bounds, and
   * inserts the corresponding key into the region-key tree.
   */
  ClutterRegion* Clutter::CreateRegion(const int x, const int z, const Wm3::AxisAlignedBox3f& box)
  {
    constexpr std::uint32_t kRegionPoolCount = 128u;

    if (mList2.size == 0u) {
      ClutterRegion* const regionPool = AllocateRegionPoolBlock();
      (void)AppendPointerListTail(reinterpret_cast<void* const*>(&regionPool), &mList1, mList1.head);

      for (std::uint32_t index = 0; index < kRegionPoolCount; ++index) {
        ClutterRegion* regionValue = regionPool + index;
        (void)AppendRegionListTailLaneA(&regionValue, &mList2, &mList2);
      }
    }

    ClutterRegionListNode* const recycleHead = mList2.head;
    ClutterRegionListNode* const recycleNode = recycleHead->next;
    if (recycleNode == recycleHead) {
      return nullptr;
    }

    ClutterRegion* const region = recycleNode->value;
    recycleNode->prev->next = recycleNode->next;
    recycleNode->next->prev = recycleNode->prev;
    ::operator delete(recycleNode);
    if (mList2.size != 0u) {
      --mList2.size;
    }

    region->mNext = nullptr;
    region->mPrev = mCurRegion;
    if (mCurRegion != nullptr) {
      mCurRegion->mNext = region;
    }
    mCurRegion = region;

    region->mX = x;
    region->mZ = z;
    region->mBox = box;

    ClutterRegionKey regionKey{};
    regionKey.vtable = RegionKeyVtableResetToken();
    regionKey.mX = x;
    regionKey.mZ = z;
    (void)InsertRegionKeyIntoTree(&mKeys, regionKey);

    return region;
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

    UnlinkRegion(region);

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
   * Address: 0x007D62B0 (FUN_007D62B0, ?Initialize@Clutter@Moho@@QAEXXZ)
   *
   * What it does:
   * Forwards to `Shutdown()` (thunk lane in the original binary).
   */
  void Clutter::Initialize()
  {
    Shutdown();
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
