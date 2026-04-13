#include "moho/ai/CAiReconDBImpl.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "moho/ai/CAiBrain.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  using PerArmyReconView = SPerArmyReconInfo;

  struct ReconMapNodeView
  {
    ReconMapNodeView* left;   // +0x00
    ReconMapNodeView* parent; // +0x04
    ReconMapNodeView* right;  // +0x08
    SReconKey key;            // +0x0C
    ReconBlip* value;         // +0x18
    std::uint8_t color;       // +0x1C (0=red, 1=black)
    std::uint8_t isNil;       // +0x1D
    std::uint8_t pad_1E_1F[0x02];
  };
  static_assert(sizeof(ReconMapNodeView) == 0x20, "ReconMapNodeView size must be 0x20");
  static_assert(offsetof(ReconMapNodeView, key) == 0x0C, "ReconMapNodeView::key offset must be 0x0C");
  static_assert(offsetof(ReconMapNodeView, value) == 0x18, "ReconMapNodeView::value offset must be 0x18");
  static_assert(offsetof(ReconMapNodeView, color) == 0x1C, "ReconMapNodeView::color offset must be 0x1C");
  static_assert(offsetof(ReconMapNodeView, isNil) == 0x1D, "ReconMapNodeView::isNil offset must be 0x1D");

  constexpr std::uint8_t kNodeColorRed = 0u;
  constexpr std::uint8_t kNodeColorBlack = 1u;
  constexpr std::uint32_t kReconMapMaxSize = 0x0FFFFFFEu;

  /**
   * Address: 0x005C8800 (FUN_005C8800)
   *
   * What it does:
   * Allocates one map-head node with null child/parent links and black color.
   * The caller performs final sentinel self-link initialization.
   */
  [[nodiscard]] ReconMapNodeView* AllocateReconMapHeadNode()
  {
    auto* const head = new ReconMapNodeView{};
    head->left = nullptr;
    head->parent = nullptr;
    head->right = nullptr;
    head->color = kNodeColorBlack;
    head->isNil = 0u;
    return head;
  }

  [[nodiscard]] ReconMapNodeView* MapHead(const CAiReconDBImpl* const owner) noexcept
  {
    return owner ? reinterpret_cast<ReconMapNodeView*>(owner->mBlipMap.mHead) : nullptr;
  }

  [[nodiscard]] bool IsNil(const ReconMapNodeView* const node) noexcept
  {
    return !node || node->isNil != 0u;
  }

  [[nodiscard]] ReconMapNodeView* MapEnd(const CAiReconDBImpl* const owner) noexcept
  {
    return MapHead(owner);
  }

  /**
   * Address: 0x005C5CC0 (FUN_005C5CC0)
   *
   * What it does:
   * Returns the leftmost (minimum-key) node reachable from `node`.
   */
  [[nodiscard]] ReconMapNodeView* TreeMin(ReconMapNodeView* node, ReconMapNodeView* const head) noexcept
  {
    while (!IsNil(node->left)) {
      node = node->left;
    }
    return node ? node : head;
  }

  /**
   * Address: 0x005C5CA0 (FUN_005C5CA0)
   *
   * What it does:
   * Returns the rightmost (maximum-key) node reachable from `node`.
   */
  [[nodiscard]] ReconMapNodeView* TreeMax(ReconMapNodeView* node, ReconMapNodeView* const head) noexcept
  {
    while (!IsNil(node->right)) {
      node = node->right;
    }
    return node ? node : head;
  }

  [[nodiscard]] ReconMapNodeView* MapBegin(const CAiReconDBImpl* const owner) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head || IsNil(head->parent)) {
      return head;
    }
    return head->left;
  }

  /**
   * Address: 0x005C7A90 (FUN_005C7A90)
   *
   * What it does:
   * Returns the in-order successor for one recon-map node iterator.
   */
  [[nodiscard]] ReconMapNodeView* MapNext(ReconMapNodeView* node, ReconMapNodeView* const head) noexcept
  {
    if (!node || IsNil(node)) {
      return head;
    }

    ReconMapNodeView* right = node->right;
    if (IsNil(right)) {
      ReconMapNodeView* parent = node->parent;
      while (!IsNil(parent) && node == parent->right) {
        node = parent;
        parent = parent->parent;
      }
      return parent;
    }

    node = right;
    while (!IsNil(node->left)) {
      node = node->left;
    }
    return node;
  }

  /**
   * Address: 0x005C5C50 (FUN_005C5C50)
   *
   * What it does:
   * Performs one left rotation around `node` in the recon-map RB-tree.
   */
  void RotateLeft(ReconMapNodeView* const node, CAiReconDBImpl* const owner) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head || !node) {
      return;
    }

    ReconMapNodeView* const right = node->right;
    node->right = right->left;
    if (!IsNil(right->left)) {
      right->left->parent = node;
    }

    right->parent = node->parent;
    if (node == head->parent) {
      head->parent = right;
    } else if (node == node->parent->left) {
      node->parent->left = right;
    } else {
      node->parent->right = right;
    }

    right->left = node;
    node->parent = right;
  }

  /**
   * Address: 0x005C5D00 (FUN_005C5D00)
   *
   * What it does:
   * Performs one right rotation around `node` in the recon-map RB-tree.
   */
  void RotateRight(ReconMapNodeView* const node, CAiReconDBImpl* const owner) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head || !node) {
      return;
    }

    ReconMapNodeView* const left = node->left;
    node->left = left->right;
    if (!IsNil(left->right)) {
      left->right->parent = node;
    }

    left->parent = node->parent;
    if (node == head->parent) {
      head->parent = left;
    } else if (node == node->parent->right) {
      node->parent->right = left;
    } else {
      node->parent->left = left;
    }

    left->right = node;
    node->parent = left;
  }

  void LinkKeyToSourceChain(SReconKey& key) noexcept
  {
    key.sourceUnit.LinkIntoOwnerChainHeadUnlinked();
  }

  /**
   * Address: 0x005C2360 (FUN_005C2360)
   *
   * What it does:
   * Unlinks one weak-link node from its owner chain.
   */
  void UnlinkKeyFromSourceChain(SReconKey& key) noexcept
  {
    key.sourceUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x005C8840 (FUN_005C8840)
   *
   * What it does:
   * Allocates one recon-map node, copies key payload, and links key weak-chain
   * ownership for `sourceUnit`.
   */
  [[nodiscard]] ReconMapNodeView* AllocateMapNode(
    ReconMapNodeView* const head, ReconMapNodeView* const parent, const SReconKey& key, ReconBlip* const value
  )
  {
    auto* const node = new ReconMapNodeView{};
    node->left = head;
    node->parent = parent;
    node->right = head;
    node->key = key;
    node->value = value;
    node->color = kNodeColorRed;
    node->isNil = 0u;
    LinkKeyToSourceChain(node->key);
    return node;
  }

  [[nodiscard]] std::uint32_t GetSourceEntityId(const Unit* const source) noexcept
  {
    return source ? static_cast<std::uint32_t>(source->id_) : 0u;
  }

  [[nodiscard]] SReconKey MakeReconMapKey(Unit* const sourceUnit) noexcept
  {
    SReconKey key{};
    key.sourceUnit.BindObjectUnlinked(sourceUnit);
    key.sourceEntityId = GetSourceEntityId(sourceUnit);
    return key;
  }

  struct ReconMapInsertResult
  {
    ReconMapNodeView* node;
    bool inserted;
  };

  /**
   * Address: 0x005C7430 (FUN_005C7430)
   *
   * What it does:
   * Inserts one node at the precomputed parent/side location and runs RB-tree
   * recolor/rotation fixup.
   */
  [[nodiscard]] ReconMapNodeView* InsertMapNodeWithHint(
    CAiReconDBImpl* const owner,
    ReconMapNodeView* const parent,
    const bool insertLeft,
    const SReconKey& key,
    ReconBlip* const value
  )
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return nullptr;
    }

    if (owner->mBlipMap.mSize >= kReconMapMaxSize) {
      throw std::length_error("map/set<T> too long");
    }

    ReconMapNodeView* const insertedNode = AllocateMapNode(head, parent, key, value);
    ++owner->mBlipMap.mSize;

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

    ReconMapNodeView* node = insertedNode;
    while (node->parent->color == kNodeColorRed) {
      ReconMapNodeView* const parentNode = node->parent;
      ReconMapNodeView* const grandParent = parentNode->parent;
      if (parentNode == grandParent->left) {
        ReconMapNodeView* const uncle = grandParent->right;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->right) {
            node = parentNode;
            RotateLeft(parentNode, owner);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateRight(node->parent->parent, owner);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          node = grandParent;
          continue;
        }
      } else {
        ReconMapNodeView* const uncle = grandParent->left;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->left) {
            node = parentNode;
            RotateRight(parentNode, owner);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateLeft(node->parent->parent, owner);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          node = grandParent;
          continue;
        }
      }
      break;
    }
    head->parent->color = kNodeColorBlack;
    return insertedNode;
  }

  /**
   * Address: 0x005C5AF0 (FUN_005C5AF0)
   *
   * What it does:
   * Finds insertion parent/side by `SReconKey::sourceEntityId` ordering and
   * forwards to the core insert+rebalance helper.
   */
  [[nodiscard]] ReconMapInsertResult InsertMapNodeBySourceEntityId(
    CAiReconDBImpl* const owner, const SReconKey& key, ReconBlip* const value
  )
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return {nullptr, false};
    }

    ReconMapNodeView* parent = head;
    ReconMapNodeView* cursor = head->parent;
    bool insertLeft = true;
    while (!IsNil(cursor)) {
      parent = cursor;
      insertLeft = key.sourceEntityId < cursor->key.sourceEntityId;
      cursor = insertLeft ? cursor->left : cursor->right;
    }

    return {InsertMapNodeWithHint(owner, parent, insertLeft, key, value), true};
  }

  [[nodiscard]] ReconMapNodeView* InsertMapNode(CAiReconDBImpl* const owner, const SReconKey& key, ReconBlip* const value)
  {
    return InsertMapNodeBySourceEntityId(owner, key, value).node;
  }

  /**
   * Address: 0x005C4950 (FUN_005C4950)
   *
   * What it does:
   * Finds the first map node whose `sourceEntityId` is not less than the
   * queried id.
   */
  [[nodiscard]] ReconMapNodeView* LowerBoundByEntityId(CAiReconDBImpl* const owner, const std::uint32_t sourceEntityId) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return nullptr;
    }

    ReconMapNodeView* result = head;
    ReconMapNodeView* cursor = head->parent;
    while (!IsNil(cursor)) {
      if (cursor->key.sourceEntityId >= sourceEntityId) {
        result = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }
    return result;
  }

  /**
   * Address: 0x005C49B0 (FUN_005C49B0)
   *
   * What it does:
   * Finds the first map node whose `sourceEntityId` is greater than the
   * queried id.
   */
  [[nodiscard]] ReconMapNodeView* UpperBoundByEntityId(CAiReconDBImpl* const owner, const std::uint32_t sourceEntityId) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return nullptr;
    }

    ReconMapNodeView* result = head;
    ReconMapNodeView* cursor = head->parent;
    while (!IsNil(cursor)) {
      if (sourceEntityId < cursor->key.sourceEntityId) {
        result = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }
    return result;
  }

  [[nodiscard]] std::pair<ReconMapNodeView*, ReconMapNodeView*>
  FindReconBlipRange(CAiReconDBImpl* const owner, Unit* const sourceUnit)
  {
    const std::uint32_t sourceEntityId = GetSourceEntityId(sourceUnit);
    return {LowerBoundByEntityId(owner, sourceEntityId), UpperBoundByEntityId(owner, sourceEntityId)};
  }

  void EraseFixup(CAiReconDBImpl* const owner, ReconMapNodeView* node, ReconMapNodeView* parent) noexcept
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return;
    }

    while (node != head->parent && node->color == kNodeColorBlack) {
      if (node == parent->left) {
        ReconMapNodeView* sibling = parent->right;
        if (sibling->color == kNodeColorRed) {
          sibling->color = kNodeColorBlack;
          parent->color = kNodeColorRed;
          RotateLeft(parent, owner);
          sibling = parent->right;
        }
        if (IsNil(sibling)) {
          node = parent;
          parent = node->parent;
          continue;
        }
        if (sibling->left->color == kNodeColorBlack && sibling->right->color == kNodeColorBlack) {
          sibling->color = kNodeColorRed;
          node = parent;
          parent = node->parent;
        } else {
          if (sibling->right->color == kNodeColorBlack) {
            sibling->left->color = kNodeColorBlack;
            sibling->color = kNodeColorRed;
            RotateRight(sibling, owner);
            sibling = parent->right;
          }
          sibling->color = parent->color;
          parent->color = kNodeColorBlack;
          sibling->right->color = kNodeColorBlack;
          RotateLeft(parent, owner);
          break;
        }
      } else {
        ReconMapNodeView* sibling = parent->left;
        if (sibling->color == kNodeColorRed) {
          sibling->color = kNodeColorBlack;
          parent->color = kNodeColorRed;
          RotateRight(parent, owner);
          sibling = parent->left;
        }
        if (IsNil(sibling)) {
          node = parent;
          parent = node->parent;
          continue;
        }
        if (sibling->right->color == kNodeColorBlack && sibling->left->color == kNodeColorBlack) {
          sibling->color = kNodeColorRed;
          node = parent;
          parent = node->parent;
        } else {
          if (sibling->left->color == kNodeColorBlack) {
            sibling->right->color = kNodeColorBlack;
            sibling->color = kNodeColorRed;
            RotateLeft(sibling, owner);
            sibling = parent->left;
          }
          sibling->color = parent->color;
          parent->color = kNodeColorBlack;
          sibling->left->color = kNodeColorBlack;
          RotateRight(parent, owner);
          break;
        }
      }
    }
    node->color = kNodeColorBlack;
  }

  /**
   * Address: 0x005C4580 (FUN_005C4580)
   *
   * What it does:
   * Erases one RB-tree node from the typed recon map and restores tree
   * invariants, then unlinks `SReconKey` weak ownership and decrements size.
   */
  [[nodiscard]] ReconMapNodeView* EraseMapNode(CAiReconDBImpl* const owner, ReconMapNodeView* const node)
  {
    auto* const head = MapHead(owner);
    if (!head || !node || node == head || IsNil(node)) {
      return head;
    }

    ReconMapNodeView* const next = MapNext(node, head);
    ReconMapNodeView* x = nullptr;
    ReconMapNodeView* xParent = nullptr;

    if (IsNil(next)) {
      x = node->right;
      xParent = node->parent;

      if (!IsNil(x)) {
        x->parent = xParent;
      }

      if (head->parent == node) {
        head->parent = x;
      } else if (xParent->left == node) {
        xParent->left = x;
      } else {
        xParent->right = x;
      }
    } else if (IsNil(node->right)) {
      x = node->left;
      xParent = node->parent;

      if (!IsNil(x)) {
        x->parent = xParent;
      }

      if (head->parent == node) {
        head->parent = x;
      } else if (xParent->left == node) {
        xParent->left = x;
      } else {
        xParent->right = x;
      }
    } else {
      ReconMapNodeView* const successor = next;
      x = successor->right;

      node->left->parent = successor;
      successor->left = node->left;
      if (successor == node->right) {
        xParent = successor;
      } else {
        xParent = successor->parent;
        if (!IsNil(x)) {
          x->parent = xParent;
        }
        xParent->left = x;
        successor->right = node->right;
        node->right->parent = successor;
      }

      if (head->parent == node) {
        head->parent = successor;
      } else if (node->parent->left == node) {
        node->parent->left = successor;
      } else {
        node->parent->right = successor;
      }
      successor->parent = node->parent;
      std::swap(successor->color, node->color);
    }

    if (head->left == node) {
      head->left = IsNil(x) ? xParent : TreeMin(x, head);
    }
    if (head->right == node) {
      head->right = IsNil(x) ? xParent : TreeMax(x, head);
    }

    if (node->color == kNodeColorBlack) {
      EraseFixup(owner, x, xParent);
    }

    UnlinkKeyFromSourceChain(node->key);
    delete node;
    if (owner->mBlipMap.mSize > 0) {
      --owner->mBlipMap.mSize;
    }

    if (owner->mBlipMap.mSize == 0 || IsNil(head->parent)) {
      head->parent = head;
      head->left = head;
      head->right = head;
    }

    return next;
  }

  /**
   * Address: 0x005C4860 (FUN_005C4860)
   *
   * What it does:
   * Clears one node range from the recon map; when used with
   * `[MapBegin(owner), MapEnd(owner))`, this performs a full map clear.
   */
  void ClearMap(CAiReconDBImpl* const owner)
  {
    auto* const head = MapHead(owner);
    if (!owner || !head) {
      return;
    }

    for (ReconMapNodeView* node = MapBegin(owner); node != head;) {
      node = EraseMapNode(owner, node);
    }

    owner->mBlipMap.mSize = 0u;
    head->parent = head;
    head->left = head;
    head->right = head;
    head->color = kNodeColorBlack;
    head->isNil = 1u;
  }

  [[nodiscard]] bool IsInsideRectXZ(const moho::Rect2<int>& rect, const Wm3::Vec3f& pos) noexcept
  {
    return pos.x >= static_cast<float>(rect.x0) && pos.x <= static_cast<float>(rect.x1) &&
      pos.z >= static_cast<float>(rect.z0) && pos.z <= static_cast<float>(rect.z1);
  }

  [[nodiscard]] bool IsInsideRadiusXZ(const Wm3::Vec3f& center, const float radius, const Wm3::Vec3f& pos) noexcept
  {
    const float dx = pos.x - center.x;
    const float dz = pos.z - center.z;
    return (dx * dx) + (dz * dz) <= (radius * radius);
  }

  [[nodiscard]] moho::Rect2<int> MakePointReconRect(const Wm3::Vec3f& pos) noexcept
  {
    const std::int32_t x = static_cast<std::int32_t>(pos.x);
    const std::int32_t z = static_cast<std::int32_t>(pos.z);
    return moho::Rect2<int>{
      .x0 = x,
      .z0 = z,
      .x1 = x + 1,
      .z1 = z + 1,
    };
  }

  [[nodiscard]] bool IsGridVisibleAtPoint(const CIntelGrid* const grid, const Wm3::Vec3f& pos)
  {
    return grid && grid->IsVisible(MakePointReconRect(pos));
  }

  [[nodiscard]] bool IsWithinPlayableMapRadius(
    const STIMap* const map,
    const Wm3::Vec3f& pos,
    const float radius,
    const bool ignorePlayableRect
  ) noexcept
  {
    if (!map) {
      return true;
    }

    float minX = 0.0f;
    float minZ = 0.0f;
    float maxX = std::numeric_limits<float>::infinity();
    float maxZ = std::numeric_limits<float>::infinity();

    const CHeightField* const heightField = map->mHeightField.get();
    if (heightField) {
      maxX = static_cast<float>(heightField->width);
      maxZ = static_cast<float>(heightField->height);
    }

    if (!ignorePlayableRect) {
      minX = std::max(minX, static_cast<float>(map->mPlayableRect.x0));
      minZ = std::max(minZ, static_cast<float>(map->mPlayableRect.z0));
      maxX = std::min(maxX, static_cast<float>(map->mPlayableRect.x1));
      maxZ = std::min(maxZ, static_cast<float>(map->mPlayableRect.z1));
    }

    if (maxX < minX || maxZ < minZ) {
      return false;
    }

    return pos.x >= minX + radius && pos.x <= maxX - radius && pos.z >= minZ + radius && pos.z <= maxZ - radius;
  }

  [[nodiscard]] EReconFlags SetFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(value) | static_cast<std::int32_t>(bit));
  }

  [[nodiscard]] EReconFlags MergeFlags(const EReconFlags lhs, const EReconFlags rhs) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(lhs) | static_cast<std::int32_t>(rhs));
  }

  [[nodiscard]] EReconFlags ClearFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(value) & ~static_cast<std::int32_t>(bit));
  }

  [[nodiscard]] bool HasFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return (static_cast<std::int32_t>(value) & static_cast<std::int32_t>(bit)) != 0;
  }

  [[nodiscard]] bool UsesWaterSenseLane(const ELayer layer) noexcept
  {
    constexpr std::int32_t kWaterSenseMask = static_cast<std::int32_t>(LAYER_Sub) | static_cast<std::int32_t>(LAYER_Water);
    return (static_cast<std::int32_t>(layer) & kWaterSenseMask) != 0;
  }

  [[nodiscard]] const char* ReconSenseLexical(const EReconFlags sense) noexcept
  {
    switch (sense) {
      case RECON_LOSNow:
        return "LOSNow";
      case RECON_Radar:
        return "Radar";
      case RECON_Sonar:
        return "Sonar";
      case RECON_Omni:
        return "Omni";
      default:
        return "Unknown";
    }
  }

  [[nodiscard]] bool IsAlliedOrSameArmy(const CArmyImpl* const viewer, const CArmyImpl* const owner) noexcept
  {
    if (!viewer || !owner) {
      return false;
    }

    if (viewer == owner) {
      return true;
    }

    if (owner->ArmyId < 0) {
      return false;
    }

    return viewer->Allies.Contains(static_cast<std::uint32_t>(owner->ArmyId));
  }

  [[nodiscard]] Unit* DecodeBlipSourceUnit(ReconBlip* const blip) noexcept
  {
    return blip ? blip->GetSourceUnit() : nullptr;
  }

  [[nodiscard]] bool IsFakeBlip(ReconBlip* const blip) noexcept
  {
    return blip && blip->IsFake();
  }

  [[nodiscard]] PerArmyReconView* GetPerArmyReconSlot(
    ReconBlip* const blip, const std::int32_t armyIndex
  ) noexcept
  {
    return blip ? blip->GetPerArmyReconInfo(armyIndex) : nullptr;
  }

  [[nodiscard]] std::int32_t GetActiveJammerBlipCount(const Unit* const unit) noexcept
  {
    if (!unit) {
      return 0;
    }

    const CIntel* const intel = unit->GetIntelManager();
    if (!intel || !intel->HasActiveJamming()) {
      return 0;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return 0;
    }

    return static_cast<std::int32_t>(blueprint->Intel.JammerBlips);
  }

  [[nodiscard]] bool IsViewerAlliedWithBlipArmy(CAiReconDBImpl* const owner, ReconBlip* const blip) noexcept
  {
    if (!owner || !blip) {
      return false;
    }

    auto* const entity = reinterpret_cast<Entity*>(blip);
    return IsAlliedOrSameArmy(owner->mArmy, entity ? entity->ArmyRef : nullptr);
  }

  [[nodiscard]] Wm3::Vec3f BlipProbePosition(ReconBlip* const blip) noexcept
  {
    if (!blip) {
      return {};
    }

    return reinterpret_cast<Entity*>(blip)->PendingPosition;
  }

  [[nodiscard]] bool DoesBlipSourceCollideBox(ReconBlip* const blip, const Wm3::Box3f& box) noexcept
  {
    Unit* const sourceUnit = DecodeBlipSourceUnit(blip);
    if (!sourceUnit) {
      return false;
    }

    EntityCollisionUpdater* const collision = sourceUnit->CollisionExtents;
    if (!collision) {
      return false;
    }

    CollisionPairResult overlap{};
    return collision->CollideBox(&box, &overlap);
  }

  void SeedReconMapFromBlipList(CAiReconDBImpl* const owner)
  {
    if (!owner || owner->mBlipMap.mSize != 0u) {
      return;
    }

    for (ReconBlip* const blip : owner->mBblips) {
      if (!blip) {
        continue;
      }
      InsertMapNode(owner, MakeReconMapKey(DecodeBlipSourceUnit(blip)), blip);
    }
  }

  /**
   * Address: 0x005C7780 (FUN_005C7780)
   *
   * What it does:
   * Grows one recon-blip pointer vector by `appendCount`, filling new entries
   * with null placeholders.
   */
  void GrowBlipPointerVector(msvc8::vector<ReconBlip*>& values, const std::size_t appendCount)
  {
    if (appendCount == 0u) {
      return;
    }
    values.resize(values.size() + appendCount, nullptr);
  }

  /**
   * Address: 0x005C5DF0 (FUN_005C5DF0)
   *
   * What it does:
   * Resizes one recon-blip pointer vector to `targetCount` by truncating tail
   * entries or growing with null placeholders.
   */
  void ResizeBlipPointerVector(msvc8::vector<ReconBlip*>& values, const std::size_t targetCount)
  {
    const std::size_t currentCount = values.size();
    if (targetCount < currentCount) {
      values.erase(values.begin() + static_cast<std::ptrdiff_t>(targetCount), values.end());
      return;
    }

    if (targetCount > currentCount) {
      GrowBlipPointerVector(values, targetCount - currentCount);
    }
  }

  void RebuildBlipListFromMapAndOrphans(CAiReconDBImpl* const owner)
  {
    if (!owner) {
      return;
    }

    const std::size_t targetCount = static_cast<std::size_t>(owner->mBlipMap.mSize) + owner->mTempBlips.size();
    ResizeBlipPointerVector(owner->mBblips, targetCount);

    std::size_t writeIndex = 0u;
    for (ReconMapNodeView* node = MapBegin(owner); node != MapEnd(owner); node = MapNext(node, MapEnd(owner))) {
      if (node->value) {
        owner->mBblips.begin()[writeIndex] = node->value;
        ++writeIndex;
      }
    }

    for (ReconBlip* const orphan : owner->mTempBlips) {
      if (orphan) {
        owner->mBblips.begin()[writeIndex] = orphan;
        ++writeIndex;
      }
    }

    ResizeBlipPointerVector(owner->mBblips, writeIndex);
  }

  void AppendUniqueBlip(msvc8::vector<ReconBlip*>& values, ReconBlip* const blip)
  {
    if (!blip) {
      return;
    }
    if (std::find(values.begin(), values.end(), blip) != values.end()) {
      return;
    }
    values.push_back(blip);
  }

  void ClearPerArmyRecon(
    CAiReconDBImpl* const owner, ReconBlip* const blip, const bool emitIntelEvents
  )
  {
    if (!owner || !owner->mArmy || !blip) {
      return;
    }

    const std::int32_t armyIndex = owner->mArmy->ArmyId;
    PerArmyReconView* const recon = GetPerArmyReconSlot(blip, armyIndex);
    if (!recon) {
      return;
    }

    const int oldFlags = static_cast<int>(recon->mReconFlags);
    if (emitIntelEvents && oldFlags != 0) {
      owner->CheckIntelEvents(blip, oldFlags, 0);
    }
    recon->mNeedsFlush = 0u;
    recon->mReconFlags = 0u;
  }

  /**
   * Address: 0x005C4CA0 (FUN_005C4CA0)
   *
   * What it does:
   * Appends one pending-new-blip request into the temporary generation vector.
   */
  void AppendPendingNewBlip(
    std::vector<CAiReconDBImpl::SNewBlip>& pending,
    Unit* const sourceUnit,
    const std::uint8_t fake,
    const EReconFlags detectedFlags
  )
  {
    pending.push_back(CAiReconDBImpl::SNewBlip{
      .sourceUnit = sourceUnit,
      .fake = fake,
      .detectedFlags = detectedFlags,
    });
  }

  [[nodiscard]] EReconFlags ReconCanDetectEntity(
    const CAiReconDBImpl* const owner, Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags
  )
  {
    return owner ? owner->ReconCanDetect(entity, pos, oldFlags) : RECON_None;
  }

  void TickAllReconGrids(CAiReconDBImpl* const owner, const int dTicks)
  {
    if (!owner) {
      return;
    }

    if (owner->mVisionGrid.px) {
      owner->mVisionGrid.px->Tick(dTicks);
    }
    if (owner->mWaterGrid.px) {
      owner->mWaterGrid.px->Tick(dTicks);
    }
    if (owner->mRadarGrid.px) {
      owner->mRadarGrid.px->Tick(dTicks);
    }
    if (owner->mSonarGrid.px) {
      owner->mSonarGrid.px->Tick(dTicks);
    }
    if (owner->mOmniGrid.px) {
      owner->mOmniGrid.px->Tick(dTicks);
    }
    if (owner->mRCIGrid.px) {
      owner->mRCIGrid.px->Tick(dTicks);
    }
    if (owner->mSCIGrid.px) {
      owner->mSCIGrid.px->Tick(dTicks);
    }
    if (owner->mVCIGrid.px) {
      owner->mVCIGrid.px->Tick(dTicks);
    }
  }
} // namespace

gpg::RType* SReconKey::sType = nullptr;
gpg::RType* CAiReconDBImpl::sType = nullptr;

/**
 * Address: 0x005C0290 (FUN_005C0290, ??0CAiReconDBImpl@Moho@@QAE@XZ)
 *
 * What it does:
 * Builds an empty recon DB instance with no owning army and all recon grids
 * released.
 */
CAiReconDBImpl::CAiReconDBImpl()
  : CAiReconDBImpl(nullptr, false)
{
}

/**
 * Address: 0x005BFF90 (FUN_005BFF90, ??0CAiReconDBImpl@Moho@@QAE@PAVSimArmy@1@_N1@Z)
 */
CAiReconDBImpl::CAiReconDBImpl(CArmyImpl* const army, const bool fogOfWar) :
    mBlipMap{},
    mBblips{},
    mTempBlips{},
    mArmy(army),
    mMapData(nullptr),
    mSim(nullptr),
    mIMap(nullptr),
    mVisionGrid{},
    mWaterGrid{},
    mRadarGrid{},
    mSonarGrid{},
    mOmniGrid{},
    mRCIGrid{},
    mSCIGrid{},
    mVCIGrid{},
    mVisibleToReconCategory{},
    mFogOfWar(static_cast<std::uint8_t>(fogOfWar ? 1u : 0u)),
    mPadA9{0, 0, 0, 0, 0, 0, 0}
{
  mBlipMap.mAllocProxy = nullptr;
  mBlipMap.mHead = AllocateReconMapHeadNode();
  if (auto* const head = reinterpret_cast<ReconMapNodeView*>(mBlipMap.mHead)) {
    head->isNil = 1u;
    head->parent = head;
    head->left = head;
    head->right = head;
  }
  mBlipMap.mSize = 0u;

  if (!mArmy) {
    return;
  }

  mSim = mArmy->GetSim();
  mMapData = mSim ? mSim->mMapData : nullptr;
  mIMap = mArmy->GetIGrid();

  if (mSim && mSim->mRules) {
    const CategoryWordRangeView* const category = mSim->mRules->GetEntityCategory("VISIBLETORECON");
    if (category) {
      mVisibleToReconCategory = *category;
    }
  }

  mRadarGrid = MakeGrid(mMapData, 4);
  mSonarGrid = MakeGrid(mMapData, 4);
  mOmniGrid = MakeGrid(mMapData, 4);
  mRCIGrid = MakeGrid(mMapData, 4);
  mSCIGrid = MakeGrid(mMapData, 4);
  mVCIGrid = MakeGrid(mMapData, 4);

  if (fogOfWar) {
    mVisionGrid = MakeGrid(mMapData, 2);
    mWaterGrid = MakeGrid(mMapData, 4);
  }
}

/**
 * Address: 0x005C2300 (FUN_005C2300, scalar deleting thunk)
 * Address: 0x005C23F0 (FUN_005C23F0, full destructor body)
 */
CAiReconDBImpl::~CAiReconDBImpl()
{
  ClearMap(this);

  mBblips.clear();
  mTempBlips.clear();

  if (mBlipMap.mHead) {
    delete reinterpret_cast<ReconMapNodeView*>(mBlipMap.mHead);
  }
  mBlipMap.mHead = nullptr;
  mBlipMap.mSize = 0u;

  mVCIGrid.release();
  mSCIGrid.release();
  mRCIGrid.release();
  mOmniGrid.release();
  mSonarGrid.release();
  mRadarGrid.release();
  mWaterGrid.release();
  mVisionGrid.release();

  mFogOfWar = 0;
  mArmy = nullptr;
  mMapData = nullptr;
  mSim = nullptr;
  mIMap = nullptr;
}

/**
 * Address: 0x005C0370 (FUN_005C0370, Moho::CAiReconDBImpl::Flush)
 *
 * What it does:
 * Clears per-army recon state for orphan and mapped blips, emits intel-loss
 * notifications, destroys no-longer-used blips, then resets map/list storage.
 */
void CAiReconDBImpl::Flush()
{
  for (ReconBlip* const blip : mTempBlips) {
    if (!blip) {
      continue;
    }
    ClearPerArmyRecon(this, blip, true);
    blip->DestroyIfUnused();
  }
  mTempBlips.clear();

  ReconMapNodeView* const head = MapEnd(this);
  for (ReconMapNodeView* it = MapBegin(this); it != head; it = MapNext(it, head)) {
    ReconBlip* const blip = it->value;
    if (!blip) {
      continue;
    }
    ClearPerArmyRecon(this, blip, true);
    blip->DestroyIfUnused();
  }

  ClearMap(this);
  mBblips.clear();
}

/**
 * Address: 0x005C0C40 (FUN_005C0C40)
 */
void CAiReconDBImpl::ReconTick(const int dTicks)
{
  if (!mArmy || !mSim) {
    TickAllReconGrids(this, dTicks);
    return;
  }

  SeedReconMapFromBlipList(this);
  ReconMapNodeView* const mapHead = MapEnd(this);

  mSim->Logf("ReconTick for army %d: %s [%s]\n", mArmy->ArmyId, mArmy->PlayerName.raw_data_unsafe(), mArmy->ArmyName.raw_data_unsafe());

  for (auto it = mTempBlips.begin(); it != mTempBlips.end();) {
    ReconBlip* const blip = *it;
    const bool shouldDelete = IsViewerAlliedWithBlipArmy(this, blip) ||
      (ReconCanDetectEntity(this, reinterpret_cast<Entity*>(blip), BlipProbePosition(blip), RECON_LOSNow) != RECON_None);
    if (shouldDelete) {
      ClearPerArmyRecon(this, blip, true);
      it = mTempBlips.erase(it);
    } else {
      ++it;
    }
  }

  for (ReconMapNodeView* it = MapBegin(this); it != mapHead;) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, mapHead);

    ReconBlip* const blip = node->value;
    if (!blip) {
      EraseMapNode(this, node);
      continue;
    }

    Unit* sourceUnit = node->key.sourceUnit.GetObjectPtr();
    if (!sourceUnit) {
      sourceUnit = DecodeBlipSourceUnit(blip);
    }

    if (!sourceUnit || sourceUnit->DestroyQueued()) {
      if (!IsFakeBlip(blip)) {
        ClearPerArmyRecon(this, blip, true);
      } else {
        const bool shouldDeleteFake = IsViewerAlliedWithBlipArmy(this, blip) ||
          (ReconCanDetectEntity(this, reinterpret_cast<Entity*>(blip), BlipProbePosition(blip), RECON_LOSNow) != RECON_None);
        if (shouldDeleteFake) {
          ClearPerArmyRecon(this, blip, true);
        } else {
          PerArmyReconView* const recon = GetPerArmyReconSlot(blip, mArmy->ArmyId);
          if (recon) {
            recon->mReconFlags |= static_cast<std::uint32_t>(RECON_MaybeDead);
          }
          AppendUniqueBlip(mTempBlips, blip);
        }
      }

      EraseMapNode(this, node);
      continue;
    }
  }

  std::vector<SNewBlip> pendingNewBlips{};
  if (mSim->mEntityDB) {
    for (Entity* const entity : mSim->mEntityDB->Entities()) {
      Unit* const unit = entity ? entity->IsUnit() : nullptr;
      if (!unit || unit->DestroyQueued()) {
        continue;
      }
      if (!unit->BluePrint) {
        continue;
      }
      if (IsAlliedOrSameArmy(mArmy, unit->ArmyRef)) {
        continue;
      }
      if (!mVisibleToReconCategory.ContainsBit(unit->BluePrint->mCategoryBitIndex)) {
        continue;
      }

      const EReconFlags detectFlags = ReconCanDetectEntity(this, unit, unit->GetPositionWm3(), RECON_AnySense);
      auto [rangeBegin, rangeEnd] = FindReconBlipRange(this, unit);
      if (detectFlags != RECON_None) {
        if (rangeBegin == rangeEnd) {
          AppendPendingNewBlip(pendingNewBlips, unit, 0u, detectFlags);
        } else {
          UpdateBlips(unit, detectFlags, pendingNewBlips);
        }
        continue;
      }

      if (rangeBegin != rangeEnd) {
        bool keepStaticLosBlip = false;
        PerArmyReconView* const recon = GetPerArmyReconSlot(rangeBegin->value, mArmy->ArmyId);
        if (recon && (recon->mReconFlags & static_cast<std::uint32_t>(RECON_LOSEver)) != 0u && !unit->IsMobile()) {
          keepStaticLosBlip = true;
        }

        if (keepStaticLosBlip) {
          UpdateBlips(unit, RECON_None, pendingNewBlips);
        } else {
          DeleteBlips(unit);
        }
      }
    }
  }

  GenerateNewBlips(pendingNewBlips);
  RebuildBlipListFromMapAndOrphans(this);
  TickAllReconGrids(this, dTicks);
}

/**
 * Address: 0x005C14E0 (FUN_005C14E0)
 *
 * Moho::CAiReconDBImpl::ReconRefresh()
 *
 * IDA signature:
 * _DWORD *__thiscall Moho::CAiReconDBImpl::ReconRefresh(Moho::CAiReconDBImpl *this)
 *
 * What it does:
 * Iterates current recon blips and refreshes per-army cached recon fields
 * from each live source unit.
 */
void CAiReconDBImpl::ReconRefresh()
{
  ReconMapNodeView* const head = MapEnd(this);
  for (ReconMapNodeView* it = MapBegin(this); it != head;) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, head);

    ReconBlip* const blip = node->value;
    if (!blip) {
      continue;
    }

    Unit* const sourceUnit = DecodeBlipSourceUnit(blip);
    if (!sourceUnit || sourceUnit->DestroyQueued()) {
      continue;
    }

    RefreshBlip(blip, sourceUnit);
  }
}

/**
 * Address: 0x005C07E0 (FUN_005C07E0, Moho::CAiReconDBImpl::CheckEvent)
 *
 * ReconBlip *, int, EReconFlags
 *
 * IDA signature:
 * void Moho::CAiReconDBImpl::CheckEvent(
 *   Moho::CAiReconDBImpl *this,
 *   Moho::ReconBlip *blip,
 *   Moho::EReconFlags newFlags,
 *   Moho::EReconFlags changedFlag);
 *
 * What it does:
 * Emits one `OnIntelChange` script event for a single changed recon lane.
 */
void CAiReconDBImpl::CheckEvent(ReconBlip* const blip, const int newFlags, const EReconFlags changedFlag)
{
  if (!mArmy || !blip) {
    return;
  }

  CAiBrain* const brain = mArmy->GetArmyBrain();
  if (!brain) {
    return;
  }

  const bool gained = (newFlags & static_cast<int>(changedFlag)) != 0;
  brain->RunScriptOnIntelChange(blip, ReconSenseLexical(changedFlag), gained);
}

/**
 * Address: 0x005C0890 (FUN_005C0890, Moho::CAiReconDBImpl::CheckIntelEvents)
 *
 * ReconBlip *, int, int
 *
 * IDA signature:
 * void __userpurge Moho::CAiReconDBImpl::CheckIntelEvents(
 *   Moho::CAiReconDBImpl *this,
 *   Moho::ReconBlip *blip,
 *   Moho::EReconFlags newFlags,
 *   Moho::EReconFlags oldFlags);
 *
 * What it does:
 * Diffs old/new recon masks and emits lane-specific intel-change callbacks.
 */
void CAiReconDBImpl::CheckIntelEvents(ReconBlip* const blip, const int oldFlags, const int newFlags)
{
  if (oldFlags == newFlags) {
    return;
  }

  const int diff = oldFlags ^ newFlags;
  if ((diff & static_cast<int>(RECON_LOSNow)) != 0) {
    CheckEvent(blip, newFlags, RECON_LOSNow);
  }
  if ((diff & static_cast<int>(RECON_Radar)) != 0) {
    CheckEvent(blip, newFlags, RECON_Radar);
  }
  if ((diff & static_cast<int>(RECON_Sonar)) != 0) {
    CheckEvent(blip, newFlags, RECON_Sonar);
  }
  if ((diff & static_cast<int>(RECON_Omni)) != 0) {
    CheckEvent(blip, newFlags, RECON_Omni);
  }
}

/**
 * Address: 0x005C0A70 (FUN_005C0A70, Moho::CAiReconDBImpl::GenerateNewBlips)
 *
 * std::vector<SNewBlip> const &
 *
 * What it does:
 * Materializes pending blips, updates per-army blip state, and inserts them
 * into the recon blip map.
 */
void CAiReconDBImpl::GenerateNewBlips(const std::vector<SNewBlip>& pending)
{
  for (const SNewBlip& candidate : pending) {
    ReconBlip* const blip = FindOrCreateBlip(candidate);
    if (!blip) {
      continue;
    }

    UpdateBlip(blip, candidate.sourceUnit, static_cast<std::uint32_t>(candidate.detectedFlags));
    InsertMapNode(this, MakeReconMapKey(candidate.sourceUnit), blip);
  }
}

/**
 * Address: 0x005C0930 (FUN_005C0930)
 */
ReconBlip* CAiReconDBImpl::FindOrCreateBlip(const SNewBlip& candidate)
{
  Unit* const sourceUnit = candidate.sourceUnit;
  if (!mArmy || !sourceUnit) {
    return nullptr;
  }

  const std::int32_t armyIndex = mArmy->ArmyId;
  if (armyIndex < 0) {
    return nullptr;
  }

  const bool wantFake = candidate.fake != 0u;
  for (ReconBlip* const existing : sourceUnit->mReconBlips) {
    if (!existing) {
      continue;
    }

    PerArmyReconView* const perArmy = existing->GetPerArmyReconInfo(armyIndex);
    if (!perArmy || perArmy->mNeedsFlush != 0u) {
      continue;
    }

    if (existing->IsFake() == wantFake) {
      perArmy->mNeedsFlush = 1u;
      return existing;
    }
  }

  ReconBlip* const created = new (std::nothrow) ReconBlip(sourceUnit, mSim, wantFake);
  if (!created) {
    return nullptr;
  }

  sourceUnit->mReconBlips.push_back(created);
  if (PerArmyReconView* const perArmy = created->GetPerArmyReconInfo(armyIndex)) {
    perArmy->mNeedsFlush = 1u;
  }
  return created;
}

/**
 * Address: 0x005C1B90 (FUN_005C1B90)
 */
void CAiReconDBImpl::RefreshBlip(ReconBlip* const blip, Unit* const sourceUnit)
{
  if (!mArmy || !blip || !sourceUnit || blip->IsFake()) {
    return;
  }

  const std::int32_t armyIndex = mArmy->ArmyId;
  if (armyIndex < 0) {
    return;
  }

  PerArmyReconView* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  if ((perArmy->mReconFlags & static_cast<std::uint32_t>(RECON_LOSNow)) != 0u) {
    perArmy->mMeshTypeClassId = sourceUnit->mMeshTypeClassId;
    perArmy->mHealth = sourceUnit->Health;
    perArmy->mMaxHealth = sourceUnit->MaxHealth;
    perArmy->mFractionComplete = sourceUnit->FractionCompleted;
  }

  if ((perArmy->mReconFlags & static_cast<std::uint32_t>(RECON_AnySense)) != 0u) {
    perArmy->mMaybeDead = static_cast<std::uint8_t>(sourceUnit->IsDead() ? 1u : 0u);
  }
}

/**
 * Address: 0x005C1CF0 (FUN_005C1CF0)
 */
void CAiReconDBImpl::UpdateBlip(ReconBlip* const blip, Unit* const sourceUnit, std::uint32_t newFlags)
{
  if (!mArmy || !blip) {
    return;
  }

  const std::int32_t armyIndex = mArmy->ArmyId;
  PerArmyReconView* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  Sim* const sim = mArmy->GetSim();
  const std::uint32_t blipId = static_cast<std::uint32_t>(blip->id_);

  if (sim) {
    sim->Logf("  UpdateBlip(blip=0x%08x):\n", blipId);
    std::uint32_t checksumTag = 4u;
    sim->mContext.Update(&checksumTag, sizeof(checksumTag));
    checksumTag = blipId;
    sim->mContext.Update(&checksumTag, sizeof(checksumTag));
  }

  const std::uint32_t oldFlags = perArmy->mReconFlags;
  if (blip->IsFake()) {
    Entity* const sourceEntity = sourceUnit ? static_cast<Entity*>(sourceUnit) : nullptr;
    newFlags = static_cast<std::uint32_t>(ReconCanDetectEntity(this, sourceEntity, blip->Position, RECON_AnySense));
  }

  newFlags |= (oldFlags & 0x30u);

  if (sim) {
    sim->Logf("    newflags=0x%08x\n", newFlags);
    sim->mContext.Update(&newFlags, sizeof(newFlags));
  }

  if ((newFlags & static_cast<std::uint32_t>(RECON_LOSNow)) != 0u && sourceUnit) {
    const std::string customName = sourceUnit->GetCustomName();
    blip->mUnitVarDat.mCustomName.assign(customName.c_str(), customName.size());
    newFlags |= static_cast<std::uint32_t>(RECON_LOSEver);
    if (blip->IsFake()) {
      newFlags |= static_cast<std::uint32_t>(RECON_KnownFake);
    }
  }

  if (blip->IsFake()) {
    bool markKnownFake = false;
    if ((newFlags & static_cast<std::uint32_t>(RECON_Omni)) != 0u) {
      markKnownFake = true;
    } else if (!sourceUnit) {
      markKnownFake = true;
    } else if (IsAlliedOrSameArmy(mArmy, sourceUnit->ArmyRef)) {
      markKnownFake = true;
    } else {
      const SFootprint& footprint = sourceUnit->GetFootprint();
      const float maxFootprint = static_cast<float>(std::max(footprint.mSizeX, footprint.mSizeZ));
      STIMap* const map = sourceUnit->SimulationRef ? sourceUnit->SimulationRef->mMapData : nullptr;
      const bool useWholeMap = mArmy->UseWholeMap();
      if (!IsWithinPlayableMapRadius(map, blip->Position, maxFootprint, useWholeMap)) {
        markKnownFake = true;
      }
    }

    if (markKnownFake) {
      newFlags |= static_cast<std::uint32_t>(RECON_KnownFake);
    }
  }

  perArmy->mReconFlags = newFlags;
  RefreshBlip(blip, sourceUnit);

  const std::uint32_t refreshedFlags = perArmy->mReconFlags;
  if (sim) {
    sim->Logf("    mReconFlags=0x%08x [second]\n", refreshedFlags);
    sim->mContext.Update(&refreshedFlags, sizeof(refreshedFlags));
  }

  if (mIMap) {
    mIMap->UpdateBlipPosition(
      static_cast<std::uint32_t>(blip->id_), blip->Position, static_cast<const RUnitBlueprint*>(blip->GetBlueprint())
    );
  }
  CheckIntelEvents(blip, static_cast<int>(oldFlags), static_cast<int>(refreshedFlags));
}

/**
 * Address: 0x005C1F80 (FUN_005C1F80, Moho::CAiReconDBImpl::UpdateBlips)
 *
 * Unit *, EReconFlags, std::vector<SNewBlip> &
 *
 * IDA signature:
 * void __thiscall Moho::CAiReconDBImpl::UpdateBlips(
 *   Moho::CAiReconDBImpl *this,
 *   ... range-pair ...,
 *   Moho::Unit *unit,
 *   unsigned int detectFlags,
 *   std::vector<Moho::CAiReconDBImpl::SNewBlip> *);
 *
 * What it does:
 * Updates all map-owned blips for one source unit, prunes excess fake jammer
 * blips, and enqueues pending fake blips when jammer count increased.
 */
void CAiReconDBImpl::UpdateBlips(
  Unit* const sourceUnit, const EReconFlags detectedFlags, std::vector<CAiReconDBImpl::SNewBlip>& pending
)
{
  if (!sourceUnit) {
    return;
  }

  auto [it, end] = FindReconBlipRange(this, sourceUnit);
  if (it == end) {
    return;
  }

  const std::int32_t requiredFakeBlips = std::max(0, GetActiveJammerBlipCount(sourceUnit));
  std::int32_t refreshedFakeBlips = 0;

  ReconMapNodeView* const head = MapEnd(this);
  while (it != end) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, head);

    ReconBlip* const blip = node->value;
    if (!blip) {
      EraseMapNode(this, node);
      continue;
    }

    if (IsFakeBlip(blip)) {
      if (refreshedFakeBlips >= requiredFakeBlips) {
        DeleteBlip(blip);
        EraseMapNode(this, node);
        continue;
      }

      UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
      ++refreshedFakeBlips;
      continue;
    }

    UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
  }

  while (refreshedFakeBlips < requiredFakeBlips) {
    AppendPendingNewBlip(pending, sourceUnit, 1u, detectedFlags);
    ++refreshedFakeBlips;
  }
}

/**
 * Address: 0x005C21F0 (FUN_005C21F0)
 */
void CAiReconDBImpl::DeleteBlip(ReconBlip* const blip)
{
  if (!mArmy || !blip) {
    return;
  }

  const std::int32_t armyIndex = mArmy->ArmyId;
  PerArmyReconView* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  const int oldFlags = static_cast<int>(perArmy->mReconFlags);
  CheckIntelEvents(blip, oldFlags, 0);
  perArmy->mNeedsFlush = 0u;
  perArmy->mReconFlags = 0u;
  blip->DestroyIfUnused();
}

/**
 * Address: 0x005C2230 (FUN_005C2230, Moho::CAiReconDBImpl::DeleteBlips)
 *
 * Unit *
 *
 * IDA signature:
 * void __thiscall Moho::CAiReconDBImpl::DeleteBlips(
 *   Moho::CAiReconDBImpl *this,
 *   ... range-pair ...);
 *
 * What it does:
 * Clears this army's recon state for all map blips from one source unit and
 * removes that source's range from the typed recon map.
 */
void CAiReconDBImpl::DeleteBlips(Unit* const sourceUnit)
{
  if (!sourceUnit) {
    return;
  }

  auto [it, end] = FindReconBlipRange(this, sourceUnit);
  ReconMapNodeView* const head = MapEnd(this);
  while (it != end) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, head);

    ReconBlip* const blip = node->value;
    if (blip) {
      DeleteBlip(blip);
    }
    EraseMapNode(this, node);
  }
}

/**
 * Address: 0x005CB360 (FUN_005CB360, Moho::CAiReconDBImpl::GetNewReconFor)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::GetNewReconFor@<eax>(
 *   Wm3::Vector3f *pos@<eax>,
 *   Moho::Entity *entity@<ecx>,
 *   Moho::CAiReconDBImpl *this,
 *   Moho::EReconFlags oldFlags,
 *   bool belowWater);
 *
 * What it does:
 * Computes one-army point recon senses (LOS/radar/sonar/omni) before
 * counter-intel suppression.
 */
EReconFlags CAiReconDBImpl::GetNewReconFor(
  Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags, const bool belowWater
) const
{
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  ReconBlip* const blip = (entity && !unit) ? entity->IsReconBlip() : nullptr;

  EReconFlags detected = RECON_None;
  if (mFogOfWar == 0 || mVisionGrid.px == nullptr) {
    detected = RECON_LOSNow;
  } else if (HasFlag(oldFlags, RECON_LOSNow)) {
    const CIntelGrid* const losGrid = belowWater ? mWaterGrid.px : mVisionGrid.px;
    if (IsGridVisibleAtPoint(losGrid, pos)) {
      detected = RECON_LOSNow;
    }
  }

  bool sonarEligible = belowWater;
  if (unit) {
    sonarEligible = sonarEligible || UsesWaterSenseLane(unit->mCurrentLayer);
  } else if (blip) {
    sonarEligible = sonarEligible || UsesWaterSenseLane(blip->mCurrentLayer);
  }

  if (sonarEligible && HasFlag(oldFlags, RECON_Sonar) && IsGridVisibleAtPoint(mSonarGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Sonar);
  }

  if (!belowWater && HasFlag(oldFlags, RECON_Radar) && IsGridVisibleAtPoint(mRadarGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Radar);
  }

  if (HasFlag(oldFlags, RECON_Omni) && IsGridVisibleAtPoint(mOmniGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Omni);
  }

  return detected;
}

/**
 * Address: 0x005CB460 (FUN_005CB460, Moho::CAiReconDBImpl::ApplyReconCounters)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags
 *
 * IDA signature:
 * unsigned int __userpurge Moho::CAiReconDBImpl::ApplyReconCounters@<eax>(
 *   Wm3::Vector3f *pos@<eax>,
 *   Moho::Entity *entity@<ecx>,
 *   Moho::CAiReconDBImpl *this,
 *   Moho::EReconFlags flags);
 *
 * What it does:
 * Applies point counter-intel and stealth/counter-stealth suppression to
 * raw recon flags.
 */
EReconFlags CAiReconDBImpl::ApplyReconCounters(Entity* const entity, const Wm3::Vec3f& pos, EReconFlags flags) const
{
  Unit* const unit = entity ? entity->IsUnit() : nullptr;

  if (HasFlag(flags, RECON_Omni)) {
    return flags;
  }

  const CIntel* const intel = unit ? unit->GetIntelManager() : nullptr;
  const bool activeCloak = intel && intel->mCloak.present != 0u && intel->mCloak.enabled != 0u;

  if (IsGridVisibleAtPoint(mRCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_Radar);
  }
  if (IsGridVisibleAtPoint(mSCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_Sonar);
  }

  if (activeCloak || IsGridVisibleAtPoint(mVCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_LOSNow);
  }

  if (intel && !HasFlag(flags, RECON_LOSNow)) {
    if (intel->mRadarStealth.present != 0u && intel->mRadarStealth.enabled != 0u) {
      flags = ClearFlag(flags, RECON_Radar);
    }
    if (intel->mSonarStealth.present != 0u && intel->mSonarStealth.enabled != 0u) {
      flags = ClearFlag(flags, RECON_Sonar);
    }
  }

  return flags;
}

/**
 * Address: 0x005C9600 (FUN_005C9600, Moho::CAiReconDBImpl::GetReconFlags)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::GetReconFlags@<eax>(
 *   Moho::CAiReconDBImpl *this@<ebx>,
 *   Moho::Entity *entity,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags,
 *   bool belowWater);
 *
 * What it does:
 * Merges point recon senses from this army and allied recon DBs, then
 * applies point counter-intel filtering.
 */
EReconFlags CAiReconDBImpl::GetReconFlags(
  Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags, const bool belowWater
) const
{
  EReconFlags combined = GetNewReconFor(entity, pos, oldFlags, belowWater);

  if (mSim && mArmy && mArmy->ArmyId >= 0) {
    const std::uint32_t viewerArmyId = static_cast<std::uint32_t>(mArmy->ArmyId);
    const std::size_t armyCount = mSim->mArmiesList.size();
    for (std::size_t i = 0; i < armyCount; ++i) {
      CArmyImpl* const allyArmy = mSim->mArmiesList[i];
      if (!allyArmy || !allyArmy->Allies.Contains(viewerArmyId)) {
        continue;
      }

      CAiReconDBImpl* const allyReconDb = allyArmy->GetReconDB();
      if (!allyReconDb) {
        continue;
      }

      combined = MergeFlags(combined, allyReconDb->GetNewReconFor(entity, pos, oldFlags, belowWater));
    }
  }

  if (combined == RECON_None) {
    return RECON_None;
  }

  return ApplyReconCounters(entity, pos, combined);
}

/**
 * Address: 0x005C9720 (FUN_005C9720, sub_5C9720)
 *
 * gpg::Rect2<int> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __stdcall sub_5C9720(
 *   Moho::CAiReconDBImpl *this,
 *   gpg::Rect2i *rect,
 *   Moho::EReconFlags oldFlags,
 *   bool underwater);
 *
 * What it does:
 * Merges rectangle recon detection across this army and allied recon DBs, then
 * applies rectangle counter-intel filtering.
 */
EReconFlags CAiReconDBImpl::GetReconFlagsForRect(
  const moho::Rect2<int>& rect, const EReconFlags oldFlags, const bool isUnderwater
) const
{
  EReconFlags combined = GetDetection(rect, oldFlags, isUnderwater);

  if (mSim && mArmy && mArmy->ArmyId >= 0) {
    const std::uint32_t viewerArmyId = static_cast<std::uint32_t>(mArmy->ArmyId);
    const std::size_t armyCount = mSim->mArmiesList.size();
    for (std::size_t i = 0; i < armyCount; ++i) {
      CArmyImpl* const allyArmy = mSim->mArmiesList[i];
      if (!allyArmy || !allyArmy->Allies.Contains(viewerArmyId)) {
        continue;
      }

      CAiReconDBImpl* const allyReconDb = allyArmy->GetReconDB();
      if (!allyReconDb) {
        continue;
      }

      combined = MergeFlags(combined, allyReconDb->GetDetection(rect, oldFlags, isUnderwater));
    }
  }

  if (combined == RECON_None) {
    return RECON_None;
  }

  return DoCounterDetection(rect, combined);
}

/**
 * Address: 0x005CB520 (FUN_005CB520, Moho::CAiReconDBImpl::GetDetection)
 *
 * gpg::Rect2<int> const &, EReconFlags, bool
 *
 * IDA signature:
 * int __userpurge Moho::CAiReconDBImpl::GetDetection@<eax>(
 *   Moho::CAiReconDBImpl *this@<edx>,
 *   gpg::Rect2i *rect@<ecx>,
 *   Moho::EReconFlags_8 oldFlags,
 *   bool isUnderwater@<al>);
 *
 * What it does:
 * Computes direct recon senses (LOS/radar/sonar/omni) for this army over one
 * world-space rectangle.
 */
EReconFlags CAiReconDBImpl::GetDetection(
  const moho::Rect2<int>& rect, const EReconFlags oldFlags, const bool isUnderwater
) const
{
  EReconFlags detected = RECON_None;

  if (mFogOfWar == 0 || mVisionGrid.px == nullptr) {
    detected = RECON_LOSNow;
  } else if (HasFlag(oldFlags, RECON_LOSNow)) {
    if (isUnderwater) {
      if (mWaterGrid.px && mWaterGrid.px->IsVisible(rect)) {
        detected = RECON_LOSNow;
      }
    } else if (mVisionGrid.px->IsVisible(rect)) {
      detected = RECON_LOSNow;
    }
  }

  const EReconFlags pingSense = isUnderwater ? RECON_Sonar : RECON_Radar;
  const CIntelGrid* const pingGrid = isUnderwater ? mSonarGrid.px : mRadarGrid.px;
  if (HasFlag(oldFlags, pingSense) && pingGrid && pingGrid->IsVisible(rect)) {
    detected = MergeFlags(detected, pingSense);
  }

  if (HasFlag(oldFlags, RECON_Omni) && mOmniGrid.px && mOmniGrid.px->IsVisible(rect)) {
    detected = MergeFlags(detected, RECON_Omni);
  }

  return detected;
}

/**
 * Address: 0x005CB600 (FUN_005CB600, Moho::CAiReconDBImpl::DoCounterDetection)
 *
 * gpg::Rect2<int> const &, EReconFlags
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::DoCounterDetection@<eax>(
 *   Moho::CAiReconDBImpl *this,
 *   gpg::Rect2i *rect@<ebx>,
 *   Moho::EReconFlags flags);
 *
 * What it does:
 * Clears recon senses suppressed by active counter-intel grids.
 */
EReconFlags CAiReconDBImpl::DoCounterDetection(const moho::Rect2<int>& rect, EReconFlags flags) const
{
  if (HasFlag(flags, RECON_Omni)) {
    return flags;
  }

  if (mRCIGrid.px && mRCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_Radar);
  }
  if (mSCIGrid.px && mSCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_Sonar);
  }
  if (mVCIGrid.px && mVCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_LOSNow);
  }
  return flags;
}

/**
 * Address: 0x005C18A0 (FUN_005C18A0, Moho::CAiReconDBImpl::ReconCanDetect)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const moho::Rect2<int>& rect, const float y, const int oldFlags) const
{
  const EReconFlags senseMask = static_cast<EReconFlags>(oldFlags);
  const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
  const bool isUnderwater = waterElevation > y;
  return GetReconFlagsForRect(rect, senseMask, isUnderwater);
}

/**
 * Address: 0x005C18F0 (FUN_005C18F0, Moho::CAiReconDBImpl::ReconCanDetect)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags
 *
 * IDA signature:
 * unsigned int __userpurge Moho::CAiReconDBImpl::ReconCanDetect@<eax>(
 *   Moho::Entity *ent@<edi>,
 *   Moho::CAiReconDBImpl *this@<esi>,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags);
 *
 * What it does:
 * Applies map/alliance/layer gates for one entity probe, then resolves
 * point recon flags through `GetReconFlags`.
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(
  Entity* const ent, const Wm3::Vec3f& pos, const EReconFlags oldFlags
) const
{
  if (!ent) {
    const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
    const bool belowWater = waterElevation > pos.y;
    return GetReconFlags(nullptr, pos, oldFlags, belowWater);
  }

  if (mMapData && mArmy) {
    const bool useWholeMap = mArmy->UseWholeMap();
    if (!IsWithinPlayableMapRadius(mMapData, pos, 0.0f, useWholeMap)) {
      return RECON_None;
    }
  }

  if (IsAlliedOrSameArmy(mArmy, ent->ArmyRef)) {
    return oldFlags;
  }

  const bool belowWater = ent->mCurrentLayer == LAYER_Seabed || ent->mCurrentLayer == LAYER_Sub;
  return GetReconFlags(ent, pos, oldFlags, belowWater);
}

/**
 * Address: 0x005C1810 (FUN_005C1810, Moho::CAiReconDBImpl::IntelConfirmDead)
 *
 * ReconBlip *
 *
 * IDA signature:
 * bool __usercall Moho::CAiReconDBImpl::IntelConfirmDead@<al>(
 *   Moho::ReconBlip *blip@<eax>, Moho::CAiReconDBImpl *this@<ecx>);
 *
 * What it does:
 * Confirms dead-state visibility when the blip is allied or currently
 * detectable via LOS at its probe position.
 */
bool CAiReconDBImpl::IntelConfirmDead(ReconBlip* const blip)
{
  if (!blip) {
    return false;
  }

  auto* const entity = reinterpret_cast<Entity*>(blip);
  if (IsAlliedOrSameArmy(mArmy, entity->ArmyRef)) {
    return true;
  }

  return ReconCanDetect(entity, entity->GetPositionWm3(), RECON_LOSNow) != RECON_None;
}

/**
 * Address: 0x005C1850 (FUN_005C1850, Moho::CAiReconDBImpl::ReconCanDetect)
 *
 * Wm3::Vector3<float> const &, int
 *
 * IDA signature:
 * Moho::EReconFlags __thiscall Moho::CAiReconDBImpl::ReconCanDetect(
 *   Moho::CAiReconDBImpl *this,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const Wm3::Vec3f& pos, const int oldFlags) const
{
  const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
  const bool belowWater = waterElevation > pos.y;
  return GetReconFlags(nullptr, pos, static_cast<EReconFlags>(oldFlags), belowWater);
}

/**
 * Address: 0x005C1720 (FUN_005C1720)
 *
 * What it does:
 * Appends blips whose source-unit collision primitive overlaps `box`.
 */
void CAiReconDBImpl::ReconGetBlips(const Wm3::Box3<float>& box, gpg::core::FastVector<Entity*>* const outBlips) const
{
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    if (DoesBlipSourceCollideBox(blip, box)) {
      outBlips->PushBack(reinterpret_cast<Entity*>(blip));
    }
  }
}

/**
 * Address: 0x005C1640 (FUN_005C1640)
 *
 * What it does:
 * Appends blips whose world position is inside a sphere centered at `center`
 * with radius `radius` (3D distance check, no output clear).
 */
void CAiReconDBImpl::ReconGetBlips(
  const Wm3::Vec3f& center, const float radius, gpg::core::FastVector<Entity*>* const outBlips
) const
{
  const float radiusSquared = radius * radius;
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    auto* const entity = reinterpret_cast<Entity*>(blip);
    const Wm3::Vec3f& pos = entity->GetPositionWm3();
    const float dx = pos.x - center.x;
    const float dy = pos.y - center.y;
    const float dz = pos.z - center.z;
    if ((dx * dx) + (dy * dy) + (dz * dz) <= radiusSquared) {
      outBlips->PushBack(entity);
    }
  }
}

/**
 * Address: 0x005C1590 (FUN_005C1590)
 *
 * What it does:
 * Returns the per-army current blip list container by reference.
 */
const msvc8::vector<ReconBlip*>& CAiReconDBImpl::ReconGetBlips() const
{
  return mBblips;
}

/**
 * Address: 0x005C1A10 (FUN_005C1A10)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetVisionGrid() const
{
  return mVisionGrid.clone_retained();
}

/**
 * Address: 0x005C1A40 (FUN_005C1A40)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetWaterGrid() const
{
  return mWaterGrid.clone_retained();
}

/**
 * Address: 0x005C1A70 (FUN_005C1A70)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetRadarGrid() const
{
  return mRadarGrid.clone_retained();
}

/**
 * Address: 0x005C1AA0 (FUN_005C1AA0)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetSonarGrid() const
{
  return mSonarGrid.clone_retained();
}

/**
 * Address: 0x005C1AD0 (FUN_005C1AD0)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetOmniGrid() const
{
  return mOmniGrid.clone_retained();
}

/**
 * Address: 0x005C1B00 (FUN_005C1B00)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetRCIGrid() const
{
  return mRCIGrid.clone_retained();
}

/**
 * Address: 0x005C1B30 (FUN_005C1B30)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetSCIGrid() const
{
  return mSCIGrid.clone_retained();
}

/**
 * Address: 0x005C1B60 (FUN_005C1B60)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetVCIGrid() const
{
  return mVCIGrid.clone_retained();
}

/**
 * Address: 0x005C08F0 (FUN_005C08F0)
 *
 * What it does:
 * Updates `mFogOfWar` only when a vision grid exists.
 */
void CAiReconDBImpl::ReconSetFogOfWar(const bool enabled)
{
  if (mVisionGrid.px) {
    mFogOfWar = static_cast<std::uint8_t>(enabled ? 1u : 0u);
  }
}

/**
 * Address: 0x005C0910 (FUN_005C0910)
 *
 * What it does:
 * Returns true when fog-of-war mode is enabled and vision grid storage exists.
 */
bool CAiReconDBImpl::ReconGetFogOfWar() const
{
  return mFogOfWar != 0 && mVisionGrid.px != nullptr;
}

/**
 * Address: 0x005C29C0 (FUN_005C29C0, nullsub_1553)
 *
 * What it does:
 * Intentionally empty hook (binary no-op).
 */
void CAiReconDBImpl::UpdateSimChecksum() {}

/**
 * Address: 0x005C15A0 (FUN_005C15A0)
 *
 * What it does:
 * Returns one recon blip entry for `unit` by lower-bound lookup in the typed
 * recon map; returns `nullptr` when lookup resolves to map-end sentinel.
 */
ReconBlip* CAiReconDBImpl::ReconGetBlip(Unit* const unit) const
{
  if (!unit) {
    return nullptr;
  }

  auto* const owner = const_cast<CAiReconDBImpl*>(this);
  ReconMapNodeView* const node = LowerBoundByEntityId(owner, static_cast<std::uint32_t>(unit->id_));
  return (node && node != MapEnd(this)) ? node->value : nullptr;
}

/**
 * Address: 0x005C20C0 (FUN_005C20C0)
 *
 * What it does:
 * Returns non-fake recon blips for one source unit while holding a weak-link
 * guard on the source object during map traversal.
 */
EntitySetTemplate<Entity> CAiReconDBImpl::ReconGetJamingBlips(Unit* const unit)
{
  EntitySetTemplate<Entity> out{};
  if (!unit || unit->DestroyQueued() || !mArmy) {
    return out;
  }

  WeakObject::ScopedWeakLinkGuard sourceGuard(static_cast<WeakObject*>(static_cast<CScriptObject*>(unit)));

  SeedReconMapFromBlipList(this);
  auto [it, end] = FindReconBlipRange(this, unit);
  while (it != end) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, MapEnd(this));

    ReconBlip* const blip = node->value;
    if (!blip) {
      continue;
    }

    PerArmyReconView* const recon = GetPerArmyReconSlot(blip, mArmy->ArmyId);
    if (recon && (recon->mReconFlags & static_cast<std::uint32_t>(RECON_KnownFake)) == 0u) {
      out.Add(reinterpret_cast<Entity*>(blip));
    }
  }
  return out;
}

/**
 * Address: 0x005C05A0 (FUN_005C05A0)
 */
void CAiReconDBImpl::ReconFlushBlipsInRect(const moho::Rect2<int>& rect)
{
  SeedReconMapFromBlipList(this);

  for (auto it = mTempBlips.begin(); it != mTempBlips.end();) {
    ReconBlip* const blip = *it;
    auto* const entity = reinterpret_cast<Entity*>(blip);
    if (entity && IsInsideRectXZ(rect, entity->GetPositionWm3())) {
      ClearPerArmyRecon(this, blip, true);
      it = mTempBlips.erase(it);
    } else {
      ++it;
    }
  }

  ReconMapNodeView* const head = MapEnd(this);
  for (ReconMapNodeView* it = MapBegin(this); it != head;) {
    ReconMapNodeView* const node = it;
    it = MapNext(node, MapEnd(this));

    ReconBlip* const blip = node->value;
    auto* const entity = reinterpret_cast<Entity*>(blip);
    if (!entity || !IsInsideRectXZ(rect, entity->GetPositionWm3())) {
      continue;
    }

    const ELayer layer = entity->mCurrentLayer;
    if (layer == LAYER_None || layer == LAYER_Sub) {
      continue;
    }

    ClearPerArmyRecon(this, blip, true);
    EraseMapNode(this, node);
  }

  RebuildBlipListFromMapAndOrphans(this);
}

/**
 * Address: 0x005C36A0 (FUN_005C36A0, ??2CAiReconDBImpl@Moho@@QAE@@Z)
 */
CAiReconDBImpl* CAiReconDBImpl::Create(CArmyImpl* const army, const bool fogOfWar)
{
  return new CAiReconDBImpl(army, fogOfWar);
}

boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::MakeGrid(STIMap* const map, const std::uint32_t gridSize)
{
  if (!map) {
    return {};
  }

  auto* const grid = new CIntelGrid(map, gridSize);
  return boost::SharedPtrRaw<CIntelGrid>::with_deleter(grid, [](CIntelGrid* const ptr) { delete ptr; });
}
