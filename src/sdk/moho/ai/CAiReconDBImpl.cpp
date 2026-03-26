#include "moho/ai/CAiReconDBImpl.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "moho/ai/CAiBrain.h"
#include "moho/entity/EntityDb.h"
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

  [[nodiscard]] ReconMapNodeView* AllocateReconMapHeadNode()
  {
    auto* const head = new ReconMapNodeView{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = kNodeColorBlack;
    head->isNil = 1u;
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

  [[nodiscard]] ReconMapNodeView* TreeMin(ReconMapNodeView* node, ReconMapNodeView* const head) noexcept
  {
    while (!IsNil(node->left)) {
      node = node->left;
    }
    return node ? node : head;
  }

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

  void UnlinkKeyFromSourceChain(SReconKey& key) noexcept
  {
    key.sourceUnit.UnlinkFromOwnerChain();
  }

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

  [[nodiscard]] ReconMapNodeView* InsertMapNode(CAiReconDBImpl* const owner, const SReconKey& key, ReconBlip* const value)
  {
    auto* const head = MapHead(owner);
    if (!head) {
      return nullptr;
    }

    ReconMapNodeView* parent = head;
    ReconMapNodeView* cursor = head->parent;
    bool insertLeft = true;
    while (!IsNil(cursor)) {
      parent = cursor;
      if (key.sourceEntityId < cursor->key.sourceEntityId) {
        insertLeft = true;
        cursor = cursor->left;
      } else {
        insertLeft = false;
        cursor = cursor->right;
      }
    }

    ReconMapNodeView* const node = AllocateMapNode(head, parent, key, value);
    ++owner->mBlipMap.mSize;

    if (parent == head) {
      head->parent = node;
      head->left = node;
      head->right = node;
    } else if (insertLeft) {
      parent->left = node;
      if (parent == head->left) {
        head->left = node;
      }
    } else {
      parent->right = node;
      if (parent == head->right) {
        head->right = node;
      }
    }

    while (node->parent->color == kNodeColorRed) {
      ReconMapNodeView* const parentNode = node->parent;
      ReconMapNodeView* const grandParent = parentNode->parent;
      if (parentNode == grandParent->left) {
        ReconMapNodeView* const uncle = grandParent->right;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->right) {
            RotateLeft(parentNode, owner);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateRight(node->parent->parent, owner);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          if (grandParent->parent->color == kNodeColorRed) {
            continue;
          }
        }
      } else {
        ReconMapNodeView* const uncle = grandParent->left;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->left) {
            RotateRight(parentNode, owner);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateLeft(node->parent->parent, owner);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          if (grandParent->parent->color == kNodeColorRed) {
            continue;
          }
        }
      }
      break;
    }
    head->parent->color = kNodeColorBlack;
    return node;
  }

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

  void RebuildBlipListFromMapAndOrphans(CAiReconDBImpl* const owner)
  {
    if (!owner) {
      return;
    }

    owner->mBblips.clear();
    owner->mBblips.reserve(static_cast<std::size_t>(owner->mBlipMap.mSize) + owner->mTempBlips.size());

    for (ReconMapNodeView* node = MapBegin(owner); node != MapEnd(owner); node = MapNext(node, MapEnd(owner))) {
      if (node->value) {
        ReconBlip* const blip = node->value;
        owner->mBblips.push_back(blip);
      }
    }

    for (ReconBlip* const orphan : owner->mTempBlips) {
      if (orphan) {
        owner->mBblips.push_back(orphan);
      }
    }
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

  void CheckEvent(CAiReconDBImpl* const owner, ReconBlip* const blip, const int newFlags, const EReconFlags changedFlag)
  {
    if (!owner || !owner->mArmy || !blip) {
      return;
    }

    CAiBrain* const brain = owner->mArmy->GetArmyBrain();
    if (!brain) {
      return;
    }

    const bool gained = (newFlags & static_cast<int>(changedFlag)) != 0;
    auto* const scriptObject = reinterpret_cast<CScriptObject*>(reinterpret_cast<Entity*>(blip));
    brain->RunScript("OnIntelChange", scriptObject->mLuaObj, ReconSenseLexical(changedFlag), gained);
  }

  void CheckIntelEvents(
    CAiReconDBImpl* const owner, ReconBlip* const blip, const int oldFlags, const int newFlags
  )
  {
    if (oldFlags == newFlags) {
      return;
    }

    const int diff = oldFlags ^ newFlags;
    if ((diff & static_cast<int>(RECON_LOSNow)) != 0) {
      CheckEvent(owner, blip, newFlags, RECON_LOSNow);
    }
    if ((diff & static_cast<int>(RECON_Radar)) != 0) {
      CheckEvent(owner, blip, newFlags, RECON_Radar);
    }
    if ((diff & static_cast<int>(RECON_Sonar)) != 0) {
      CheckEvent(owner, blip, newFlags, RECON_Sonar);
    }
    if ((diff & static_cast<int>(RECON_Omni)) != 0) {
      CheckEvent(owner, blip, newFlags, RECON_Omni);
    }
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
      CheckIntelEvents(owner, blip, oldFlags, 0);
    }
    recon->mNeedsFlush = 0u;
    recon->mReconFlags = 0u;
  }

  void GenerateNewBlips(CAiReconDBImpl* const owner, const std::vector<CAiReconDBImpl::SNewBlip>& pending)
  {
    if (!owner) {
      return;
    }

    for (const CAiReconDBImpl::SNewBlip& candidate : pending) {
      ReconBlip* const blip = owner->FindOrCreateBlip(candidate);
      if (!blip) {
        continue;
      }

      owner->UpdateBlip(blip, candidate.sourceUnit, static_cast<std::uint32_t>(candidate.detectedFlags));
      InsertMapNode(owner, MakeReconMapKey(candidate.sourceUnit), blip);
    }
  }

  void UpdateBlips(
    CAiReconDBImpl* const owner,
    Unit* const sourceUnit,
    const EReconFlags detectedFlags,
    std::vector<CAiReconDBImpl::SNewBlip>& pending
  )
  {
    if (!owner || !sourceUnit) {
      return;
    }

    auto [it, end] = FindReconBlipRange(owner, sourceUnit);
    if (it == end) {
      pending.push_back(CAiReconDBImpl::SNewBlip{
        .sourceUnit = sourceUnit,
        .fake = 0u,
        .detectedFlags = detectedFlags,
      });
      return;
    }

    const std::int32_t requiredFakeBlips = std::max(0, GetActiveJammerBlipCount(sourceUnit));
    std::int32_t refreshedFakeBlips = 0;

    ReconMapNodeView* const head = MapEnd(owner);
    while (it != end) {
      ReconMapNodeView* const node = it;
      it = MapNext(node, head);

      ReconBlip* const blip = node->value;
      if (!blip) {
        EraseMapNode(owner, node);
        continue;
      }

      if (IsFakeBlip(blip)) {
        if (refreshedFakeBlips >= requiredFakeBlips) {
          owner->DeleteBlip(blip);
          EraseMapNode(owner, node);
          continue;
        }

        owner->UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
        ++refreshedFakeBlips;
        continue;
      }

      owner->UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
    }

    while (refreshedFakeBlips < requiredFakeBlips) {
      pending.push_back(CAiReconDBImpl::SNewBlip{
        .sourceUnit = sourceUnit,
        .fake = 1u,
        .detectedFlags = detectedFlags,
      });
      ++refreshedFakeBlips;
    }
  }

  void DeleteBlips(CAiReconDBImpl* const owner, Unit* const sourceUnit)
  {
    if (!owner || !sourceUnit) {
      return;
    }

    auto [it, end] = FindReconBlipRange(owner, sourceUnit);
    ReconMapNodeView* const head = MapEnd(owner);
    while (it != end) {
      ReconMapNodeView* const node = it;
      it = MapNext(node, head);

      ReconBlip* const blip = node->value;
      if (blip) {
        owner->DeleteBlip(blip);
      }
      EraseMapNode(owner, node);
    }
  }

  [[nodiscard]] EReconFlags ReconCanDetectEntity(
    const CAiReconDBImpl* const owner, Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags
  )
  {
    if (!owner) {
      return RECON_None;
    }

    if (!entity) {
      const bool isWaterPositioned = owner->mMapData && owner->mMapData->mWaterEnabled != 0u &&
        owner->mMapData->mWaterElevation > pos.y;
      (void)isWaterPositioned;
      return owner->ReconCanDetect(pos, static_cast<int>(oldFlags));
    }

    if (owner->mMapData && owner->mArmy && !owner->mArmy->UseWholeMap()) {
      const auto& playable = owner->mMapData->mPlayableRect;
      if (pos.x < static_cast<float>(playable.x0) || pos.x > static_cast<float>(playable.x1) ||
          pos.z < static_cast<float>(playable.z0) || pos.z > static_cast<float>(playable.z1)) {
        return RECON_None;
      }
    }

    if (IsAlliedOrSameArmy(owner->mArmy, entity->ArmyRef)) {
      return oldFlags;
    }

    // FUN_005C18F0 classifies Seabed/Sub contacts as "water-positioned" before
    // forwarding to GetReconFlags. Current lifted path retains semantic layer
    // classification while delegating flag synthesis to ReconCanDetect().
    const ELayer layer = entity->mCurrentLayer;
    const bool isWaterPositioned = layer == LAYER_Seabed || layer == LAYER_Sub;
    (void)isWaterPositioned;

    return owner->ReconCanDetect(pos, static_cast<int>(oldFlags));
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

gpg::RType* CAiReconDBImpl::sType = nullptr;

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
          pendingNewBlips.push_back(SNewBlip{
            .sourceUnit = unit,
            .fake = 0u,
            .detectedFlags = detectFlags,
          });
        } else {
          UpdateBlips(this, unit, detectFlags, pendingNewBlips);
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
          UpdateBlips(this, unit, RECON_None, pendingNewBlips);
        } else {
          DeleteBlips(this, unit);
        }
      }
    }
  }

  GenerateNewBlips(this, pendingNewBlips);
  RebuildBlipListFromMapAndOrphans(this);
  TickAllReconGrids(this, dTicks);
}

/**
 * Address: 0x005C14E0 (FUN_005C14E0)
 */
void CAiReconDBImpl::ReconRefresh()
{
  // TODO(binary-fidelity): recover FUN_005C14E0 + RefreshBlip helper chain and
  // rebuild per-blip refresh side effects exactly.
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
  CheckIntelEvents(this, blip, static_cast<int>(oldFlags), static_cast<int>(refreshedFlags));
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
  CheckIntelEvents(this, blip, oldFlags, 0);
  perArmy->mNeedsFlush = 0u;
  perArmy->mReconFlags = 0u;
  blip->DestroyIfUnused();
}

/**
 * Address: 0x005C18A0 (FUN_005C18A0)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const moho::Rect2<int>& rect, const float y, const int oldFlags) const
{
  const Wm3::Vec3f center{
    0.5f * static_cast<float>(rect.x0 + rect.x1),
    y,
    0.5f * static_cast<float>(rect.z0 + rect.z1),
  };
  return ReconCanDetect(center, oldFlags);
}

/**
 * Address: 0x005C1850 (FUN_005C1850)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const Wm3::Vec3f& pos, const int oldFlags) const
{
  EReconFlags flags = RECON_None;
  const std::int32_t x = static_cast<std::int32_t>(pos.x);
  const std::int32_t z = static_cast<std::int32_t>(pos.z);

  if (mRadarGrid.px && mRadarGrid.px->IsVisible(x, z)) {
    flags = SetFlag(flags, RECON_Radar);
  }
  if (mSonarGrid.px && mSonarGrid.px->IsVisible(x, z)) {
    flags = SetFlag(flags, RECON_Sonar);
  }
  if (mOmniGrid.px && mOmniGrid.px->IsVisible(x, z)) {
    flags = SetFlag(flags, RECON_Omni);
  }
  if (mVisionGrid.px && mVisionGrid.px->IsVisible(x, z)) {
    flags = SetFlag(flags, RECON_LOSNow);
    flags = SetFlag(flags, RECON_LOSEver);
  } else if ((oldFlags & RECON_LOSEver) != 0) {
    flags = SetFlag(flags, RECON_LOSEver);
  }

  if ((oldFlags & RECON_KnownFake) != 0) {
    flags = SetFlag(flags, RECON_KnownFake);
  }
  if ((oldFlags & RECON_MaybeDead) != 0) {
    flags = SetFlag(flags, RECON_MaybeDead);
  }
  return flags;
}

/**
 * Address: 0x005C1720 (FUN_005C1720)
 */
void CAiReconDBImpl::ReconGetBlips(const Wm3::Box3<float>& box, gpg::core::FastVector<Entity*>* const outBlips) const
{
  if (!outBlips) {
    return;
  }

  outBlips->Clear();
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    auto* const entity = reinterpret_cast<Entity*>(blip);
    const Wm3::Vec3f& pos = entity->GetPositionWm3();
    if (box.ContainsPoint(pos)) {
      outBlips->PushBack(entity);
    }
  }
}

/**
 * Address: 0x005C1640 (FUN_005C1640)
 */
void CAiReconDBImpl::ReconGetBlips(
  const Wm3::Vec3f& center, const float radius, gpg::core::FastVector<Entity*>* const outBlips
) const
{
  if (!outBlips) {
    return;
  }

  outBlips->Clear();
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    auto* const entity = reinterpret_cast<Entity*>(blip);
    if (IsInsideRadiusXZ(center, radius, entity->GetPositionWm3())) {
      outBlips->PushBack(entity);
    }
  }
}

/**
 * Address: 0x005C1590 (FUN_005C1590)
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
 */
void CAiReconDBImpl::ReconSetFogOfWar(const bool enabled)
{
  if (mVisionGrid.px) {
    mFogOfWar = static_cast<std::uint8_t>(enabled ? 1u : 0u);
  }
}

/**
 * Address: 0x005C0910 (FUN_005C0910)
 */
bool CAiReconDBImpl::ReconGetFogOfWar() const
{
  return mFogOfWar != 0 && mVisionGrid.px != nullptr;
}

/**
 * Address: 0x005C29C0 (FUN_005C29C0, nullsub_1553)
 */
void CAiReconDBImpl::UpdateSimChecksum() {}

/**
 * Address: 0x005C15A0 (FUN_005C15A0)
 */
ReconBlip* CAiReconDBImpl::ReconGetBlip(Unit* const unit) const
{
  if (!unit || unit->DestroyQueued()) {
    return nullptr;
  }

  ReconBlip** const begin = unit->mReconBlips.begin();
  ReconBlip** const end = unit->mReconBlips.end();
  return begin != end ? *begin : nullptr;
}

/**
 * Address: 0x005C20C0 (FUN_005C20C0)
 */
EntitySetTemplate<Entity> CAiReconDBImpl::ReconGetJamingBlips(Unit* const unit)
{
  EntitySetTemplate<Entity> out{};
  if (!unit || unit->DestroyQueued() || !mArmy) {
    return out;
  }

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
