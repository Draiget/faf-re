#include "moho/ai/CAiFormationInstance.h"

#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <new>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* CachedCFormationInstanceType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = ResolveTypeByAnyName({"CFormationInstance", "Moho::CFormationInstance"});
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!moho::Sim::sType) {
      moho::Sim::sType = gpg::LookupRType(typeid(moho::Sim));
    }
    return moho::Sim::sType;
  }

  [[nodiscard]] gpg::RRef MakeSimRef(moho::Sim* sim)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedSimType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!sim || !staticType) {
      out.mObj = sim;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*sim));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = sim;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(sim) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] moho::Sim* ReadPointerSim(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedSimType();
    if (!expectedType || !tracked.type) {
      return static_cast<moho::Sim*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<moho::Sim*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "Sim",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  void WritePointerSim(gpg::WriteArchive* const archive, moho::Sim* const sim, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef objectRef = MakeSimRef(sim);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  constexpr Wm3::Vec3f kZeroForwardVector{0.0f, 0.0f, 0.0f};
  constexpr Wm3::Quatf kZeroQuaternion{0.0f, 0.0f, 0.0f, 0.0f};

  struct SFormationLinkedUnitRefWordView
  {
    std::uint32_t ownerChainHeadWord;
    std::uint32_t nextChainLinkWord;
  };
  static_assert(
    sizeof(SFormationLinkedUnitRefWordView) == sizeof(moho::SFormationLinkedUnitRef),
    "SFormationLinkedUnitRefWordView size must match SFormationLinkedUnitRef"
  );

  [[nodiscard]] bool BinaryFloatNotEqual(const float lhs, const float rhs) noexcept
  {
    // Matches the recovered x87 `ucomiss` compare shape:
    // true only when values are different and both are not NaN.
    return ((std::isnan(lhs) || std::isnan(rhs)) == (lhs == rhs));
  }

  [[nodiscard]] bool QuaternionEqualsExact(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return lhs.w == rhs.w && lhs.x == rhs.x && lhs.y == rhs.y && lhs.z == rhs.z;
  }

  void DestroyCoordCacheSubtree(moho::SFormationCoordCacheNode* node, const moho::SFormationCoordCacheNode* head)
  {
    if (node == nullptr || node == head || node->isNil != 0u) {
      return;
    }

    DestroyCoordCacheSubtree(node->left, head);
    DestroyCoordCacheSubtree(node->right, head);
    delete node;
  }

  void ResetCoordCacheMap(moho::SFormationCoordCacheMap& cache)
  {
    moho::SFormationCoordCacheNode* const head = cache.head;
    if (head == nullptr) {
      cache.size = 0;
      return;
    }

    DestroyCoordCacheSubtree(head->parent, head);
    head->parent = head;
    head->left = head;
    head->right = head;
    cache.size = 0;
  }

  template <class T>
  [[nodiscard]] std::uint32_t PtrToWord(T* const ptr) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ptr));
  }

  template <class T>
  [[nodiscard]] T* WordToPtr(const std::uint32_t word) noexcept
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(word));
  }

  [[nodiscard]] std::uint32_t EncodeUnitOwnerSlotWord(moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return 0;
    }

    constexpr std::uintptr_t kWeakOwnerLinkOffset = 0x4u;
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(unit) + kWeakOwnerLinkOffset);
  }

  [[nodiscard]] moho::Unit* DecodeUnitOwnerSlotWord(const std::uint32_t ownerWord) noexcept
  {
    constexpr std::uintptr_t kWeakOwnerLinkOffset = 0x4u;
    const auto encoded = static_cast<std::uintptr_t>(ownerWord);
    if (encoded <= kWeakOwnerLinkOffset) {
      return nullptr;
    }

    return reinterpret_cast<moho::Unit*>(encoded - kWeakOwnerLinkOffset);
  }

  void UnlinkWeakWordNode(std::uint32_t& ownerWord, std::uint32_t& nextWord) noexcept
  {
    if (ownerWord == 0u) {
      nextWord = 0u;
      return;
    }

    std::uint32_t* cursor = WordToPtr<std::uint32_t>(ownerWord);
    if (!cursor) {
      ownerWord = 0u;
      nextWord = 0u;
      return;
    }

    const std::uint32_t selfWord = PtrToWord(&ownerWord);
    constexpr int kMaxFollowSteps = 1 << 20;
    for (int i = 0; i < kMaxFollowSteps && *cursor != 0u && *cursor != selfWord; ++i) {
      cursor = moho::SFormationLinkedUnitRef::NextChainLinkSlot(*cursor);
      if (!cursor) {
        break;
      }
    }

    if (cursor && *cursor == selfWord) {
      *cursor = nextWord;
    }

    ownerWord = 0u;
    nextWord = 0u;
  }

  void RelinkWeakWordNode(std::uint32_t& ownerWord, std::uint32_t& nextWord, moho::Unit* const owner) noexcept
  {
    ownerWord = EncodeUnitOwnerSlotWord(owner);
    if (ownerWord == 0u) {
      nextWord = 0u;
      return;
    }

    std::uint32_t* const head = WordToPtr<std::uint32_t>(ownerWord);
    if (!head) {
      ownerWord = 0u;
      nextWord = 0u;
      return;
    }

    nextWord = *head;
    *head = PtrToWord(&ownerWord);
  }

  [[nodiscard]] moho::Unit* DecodeLinkedRefUnit(const moho::SFormationLinkedUnitRef& link) noexcept
  {
    if (!link.ownerChainHead) {
      return nullptr;
    }
    return DecodeUnitOwnerSlotWord(PtrToWord(link.ownerChainHead));
  }

  void UnlinkLinkedRef(moho::SFormationLinkedUnitRef& link) noexcept
  {
    if (!link.ownerChainHead) {
      link.nextChainLink = 0u;
      return;
    }

    std::uint32_t* cursor = link.ownerChainHead;
    const std::uint32_t selfWord = PtrToWord(&link);
    constexpr int kMaxFollowSteps = 1 << 20;
    for (int i = 0; i < kMaxFollowSteps && *cursor != 0u && *cursor != selfWord; ++i) {
      cursor = moho::SFormationLinkedUnitRef::NextChainLinkSlot(*cursor);
      if (!cursor) {
        break;
      }
    }

    if (cursor && *cursor == selfWord) {
      *cursor = link.nextChainLink;
    }

    link.ownerChainHead = nullptr;
    link.nextChainLink = 0u;
  }

  void RelinkLinkedRef(moho::SFormationLinkedUnitRef& link, moho::Unit* const owner) noexcept
  {
    if (!owner) {
      link.ownerChainHead = nullptr;
      link.nextChainLink = 0u;
      return;
    }

    auto* const ownerHead = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uintptr_t>(owner) + 0x4u);
    link.ownerChainHead = ownerHead;
    link.nextChainLink = *ownerHead;
    *ownerHead = PtrToWord(&link);
  }

  [[nodiscard]] std::uint32_t UnitEntityIdWord(const moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return 0u;
    }

    return static_cast<std::uint32_t>(unit->GetEntityId());
  }

  void EnsureLaneMapHead(moho::SFormationLaneUnitMap& map)
  {
    if (map.head != nullptr) {
      return;
    }

    auto* const head = new moho::SFormationLaneUnitNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->isNil = 1u;
    map.head = head;
    map.size = 0u;
  }

  [[nodiscard]] moho::SFormationLaneUnitNode* LaneMapFindNode(
    const moho::SFormationLaneUnitMap& map,
    const std::uint32_t unitEntityId
  )
  {
    const moho::SFormationLaneUnitNode* const head = map.head;
    if (!head) {
      return nullptr;
    }

    moho::SFormationLaneUnitNode* node = head->parent;
    while (node && node != head && node->isNil == 0u) {
      if (unitEntityId < node->unitEntityId) {
        node = node->left;
      } else if (node->unitEntityId < unitEntityId) {
        node = node->right;
      } else {
        return node;
      }
    }

    return nullptr;
  }

  void DestroyLaneMapSubtree(moho::SFormationLaneUnitNode* node, const moho::SFormationLaneUnitNode* head)
  {
    if (!node || node == head || node->isNil != 0u) {
      return;
    }

    DestroyLaneMapSubtree(node->left, head);
    DestroyLaneMapSubtree(node->right, head);
    UnlinkWeakWordNode(node->linkedUnitOwnerWord, node->linkedUnitNextWord);
    delete node;
  }

  void ResetLaneMap(moho::SFormationLaneUnitMap& map)
  {
    moho::SFormationLaneUnitNode* const head = map.head;
    if (!head) {
      map.size = 0u;
      return;
    }

    DestroyLaneMapSubtree(head->parent, head);
    head->parent = head;
    head->left = head;
    head->right = head;
    map.size = 0u;
  }

  void CollectLaneMapNodes(
    const moho::SFormationLaneUnitNode* node,
    const moho::SFormationLaneUnitNode* head,
    std::vector<moho::SFormationLaneUnitNode>& out
  )
  {
    if (!node || node == head || node->isNil != 0u) {
      return;
    }

    CollectLaneMapNodes(node->left, head, out);

    moho::SFormationLaneUnitNode value = *node;
    value.left = nullptr;
    value.parent = nullptr;
    value.right = nullptr;
    value.color = 0u;
    value.isNil = 0u;
    out.push_back(value);

    CollectLaneMapNodes(node->right, head, out);
  }

  [[nodiscard]] moho::SFormationLaneUnitNode* InsertLaneMapNode(
    moho::SFormationLaneUnitMap& map,
    const moho::SFormationLaneUnitNode& src
  )
  {
    EnsureLaneMapHead(map);
    moho::SFormationLaneUnitNode* const head = map.head;

    moho::SFormationLaneUnitNode* parent = head;
    moho::SFormationLaneUnitNode* node = head->parent;
    bool insertLeft = true;

    while (node && node != head && node->isNil == 0u) {
      parent = node;
      if (src.unitEntityId < node->unitEntityId) {
        insertLeft = true;
        node = node->left;
      } else if (node->unitEntityId < src.unitEntityId) {
        insertLeft = false;
        node = node->right;
      } else {
        UnlinkWeakWordNode(node->linkedUnitOwnerWord, node->linkedUnitNextWord);

        node->unitEntityId = src.unitEntityId;
        node->leaderPriority = src.leaderPriority;
        node->formationOffsetX = src.formationOffsetX;
        node->formationOffsetZ = src.formationOffsetZ;
        node->formationVector = src.formationVector;
        node->formationWeight = src.formationWeight;
        node->speedBandLow = src.speedBandLow;
        node->speedBandMid = src.speedBandMid;
        node->speedBandHigh = src.speedBandHigh;
        node->color = src.color;

        RelinkWeakWordNode(
          node->linkedUnitOwnerWord,
          node->linkedUnitNextWord,
          DecodeUnitOwnerSlotWord(src.linkedUnitOwnerWord)
        );
        return node;
      }
    }

    auto* const inserted = new moho::SFormationLaneUnitNode{};
    *inserted = src;
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent;
    inserted->color = 0u;
    inserted->isNil = 0u;
    inserted->linkedUnitOwnerWord = 0u;
    inserted->linkedUnitNextWord = 0u;

    RelinkWeakWordNode(
      inserted->linkedUnitOwnerWord,
      inserted->linkedUnitNextWord,
      DecodeUnitOwnerSlotWord(src.linkedUnitOwnerWord)
    );

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (insertLeft) {
      parent->left = inserted;
      if (head->left == head || inserted->unitEntityId < head->left->unitEntityId) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (head->right == head || head->right->unitEntityId < inserted->unitEntityId) {
        head->right = inserted;
      }
    }

    ++map.size;
    return inserted;
  }

  void EraseLaneMapNodeByEntityId(moho::SFormationLaneUnitMap& map, const std::uint32_t unitEntityId)
  {
    moho::SFormationLaneUnitNode* const head = map.head;
    if (!head) {
      return;
    }

    std::vector<moho::SFormationLaneUnitNode> keptNodes;
    keptNodes.reserve(map.size > 0u ? map.size - 1u : 0u);
    CollectLaneMapNodes(head->parent, head, keptNodes);

    ResetLaneMap(map);

    for (const moho::SFormationLaneUnitNode& node : keptNodes) {
      if (node.unitEntityId == unitEntityId) {
        continue;
      }
      (void)InsertLaneMapNode(map, node);
    }
  }

  void EnsureCoordCacheHead(moho::SFormationCoordCacheMap& cache)
  {
    if (cache.head != nullptr) {
      return;
    }

    auto* const head = new moho::SFormationCoordCacheNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->isNil = 1u;
    cache.head = head;
    cache.size = 0u;
  }

  [[nodiscard]] moho::SFormationCoordCacheNode* CoordCacheFindNode(
    const moho::SFormationCoordCacheMap& cache,
    const std::uint32_t unitEntityId
  )
  {
    const moho::SFormationCoordCacheNode* const head = cache.head;
    if (!head) {
      return nullptr;
    }

    moho::SFormationCoordCacheNode* node = head->parent;
    while (node && node != head && node->isNil == 0u) {
      if (unitEntityId < node->unitEntityId) {
        node = node->left;
      } else if (node->unitEntityId < unitEntityId) {
        node = node->right;
      } else {
        return node;
      }
    }

    return nullptr;
  }

  moho::SFormationCoordCacheNode* CoordCacheInsertOrAssign(
    moho::SFormationCoordCacheMap& cache,
    const std::uint32_t unitEntityId,
    const moho::SCoordsVec2& position
  )
  {
    EnsureCoordCacheHead(cache);
    moho::SFormationCoordCacheNode* const head = cache.head;

    moho::SFormationCoordCacheNode* parent = head;
    moho::SFormationCoordCacheNode* node = head->parent;
    bool insertLeft = true;

    while (node && node != head && node->isNil == 0u) {
      parent = node;
      if (unitEntityId < node->unitEntityId) {
        insertLeft = true;
        node = node->left;
      } else if (node->unitEntityId < unitEntityId) {
        insertLeft = false;
        node = node->right;
      } else {
        node->position = position;
        return node;
      }
    }

    auto* const inserted = new moho::SFormationCoordCacheNode{};
    inserted->left = head;
    inserted->parent = parent;
    inserted->right = head;
    inserted->unitEntityId = unitEntityId;
    inserted->position = position;
    inserted->color = 0u;
    inserted->isNil = 0u;

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (insertLeft) {
      parent->left = inserted;
      if (head->left == head || unitEntityId < head->left->unitEntityId) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (head->right == head || head->right->unitEntityId < unitEntityId) {
        head->right = inserted;
      }
    }

    ++cache.size;
    return inserted;
  }

  [[nodiscard]] bool LaneEntriesOverlap(
    const moho::SFormationLaneEntry& lhs,
    const moho::SFormationLaneEntry& rhs
  ) noexcept
  {
    const bool overlapX = (lhs.overlapRadiusX - lhs.overlapAnchorX) <= (rhs.overlapAnchorX + rhs.overlapRadiusX)
      && (rhs.overlapRadiusX - rhs.overlapAnchorX) <= (lhs.overlapAnchorX + lhs.overlapRadiusX);
    if (!overlapX) {
      return false;
    }

    const bool overlapZ = (lhs.overlapRadiusZ - lhs.overlapAnchorZ) <= (rhs.overlapAnchorZ + rhs.overlapRadiusZ)
      && (rhs.overlapRadiusZ - rhs.overlapAnchorZ) <= (lhs.overlapAnchorZ + lhs.overlapRadiusZ);
    return overlapZ;
  }

  struct FormationUpdateListenerNode
  {
    void** vtable;                                // +0x00
    moho::TDatListItem<void, void> updateLink;   // +0x04
  };
  static_assert(
    offsetof(FormationUpdateListenerNode, updateLink) == 0x04,
    "FormationUpdateListenerNode::updateLink offset must be 0x04"
  );

  [[nodiscard]] FormationUpdateListenerNode* ListenerOwnerFromLink(
    moho::TDatListItem<void, void>* const link
  ) noexcept
  {
    if (link == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<FormationUpdateListenerNode*>(
      reinterpret_cast<std::uintptr_t>(link) - offsetof(FormationUpdateListenerNode, updateLink)
    );
  }

  /**
   * Address: 0x0056B070 (FUN_0056B070, sub_56B070)
   *
   * What it does:
   * Detaches one intrusive listener ring, relinks listeners back to the owner
   * head one-by-one, and dispatches one integer update event through each
   * listener's vtable slot-0 callback.
   */
  [[maybe_unused]] void DispatchFormationUpdateEvent(
    const std::int32_t eventCode,
    moho::TDatListItem<void, void>& listenerHead
  )
  {
    moho::TDatListItem<void, void> detached{};
    if (listenerHead.mNext == &listenerHead) {
      return;
    }

    detached.mNext = listenerHead.mNext;
    detached.mPrev = listenerHead.mPrev;
    detached.mNext->mPrev = &detached;
    detached.mPrev->mNext = &detached;
    listenerHead.ListResetLinks();

    while (detached.mNext != &detached) {
      auto* const listenerLink = detached.mNext;
      listenerLink->ListLinkAfter(&listenerHead);

      using OnEventFn = void(__thiscall*)(FormationUpdateListenerNode*, std::int32_t);
      if (FormationUpdateListenerNode* const listener = ListenerOwnerFromLink(listenerLink);
          listener != nullptr && listener->vtable != nullptr && listener->vtable[0] != nullptr) {
        reinterpret_cast<OnEventFn>(listener->vtable[0])(listener, eventCode);
      }
    }

    detached.mNext->mPrev = detached.mPrev;
    detached.mPrev->mNext = detached.mNext;
  }

  [[nodiscard]] moho::SFormationLaneUnitNode* NextLaneMapNodeInOrder(
    moho::SFormationLaneUnitNode* const node,
    moho::SFormationLaneUnitNode* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr || node == head || node->isNil != 0u) {
      return head;
    }

    moho::SFormationLaneUnitNode* current = node;
    if (current->right == nullptr || current->right->isNil != 0u) {
      moho::SFormationLaneUnitNode* parent = current->parent;
      while (parent != nullptr && parent != head && parent->isNil == 0u) {
        if (current != parent->right) {
          break;
        }
        current = parent;
        parent = parent->parent;
      }
      return parent ? parent : head;
    }

    current = current->right;
    while (current->left != nullptr && current->left->isNil == 0u) {
      current = current->left;
    }
    return current;
  }

  /**
   * Address: 0x0056EB40 (FUN_0056EB40, sub_56EB40)
   *
   * What it does:
   * Erases one lane-map node range [`beginNode`, `endNode`) and returns the
   * next in-order node after the erased span; includes full-map clear fast path.
   */
  [[maybe_unused]] moho::SFormationLaneUnitNode* EraseLaneMapNodeRange(
    moho::SFormationLaneUnitMap& map,
    moho::SFormationLaneUnitNode*& outNextNode,
    moho::SFormationLaneUnitNode* beginNode,
    moho::SFormationLaneUnitNode* endNode
  )
  {
    moho::SFormationLaneUnitNode* const head = map.head;
    if (head == nullptr) {
      outNextNode = nullptr;
      return outNextNode;
    }

    if (beginNode == head->left && endNode == head) {
      ResetLaneMap(map);
      outNextNode = head->left;
      return outNextNode;
    }

    const bool endIsHead = (endNode == head);
    const std::uint32_t endEntityId =
      (!endIsHead && endNode != nullptr && endNode != head && endNode->isNil == 0u) ? endNode->unitEntityId : 0u;

    auto resolveEndNode = [&map, endIsHead, endEntityId]() -> moho::SFormationLaneUnitNode* {
      moho::SFormationLaneUnitNode* const currentHead = map.head;
      if (currentHead == nullptr) {
        return nullptr;
      }
      if (endIsHead) {
        return currentHead;
      }
      if (moho::SFormationLaneUnitNode* const resolved = LaneMapFindNode(map, endEntityId); resolved != nullptr) {
        return resolved;
      }
      return currentHead;
    };

    moho::SFormationLaneUnitNode* current = beginNode;
    moho::SFormationLaneUnitNode* resolvedEnd = resolveEndNode();
    while (current != nullptr && current != resolvedEnd) {
      if (current == map.head || current->isNil != 0u) {
        break;
      }

      const moho::SFormationLaneUnitNode* const eraseNode = current;
      moho::SFormationLaneUnitNode* const successor = NextLaneMapNodeInOrder(current, map.head);
      const bool successorIsHead = successor == nullptr || successor == map.head || successor->isNil != 0u;
      const std::uint32_t successorEntityId = successorIsHead ? 0u : successor->unitEntityId;

      EraseLaneMapNodeByEntityId(map, eraseNode->unitEntityId);

      if (map.head == nullptr) {
        current = nullptr;
        resolvedEnd = nullptr;
        break;
      }

      resolvedEnd = resolveEndNode();
      if (successorIsHead) {
        current = map.head;
      } else if (moho::SFormationLaneUnitNode* const resolved = LaneMapFindNode(map, successorEntityId);
                 resolved != nullptr) {
        current = resolved;
      } else {
        current = map.head;
      }
    }

    outNextNode = current;
    return outNextNode;
  }

  /**
   * Address: 0x00568980 (FUN_00568980, sub_568980)
   *
   * What it does:
   * For non-guard formation commands, scans overlap between lane-0 entries and
   * both lane groups, then merges overlap extents/speed bands with a minimum
   * floor to keep coupled lane movement consistent.
   */
  [[maybe_unused]] void MergeOverlappingLaneBands(moho::CAiFormationInstance& formation)
  {
    if (formation.mCommandType == moho::EUnitCommandType::UNITCOMMAND_Guard) {
      return;
    }

    constexpr float kBandFloor = 10.0f;
    moho::SFormationLaneEntry* lane0Entry = formation.mLanes[0].begin();
    const moho::SFormationLaneEntry* const lane0End = formation.mLanes[0].end();
    while (lane0Entry != lane0End) {
      for (std::int32_t laneIndex = 0; laneIndex < 2; ++laneIndex) {
        moho::SFormationLaneEntry* candidate = formation.mLanes[laneIndex].begin();
        const moho::SFormationLaneEntry* const laneEnd = formation.mLanes[laneIndex].end();
        while (candidate != laneEnd) {
          if (LaneEntriesOverlap(*candidate, *lane0Entry)) {
            float mergedBandA = std::max(lane0Entry->overlapAnchorX, candidate->overlapAnchorX);
            if (mergedBandA < kBandFloor) {
              mergedBandA = kBandFloor;
            }

            float mergedBandB = std::max(lane0Entry->overlapAnchorZ, candidate->overlapAnchorZ);
            if (mergedBandB < kBandFloor) {
              mergedBandB = kBandFloor;
            }

            const float mergedSpeed = std::min(lane0Entry->preferredSpeed, candidate->preferredSpeed);

            candidate->overlapRadiusX = lane0Entry->overlapRadiusX;
            candidate->overlapRadiusZ = lane0Entry->overlapRadiusZ;
            candidate->overlapAnchorX = mergedBandA;
            candidate->overlapAnchorZ = mergedBandB;
            candidate->preferredSpeed = mergedSpeed;

            lane0Entry->overlapAnchorX = mergedBandA;
            lane0Entry->overlapAnchorZ = mergedBandB;
            lane0Entry->preferredSpeed = mergedSpeed;
          }
          ++candidate;
        }
      }
      ++lane0Entry;
    }
  }

  void FindBestLeaderInLane(
    const moho::SFormationLaneUnitNode* node,
    const moho::SFormationLaneUnitNode* head,
    std::int32_t& bestPriority,
    moho::Unit*& bestUnit
  )
  {
    if (!node || node == head || node->isNil != 0u) {
      return;
    }

    FindBestLeaderInLane(node->left, head, bestPriority, bestUnit);
    if (moho::Unit* const candidate = DecodeUnitOwnerSlotWord(node->linkedUnitOwnerWord);
        candidate != nullptr && node->leaderPriority > bestPriority) {
      bestPriority = node->leaderPriority;
      bestUnit = candidate;
    }
    FindBestLeaderInLane(node->right, head, bestPriority, bestUnit);
  }

  /**
   * Address: 0x0059A300 (FUN_0059A300, sub_59A300)
   *
   * What it does:
   * Returns one lane leader resolved from `laneEntry.unitMap`; when no cached
   * weak backlink is active, it recomputes the best-priority unit and rewires
   * the backlink chain to that owner.
   */
  [[nodiscard]] moho::Unit* SelectLaneLeader(moho::SFormationLaneEntry& laneEntry)
  {
    if (laneEntry.linkedUnitBackLinkHeadWord == 0u || laneEntry.linkedUnitBackLinkHeadWord == 0x4u) {
      std::int32_t bestPriority = 0;
      moho::Unit* bestUnit = nullptr;

      const moho::SFormationLaneUnitNode* const head = laneEntry.unitMap.head;
      if (head) {
        FindBestLeaderInLane(head->parent, head, bestPriority, bestUnit);
      }

      const std::uint32_t desiredOwnerWord = EncodeUnitOwnerSlotWord(bestUnit);
      if (desiredOwnerWord != laneEntry.linkedUnitBackLinkHeadWord) {
        UnlinkWeakWordNode(laneEntry.linkedUnitBackLinkHeadWord, laneEntry.linkedUnitBackLinkNextWord);
        RelinkWeakWordNode(laneEntry.linkedUnitBackLinkHeadWord, laneEntry.linkedUnitBackLinkNextWord, bestUnit);
      }
    }

    return DecodeUnitOwnerSlotWord(laneEntry.linkedUnitBackLinkHeadWord);
  }

  /**
   * Address: 0x0059A970 (FUN_0059A970, sub_59A970)
   *
   * What it does:
   * Resolves the effective lane-leader unit for one lane entry during update:
   * when processing lane 1 it first checks overlap against lane-0 entries and
   * may switch leader to the first overlapping lane, then applies guard-command
   * remap to guarded target unit.
   */
  [[nodiscard]] moho::Unit* ResolveUpdateLaneLeader(
    const std::int32_t laneIndex,
    moho::CAiFormationInstance& formation,
    moho::SFormationLaneEntry& laneEntry
  )
  {
    moho::Unit* leader = SelectLaneLeader(laneEntry);

    if (laneIndex == 1) {
      moho::SFormationLaneEntry* candidate = formation.mLanes[0].begin();
      const moho::SFormationLaneEntry* const end = formation.mLanes[0].end();
      while (candidate != end) {
        if (LaneEntriesOverlap(*candidate, laneEntry)) {
          leader = SelectLaneLeader(*candidate);
          break;
        }
        ++candidate;
      }
    }

    if (formation.mCommandType != moho::EUnitCommandType::UNITCOMMAND_Guard || leader == nullptr) {
      return leader;
    }

    moho::Unit* const runtimeLeader = leader->IsUnit();
    if (runtimeLeader == nullptr) {
      return nullptr;
    }
    return runtimeLeader->GuardedUnitRef.ResolveObjectPtr<moho::Unit>();
  }

  void RefreshFormationPlanIfRequested(moho::CAiFormationInstance& formation)
  {
    if (formation.mPlanUpdateRequested == 0u) {
      return;
    }

    formation.mPlanUpdateRequested = 0u;
    (void)formation.RemoveDeadUnits(nullptr);

    // Full UpdateFormation path remains in-progress in this translation unit.
  }

  [[nodiscard]] bool IsBusyFormationQueueCommand(const moho::EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
    case moho::EUnitCommandType::UNITCOMMAND_Move:
    case moho::EUnitCommandType::UNITCOMMAND_Attack:
    case moho::EUnitCommandType::UNITCOMMAND_Patrol:
    case moho::EUnitCommandType::UNITCOMMAND_FormMove:
    case moho::EUnitCommandType::UNITCOMMAND_FormAttack:
    case moho::EUnitCommandType::UNITCOMMAND_FormPatrol:
    case moho::EUnitCommandType::UNITCOMMAND_Guard:
      return true;
    default:
      return false;
    }
  }

  [[nodiscard]] bool CanPlaceFormationSlot(
    const moho::CAiFormationInstance& formation,
    const moho::SCoordsVec2& position,
    const moho::SFootprint& footprint,
    const std::int32_t footprintSize,
    const bool useWholeMap,
    const std::int32_t laneToken
  )
  {
    if (formation.mSim == nullptr || formation.mSim->mOGrid == nullptr || formation.mSim->mMapData == nullptr) {
      return false;
    }

    if (footprint.FitsAt(position, *formation.mSim->mOGrid) != static_cast<moho::EOccupancyCaps>(0u)) {
      return false;
    }

    const Wm3::Vec3f worldPos{position.x, 0.0f, position.z};
    if (!formation.mSim->mMapData->IsWithin(worldPos, static_cast<float>(footprintSize), useWholeMap)) {
      return false;
    }

    return formation.Func27(position, footprintSize, laneToken);
  }
} // namespace

namespace moho
{
  std::uint32_t* SFormationLinkedUnitRef::NextChainLinkSlot(const std::uint32_t linkWord) noexcept
  {
    auto* const link = reinterpret_cast<SFormationLinkedUnitRefWordView*>(static_cast<std::uintptr_t>(linkWord));
    return &link->nextChainLinkWord;
  }

  /**
   * Address: 0x0059BD60 (FUN_0059BD60, ??3CAiFormationInstance@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes CAiFormationInstance teardown and conditionally frees this object
   * when `deleteFlags & 1` is set.
   */
  void CAiFormationInstance::operator_delete(const std::int32_t deleteFlags)
  {
    this->~CAiFormationInstance();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(this);
    }
  }

  /**
   * Address: 0x0059E950 (FUN_0059E950, Moho::CAiFormationInstance::MemberDeserialize)
   *
   * What it does:
   * Reads serialized base-formation payload, then restores the `Sim*` lane as
   * an unowned tracked pointer.
   */
  void CAiFormationInstance::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    gpg::RType* const baseType = CachedCFormationInstanceType();
    GPG_ASSERT(baseType != nullptr);
    if (baseType) {
      archive->Read(baseType, this, owner);
    }

    mSim = ReadPointerSim(archive, owner);
  }

  /**
   * Address: 0x0059DB60 (FUN_0059DB60)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CAiFormationInstance::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiFormationInstanceMemberDeserializeBridgeA(
    gpg::ReadArchive* const archive,
    CAiFormationInstance* const formation
  )
  {
    if (formation != nullptr) {
      formation->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x0059E9B0 (FUN_0059E9B0, Moho::CAiFormationInstance::MemberSerialize)
   *
   * What it does:
   * Writes serialized base-formation payload, then saves the `Sim*` lane as
   * an unowned tracked pointer.
   */
  void CAiFormationInstance::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    gpg::RType* const baseType = CachedCFormationInstanceType();
    GPG_ASSERT(baseType != nullptr);
    if (baseType) {
      archive->Write(baseType, this, owner);
    }

    WritePointerSim(archive, mSim, owner);
  }

  /**
   * Address: 0x0059DB70 (FUN_0059DB70)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CAiFormationInstance::MemberSerialize`.
   */
  [[maybe_unused]] void CAiFormationInstanceMemberSerializeBridgeA(
    const CAiFormationInstance* const formation,
    gpg::WriteArchive* const archive
  )
  {
    if (formation != nullptr) {
      formation->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0059E000 (FUN_0059E000)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CAiFormationInstance::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiFormationInstanceMemberDeserializeBridgeB(
    gpg::ReadArchive* const archive,
    CAiFormationInstance* const formation
  )
  {
    if (formation != nullptr) {
      formation->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x0059E010 (FUN_0059E010)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CAiFormationInstance::MemberSerialize`.
   */
  [[maybe_unused]] void CAiFormationInstanceMemberSerializeBridgeB(
    const CAiFormationInstance* const formation,
    gpg::WriteArchive* const archive
  )
  {
    if (formation != nullptr) {
      formation->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00569A10 (FUN_00569A10)
   *
   * Moho::SCoordsVec2*
   *
   * What it does:
   * Copies the current formation center into `outCenter`.
   */
  SCoordsVec2* CAiFormationInstance::Func2(SCoordsVec2* const outCenter) const
  {
    outCenter->x = mFormationCenter.x;
    outCenter->z = mFormationCenter.z;
    return outCenter;
  }

  /**
   * Address: 0x00569A30 (FUN_00569A30)
   *
   * Moho::SCoordsVec2 const&
   *
   * What it does:
   * Applies a new center (if finite and changed), then invalidates slot and coord caches.
   */
  void CAiFormationInstance::Func3(const SCoordsVec2& center)
  {
    if (!BinaryFloatNotEqual(mFormationCenter.x, center.x) && !BinaryFloatNotEqual(mFormationCenter.z, center.z)) {
      return;
    }
    if (std::isnan(center.x) || std::isnan(center.z)) {
      return;
    }

    mFormationCenter = center;
    mOccupiedSlots.ResetStorageToInline();
    ResetCoordCacheMap(mCoordCachePrimary);
    ResetCoordCacheMap(mCoordCacheSecondary);
  }

  /**
   * Address: 0x0056A210 (FUN_0056A210)
   *
   * What it does:
   * Returns number of linked unit references currently tracked by this formation.
   */
  int CAiFormationInstance::UnitCount() const
  {
    return static_cast<int>(mUnits.end() - mUnits.begin());
  }

  /**
   * Address: 0x00569BD0 (FUN_00569BD0)
   *
   * Moho::Unit*
   *
   * What it does:
   * Classifies the unit into the air-motion bucket.
   */
  bool CAiFormationInstance::Func5(Unit* const unit) const
  {
    if (unit == nullptr) {
      return false;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    return blueprint != nullptr && blueprint->Physics.MotionType == RULEUMT_Air;
  }

  /**
   * Address: 0x005669A0 (FUN_005669A0, Moho::CFormationInstance::Func6)
   *
   * What it does:
   * Resolves and returns the lane entry that currently owns `unit`.
   */
  SFormationLaneEntry* CAiFormationInstance::Func6(Unit* const unit)
  {
    if (!unit) {
      return nullptr;
    }

    const std::int32_t laneIndex = Func5(unit) ? 1 : 0;
    SFormationLaneEntry* lane = mLanes[laneIndex].begin();
    SFormationLaneEntry* const laneEnd = mLanes[laneIndex].end();
    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    while (lane != laneEnd) {
      if (LaneMapFindNode(lane->unitMap, unitEntityId) != nullptr) {
        return lane;
      }
      ++lane;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    gpg::Warnf(
      "unit %s not part of formation.",
      blueprint != nullptr ? blueprint->mBlueprintId.c_str() : "<null>"
    );
    return nullptr;
  }

  /**
   * Address: 0x00569CB0 (FUN_00569CB0, Moho::CFormationInstance::GetFormationPosition)
   *
   * What it does:
   * Computes one formation target position for `unit` and updates the primary
   * coord cache.
   */
  SCoordsVec2* CAiFormationInstance::GetFormationPosition(
    SCoordsVec2* const dest,
    Unit* const unit,
    SFormationLaneEntry* laneEntry
  )
  {
    if (!dest || !unit) {
      return dest;
    }

    RefreshFormationPlanIfRequested(*this);

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    SCoordsVec2 position{unitPos.x, unitPos.z};
    if (unit->IsDead()) {
      *dest = position;
      return dest;
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    if (SFormationCoordCacheNode* const cached = CoordCacheFindNode(mCoordCachePrimary, unitEntityId)) {
      *dest = cached->position;
      return dest;
    }

    SFormationLaneEntry* lane = laneEntry;
    if (lane == nullptr) {
      if (!Func17(unit, false)) {
        *dest = position;
        return dest;
      }
      lane = Func6(unit);
    }

    if (lane != nullptr) {
      if (const SFormationLaneUnitNode* const node = LaneMapFindNode(lane->unitMap, unitEntityId)) {
        float localX = node->formationOffsetX;
        float localZ = node->formationOffsetZ;
        if (lane->applyDynamicOffset != 0u) {
          localX += lane->dynamicOffsetX;
          localZ += lane->dynamicOffsetZ;
        }

        SCoordsVec2 requested{};
        requested.x = mFormationCenter.x + localX;
        requested.z = mFormationCenter.z + localZ;

        SCoordsVec2 snapped{};
        FindSlotFor(&snapped, &requested, unit);
        position = snapped;
      }
    }

    (void)CoordCacheInsertOrAssign(mCoordCachePrimary, unitEntityId, position);
    *dest = position;
    return dest;
  }

  /**
   * Address: 0x00569EA0 (FUN_00569EA0, Moho::CFormationInstance::GetAdjustedFormationPosition)
   *
   * What it does:
   * Converts formation world coordinates to footprint-min cell coordinates.
   */
  SOCellPos* CAiFormationInstance::GetAdjustedFormationPosition(
    SOCellPos* const dest,
    Unit* const unit,
    SFormationLaneEntry* laneEntry
  )
  {
    if (!dest) {
      return dest;
    }

    dest->x = 0;
    dest->z = 0;
    if (!unit || unit->IsDead()) {
      return dest;
    }

    SCoordsVec2 position{};
    GetFormationPosition(&position, unit, laneEntry);

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return dest;
    }

    const float halfSizeX = static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f;
    const float halfSizeZ = static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f;
    const int adjustedX = static_cast<int>(std::lround(position.x - halfSizeX));
    const int adjustedZ = static_cast<int>(std::lround(position.z - halfSizeZ));
    dest->x = static_cast<std::int16_t>(adjustedX);
    dest->z = static_cast<std::int16_t>(adjustedZ);
    return dest;
  }

  /**
   * Address: 0x00569F70 (FUN_00569F70, Moho::CFormationInstance::Func9)
   *
   * What it does:
   * Computes one formation/steering hint coordinate and updates the secondary
   * coord cache.
   */
  SCoordsVec2* CAiFormationInstance::Func9(SCoordsVec2* const dest, Unit* const unit, SFormationLaneEntry* laneEntry)
  {
    if (!dest || !unit) {
      return dest;
    }

    RefreshFormationPlanIfRequested(*this);

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    SCoordsVec2 position{unitPos.x, unitPos.z};
    if (unit->IsDead()) {
      *dest = position;
      return dest;
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    if (SFormationCoordCacheNode* const cached = CoordCacheFindNode(mCoordCacheSecondary, unitEntityId)) {
      *dest = cached->position;
      return dest;
    }

    if (laneEntry != nullptr) {
      if (!unit->IsMobile()) {
        position.x = unitPos.x;
        position.z = unitPos.z;
      } else if (const SFormationLaneUnitNode* const node = LaneMapFindNode(laneEntry->unitMap, unitEntityId)) {
        float localX = node->formationOffsetX;
        float localZ = node->formationOffsetZ;
        if (laneEntry->applyDynamicOffset != 0u) {
          localX += laneEntry->dynamicOffsetX;
          localZ += laneEntry->dynamicOffsetZ;
        }
        position.x = mFormationCenter.x + localX;
        position.z = mFormationCenter.z + localZ;
      }
    }

    (void)CoordCacheInsertOrAssign(mCoordCacheSecondary, unitEntityId, position);
    *dest = position;
    return dest;
  }

  /**
   * Address: 0x0056A150 (FUN_0056A150, Moho::CFormationInstance::Func10)
   *
   * What it does:
   * Returns lane-provided formation vector when present, else unit position.
   */
  Wm3::Vec3f* CAiFormationInstance::Func10(Wm3::Vec3f* const out, Unit* const unit, SFormationLaneEntry* laneEntry)
  {
    if (!out) {
      return out;
    }

    if (!unit || unit->IsDead()) {
      out->x = 0.0f;
      out->y = 0.0f;
      out->z = 0.0f;
      return out;
    }

    if (laneEntry != nullptr) {
      const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
      if (const SFormationLaneUnitNode* const node = LaneMapFindNode(laneEntry->unitMap, unitEntityId)) {
        if (node->formationVector.x != 0.0f || node->formationVector.y != 0.0f || node->formationVector.z != 0.0f) {
          *out = node->formationVector;
          return out;
        }
      }
    }

    *out = unit->GetPosition();
    return out;
  }

  /**
   * Address: 0x0056A220 (FUN_0056A220, Moho::CFormationInstance::AddUnit)
   *
   * What it does:
   * Adds one live unit weak-ref to this formation and marks plan rebuild.
   */
  void CAiFormationInstance::AddUnit(Unit* const unit)
  {
    if (!unit || unit->IsDead()) {
      return;
    }

    bool alreadyPresent = false;
    std::vector<Unit*> kept;
    kept.reserve(mUnits.size());
    for (SFormationLinkedUnitRef* it = mUnits.begin(); it != mUnits.end(); ++it) {
      Unit* const linkedUnit = DecodeLinkedRefUnit(*it);
      if (linkedUnit == nullptr || linkedUnit->IsDead() || linkedUnit->DestroyQueued()) {
        UnlinkLinkedRef(*it);
        continue;
      }

      if (linkedUnit == unit) {
        alreadyPresent = true;
      }

      kept.push_back(linkedUnit);
      UnlinkLinkedRef(*it);
    }

    mUnits.ResetStorageToInline();
    for (Unit* const keptUnit : kept) {
      SFormationLinkedUnitRef linked{};
      mUnits.push_back(linked);
      RelinkLinkedRef(mUnits.back(), keptUnit);
    }

    if (alreadyPresent) {
      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      gpg::Warnf(
        "Attempted to re-add existing unit (%d - %s) to formation (%d)",
        static_cast<int>(reinterpret_cast<std::uintptr_t>(unit)),
        blueprint != nullptr ? blueprint->mBlueprintId.c_str() : "<null>",
        static_cast<int>(reinterpret_cast<std::uintptr_t>(this))
      );
      return;
    }

    SFormationLinkedUnitRef linked{};
    mUnits.push_back(linked);
    RelinkLinkedRef(mUnits.back(), unit);
    mPlanUpdateRequested = 1u;
  }

  /**
   * Address: 0x0056A300 (FUN_0056A300, Moho::CFormationInstance::RemoveUnit)
   *
   * What it does:
   * Removes one unit from lane maps and linked unit-reference storage.
   */
  void CAiFormationInstance::RemoveUnit(Unit* const unit)
  {
    if (!unit) {
      return;
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    const std::int32_t laneIndex = Func5(unit) ? 1 : 0;
    SFormationLaneEntry* lane = mLanes[laneIndex].begin();
    SFormationLaneEntry* const laneEnd = mLanes[laneIndex].end();
    while (lane != laneEnd) {
      if (LaneMapFindNode(lane->unitMap, unitEntityId) != nullptr) {
        EraseLaneMapNodeByEntityId(lane->unitMap, unitEntityId);
        if (DecodeUnitOwnerSlotWord(lane->linkedUnitBackLinkHeadWord) == unit) {
          UnlinkWeakWordNode(lane->linkedUnitBackLinkHeadWord, lane->linkedUnitBackLinkNextWord);
        }
      }
      ++lane;
    }

    std::vector<Unit*> kept;
    kept.reserve(mUnits.size());
    for (SFormationLinkedUnitRef* it = mUnits.begin(); it != mUnits.end(); ++it) {
      Unit* const linkedUnit = DecodeLinkedRefUnit(*it);
      if (linkedUnit != nullptr && linkedUnit != unit) {
        kept.push_back(linkedUnit);
      }
      UnlinkLinkedRef(*it);
    }

    mUnits.ResetStorageToInline();
    for (Unit* const keptUnit : kept) {
      SFormationLinkedUnitRef linked{};
      mUnits.push_back(linked);
      RelinkLinkedRef(mUnits.back(), keptUnit);
    }
  }

  /**
   * Address: 0x0056A440 (FUN_0056A440, Moho::CFormationInstance::Func17)
   *
   * What it does:
   * Returns true if `unit` exists in the lane map (or full linked set when
   * `checkAll` is true).
   */
  bool CAiFormationInstance::Func17(Unit* const unit, const bool checkAll) const
  {
    if (!unit) {
      return false;
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    const std::int32_t laneIndex = Func5(unit) ? 1 : 0;
    const SFormationLaneEntry* lane = mLanes[laneIndex].begin();
    const SFormationLaneEntry* const laneEnd = mLanes[laneIndex].end();
    while (lane != laneEnd) {
      if (LaneMapFindNode(lane->unitMap, unitEntityId) != nullptr) {
        return true;
      }
      ++lane;
    }

    if (!checkAll) {
      return false;
    }

    const SFormationLinkedUnitRef* it = mUnits.begin();
    const SFormationLinkedUnitRef* const end = mUnits.end();
    while (it != end) {
      if (DecodeLinkedRefUnit(*it) == unit) {
        return true;
      }
      ++it;
    }

    return false;
  }

  /**
   * Address: 0x005691E0 (FUN_005691E0, Moho::CAiFormationInstance::RemoveDeadUnits)
   *
   * What it does:
   * Compacts linked formation unit refs by removing null/dead/destroy-queued
   * units and returns whether `checkForUnit` is still present after cleanup.
   */
  bool CAiFormationInstance::RemoveDeadUnits(Unit* const checkForUnit)
  {
    bool hasCheckForUnit = false;
    std::vector<Unit*> kept;
    kept.reserve(mUnits.size());

    for (SFormationLinkedUnitRef* it = mUnits.begin(); it != mUnits.end(); ++it) {
      Unit* const linkedUnit = DecodeLinkedRefUnit(*it);
      const bool removeEntry =
        linkedUnit == nullptr || linkedUnit->IsDead() || linkedUnit->DestroyQueued();
      if (!removeEntry) {
        if (checkForUnit != nullptr && linkedUnit == checkForUnit) {
          hasCheckForUnit = true;
        }
        kept.push_back(linkedUnit);
      }
      UnlinkLinkedRef(*it);
    }

    mUnits.ResetStorageToInline();
    for (Unit* const keptUnit : kept) {
      SFormationLinkedUnitRef linked{};
      mUnits.push_back(linked);
      RelinkLinkedRef(mUnits.back(), keptUnit);
    }

    return hasCheckForUnit;
  }

  /**
   * Address: 0x00569B60 (FUN_00569B60, Moho::CFormationInstance::Func19)
   *
   * What it does:
   * Returns formation forward vector for contained units, else zero.
   */
  Wm3::Vec3f* CAiFormationInstance::Func19(Wm3::Vec3f* const out, Unit* const unit) const
  {
    if (!out) {
      return out;
    }

    if (Func17(unit, false)) {
      *out = mForwardVector;
    } else {
      *out = kZeroForwardVector;
    }
    return out;
  }

  /**
   * Address: 0x00569C20 (FUN_00569C20, Moho::CFormationInstance::Func21)
   *
   * What it does:
   * Returns lane slot availability status for `unit`, or aggregate
   * all-lane availability when no valid unit target is provided.
   */
  bool CAiFormationInstance::Func21(Unit* const unit) const
  {
    if (unit != nullptr && !unit->IsDead() && Func17(unit, false)) {
      if (SFormationLaneEntry* const lane = const_cast<CAiFormationInstance*>(this)->Func6(unit); lane != nullptr) {
        return lane->slotAvailable != 0u;
      }
      return true;
    }

    for (std::int32_t laneIndex = 0; laneIndex < 2; ++laneIndex) {
      const SFormationLaneEntry* lane = mLanes[laneIndex].begin();
      const SFormationLaneEntry* const laneEnd = mLanes[laneIndex].end();
      while (lane != laneEnd) {
        if (lane->slotAvailable == 0u) {
          return false;
        }
        ++lane;
      }
    }
    return true;
  }

  /**
   * Address: 0x0059A790 (FUN_0059A790, Moho::CAiFormationInstance::Func11)
   *
   * What it does:
   * Returns one lane-node speed sample for `unit`.
   */
  float CAiFormationInstance::Func11(Unit* const unit, SFormationLaneEntry* const laneEntry)
  {
    if (!unit || laneEntry == nullptr) {
      return 0.0f;
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    const SFormationLaneUnitNode* const node = LaneMapFindNode(laneEntry->unitMap, unitEntityId);
    return node ? node->speedBandMid : 0.0f;
  }

  /**
   * Address: 0x0059A7D0 (FUN_0059A7D0, Moho::CAiFormationInstance::Func12)
   *
   * What it does:
   * Computes one integer move-priority weight from lane speed data.
   */
  std::int32_t CAiFormationInstance::Func12(Unit* const unit, SFormationLaneEntry* laneEntry)
  {
    if (!unit) {
      return 1;
    }

    Unit* const runtimeUnit = unit->IsUnit();
    if (runtimeUnit == nullptr) {
      return 1;
    }

    if (runtimeUnit->GuardedUnitRef.ResolveObjectPtr<Unit>() != nullptr) {
      return 1;
    }

    if (laneEntry == nullptr) {
      laneEntry = Func6(unit);
      if (laneEntry == nullptr) {
        return 1;
      }
    }

    const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
    const SFormationLaneUnitNode* const node = LaneMapFindNode(laneEntry->unitMap, unitEntityId);
    if (!node || node->speedBandHigh <= 0.0f) {
      return 1;
    }

    const std::int32_t scaled = static_cast<std::int32_t>(node->speedBandHigh) * 10;
    return scaled > 1 ? scaled : 1;
  }

  /**
   * Address: 0x0059A620 (FUN_0059A620, Moho::CAiFormationInstance::CalcFormationSpeed)
   *
   * What it does:
   * Computes one lane speed and per-unit speed scale for formation movement.
   */
  float CAiFormationInstance::CalcFormationSpeed(
    Unit* const unit,
    float* const speedScaleOut,
    SFormationLaneEntry* const laneEntry
  )
  {
    if (!unit || !CommandIsForm()) {
      return 0.0f;
    }

    Unit* const laneLeader = Func14(unit, laneEntry);
    if (laneLeader != nullptr) {
      if (!Func17(laneLeader, false) && !laneLeader->IsMobile()) {
        return 0.0f;
      }
    }

    Unit* const runtimeUnit = unit->IsUnit();
    if (!runtimeUnit || !runtimeUnit->AiNavigator || runtimeUnit->AiNavigator->IsIgnoringFormation() || laneEntry == nullptr) {
      return 0.0f;
    }

    *speedScaleOut = 0.85f;
    bool canScaleWithLaneDelta = runtimeUnit->AiNavigator->FollowingLeader() || laneLeader == unit;
    if (laneEntry->speedAnchor > 0.0f && canScaleWithLaneDelta) {
      const std::uint32_t unitEntityId = UnitEntityIdWord(unit);
      if (const SFormationLaneUnitNode* const node = LaneMapFindNode(laneEntry->unitMap, unitEntityId); node != nullptr) {
        const RUnitBlueprint* const blueprint = unit->GetBlueprint();
        const float laneFactor = (blueprint != nullptr && blueprint->Air.CanFly != 0u) ? 1.5f : 4.0f;
        float delta = (node->speedBandLow - laneEntry->speedAnchor) * laneFactor;
        if (delta > 20.0f) {
          delta = 20.0f;
        } else if (delta < -5.0f) {
          delta = -5.0f;
        }
        *speedScaleOut = (delta * 0.1f) + 1.0f;
      }
    }

    return laneEntry->preferredSpeed;
  }

  /**
   * Address: 0x0059A870 (FUN_0059A870, Moho::CAiFormationInstance::Func14)
   *
   * What it does:
   * Resolves lane leader unit for one member unit and lane context.
   */
  Unit* CAiFormationInstance::Func14(Unit* const unit, SFormationLaneEntry* const laneEntry)
  {
    if (!unit) {
      return nullptr;
    }

    if (mCommandType == EUnitCommandType::UNITCOMMAND_Guard) {
      if (Unit* const runtimeUnit = unit->IsUnit(); runtimeUnit != nullptr) {
        return runtimeUnit->GuardedUnitRef.ResolveObjectPtr<Unit>();
      }
      return nullptr;
    }

    if (laneEntry == nullptr || unit->IsDead()) {
      return nullptr;
    }

    const std::int32_t laneIndex = Func5(unit) ? 1 : 0;
    return ResolveUpdateLaneLeader(laneIndex, *this, *laneEntry);
  }

  /**
   * Address: 0x0059AE80 (FUN_0059AE80, Moho::CAiFormationInstance::Update)
   *
   * What it does:
   * Refreshes any pending lane plan work, then walks both formation lane sets
   * to resolve leaders, update per-unit lane metrics, and emit formation
   * change events when a lane stays actionable.
   */
  void CAiFormationInstance::Update()
  {
    if (mPlanUpdateRequested != 0u) {
      mPlanUpdateRequested = 0u;
      (void)RemoveDeadUnits(nullptr);
    }

    if (!CommandIsForm() || UnitCount() == 0) {
      return;
    }

    if (mCommandType != EUnitCommandType::UNITCOMMAND_Guard) {
      MergeOverlappingLaneBands(*this);
    }

    const int unitCount = UnitCount();
    const bool overCapacity = mMaxUnitSlotCount > 0 && unitCount > mMaxUnitSlotCount;

    for (std::int32_t laneIndex = 0; laneIndex < 2; ++laneIndex) {
      SFormationLaneEntry* lane = mLanes[laneIndex].begin();
      SFormationLaneEntry* const laneEnd = mLanes[laneIndex].end();
      while (lane != laneEnd) {
        lane->slotAvailable = 0u;
        lane->applyDynamicOffset = 0u;

        Unit* const leader = ResolveUpdateLaneLeader(laneIndex, *this, *lane);
        if (leader == nullptr || leader->IsDead()) {
          ++lane;
          continue;
        }

        float leaderSpeedScale = 0.0f;
        const float leaderSpeed = CalcFormationSpeed(leader, &leaderSpeedScale, lane);
        lane->preferredSpeed = leaderSpeed;
        lane->speedAnchor = leaderSpeedScale;

        SCoordsVec2 laneTarget{};
        if (mCommandType == EUnitCommandType::UNITCOMMAND_Guard) {
          laneTarget.x = mFormationCenter.x;
          laneTarget.z = mFormationCenter.z;
        } else {
          (void)Func9(&laneTarget, leader, lane);
        }

        SFormationLaneUnitMap& unitMap = lane->unitMap;
        SFormationLaneUnitNode* const head = unitMap.head;
        bool hasLiveUnit = false;
        if (head != nullptr) {
          SFormationLaneUnitNode* node = head->left;
          while (node != nullptr && node != head && node->isNil == 0u) {
            Unit* const unit = DecodeUnitOwnerSlotWord(node->linkedUnitOwnerWord);
            if (unit != nullptr && !unit->IsDead() && !unit->DestroyQueued()) {
              hasLiveUnit = true;

              SCoordsVec2 desiredPos{};
              if (mCommandType == EUnitCommandType::UNITCOMMAND_Guard) {
                (void)GetFormationPosition(&desiredPos, unit, lane);
              } else {
                (void)Func9(&desiredPos, unit, lane);

                if (Unit* const runtimeUnit = unit->IsUnit();
                    runtimeUnit != nullptr && runtimeUnit->AiNavigator != nullptr
                    && runtimeUnit->AiNavigator->IsIgnoringFormation()) {
                  SOCellPos adjustedCell{};
                  (void)GetAdjustedFormationPosition(&adjustedCell, unit, lane);
                  desiredPos.x = static_cast<float>(adjustedCell.x);
                  desiredPos.z = static_cast<float>(adjustedCell.z);
                }
              }

              const Wm3::Vec3f& currentPos = unit->GetPosition();
              const float dx = desiredPos.x - currentPos.x;
              const float dz = desiredPos.z - currentPos.z;
              const float targetDx = desiredPos.x - laneTarget.x;
              const float targetDz = desiredPos.z - laneTarget.z;
              float memberSpeedScale = 0.0f;

              node->formationOffsetX = targetDx;
              node->formationOffsetZ = targetDz;
              node->formationVector.x = dx;
              node->formationVector.y = 0.0f;
              node->formationVector.z = dz;
              node->formationWeight = std::sqrt((dx * dx) + (dz * dz));
              node->speedBandLow = node->formationWeight;
              node->speedBandMid = Func11(unit, lane);
              node->speedBandHigh = CalcFormationSpeed(unit, &memberSpeedScale, lane);
              node->leaderPriority = Func12(unit, lane);
            }

            node = NextLaneMapNodeInOrder(node, head);
          }
        }

        if (hasLiveUnit && !overCapacity && leaderSpeed > 0.0f) {
          lane->applyDynamicOffset = 1u;
          lane->slotAvailable = 1u;
          lane->dynamicOffsetX = laneTarget.x - mFormationCenter.x;
          lane->dynamicOffsetZ = laneTarget.z - mFormationCenter.z;
          lane->overlapAnchorX = std::fabs(lane->dynamicOffsetX);
          lane->overlapAnchorZ = std::fabs(lane->dynamicOffsetZ);
          DispatchFormationUpdateEvent(1, mUnitLinkListHead);
        }

        ++lane;
      }
    }
  }

  /**
   * Address: 0x00569BF0 (FUN_00569BF0)
   *
   * What it does:
   * Returns true when current command type is one of the formation commands.
   */
  bool CAiFormationInstance::CommandIsForm() const
  {
    switch (mCommandType) {
    case EUnitCommandType::UNITCOMMAND_FormMove:
    case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
    case EUnitCommandType::UNITCOMMAND_FormPatrol:
    case EUnitCommandType::UNITCOMMAND_FormAttack:
    case EUnitCommandType::UNITCOMMAND_Guard:
      return true;
    default:
      return false;
    }
  }

  /**
   * Address: 0x0056A4F0 (FUN_0056A4F0)
   *
   * float
   *
   * What it does:
   * Updates formation scale and marks the plan for rebuild when value changed.
   */
  void CAiFormationInstance::Func22(const float scale)
  {
    if (!BinaryFloatNotEqual(mFormationUpdateScale, scale)) {
      return;
    }

    mFormationUpdateScale = scale;
    mPlanUpdateRequested = 1;
  }

  /**
   * Address: 0x0056A520 (FUN_0056A520)
   *
   * Wm3::Quaternion<float> const&
   *
   * What it does:
   * Sets formation orientation, recomputes forward vector, and requests a plan rebuild.
   */
  void CAiFormationInstance::SetOrientation(const Wm3::Quatf& orientation)
  {
    if (QuaternionEqualsExact(mOrientation, orientation)) {
      return;
    }

    mOrientation = orientation;
    if (QuaternionEqualsExact(mOrientation, kZeroQuaternion) || mCommandType == EUnitCommandType::UNITCOMMAND_Move) {
      mForwardVector = kZeroForwardVector;
    } else {
      const float x = mOrientation.x;
      const float y = mOrientation.y;
      const float z = mOrientation.z;
      const float w = mOrientation.w;
      mForwardVector.x = ((x * z) + (y * w)) * 2.0f;
      mForwardVector.y = ((z * w) - (x * y)) * 2.0f;
      mForwardVector.z = 1.0f - (((y * y) + (z * z)) * 2.0f);
    }

    mPlanUpdateRequested = 1;
  }

  /**
   * Address: 0x0056A680 (FUN_0056A680)
   *
   * Wm3::Quaternion<float>*
   *
   * What it does:
   * Copies the current orientation into `outOrientation`.
   */
  Wm3::Quatf* CAiFormationInstance::GetOrientation(Wm3::Quatf* const outOrientation) const
  {
    *outOrientation = mOrientation;
    return outOrientation;
  }

  /**
   * Address: 0x00569A00 (FUN_00569A00)
   *
   * What it does:
   * Returns the active command type for this formation.
   */
  EUnitCommandType CAiFormationInstance::GetCommandType() const
  {
    return mCommandType;
  }

  /**
   * Address: 0x0059AA20 (FUN_0059AA20, Moho::CAiFormationInstance::FindSlotFor)
   *
   * What it does:
   * Finds one valid slot near `pos` (spiral search capped at 2000 probes),
   * records it in `mOccupiedSlots`, and falls back to current unit position
   * when no free slot can be found.
   */
  SCoordsVec2* CAiFormationInstance::FindSlotFor(SCoordsVec2* const dest, const SCoordsVec2* const pos, Unit* const unit)
  {
    if (dest == nullptr || pos == nullptr || unit == nullptr) {
      return dest;
    }

    Unit* const runtimeUnit = unit->IsUnit();
    const bool fallbackToInputPos = runtimeUnit == nullptr
      || runtimeUnit->IsDead()
      || runtimeUnit->CommandQueue == nullptr
      || mCommandType == EUnitCommandType::UNITCOMMAND_Guard
      || mFormationUpdateScale < 1.0f
      || Func5(runtimeUnit);
    if (fallbackToInputPos) {
      dest->x = pos->x;
      dest->z = pos->z;
      return dest;
    }

    const RUnitBlueprint* const blueprint = runtimeUnit->GetBlueprint();
    if (blueprint == nullptr || mSim == nullptr || mSim->mOGrid == nullptr || mSim->mMapData == nullptr) {
      dest->x = pos->x;
      dest->z = pos->z;
      return dest;
    }

    const SFootprint footprint = blueprint->mFootprint;
    const std::int32_t footprintSize = std::max<int>(footprint.mSizeX, footprint.mSizeZ);
    const std::int32_t laneToken = Func5(runtimeUnit) ? 1 : 0;
    const bool useWholeMap = (runtimeUnit->ArmyRef != nullptr) ? runtimeUnit->ArmyRef->UseWholeMap() : false;

    auto reserveSlot = [this, footprintSize, laneToken](const SCoordsVec2& slotPos) {
      SFormationOccupiedSlot slot{};
      slot.position = slotPos;
      slot.footprintSize = footprintSize;
      slot.laneToken = laneToken;
      mOccupiedSlots.push_back(slot);
    };

    if (CanPlaceFormationSlot(*this, *pos, footprint, footprintSize, useWholeMap, laneToken)) {
      reserveSlot(*pos);
      dest->x = pos->x;
      dest->z = pos->z;
      return dest;
    }

    std::int32_t attempts = 0;
    for (std::int32_t radius = 1; attempts < 2000; ++radius) {
      for (std::int32_t dx = -radius; dx <= radius && attempts < 2000; ++dx) {
        const std::int32_t step = (dx == -radius || dx == radius) ? 1 : (radius * 2);
        for (std::int32_t dz = -radius; dz <= radius && attempts < 2000; dz += step) {
          ++attempts;

          SCoordsVec2 candidate{};
          candidate.x = pos->x + static_cast<float>(dx);
          candidate.z = pos->z + static_cast<float>(dz);
          if (!CanPlaceFormationSlot(*this, candidate, footprint, footprintSize, useWholeMap, laneToken)) {
            continue;
          }

          reserveSlot(candidate);
          dest->x = candidate.x;
          dest->z = candidate.z;
          return dest;
        }
      }
    }

    if (CUnitCommand* const nextCommand = runtimeUnit->CommandQueue->GetNextCommand();
        nextCommand != nullptr && IsBusyFormationQueueCommand(nextCommand->mVarDat.mCmdType)) {
      reserveSlot(*pos);
      dest->x = pos->x;
      dest->z = pos->z;
      return dest;
    }

    const Wm3::Vec3f& unitPos = runtimeUnit->GetPosition();
    dest->x = unitPos.x;
    dest->z = unitPos.z;
    return dest;
  }

  /**
   * Address: 0x0059A570 (FUN_0059A570)
   *
   * Moho::SCoordsVec2 const&, int, int
   *
   * What it does:
   * Returns true when no occupied slot for `laneToken` overlaps `position` by `footprintSize`.
   */
  bool CAiFormationInstance::Func27(
    const SCoordsVec2& position,
    const std::int32_t footprintSize,
    const std::int32_t laneToken
  ) const
  {
    const SFormationOccupiedSlot* slot = mOccupiedSlots.begin();
    const SFormationOccupiedSlot* const slotEnd = mOccupiedSlots.end();
    while (slot != slotEnd) {
      if (slot->laneToken == laneToken) {
        const std::int32_t maxFootprint =
          slot->footprintSize < footprintSize ? footprintSize : slot->footprintSize;
        const float dx = std::fabs(position.x - slot->position.x);
        if (dx < static_cast<float>(maxFootprint)) {
          const float dz = std::fabs(position.z - slot->position.z);
          if (dz < static_cast<float>(maxFootprint)) {
            return false;
          }
        }
      }
      ++slot;
    }

    return true;
  }
} // namespace moho
