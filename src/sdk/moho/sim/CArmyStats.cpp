#include "CArmyStats.h"

#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <typeinfo>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiBrain.h"
#include "moho/sim/SConditionTriggerTypes.h"

namespace
{
  constexpr const char* kOnStatsTriggerScriptName = "OnStatsTrigger";

  [[nodiscard]] bool CategorySetHasAnyBits(const moho::EntityCategorySet& categorySet)
  {
    const moho::BVIntSet& bits = categorySet.Bits();
    const unsigned int sentinel = bits.Max();
    return bits.GetNext(std::numeric_limits<unsigned int>::max()) != sentinel;
  }

  [[nodiscard]] float ResolveConditionValue(const moho::SCondition& condition)
  {
    moho::CArmyStatItem* const item = condition.mItem;
    if (item == nullptr) {
      return 0.0f;
    }

    if (CategorySetHasAnyBits(condition.mCat)) {
      return item->SumCategory(&condition.mCat);
    }

    switch (item->mType) {
      case moho::EStatType::kFloat:
        return item->GetFloat(false);
      case moho::EStatType::kInt:
        return static_cast<float>(item->GetInt(false));
      case moho::EStatType::kString:
      default: {
        msvc8::string value;
        item->SetValueCopy(&value);
        return static_cast<float>(std::atof(value.c_str()));
      }
    }
  }

  [[nodiscard]] bool EvaluateCondition(const moho::SCondition& condition, const float value)
  {
    switch (condition.mOp) {
      case moho::TRIGGER_GreaterThan:
        return value > condition.mVal;
      case moho::TRIGGER_GreaterThanOrEqual:
        return value >= condition.mVal;
      case moho::TRIGGER_LessThan:
        return value < condition.mVal;
      case moho::TRIGGER_LessThanOrEqual:
        return value <= condition.mVal;
      default:
        return false;
    }
  }

  [[nodiscard]] int CompareNameIndexKey(const msvc8::string& lhs, const msvc8::string& rhs)
  {
    return std::strcmp(lhs.c_str(), rhs.c_str());
  }

  [[nodiscard]] std::int32_t AtomicExchangeAddI32(volatile std::int32_t* const slot, const std::int32_t value) noexcept
  {
#if defined(_MSC_VER)
    return static_cast<std::int32_t>(
      _InterlockedExchangeAdd(reinterpret_cast<volatile long*>(slot), static_cast<long>(value))
    );
#else
    const std::int32_t previous = *slot;
    *slot = previous + value;
    return previous;
#endif
  }

  [[nodiscard]] std::int32_t
  AtomicCompareExchangeI32(volatile std::int32_t* const slot, const std::int32_t desired, const std::int32_t expected) noexcept
  {
#if defined(_MSC_VER)
    return static_cast<std::int32_t>(
      _InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(slot),
        static_cast<long>(desired),
        static_cast<long>(expected)
      )
    );
#else
    const std::int32_t observed = *slot;
    if (observed == expected) {
      *slot = desired;
    }
    return observed;
#endif
  }

  [[nodiscard]] float IntBitsToFloat(const std::int32_t bits) noexcept
  {
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
  }

  [[nodiscard]] std::int32_t FloatToIntBits(const float value) noexcept
  {
    std::int32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  [[nodiscard]] moho::ArmyNameIndexNode* FindNameIndexNode(
    moho::ArmyNameIndexTree* const tree, const msvc8::string& statPath
  )
  {
    if (tree == nullptr || tree->head == nullptr) {
      return nullptr;
    }

    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      const int keyCmp = CompareNameIndexKey(statPath, node->key);
      if (keyCmp == 0) {
        return node;
      }
      node = (keyCmp < 0) ? node->left : node->right;
    }

    return nullptr;
  }

  [[nodiscard]] moho::CArmyStatItem* FindArmyChildByName(moho::CArmyStatItem* parent, const msvc8::string& token)
  {
    if (parent == nullptr) {
      return nullptr;
    }

    return static_cast<moho::CArmyStatItem*>(parent->FindDirectChildByName(token));
  }

  [[nodiscard]] moho::ArmyBlueprintStatNode* CreateBlueprintTreeSentinel()
  {
    auto* const head = new moho::ArmyBlueprintStatNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = 1;
    head->isNil = 1;
    return head;
  }

  template <typename TNode>
  void DestroyNilTree(TNode* node, const std::uint8_t TNode::* nilField)
  {
    if (node == nullptr || node->*nilField != 0u) {
      return;
    }

    DestroyNilTree(node->left, nilField);
    DestroyNilTree(node->right, nilField);
    delete node;
  }

  [[nodiscard]] moho::ArmyBlueprintStatNode*
  NextBlueprintNode(moho::ArmyBlueprintStatNode* node, moho::ArmyBlueprintStatNode* head)
  {
    if (node == nullptr || head == nullptr) {
      return head;
    }
    if (node->isNil != 0u) {
      return node->parent;
    }

    if (node->right != nullptr && node->right->isNil == 0u) {
      node = node->right;
      while (node->left != nullptr && node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    moho::ArmyBlueprintStatNode* parent = node->parent;
    while (parent != nullptr && parent->isNil == 0u && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return (parent != nullptr) ? parent : head;
  }

  [[nodiscard]] const moho::ArmyBlueprintStatNode*
  NextBlueprintNode(const moho::ArmyBlueprintStatNode* node, const moho::ArmyBlueprintStatNode* head)
  {
    if (node == nullptr || head == nullptr) {
      return head;
    }
    if (node->isNil != 0u) {
      return node->parent;
    }

    if (node->right != nullptr && node->right->isNil == 0u) {
      node = node->right;
      while (node->left != nullptr && node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    const moho::ArmyBlueprintStatNode* parent = node->parent;
    while (parent != nullptr && parent->isNil == 0u && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return (parent != nullptr) ? parent : head;
  }

  [[nodiscard]] int CompareBlueprintStatKey(
    const moho::ArmyBlueprintNameView* const lhs,
    const moho::ArmyBlueprintNameView* const rhs
  ) noexcept
  {
    const std::uintptr_t lhsValue = reinterpret_cast<std::uintptr_t>(lhs);
    const std::uintptr_t rhsValue = reinterpret_cast<std::uintptr_t>(rhs);
    if (lhsValue < rhsValue) {
      return -1;
    }
    if (lhsValue > rhsValue) {
      return 1;
    }
    return 0;
  }

  [[nodiscard]] bool IsBlueprintNodeNil(const moho::ArmyBlueprintStatNode* const node)
  {
    return node == nullptr || node->isNil != 0u;
  }

  [[nodiscard]] moho::ArmyBlueprintStatNode*
  BlueprintNodeMin(moho::ArmyBlueprintStatNode* node, moho::ArmyBlueprintStatNode* head)
  {
    while (!IsBlueprintNodeNil(node) && !IsBlueprintNodeNil(node->left)) {
      node = node->left;
    }
    return IsBlueprintNodeNil(node) ? head : node;
  }

  [[nodiscard]] moho::ArmyBlueprintStatNode*
  BlueprintNodeMax(moho::ArmyBlueprintStatNode* node, moho::ArmyBlueprintStatNode* head)
  {
    while (!IsBlueprintNodeNil(node) && !IsBlueprintNodeNil(node->right)) {
      node = node->right;
    }
    return IsBlueprintNodeNil(node) ? head : node;
  }

  void RecomputeBlueprintExtrema(moho::ArmyBlueprintStatTree* const tree)
  {
    if (tree == nullptr || tree->head == nullptr) {
      return;
    }

    moho::ArmyBlueprintStatNode* const head = tree->head;
    moho::ArmyBlueprintStatNode* const root = head->parent;
    if (IsBlueprintNodeNil(root)) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = BlueprintNodeMin(root, head);
    head->right = BlueprintNodeMax(root, head);
  }

  void RotateBlueprintLeft(moho::ArmyBlueprintStatTree* const tree, moho::ArmyBlueprintStatNode* const node)
  {
    moho::ArmyBlueprintStatNode* const head = tree->head;
    moho::ArmyBlueprintStatNode* const pivot = node->right;
    node->right = pivot->left;
    if (!IsBlueprintNodeNil(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void RotateBlueprintRight(moho::ArmyBlueprintStatTree* const tree, moho::ArmyBlueprintStatNode* const node)
  {
    moho::ArmyBlueprintStatNode* const head = tree->head;
    moho::ArmyBlueprintStatNode* const pivot = node->left;
    node->left = pivot->right;
    if (!IsBlueprintNodeNil(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void FixupAfterBlueprintInsert(moho::ArmyBlueprintStatTree* const tree, moho::ArmyBlueprintStatNode* node)
  {
    moho::ArmyBlueprintStatNode* const head = tree->head;
    while (node != head->parent && node->parent->color == 0u) {
      moho::ArmyBlueprintStatNode* const parent = node->parent;
      moho::ArmyBlueprintStatNode* const grand = parent->parent;
      if (grand == nullptr || grand == head) {
        break;
      }

      if (parent == grand->left) {
        moho::ArmyBlueprintStatNode* const uncle = grand->right;
        if (!IsBlueprintNodeNil(uncle) && uncle->color == 0u) {
          parent->color = 1;
          uncle->color = 1;
          grand->color = 0;
          node = grand;
          continue;
        }

        if (node == parent->right) {
          node = parent;
          RotateBlueprintLeft(tree, node);
        }

        node->parent->color = 1;
        grand->color = 0;
        RotateBlueprintRight(tree, grand);
        continue;
      }

      moho::ArmyBlueprintStatNode* const uncle = grand->left;
      if (!IsBlueprintNodeNil(uncle) && uncle->color == 0u) {
        parent->color = 1;
        uncle->color = 1;
        grand->color = 0;
        node = grand;
        continue;
      }

      if (node == parent->left) {
        node = parent;
        RotateBlueprintRight(tree, node);
      }

      node->parent->color = 1;
      grand->color = 0;
      RotateBlueprintLeft(tree, grand);
    }

    if (head->parent != nullptr && head->parent != head) {
      head->parent->color = 1;
    }
  }

  [[nodiscard]] moho::ArmyBlueprintStatNode* FindOrInsertBlueprintStatNode(
    moho::ArmyBlueprintStatTree* const tree,
    const moho::ArmyBlueprintNameView* const blueprintName
  )
  {
    if (tree == nullptr || tree->head == nullptr || blueprintName == nullptr) {
      return nullptr;
    }

    moho::ArmyBlueprintStatNode* const head = tree->head;
    moho::ArmyBlueprintStatNode* parent = head;
    moho::ArmyBlueprintStatNode* node = head->parent;
    int compareResult = 0;
    while (!IsBlueprintNodeNil(node)) {
      parent = node;
      compareResult = CompareBlueprintStatKey(blueprintName, node->blueprintName);
      if (compareResult == 0) {
        return node;
      }
      node = (compareResult < 0) ? node->left : node->right;
    }

    auto* const inserted = new moho::ArmyBlueprintStatNode{};
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent;
    inserted->blueprintName = blueprintName;
    inserted->value = 0.0f;
    inserted->color = 0;
    inserted->isNil = 0;

    if (parent == head) {
      head->parent = inserted;
    } else if (compareResult < 0) {
      parent->left = inserted;
    } else {
      parent->right = inserted;
    }

    ++tree->size;
    FixupAfterBlueprintInsert(tree, inserted);
    RecomputeBlueprintExtrema(tree);
    return inserted;
  }

  [[nodiscard]] moho::ArmyNameIndexNode* CreateNameIndexSentinel()
  {
    auto* const head = new moho::ArmyNameIndexNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = 1;
    head->isNil = 1;
    return head;
  }

  [[nodiscard]] moho::ArmyNameIndexNode* NextNameIndexNode(moho::ArmyNameIndexNode* node, moho::ArmyNameIndexNode* head)
  {
    if (node == nullptr || head == nullptr) {
      return head;
    }
    if (node->isNil != 0u) {
      return node->parent;
    }

    if (node->right != nullptr && node->right->isNil == 0u) {
      node = node->right;
      while (node->left != nullptr && node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    moho::ArmyNameIndexNode* parent = node->parent;
    while (parent != nullptr && parent->isNil == 0u && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return (parent != nullptr) ? parent : head;
  }

  [[nodiscard]] bool IsNameIndexNil(const moho::ArmyNameIndexNode* node)
  {
    return node == nullptr || node->isNil != 0u;
  }

  [[nodiscard]] moho::ArmyNameIndexNode* NameIndexMin(moho::ArmyNameIndexNode* node, moho::ArmyNameIndexNode* head)
  {
    while (!IsNameIndexNil(node) && !IsNameIndexNil(node->left)) {
      node = node->left;
    }
    return IsNameIndexNil(node) ? head : node;
  }

  [[nodiscard]] moho::ArmyNameIndexNode* NameIndexMax(moho::ArmyNameIndexNode* node, moho::ArmyNameIndexNode* head)
  {
    while (!IsNameIndexNil(node) && !IsNameIndexNil(node->right)) {
      node = node->right;
    }
    return IsNameIndexNil(node) ? head : node;
  }

  void RecomputeNameIndexExtrema(moho::ArmyNameIndexTree* tree)
  {
    if (tree == nullptr || tree->head == nullptr) {
      return;
    }

    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* const root = head->parent;
    if (IsNameIndexNil(root)) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = NameIndexMin(root, head);
    head->right = NameIndexMax(root, head);
  }

  void ReplaceNameIndexSubtree(
    moho::ArmyNameIndexTree* tree, moho::ArmyNameIndexNode* oldNode, moho::ArmyNameIndexNode* newNode
  )
  {
    moho::ArmyNameIndexNode* const head = tree->head;
    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (!IsNameIndexNil(newNode)) {
      newNode->parent = oldNode->parent;
    }
  }

  void RotateNameIndexLeft(moho::ArmyNameIndexTree* tree, moho::ArmyNameIndexNode* node)
  {
    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* const pivot = node->right;
    node->right = pivot->left;
    if (!IsNameIndexNil(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void RotateNameIndexRight(moho::ArmyNameIndexTree* tree, moho::ArmyNameIndexNode* node)
  {
    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* const pivot = node->left;
    node->left = pivot->right;
    if (!IsNameIndexNil(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void FixupAfterNameIndexInsert(moho::ArmyNameIndexTree* const tree, moho::ArmyNameIndexNode* node)
  {
    moho::ArmyNameIndexNode* const head = tree->head;
    while (node != head->parent && node->parent->color == 0u) {
      moho::ArmyNameIndexNode* const parent = node->parent;
      moho::ArmyNameIndexNode* const grand = parent->parent;
      if (grand == nullptr || grand == head) {
        break;
      }

      if (parent == grand->left) {
        moho::ArmyNameIndexNode* const uncle = grand->right;
        if (!IsNameIndexNil(uncle) && uncle->color == 0u) {
          parent->color = 1;
          uncle->color = 1;
          grand->color = 0;
          node = grand;
          continue;
        }

        if (node == parent->right) {
          node = parent;
          RotateNameIndexLeft(tree, node);
        }

        node->parent->color = 1;
        grand->color = 0;
        RotateNameIndexRight(tree, grand);
        continue;
      }

      moho::ArmyNameIndexNode* const uncle = grand->left;
      if (!IsNameIndexNil(uncle) && uncle->color == 0u) {
        parent->color = 1;
        uncle->color = 1;
        grand->color = 0;
        node = grand;
        continue;
      }

      if (node == parent->left) {
        node = parent;
        RotateNameIndexRight(tree, node);
      }

      node->parent->color = 1;
      grand->color = 0;
      RotateNameIndexLeft(tree, grand);
    }

    if (head->parent != nullptr && head->parent != head) {
      head->parent->color = 1;
    }
  }

  void InsertOrAssignNameIndexNode(
    moho::ArmyNameIndexTree* const tree, const msvc8::string& statPath, moho::CArmyStatItem* const value
  )
  {
    if (tree == nullptr || tree->head == nullptr) {
      return;
    }

    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* parent = head;
    moho::ArmyNameIndexNode* node = head->parent;
    int cmp = 0;
    while (node != nullptr && node != head && node->isNil == 0u) {
      parent = node;
      cmp = CompareNameIndexKey(statPath, node->key);
      if (cmp == 0) {
        node->value = value;
        return;
      }
      node = (cmp < 0) ? node->left : node->right;
    }

    auto* const inserted = new moho::ArmyNameIndexNode{};
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent;
    inserted->key.assign(statPath, 0, msvc8::string::npos);
    inserted->value = value;
    inserted->color = 0;
    inserted->isNil = 0;

    if (parent == head) {
      head->parent = inserted;
    } else if (cmp < 0) {
      parent->left = inserted;
    } else {
      parent->right = inserted;
    }

    ++tree->size;
    FixupAfterNameIndexInsert(tree, inserted);
    RecomputeNameIndexExtrema(tree);
  }

  void FixupAfterNameIndexErase(
    moho::ArmyNameIndexTree* tree, moho::ArmyNameIndexNode* node, moho::ArmyNameIndexNode* nodeParent
  )
  {
    moho::ArmyNameIndexNode* const head = tree->head;
    moho::ArmyNameIndexNode* parent = (!IsNameIndexNil(node)) ? node->parent : nodeParent;
    while (node != head->parent && (IsNameIndexNil(node) || node->color == 1u)) {
      if (parent == nullptr) {
        break;
      }

      if (node == parent->left) {
        moho::ArmyNameIndexNode* sibling = parent->right;
        if (sibling == head) {
          node = parent;
          parent = node->parent;
          continue;
        }
        if (sibling->color == 0u) {
          sibling->color = 1;
          parent->color = 0;
          RotateNameIndexLeft(tree, parent);
          sibling = parent->right;
        }

        const bool leftBlack = IsNameIndexNil(sibling->left) || sibling->left->color == 1u;
        const bool rightBlack = IsNameIndexNil(sibling->right) || sibling->right->color == 1u;
        if (leftBlack && rightBlack) {
          sibling->color = 0;
          node = parent;
          parent = node->parent;
          continue;
        }

        if (IsNameIndexNil(sibling->right) || sibling->right->color == 1u) {
          if (!IsNameIndexNil(sibling->left)) {
            sibling->left->color = 1;
          }
          sibling->color = 0;
          RotateNameIndexRight(tree, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1;
        if (!IsNameIndexNil(sibling->right)) {
          sibling->right->color = 1;
        }
        RotateNameIndexLeft(tree, parent);
        node = head->parent;
        break;
      }

      moho::ArmyNameIndexNode* sibling = parent->left;
      if (sibling == head) {
        node = parent;
        parent = node->parent;
        continue;
      }
      if (sibling->color == 0u) {
        sibling->color = 1;
        parent->color = 0;
        RotateNameIndexRight(tree, parent);
        sibling = parent->left;
      }

      const bool rightBlack = IsNameIndexNil(sibling->right) || sibling->right->color == 1u;
      const bool leftBlack = IsNameIndexNil(sibling->left) || sibling->left->color == 1u;
      if (rightBlack && leftBlack) {
        sibling->color = 0;
        node = parent;
        parent = node->parent;
        continue;
      }

      if (IsNameIndexNil(sibling->left) || sibling->left->color == 1u) {
        if (!IsNameIndexNil(sibling->right)) {
          sibling->right->color = 1;
        }
        sibling->color = 0;
        RotateNameIndexLeft(tree, sibling);
        sibling = parent->left;
      }

      sibling->color = parent->color;
      parent->color = 1;
      if (!IsNameIndexNil(sibling->left)) {
        sibling->left->color = 1;
      }
      RotateNameIndexRight(tree, parent);
      node = head->parent;
      break;
    }

    if (!IsNameIndexNil(node)) {
      node->color = 1;
    }
  }

  [[nodiscard]] moho::ArmyTriggerNode* CreateTriggerListSentinel()
  {
    auto* const head = new moho::ArmyTriggerNode{};
    head->next = head;
    head->prev = head;
    return head;
  }

  struct ArmyTriggerSentinelRuntimeNode
  {
    ArmyTriggerSentinelRuntimeNode* next;
    ArmyTriggerSentinelRuntimeNode* prev;
    std::uint32_t payload0;
    std::uint32_t payload1;
  };
  static_assert(sizeof(ArmyTriggerSentinelRuntimeNode) == 0x10, "ArmyTriggerSentinelRuntimeNode size must be 0x10");

  /**
   * Address: 0x00702090 (FUN_00702090, CArmyStats trigger-list sentinel allocator)
   *
   * What it does:
   * Allocates one 16-byte trigger-list sentinel lane and self-links its
   * `{next,prev}` pointers.
   */
  [[maybe_unused]] [[nodiscard]] ArmyTriggerSentinelRuntimeNode* AllocateSelfLinkedArmyTriggerSentinel()
  {
    auto* const node =
      static_cast<ArmyTriggerSentinelRuntimeNode*>(gpg::core::legacy::AllocateChecked16ByteLane(1u));
    node->next = node;
    node->prev = node;
    return node;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  struct ArmyNameIndexMapRuntime
  {
    std::uint32_t meta0;
    moho::ArmyNameIndexNode* head;
    std::uint32_t size;
  };
  static_assert(sizeof(ArmyNameIndexMapRuntime) == 0x0C, "ArmyNameIndexMapRuntime size must be 0x0C");

  struct ArmyTriggerListRuntime
  {
    void* proxy;
    moho::ArmyTriggerNode* head;
    std::uint32_t size;
  };
  static_assert(sizeof(ArmyTriggerListRuntime) == 0x0C, "ArmyTriggerListRuntime size must be 0x0C");

  [[nodiscard]] ArmyNameIndexMapRuntime* NameIndexMapRuntimeView(moho::CArmyStats* const object)
  {
    return reinterpret_cast<ArmyNameIndexMapRuntime*>(&object->mNameIndex);
  }

  [[nodiscard]] const ArmyNameIndexMapRuntime* NameIndexMapRuntimeView(const moho::CArmyStats* const object)
  {
    return reinterpret_cast<const ArmyNameIndexMapRuntime*>(&object->mNameIndex);
  }

  [[nodiscard]] ArmyTriggerListRuntime* TriggerListRuntimeView(moho::CArmyStats* const object)
  {
    return reinterpret_cast<ArmyTriggerListRuntime*>(&object->mNameIndex.metaC);
  }

  [[nodiscard]] const ArmyTriggerListRuntime* TriggerListRuntimeView(const moho::CArmyStats* const object)
  {
    return reinterpret_cast<const ArmyTriggerListRuntime*>(&object->mNameIndex.metaC);
  }

  /**
   * Address: 0x00701570 (FUN_00701570)
   *
   * What it does:
   * Clears one name-index tree payload, frees the map-header sentinel node,
   * and zeros `{head,size}` lanes.
   */
  [[maybe_unused]] int ReleaseArmyNameIndexStorage(ArmyNameIndexMapRuntime& nameIndexRuntime) noexcept
  {
    if (nameIndexRuntime.head != nullptr) {
      DestroyNilTree(nameIndexRuntime.head->parent, &moho::ArmyNameIndexNode::isNil);
      delete nameIndexRuntime.head;
    }

    nameIndexRuntime.head = nullptr;
    nameIndexRuntime.size = 0u;
    return 0;
  }

  /**
   * Address: 0x007020B0 (FUN_007020B0)
   *
   * What it does:
   * Clears one trigger-list payload, frees the list-header sentinel node, and
   * zeros `{head,size}` lanes.
   */
  [[maybe_unused]] void ReleaseArmyTriggerListStorage(ArmyTriggerListRuntime& triggerListRuntime) noexcept
  {
    if (triggerListRuntime.head != nullptr) {
      moho::ArmyTriggerNode* node = triggerListRuntime.head->next;
      while (node != triggerListRuntime.head) {
        moho::ArmyTriggerNode* const next = node->next;
        delete node;
        node = next;
      }

      delete triggerListRuntime.head;
    }

    triggerListRuntime.head = nullptr;
    triggerListRuntime.size = 0u;
  }

  /**
   * Address: 0x0070E460 (FUN_0070E460)
   *
   * What it does:
   * Erases one trigger-list node, updates list links and size, and stores the
   * following iterator node in `outNext`.
   */
  [[nodiscard]] moho::ArmyTriggerNode** EraseTriggerListNodeAndAdvance(
    ArmyTriggerListRuntime* const listRuntime,
    moho::ArmyTriggerNode** const outNext,
    moho::ArmyTriggerNode* const node
  )
  {
    if (outNext == nullptr || listRuntime == nullptr || listRuntime->head == nullptr || node == nullptr) {
      return outNext;
    }

    moho::ArmyTriggerNode* const head = listRuntime->head;
    moho::ArmyTriggerNode* const next = node->next;
    if (node == head) {
      *outNext = next;
      return outNext;
    }

    node->prev->next = node->next;
    node->next->prev = node->prev;
    delete node;
    if (listRuntime->size > 0u) {
      --listRuntime->size;
    }

    *outNext = next;
    return outNext;
  }

  gpg::RType* gArmyStatsBaseType = nullptr;
  gpg::RType* gArmyNameIndexType = nullptr;
  gpg::RType* gArmyTriggerListType = nullptr;
} // namespace

namespace moho
{
  gpg::RType* Stats<CArmyStatItem>::sType = nullptr;
  gpg::RType* CArmyStatItem::sType = nullptr;
  gpg::RType* CArmyStatItem::sPointerType = nullptr;
  gpg::RType* CArmyStats::sType = nullptr;

  gpg::RType* CArmyStatItem::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CArmyStatItem));
    }
    return sType;
  }

  gpg::RType* CArmyStats::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CArmyStats));
    }
    return sType;
  }

  /**
   * Address: 0x007107E0 (FUN_007107E0, Moho::CArmyStatItem::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI for `CArmyStatItem*`.
   */
  gpg::RType* CArmyStatItem::GetPointerType()
  {
    (void)StaticGetClass();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CArmyStatItem*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x00585B30 (FUN_00585B30, Moho::CArmyStatItem::CArmyStatItem)
   */
  CArmyStatItem::CArmyStatItem(const char* name)
    : StatItem(name)
    , mBlueprintStats{}
  {
    mBlueprintStats.meta0 = 0;
    mBlueprintStats.head = CreateBlueprintTreeSentinel();
    mBlueprintStats.size = 0;
  }

  /**
   * Address: 0x00585BB0 (FUN_00585BB0, deleting dtor thunk)
   * Address: 0x00585C00 (FUN_00585C00, destructor core)
   */
  CArmyStatItem::~CArmyStatItem()
  {
    DestroyBlueprintTree();
  }

  void CArmyStatItem::DestroyBlueprintTree()
  {
    ArmyBlueprintStatNode* const head = mBlueprintStats.head;
    if (head == nullptr) {
      return;
    }

    DestroyNilTree(head->parent, &ArmyBlueprintStatNode::isNil);
    delete head;
    mBlueprintStats.head = nullptr;
    mBlueprintStats.size = 0;
  }

  /**
   * Address: 0x0070B430 (FUN_0070B430, CArmyStatItem vtable slot 1)
   */
  void CArmyStatItem::ToLua(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject)
  {
    StatItem::ToLua(state, outObject);
    if (mBlueprintStats.size == 0u) {
      return;
    }

    LuaPlus::LuaObject blueprints;
    blueprints.AssignNewTable(state, 0, 0);

    ArmyBlueprintStatNode* node = mBlueprintStats.head->left;
    while (node != nullptr && node != mBlueprintStats.head) {
      const ArmyBlueprintNameView* const nameView = node->blueprintName;
      if (nameView != nullptr) {
        const msvc8::string value = gpg::STR_Printf("%.2f", node->value);
        blueprints.SetString(nameView->mName.c_str(), value.c_str());
      }

      node = NextBlueprintNode(node, mBlueprintStats.head);
    }

    outObject->SetObject("Blueprints", &blueprints);
  }

  /**
   * Address: 0x0070B580 (FUN_0070B580, Moho::CArmyStatItem::SumCategory)
   */
  float CArmyStatItem::SumCategory(const EntityCategorySet* const categorySet) const
  {
    if (categorySet == nullptr || categorySet->mUniverse.mWordUniverseHandle == 0u) {
      return 0.0f;
    }

    const ArmyBlueprintStatNode* const head = mBlueprintStats.head;
    if (head == nullptr) {
      return 0.0f;
    }

    float total = 0.0f;
    for (const ArmyBlueprintStatNode* node = head->left; node != head; node = NextBlueprintNode(node, head)) {
      const ArmyBlueprintNameView* const blueprintView = node->blueprintName;
      if (blueprintView == nullptr) {
        continue;
      }

      if (categorySet->mBits.Contains(static_cast<unsigned int>(blueprintView->mBlueprintOrdinal))) {
        total += node->value;
      }
    }

    return total;
  }

  /**
   * Address: 0x0070E2B0 (FUN_0070E2B0)
   *
   * What it does:
   * Resolves one per-blueprint float lane in `mBlueprintStats`, inserting a
   * zero-initialized node when missing, and returns a writable pointer to that
   * lane.
   */
  float* CArmyStatItem::FindOrCreateBlueprintStatValue(const ArmyBlueprintNameView* const blueprintName)
  {
    ArmyBlueprintStatNode* const node = FindOrInsertBlueprintStatNode(&mBlueprintStats, blueprintName);
    if (node == nullptr) {
      return nullptr;
    }

    return &node->value;
  }

  /**
   * Address: 0x007014A0 (FUN_007014A0, Stats<CArmyStatItem> constructor)
   */
  Stats<CArmyStatItem>::Stats()
    : mItem(new CArmyStatItem("Root"))
    , mLock(new boost::mutex())
    , pad_000D{0, 0, 0}
  {}

  /**
   * Address: 0x006FD850 (FUN_006FD850, Stats<CArmyStatItem> destructor core)
   */
  Stats<CArmyStatItem>::~Stats()
  {
    delete mItem;
    mItem = nullptr;
    delete mLock;
    mLock = nullptr;
  }

  /**
   * Address: 0x005953A0 (FUN_005953A0, token walk)
   */
  CArmyStatItem* Stats<CArmyStatItem>::WalkTokenPath(
    CArmyStatItem* root, const msvc8::vector<msvc8::string>& tokens, const bool allowCreate, bool* const didCreate
  )
  {
    if (didCreate != nullptr) {
      *didCreate = false;
    }
    if (root == nullptr) {
      return nullptr;
    }

    const std::size_t tokenCount = tokens.size();
    if (tokenCount == 0u) {
      return root;
    }

    CArmyStatItem* current = root;
    std::size_t index = 0u;
    for (; index < tokenCount; ++index) {
      CArmyStatItem* const found = FindArmyChildByName(current, tokens[index]);
      if (found == nullptr) {
        break;
      }
      current = found;
    }

    if (index == tokenCount) {
      return current;
    }
    if (!allowCreate) {
      return nullptr;
    }

    if (didCreate != nullptr) {
      *didCreate = true;
    }

    CArmyStatItem* parent = current;
    CArmyStatItem* lastCreated = nullptr;
    for (; index < tokenCount; ++index) {
      auto* const child = new CArmyStatItem(tokens[index].c_str());
      parent->AttachChild(child);
      parent = child;
      lastCreated = child;
    }
    return lastCreated;
  }

  /**
   * Address: 0x00594400 (FUN_00594400, token traversal helper)
   */
  CArmyStatItem* Stats<CArmyStatItem>::TraverseTables(const gpg::StrArg statPath, const bool allowCreate)
  {
    boost::mutex::scoped_lock lock(*mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    CArmyStatItem* const item = WalkTokenPath(mItem, tokens, allowCreate, &didCreate);
    if (didCreate && item != nullptr) {
      item->SynchronizeAsInt();
    }
    return item;
  }

  /**
   * Address: 0x005944F0 (FUN_005944F0, func_TraverseTables2)
   *
   * What it does:
   * Create-enabled wrapper lane over token traversal used by legacy
   * CArmyStats helper callsites.
   */
  CArmyStatItem* Stats<CArmyStatItem>::TraverseTablesCreate(const gpg::StrArg statPath)
  {
    return TraverseTables(statPath, true);
  }

  /**
   * Address: 0x00706360 (FUN_00706360, sub_706360)
   * Alias:   0x00705BD0 (FUN_00705BD0, thunk)
   * Alias:   0x006105A0 (FUN_006105A0)
   */
  CArmyStatItem* Stats<CArmyStatItem>::GetStringItem(const gpg::StrArg statPath)
  {
    boost::mutex::scoped_lock lock(*mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    CArmyStatItem* const item = WalkTokenPath(mItem, tokens, true, &didCreate);
    if (didCreate && item != nullptr) {
      boost::mutex::scoped_lock itemLock(item->mLock);
      item->mType = EStatType::kString;
    }
    return item;
  }

  /**
   * Address: 0x00703D70 (FUN_00703D70, delete-by-path helper)
   */
  void Stats<CArmyStatItem>::Delete(const char* statPath)
  {
    boost::mutex::scoped_lock lock(*mLock);
    CArmyStatItem* const item = TraverseTables(statPath, false);
    if (item == mItem) {
      throw std::runtime_error("Don't be doing that, chief.");
    }
    if (item != nullptr) {
      delete item;
    }
  }

  /**
   * Address: 0x006FD7C0 (FUN_006FD7C0, CArmyStats constructor)
   */
  CArmyStats::CArmyStats(CAiBrain* ownerArmy)
    : mOwnerArmy(ownerArmy)
    , mNameIndex{}
    , mAuxHead(CreateTriggerListSentinel())
    , mAuxSize(0)
  {
    mNameIndex.meta0 = 0;
    mNameIndex.head = CreateNameIndexSentinel();
    mNameIndex.size = 0;
    mNameIndex.metaC = 0;
  }

  /**
   * Address: 0x00704A40 (FUN_00704A40, CArmyStats destructor)
   */
  CArmyStats::~CArmyStats()
  {
    DestroyNameIndexTree();
    DestroyAuxList();
  }

  /**
   * Address: 0x00703700 (FUN_00703700, name-index erase-iterator helper)
   */
  ArmyNameIndexNode* CArmyStats::EraseNameIndexNodeAndAdvance(ArmyNameIndexNode* node)
  {
    ArmyNameIndexNode* const head = mNameIndex.head;
    if (IsNameIndexNil(node)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    ArmyNameIndexNode* const next = NextNameIndexNode(node, head);
    ArmyNameIndexNode* removed = node;
    ArmyNameIndexNode* spliceTarget = node;
    std::uint8_t removedColor = spliceTarget->color;
    ArmyNameIndexNode* fixNode = head;
    ArmyNameIndexNode* fixParent = head;

    if (IsNameIndexNil(node->left)) {
      fixNode = node->right;
      fixParent = node->parent;
      ReplaceNameIndexSubtree(&mNameIndex, node, node->right);
    } else if (IsNameIndexNil(node->right)) {
      fixNode = node->left;
      fixParent = node->parent;
      ReplaceNameIndexSubtree(&mNameIndex, node, node->left);
    } else {
      spliceTarget = NameIndexMin(node->right, head);
      removedColor = spliceTarget->color;
      fixNode = spliceTarget->right;
      if (spliceTarget->parent == node) {
        fixParent = spliceTarget;
        if (!IsNameIndexNil(fixNode)) {
          fixNode->parent = spliceTarget;
        }
      } else {
        fixParent = spliceTarget->parent;
        ReplaceNameIndexSubtree(&mNameIndex, spliceTarget, spliceTarget->right);
        spliceTarget->right = node->right;
        spliceTarget->right->parent = spliceTarget;
      }

      ReplaceNameIndexSubtree(&mNameIndex, node, spliceTarget);
      spliceTarget->left = node->left;
      spliceTarget->left->parent = spliceTarget;
      spliceTarget->color = node->color;
    }

    delete removed;
    if (mNameIndex.size > 0u) {
      --mNameIndex.size;
    }
    if (removedColor == 1u) {
      FixupAfterNameIndexErase(&mNameIndex, fixNode, fixParent);
    }
    RecomputeNameIndexExtrema(&mNameIndex);
    return next;
  }

  /**
   * Address: 0x0070B980 (FUN_0070B980, CArmyStats vtable slot 0)
   */
  void CArmyStats::Delete(const char* statPath)
  {
    ArmyNameIndexNode* node = mNameIndex.head->left;
    while (node != nullptr && node != mNameIndex.head) {
      const msvc8::string keyCopy = node->key;
      if (std::strstr(keyCopy.c_str(), statPath) != nullptr) {
        node = EraseNameIndexNodeAndAdvance(node);
      } else {
        node = NextNameIndexNode(node, mNameIndex.head);
      }
    }

    Stats<CArmyStatItem>::Delete(statPath);
  }

  /**
   * Address: 0x00714870 (FUN_00714870, Moho::CArmyStats::MemberDeserialize)
   *
   * gpg::ReadArchive*
   *
   * What it does:
   * Loads base stats storage, name-index map runtime lane, and trigger-list
   * runtime lane from archive using cached reflection RTTI.
   */
  void CArmyStats::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedType<Stats<CArmyStatItem>>(gArmyStatsBaseType), static_cast<Stats<CArmyStatItem>*>(this), owner);
    archive->Read(CachedType<ArmyNameIndexMapRuntime>(gArmyNameIndexType), NameIndexMapRuntimeView(this), owner);
    archive->Read(CachedType<ArmyTriggerListRuntime>(gArmyTriggerListType), TriggerListRuntimeView(this), owner);
  }

  /**
   * Address: 0x00714920 (FUN_00714920, Moho::CArmyStats::MemberSerialize)
   *
   * gpg::WriteArchive*
   *
   * What it does:
   * Writes base stats storage, name-index map runtime lane, and trigger-list
   * runtime lane to archive using cached reflection RTTI.
   */
  void CArmyStats::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(
      CachedType<Stats<CArmyStatItem>>(gArmyStatsBaseType),
      static_cast<const Stats<CArmyStatItem>*>(this),
      owner
    );
    archive->Write(CachedType<ArmyNameIndexMapRuntime>(gArmyNameIndexType), NameIndexMapRuntimeView(this), owner);
    archive->Write(CachedType<ArmyTriggerListRuntime>(gArmyTriggerListType), TriggerListRuntimeView(this), owner);
  }

  /**
   * Address: 0x0070B860 (FUN_0070B860, Moho::CArmyStats::GetStat)
   */
  CArmyStatItem* CArmyStats::GetStat(const char* statPath)
  {
    const msvc8::string key(statPath);
    if (ArmyNameIndexNode* const foundNode = FindNameIndexNode(&mNameIndex, key)) {
      return foundNode->value;
    }

    CArmyStatItem* const item = TraverseTables(statPath, false);
    if (item == nullptr) {
      return nullptr;
    }

    item->Release(0);
    InsertOrAssignNameIndexNode(&mNameIndex, key, item);
    return item;
  }

  /**
   * Address: 0x005945E0 (FUN_005945E0, Moho::CArmyStats::GetItem)
   */
  CArmyStatItem* CArmyStats::GetItem(const char* const statPath)
  {
    const msvc8::string key(statPath);
    if (ArmyNameIndexNode* const foundNode = FindNameIndexNode(&mNameIndex, key)) {
      return foundNode->value;
    }

    CArmyStatItem* const item = TraverseTables(statPath, true);
    item->Release(0);
    InsertOrAssignNameIndexNode(&mNameIndex, key, item);
    return item;
  }

  /**
   * Address: 0x00594720 (FUN_00594720, func_GetArmyStat2)
   *
   * What it does:
   * Resolves one army-stat item by path from the name-index cache and creates
   * and caches the lane when missing.
   */
  CArmyStatItem* ResolveArmyStatItemCachedCreate(CArmyStats* const armyStats, const char* const statPath)
  {
    const msvc8::string key(statPath);
    if (ArmyNameIndexNode* const foundNode = FindNameIndexNode(&armyStats->mNameIndex, key)) {
      return foundNode->value;
    }

    CArmyStatItem* const item = armyStats->TraverseTablesCreate(statPath);
    item->Release(0);
    InsertOrAssignNameIndexNode(&armyStats->mNameIndex, key, item);
    return item;
  }

  /**
   * Address: 0x0070B820 (FUN_0070B820)
   *
   * What it does:
   * Resolves one army-stat item by path, resolves one per-blueprint float lane
   * in that item, applies `delta`, and returns the updated lane pointer.
   */
  float*
  CArmyStats::AddBlueprintStatDelta(const char* const statPath, const ArmyBlueprintNameView* const blueprintName, const float delta)
  {
    CArmyStatItem* const statItem = ResolveArmyStatItemCachedCreate(this, statPath);
    float* const lane = statItem->FindOrCreateBlueprintStatValue(blueprintName);
    *lane += delta;
    return lane;
  }

  /**
   * Address: 0x00593260 (FUN_00593260, func_UpdateUnitStat)
   */
  std::int32_t CArmyStats::UpdateUnitStat(const char* const statPath, const std::int32_t* const delta)
  {
    CArmyStatItem* const item = GetItem(statPath);
    item->SynchronizeAsInt();
    return AtomicExchangeAddI32(&item->mPrimaryValueBits, *delta);
  }

  /**
   * Address: 0x00593220 (FUN_00593220, func_SetUnitStat)
   */
  std::int32_t CArmyStats::SetUnitStat(const char* const statPath, const std::int32_t* const value)
  {
    CArmyStatItem* const item = GetItem(statPath);
    item->SynchronizeAsInt();

    volatile std::int32_t* const counter = &item->mPrimaryValueBits;
    for (;;) {
      const std::int32_t observed = AtomicCompareExchangeI32(counter, 0, 0);
      const std::int32_t result = AtomicCompareExchangeI32(counter, *value, observed);
      if (result == observed) {
        return result;
      }
    }
  }

  /**
   * Address: 0x005931E0 (FUN_005931E0, Moho::CArmyStats::SetIntStatAtomic)
   *
   * What it does:
   * Resolves one stat item by path, marks it as an integer lane, and then
   * repeatedly compares and swaps the stored counter until the replace
   * succeeds, returning the previous counter value.
   */
  std::int32_t CArmyStats::SetIntStatAtomic(const char* const statPath, const std::int32_t* const value)
  {
    CArmyStatItem* const item = GetItem(statPath);
    item->SynchronizeAsInt();

    volatile std::int32_t* const counter = &item->mPrimaryValueBits;
    for (;;) {
      const std::int32_t observed = AtomicCompareExchangeI32(counter, 0, 0);
      const std::int32_t previous = AtomicCompareExchangeI32(counter, *value, observed);
      if (previous == observed) {
        return previous;
      }
    }
  }

  /**
   * Address: 0x005932C0 (FUN_005932C0, sub_5932C0)
   */
  std::int32_t CArmyStats::SetUnitStatGreaterOf(const char* const statPath, const std::int32_t* const candidate)
  {
    CArmyStatItem* const item = GetItem(statPath);
    volatile std::int32_t* const counter = &item->mPrimaryValueBits;

    std::int32_t result = AtomicCompareExchangeI32(counter, 0, 0);
    const std::int32_t targetValue = *candidate;
    if (targetValue > result) {
      item->SynchronizeAsInt();
      for (;;) {
        const std::int32_t observed = AtomicCompareExchangeI32(counter, 0, 0);
        result = AtomicCompareExchangeI32(counter, targetValue, observed);
        if (result == observed) {
          break;
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00593310 (FUN_00593310, sub_593310)
   *
   * What it does:
   * Sets one float stat counter to `max(current, *candidate)` using an
   * atomic compare-exchange loop over the bitwise float lane.
   */
  void CArmyStats::SetUnitStatGreaterFloat(const char* const statPath, const float* const candidate)
  {
    CArmyStatItem* const item = ResolveArmyStatItemCachedCreate(this, statPath);
    volatile std::int32_t* const counter = &item->mPrimaryValueBits;

    const std::int32_t currentBits = AtomicCompareExchangeI32(counter, 0, 0);
    const float currentValue = IntBitsToFloat(currentBits);
    const float candidateValue = *candidate;
    const float targetValue = (currentValue > candidateValue) ? currentValue : candidateValue;
    if (targetValue == currentValue) {
      return;
    }

    item->SynchronizeAsFloat();
    const std::int32_t targetBits = FloatToIntBits(targetValue);
    for (;;) {
      const std::int32_t observed = AtomicCompareExchangeI32(counter, 0, 0);
      const std::int32_t previous = AtomicCompareExchangeI32(counter, targetBits, observed);
      if (previous == observed) {
        return;
      }
    }
  }

  /**
   * Address: 0x0070BAB0 (FUN_0070BAB0, Moho::CArmyStats::GetTrigger)
   */
  boost::shared_ptr<STrigger>* CArmyStats::GetTrigger(boost::shared_ptr<STrigger>* outTrigger, const char* triggerName)
  {
    ArmyTriggerNode* const head = mAuxHead;
    for (ArmyTriggerNode* node = head->next; node != head; node = node->next) {
      if (_stricmp(node->trigger->mName.c_str(), triggerName) == 0) {
        *outTrigger = node->trigger;
        return outTrigger;
      }
    }

    outTrigger->reset();
    return outTrigger;
  }

  /**
   * Address: 0x0070BCA0 (FUN_0070BCA0, Moho::CArmyStats::SetArmyStatsTrigger)
   */
  void CArmyStats::SetArmyStatsTrigger(
    const EntityCategorySet* const categorySet,
    CArmyStats* const armyStats,
    const char* const triggerName,
    const char* const statPath,
    const ETriggerOperator triggerOperator,
    const float triggerValue
  )
  {
    boost::shared_ptr<STrigger> trigger;
    armyStats->GetTrigger(&trigger, triggerName);
    if (!trigger) {
      gpg::Warnf("Trigger %s does not exist.", triggerName);
      return;
    }

    CArmyStatItem* const statItem = armyStats->GetStat(statPath);
    if (statItem == nullptr) {
      gpg::Warnf("ArmyStatItem %s does not exist.", statPath);
      return;
    }

    SCondition condition{};
    condition.mItem = statItem;
    condition.mCat = *categorySet;
    condition.mVal = triggerValue;
    condition.mOp = triggerOperator;

    gpg::FastVectorRuntimeInsertRange(trigger->mConditions, trigger->mConditions.end, &condition, &condition + 1);
  }

  /**
   * Address: 0x0070BB40 (FUN_0070BB40, sub_70BB40)
   */
  void CArmyStats::EnsureTriggerExists(const char* const triggerName)
  {
    if (mAuxHead == nullptr) {
      mAuxHead = CreateTriggerListSentinel();
      mAuxSize = 0u;
    }

    boost::shared_ptr<STrigger> trigger;
    GetTrigger(&trigger, triggerName);
    if (trigger) {
      return;
    }

    boost::shared_ptr<STrigger> created{new STrigger()};
    created->mName = triggerName ? triggerName : "";

    ArmyTriggerNode* const head = mAuxHead;
    auto* const node = new ArmyTriggerNode{};
    node->trigger = created;
    node->next = head;
    node->prev = head->prev;
    head->prev->next = node;
    head->prev = node;
    ++mAuxSize;
  }

  /**
   * Address: 0x0070BE50 (FUN_0070BE50, Moho::CArmyStats::RemoveArmyStatsTrigger)
   */
  void CArmyStats::RemoveArmyStatsTrigger(const char* const triggerName)
  {
    ArmyTriggerListRuntime* const triggerRuntime = TriggerListRuntimeView(this);
    ArmyTriggerNode* const head = (triggerRuntime != nullptr) ? triggerRuntime->head : nullptr;
    if (head == nullptr) {
      return;
    }

    for (ArmyTriggerNode* node = head->next; node != head; node = node->next) {
      if (node->trigger && _stricmp(node->trigger->mName.c_str(), triggerName) == 0) {
        ArmyTriggerNode* nextNode = nullptr;
        (void)EraseTriggerListNodeAndAdvance(triggerRuntime, &nextNode, node);
        (void)nextNode;
        return;
      }
    }
  }

  /**
   * Address: 0x0070BEA0 (FUN_0070BEA0, Moho::CArmyStats::Update)
   *
   * What it does:
   * Evaluates all trigger condition vectors and dispatches one
   * `OnStatsTrigger` script callback per trigger when all conditions pass.
   */
  void CArmyStats::Update()
  {
    ArmyTriggerNode* const head = mAuxHead;
    if (head == nullptr || mOwnerArmy == nullptr) {
      return;
    }

    for (ArmyTriggerNode* node = head->next; node != head; node = node->next) {
      if (node->trigger == nullptr) {
        continue;
      }

      auto& conditions = node->trigger->mConditions;
      if (conditions.begin == nullptr || conditions.end == nullptr || conditions.begin == conditions.end) {
        continue;
      }

      bool allConditionsSatisfied = true;
      for (const SCondition* condition = conditions.begin; condition != conditions.end; ++condition) {
        const float conditionValue = ResolveConditionValue(*condition);
        if (!EvaluateCondition(*condition, conditionValue)) {
          allConditionsSatisfied = false;
          break;
        }
      }

      if (!allConditionsSatisfied) {
        continue;
      }

      (void)mOwnerArmy->RunScript(kOnStatsTriggerScriptName, node->trigger->mName.c_str());
    }
  }

  /**
   * Address: 0x00704FD0 (FUN_00704FD0, sub_704FD0)
   */
  CArmyStatItem* CArmyStats::GetStringItemCached(const gpg::StrArg statPath)
  {
    const msvc8::string key(statPath ? statPath : "");
    if (ArmyNameIndexNode* const foundNode = FindNameIndexNode(&mNameIndex, key)) {
      return foundNode->value;
    }

    CArmyStatItem* const item = GetStringItem(key.c_str());
    if (item != nullptr) {
      item->Release(0);
    }
    InsertOrAssignNameIndexNode(&mNameIndex, key, item);
    return item;
  }

  /**
   * Address: 0x00704000 (FUN_00704000, sub_704000)
   */
  void CArmyStats::SetStringValueByPath(const gpg::StrArg statPath, const msvc8::string& value)
  {
    CArmyStatItem* const item = GetStringItemCached(statPath);
    if (item == nullptr) {
      return;
    }

    {
      boost::mutex::scoped_lock itemLock(item->mLock);
      item->mType = EStatType::kString;
    }
    item->SetValue(value);
  }

  /**
   * Address: 0x0070DDC0 (FUN_0070DDC0, CArmyStats name-index tree cleanup)
   *
   * What it does:
   * Destroys all name-index nodes, frees the sentinel head, and resets the
   * name-index runtime lane.
   */
  void CArmyStats::DestroyNameIndexTree()
  {
    ArmyNameIndexNode* const head = mNameIndex.head;
    if (head == nullptr) {
      return;
    }

    DestroyNilTree(head->parent, &ArmyNameIndexNode::isNil);
    delete head;
    mNameIndex.head = nullptr;
    mNameIndex.size = 0;
  }

  /**
   * Address: 0x00702BB0 (FUN_00702BB0, std::list<shared_ptr<STrigger>>::clear inlined helper)
   *
   * IDA signature:
   * void __usercall sub_702BB0(int a1@<ebx>);
   *
   * What it does:
   * Clears one sentinel-headed trigger-node list in-place: resets the sentinel
   * head's next/prev to itself, zeroes the size lane, then walks each former
   * payload node, releases its intrusive `boost::shared_ptr<STrigger>` control
   * block (matched add_ref/release pair at +0x0C), and frees the node storage.
   *
   * This is the MSVC8 std::list<boost::shared_ptr<STrigger>>::clear expansion
   * used by both the auxiliary `mAuxHead` lane on CArmyStats and by
   * reflection-driven SerLoad helpers that reuse the same node ABI.
   */
  void CArmyStats::ClearTriggerList()
  {
    ArmyTriggerNode* const head = mAuxHead;
    if (head == nullptr) {
      return;
    }

    // Detach the circular list from its payload: sentinel head becomes empty
    // (next = prev = head), size lane is reset, matching FUN_00702BB0's prologue
    // exactly so re-entrancy during node destruction cannot observe stale links.
    ArmyTriggerNode* node = head->next;
    head->next = head;
    head->prev = head;
    mAuxSize = 0;

    while (node != head) {
      ArmyTriggerNode* const next = node->next;
      // ArmyTriggerNode's `boost::shared_ptr<STrigger>` member destructor runs
      // here and performs the interlocked shared_count/weak_count release pair
      // (ref_count::release + ref_count::weak_release) that the decompiler
      // rendered as inlined lock-xadd sequences at +0x0C/+0x10.
      delete node;
      node = next;
    }
  }

  /**
   * Address: 0x007015C0 (FUN_007015C0, CArmyStats auxiliary trigger-list cleanup)
   *
   * What it does:
   * Destroys all trigger-list nodes via `ClearTriggerList`, frees the sentinel
   * head allocation, and clears the auxiliary-list runtime pointer lane.
   */
  void CArmyStats::DestroyAuxList()
  {
    ClearTriggerList();

    if (ArmyTriggerNode* const head = mAuxHead) {
      delete head;
      mAuxHead = nullptr;
    }
  }
} // namespace moho
