#include "CArmyStats.h"

#include <cstring>
#include <stdexcept>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"

namespace
{
  struct StatIntrusiveNode
  {
    StatIntrusiveNode* prev;
    StatIntrusiveNode* next;
    moho::StatItem* parent;
    moho::StatItem* owner;
  };

  [[nodiscard]] StatIntrusiveNode* AsSelfNode(moho::StatItem* item)
  {
    return reinterpret_cast<StatIntrusiveNode*>(reinterpret_cast<std::uint8_t*>(item) + 0x04);
  }

  [[nodiscard]] StatIntrusiveNode* AsChildHead(moho::StatItem* item)
  {
    return reinterpret_cast<StatIntrusiveNode*>(reinterpret_cast<std::uint8_t*>(item) + 0x14);
  }

  void DetachSelfNode(moho::StatItem* item)
  {
    StatIntrusiveNode* const selfNode = AsSelfNode(item);
    if (selfNode->next != nullptr && selfNode->prev != nullptr) {
      selfNode->next->prev = selfNode->prev;
      selfNode->prev->next = selfNode->next;
    }
    selfNode->prev = selfNode;
    selfNode->next = selfNode;
    selfNode->parent = nullptr;
  }

  void AttachChild(moho::StatItem* parent, moho::StatItem* child)
  {
    DetachSelfNode(child);

    StatIntrusiveNode* const childNode = AsSelfNode(child);
    childNode->parent = parent;
    if (parent == nullptr) {
      return;
    }

    StatIntrusiveNode* const parentHead = AsChildHead(parent);
    childNode->prev = parentHead->prev;
    childNode->next = parentHead;
    parentHead->prev = childNode;
    childNode->prev->next = childNode;
  }

  [[nodiscard]] moho::CArmyStatItem* FindArmyChildByName(moho::CArmyStatItem* parent, const msvc8::string& token)
  {
    if (parent == nullptr) {
      return nullptr;
    }

    for (StatIntrusiveNode* node = AsChildHead(parent)->next; node != nullptr; node = node->next) {
      moho::StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }
      if (child->mName == token) {
        return static_cast<moho::CArmyStatItem*>(child);
      }
    }
    return nullptr;
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

  [[nodiscard]] moho::ArmyAuxListNode* CreateAuxListSentinel()
  {
    auto* const head = new moho::ArmyAuxListNode{};
    head->next = head;
    head->prev = head;
    return head;
  }
} // namespace

namespace moho
{
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
   * Address: 0x007014A0 (FUN_007014A0, Stats<CArmyStatItem> constructor)
   */
  Stats<CArmyStatItem>::Stats()
    : mItem(new CArmyStatItem("Root"))
    , mLock()
    , pad_000D{0, 0, 0}
  {}

  /**
   * Address: 0x006FD850 (FUN_006FD850, Stats<CArmyStatItem> destructor core)
   */
  Stats<CArmyStatItem>::~Stats()
  {
    delete mItem;
    mItem = nullptr;
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
      AttachChild(parent, child);
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
    boost::mutex::scoped_lock lock(mLock);

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
   * Address: 0x00703D70 (FUN_00703D70, delete-by-path helper)
   */
  void Stats<CArmyStatItem>::Delete(const char* statPath)
  {
    boost::mutex::scoped_lock lock(mLock);
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
    , mAuxHead(CreateAuxListSentinel())
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

  void CArmyStats::DestroyAuxList()
  {
    delete mAuxHead;
    mAuxHead = nullptr;
    mAuxSize = 0;
  }
} // namespace moho
