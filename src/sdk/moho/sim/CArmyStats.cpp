// `CArmyStats::DumpStats` (0x0070C160) asks for its output directory through a
// `wxDirDialog` on the first call (0x0070C438), so this sim translation unit
// really does pull in the wx dialog family. wx has to be included first: it
// needs to own the `windows.h` inclusion so that `wx/msw/winundef.h` can drop
// the `CreateDialog`/`GetClassInfo` macros before the wx class declarations are
// parsed.
#include <wx/defs.h>
#include <wx/dirdlg.h>

#include "CArmyStats.h"

#include <cstdlib>
#include <cstring>
#include <float.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Set.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiBrain.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/Sim.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * Address: 0x00594BD0 (FUN_00594BD0, std::map<std::string,Moho::CArmyStatItem*>::find)
   * Address: 0x00595130 (FUN_00595130, std::map<std::string,Moho::CArmyStatItem*>::_Lbound
   * - the lower-bound descent half that find()/operator[] both call in the
   * binary; this recovery inlines the same descent directly rather than
   * factoring it into a separate call, so both addresses resolve here)
   *
   * What it does:
   * Lower-bound descent by string key, returning the found node or the tree
   * head sentinel when absent. The binary splits this into a `_Lbound` call
   * plus an equality check; this recovery walks the parent chain directly
   * with the same key comparator (`CompareNameIndexKey`) to the same effect.
   */
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

  void AppendMsvcString(std::string& out, const msvc8::string& text)
  {
    out.append(text.c_str(), text.size());
  }

  [[nodiscard]] const moho::RBlueprint* AsBlueprint(const moho::ArmyBlueprintNameView* const view) noexcept
  {
    return reinterpret_cast<const moho::RBlueprint*>(view);
  }

  [[nodiscard]] const moho::RUnitBlueprint* AsUnitBlueprint(const moho::ArmyBlueprintNameView* const view) noexcept
  {
    return reinterpret_cast<const moho::RUnitBlueprint*>(view);
  }

  [[nodiscard]] const moho::EntityCategorySet*
  ResolveStatsCategory(const moho::RRuleGameRules* const rules, const char* const categoryName)
  {
    return rules->GetEntityCategory(categoryName);
  }

  [[nodiscard]] float SumStatCategory(
    const moho::CArmyStatItem* const item,
    const moho::EntityCategorySet* const category
  )
  {
    return item->SumCategory(category);
  }

  [[nodiscard]] int SumStatCategoryInt(
    const moho::CArmyStatItem* const item,
    const moho::EntityCategorySet* const category
  )
  {
    return static_cast<int>(SumStatCategory(item, category));
  }

  void CollectBlueprintStatKeys(
    msvc8::set<const moho::ArmyBlueprintNameView*>& outKeys,
    const moho::CArmyStatItem* const item
  )
  {
    for (const auto& entry : item->mBlueprintStats) {
      if (entry.first != nullptr) {
        outKeys.insert(entry.first);
      }
    }
  }

  void AppendCategoryStatsXml(
    std::string& outXml,
    const char* const indent,
    const moho::RRuleGameRules* const rules,
    const char* const categoryName,
    const moho::CArmyStatItem* const unitsActive,
    const moho::CArmyStatItem* const enemiesKilled
  )
  {
    const moho::EntityCategorySet* const category = ResolveStatsCategory(rules, categoryName);
    AppendMsvcString(
      outXml,
      gpg::STR_Printf(
        "%s      <Category type=\"%s\" built=\"%d\" killed=\"%d\"/>\n",
        indent,
        categoryName,
        SumStatCategoryInt(unitsActive, category),
        SumStatCategoryInt(enemiesKilled, category)
      )
    );
  }

  [[nodiscard]] float ReadRequiredFloatStat(moho::CArmyStats& stats, const char* const statPath)
  {
    return stats.GetStat(statPath)->GetFloat(false);
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

  /**
   * Address: 0x00592E50 (FUN_00592E50, sub_592E50)
   *
   * What it does:
   * Standard red-black left rotation on `node`: promotes `node->right`,
   * relinking the pivoted subtree, the pivot's old left child, and the
   * root/parent-child link (asm-verified instruction-by-instruction against
   * FUN_00592E50.asm; the `isNil` check reads offset 0x2D, matching
   * `ArmyNameIndexNode::isNil`).
   */
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

  /**
   * Address: 0x00592EE0 (FUN_00592EE0, sub_592EE0)
   *
   * What it does:
   * Standard red-black right rotation on `node` (mirror image of
   * `RotateNameIndexLeft`), asm-verified instruction-by-instruction against
   * FUN_00592EE0.asm.
   */
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

  /**
   * Address: 0x00594F80 (FUN_00594F80, std::map<std::string,Moho::CArmyStatItem*>'s
   * `_Tree::_Insert` node-buy-and-link-and-rebalance body -- allocates/links
   * the new node at the descended insertion point (calling the recovered
   * copy-ctor-based node allocation this file already uses for `new
   * moho::ArmyNameIndexNode{}`), then runs the identical red-black
   * insert-fixup loop below via `RotateNameIndexLeft`/`RotateNameIndexRight`
   * (FUN_00592E50/FUN_00592EE0))
   *
   * What it does:
   * Standard CLR-style red-black insert fixup: while the inserted node's
   * parent is red, recolor through the uncle or rotate to restore the
   * red-black invariants, then force the root black.
   */
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

  /**
   * Address: 0x00594E70 (FUN_00594E70, std::map<std::string,Moho::CArmyStatItem*>'s
   * `_Tree::_Insert` descent-and-duplicate-check body -- descends by key
   * comparison (`CompareNameIndexKey`), consulting the predecessor via
   * FUN_005952C0 when the descent doesn't land on the tree's cached minimum,
   * then calls FUN_00594F80 to buy/link/rebalance a new node on a miss)
   * Address: 0x00594C90 (FUN_00594C90, `std::map_string_CArmyStatItem_P::insert`
   * -- pair<iterator,bool> wrapper around FUN_00594E70)
   * Address: 0x00594B10 (FUN_00594B10, `std::map_string_CArmyStatItem_P::operator[]`
   * -- `_Lbound`-then-equality-check wrapper that inserts a default-constructed
   * mapped value on a miss and returns a reference to the slot)
   *
   * What it does:
   * `std::map<std::string,CArmyStatItem*>::insert`/`operator[]` combined:
   * finds the node for `statPath`, updating its value in place if present,
   * otherwise inserting a new node with `value` and rebalancing. The real
   * binary factors this into a separate descent (FUN_00594E70) and a
   * buy-and-rebalance call (FUN_00594F80) reached only on a miss, plus a
   * predecessor lookahead (FUN_005952C0) that is a pure performance
   * micro-optimization of the same textbook BST insert-position search; this
   * recovery's single-pass descent produces the identical final tree state.
   * `GetItem` (0x005945E0) calls the real `operator[]` then assigns through
   * the returned reference (`*operator[](key) = value`); calling this
   * function with `value` directly achieves the same net effect.
   */
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

  // --- shared red-black erase mechanics --------------------------------------
  //
  // The per-blueprint stat map (`std::map<const RBlueprint*, float>`) and the
  // stat-path name index (`std::map<msvc8::string, CArmyStatItem*>`) are two
  // instantiations of one MSVC8 `std::_Tree`, so the erase rebalance below is
  // written once and shared by both node families through the `RotateRb*`
  // overload set.

  void RotateRbLeft(moho::ArmyNameIndexTree* const tree, moho::ArmyNameIndexNode* const node)
  {
    RotateNameIndexLeft(tree, node);
  }

  void RotateRbRight(moho::ArmyNameIndexTree* const tree, moho::ArmyNameIndexNode* const node)
  {
    RotateNameIndexRight(tree, node);
  }
  template <class TNode>
  [[nodiscard]] bool IsRbNil(const TNode* const node) noexcept
  {
    return node == nullptr || node->isNil != 0u;
  }

  template <class TTree, class TNode>
  void FixupAfterRbErase(TTree* const tree, TNode* node, TNode* const nodeParent)
  {
    TNode* const head = tree->head;
    TNode* parent = (!IsRbNil(node)) ? node->parent : nodeParent;
    while (node != head->parent && (IsRbNil(node) || node->color == 1u)) {
      if (parent == nullptr) {
        break;
      }

      if (node == parent->left) {
        TNode* sibling = parent->right;
        if (sibling == head) {
          node = parent;
          parent = node->parent;
          continue;
        }
        if (sibling->color == 0u) {
          sibling->color = 1;
          parent->color = 0;
          RotateRbLeft(tree, parent);
          sibling = parent->right;
        }

        const bool leftBlack = IsRbNil(sibling->left) || sibling->left->color == 1u;
        const bool rightBlack = IsRbNil(sibling->right) || sibling->right->color == 1u;
        if (leftBlack && rightBlack) {
          sibling->color = 0;
          node = parent;
          parent = node->parent;
          continue;
        }

        if (IsRbNil(sibling->right) || sibling->right->color == 1u) {
          if (!IsRbNil(sibling->left)) {
            sibling->left->color = 1;
          }
          sibling->color = 0;
          RotateRbRight(tree, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1;
        if (!IsRbNil(sibling->right)) {
          sibling->right->color = 1;
        }
        RotateRbLeft(tree, parent);
        node = head->parent;
        break;
      }

      TNode* sibling = parent->left;
      if (sibling == head) {
        node = parent;
        parent = node->parent;
        continue;
      }
      if (sibling->color == 0u) {
        sibling->color = 1;
        parent->color = 0;
        RotateRbRight(tree, parent);
        sibling = parent->left;
      }

      const bool rightBlack = IsRbNil(sibling->right) || sibling->right->color == 1u;
      const bool leftBlack = IsRbNil(sibling->left) || sibling->left->color == 1u;
      if (rightBlack && leftBlack) {
        sibling->color = 0;
        node = parent;
        parent = node->parent;
        continue;
      }

      if (IsRbNil(sibling->left) || sibling->left->color == 1u) {
        if (!IsRbNil(sibling->right)) {
          sibling->right->color = 1;
        }
        sibling->color = 0;
        RotateRbLeft(tree, sibling);
        sibling = parent->left;
      }

      sibling->color = parent->color;
      parent->color = 1;
      if (!IsRbNil(sibling->left)) {
        sibling->left->color = 1;
      }
      RotateRbRight(tree, parent);
      node = head->parent;
      break;
    }

    if (!IsRbNil(node)) {
      node->color = 1;
    }
  }

  void FixupAfterNameIndexErase(
    moho::ArmyNameIndexTree* const tree,
    moho::ArmyNameIndexNode* const node,
    moho::ArmyNameIndexNode* const nodeParent
  )
  {
    FixupAfterRbErase(tree, node, nodeParent);
  }

  /**
   * Scoped owner for one stack-local blueprint-stat map.
   *
   * `CArmyStats::DumpStats` keeps two of these on its frame and the binary gives
   * both real `std::map` lifetimes - the unwind funclets at 0x00BB0B7E and
   * 0x00BB0B89 tear them down through 0x00585BD0 when an exception escapes the
   * body. This wrapper reproduces that without disturbing the binary layout of
   * `ArmyBlueprintStatTree`, which has to stay a plain header triple.
   */
  class ScopedBlueprintStatTree
  {
  public:
    ScopedBlueprintStatTree() = default;
    ScopedBlueprintStatTree(const ScopedBlueprintStatTree&) = delete;
    ScopedBlueprintStatTree& operator=(const ScopedBlueprintStatTree&) = delete;

    ~ScopedBlueprintStatTree() = default;

    [[nodiscard]] moho::ArmyBlueprintStatTree* Lane() noexcept
    {
      return &mTree;
    }

  private:
    moho::ArmyBlueprintStatTree mTree{};
  };

  /**
   * Directory the snapshot files are written to (`desktop_path`, 0x00F5A044) and
   * the per-process snapshot counter (`dword_10A63D8`, 0x010A63D8). Both are
   * file-scope state in the binary and only `CArmyStats::DumpStats` touches them.
   */
  msvc8::string gSnapshotDirectory;
  std::int32_t gSnapshotIndex = 0;

  /**
   * NOTE: inlined by the compiler at 0x0070C750-0x0070C7D1 and again, with the
   * iterator advance expanded in place, at 0x0070C9C0-0x0070CA76.
   *
   * What it does:
   * Walks one blueprint-stat map in key order and emits `id(description): value`
   * to the engine log and `id(description), value` to the snapshot file. The two
   * call sites differ only in the log format string (the second indents by one
   * space), so the shared body takes it as a parameter.
   */
  void DumpBlueprintStatLanes(
    gpg::TextWriter& writer,
    const moho::ArmyBlueprintStatTree& tree,
    const char* const logFormat
  )
  {
    for (const auto& entry : tree) {
      const moho::RBlueprint* const blueprint = AsBlueprint(entry.first);
      const int value = static_cast<int>(entry.second);
      gpg::Logf(logFormat, blueprint->mBlueprintId.c_str(), blueprint->mDescription.c_str(), value);
      writer.Printf("%s(%s), %d\n", blueprint->mBlueprintId.c_str(), blueprint->mDescription.c_str(), value);
    }
  }

  /**
   * NOTE: inlined by the compiler at 0x0070C7F0-0x0070C83F and again at
   * 0x0070CA90-0x0070CAD9.
   *
   * What it does:
   * Resolves each name in the NUL-terminated `categoryNames` table to its
   * entity-category set through `RRuleGameRules::GetEntityCategory` (vtable slot
   * 22, offset +0x58 - the `call [eax+58h]` both loops make) and logs the sum of
   * `item`'s blueprint lanes over that set.
   */
  void DumpCategorySums(
    gpg::TextWriter& writer,
    const moho::RRuleGameRules* const rules,
    const moho::CArmyStatItem* const item,
    const char* const* const categoryNames,
    const char* const logFormat
  )
  {
    for (const char* const* cursor = categoryNames; *cursor != nullptr; ++cursor) {
      const char* const categoryName = *cursor;
      const moho::EntityCategorySet* const category = ResolveStatsCategory(rules, categoryName);
      const int sum = SumStatCategoryInt(item, category);
      gpg::Logf(logFormat, categoryName, sum);
      writer.Printf("%s, %d\n", categoryName, sum);
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

  namespace
  {
    /**
     * Static `RPointerType<CArmyStatItem>` descriptor that the binary exposes
     * as `Moho::CArmyStatItem::PointerType`. Default static-init runs the
     * RPointerTypeBase → RType → RObject ctor chain and installs the most-
     * derived vftable lane.
     */
    gpg::RPointerType<moho::CArmyStatItem> sCArmyStatItemPointerTypeStorage{};

    /**
     * Address: 0x007116C0 (FUN_007116C0)
     *
     * What it does:
     * Pre-registers the static `RPointerType<CArmyStatItem>` descriptor under
     * the `CArmyStatItem*` type-info key so subsequent `LookupRType` queries
     * from the lazy `GetPointerType` lane resolve to this descriptor.
     */
    void PreregisterCArmyStatItemPointerType()
    {
      gpg::PreRegisterRType(typeid(moho::CArmyStatItem*), &sCArmyStatItemPointerTypeStorage);
    }

    /**
     * Address: 0x00BFF9A0 (FUN_00BFF9A0)
     *
     * What it does:
     * Tears down the static `RPointerType<CArmyStatItem>` descriptor at process
     * exit: frees heap-backed `bases_`/`fields_` vector storage and resets the
     * RType vftable lane to the `RObject` base. Registered via `atexit` from
     * `GetPointerType`'s once-init path.
     */
    void CleanupCArmyStatItemPointerType()
    {
      sCArmyStatItemPointerTypeStorage.~RPointerType<moho::CArmyStatItem>();
    }
  } // namespace

  /**
   * Address: 0x007107E0 (FUN_007107E0, Moho::CArmyStatItem::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<CArmyStatItem>`
   * descriptor and installs the matching atexit teardown. After that, lazily
   * caches the `LookupRType(typeid(CArmyStatItem*))` result in `sPointerType`
   * and returns it.
   */
  gpg::RType* CArmyStatItem::GetPointerType()
  {
    static const bool sOnceInit = []() {
      PreregisterCArmyStatItemPointerType();
      (void)std::atexit(&CleanupCArmyStatItemPointerType);
      return true;
    }();
    (void)sOnceInit;

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
    // `msvc8::map`'s own constructor builds the head sentinel and zeroes the
    // size, which is what the binary open-codes here.
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
    // 0x00585C39 reaches the map teardown through the range erase at
    // 0x00592230, which is what `clear()` compiles to.
    mBlueprintStats.clear();
  }

  /**
   * Address: 0x0070B430 (FUN_0070B430, CArmyStatItem vtable slot 1)
   */
  void CArmyStatItem::ToLua(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject)
  {
    StatItem::ToLua(state, outObject);
    if (mBlueprintStats.empty()) {
      return;
    }

    LuaPlus::LuaObject blueprints;
    blueprints.AssignNewTable(state, 0, 0);

    for (const auto& entry : mBlueprintStats) {
      const ArmyBlueprintNameView* const nameView = entry.first;
      if (nameView != nullptr) {
        const msvc8::string value = gpg::STR_Printf("%.2f", entry.second);
        blueprints.SetString(nameView->mName.c_str(), value.c_str());
      }
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

    float total = 0.0f;
    for (const auto& entry : mBlueprintStats) {
      const ArmyBlueprintNameView* const blueprintView = entry.first;
      if (blueprintView == nullptr) {
        continue;
      }

      if (categorySet->mBits.Contains(static_cast<unsigned int>(blueprintView->mBlueprintOrdinal))) {
        total += entry.second;
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
    // The binary is VC8's `map::operator[]`: lower_bound, then a *hinted*
    // insert of a zero-initialised mapped value when the key is absent, and
    // a reference to the mapped lane either way. That hinted insert is the
    // emission at 0x0070F6C0.
    return &mBlueprintStats[blueprintName];
  }

  /**
   * Address: 0x0070ADD0 (FUN_0070ADD0, sub_70ADD0)
   *
   * IDA signature:
   * int __usercall sub_70ADD0@<eax>(Moho::CArmyStatItem *a1@<eax>, int a2@<esi>);
   *
   * What it does:
   * Copy-constructs `mBlueprintStats` (`this + 0xA0`) into `destination` and
   * returns it, giving the caller a private snapshot of this item's per-blueprint
   * float lanes.
   */
  ArmyBlueprintStatTree* CArmyStatItem::CopyBlueprintStatsInto(ArmyBlueprintStatTree* const destination) const
  {
    *destination = mBlueprintStats;
    return destination;
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
   * Address: 0x0070CC40 (FUN_0070CC40, Moho::CArmyStats::ArmyXmlStatsNode)
   * Mangled: ?ArmyXmlStatsNode@CArmyStats@Moho@@QAE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@@Z
   */
  msvc8::string CArmyStats::ArmyXmlStatsNode(const msvc8::string& indent)
  {
    CAiBrain* const brain = mOwnerArmy;
    CArmyImpl* const army = brain->mArmy;
    RRuleGameRules* const rules = brain->mSim->mRules;

    const char* const indentText = indent.c_str();
    std::string xml;
    AppendMsvcString(
      xml,
      gpg::STR_Printf("%s<Army index=\"%d\" name=\"%s\">\n", indentText, army->ArmyId, army->PlayerName.c_str())
    );

    CArmyStatItem* const unitsActive = GetItem("Units_Active");
    CArmyStatItem* const unitsLost = GetItem("Units_Killed");
    CArmyStatItem* const enemiesKilled = GetItem("Enemies_Killed");
    CArmyStatItem* const damageDealt = GetItem("Units_TotalDamageDealt");
    CArmyStatItem* const damageReceived = GetItem("Units_TotalDamageReceive");

    msvc8::set<const ArmyBlueprintNameView*> blueprintKeys;
    CollectBlueprintStatKeys(blueprintKeys, unitsActive);
    CollectBlueprintStatKeys(blueprintKeys, enemiesKilled);

    AppendMsvcString(xml, gpg::STR_Printf("%s    <UnitStats>\n", indentText));
    for (const ArmyBlueprintNameView* const key : blueprintKeys) {
      const RBlueprint* const blueprint = AsBlueprint(key);
      const RUnitBlueprint* const unitBlueprint = AsUnitBlueprint(key);
      const EntityCategorySet* const unitCategory = ResolveStatsCategory(rules, blueprint->mBlueprintId.c_str());

      AppendMsvcString(
        xml,
        gpg::STR_Printf(
          "%s      <Unit id=\"%s\" type=\"%s\" built=\"%d\" lost=\"%d\" killed=\"%d\" damagedealt=\"%.2f\" damagereceived=\"%.2f\" masscost=\"%.2f\" energycost=\"%.2f\" buildtime=\"%.2f\"/>\n",
          indentText,
          blueprint->mBlueprintId.c_str(),
          blueprint->mDescription.c_str(),
          SumStatCategoryInt(unitsActive, unitCategory),
          SumStatCategoryInt(unitsLost, unitCategory),
          SumStatCategoryInt(enemiesKilled, unitCategory),
          SumStatCategory(damageDealt, unitCategory),
          SumStatCategory(damageReceived, unitCategory),
          unitBlueprint->Economy.BuildCostMass,
          unitBlueprint->Economy.BuildCostEnergy,
          unitBlueprint->Economy.BuildTime
        )
      );
    }
    AppendMsvcString(xml, gpg::STR_Printf("%s    </UnitStats>\n", indentText));

    AppendMsvcString(xml, gpg::STR_Printf("%s    <SummaryStats>\n", indentText));
    constexpr const char* kSummaryCategories[] = {
      "AIR",
      "LAND",
      "NAVAL",
      "ENGINEER",
      "ARTILLERY",
      "ANTIAIR",
      "TRANSPORTATION",
      "STRUCTURE",
      "FACTORY",
      "ENERGYPRODUCTION",
      "MASSPRODUCTION",
      "DEFENSE",
      "TECH1",
      "TECH2",
      "TECH3",
    };
    for (const char* const categoryName : kSummaryCategories) {
      AppendCategoryStatsXml(xml, indentText, rules, categoryName, unitsActive, enemiesKilled);
    }
    AppendMsvcString(xml, gpg::STR_Printf("%s    </SummaryStats>\n", indentText));

    AppendMsvcString(xml, gpg::STR_Printf("%s    <EconomyStats>\n", indentText));
    AppendMsvcString(
      xml,
      gpg::STR_Printf(
        "%s      <Energy produced=\"%.2f\" consumed=\"%.2f\" storage=\"%.2f\"/>\n",
        indentText,
        ReadRequiredFloatStat(*this, "Economy_TotalProduced_Energy"),
        ReadRequiredFloatStat(*this, "Economy_TotalConsumed_Energy"),
        ReadRequiredFloatStat(*this, "Economy_MaxStorage_Energy")
      )
    );
    AppendMsvcString(
      xml,
      gpg::STR_Printf(
        "%s      <Mass produced=\"%.2f\" consumed=\"%.2f\" storage=\"%.2f\"/>\n",
        indentText,
        ReadRequiredFloatStat(*this, "Economy_TotalProduced_Mass"),
        ReadRequiredFloatStat(*this, "Economy_TotalConsumed_Mass"),
        ReadRequiredFloatStat(*this, "Economy_MaxStorage_Mass")
      )
    );
    AppendMsvcString(xml, gpg::STR_Printf("%s    </EconomyStats>\n", indentText));
    AppendMsvcString(xml, gpg::STR_Printf("%s</Army>\n", indentText));

    msvc8::string result;
    result.assign_owned(std::string_view(xml.data(), xml.size()));
    return result;
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
   * Address: 0x0070C160 (FUN_0070C160, Moho::CArmyStats::DumpStats)
   *
   * IDA signature:
   * void __userpurge Moho::CArmyStats::DumpStats(double a1@<st0>, Moho::CArmyStats *a2);
   *
   * What it does:
   * Writes one army snapshot to `<snapshotDir>/SnapShot<N>.txt` and mirrors it to
   * the engine log. The first call resolves the output directory: it defaults to
   * `%USERPROFILE%/Desktop` and then offers a `wxDirDialog` (0x0070C438) whose
   * accepted path replaces it. wx leaves the x87 control word on its own setting,
   * so the sim's 24-bit precision is restored right after the dialog closes
   * (`_controlfp(_PC_24, _MCW_PC)` at 0x0070C587).
   */
  void CArmyStats::DumpStats()
  {
    // Both tables are materialized on the frame per call (0x0070C18C-0x0070C2FE)
    // and are NUL-terminated - the terminator is what ends each loop.
    const char* const categoryNames[] = {
      "AIR",
      "LAND",
      "NAVAL",
      "ENGINEER",
      "ARTILLERY",
      "ANTIAIR",
      "RADARSHIELDTRANSPORTATION",
      "STRUCTURE",
      "FACTORY",
      "AIRSTAGINGPLATFORM",
      "NUKE",
      "ANTIMISSILEENERGYPRODUCTION",
      "MASSPRODUCTION",
      "DEFENSE",
      "TECH1",
      "TECH2",
      "TECH3",
      nullptr,
    };
    const char* const economyStatPaths[] = {
      "Economy_TotalProduced_Energy",
      "Economy_TotalConsumed_Energy",
      "Economy_Income_Energy",
      "Economy_Output_Energy",
      "Economy_Stored_Energy",
      "Economy_Reclaimed_Energy",
      "Economy_MaxStorage_Energy",
      "Economy_PeakStorage_Energy",
      "Economy_TotalProduced_Mass",
      "Economy_TotalConsumed_Mass",
      "Economy_Income_Mass",
      "Economy_Output_Mass",
      "Economy_Stored_Mass",
      "Economy_Reclaimed_Mass",
      "Economy_MaxStorage_Mass",
      "Economy_PeakStorage_Mass",
      nullptr,
    };

    if (gSnapshotDirectory.size() == 0u) {
      gSnapshotDirectory.assign(
        gpg::STR_Printf("%s/Desktop", std::getenv("USERPROFILE")), 0, msvc8::string::npos
      );

      wxDirDialog directoryDialog(
        nullptr,
        wxT("Dump snap shot data to"),
        gpg::STR_Utf8ToWide(gSnapshotDirectory.c_str()).c_str(),
        wxDD_NEW_DIR_BUTTON
      );
      if (directoryDialog.ShowModal() == wxID_OK) {
        gSnapshotDirectory.assign(
          gpg::STR_WideToUtf8(directoryDialog.GetPath().c_str()), 0, msvc8::string::npos
        );
      }

      (void)_controlfp(_PC_24, _MCW_PC);
    }

    CAiBrain* const brain = mOwnerArmy;
    CArmyImpl* const army = brain->mArmy;
    RRuleGameRules* const rules = brain->mSim->mRules;

    const std::int32_t snapshotIndex = gSnapshotIndex++;
    const msvc8::string snapshotPath =
      gpg::STR_Printf("%s/SnapShot%d.txt", gSnapshotDirectory.c_str(), snapshotIndex);

    gpg::FileStream snapshotStream(snapshotPath.c_str(), gpg::Stream::ModeSend, 0u, 4096);
    gpg::TextWriter writer(&snapshotStream, 2);

    gpg::Logf("********** DUMPING ARMY BUILT SUMMARY FOR ARMY (%d) **********", army->ArmyId);

    CArmyStatItem* const unitsActive = GetItem("Units_Active");
    CArmyStatItem* const unitsProduced = GetItem("Units_History");
    CArmyStatItem* const unitsKilled = GetItem("Units_Killed");

    gpg::Logf(
      " Units Produced/Active/Killed: %i/%i/%i",
      unitsProduced->GetInt(false),
      unitsActive->GetInt(false),
      unitsKilled->GetInt(false)
    );
    writer.Printf("Units Active, %d\n", unitsActive->GetInt(false));
    writer.Printf("Units Produced, %d\n", unitsProduced->GetInt(false));
    writer.Printf("Units Killed, %d\n\n", unitsKilled->GetInt(false));

    // Declared after the stream so the frame unwinds tree-then-stream, matching
    // the binary's teardown at 0x0070CB05-0x0070CB41.
    ScopedBlueprintStatTree blueprintSnapshot;
    (void)unitsProduced->CopyBlueprintStatsInto(blueprintSnapshot.Lane());

    DumpBlueprintStatLanes(writer, *blueprintSnapshot.Lane(), "%s(%s): %d");
    writer.WriteNewline();
    DumpCategorySums(writer, rules, unitsProduced, categoryNames, "%s: %d");
    writer.WriteNewline();

    gpg::Logf("********** DUMPING ECONOMY STATS FOR ARMY (%d) **********", army->ArmyId);
    for (const char* const* cursor = economyStatPaths; *cursor != nullptr; ++cursor) {
      const char* const statPath = *cursor;
      const float value = ReadRequiredFloatStat(*this, statPath);
      gpg::Logf("%s: %.2f", statPath, value);
      writer.Printf("%s, %.2f\n", statPath, value);
    }
    writer.WriteNewline();

    gpg::Logf("********** DUMPING ENEMY KILLED SUMMARY FOR ARMY (%d) **********", army->ArmyId);
    CArmyStatItem* const enemiesKilled = GetItem("Enemies_Killed");
    gpg::Logf(" Enemies Killed: %i", enemiesKilled->GetInt(false));
    writer.Printf("Enemies Killed, %d\n\n", enemiesKilled->GetInt(false));

    {
      ScopedBlueprintStatTree enemyKilledSnapshot;
      (void)enemiesKilled->CopyBlueprintStatsInto(enemyKilledSnapshot.Lane());
      *blueprintSnapshot.Lane() = *enemyKilledSnapshot.Lane();
    }

    DumpBlueprintStatLanes(writer, *blueprintSnapshot.Lane(), " %s(%s): %d");
    writer.WriteNewline();
    // 0x0070CA9D reloads the spilled `Enemies_Killed` item from the frame slot
    // written at 0x0070C90D, so the second sweep sums that item - not the rules
    // pointer the decompiler's stack model attributes it to.
    DumpCategorySums(writer, rules, enemiesKilled, categoryNames, "%s : %d");

    gpg::Logf("***************************************************************");
    snapshotStream.VirtClose(gpg::Stream::ModeBoth);
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

    // Route the per-T raw-pointer ctor through the canonical helper
    // (FUN_007134C0) so the MSVC8 `shared_ptr<STrigger>(STrigger*)`
    // template emission symbol is preserved.
    boost::shared_ptr<STrigger> created;
    ConstructSharedSTriggerFromRaw(created, new STrigger());
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

  /**
   * Address: 0x007134C0 (FUN_007134C0, boost::shared_ptr<Moho::STrigger>::shared_ptr(STrigger*))
   *
   * What it does:
   * Per-T canonical-template-helper binding for the engine-instantiated
   * `boost::shared_ptr<Moho::STrigger>` raw-pointer constructor. Internally
   * `out.reset(raw)` constructs a fresh `shared_ptr<STrigger>` from the raw
   * pointer (allocating the `sp_counted_impl_p<STrigger>` reference-count
   * block with use_count=1 / weak_count=1, setting the vtable, and binding
   * the owned pointer) then swaps it into `out` — equivalent runtime
   * behavior to the binary's out-of-line ctor body.
   *
   * Wiring at the `EnsureTriggerExists` caller site preserves the MSVC8
   * per-T template emission symbol for `T = STrigger`.
   */
  void ConstructSharedSTriggerFromRaw(boost::shared_ptr<STrigger>& out, STrigger* const raw)
  {
    out.reset(raw);
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterCArmyStatItemPointerType_5a41c5, moho::PreregisterCArmyStatItemPointerType)
