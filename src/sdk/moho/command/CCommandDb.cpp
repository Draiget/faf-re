#include "moho/command/CCommandDb.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <sstream>
#include <utility>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/sim/SimDriver.h"

namespace
{
  constexpr std::uint8_t kTreeRed = 0u;
  constexpr std::uint8_t kTreeBlack = 1u;

  struct CommandDbMapNodeRuntime
  {
    CommandDbMapNodeRuntime* left;   // +0x00
    CommandDbMapNodeRuntime* parent; // +0x04
    CommandDbMapNodeRuntime* right;  // +0x08
    std::uint32_t key;               // +0x0C
    moho::CUnitCommand* value;       // +0x10
    std::uint8_t color;              // +0x14
    std::uint8_t isNil;              // +0x15
    std::uint8_t reserved16[2];      // +0x16
  };
  static_assert(sizeof(CommandDbMapNodeRuntime) == 0x18, "CommandDbMapNodeRuntime size must be 0x18");

  struct CommandDbMapRuntime
  {
    void* proxy;                     // +0x00
    CommandDbMapNodeRuntime* head;   // +0x04
    std::uint32_t size;              // +0x08
  };
  static_assert(sizeof(CommandDbMapRuntime) == 0x0C, "CommandDbMapRuntime size must be 0x0C");

  struct CCommandDbRuntimeView
  {
    moho::Sim* sim;                  // +0x0000
    CommandDbMapRuntime map;         // +0x0004
    moho::IdPool pool;               // +0x0010
    msvc8::vector<moho::CmdId> pendingReleasedCmdIds; // +0x0CC0
  };
  static_assert(offsetof(CCommandDbRuntimeView, map) == 0x04, "CCommandDbRuntimeView::map offset must be 0x04");
  static_assert(offsetof(CCommandDbRuntimeView, pool) == 0x10, "CCommandDbRuntimeView::pool offset must be 0x10");
  static_assert(
    offsetof(CCommandDbRuntimeView, pendingReleasedCmdIds) == 0xCC0,
    "CCommandDbRuntimeView::pendingReleasedCmdIds offset must be 0xCC0"
  );
  static_assert(sizeof(CCommandDbRuntimeView) == 0xCD0, "CCommandDbRuntimeView size must be 0xCD0");

  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] CommandDbMapNodeRuntime* CreateMapHeadNode()
  {
    auto* const head = static_cast<CommandDbMapNodeRuntime*>(::operator new(sizeof(CommandDbMapNodeRuntime)));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->key = 0u;
    head->value = nullptr;
    head->color = kTreeBlack;
    head->isNil = 1u;
    head->reserved16[0] = 0u;
    head->reserved16[1] = 0u;
    return head;
  }

  [[nodiscard]] CommandDbMapNodeRuntime* EnsureMapHead(CommandDbMapRuntime& map)
  {
    if (!map.head) {
      map.head = CreateMapHeadNode();
      map.size = 0u;
    }
    return map.head;
  }

  /**
   * Address: 0x006E1580 (FUN_006E1580)
   *
   * What it does:
   * Stores the command-map begin node (`head->left`) into output storage.
   */
  [[maybe_unused]] CommandDbMapNodeRuntime** StoreCommandMapBeginNode(
    CommandDbMapNodeRuntime** const outNode,
    const CommandDbMapRuntime* const map
  ) noexcept
  {
    *outNode = map->head->left;
    return outNode;
  }

  /**
   * Address: 0x006E15A0 (FUN_006E15A0)
   *
   * What it does:
   * Returns true when command-map size lane is zero.
   */
  [[maybe_unused]] bool IsCommandMapEmptyBySize(const CommandDbMapRuntime* const map) noexcept
  {
    return map->size == 0u;
  }

  /**
   * Address: 0x006E23C0 (FUN_006E23C0)
   *
   * What it does:
   * Returns one lower-bound node for `key` from the command map tree.
   */
  [[maybe_unused]] CommandDbMapNodeRuntime* LowerBoundCommandMapNode(
    const CommandDbMapRuntime* const map,
    const std::uint32_t* const key
  ) noexcept
  {
    CommandDbMapNodeRuntime* result = map->head;
    CommandDbMapNodeRuntime* cursor = result->parent;
    if (cursor->isNil == 0u) {
      const std::uint32_t value = *key;
      do {
        if (cursor->key >= value) {
          result = cursor;
          cursor = cursor->left;
        } else {
          cursor = cursor->right;
        }
      } while (cursor->isNil == 0u);
    }
    return result;
  }

  /**
   * Address: 0x006E1D30 (FUN_006E1D30)
   *
   * What it does:
   * Stores one lower-bound node for `key` into output storage.
   */
  [[maybe_unused]] CommandDbMapNodeRuntime** StoreLowerBoundCommandMapNode(
    CommandDbMapNodeRuntime** const outNode,
    const CommandDbMapRuntime* const map,
    const std::uint32_t* const key
  ) noexcept
  {
    *outNode = LowerBoundCommandMapNode(map, key);
    return outNode;
  }

  [[nodiscard]] const CommandDbMapNodeRuntime* LeftmostNode(
    const CommandDbMapNodeRuntime* node, const CommandDbMapNodeRuntime* head
  ) noexcept
  {
    const CommandDbMapNodeRuntime* cursor = node;
    while (cursor && cursor != head && cursor->left && cursor->left != head && cursor->left->isNil == 0u) {
      cursor = cursor->left;
    }
    return cursor ? cursor : head;
  }

  [[nodiscard]] const CommandDbMapNodeRuntime* RightmostNode(
    const CommandDbMapNodeRuntime* node, const CommandDbMapNodeRuntime* head
  ) noexcept
  {
    const CommandDbMapNodeRuntime* cursor = node;
    while (cursor && cursor != head && cursor->right && cursor->right != head && cursor->right->isNil == 0u) {
      cursor = cursor->right;
    }
    return cursor ? cursor : head;
  }

  [[nodiscard]] const CommandDbMapNodeRuntime* TreeSuccessor(
    const CommandDbMapNodeRuntime* node, const CommandDbMapNodeRuntime* head
  ) noexcept
  {
    if (!node || !head) {
      return head;
    }

    if (node->right && node->right != head && node->right->isNil == 0u) {
      return LeftmostNode(node->right, head);
    }

    const CommandDbMapNodeRuntime* child = node;
    const CommandDbMapNodeRuntime* parent = node->parent;
    while (parent && parent != head && child == parent->right) {
      child = parent;
      parent = parent->parent;
    }
    return parent ? parent : head;
  }

  [[nodiscard]] std::uint8_t NodeColor(
    const CommandDbMapNodeRuntime* node, const CommandDbMapNodeRuntime* head
  ) noexcept
  {
    return (!node || node == head || node->isNil != 0u) ? kTreeBlack : node->color;
  }

  void ReplaceTreeNode(
    CommandDbMapRuntime& map, CommandDbMapNodeRuntime* const oldNode, CommandDbMapNodeRuntime* const newNode
  )
  {
    CommandDbMapNodeRuntime* const head = map.head;
    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (newNode != nullptr && newNode != head) {
      newNode->parent = oldNode->parent;
    }
  }

  void RefreshTreeBounds(CommandDbMapRuntime& map)
  {
    CommandDbMapNodeRuntime* const head = map.head;
    if (!head) {
      return;
    }

    CommandDbMapNodeRuntime* const root = head->parent;
    if (!root || root == head || root->isNil != 0u) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = const_cast<CommandDbMapNodeRuntime*>(LeftmostNode(root, head));
    head->right = const_cast<CommandDbMapNodeRuntime*>(RightmostNode(root, head));
  }

  void RotateLeft(CommandDbMapRuntime& map, CommandDbMapNodeRuntime* const node)
  {
    CommandDbMapNodeRuntime* const head = map.head;
    CommandDbMapNodeRuntime* const pivot = node->right;

    node->right = pivot->left;
    if (pivot->left != head) {
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

  void RotateRight(CommandDbMapRuntime& map, CommandDbMapNodeRuntime* const node)
  {
    CommandDbMapNodeRuntime* const head = map.head;
    CommandDbMapNodeRuntime* const pivot = node->left;

    node->left = pivot->right;
    if (pivot->right != head) {
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

  void InsertCommandNodeFixup(CommandDbMapRuntime& map, CommandDbMapNodeRuntime* node)
  {
    CommandDbMapNodeRuntime* const head = map.head;
    while (node->parent != head && node->parent->color == kTreeRed) {
      CommandDbMapNodeRuntime* const grandParent = node->parent->parent;
      if (node->parent == grandParent->left) {
        CommandDbMapNodeRuntime* uncle = grandParent->right;
        if (NodeColor(uncle, head) == kTreeRed) {
          node->parent->color = kTreeBlack;
          if (uncle != head) {
            uncle->color = kTreeBlack;
          }
          grandParent->color = kTreeRed;
          node = grandParent;
          continue;
        }

        if (node == node->parent->right) {
          node = node->parent;
          RotateLeft(map, node);
        }

        node->parent->color = kTreeBlack;
        grandParent->color = kTreeRed;
        RotateRight(map, grandParent);
      } else {
        CommandDbMapNodeRuntime* uncle = grandParent->left;
        if (NodeColor(uncle, head) == kTreeRed) {
          node->parent->color = kTreeBlack;
          if (uncle != head) {
            uncle->color = kTreeBlack;
          }
          grandParent->color = kTreeRed;
          node = grandParent;
          continue;
        }

        if (node == node->parent->left) {
          node = node->parent;
          RotateRight(map, node);
        }

        node->parent->color = kTreeBlack;
        grandParent->color = kTreeRed;
        RotateLeft(map, grandParent);
      }
    }

    if (head->parent != nullptr && head->parent != head) {
      head->parent->color = kTreeBlack;
    }
  }

  void EraseNodeFixup(
    CommandDbMapRuntime& map, CommandDbMapNodeRuntime* node, CommandDbMapNodeRuntime* nodeParent
  )
  {
    CommandDbMapNodeRuntime* const head = map.head;
    while (node != head->parent && NodeColor(node, head) == kTreeBlack) {
      if (node == nodeParent->left) {
        CommandDbMapNodeRuntime* sibling = nodeParent->right;
        if (NodeColor(sibling, head) == kTreeRed) {
          sibling->color = kTreeBlack;
          nodeParent->color = kTreeRed;
          RotateLeft(map, nodeParent);
          sibling = nodeParent->right;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->left, head) == kTreeBlack && NodeColor(sibling->right, head) == kTreeBlack) {
          sibling->color = kTreeRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->right, head) == kTreeBlack) {
          if (sibling->left != head) {
            sibling->left->color = kTreeBlack;
          }
          sibling->color = kTreeRed;
          RotateRight(map, sibling);
          sibling = nodeParent->right;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kTreeBlack;
        if (sibling->right != head) {
          sibling->right->color = kTreeBlack;
        }
        RotateLeft(map, nodeParent);
      } else {
        CommandDbMapNodeRuntime* sibling = nodeParent->left;
        if (NodeColor(sibling, head) == kTreeRed) {
          sibling->color = kTreeBlack;
          nodeParent->color = kTreeRed;
          RotateRight(map, nodeParent);
          sibling = nodeParent->left;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->right, head) == kTreeBlack && NodeColor(sibling->left, head) == kTreeBlack) {
          sibling->color = kTreeRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->left, head) == kTreeBlack) {
          if (sibling->right != head) {
            sibling->right->color = kTreeBlack;
          }
          sibling->color = kTreeRed;
          RotateLeft(map, sibling);
          sibling = nodeParent->left;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kTreeBlack;
        if (sibling->left != head) {
          sibling->left->color = kTreeBlack;
        }
        RotateRight(map, nodeParent);
      }

      node = head->parent;
      break;
    }

    if (node != head) {
      node->color = kTreeBlack;
    }
  }

  void EraseCommandNode(CommandDbMapRuntime& map, CommandDbMapNodeRuntime* const node)
  {
    CommandDbMapNodeRuntime* const head = map.head;
    CommandDbMapNodeRuntime* spliceTarget = node;
    CommandDbMapNodeRuntime* rebalanceNode = head;
    CommandDbMapNodeRuntime* rebalanceParent = head;
    std::uint8_t removedColor = spliceTarget->color;

    if (node->left == head) {
      rebalanceNode = node->right;
      rebalanceParent = node->parent;
      ReplaceTreeNode(map, node, node->right);
    } else if (node->right == head) {
      rebalanceNode = node->left;
      rebalanceParent = node->parent;
      ReplaceTreeNode(map, node, node->left);
    } else {
      spliceTarget = const_cast<CommandDbMapNodeRuntime*>(LeftmostNode(node->right, head));
      removedColor = spliceTarget->color;
      rebalanceNode = spliceTarget->right;

      if (spliceTarget->parent == node) {
        rebalanceParent = spliceTarget;
        if (rebalanceNode != head) {
          rebalanceNode->parent = spliceTarget;
        }
      } else {
        rebalanceParent = spliceTarget->parent;
        ReplaceTreeNode(map, spliceTarget, spliceTarget->right);
        spliceTarget->right = node->right;
        spliceTarget->right->parent = spliceTarget;
      }

      ReplaceTreeNode(map, node, spliceTarget);
      spliceTarget->left = node->left;
      spliceTarget->left->parent = spliceTarget;
      spliceTarget->color = node->color;
    }

    if (removedColor == kTreeBlack) {
      EraseNodeFixup(map, rebalanceNode, rebalanceParent);
    }

    ::operator delete(node);
    if (map.size != 0u) {
      --map.size;
    }
    RefreshTreeBounds(map);
  }

  void DestroyCommandSubtree(CommandDbMapNodeRuntime* node, CommandDbMapNodeRuntime* const head)
  {
    if (node == nullptr || node == head || node->isNil != 0u) {
      return;
    }

    DestroyCommandSubtree(node->left, head);
    DestroyCommandSubtree(node->right, head);
    ::operator delete(node);
  }

  /**
   * Address: 0x006E22D0 (FUN_006E22D0, std::map_uint_CUnitCommand::_Erase-range helper)
   *
   * What it does:
   * Erases one half-open command-map iterator range and returns/stores the
   * successor iterator that follows the erased segment.
   */
  CommandDbMapNodeRuntime* EraseCommandMapRange(
    CommandDbMapRuntime& map,
    CommandDbMapNodeRuntime*& outIterator,
    CommandDbMapNodeRuntime* first,
    CommandDbMapNodeRuntime* last
  )
  {
    CommandDbMapNodeRuntime* const head = map.head;
    if (head == nullptr) {
      outIterator = last;
      return outIterator;
    }

    CommandDbMapNodeRuntime* cursor = first;
    if (cursor == head->left && last == head) {
      DestroyCommandSubtree(head->parent, head);
      head->parent = head;
      map.size = 0u;
      head->left = head;
      head->right = head;
      outIterator = head->left;
      return outIterator;
    }

    while (cursor != last) {
      CommandDbMapNodeRuntime* const current = cursor;
      if (current == nullptr || current == head) {
        cursor = last;
        break;
      }

      if (current->isNil == 0u) {
        CommandDbMapNodeRuntime* next = current->right;
        if (next->isNil != 0u) {
          CommandDbMapNodeRuntime* parent = current->parent;
          while (parent->isNil == 0u) {
            if (cursor != parent->right) {
              break;
            }
            cursor = parent;
            parent = parent->parent;
          }
          cursor = parent;
        } else {
          cursor = next;
          while (cursor->left->isNil == 0u) {
            cursor = cursor->left;
          }
        }
      }

      EraseCommandNode(map, current);
    }

    outIterator = cursor;
    return outIterator;
  }

  /**
   * Address: 0x006E1550 (FUN_006E1550)
   *
   * What it does:
   * Clears one legacy command-map tree payload, frees the map-header sentinel,
   * and zeros `{head,size}` lanes.
   */
  [[maybe_unused]] int ReleaseCommandMapStorageLaneA(CommandDbMapRuntime& map) noexcept
  {
    if (map.head != nullptr) {
      CommandDbMapNodeRuntime* iterator = map.head;
      (void)EraseCommandMapRange(map, iterator, map.head->left, map.head);
      ::operator delete(map.head);
    }

    map.head = nullptr;
    map.size = 0u;
    return 0;
  }

  /**
   * Address: 0x006E2020 (FUN_006E2020)
   *
   * What it does:
   * Duplicate release lane for command-map storage: erases all nodes, frees
   * the map-header sentinel, and zeros `{head,size}`.
   */
  [[maybe_unused]] int ReleaseCommandMapStorageLaneB(CommandDbMapRuntime& map) noexcept
  {
    return ReleaseCommandMapStorageLaneA(map);
  }

  [[nodiscard]] std::uint32_t ResolveCommandUnitEntryAddressForDump(const moho::CScriptObject* const entry) noexcept
  {
    if (entry == nullptr) {
      return 0u;
    }

    if (!moho::SCommandUnitSet::IsUsableEntry(entry)) {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entry));
    }

    const moho::Unit* const unit = moho::SCommandUnitSet::UnitFromEntry(entry);
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(unit));
  }

  void AppendCommandDbNodeDump(std::ostringstream& stream, const CommandDbMapNodeRuntime* const node)
  {
    stream << gpg::STR_Printf("  0x%08x =>", node->key).c_str();

    const moho::CUnitCommand* const command = node->value;
    if (command == nullptr) {
      stream << " NULL\n";
      return;
    }

    stream << "\n";
    stream << gpg::STR_Printf("    GetType() => %d\n", static_cast<int>(command->mVarDat.mCmdType)).c_str();

    const auto& entries = command->mUnitSet.mVec;
    const int unitCount = static_cast<int>(entries.size());
    const char* unitSuffix = "s";
    if (unitCount != 0) {
      unitSuffix = (unitCount == 1) ? ":" : "s:";
    }
    stream << gpg::STR_Printf("    %d Unit%s\n", unitCount, unitSuffix).c_str();

    for (const moho::CScriptObject* const entry : entries) {
      stream << gpg::STR_Printf("      0x%08x\n", ResolveCommandUnitEntryAddressForDump(entry)).c_str();
    }
  }

  void ValidateCommandMapEmptyOrDie(const CCommandDbRuntimeView& runtime)
  {
    const CommandDbMapRuntime& map = runtime.map;
    if (map.size == 0u || map.head == nullptr) {
      return;
    }

    std::ostringstream message{};
    message << "Trying to destroy the sim's command database, but it isn't empty.\n\n";

    const CommandDbMapNodeRuntime* const head = map.head;
    for (const CommandDbMapNodeRuntime* node = head->left; node != nullptr && node != head; node = TreeSuccessor(node, head)) {
      AppendCommandDbNodeDump(message, node);
    }

    gpg::Die("%s", message.str().c_str());
  }

  [[nodiscard]] CommandDbMapNodeRuntime* AllocateMapNode(
    const std::uint32_t key, moho::CUnitCommand* const value, CommandDbMapNodeRuntime* const head
  )
  {
    auto* const node = static_cast<CommandDbMapNodeRuntime*>(::operator new(sizeof(CommandDbMapNodeRuntime)));
    node->left = head;
    node->parent = head;
    node->right = head;
    node->key = key;
    node->value = value;
    node->color = kTreeRed;
    node->isNil = 0u;
    node->reserved16[0] = 0u;
    node->reserved16[1] = 0u;
    return node;
  }

  void InsertCommandNode(CommandDbMapRuntime& map, const std::uint32_t key, moho::CUnitCommand* const value)
  {
    CommandDbMapNodeRuntime* const head = EnsureMapHead(map);
    CommandDbMapNodeRuntime* parent = head;
    CommandDbMapNodeRuntime* cursor = head->parent;
    bool insertLeft = true;

    while (cursor && cursor != head && cursor->isNil == 0u) {
      parent = cursor;
      if (key < cursor->key) {
        insertLeft = true;
        cursor = cursor->left;
      } else if (cursor->key < key) {
        insertLeft = false;
        cursor = cursor->right;
      } else {
        cursor->value = value;
        return;
      }
    }

    CommandDbMapNodeRuntime* const node = AllocateMapNode(key, value, head);
    node->parent = parent;

    if (parent == head || parent == nullptr || parent->isNil != 0u) {
      head->parent = node;
      head->left = node;
      head->right = node;
      node->parent = head;
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

    ++map.size;
    InsertCommandNodeFixup(map, node);
    RefreshTreeBounds(map);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006E09C0 (FUN_006E09C0, ??0CommandDatabase@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one command database with its owning Sim and empty
   * container/id-pool lanes.
   */
  CCommandDb::CCommandDb(Sim* const sim)
    : sim(sim)
    , commands()
    , pool()
  {
  }

  /**
   * Address: 0x006E0A70 (FUN_006E0A70, ??1CommandDatabase@Moho@@QAE@@Z)
   * Mangled: ??1CommandDatabase@Moho@@QAE@@Z
   *
   * What it does:
   * Validates that the command map is empty (dumping and terminating if not),
   * then releases command-db map proxy storage, id-pool recycle lanes, and the
   * command map sentinel/tree storage.
   */
  CCommandDb::~CCommandDb()
  {
    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(this);
    ValidateCommandMapEmptyOrDie(*runtime);

    if (runtime->map.proxy != nullptr) {
      ::operator delete(runtime->map.proxy);
      runtime->map.proxy = nullptr;
    }

    runtime->pool.mSubRes2.Reset();
    runtime->pool.mReleasedLows.mWords.ResetStorageToInline();

    if (runtime->map.head != nullptr) {
      CommandDbMapNodeRuntime* iterator = runtime->map.head;
      (void)EraseCommandMapRange(runtime->map, iterator, runtime->map.head->left, runtime->map.head);
      ::operator delete(runtime->map.head);
      runtime->map.head = nullptr;
    }

    runtime->map.size = 0u;
  }

  /**
   * Address: 0x006E0DB0 (FUN_006E0DB0, Moho::CommandDatabase::AddIssueData)
   *
   * What it does:
   * Resolves a fresh command id when the incoming id is unresolved, constructs
   * one command from issue-data lanes, inserts it into the command map, and
   * returns the command pointer.
   */
  CUnitCommand* CCommandDb::AddIssueData(SSTICommandIssueData issueData)
  {
    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(this);
    CmdId commandId = issueData.nextCommandId;

    if ((static_cast<std::uint32_t>(commandId) & 0xFF000000u) == 0xFF000000u) {
      unsigned int nextLowId = 0u;
      if (runtime->pool.mReleasedLows.mWords.Empty()) {
        nextLowId = static_cast<unsigned int>(runtime->pool.mNextLowId);
        runtime->pool.mNextLowId = static_cast<std::int32_t>(nextLowId + 1u);
      } else {
        nextLowId = runtime->pool.mReleasedLows.GetNext(std::numeric_limits<unsigned int>::max());
        (void)runtime->pool.mReleasedLows.Remove(nextLowId);
      }

      commandId = static_cast<CmdId>(nextLowId | 0x80000000u);
      issueData.nextCommandId = commandId;
    }

    CUnitCommand* const command = new (std::nothrow) CUnitCommand(runtime->sim, issueData, commandId);
    if (command == nullptr) {
      return nullptr;
    }

    InsertCommandNode(runtime->map, static_cast<std::uint32_t>(command->mConstDat.cmd), command);
    return command;
  }

  /**
   * Address: 0x006E0F50 (FUN_006E0F50)
   *
   * What it does:
   * Publishes per-command sync event lanes into one outgoing sync packet,
   * swaps pending released command-id vectors with packet storage, and updates
   * id-pool recycle state.
   */
  void CCommandDb::PublishSyncData(SSyncData* const syncData, const bool forceRefresh)
  {
    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(this);
    CommandDbMapNodeRuntime* const head = runtime->map.head;

    if (head != nullptr && head->left != head) {
      for (CommandDbMapNodeRuntime* node = head->left; node != head;
           node = const_cast<CommandDbMapNodeRuntime*>(TreeSuccessor(node, head))) {
        CUnitCommand* const command = node->value;
        if (command != nullptr) {
          command->RefreshPublishedCommandEvent(forceRefresh, syncData);
        }
      }
    }

    std::swap(runtime->pendingReleasedCmdIds, syncData->mPendingReleasedCommandIds);
    runtime->pool.Update();
  }

  /**
   * Address: 0x006E2E10 (FUN_006E2E10)
   *
   * What it does:
   * Runs one `CCommandDb` destructor lane and then releases the object storage
   * with scalar `operator delete`, returning the same pointer.
   */
  [[maybe_unused]] CCommandDb* DestroyCommandDbAndDeleteStorage(CCommandDb* const db)
  {
    db->~CCommandDb();
    ::operator delete(db);
    return db;
  }

  /**
   * Address: 0x006E13A0 (FUN_006E13A0, Moho::CCommandDB::MemberSerialize)
   *
   * What it does:
   * Serializes each stored command pointer as `OWNED`, then writes the
   * terminating null command-pointer lane.
   */
  void CCommandDb::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const auto* const runtime = reinterpret_cast<const CCommandDbRuntimeView*>(this);
    const CommandDbMapNodeRuntime* const head = runtime->map.head;
    if (head && head->parent && head->parent != head) {
      for (const CommandDbMapNodeRuntime* node = LeftmostNode(head->parent, head); node && node != head;
           node = TreeSuccessor(node, head)) {
        gpg::RRef commandRef{};
        (void)gpg::RRef_CUnitCommand(&commandRef, node->value);
        gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Owned, NullOwnerRef());
      }
    }

    gpg::RRef nullRef{};
    (void)gpg::RRef_CUnitCommand_P(&nullRef, nullptr);
    gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Owned, NullOwnerRef());
  }

  /**
   * Address: 0x006E1430 (FUN_006E1430, Moho::CCommandDB::MemberDeserialize)
   *
   * What it does:
   * Reads owned command pointers until null terminator, assigns command ids
   * from the id-pool lanes, and inserts commands into the runtime map.
   */
  void CCommandDb::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(this);
    CommandDbMapNodeRuntime* const head = EnsureMapHead(runtime->map);
    CommandDbMapNodeRuntime* rangeResult = head;
    (void)EraseCommandMapRange(runtime->map, rangeResult, head->left, head);

    CUnitCommand* command = nullptr;
    gpg::RRef ownerRef{};
    (void)archive->ReadPointerOwned_CUnitCommand(&command, &ownerRef);

    while (command != nullptr) {
      BVIntSet& releasedLowIds = runtime->pool.mReleasedLows;
      std::uint32_t nextLowId = 0u;

      if (releasedLowIds.mWords.Empty()) {
        nextLowId = static_cast<std::uint32_t>(runtime->pool.mNextLowId);
        runtime->pool.mNextLowId = static_cast<std::int32_t>(nextLowId + 1u);
      } else {
        nextLowId = releasedLowIds.GetNext(std::numeric_limits<unsigned int>::max());

        const unsigned int wordIndex = (nextLowId >> 5u) - releasedLowIds.mFirstWordIndex;
        const std::size_t wordCount = releasedLowIds.mWords.Size();
        if (static_cast<std::size_t>(wordIndex) < wordCount) {
          releasedLowIds.mWords[wordIndex] &= ~(1u << (nextLowId & 0x1Fu));
          releasedLowIds.Finalize();
        }
      }

      const CmdId commandId = static_cast<CmdId>(nextLowId | 0x80000000u);
      command->mConstDat.cmd = commandId;
      InsertCommandNode(runtime->map, static_cast<std::uint32_t>(commandId), command);

      ownerRef.mObj = nullptr;
      ownerRef.mType = nullptr;
      command = nullptr;
      (void)archive->ReadPointerOwned_CUnitCommand(&command, &ownerRef);
    }
  }

  /**
   * Address: 0x006E3300 (FUN_006E3300)
   *
   * What it does:
   * Register-shape adapter that forwards one command-db save lane to
   * `CCommandDb::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCommandDbMemberLanePrimary(
    gpg::WriteArchive* const archive,
    CCommandDb* const commandDb
  )
  {
    commandDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x006E3CF0 (FUN_006E3CF0)
   *
   * What it does:
   * Register-shape adapter that forwards one command-db load lane to
   * `CCommandDb::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCommandDbMemberLane(
    CCommandDb* const commandDb,
    gpg::ReadArchive* const archive
  )
  {
    commandDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006E3D00 (FUN_006E3D00)
   *
   * What it does:
   * Secondary register-shape adapter that forwards one command-db save lane to
   * `CCommandDb::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCommandDbMemberLaneSecondary(
    gpg::WriteArchive* const archive,
    CCommandDb* const commandDb
  )
  {
    commandDb->MemberSerialize(archive);
  }
} // namespace moho
