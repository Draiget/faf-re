#include "moho/command/CCommandDb.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

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
    std::uint8_t reservedCC0[0x10];  // +0x0CC0
  };
  static_assert(offsetof(CCommandDbRuntimeView, map) == 0x04, "CCommandDbRuntimeView::map offset must be 0x04");
  static_assert(offsetof(CCommandDbRuntimeView, pool) == 0x10, "CCommandDbRuntimeView::pool offset must be 0x10");
  static_assert(offsetof(CCommandDbRuntimeView, reservedCC0) == 0xCC0, "CCommandDbRuntimeView::reservedCC0 offset must be 0xCC0");
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
    (void)EnsureMapHead(runtime->map);

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
} // namespace moho
