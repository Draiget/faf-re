#include "moho/audio/CSndVar.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetOwned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int value);
  };
} // namespace gpg

namespace
{
  constexpr std::uint32_t kSndVarHashSalt = 0x7BEF2693u;

  std::recursive_mutex gSndVarRegistryMutex;
  std::vector<moho::CSndVar*> gSndVarRegistry;
  std::unordered_multimap<std::uint32_t, moho::CSndVar*> gSndVarNameCache;

  struct SndVarRegistryEntryRuntimeView
  {
    std::uint32_t lane00 = 0;
    std::uint32_t lane04 = 0;
    std::uint32_t lane08 = 0;
  };
  static_assert(sizeof(SndVarRegistryEntryRuntimeView) == 0x0C, "SndVarRegistryEntryRuntimeView size must be 0x0C");

  struct SndVarTreeNodeHeadRuntimeView
  {
    std::uint32_t parent = 0;      // +0x00
    std::uint32_t left = 0;        // +0x04
    std::uint32_t right = 0;       // +0x08
    std::uint8_t reserved0C[0x8]{}; // +0x0C
    std::uint8_t color = 0;        // +0x14
    std::uint8_t isNil = 0;        // +0x15
    std::uint8_t reserved16[0x2]{}; // +0x16
  };
  static_assert(
    offsetof(SndVarTreeNodeHeadRuntimeView, color) == 0x14,
    "SndVarTreeNodeHeadRuntimeView::color offset must be 0x14"
  );
  static_assert(
    offsetof(SndVarTreeNodeHeadRuntimeView, isNil) == 0x15,
    "SndVarTreeNodeHeadRuntimeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(SndVarTreeNodeHeadRuntimeView) == 0x18, "SndVarTreeNodeHeadRuntimeView size must be 0x18");

  struct SndVarTreeIteratorNodeRuntimeView
  {
    SndVarTreeIteratorNodeRuntimeView* left;   // +0x00
    SndVarTreeIteratorNodeRuntimeView* parent; // +0x04
    SndVarTreeIteratorNodeRuntimeView* right;  // +0x08
    std::uint8_t reserved0C[0x8]{};            // +0x0C
    std::uint8_t color = 0;                    // +0x14
    std::uint8_t isNil = 0;                    // +0x15
    std::uint8_t reserved16[0x2]{};            // +0x16
  };
  static_assert(
    offsetof(SndVarTreeIteratorNodeRuntimeView, isNil) == 0x15,
    "SndVarTreeIteratorNodeRuntimeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(SndVarTreeIteratorNodeRuntimeView) == 0x18, "SndVarTreeIteratorNodeRuntimeView size must be 0x18");

  struct SndVarTreeLookupNodeRuntimeView
  {
    SndVarTreeLookupNodeRuntimeView* left;   // +0x00
    SndVarTreeLookupNodeRuntimeView* parent; // +0x04
    SndVarTreeLookupNodeRuntimeView* right;  // +0x08
    std::uint32_t keyHash = 0;               // +0x0C
    moho::CSndVar* value = nullptr;          // +0x10
    std::uint8_t color = 0;                  // +0x14
    std::uint8_t isNil = 0;                  // +0x15
    std::uint8_t reserved16[0x2]{};          // +0x16
  };
  static_assert(
    offsetof(SndVarTreeLookupNodeRuntimeView, keyHash) == 0x0C,
    "SndVarTreeLookupNodeRuntimeView::keyHash offset must be 0x0C"
  );
  static_assert(
    offsetof(SndVarTreeLookupNodeRuntimeView, value) == 0x10,
    "SndVarTreeLookupNodeRuntimeView::value offset must be 0x10"
  );
  static_assert(
    offsetof(SndVarTreeLookupNodeRuntimeView, isNil) == 0x15,
    "SndVarTreeLookupNodeRuntimeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(SndVarTreeLookupNodeRuntimeView) == 0x18, "SndVarTreeLookupNodeRuntimeView size must be 0x18");

  struct SndVarTreeLookupOwnerRuntimeView
  {
    std::uint32_t reserved00 = 0;                  // +0x00
    SndVarTreeLookupNodeRuntimeView* header = nullptr; // +0x04
  };
  static_assert(
    offsetof(SndVarTreeLookupOwnerRuntimeView, header) == 0x04,
    "SndVarTreeLookupOwnerRuntimeView::header offset must be 0x04"
  );
  static_assert(sizeof(SndVarTreeLookupOwnerRuntimeView) == 0x8, "SndVarTreeLookupOwnerRuntimeView size must be 0x8");

  struct SndVarTreeLookupRangeRuntimeView
  {
    SndVarTreeLookupNodeRuntimeView* lowerBound = nullptr; // +0x00
    SndVarTreeLookupNodeRuntimeView* upperBound = nullptr; // +0x04
  };
  static_assert(sizeof(SndVarTreeLookupRangeRuntimeView) == 0x8, "SndVarTreeLookupRangeRuntimeView size must be 0x8");

  struct SndVarListNodeRuntimeView
  {
    SndVarListNodeRuntimeView* next; // +0x00
    SndVarListNodeRuntimeView* prev; // +0x04
  };
  static_assert(sizeof(SndVarListNodeRuntimeView) == 0x08, "SndVarListNodeRuntimeView size must be 0x08");

  struct SndVarListStorageRuntimeView
  {
    void* allocProxy;                 // +0x00
    SndVarListNodeRuntimeView* head;  // +0x04
    std::uint32_t size;               // +0x08
  };
  static_assert(sizeof(SndVarListStorageRuntimeView) == 0x0C, "SndVarListStorageRuntimeView size must be 0x0C");

  struct SndVarListNodeKeyRuntimeView
  {
    SndVarListNodeKeyRuntimeView* next; // +0x00
    SndVarListNodeKeyRuntimeView* prev; // +0x04
    std::int32_t key;                   // +0x08
  };
  static_assert(sizeof(SndVarListNodeKeyRuntimeView) == 0x0C, "SndVarListNodeKeyRuntimeView size must be 0x0C");
  static_assert(
    offsetof(SndVarListNodeKeyRuntimeView, key) == 0x08,
    "SndVarListNodeKeyRuntimeView::key offset must be 0x08"
  );

  struct SndVarPayloadNodeRuntimeView
  {
    SndVarPayloadNodeRuntimeView* next; // +0x00
    SndVarPayloadNodeRuntimeView* prev; // +0x04
    void* payload;                      // +0x08
  };
  static_assert(sizeof(SndVarPayloadNodeRuntimeView) == 0x0C, "SndVarPayloadNodeRuntimeView size must be 0x0C");
  static_assert(
    offsetof(SndVarPayloadNodeRuntimeView, payload) == 0x08,
    "SndVarPayloadNodeRuntimeView::payload offset must be 0x08"
  );

  struct SndVarDetachedChainNodeRuntimeView
  {
    SndVarDetachedChainNodeRuntimeView* prev; // +0x00
    SndVarDetachedChainNodeRuntimeView* next; // +0x04
  };

  struct SndVarDetachedChainHeadRuntimeView
  {
    SndVarDetachedChainNodeRuntimeView* first; // +0x00
  };

  struct SndVarTreeNodeWithDetachedChainRuntimeView
  {
    SndVarTreeNodeWithDetachedChainRuntimeView* left;   // +0x00
    SndVarTreeNodeWithDetachedChainRuntimeView* parent; // +0x04
    SndVarTreeNodeWithDetachedChainRuntimeView* right;  // +0x08
    std::uint32_t keyHash = 0;                          // +0x0C
    SndVarDetachedChainHeadRuntimeView* detachedChainHead = nullptr; // +0x10
    std::uint8_t color = 0;                             // +0x14
    std::uint8_t isNil = 0;                             // +0x15
    std::uint8_t reserved16[2]{};                       // +0x16
  };
  static_assert(
    offsetof(SndVarTreeNodeWithDetachedChainRuntimeView, detachedChainHead) == 0x10,
    "SndVarTreeNodeWithDetachedChainRuntimeView::detachedChainHead offset must be 0x10"
  );

  /**
   * Address: 0x004E3410 (FUN_004E3410)
   *
   * What it does:
   * Clears one intrusive doubly-linked list lane by resetting the head sentinel
   * links to self, zeroing the size lane, and freeing all detached nodes.
   */
  [[maybe_unused]] [[nodiscard]] SndVarListNodeRuntimeView* ClearSndVarListStorage(
    SndVarListStorageRuntimeView* const storage
  )
  {
    SndVarListNodeRuntimeView* const head = storage->head;
    SndVarListNodeRuntimeView* node = head->next;
    head->next = head;
    head->prev = head;
    storage->size = 0u;

    if (node != head) {
      do {
        SndVarListNodeRuntimeView* const next = node->next;
        ::operator delete(node);
        node = next;
      } while (node != head);
    }

    return node;
  }

  /**
   * Address: 0x004E25E0 (FUN_004E25E0)
   *
   * What it does:
   * Unlinks one node from the intrusive sound-variable list (when not the
   * head sentinel), deletes that node, decrements the list size lane, and
   * returns the detached node's `next` link through the output slot.
   */
  [[maybe_unused]] [[nodiscard]] SndVarListNodeRuntimeView** UnlinkAndDeleteSndVarListNode(
    SndVarListNodeRuntimeView** const outNextNodeSlot,
    SndVarListStorageRuntimeView* const storage,
    SndVarListNodeRuntimeView* const node
  ) noexcept
  {
    SndVarListNodeRuntimeView* const next = node->next;
    if (node != storage->head) {
      node->prev->next = next;
      next->prev = node->prev;
      ::operator delete(node);
      --storage->size;
    }

    *outNextNodeSlot = next;
    return outNextNodeSlot;
  }

  /**
   * Address: 0x004E1B50 (FUN_004E1B50)
   *
   * What it does:
   * Walks one intrusive keyed-list lane, erases every node whose key matches
   * `*keySlot`, decrements the tracked node-count lane, and returns the final
   * traversal cursor.
   */
  [[maybe_unused]] [[nodiscard]] SndVarListNodeKeyRuntimeView* EraseSndVarNodesByKey(
    const std::int32_t* const keySlot,
    SndVarListStorageRuntimeView* const storage
  ) noexcept
  {
    auto* const head = reinterpret_cast<SndVarListNodeKeyRuntimeView*>(storage->head);
    const std::int32_t key = *keySlot;

    SndVarListNodeKeyRuntimeView* cursor = head->next;
    while (cursor != head) {
      if (cursor->key == key) {
        SndVarListNodeKeyRuntimeView* const next = cursor->next;
        if (cursor != head) {
          cursor->prev->next = next;
          next->prev = cursor->prev;
          ::operator delete(cursor);
          --storage->size;
        }
        cursor = next;
      } else {
        cursor = cursor->next;
      }
    }

    return cursor;
  }

  /**
   * Address: 0x004E2630 (FUN_004E2630)
   *
   * What it does:
   * Clears one sound-variable intrusive list payload lane, releases the list
   * head sentinel allocation, and nulls the head slot.
   */
  [[maybe_unused]] void DestroySndVarListStorageAndReleaseHead(
    SndVarListStorageRuntimeView* const storage
  ) noexcept
  {
    (void)ClearSndVarListStorage(storage);
    ::operator delete(storage->head);
    storage->head = nullptr;
  }

  /**
   * Address: 0x004E3450 (FUN_004E3450)
   *
   * What it does:
   * Allocates one 12-byte registry entry and seeds the three scalar lanes from
   * caller-owned values.
   */
  [[maybe_unused]] [[nodiscard]] SndVarRegistryEntryRuntimeView* AllocateSndVarRegistryEntryRuntime(
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t* const lane08Source
  )
  {
    auto* const entry = static_cast<SndVarRegistryEntryRuntimeView*>(gpg::core::legacy::AllocateChecked12ByteLane(1u));
    if (entry != nullptr) {
      entry->lane00 = lane00;
    }
    if (entry != reinterpret_cast<SndVarRegistryEntryRuntimeView*>(-4)) {
      entry->lane04 = lane04;
    }
    if (entry != reinterpret_cast<SndVarRegistryEntryRuntimeView*>(-8)) {
      entry->lane08 = *lane08Source;
    }
    return entry;
  }

  [[nodiscard]] SndVarTreeNodeHeadRuntimeView* AllocateSndVarTreeNodeHeadRuntime()
  {
    auto* const node = static_cast<SndVarTreeNodeHeadRuntimeView*>(gpg::core::legacy::AllocateChecked24ByteLane(1u));
    if (node != nullptr) {
      node->parent = 0;
    }
    if (node != reinterpret_cast<SndVarTreeNodeHeadRuntimeView*>(-4)) {
      node->left = 0;
    }
    if (node != reinterpret_cast<SndVarTreeNodeHeadRuntimeView*>(-8)) {
      node->right = 0;
    }
    node->color = 1;
    node->isNil = 0;
    return node;
  }

  /**
   * Address: 0x004E3B50 (FUN_004E3B50)
   *
   * What it does:
   * Allocates and zero-seeds one 24-byte sound runtime tree-head node with the
   * original non-sentinel color/isNil flag lane values.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeNodeHeadRuntimeView* AllocateSndVarParamsCacheHeadRuntime()
  {
    return AllocateSndVarTreeNodeHeadRuntime();
  }

  /**
   * Address: 0x004E3FD0 (FUN_004E3FD0)
   *
   * What it does:
   * Allocates and zero-seeds one 24-byte sound runtime tree-head node with the
   * original non-sentinel color/isNil flag lane values.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeNodeHeadRuntimeView* AllocateSndVarAuxCacheHeadRuntimeA()
  {
    return AllocateSndVarTreeNodeHeadRuntime();
  }

  /**
   * Address: 0x004E4340 (FUN_004E4340)
   *
   * What it does:
   * Allocates and zero-seeds one 24-byte sound runtime tree-head node with the
   * original non-sentinel color/isNil flag lane values.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeNodeHeadRuntimeView* AllocateSndVarAuxCacheHeadRuntimeB()
  {
    return AllocateSndVarTreeNodeHeadRuntime();
  }

  /**
   * Address: 0x004E17C0 (FUN_004E17C0)
   * Address: 0x008B62C0 (FUN_008B62C0)
   *
   * What it does:
   * Computes the `(lower_bound, upper_bound)` node pair for one hash probe in
   * the legacy sound-variable RB-tree cache.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeLookupRangeRuntimeView* ResolveSndVarHashEqualRange(
    SndVarTreeLookupRangeRuntimeView* const outRange,
    const SndVarTreeLookupOwnerRuntimeView* const treeOwner,
    const std::uint32_t* const hashKeySlot
  ) noexcept
  {
    SndVarTreeLookupNodeRuntimeView* upperBound = treeOwner->header;
    SndVarTreeLookupNodeRuntimeView* cursor = upperBound->parent;
    while (cursor->isNil == 0u) {
      if (*hashKeySlot < cursor->keyHash) {
        upperBound = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }

    SndVarTreeLookupNodeRuntimeView* lowerBound = treeOwner->header;
    cursor = lowerBound->parent;
    while (cursor->isNil == 0u) {
      if (cursor->keyHash >= *hashKeySlot) {
        lowerBound = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }

    outRange->lowerBound = lowerBound;
    outRange->upperBound = upperBound;
    return outRange;
  }

  [[nodiscard]] SndVarTreeIteratorNodeRuntimeView* AdvanceSndVarTreeSuccessorCursorCore(
    SndVarTreeIteratorNodeRuntimeView** const cursor
  )
  {
    SndVarTreeIteratorNodeRuntimeView* result = *cursor;
    if (result->isNil == 0u) {
      SndVarTreeIteratorNodeRuntimeView* node = result->right;
      if (node->isNil != 0u) {
        for (result = result->parent; result->isNil == 0u; result = result->parent) {
          if (*cursor != result->right) {
            break;
          }
          *cursor = result;
        }
        *cursor = result;
      } else {
        result = node->left;
        if (node->left->isNil == 0u) {
          do {
            node = result;
            result = result->left;
          } while (result->isNil == 0u);
        }
        *cursor = node;
      }
    }
    return result;
  }

  /**
   * Address: 0x004E3640 (FUN_004E3640)
   *
   * What it does:
   * Advances one legacy RB-tree cursor to its in-order successor and returns
   * the same sentinel/probe lane value shape observed by the original helper.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeIteratorNodeRuntimeView* AdvanceSndVarTreeSuccessorCursor(
    SndVarTreeIteratorNodeRuntimeView** const cursor
  )
  {
    return AdvanceSndVarTreeSuccessorCursorCore(cursor);
  }

  /**
   * Address: 0x004E36D0 (FUN_004E36D0)
   *
   * What it does:
   * Alternate calling-convention lane of the same RB-tree successor helper
   * used by CSndParams cache traversal.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeIteratorNodeRuntimeView* AdvanceSndParamsTreeSuccessorCursor(
    void* const /*unusedThisLike*/,
    SndVarTreeIteratorNodeRuntimeView** const cursor
  )
  {
    return AdvanceSndVarTreeSuccessorCursorCore(cursor);
  }

  /**
   * Address: 0x004E3AD0 (FUN_004E3AD0)
   *
   * What it does:
   * Walks the left-child lane until the next sentinel and returns the last
   * non-sentinel node reached (or the input node when already minimal).
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeIteratorNodeRuntimeView* ResolveLeftmostSndVarTreeNode(
    SndVarTreeIteratorNodeRuntimeView* const node
  )
  {
    if (node == nullptr) {
      return nullptr;
    }

    SndVarTreeIteratorNodeRuntimeView* result = node;
    SndVarTreeIteratorNodeRuntimeView* next = result->left;
    if (next != nullptr && next->isNil == 0u) {
      do {
        result = next;
        next = result->left;
      } while (next != nullptr && next->isNil == 0u);
    }

    return result;
  }

  /**
   * Address: 0x004E48D0 (FUN_004E48D0)
   *
   * What it does:
   * Alternate successor-walk lane for the same sound variable RB-tree cursor
   * traversal routine.
   */
  [[maybe_unused]] [[nodiscard]] SndVarTreeIteratorNodeRuntimeView* AdvanceSndVarTreeSuccessorCursorAlt(
    void* const /*unusedThisLike*/,
    SndVarTreeIteratorNodeRuntimeView** const cursor
  )
  {
    return AdvanceSndVarTreeSuccessorCursorCore(cursor);
  }

  /**
   * Address: 0x004E5A00 (FUN_004E5A00)
   *
   * What it does:
   * Detaches every node from one linear intrusive chain head, nulling each
   * detached node link pair, then releases the chain-head allocation.
   */
  [[maybe_unused]] [[nodiscard]] SndVarDetachedChainHeadRuntimeView* DestroyDetachedSndVarChainHead(
    SndVarDetachedChainHeadRuntimeView* const chainHead
  ) noexcept
  {
    if (chainHead == nullptr) {
      return nullptr;
    }

    while (chainHead->first != nullptr) {
      SndVarDetachedChainNodeRuntimeView* const node = chainHead->first;
      chainHead->first = node->next;
      node->prev = nullptr;
      node->next = nullptr;
    }

    ::operator delete(chainHead);
    return chainHead;
  }

  /**
   * Address: 0x004E4A40 (FUN_004E4A40)
   *
   * What it does:
   * Walks one intrusive payload-node range and destroys/frees each non-null
   * `CSndVar` payload.
   */
  [[maybe_unused]] void DestroyCSndVarPayloadRange(
    SndVarPayloadNodeRuntimeView* const begin,
    SndVarPayloadNodeRuntimeView* const end,
    const std::uint8_t /*tailTag*/
  ) noexcept
  {
    for (SndVarPayloadNodeRuntimeView* cursor = begin; cursor != end; cursor = cursor->next) {
      auto* const payload = static_cast<moho::CSndVar*>(cursor->payload);
      if (payload != nullptr) {
        payload->~CSndVar();
        ::operator delete(payload);
      }
    }
  }

  /**
   * Address: 0x004E49A0 (FUN_004E49A0)
   *
   * What it does:
   * Walks one RB-tree iterator range and frees each node's detached chain-head
   * lane (`+0x10`) after unlinking its chained payload nodes.
   */
  [[maybe_unused]] std::uint8_t DestroyDetachedSndVarChainsForTreeRange(
    SndVarTreeNodeWithDetachedChainRuntimeView* const begin,
    SndVarTreeNodeWithDetachedChainRuntimeView* const end,
    const std::uint8_t tailTag
  ) noexcept
  {
    SndVarTreeNodeWithDetachedChainRuntimeView* cursor = begin;
    while (cursor != end) {
      if (cursor->detachedChainHead != nullptr) {
        (void)DestroyDetachedSndVarChainHead(cursor->detachedChainHead);
      }

      auto* iteratorCursor = reinterpret_cast<SndVarTreeIteratorNodeRuntimeView*>(cursor);
      (void)AdvanceSndVarTreeSuccessorCursorAlt(nullptr, &iteratorCursor);
      cursor = reinterpret_cast<SndVarTreeNodeWithDetachedChainRuntimeView*>(iteratorCursor);
    }

    return tailTag;
  }

  [[nodiscard]] std::uint32_t HashSndVarName(const msvc8::string& name)
  {
    const std::string hashInput(name.c_str(), name.size());
    return gpg::Hash(hashInput, kSndVarHashSalt);
  }

  [[nodiscard]] moho::CSndVar*
  FindCachedSndVarByNameLocked(const msvc8::string& variableName, const std::uint32_t nameHash)
  {
    const auto [first, last] = gSndVarNameCache.equal_range(nameHash);
    for (auto it = first; it != last; ++it) {
      moho::CSndVar* const entry = it->second;
      if (entry != nullptr && entry->mName.view() == variableName.view()) {
        return entry;
      }
    }

    return nullptr;
  }

  void RemoveCachedSndVarByPointerLocked(const moho::CSndVar* const value)
  {
    for (auto it = gSndVarNameCache.begin(); it != gSndVarNameCache.end();) {
      if (it->second == value) {
        it = gSndVarNameCache.erase(it);
      } else {
        ++it;
      }
    }
  }

  /**
   * Address: 0x004DF990 (FUN_004DF990, func_RegisterCSndVar)
   *
   * What it does:
   * Registers one `CSndVar` instance in the process-global variable-name lane.
   */
  void RegisterSndVarInstance(moho::CSndVar* const value)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    gSndVarRegistry.push_back(value);
  }

  /**
   * Address: 0x004DFA20 (FUN_004DFA20)
   *
   * What it does:
   * Removes one `CSndVar` instance from the process-global variable-name lane.
   */
  void UnregisterSndVarInstance(const moho::CSndVar* const value)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    RemoveCachedSndVarByPointerLocked(value);
    const auto it = std::remove(gSndVarRegistry.begin(), gSndVarRegistry.end(), value);
    gSndVarRegistry.erase(it, gSndVarRegistry.end());
  }

  /**
   * Address: 0x004DFAE0 (FUN_004DFAE0)
   *
   * What it does:
   * Returns the registered variable name for one resolved variable id, or an
   * empty string when no matching descriptor is present.
   */
  msvc8::string LookupSndVarNameById(const std::uint16_t variableId)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    for (const moho::CSndVar* const entry : gSndVarRegistry) {
      if (entry != nullptr && entry->mState == variableId) {
        return entry->mName;
      }
    }

    return msvc8::string("");
  }

  [[nodiscard]] gpg::RType* ResolveCSndVarType()
  {
    gpg::RType* type = moho::CSndVar::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CSndVar));
      moho::CSndVar::sType = type;
    }
    return type;
  }

  constexpr int kSerializationSaveConstructLine = 189;
  constexpr int kSerializationConstructLine = 231;
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";

  struct SerSaveConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(SerSaveConstructHelperView, mSaveConstructArgsCallback) == 0x0C,
    "SerSaveConstructHelperView::mSaveConstructArgsCallback offset must be 0x0C"
  );

  struct SerConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(SerConstructHelperView, mConstructCallback) == 0x0C,
    "SerConstructHelperView::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerConstructHelperView, mDeleteCallback) == 0x10,
    "SerConstructHelperView::mDeleteCallback offset must be 0x10"
  );

  /**
   * Address: 0x004E0430 (FUN_004E0430)
   *
   * What it does:
   * Saves one `CSndVar` construct argument payload (`mName`) into archive.
   */
  void SaveConstructArgs_CSndVar(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const sndVar = reinterpret_cast<moho::CSndVar*>(objectPtr);
    archive->WriteString(&sndVar->mName);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x004E0560 (FUN_004E0560)
   *
   * What it does:
   * Reads one variable-name construct arg, interns/creates `CSndVar`, and
   * returns it as an owned reflection result.
   */
  void Construct_CSndVar(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    msvc8::string variableName{};
    archive->ReadString(&variableName);

    moho::CSndVar* const sndVar = moho::SND_FindOrCreateVariable(variableName);
    gpg::RRef ref{};
    ref.mObj = sndVar;
    ref.mType = sndVar != nullptr ? ResolveCSndVarType() : nullptr;
    result->SetOwned(ref, 1u);
  }

  /**
   * Address: 0x004E4BD0 (FUN_004E4BD0)
   *
   * What it does:
   * Destroys one reflected `CSndVar` object allocated by construct callback.
   */
  void Delete_CSndVar(void* const objectPtr)
  {
    auto* const sndVar = static_cast<moho::CSndVar*>(objectPtr);
    if (sndVar == nullptr) {
      return;
    }

    sndVar->~CSndVar();
    ::operator delete(sndVar);
  }

  /**
   * Address: 0x004E1CB0 (FUN_004E1CB0)
   *
   * What it does:
   * Binds one CSndVar save-construct callback into RTTI.
   */
  [[nodiscard]] gpg::RType* InitCSndVarSaveConstructHelper(const SerSaveConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(kSaveConstructAssertText, kSerializationSaveConstructLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = helper.mSaveConstructArgsCallback;
    return type;
  }

  /**
   * Address: 0x004E1D30 (FUN_004E1D30)
   *
   * What it does:
   * Binds one CSndVar construct callback and delete callback into RTTI.
   */
  [[nodiscard]] gpg::RType::construct_func_t InitCSndVarConstructHelper(const SerConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  /**
   * Address: 0x004E1D00 (FUN_004E1D00)
   *
   * What it does:
   * Builds one static CSndVar construct-helper view carrying construct/delete
   * callback lanes used by serialization registration.
   */
  [[nodiscard]] const SerConstructHelperView& BuildCSndVarConstructHelper()
  {
    static const SerConstructHelperView helper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CSndVar),
      .mDeleteCallback = &Delete_CSndVar,
    };
    return helper;
  }

  void RegisterCSndVarSerializationCallbacks()
  {
    const SerSaveConstructHelperView saveHelper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mSaveConstructArgsCallback = reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CSndVar),
    };
    (void)InitCSndVarSaveConstructHelper(saveHelper);

    const SerConstructHelperView& constructHelper = BuildCSndVarConstructHelper();
    (void)InitCSndVarConstructHelper(constructHelper);
  }

  struct CSndVarSerializationBootstrap
  {
    CSndVarSerializationBootstrap()
    {
      RegisterCSndVarSerializationCallbacks();
    }
  };

  [[maybe_unused]] CSndVarSerializationBootstrap gCSndVarSerializationBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x004DF390 (FUN_004DF390, func_NewCSndVar)
   *
   * msvc8::string const&
   *
   * What it does:
   * Returns one interned `CSndVar` for the supplied variable name.
   */
  CSndVar* SND_FindOrCreateVariable(const msvc8::string& variableName)
  {
    if (variableName.empty()) {
      return nullptr;
    }

    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);

    const std::uint32_t nameHash = HashSndVarName(variableName);
    if (CSndVar* const cached = FindCachedSndVarByNameLocked(variableName, nameHash); cached != nullptr) {
      return cached;
    }

    CSndVar* const created = new CSndVar(variableName.c_str());
    gSndVarNameCache.emplace(nameHash, created);
    return created;
  }

  /**
   * Address: 0x004E02B0 (FUN_004E02B0)
   *
   * What it does:
   * Initializes one unresolved sound-variable descriptor and registers it in
   * the global variable-name lane.
   */
  CSndVar::CSndVar(const char* const name)
    : mState(0xFFFFu)
    , mResolved(0u)
    , mReserved03(0u)
    , mName()
  {
    mName.assign_owned(name);
    RegisterSndVarInstance(this);
  }

  /**
   * Address: 0x004E0330 (FUN_004E0330)
   *
   * What it does:
   * Unregisters one descriptor and tears down owned name storage.
   */
  CSndVar::~CSndVar()
  {
    UnregisterSndVarInstance(this);
    mName.tidy(true, 0u);
    mState = 0xFFFFu;
    mResolved = 0u;
    mReserved03 = 0u;
  }

  /**
   * Address: 0x004E0390 (FUN_004E0390)
   *
   * What it does:
   * Resolves one global XACT variable index by name and caches the result.
   */
  bool CSndVar::DoResolve() const
  {
    mResolved = 1u;
    if (SND_GetGlobalVarIndex(mName.c_str(), &mState)) {
      return true;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration != nullptr && configuration->mEngines.mStart != nullptr &&
        configuration->mEngines.mStart != configuration->mEngines.mFinish && configuration->mNoSound == 0u) {
      gpg::Warnf("SND: Couldn't find variable %s", mName.c_str());
    }

    return false;
  }

  /**
   * Address: 0x004E0150 (FUN_004E0150, ?SND_GetVariableName@Moho@@...)
   *
   * int variableId
   *
   * What it does:
   * Returns the registered name for one global sound variable id.
   */
  msvc8::string SND_GetVariableName(const int variableId)
  {
    return LookupSndVarNameById(static_cast<std::uint16_t>(variableId));
  }
} // namespace moho
