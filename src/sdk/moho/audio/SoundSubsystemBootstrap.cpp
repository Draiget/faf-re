// SPDX: faf engine recovery
//
// SoundSubsystemBootstrap.cpp
//
// CRT static-initializer / teardown for the engine's sound-subsystem
// global cache lanes. Recovers the binary's `Moho::InitSoundStructs`
// (FUN_004DFC80) — registered in the binary's `__xc_*` init array —
// which bootstraps the three sound-parameter caches (RB-tree sentinels),
// one auxiliary intrusive list, one singleton list-node, the default
// sound-loop descriptor, and the boost::mutex guarding the caches.
//
// The modern CSndParams.cpp uses different (std-based) cache containers
// for runtime lookup; these binary-mirror globals exist solely so the
// binary's per-T `_Buynode` template emissions and the CRT init/teardown
// symbols have a real source-level invocation chain. The mirrors are
// populated at static-init time and torn down at static-deinit.

#include <cstdint>
#include <cstdlib>
#include <new>

#include "boost/mutex.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "moho/audio/CSndParams.h"

namespace
{
  /**
   * 24-byte RB-tree head/sentinel node matching the binary's MSVC8
   * `std::_Tree<...>::_Node` shape for sound-parameter caches keyed by
   * 32-bit hash. The sentinel header lives at the start of every
   * `Moho::sSndParamsCache` / `stru_10A9298` / `dword_10A92A4`.
   *
   * Layout matches `Moho::SndVarTreeNodeHeadRuntimeView` in CSndVar.cpp.
   */
  struct SoundTreeHeadNode
  {
    std::uint32_t parent;             // +0x00
    std::uint32_t left;               // +0x04
    std::uint32_t right;              // +0x08
    std::uint8_t reservedValue[0x8];  // +0x0C — value pair storage
    std::uint8_t color;               // +0x14 — 1 = Black
    std::uint8_t isNil;               // +0x15 — 1 = sentinel
    std::uint8_t reservedPad[0x2];    // +0x16
  };
  static_assert(sizeof(SoundTreeHeadNode) == 0x18, "SoundTreeHeadNode size must be 0x18");

  /**
   * 12-byte self-linked intrusive-list node matching the binary's MSVC8
   * `std::_List<...>::_Node` head/sentinel shape. Used for the auxiliary
   * sound-list at `stru_10A92AC` and the singleton at `stru_10A92BC`.
   */
  struct SoundListNode
  {
    SoundListNode* next; // +0x00
    SoundListNode* prev; // +0x04
    std::uint32_t value; // +0x08
  };
  static_assert(sizeof(SoundListNode) == 0x0C, "SoundListNode size must be 0x0C");

  /**
   * Tree-storage triple matching the binary's `std::map<...>` head
   * layout: head node pointer, _Myhead alias, _Mysize. The `auxIter`
   * lane shadows the binary's `_Myfirstiter` access in the disasm.
   */
  struct SoundTreeStorage
  {
    SoundTreeHeadNode* head;  // _Myfirstiter / sentinel
    void* auxIter;            // _Myhead alias (binary sets to nullptr)
    std::uint32_t size;       // _Mysize
  };

  /**
   * Single-pointer + size pair matching the binary's `dword_10A92A4` /
   * `dword_10A92A8` pair (third RB-tree map's head + size).
   */
  struct SoundPointerSizePair
  {
    SoundTreeHeadNode* head;
    std::uint32_t size;
  };

  /**
   * List-head + size pair matching `stru_10A92AC._Myhead` / `_Mysize`.
   */
  struct SoundListStorage
  {
    SoundListNode* head;
    std::uint32_t size;
  };

  /**
   * Singleton box matching `dword_10A92BC` / `unk_10A92C0` (head + flag).
   */
  struct SoundSingletonBox
  {
    SoundListNode* head;
    std::uint32_t flag;
  };

  // ===== Binary-mirror globals at file scope =====
  //
  // These shadow the binary's globals at 0x010A9288..0x010A92E0. They are
  // populated by Moho::InitSoundStructs at CRT static init time and are
  // intentionally not read by the modern runtime path (which uses the
  // gSndParamsHashCache etc. globals in CSndParams.cpp). The mirrors
  // exist so the binary's CRT init/teardown symbols have real source-
  // level invocation chains.

  SoundTreeStorage gSSndParamsCacheMirror{};     // sSndParamsCache @ 0x010A9288
  SoundTreeStorage gStru_10A9298Mirror{};        // stru_10A9298    @ 0x010A9298
  SoundPointerSizePair gDword_10A92A4Mirror{};   // dword_10A92A4   @ 0x010A92A4
  SoundListStorage gStru_10A92ACMirror{};        // stru_10A92AC    @ 0x010A92AC
  SoundSingletonBox gStru_10A92BCMirror{};       // stru_10A92BC    @ 0x010A92BC
  moho::HSndEntityLoop gDefSndLoopMirror{};      // sDefSndLoop     @ 0x010A92C4

  alignas(boost::mutex) std::byte gStru_10A92D0Storage[sizeof(boost::mutex)]{};
  bool gStru_10A92D0Constructed = false;

  /**
   * Allocates one 24-byte RB-tree sentinel head node and self-links it
   * with color=Black, isNil=1. Mirrors the binary's per-cache sentinel
   * setup: `head = allocate; head->parent=head->left=head->right=head;
   * head->color=1; head->isNil=1`.
   */
  [[nodiscard]] SoundTreeHeadNode* AllocateSentinelTreeHead()
  {
    auto* const head =
      static_cast<SoundTreeHeadNode*>(gpg::core::legacy::AllocateChecked24ByteLane(1u));
    if (head == nullptr) {
      return nullptr;
    }

    const std::uint32_t headValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(head));
    head->parent = headValue;
    head->left = headValue;
    head->right = headValue;
    for (std::size_t index = 0; index < sizeof(head->reservedValue); ++index) {
      head->reservedValue[index] = 0;
    }
    head->color = 1;
    head->isNil = 1;
    head->reservedPad[0] = 0;
    head->reservedPad[1] = 0;
    return head;
  }

  /**
   * Allocates one 12-byte self-linked list node (head sentinel).
   * Mirrors the binary's `head[0] = head; head[1] = head` pattern.
   */
  [[nodiscard]] SoundListNode* AllocateSelfLinkedListNode()
  {
    auto* const node =
      static_cast<SoundListNode*>(gpg::core::legacy::AllocateChecked12ByteLane(1u));
    if (node == nullptr) {
      return nullptr;
    }
    node->next = node;
    node->prev = node;
    node->value = 0;
    return node;
  }

  /**
   * Address: 0x004E2030 (FUN_004E2030)
   *
   * IDA signature:
   * void __usercall sub_4E2030(SoundTreeHeadNode **outResult@<eax>, const std::uint32_t *keyPtr);
   *
   * What it does:
   * `lower_bound`-style walk of the `sSndParamsCache` RB-tree: returns the
   * first node whose key (the leading 4 bytes of `reservedValue`) is not
   * less than `*keyPtr`, or the header itself (`end()`) when none qualifies
   * or the tree is empty.
   *
   * Field-offset note: the binary reads the header's search root from the
   * fixed `[head+4]` slot and descends toward smaller keys via each node's
   * fixed `[node+0]` slot -- i.e. this walk treats `SoundTreeHeadNode::left`
   * as the root pointer and `::parent` as the "go smaller" link, which is
   * the reverse of their declared names above (real MSVC8 `_Tree_nod::_Node`
   * layout is `{_Left, _Parent, _Right}`; the header's `_Parent` is root,
   * a regular node's `_Left` is its smaller-child link). `AllocateSentinelTreeHead`
   * sets all three slots to the same self-reference at init time so this
   * naming mismatch has no observable effect there; not renamed here to
   * avoid touching the shared declaration mid-batch. Not yet wired to a
   * source-level caller -- its real caller (0x004E1710) is unrecovered, and
   * this file's own mirrors are documented as "not read by the modern
   * runtime path" (see file header), so kept `[[maybe_unused]]` pending
   * that caller's recovery.
   */
  [[maybe_unused]] SoundTreeHeadNode* LowerBoundSoundParamsCacheByHash(const std::uint32_t* const keyPtr)
  {
    SoundTreeHeadNode* const head = gSSndParamsCacheMirror.head;
    auto* node = reinterpret_cast<SoundTreeHeadNode*>(head->left);
    SoundTreeHeadNode* best = head;

    if (node->isNil == 0) {
      const std::uint32_t key = *keyPtr;
      while (node->isNil == 0) {
        const std::uint32_t nodeKey = *reinterpret_cast<const std::uint32_t*>(node->reservedValue);
        if (nodeKey >= key) {
          best = node;
          node = reinterpret_cast<SoundTreeHeadNode*>(node->parent);
        } else {
          node = reinterpret_cast<SoundTreeHeadNode*>(node->right);
        }
      }
    }

    return best;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004DFC80 (FUN_004DFC80, Moho::InitSoundStructs)
   *
   * What it does:
   * Bootstraps the engine's sound-subsystem globals at CRT static init
   * time. Allocates RB-tree sentinel heads for three sound-parameter
   * caches (`sSndParamsCache`, `stru_10A9298`, `dword_10A92A4`), one
   * intrusive list head (`stru_10A92AC`), one singleton list node
   * (`stru_10A92BC`), resets the default sound-loop descriptor
   * (`sDefSndLoop` -> `{v0=0, index=-1, params=nullptr}`), and
   * constructs the boost::mutex guarding the caches (`stru_10A92D0`).
   *
   * Returns the address of the cache region (binary returns
   * `&unk_10A9288` which is `&sSndParamsCache`).
   *
   * The modern CSndParams.cpp runtime path uses different (std-based)
   * caches for the actual lookup; these binary-mirror globals exist so
   * the binary's CRT init machinery has a real source-level invocation
   * chain. Both code paths coexist; cache lookups go through the modern
   * globals while the mirror globals shadow the binary layout.
   */
  void* InitSoundStructs()
  {
    gSSndParamsCacheMirror.head = AllocateSentinelTreeHead();
    gSSndParamsCacheMirror.auxIter = nullptr;
    gSSndParamsCacheMirror.size = 0u;

    gStru_10A9298Mirror.head = AllocateSentinelTreeHead();
    gStru_10A9298Mirror.auxIter = nullptr;
    gStru_10A9298Mirror.size = 0u;

    gDword_10A92A4Mirror.head = AllocateSentinelTreeHead();
    gDword_10A92A4Mirror.size = 0u;

    gStru_10A92ACMirror.head = AllocateSelfLinkedListNode();
    gStru_10A92ACMirror.size = 0u;

    gStru_10A92BCMirror.head = AllocateSelfLinkedListNode();
    gStru_10A92BCMirror.flag = 0u;

    gDefSndLoopMirror.mListLinkHead = nullptr;
    gDefSndLoopMirror.mLoopIndex = -1;
    gDefSndLoopMirror.mParams = nullptr;

    new (&gStru_10A92D0Storage[0]) boost::mutex();
    gStru_10A92D0Constructed = true;

    return &gSSndParamsCacheMirror;
  }

  /**
   * Address: 0x004DF0E0 (FUN_004DF0E0, Moho::TeardownSoundStructs)
   *
   * What it does:
   * Tears down the engine's sound-subsystem globals at CRT static
   * deinit time (registered via `std::atexit` mirroring the binary's
   * CRT teardown registration). The body releases sentinel head nodes
   * for the three RB-tree caches and the two list nodes, destroys the
   * boost::mutex via in-place dtor, and resets all mirror globals to
   * empty state. Modern `CSndParams.cpp` runtime globals are torn down
   * separately by the compiler's normal static-deinit sequence.
   *
   * The binary's teardown body additionally invokes the
   * `_Tree::erase` / `_Tree::clear` MSVC8 STL template emissions
   * (sub_4E28A0, sub_4E2C80, sub_4E3020, sub_4E3290, sub_4E3410,
   * sub_4E49A0, sub_4E4A00, sub_4E4A40), the per-node erase-at-iterator
   * inner helpers those erases dispatch to (sub_4E3780, sub_4E3C10,
   * sub_4E4060), and the defensive `_Tree::_Copy` chain
   * (sub_4E1A60 copy ctor + sub_4E5960 tree-clone inner loop) that
   * copies `unk_10A92B8` into a local tree, walks the copy, then
   * walks the original before freeing both. Since the mirror trees
   * are populated only with their sentinel head (no inserted entries
   * — runtime inserts go to the modern globals), each tree contains
   * zero non-sentinel nodes and the per-T erase/clone emissions are
   * no-ops; we elide the calls and directly free the sentinel
   * storage.
   */
  void TeardownSoundStructs()
  {
    if (gStru_10A92D0Constructed) {
      reinterpret_cast<boost::mutex*>(&gStru_10A92D0Storage[0])->~mutex();
      gStru_10A92D0Constructed = false;
    }

    gDefSndLoopMirror.mListLinkHead = nullptr;
    gDefSndLoopMirror.mLoopIndex = -1;
    gDefSndLoopMirror.mParams = nullptr;

    if (gStru_10A92BCMirror.head != nullptr) {
      ::operator delete(gStru_10A92BCMirror.head);
      gStru_10A92BCMirror.head = nullptr;
    }
    gStru_10A92BCMirror.flag = 0u;

    if (gStru_10A92ACMirror.head != nullptr) {
      ::operator delete(gStru_10A92ACMirror.head);
      gStru_10A92ACMirror.head = nullptr;
    }
    gStru_10A92ACMirror.size = 0u;

    if (gDword_10A92A4Mirror.head != nullptr) {
      ::operator delete(gDword_10A92A4Mirror.head);
      gDword_10A92A4Mirror.head = nullptr;
    }
    gDword_10A92A4Mirror.size = 0u;

    if (gStru_10A9298Mirror.head != nullptr) {
      ::operator delete(gStru_10A9298Mirror.head);
      gStru_10A9298Mirror.head = nullptr;
    }
    gStru_10A9298Mirror.auxIter = nullptr;
    gStru_10A9298Mirror.size = 0u;

    if (gSSndParamsCacheMirror.head != nullptr) {
      ::operator delete(gSSndParamsCacheMirror.head);
      gSSndParamsCacheMirror.head = nullptr;
    }
    gSSndParamsCacheMirror.auxIter = nullptr;
    gSSndParamsCacheMirror.size = 0u;
  }
} // namespace moho

namespace
{
  /**
   * CRT static-init driver. Invokes `Moho::InitSoundStructs` once at
   * program load so the binary-mirror globals are populated before any
   * sound-subsystem code runs. The binary registers FUN_004DFC80 in the
   * `__xc_*` init array; in the modern build the same effect is
   * achieved by this file-scope static-init dummy. The same dummy
   * registers `Moho::TeardownSoundStructs` with `std::atexit` to
   * mirror the binary's CRT-registered teardown (FUN_004DF0E0 via
   * `FUN_00BF0E80` thunk).
   */
  struct SoundSubsystemBootstrapDriver
  {
    SoundSubsystemBootstrapDriver() noexcept
    {
      (void)moho::InitSoundStructs();
      (void)std::atexit(&moho::TeardownSoundStructs);
    }
  };

  [[maybe_unused]] const SoundSubsystemBootstrapDriver gSoundSubsystemBootstrap{};
} // namespace
