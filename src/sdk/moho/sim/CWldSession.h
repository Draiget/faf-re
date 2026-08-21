#pragma once
#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "CArmyImpl.h"
#include "gpg/core/containers/IntrusiveLink.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/List.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "lua/LuaObject.h"
#include "moho/misc/VisionDb.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/SyncInlineVector.h"
#include "moho/sim/VisibilityRect.h"
#include "moho/command/CommandManager.h"
#include "moho/sim/WeakEntitySet.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/task/CTaskThread.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  using EntId = std::int32_t;

  class UserArmy;
  class UserUnit;
  class CWldSession;
  struct SSyncData;
  struct UserCommandIssueHelper;
  // The `Moho::UserTarget` command-target payload (UserUnit.h). Only used
  // as an incomplete by-const-ref parameter type here; ISSUE_SetCommandTarget's
  // definition (Sim.cpp) and its callers need the full UserUnit.h include.
  struct UserCommandTargetView;
  // Opaque cross-TU handle to the runtime command-graph anchor-history object
  // (see UserUnit.h). Only used as an incomplete pointer by the dock worker bridge.
  struct QueuedUserCommandRecord;
  enum EMauiEventModifier : std::uint32_t;
  class EntityCategoryLookupResolver;
  class LaunchInfoBase;
  class RRuleGameRules;
  class RRuleGameRulesImpl;
  class UserEntity;
  class CameraImpl;
  class CRenderWorldView;
  class CD3DPrimBatcher;
  class UICommandGraph;
  class CFormation;
  class CDebugCanvas;
  class CSimResources;
  class ISTIDriver;
  struct SSTICommandIssueData;
  class STIMap;
  class IWldUIProvider;
  struct SBuildTemplateInfo
  {
    SBuildTemplateInfo() = default;

    Wm3::Vector3f mPos;         // +0x00
    std::int32_t mBuildOrder;   // +0x0C
    msvc8::string mBlueprintId; // +0x10

    /**
     * Address: 0x00823B40 (FUN_00823B40, struct_BuildTemplate::struct_BuildTemplate)
     *
     * What it does:
     * Copy-constructs one build-template entry (position, heading, blueprint
     * id).
     */
    SBuildTemplateInfo(const SBuildTemplateInfo& other);
  };
  static_assert(sizeof(SBuildTemplateInfo) == 0x2C, "SBuildTemplateInfo size must be 0x2C");
  static_assert(offsetof(SBuildTemplateInfo, mBuildOrder) == 0x0C, "SBuildTemplateInfo::mBuildOrder offset must be 0x0C");
  static_assert(
    offsetof(SBuildTemplateInfo, mBlueprintId) == 0x10, "SBuildTemplateInfo::mBlueprintId offset must be 0x10"
  );
  struct GeomCamera3;

  struct SBuildTemplateBuffer
  {
    SBuildTemplateInfo* mStart;         // +0x00
    SBuildTemplateInfo* mFinish;        // +0x04
    SBuildTemplateInfo* mCapacity;      // +0x08
    SBuildTemplateInfo* mOriginalStart; // +0x0C
    std::uint8_t mInlineStorage[0x2C0]; // +0x10 (16 * sizeof(SBuildTemplateInfo), 0x2C each)

    // gpg::fastvector_n<SBuildTemplateInfo, 16> behaviour. Declared as named
    // methods (not ctor/dtor) so the struct stays trivially-copyable POD for the
    // callers that manipulate the lanes directly; defined out-of-line in
    // CWldSession.cpp where the inline-buffer growth/teardown helpers live.
    void InitInlineStorage() noexcept;                     // rebind lanes to the inline buffer (empty)
    void PushBack(const SBuildTemplateInfo& info);         // append one entry, growing off-inline as needed
    void DestroyStorage();                                 // destroy entries + free any spilled buffer
    [[nodiscard]] bool Empty() const noexcept { return mFinish == mStart; }
  };

  static_assert(sizeof(SBuildTemplateBuffer) == 0x2D0, "SBuildTemplateBuffer size must be 0x2D0");
  static_assert(offsetof(SBuildTemplateBuffer, mStart) == 0x00, "SBuildTemplateBuffer::mStart offset must be 0x00");
  static_assert(offsetof(SBuildTemplateBuffer, mFinish) == 0x04, "SBuildTemplateBuffer::mFinish offset must be 0x04");
  static_assert(
    offsetof(SBuildTemplateBuffer, mCapacity) == 0x08, "SBuildTemplateBuffer::mCapacity offset must be 0x08"
  );
  static_assert(
    offsetof(SBuildTemplateBuffer, mOriginalStart) == 0x0C, "SBuildTemplateBuffer::mOriginalStart offset must be 0x0C"
  );
  static_assert(
    offsetof(SBuildTemplateBuffer, mInlineStorage) == 0x10, "SBuildTemplateBuffer::mInlineStorage offset must be 0x10"
  );

  /**
   * Address: 0x00899790 (FUN_00899790,
   *   gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>::operator=)
   *
   * IDA signature:
   * void __userpurge sub_899790(
   *     gpg::fastvector_n16_SBuildTemplateInfo *result@<eax>,
   *     gpg::fastvector_n16_SBuildTemplateInfo *a2);
   *
   * What it does:
   * Per-T named helper for the engine-instantiated assignment-operator body
   * of `gpg::fastvector_n<SBuildTemplateInfo, 16>` (inline-buffer variant
   * with stride 0x2C). Performs self-assignment guard, then either copies
   * the existing elements into the destination's pre-allocated tail and
   * grows when the source size exceeds destination capacity, falling back
   * to the per-element copy/destroy split path otherwise.
   *
   * Caller: `Moho::CWldSession::SetActiveBuildTemplate` (FUN_00896A70) —
   * the single binary call site that replaces the build-template buffer
   * before the placement preview is re-anchored.
   */
  void AssignBuildTemplateBuffer(SBuildTemplateBuffer& destination, const SBuildTemplateBuffer& source);


  struct MouseInfo
  {
    MouseInfo();

    /**
     * Address: 0x0081CF00 (FUN_0081CF00, ??0UICursorInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Copy-constructs cursor info and relinks weak hovered-unit ownership to this instance.
     */
    MouseInfo(const MouseInfo& other);

    /**
     * Address: 0x00893140 (FUN_00893140, ??1UICursorInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this cursor info from the hovered-unit weak-owner chain.
     */
    ~MouseInfo();

    /**
     * Address: 0x0082B270 (FUN_0082B270, Moho::UICursorInfo::Copy)
     *
     * What it does:
     * Assigns cursor info and updates hovered-unit weak-owner chain links.
     */
    MouseInfo& operator=(const MouseInfo& other);

    std::uint8_t mHitValid; // +0x00
    std::uint8_t pad_01[3];
    Wm3::Vector3f mMouseWorldPos;  // +0x04
    UserEntity* mUnitHover;        // +0x10
    UserEntity* mPrevious;         // +0x14
    std::int32_t mIsDragger;       // +0x18
    Wm3::Vector2f mMouseScreenPos; // +0x1C
  };

  static_assert(sizeof(MouseInfo) == 0x24, "MouseInfo size must be 0x24");
  static_assert(offsetof(MouseInfo, mMouseWorldPos) == 0x04, "MouseInfo::mMouseWorldPos offset must be 0x04");
  static_assert(offsetof(MouseInfo, mUnitHover) == 0x10, "MouseInfo::mUnitHover offset must be 0x10");
  static_assert(offsetof(MouseInfo, mIsDragger) == 0x18, "MouseInfo::mIsDragger offset must be 0x18");

  enum ECommandMode : std::int32_t
  {
    COMMOD_None = 0,
    COMMOD_Order = 1,
    COMMOD_Build = 2,
    COMMOD_BuildAnchored = 3,
    COMMOD_Move = 4,
    COMMOD_Reclaim = 5,
    COMMOD_Ping = 6,
  };

  struct CommandModeData
  {
    CommandModeData() = default;

    /**
     * Address: 0x0081F6C0 (FUN_0081F6C0, ??0SCommandModeData@Moho@@QAE@@Z)
     *
     * What it does:
     * Copy-constructs command mode state, including both cursor snapshots.
     */
    CommandModeData(const CommandModeData& other);

    /**
     * Address: 0x0081CEA0 (FUN_0081CEA0)
     *
     * What it does:
     * Initializes command mode from one cursor snapshot and one modifier lane:
     * mode/caps/blueprint are reset, drag-start is copied, drag-end is reset,
     * and trailing sentinel fields are set to `-1`.
     */
    CommandModeData(const MouseInfo& mouseInfo, int modifiers);

    /**
     * Address: 0x007EF070 (FUN_007EF070, ??1SCommandModeData@Moho@@QAE@XZ)
     *
     * What it does:
     * Destroys command-mode cursor snapshots and unlinks both hovered-unit
     * weak-owner lanes.
     */
    ~CommandModeData();

    /**
     * Address: 0x0082B230 (FUN_0082B230, ??0SCommandModeData@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Assigns command mode state from another value, using `MouseInfo::operator=`
     * for both drag-snapshot lanes.
     */
    CommandModeData& operator=(const CommandModeData& other);

    /**
     * Address: 0x0081FCD0 (FUN_0081FCD0, Moho::SCommandModeData::HandleEvent)
     *
     * IDA signature:
     * void __thiscall Moho::SCommandModeData::HandleEvent(
     *     Moho::SCommandModeData *this, Moho::CWldSession *a2, char a3);
     *
     * What it does:
     * The world-view command-mode dispatcher: turns one committed mouse
     * gesture (the drag snapshot this object carries) into the actual
     * `ISSUE_*` traffic for the session's current selection. 2167
     * instructions, one arm per command mode and, inside `COMMOD_Order`, one
     * arm per `ERuleBPUnitCommandCaps` value. See the definition in
     * CWldSession.cpp for the per-arm breakdown.
     *
     * `isDragUpdate` is set by the caller when this event replaces a command
     * this same drag already issued (the attack-drag re-target path): it
     * enables the `ISSUE_RemoveLastCommand` + "Coordinated Attack!" cursor
     * banner behaviour in the `RULEUCC_Attack` arm.
     */
    void HandleEvent(CWldSession& session, bool isDragUpdate);

    ECommandMode mMode;
    ERuleBPUnitCommandCaps mCommandCaps;
    void* mBlueprint;
    MouseInfo mMouseDragStart;
    MouseInfo mMouseDragEnd;
    std::int32_t mModifiers;
    /// The command id of the order this drag is currently editing, or `-1`
    /// when the drag has not re-targeted an existing order yet. Written as a
    /// sentinel `-1` by the `(MouseInfo, modifiers)` constructor (0x0081CEA0)
    /// and consumed as a `CmdId` by `HandleEvent`'s attack/move arms
    /// (0x0081FEA0, 0x0082078B).
    std::int32_t mIsDragged;
    std::int32_t mReserved5C;
  };

  static_assert(sizeof(CommandModeData) == 0x60, "CommandModeData size must be 0x60");
  static_assert(
    offsetof(CommandModeData, mMouseDragStart) == 0x0C, "CommandModeData::mMouseDragStart offset must be 0x0C"
  );
  static_assert(offsetof(CommandModeData, mMouseDragEnd) == 0x30, "CommandModeData::mMouseDragEnd offset must be 0x30");
  static_assert(offsetof(CommandModeData, mModifiers) == 0x54, "CommandModeData::mModifiers offset must be 0x54");

  struct SSessionSaveNodeLabel
  {
    std::uint32_t mCommandSourceId; // +0x00
    msvc8::string mSaveNodeName;    // +0x04
  };

  static_assert(sizeof(SSessionSaveNodeLabel) == 0x20, "SSessionSaveNodeLabel size must be 0x20");
  static_assert(
    offsetof(SSessionSaveNodeLabel, mCommandSourceId) == 0x00,
    "SSessionSaveNodeLabel::mCommandSourceId offset must be 0x00"
  );
  static_assert(
    offsetof(SSessionSaveNodeLabel, mSaveNodeName) == 0x04, "SSessionSaveNodeLabel::mSaveNodeName offset must be 0x04"
  );

  struct SSessionSaveNodeMapNode
  {
    SSessionSaveNodeMapNode* mLeft;   // +0x00
    SSessionSaveNodeMapNode* mParent; // +0x04
    SSessionSaveNodeMapNode* mRight;  // +0x08
    SSessionSaveNodeLabel mLabel;     // +0x0C
    std::uint8_t mColor;              // +0x2C
    std::uint8_t mIsSentinel;         // +0x2D
    std::uint8_t pad_2E[2];
  };

  static_assert(sizeof(SSessionSaveNodeMapNode) == 0x30, "SSessionSaveNodeMapNode size must be 0x30");
  static_assert(
    offsetof(SSessionSaveNodeMapNode, mLabel) == 0x0C, "SSessionSaveNodeMapNode::mLabel offset must be 0x0C"
  );
  static_assert(
    offsetof(SSessionSaveNodeMapNode, mColor) == 0x2C, "SSessionSaveNodeMapNode::mColor offset must be 0x2C"
  );
  static_assert(
    offsetof(SSessionSaveNodeMapNode, mIsSentinel) == 0x2D, "SSessionSaveNodeMapNode::mIsSentinel offset must be 0x2D"
  );

  struct SSessionSaveNodeMap
  {
    void* mAllocProxy;              // +0x00
    SSessionSaveNodeMapNode* mHead; // +0x04
    std::uint32_t mSize;            // +0x08
  };

  static_assert(sizeof(SSessionSaveNodeMap) == 0x0C, "SSessionSaveNodeMap size must be 0x0C");
  static_assert(offsetof(SSessionSaveNodeMap, mHead) == 0x04, "SSessionSaveNodeMap::mHead offset must be 0x04");
  static_assert(offsetof(SSessionSaveNodeMap, mSize) == 0x08, "SSessionSaveNodeMap::mSize offset must be 0x08");

  /**
   * The session's selection weak-set: the shipped 12-byte
   * `WeakSet<UserEntity>` tree header plus the extra selection lane at
   * `+0x0C` that the session-side sets carry. `UserArmy`'s idle registries
   * embed the bare `WeakEntitySetUserEntity` instead — they sit 12 bytes
   * apart at +0x1F8 and +0x204.
   */
  struct SSelectionSetUserEntity : WeakEntitySetUserEntity
  {
    std::uint32_t mSizeMirrorOrUnused; // +0x0C

    struct Index
    {
      SSelectionSetUserEntity* mOwnerSet; // +0x00
      SSelectionNodeUserEntity* mNode;    // +0x04

      /**
       * Address: 0x007AE7E0 (FUN_007AE7E0, Moho::WeakSet_UserEntity::Iterator::Next)
       *
       * What it does:
       * Advances iterator cursor one RB-tree successor and then skips tombstone
       * nodes through `find`, updating `mNode` in-place.
       */
      [[nodiscard]] Index* Next();
    };

    struct AddResult : Index
    {
      std::uint8_t mWasInserted;          // +0x08
      std::uint8_t mReserved09_0B[3]{};   // +0x09
    };

    struct FindResult
    {
      SSelectionSetUserEntity* mSet;   // +0x00
      SSelectionNodeUserEntity* mRes;  // +0x04
    };

    /**
     * Address: 0x007AE1B0 (FUN_007AE1B0, Moho::WeakSet_UserEntity::Add)
     *
     * What it does:
     * Inserts one user-entity pointer key into the selection weak-set tree and
     * returns `{ownerSet,node,inserted}` in `outResult`.
     */
    [[nodiscard]] static AddResult*
      Add(AddResult* outResult, SSelectionSetUserEntity* set, UserEntity* entity);

    /**
     * Address: 0x007FDD50 (FUN_007FDD50, Moho::WeakSet_UserEntity::Find)
     *
     * What it does:
     * Resolves one weak-set tree node by user-entity key and writes one
     * `{set,node}` pair to `outResult`, using the transient weak-link guard lane
     * required by the original weak-pointer map lookup path.
     */
    [[nodiscard]] static FindResult*
      Find(FindResult* outResult, SSelectionSetUserEntity* set, UserEntity* entity);

    /**
     * Address: 0x008676E0 (FUN_008676E0, sub_8676E0)
     *
     * IDA signature:
     * int __stdcall sub_8676E0(int a1, int a2);
     *
     * What it does:
     * Removes one user-entity key from a weak set, holding the transient
     * weak-link guard across the erase exactly as the binary does, and reports
     * whether a live node was actually removed.
     *
     * Takes the 12-byte base so the session selection, the extra-select list
     * and the per-army idle registries all share one erase.
     */
    static bool Erase(WeakEntitySetUserEntity& set, UserEntity* entity);

    /**
     * Address: 0x007B59B0 (FUN_007B59B0, Moho::WeakSet_UserEntity::size)
     *
     * What it does:
     * Counts live weak-set tree nodes by in-order traversal of the selection
     * RB-tree lane.
     */
    [[nodiscard]] std::int32_t size() const;

    /**
     * Address: 0x007B2620 (FUN_007B2620, sub_7B2620)
     *
     * What it does:
     * Returns true when tombstone pruning from the left-most node reaches the
     * head sentinel immediately (no live weak-set entries remain).
     */
    [[nodiscard]] bool IsEmptyAfterPrune();

    /**
     * Address: 0x0066A090 (FUN_0066A090, sub_66A090)
     *
     * What it does:
     * Starts from the tree left-most lane and returns true when `find`
     * resolves directly to the head sentinel (no live weak-set entries).
     */
    [[nodiscard]] bool IsEmptyFromHeadFind();

    /**
     * Address: 0x00863760 (FUN_00863760, sub_863760)
     *
     * What it does:
     * Counts live weak-set entries in this set that are absent from `other`.
     */
    [[nodiscard]] std::int32_t CountEntitiesMissingFrom(const SSelectionSetUserEntity& other) const;

    /**
     * Address: 0x00868690 (FUN_00868690, sub_868690)
     *
     * What it does:
     * Returns true when this set and `other` contain the same live entity keys.
     */
    [[nodiscard]] bool HasSameLiveEntitySet(const SSelectionSetUserEntity& other) const;

    /**
     * Address: 0x00831110 (FUN_00831110, sub_831110)
     *
     * What it does:
     * Returns true when this set and `other` share at least one live entity.
     * The binary walks both trees as a sorted merge (both are ordered by the
     * same `UserEntity*` key); this is expressed as a per-element membership
     * test against `other` instead, which returns the identical boolean for
     * every input - the merge's only externally observable effect is the
     * early-exit on first match, which the membership-test loop preserves.
     */
    [[nodiscard]] bool HasCommonLiveEntityWith(const SSelectionSetUserEntity& other) const;

    /**
     * Address: 0x0066A330 (FUN_0066A330, Moho::WeakSet_UserEntity::find)
     *
     * What it does:
     * Walks forward from `start` through the RB-tree using `next`, skipping
     * tombstone entries (whose embedded `WeakObject_IUnit*` is null or the
     * sentinel `(void*)8`), and returns the first live entry or `mHead`
     * (sentinel) if none remains. Result is written to `*outNode`.
     */
    [[nodiscard]] static SSelectionNodeUserEntity*
      find(SSelectionSetUserEntity* set, SSelectionNodeUserEntity* start, SSelectionNodeUserEntity** outNode);

    /**
     * Address: 0x007B29C0 (FUN_007B29C0, sub_7B29C0)
     *
     * What it does:
     * Starting at `start`, removes tombstone weak-set entries (null/`(void*)8`
     * owner-link slots) until reaching one live node or the head sentinel.
     * Writes the resulting node to `*outNode`.
     */
    [[nodiscard]] SSelectionNodeUserEntity**
      PruneTombstonesAndFindLive(SSelectionNodeUserEntity** outNode, SSelectionNodeUserEntity* start);


    /**
     * Address: 0x007ABDE0 (FUN_007ABDE0, sub_7ABDE0)
     * Address: 0x007ABE10 (FUN_007ABE10, sub_7ABE10)
     *
     * What it does:
     * Clears all weak-set nodes, destroys the tree head sentinel, and resets
     * persistent storage pointers/counters.
     */
    std::int32_t ReleaseStorage();

    /**
     * Address: 0x0066A060 (FUN_0066A060, Moho::WeakSet_UserEntity::First)
     *
     * What it does:
     * Starts weak-set iteration at the left-most tree node and returns one
     * `{set,node}` cursor pair after tombstone filtering through `find`.
     */
    [[nodiscard]] FindResult* First(FindResult* outResult);

    /**
     * Address: 0x0066ADD0 (FUN_0066ADD0, Moho::WeakSet_UserEntity::Iterator::inc)
     *
     * What it does:
     * Standard MSVC red-black tree successor: if the current node has a right
     * child, descends to its leftmost descendant; otherwise climbs ancestors
     * until reaching one whose right child is not the current path. No-op when
     * the current node is already the sentinel.
     */
    static void Iterator_inc(SSelectionNodeUserEntity** cursor);

  };

  static_assert(sizeof(SSelectionSetUserEntity) == 0x10, "SSelectionSetUserEntity size must be 0x10");
  static_assert(
    offsetof(SSelectionSetUserEntity, mHead) == 0x04, "SSelectionSetUserEntity::mHead offset must be 0x04"
  );
  static_assert(offsetof(SSelectionSetUserEntity, mSize) == 0x08, "SSelectionSetUserEntity::mSize offset must be 0x08");
  static_assert(
    offsetof(SSelectionSetUserEntity, mSizeMirrorOrUnused) == 0x0C,
    "SSelectionSetUserEntity::mSizeMirrorOrUnused offset must be 0x0C"
  );
  static_assert(sizeof(SSelectionSetUserEntity::Index) == 0x08, "SSelectionSetUserEntity::Index size must be 0x08");
  static_assert(
    offsetof(SSelectionSetUserEntity::AddResult, mWasInserted) == 0x08,
    "SSelectionSetUserEntity::AddResult::mWasInserted offset must be 0x08"
  );
  static_assert(sizeof(SSelectionSetUserEntity::AddResult) == 0x0C, "SSelectionSetUserEntity::AddResult size must be 0x0C");
  static_assert(sizeof(SSelectionSetUserEntity::FindResult) == 0x08, "SSelectionSetUserEntity::FindResult size must be 0x08");

  /** Brings one selection weak-set up empty, head sentinel included. */
  inline void InitializeLocalSelectionSet(SSelectionSetUserEntity& set)
  {
    InitWeakEntitySetHead(set);
    set.mSizeMirrorOrUnused = 0u;
  }

  /**
   * Address: 0x008B16A1..0x008B16F1 (inlined into `UserArmy::~UserArmy`,
   *          FUN_008B1650, for the two army idle registries)
   *
   * What it does:
   * Erases every node of one bare `WeakSet<UserEntity>` while keeping the head
   * sentinel alive, through the shared full-range erase (FUN_007AF740). The
   * bare 12-byte set has no `mSizeMirrorOrUnused` lane, so the operation runs
   * on a staged `SSelectionSetUserEntity` view - the same adapter pattern the
   * per-unit issue sets use - and the three ABI lanes are written back.
   */
  inline void ClearWeakEntitySet(WeakEntitySetUserEntity& set) noexcept
  {
    SSelectionNodeUserEntity* const head = set.mHead;
    if (head == nullptr) {
      return;
    }

    SSelectionSetUserEntity view{};
    view.mAllocProxy = set.mAllocProxy;
    view.mHead = set.mHead;
    view.mSize = set.mSize;
    view.mSizeMirrorOrUnused = set.mSize;

    SSelectionNodeUserEntity* outNode = nullptr;
    (void)view.EraseRange(&outNode, head->mLeft, head);

    set.mAllocProxy = view.mAllocProxy;
    set.mHead = view.mHead;
    set.mSize = view.mSize;
  }

  /**
   * Address: 0x008B16F9..0x008B1743 (inlined into `UserArmy::~UserArmy`,
   *          FUN_008B1650; the out-of-line twin is FUN_007B2530)
   *
   * What it does:
   * Tears one weak-entity set down completely: full-range erase followed by
   * `operator delete` on the head sentinel, leaving `{mHead, mSize}` zeroed.
   * The allocator-proxy lane is deliberately left alone - the binary's
   * `_Tidy()` emission never touches it.
   */
  inline void DestroyWeakEntitySet(WeakEntitySetUserEntity& set) noexcept
  {
    SSelectionNodeUserEntity* const head = set.mHead;
    if (head == nullptr) {
      return;
    }

    ClearWeakEntitySet(set);
    ::operator delete(head);
    set.mHead = nullptr;
    set.mSize = 0u;
  }

  /**
   * Address: 0x007AE270 (FUN_007AE270)
   *
   * Mirrors the engine teardown chain: `EraseRange` over the whole tree
   * (FUN_007AF740) followed by `operator delete` on the head sentinel.
   *
   * IDA labels the symbol `Broadcaster<SCameraTracking>::RemoveListener`
   * because it types the set header as a broadcaster; the two callers are
   * `CWldSession::DoBeat` and 0x00822C50, both tearing down a local selection
   * set, which is what the body actually does.
   * Tolerates a null head so a never-populated set still tears down cleanly.
   */
  inline void DestroyLocalSelectionSet(SSelectionSetUserEntity& set) noexcept
  {
    if (set.mHead == nullptr) {
      return;
    }

    DestroyWeakEntitySet(set);
    set.mAllocProxy = nullptr;
    set.mSizeMirrorOrUnused = 0u;
  }

  /**
   * A transient selection weak-set that owns its head sentinel: the shape the
   * binary builds on the stack whenever it needs to stage a selection before
   * handing it to `CWldSession::SetSelection`.
   *
   * `SSelectionSetUserEntity` itself stays a raw ABI aggregate (it is embedded
   * by value in `CWldSession` at +0x4A0, whose lifetime the engine drives), so
   * the ownership lives here rather than in a destructor on the layout type.
   */
  class ScopedLocalSelectionSet final
  {
  public:
    ScopedLocalSelectionSet() { InitializeLocalSelectionSet(mSet); }
    ~ScopedLocalSelectionSet() { DestroyLocalSelectionSet(mSet); }

    ScopedLocalSelectionSet(const ScopedLocalSelectionSet&) = delete;
    ScopedLocalSelectionSet& operator=(const ScopedLocalSelectionSet&) = delete;

    [[nodiscard]] SSelectionSetUserEntity& get() noexcept { return mSet; }
    [[nodiscard]] const SSelectionSetUserEntity& get() const noexcept { return mSet; }

  private:
    SSelectionSetUserEntity mSet{};
  };

  /**
   * `ScopedLocalSelectionSet`'s `WeakSet<UserUnit>` sibling: the transient
   * participant set `Moho::SCommandModeData::HandleEvent` (0x0081FCD0) builds
   * on the stack before handing it to `CFormation::ChooseFormation`.
   *
   * The two instantiations are byte-identical (see `WeakUnitSetUserUnit`'s own
   * doc comment), so the head sentinel/teardown reuse the shared helpers; only
   * the C++ element type differs, which is what keeps `WeakSet<UserUnit>::Add`
   * (0x00822270) apart from `WeakSet<UserEntity>::Add` (0x007AE1B0).
   *
   * Address: 0x007B25C0 (ctor emission) / 0x007B2530 (dtor emission).
   */
  class ScopedLocalUnitSet final
  {
  public:
    ScopedLocalUnitSet() { InitWeakEntitySetHead(mSet); }
    ~ScopedLocalUnitSet() { DestroyWeakEntitySet(mSet); }

    ScopedLocalUnitSet(const ScopedLocalUnitSet&) = delete;
    ScopedLocalUnitSet& operator=(const ScopedLocalUnitSet&) = delete;

    [[nodiscard]] WeakUnitSetUserUnit& get() noexcept { return mSet; }
    [[nodiscard]] const WeakUnitSetUserUnit& get() const noexcept { return mSet; }

  private:
    WeakUnitSetUserUnit mSet{};
  };

  /**
   * Like `ScopedLocalSelectionSet`, but leaves the head storage unallocated so
   * a copy routine (`CopySessionSelectionSet`) allocates and populates it in
   * one pass, matching the binary's raw-weak-set + `CopySelectionSetFromOther`
   * idiom.
   */
  class ScopedCopiedSelectionSet final
  {
  public:
    ScopedCopiedSelectionSet() = default;
    ~ScopedCopiedSelectionSet() { DestroyLocalSelectionSet(mSet); }

    ScopedCopiedSelectionSet(const ScopedCopiedSelectionSet&) = delete;
    ScopedCopiedSelectionSet& operator=(const ScopedCopiedSelectionSet&) = delete;

    [[nodiscard]] SSelectionSetUserEntity& get() noexcept { return mSet; }
    [[nodiscard]] const SSelectionSetUserEntity& get() const noexcept { return mSet; }

  private:
    SSelectionSetUserEntity mSet{};
  };

  struct SSessionSaveData
  {
    SSessionSaveNodeMap mNodeMap; // +0x00

    /**
       * Address: 0x00896F00 (FUN_00896F00)
     *
     * What it does:
     * Initializes save-data RB-tree header node and resets map size.
     */
    SSessionSaveData();

    /**
       * Address: 0x008971A0 (FUN_008971A0)
     *
     * What it does:
     * Releases all map nodes and their string payloads.
     */
    ~SSessionSaveData();

    /**
       * Address: 0x008992D0 (FUN_008992D0)
     *
     * What it does:
     * Inserts one `(commandSourceId, saveNodeName)` record into session save-data map.
     * Source-side helpers (`InsertSaveDataLabelNode`, `FixupSaveDataInsert`,
     * `RotateSaveDataLeft`, `RotateSaveDataRight`) are a typed decomposition of that
     * binary chain, not standalone exported game methods.
     */
    void InsertNodeLabel(std::uint32_t commandSourceId, const msvc8::string& saveNodeName);
  };

  static_assert(sizeof(SSessionSaveData) == 0x0C, "SSessionSaveData size must be 0x0C");
  static_assert(offsetof(SSessionSaveData, mNodeMap) == 0x00, "SSessionSaveData::mNodeMap offset must be 0x00");

  /**
   * Address: 0x0089AEC0 (FUN_0089AEC0, boost::shared_ptr_SSessionSaveData::shared_ptr_SSessionSaveData)
   *
   * What it does:
   * Constructs one `shared_ptr<SSessionSaveData>` from one raw save-data
   * pointer lane.
   */
  boost::shared_ptr<SSessionSaveData>* ConstructSharedSessionSaveDataFromRaw(
    boost::shared_ptr<SSessionSaveData>* outSaveData,
    SSessionSaveData* saveData
  );

  class CWldSession
  {
  public:
    /**
     * Address: 0x00893160 (FUN_00893160,
     * ??0CWldSession@Moho@@QAE@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@3@AAV?$auto_ptr@VCWldMap@Moho@@@3@AAUSWldSessionInfo@1@@Z)
     *
     * What it does:
     * Bootstraps world-session runtime state from released Lua/rules/map auto_ptr owners
     * and session-info launch data.
     */
    CWldSession(
      msvc8::auto_ptr<LuaPlus::LuaState>& state,
      msvc8::auto_ptr<RRuleGameRules>& rules,
      msvc8::auto_ptr<CWldMap>& wldMap,
      SWldSessionInfo& sessionInfo
    );

    /**
     * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
     *
     * What it does:
     * Tears down world-session owned runtime objects and releases transferred owners.
     */
    ~CWldSession();

    /**
      * Alias of FUN_008B9580 (non-canonical helper lane).
     *
     * What it does:
     * Reads terrain playable-bounds rectangle used by user-entity visibility checks.
     */
    [[nodiscard]] bool TryGetPlayableMapRect(VisibilityRect& outRect) const;

    /**
     * Address: 0x007F6390 (FUN_007F6390, Moho::CWldSession::GetTickDebugCanvas)
     *
     * What it does:
     * Returns a retained shared reference to the tick-scoped debug canvas
     * (`mDebugCanvas`, +0x0414). Despite the field's plain name, `DoBeat`
     * re-seats it from `beat.mTickDebugCanvas` every tick, so "tick" describes
     * what it holds, not the member name.
     *
     * `WRenViewport::Render` (0x007F90D0) calls this once per frame to decide
     * whether there is a tick debug canvas to draw.
     */
    [[nodiscard]] boost::SharedPtrRaw<CDebugCanvas> GetTickDebugCanvas() const;

    /**
     * Address: 0x007F63C0 (FUN_007F63C0, Moho::CWldSession::GetBeatDebugCanvas)
     *
     * What it does:
     * Returns a retained shared reference to the beat-scoped debug canvas
     * (`mBeatDebugCanvas`, +0x041C).
     */
    [[nodiscard]] boost::SharedPtrRaw<CDebugCanvas> GetBeatDebugCanvas() const;

    /**
     * Address: 0x007A6360 (FUN_007A6360, ?GetFocusArmy@CWldSession@Moho@@QBEPAVUserArmy@2@XZ)
     *
     * What it does:
     * Returns the currently focused army pointer, or `nullptr` when focus is
     * disabled (`FocusArmy < 0`).
     */
    [[nodiscard]] UserArmy* GetFocusArmy() const;

    /**
     * Address: 0x00896590 (FUN_00896590, ?IsObserver@CWldSession@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns true when focus army is disabled (`FocusArmy < 0`) or when the
     * focused army lane has no live `UserArmy*` owner.
     */
    [[nodiscard]] bool IsObserver() const;

    /**
     * Address: 0x00896570 (FUN_00896570, ?SetCursorInfo@CWldSession@Moho@@QAEXABUUICursorInfo@2@@Z)
     *
     * What it does:
     * Copies one cursor-info payload into the session cursor-info lane.
     */
    void SetCursorInfo(const MouseInfo& cursorInfo);

    /**
     * Address: 0x00895FF0 (FUN_00895FF0, ?GetSelection@CWldSession@Moho@@QBEABV?$WeakSet@VUserEntity@Moho@@@2@XZ)
     *
     * What it does:
     * Returns the current world-session selection weak-set.
     */
    [[nodiscard]] const SSelectionSetUserEntity& GetSelection() const;

    /**
     * Address: 0x00896730 (FUN_00896730, ?GetExtraSelectList@CWldSession@Moho@@QBE?AV?$WeakSet@VUserEntity@Moho@@@2@XZ)
     *
     * What it does:
     * Returns a by-value copy of the world-session extra-selection weak-set
     * using the same iterator-range clone path as the original binary.
     */
    [[nodiscard]] SSelectionSetUserEntity GetExtraSelectList() const;

    /**
     * Address: 0x00896580 (FUN_00896580, ?GetCursorInfo@CWldSession@Moho@@QBEABUUICursorInfo@2@XZ)
     *
     * What it does:
     * Returns the current cursor-info payload stored by this world session.
     */
    [[nodiscard]] const MouseInfo& GetCursorInfo() const;

    /**
     * Not a distinct binary function - every caller inlines the same
     * `mCursorInfo.mUnitHover` weak-link decode. Promoted to a public
     * accessor so callers outside this TU can resolve the hovered entity
     * without their own copy of the decode.
     *
     * `MouseInfo::mUnitHover` is declared as a raw `UserEntity*`, but the
     * binary stores an intrusive weak-link slot there, not a live pointer -
     * this accessor decodes it correctly; reading `GetCursorInfo().mUnitHover`
     * directly does not.
     */
    [[nodiscard]] UserEntity* GetHoveredUserEntity() const noexcept;

    /**
     * Address: 0x008965C0 (FUN_008965C0, ?BecomeObserver@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Validates observer focus request (`-1`) and applies it to the active sim
     * driver when allowed.
     */
    void BecomeObserver();

    /**
     * Address context: compatibility wrapper lane used by recovered callsites.
     *
     * What it does:
     * Exposes focused army accessor for user-session code paths.
     */
    [[nodiscard]] UserArmy* GetFocusUserArmy();
    [[nodiscard]] const UserArmy* GetFocusUserArmy() const;

    /**
     * Address: 0x008965E0 (FUN_008965E0, ?RequestFocusArmy@CWldSession@Moho@@QAEXH@Z)
     *
     * What it does:
     * Validates one zero-based focus-army index (`-1` allowed) and forwards
     * accepted changes to the active sim driver.
     */
    void RequestFocusArmy(int index);

    /**
      * Alias of FUN_008B97C0 (non-canonical helper lane).
     *
     * What it does:
     * Returns typed category resolver interface for `rules`.
     */
    [[nodiscard]] EntityCategoryLookupResolver* GetCategoryLookupResolver();
    [[nodiscard]] const EntityCategoryLookupResolver* GetCategoryLookupResolver() const;

    /**
      * Alias of FUN_008B85E0 (non-canonical helper lane).
     *
     * What it does:
     * Returns storage root used as SpatialDB_MeshInstance owner for user-entity DB entries.
     */
    [[nodiscard]] void* GetEntitySpatialDbStorage();
    [[nodiscard]] const void* GetEntitySpatialDbStorage() const;

    /**
     * Address: 0x00894120 (FUN_00894120, ?GetTerrainRes@CWldSession@Moho@@QBEPAVIWldTerrainRes@2@XZ)
     *
     * What it does:
     * Returns the world-map terrain resource lane owned by this world session.
     */
    [[nodiscard]] IWldTerrainRes* GetTerrainRes() const;

    /**
     * Address: 0x00894130 (FUN_00894130, ?GetSTIMap@CWldSession@Moho@@QBEPAVSTIMap@2@XZ)
     *
     * What it does:
     * Returns the terrain STI map lane owned by the world-map terrain resource.
     */
    [[nodiscard]] STIMap* GetSTIMap() const;

    /**
     * Typed view over the flattened cursor snapshot at `+0x4B0` (see the
     * member comment there). `FUN_00852C10` passes exactly this to
     * `GetLeftMouseButtonAction`.
     */
    [[nodiscard]] MouseInfo& CursorInfo() noexcept;

    /**
     * Address: 0x00894140 (FUN_00894140, ?AddEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Inserts one `(entityId, entity*)` mapping into the world-session entity map.
     */
    void AddEntity(UserEntity* entity);

    /**
     * Address: 0x00894170 (FUN_00894170, ?RemoveEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Removes one entity-id mapping from the world-session entity map.
     */
    void RemoveEntity(UserEntity* entity);

    /**
     * Address: 0x008941B0 (FUN_008941B0, ?OrphanEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Removes one entity-id mapping from the session entity tree, marks the
     * entity for deletion, and enqueues it in the session orphan weak-set lane.
     */
    void OrphanEntity(UserEntity* entity);

    /**
     * Address: 0x00894210 (FUN_00894210, ?AddToVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Adds an entity into the world-session viz-update RB-tree.
     */
    void AddToVizUpdate(UserEntity* entity);

    /**
     * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Removes an entity from the world-session viz-update RB-tree.
     */
    void RemoveFromVizUpdate(UserEntity* entity);

    /**
     * Address: 0x008942B0 (FUN_008942B0, ?RequestPause@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Applies session pause request state and notifies registered pause listeners.
     */
    void RequestPause();

    /**
     * Address: 0x00894330 (FUN_00894330, ?Resume@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Applies session resume request state and notifies registered pause listeners.
     */
    void Resume();

    /**
     * Address: 0x008943E0 (FUN_008943E0, ?CheckForNecessaryUIRefresh@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Rebuilds selection when selected entities request UI refresh or when
     * stale/dead weak links reduce the live selection set.
     */
    void CheckForNecessaryUIRefresh();

    /**
     * Address: 0x00894530 (FUN_00894530,
     * ?DoBeat@CWldSession@Moho@@QAEXV?$auto_ptr@USSyncData@Moho@@@std@@@Z)
     *
     * IDA signature:
     * void __stdcall Moho::CWldSession::DoBeat(Moho::CWldSession *this, std::auto_ptr<SSyncData> sdata);
     *
     * What it does:
     * Applies one sim beat to the client world. This is the sole consumer of
     * the sync queue: it adopts the packet, walks its ~25 lanes in order
     * (armies, entities, units, commands, decals, cameras, poses, deletions,
     * Lua sync, desyncs), ticks every registered unit, drains the orphan and
     * visibility sets, and destroys the packet on the way out.
     *
     * The parameter is by-value ownership; nothing else may free the packet.
     */
    void DoBeat(msvc8::auto_ptr<SSyncData> syncData);

    /**
     * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
     *
     * What it does:
     * Runs one world-session frame: Lua rules update, sync beat drain, command-graph
     * mesh build, and task-stage user frame.
     */
    void SessionFrame(float deltaSeconds);

    /**
     * Address: 0x00896900 (FUN_00896900, ?GetDelayToNextBeat@CWldSession@Moho@@QBEMXZ)
     *
     * What it does:
     * Returns the delay until the next beat in seconds, or `+inf` while replay
     * pause is holding on a tick boundary.
     */
    [[nodiscard]] float GetDelayToNextBeat() const;

    /**
     * Address: 0x00895FD0 (FUN_00895FD0, ?GetGameTime@CWldSession@Moho@@QBEMXZ)
     *
     * What it does:
     * Returns total game time in seconds (`(mGameTick + mTimeSinceLastTick) * 0.1`).
     */
    [[nodiscard]] float GetGameTime() const;

    /**
     * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
     *
     * What it does:
     * Walks world-session selected-entity weak-set and appends typed `UserUnit*`
     * entries for currently live selected units.
     */
    void GetSelectionUnits(msvc8::vector<UserUnit*>& outUnits) const;

    /**
     * Address: 0x00896090 (FUN_00896090, ?GetValidAttackingUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
     *
     * What it does:
     * Filters current selection down to units that can attack the hovered
     * target entity and writes unique unit entries to `outUnits`.
     */
    void GetValidAttackingUnits(msvc8::vector<UserUnit*>& outUnits) const;

    /**
     * Address: 0x00894280 (FUN_00894280, ?LookupEntityId@CWldSession@Moho@@QAEPAVUserEntity@2@VEntId@2@@Z)
     *
     * What it does:
     * Performs one ordered entity-id lookup in the world-session entity map
     * and returns the live `UserEntity*` when the key is present.
     */
    [[nodiscard]] UserEntity* LookupEntityId(EntId entityId);

    /**
     * Address: 0x00896140 (FUN_00896140, ?SetSelection@CWldSession@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@@Z)
     *
     * What it does:
     * Replaces world-session selection from one supplied weak-set, broadcasts
     * one `{previous,current,added,removed}` selection-event payload, updates
     * max-selection bookkeeping, and refreshes sync-filter mask B when changed.
     */
    void SetSelection(const SSelectionSetUserEntity& selection);

    /**
     * Address context:
     * - `cfunc_SelectUnitsL` / `cfunc_AddSelectUnitsL` user-Lua selection paths.
     *
     * What it does:
     * Replaces world-session selection with the supplied user-unit list,
     * updates selection-size bookkeeping, and refreshes sync filter mask B
     * when the selection set changes.
     */
    void SetSelectionUnits(const msvc8::vector<UserUnit*>& units);

    /**
     * Address: 0x00865830 (FUN_00865830, ?CanSelectUnit@CWldSession@Moho@@QBE_NPAVUserUnit@2@@Z)
     *
     * What it does:
     * Returns whether one unit is selectable for this session using focus-army
     * ownership rules, with optional cheat override (`UI_SelectAnything`).
     */
    [[nodiscard]] bool CanSelectUnit(UserUnit* unit) const;

    /**
     * Address: 0x00865920 (FUN_00865920, ?ReleaseDrag@CWldSession@Moho@@QAEXW4EMauiEventModifier@2@@Z)
     *
     * What it does:
     * Finalizes click-based unit selection for current cursor hover and input
     * modifier mask.
     */
    void ReleaseDrag(EMauiEventModifier modifiers);

    /**
     * Address: 0x00865E20 (FUN_00865E20, ?HandleDoubleClickSelection@CWldSession@Moho@@QAEXPAVCameraImpl@2@@Z)
     *
     * What it does:
     * Expands selection to matching units in camera frustum after unit
     * double-click.
     */
    void HandleDoubleClickSelection(CameraImpl* camera);

    /**
     * Address: 0x00896780 (FUN_00896780, ?AddToExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Starts transport order command mode and adds one entity into the
     * world-session extra-selection weak-set.
     */
    void AddToExtraSelectList(UserEntity* entity);

    /**
     * Address: 0x00896830 (FUN_00896830, ?RemoveFromExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Removes one entity from the world-session extra-selection weak-set and
     * exits command mode when the set becomes empty.
     */
    void RemoveFromExtraSelectList(UserEntity* entity);

    /**
     * Address: 0x00896870 (FUN_00896870, ?ClearExtraSelectList@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears world-session extra selection weak-set and exits command mode when
     * any entries were present.
     */
    void ClearExtraSelectList();

    /**
     * Address: 0x0081DC70 (FUN_0081DC70, Moho::CWldSession::UnitFirstInSelection)
     *
     * What it does:
     * Returns true when selection is empty or every live selected entity
     * resolves to the supplied user-unit pointer.
     */
    [[nodiscard]] bool UnitFirstInSelection(const UserUnit* unit) const;

    /**
     * Address: 0x00896960 (FUN_00896960, ?SyncPlayableRect@CWldSession@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Applies one playable rectangle to terrain and updates user-entity mesh
     * hidden flags to match whether each entity lies inside that rectangle.
     */
    void SyncPlayableRect(const gpg::Rect2i& playableRect);

    /**
      * Alias of FUN_00896F00 (non-canonical helper lane).
     * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
     *
     * What it does:
     * Builds a save-data snapshot for current world-session entities.
     */
    [[nodiscard]] boost::shared_ptr<SSessionSaveData> GetSaveData() const;

    /**
     * Address: 0x0087FC90 (FUN_0087FC90,
     * ?GetScenarioInfo@CWldSession@Moho@@QBE?AVLuaObject@LuaPlus@@XZ)
     *
     * What it does:
     * Returns one value-copy of the session scenario-info Lua object.
     */
    [[nodiscard]] LuaPlus::LuaObject GetScenarioInfo() const;

    /**
     * Address: 0x0081F7B0 (FUN_0081F7B0,
     * ?GetLeftMouseButtonAction@CWldSession@Moho@@QAEAAUCommandModeData@2@PAU32@PBUstruct_MouseInfo@@H@Z)
     *
     * What it does:
     * Resolves current left-mouse action mode from UI command state + mouse context.
     */
    CommandModeData* GetLeftMouseButtonAction(CommandModeData* outMode, const MouseInfo* mouseInfo, int modifiers);

    /**
     * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
     *
     * The mangled name types this as a zero-argument `__thiscall`, but the
     * sole call site (`CRenderWorldView::Render`, 0x0086EEE5..0x0086EEED)
     * pushes two explicit stack values before the call - the camera view
     * pointer (`CameraImpl::CameraGetView()`'s result) and the session
     * pointer itself, matching the same "IDA's declared prototype
     * undercounts the real args" pattern already documented on
     * `DrawPathPreview` and `DrawEconomyOverlay` in this file. `this`
     * arrives normally in `ecx` (session-member field reads throughout the
     * body confirm it); the second stack slot the body reads is a
     * `CD3DPrimBatcher*` third value that `Render` also pushes at that call
     * site (`edi`, its own `batcher` parameter, staged ahead of the
     * intervening `CameraGetView` call).
     *
     * What it does:
     * Debug/dev overlay, gated on Shift being held with no UI control
     * focused (`MAUI_KeyIsDown(MKEY_SHIFT)`, 0x00851721..0x00851742):
     * walks the selection weak-set, collects the distinct army indices of
     * selected units into a `BVIntSet`, and always publishes that set via
     * `ISTIDriver::SetSyncFilterMaskA` so the overlay can see sync data for
     * those armies even when Shift is not held. While Shift is held, walks
     * `mSyncInlineVectors` (the per-beat command-link scratch runs written
     * by `CWldSession::DoBeat`/`AssignSyncInlineVectors`, previously an
     * unread lane) and, for each `(sourceEntityId, {boneIndex, targetId})`
     * record, draws a thin beveled line quad from the source unit's
     * position (direct interpolated position, or one bone's composite pose
     * position when `boneIndex >= 0`) to the target unit's position -
     * teleport-colored when both units share an army and the target is in
     * the "TELEPORTBEACON" category, attack-colored otherwise - then queues
     * a small flat icon billboard at the target position into one of two
     * batches. After the loop, draws the queued attack-icon batch textured
     * with `attack_btn_up.dds` and the teleport-icon batch textured with
     * `teleport_btn_up.dds`, then flushes the batcher.
     */
    void DrawCommandSplats(GeomCamera3* camera, CD3DPrimBatcher* primBatcher);

    /**
     * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
     *
     * What it does:
     * Rebuilds this frame's formation-placement ghosts: clears last frame's
     * previews, then - while the pending formation is ready, still has a live
     * instance and its placement timer has elapsed - spawns one translucent
     * "UnitFormationPreview"-shaded mesh per participant unit, seated on the
     * terrain at its assigned slot and turned to the formation heading.
     */
    void RenderMeshPreviews();

    /**
     * Address: 0x0085B6E0 (FUN_0085B6E0,
     * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
     *
     * What it does:
     * Classifies visible units and renders strategic icons, overlays, and lifebars.
     *
     * Argument note: the body reads the third slot as a `float`, not as the
     * `CWldMap*` the mangled name types it. Both reads are `movss` against
     * `[esp+argC]` - 0x0085B843, which stores it into the icon-aux object's
     * tick-fraction lane with `movss dword ptr [ebp+1Ch], xmm0`, and
     * 0x0085BCF8, which loads it straight into `xmm1` as the interpolant for
     * `UserEntity::GetInterpolatedTransform(float)` at 0x0085BD08. The
     * declared type is kept because `CRenderWorldView::Render` (0x0086EE69)
     * passes its own `map` parameter through unchanged and the same puzzle is
     * already documented on `DrawEconomyOverlay` below; retyping the whole
     * `map` slot chain is a separate pass that has to own CRenderWorldView.
     */
    /**
     * `isMiniMap` is a fourth argument the mangled name does not carry.
     * `CRenderWorldView::Render` dispatches `IsMiniMap()` at 0x0086EE4E and
     * pushes the result at 0x0086EE5B as the fifth stack slot (the first
     * holds `this`), and this function forwards it - unmodified, loop
     * invariant - to both label passes as their suppress flag: the minimap
     * draws bars but never text.
     */
    void RenderStrategicIcons(CameraImpl* camera, CD3DPrimBatcher* primBatcher, CWldMap* map, bool isMiniMap);

    /**
     * Address: 0x008621B0 (FUN_008621B0,
     * ?RenderProjectileIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCRenderWorldView@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@M@Z)
     *
     * What it does:
     * Renders strategic projectile icons/glow overlays for visible projectile entities.
     */
    void RenderProjectileIcons(
      CameraImpl* camera, CRenderWorldView* worldView, CD3DPrimBatcher* primBatcher, CWldMap* map, float deltaSeconds
    );

    /**
     * Address: 0x00862A80 (FUN_00862A80,
     * ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
     *
     * What it does:
     * Renders mass/hydro strategic resource splats in strategic view.
     */
    void RenderResources(GeomCamera3* camera, CD3DPrimBatcher* primBatcher);

    /**
     * Address: 0x00858D80 (FUN_00858D80, Moho::CWldSession::DrawEconomyOverlay)
     *
     * IDA signature:
     * void __usercall Moho::CWldSession::DrawEconomyOverlay(
     *   CWldSession *session, CD3DPrimBatcher *batcher, CWldMap *map,
     *   CameraImpl *camera@<ecx>);
     *
     * What it does:
     * Draws the net energy/mass rate readout over every army unit in the
     * camera frustum. Per unit: a three-slice textured bar sized to the wider
     * of the two numbers, then each number twice - a one-pixel black drop
     * shadow, then the value in the positive or negative colour. Units that
     * are dead, queued for destruction, past their mesh's icon-fade-in
     * distance, or exactly break-even on both resources are skipped.
     *
     * `camera` arrives in `ecx` at the call site (0x0086EF07) while the
     * session is the first stack argument, so this is a `__usercall` in the
     * binary and a method here, matching the sibling render overlays.
     *
     * `map` is passed by the caller and never read by the body: the only reads
     * of incoming stack slots are +4 (session, `mov eax, [esp+0Ch+a1]`) and +8
     * (batcher, `mov ebp, [esp+198h+a6]` = `[esp+1A0h]`). Slot +0xC is dead.
     * It is kept in the signature because `Render` (0x0086EF07) does push it,
     * and because the sibling overlay
     * `RenderStrategicIcons(CameraImpl*, CD3DPrimBatcher*, CWldMap*)` - whose
     * mangled name types that slot outright - takes the same triple.
     *
     * There is no `float interpolant` parameter. The value this passes to
     * `UserEntity::GetInterpolatedPosition` is a frame LOCAL at -4, stored once
     * from a zeroed `ebx` (`xor ebx, ebx` 0x00858DAF ->
     * `mov [esp+1A0h+interpolant], ebx` 0x00858E0E, raw `89 9C 24 9C 01 00 00`
     * = `[esp+19Ch]`, i.e. 0x19C - 0x1A0 = -4) and never rewritten. So the
     * overlay always samples entity positions at interpolant 0.
     */
    void DrawEconomyOverlay(CameraImpl* camera, CD3DPrimBatcher* primBatcher, CWldMap* map);

  public:
    /**
     * Address: 0x00896A40 (FUN_00896A40, ?GetActiveBuildTemplate@CWldSession@Moho@@QBE?AV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@AAH0@Z)
     *
     * What it does:
     * Copies the active build-template buffer into one caller-owned inline
     * fastvector lane and returns the current template X/Z extents.
     */
    SBuildTemplateBuffer*
    GetActiveBuildTemplate(float* outTemplateSpanZ, float* outTemplateSpanX, SBuildTemplateBuffer* result) const;

    /**
     * Address: 0x00896AA0 (FUN_00896AA0, ?GenerateBuildTemplates@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Rebuilds build-template entries from the current selection using
     * non-mobile, non-dead units; computes template extents and normalizes all
     * entry positions relative to the first sorted template lane.
     */
    void GenerateBuildTemplates();

    /**
     * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Releases build-template entry strings, resets inline storage pointers,
     * and clears template placement args.
     */
    void ClearBuildTemplates();

    /**
     * Address: 0x00896A70 (FUN_00896A70,
     *   ?SetActiveBuildTemplate@CWldSession@Moho@@QAEXABV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@HH@Z)
     *
     * What it does:
     * Replaces the active build-template fastvector buffer with `templates`
     * and records the placement preview anchor as (`templateSpanX`,
     * `templateSpanZ`) for the build-cursor overlay.
     *
     * The actual buffer copy is routed through the per-type named helper
     * `moho::AssignBuildTemplateBuffer` (FUN_00899790) so the linker keeps
     * the engine-emitted assignment symbol bound.
     */
    void SetActiveBuildTemplate(
      const SBuildTemplateBuffer& templates,
      float templateSpanX,
      float templateSpanZ
    );

    /**
     * Address: 0x00895F70 (FUN_00895F70, ?DirtyCommandGraph@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Locks the cached UI command-graph weak handle, marks it dirty when
     * present, and releases the temporary shared hold.
     */
    void DirtyCommandGraph();

    /**
     * Address: 0x00895EB0 (FUN_00895EB0,
     * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
     *
     * What it does:
     * Locks/returns cached command-graph weak handle and optionally creates it.
     *
     * Callers outside `CWldSession`: `Moho::DrawCommandGraph` (0x00853DC0) and
     * `sub_85AF40` (0x0085AF40) both call this directly, so it can't stay
     * private.
     */
    [[nodiscard]] boost::SharedPtrRaw<UICommandGraph> GetCommandGraph(bool allowCreate);

  private:
    /**
     * Address: 0x008958B0 (FUN_008958B0, ?ApplyPendingSaveData@CWldSession@Moho@@AAEXXZ)
     *
     * What it does:
     * Applies pending save-data selection-set labels to live user units and
     * calls UI selection reset with a table grouped by set name.
     */
    void ApplyPendingSaveData();

    /**
     * Address: 0x00895DC0 (FUN_00895DC0, ?HandleFogEdge@CWldSession@Moho@@AAEXABV?$Rect2@H@gpg@@HH@Z)
     *
     * What it does:
     * Clears/marks edge-fog rows outside the supplied visible rectangle and
     * refreshes the backing edge-fog buffer.
     */
    void HandleFogEdge(const gpg::Rect2i& visibleRect, int width, int height);

    /**
     * Address: 0x00896670 (FUN_00896670, ?ValidateFocusArmyRequest@CWldSession@Moho@@AAE_NH@Z)
     *
     * What it does:
     * Returns whether one focus-army switch is allowed for the current command
     * source/session observation state.
     */
    [[nodiscard]] bool ValidateFocusArmyRequest(int index);

    /**
     * Address context: 0x00896870 (`ClearExtraSelectList`) field lane.
     *
     * What it does:
     * Returns typed view for the extra-selection weak-set embedded inside the
     * spatial-db storage block.
     */
    [[nodiscard]] SSelectionSetUserEntity& ExtraSelectionView();
    [[nodiscard]] const SSelectionSetUserEntity& ExtraSelectionView() const;

  public:
    gpg::core::IntrusiveLink<CWldSession*> head0;
    gpg::core::IntrusiveLink<CWldSession*> head1;

    LuaPlus::LuaState* mState;                              // 0x0010
    CTaskStage* mCurThread;                                 // 0x0014
    RRuleGameRulesImpl* mRules;                             // 0x0018
    CWldMap* mWldMap;                                       // 0x001C
    boost::shared_ptr<LaunchInfoBase> mLaunchInfo;          // 0x0020
    msvc8::string mMapName;                                 // 0x0028
    void* mUnknownOwner44;                                  // 0x0044
    void* mSaveSourceTreeHead;                              // 0x0048
    std::uint32_t mSaveSourceTreeSize;                      // 0x004C
    std::uint8_t mEntitySpatialDbStorage[0xA0];             // 0x0050
    SBuildTemplateBuffer mBuildTemplates;                   // 0x00F0 (inline-buffer vector-style storage)
    float mBuildTemplateArg1;                               // 0x03C0
    float mBuildTemplateArg2;                               // 0x03C4
    VisionDb mVisionDb;                                     // 0x03C8
    msvc8::vector<UserArmy*> userArmies;                    // 0x03EC
    /// The session-wide command manager. `DoBeat`, the right-click dispatcher
    /// and `UserUnit`'s manager resync all reach its `mCommands` map through
    /// this pointer.
    CommandManager* mCommandManager;                        // 0x03FC
    CFormation* mCurFormation;                              // 0x0400
    UICommandGraph* mUICommandGraphPx;                      // 0x0404
    boost::detail::sp_counted_base* mUICommandGraphControl; // 0x0408 (weak control block for mUICommandGraphPx)
    boost::SharedPtrRaw<void> mUnknownShared40C;            // 0x040C
    boost::SharedPtrRaw<CDebugCanvas> mDebugCanvas;         // 0x0414
    /// The beat-scoped debug canvas; `DoBeat` re-seats it from the packet.
    boost::SharedPtrRaw<CDebugCanvas> mBeatDebugCanvas;     // 0x041C
    boost::SharedPtrRaw<CSimResources> mSimResources;       // 0x0424
    void* mAuxUpdateRoot;                                   // 0x042C
    void* mAuxUpdateHead;                                   // 0x0430
    std::uint32_t mAuxUpdateSize;                           // 0x0434
    void* mVizUpdateRoot;                                   // 0x0438
    void* mVizUpdateHead;                                   // 0x043C
    std::uint32_t mVizUpdateSize;                           // 0x0440
    LuaPlus::LuaObject mScenarioInfo;                       // 0x0444
    std::int32_t mGameTick;                                 // 0x0458
    std::int32_t mLastBeatWasTick;                          // 0x045C
    float mTimeSinceLastTick;                               // 0x0460
    std::uint8_t mSessionPauseStateA;                       // 0x0464
    std::uint8_t mRequestingPauseState;                     // 0x0465
    std::uint8_t mRequestingPause;                          // 0x0466
    std::uint8_t pad_0467[1];                               // 0x0467
    std::int32_t mPauseRequester;                           // 0x0468
    std::uint8_t mReplayIsPaused;                           // 0x046C
    char pad_046D[3];                                       // 0x046D
    msvc8::vector<SSTICommandSource> cmdSources;            // 0x0470
    int32_t ourCmdSource;                                   // 0x0480
    bool IsReplay;                                          // 0x0484
    bool IsBeingRecorded;                                   // 0x0485
    bool IsMultiplayer;                                     // 0x0486
    bool IsObservingAllowed;                                // 0x0487
    int32_t FocusArmy;                                      // 0x0488
    uint8_t IsGameOver;                                     // 0x048C
    char pad_048D[3];                                       // 0x048D
    /// Per-beat copy of `SSyncData::mInlineScratchVectors`. `CWldSession::DoBeat`
    /// assigns the whole run over (0x00895214, the 32-byte-stride vector
    /// assignment); it is the lane's only writer, and no reader has been
    /// identified in the binary yet.
    msvc8::vector<SyncInlineVector> mSyncInlineVectors;      // 0x0490
    SSelectionSetUserEntity mSelection;                     // 0x04A0
    /// These five members are one flattened `MouseInfo` - the cursor snapshot
    /// the session keeps. `FUN_00852C10` hands `this + 0x4B0` straight to
    /// `GetLeftMouseButtonAction(out, const MouseInfo*, int)` at 0x00852C39,
    /// and the bytes line up exactly: `mHitValid`+pad, `mMouseWorldPos`,
    /// `{mUnitHover, mPrevious}`, `mIsDragger` (which is what
    /// `HighlightCommandId` really is) and `mMouseScreenPos`, ending at
    /// 0x4B0 + sizeof(MouseInfo) == 0x4D4. Use `CursorInfo()` below rather
    /// than these lanes; folding them into a real member is a separate pass
    /// because 31 call sites still name them individually.
    std::uint8_t mCursorWorldState[4];                      // 0x04B0
    Wm3::Vector3f CursorWorldPos;                           // 0x04B4
    char pad_04C0[8];                                       // 0x04C0
    int32_t HighlightCommandId;                             // 0x04C8
    Wm3::Vector2f CursorScreenPos;                          // 0x04CC
    bool IsCheatsEnabled;                                   // 0x04D4
    bool mShowInvalidBuildPlacementPreview;                 // 0x04D5
    char pad_04D6[2];                                       // 0x04D6
    msvc8::vector<msvc8::string> mOverlayFilters;           // 0x04D8
    bool DisplayEconomyOverlay;                             // 0x04E8
    bool mTeamColorMode;                                    // 0x04E9
    char pad_04EA[2];                                       // 0x04EA
    gpg::MemBuffer<char> mEdgeFog;                          // 0x04EC
    boost::shared_ptr<SSessionSaveData> mPendingSaveData;   // 0x04FC
    char pad_0504[4];                                       // 0x0504
  };

  static_assert(
    sizeof(CWldSession) >= 0x500 && sizeof(CWldSession) <= 0x540, "CWldSession size must remain in expected x86 range"
  );
  static_assert(offsetof(CWldSession, mWldMap) == 0x1C, "CWldSession::mWldMap offset must be 0x1C");
  static_assert(offsetof(CWldSession, mLaunchInfo) == 0x20, "CWldSession::mLaunchInfo offset must be 0x20");
  static_assert(
    offsetof(CWldSession, mSaveSourceTreeHead) == 0x48, "CWldSession::mSaveSourceTreeHead offset must be 0x48"
  );
  static_assert(
    offsetof(CWldSession, mEntitySpatialDbStorage) == 0x50, "CWldSession::mEntitySpatialDbStorage offset must be 0x50"
  );
  static_assert(
    (offsetof(CWldSession, mEntitySpatialDbStorage) + 0x90) == 0xE0,
    "CWldSession extra-selection view base must remain at 0xE0"
  );
  static_assert(offsetof(CWldSession, mBuildTemplates) == 0xF0, "CWldSession::mBuildTemplates offset must be 0xF0");
  static_assert(
    offsetof(CWldSession, mBuildTemplateArg1) == 0x3C0, "CWldSession::mBuildTemplateArg1 offset must be 0x3C0"
  );
  static_assert(offsetof(CWldSession, mVizUpdateRoot) == 0x438, "CWldSession::mVizUpdateRoot offset must be 0x438");
  static_assert(offsetof(CWldSession, mScenarioInfo) == 0x444, "CWldSession::mScenarioInfo offset must be 0x444");
  static_assert(offsetof(CWldSession, mGameTick) == 0x458, "CWldSession::mGameTick offset must be 0x458");
  static_assert(
    offsetof(CWldSession, mLastBeatWasTick) == 0x45C, "CWldSession::mLastBeatWasTick offset must be 0x45C"
  );
  static_assert(
    offsetof(CWldSession, mTimeSinceLastTick) == 0x460, "CWldSession::mTimeSinceLastTick offset must be 0x460"
  );
  static_assert(
    offsetof(CWldSession, mPauseRequester) == 0x468, "CWldSession::mPauseRequester offset must be 0x468"
  );
  static_assert(
    offsetof(CWldSession, mReplayIsPaused) == 0x46C, "CWldSession::mReplayIsPaused offset must be 0x46C"
  );
  static_assert(offsetof(CWldSession, FocusArmy) == 0x488, "CWldSession::FocusArmy offset must be 0x488");
  static_assert(offsetof(CWldSession, mSelection) == 0x4A0, "CWldSession::mSelection offset must be 0x4A0");
  static_assert(
    offsetof(CWldSession, mCursorWorldState) == 0x4B0, "CWldSession::mCursorWorldState offset must be 0x4B0"
  );
  static_assert(offsetof(CWldSession, CursorWorldPos) == 0x4B4, "CWldSession::CursorWorldPos offset must be 0x4B4");
  static_assert(offsetof(CWldSession, CursorScreenPos) == 0x4CC, "CWldSession::CursorScreenPos offset must be 0x4CC");
  static_assert(
    offsetof(CWldSession, mShowInvalidBuildPlacementPreview) == 0x4D5,
    "CWldSession::mShowInvalidBuildPlacementPreview offset must be 0x4D5"
  );
  static_assert(
    offsetof(CWldSession, mOverlayFilters) == 0x4D8, "CWldSession::mOverlayFilters offset must be 0x4D8"
  );
  static_assert(offsetof(CWldSession, mEdgeFog) == 0x4EC, "CWldSession::mEdgeFog offset must be 0x4EC");
  static_assert(
    offsetof(CWldSession, mPendingSaveData) == 0x4FC,
    "CWldSession::mPendingSaveData offset must be 0x4FC"
  );

  enum class EWldFrameAction : std::int32_t
  {
    Inactive = 0,
    Preload = 1,
    Loading = 2,
    Initialize = 3,
    PostInitialize = 4,
    Waiting = 5,
    Playing = 6,
    CreateSession = 7,
    Exit = 8,
  };

  static_assert(sizeof(EWldFrameAction) == 0x4, "EWldFrameAction size must be 0x4");

  class IWldTeardownCallback
  {
  public:
    virtual ~IWldTeardownCallback() = default;

    /**
     * Address family: callback invoke lane used by world teardown callback
     * dispatch (`FUN_00869870`).
     */
    virtual int OnWldSessionTeardown(CWldSession* session) = 0;
  };
  static_assert(sizeof(IWldTeardownCallback) == 0x4, "IWldTeardownCallback size must be 0x4");

  using WldTeardownCallbackVector = msvc8::vector<IWldTeardownCallback*>;

  /**
   * Address: 0x0083E150 (FUN_0083E150, func_UserScriptCommandObj)
   *
   * What it does:
   * Builds one Lua command-issue descriptor table (`Units`, `Blueprint`,
   * `Target`, optional `LuaParams`, `CommandType`, `Clear`) used by UI script
   * command callbacks.
   */
  [[nodiscard]] LuaPlus::LuaObject* BuildUserScriptCommandObject(
    LuaPlus::LuaObject* outCommandObject,
    LuaPlus::LuaState* state,
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    bool doClear
  );

  /**
   * Address: 0x0083E640 (FUN_0083E640,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one script command descriptor from explicit `UserUnit*` lanes,
   * calls `/lua/user/UserScriptCommand.lua:VerifyScriptCommand`, and returns
   * the Lua result object (or the command descriptor on callback failure).
   */
  [[nodiscard]] LuaPlus::LuaObject UI_VerifyScriptCommand(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    bool doClear
  );

  /**
   * Address: 0x0083E500 (FUN_0083E500,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_VerifyScriptCommand` overload.
   */
  [[nodiscard]] LuaPlus::LuaObject UI_VerifyScriptCommand(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    bool doClear
  );

  /**
   * Address: 0x0083E770 (FUN_0083E770,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one Lua command descriptor table from explicit `UserUnit*` lanes and
   * invokes `/lua/ui/game/commandmode.lua:OnCommandIssued`.
   */
  void UI_OnCommandIssued(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    bool doClear
  );

  /**
   * Address: 0x0083E870 (FUN_0083E870,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_OnCommandIssued` overload.
   */
  void UI_OnCommandIssued(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    bool doClear
  );

  /**
   * Address: 0x008B0180 (FUN_008B0180,
   * ?ISSUE_Command@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Client/UI-side command-issue keystone over an explicit `UserUnit*` list:
   * allocates a command id, runs the no-rush gate, dispatches to the sim driver,
   * publishes the command-issue helper, and enqueues it into each unit's command
   * manager. Defined in Sim.cpp.
   */
  void ISSUE_Command(const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData commandIssueData, bool clearQueue);

  /**
   * Address: 0x008B0730 (FUN_008B0730,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Factory-queue counterpart of `ISSUE_Command`: routes the command into each
   * unit's *factory* command queue instead of its primary one. Defined in
   * CWldSession.cpp; invoked from `SCommandModeData::HandleEvent`'s
   * rally-point/patrol/ferry arms.
   */
  void ISSUE_FactoryCommand(const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData commandIssueData, bool clearQueue);

  /**
   * Address: 0x008B0B30 (FUN_008B0B30,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Weak-set overload of the above: resolves the live `UserUnit*` lanes out of
   * the selection and forwards to the `fastvector` overload.
   */
  void ISSUE_FactoryCommand(
    const SSelectionSetUserEntity& entities, const SSTICommandIssueData& commandIssueData, bool clearQueue
  );

  /**
   * Address: 0x008B0EB0 (FUN_008B0EB0)
   * Mangled: ?ISSUE_DecreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_DecreaseCommandCount(
   *     int a1@<ecx>, Moho::UserCommand *a2@<edi>, int a3@<esi>);
   *
   * What it does:
   * Mirror of `ISSUE_IncreaseCommandCount`: marshals a `DecreaseCommandCount`
   * for `helper`'s command id through the active sim driver and records the
   * matching local decrease-count update event against the driver-returned
   * cookie. Defined in Sim.cpp next to the rest of the command-issue
   * event-queue lanes.
   */
  void ISSUE_DecreaseCommandCount(UserCommandIssueHelper* helper, int count);

  /**
   * Address: 0x008B0C80 (FUN_008B0C80)
   * Mangled: ?ISSUE_IncreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_IncreaseCommandCount(Moho::UserCommand* helper, int count);
   *
   * What it does:
   * Re-issues one factory-build command `count` extra times. Early-outs unless the
   * helper's resolved command type is `UNITCOMMAND_BuildFactory`. Reconstructs a
   * `SSTICommandIssueData` carrying the helper's constant command index and target
   * blueprint, decodes the helper's cached cursor entities into a live
   * `fastvector<UserUnit*>`, then calls `ISSUE_Command` once per requested count.
   */
  void ISSUE_IncreaseCommandCount(UserCommandIssueHelper* helper, int count);

  /**
   * Address: 0x008B05E0 (FUN_008B05E0,
   * ?ISSUE_Command@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*` lanes
   * and forwards to the explicit-unit `ISSUE_Command` overload. Defined in
   * CWldSession.cpp.
   */
  void ISSUE_Command(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    bool clearQueue
  );

  /**
   * Address: 0x008B0EE0 (FUN_008B0EE0,
   * ?ISSUE_SetCommandTarget@Moho@@YAXPAVUserCommand@1@ABVUserTarget@1@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_SetCommandTarget(Moho::UserCommand* helper, Moho::UserTarget const& target);
   *
   * What it does:
   * Client/UI-side command-target keystone, the `ISSUE_Command` family's
   * counterpart for redirecting a command already in flight. See the full
   * doc comment on the definition (Sim.cpp) for the no-rush gate and the
   * pickup-command category restriction. `UserCommandTargetView` is
   * `UserUnit.h`'s name for the `Moho::UserTarget` payload this mangles to
   * (only forward-declared here to avoid a CWldSession.h <-> UserUnit.h
   * include cycle; callers need `moho/unit/core/UserUnit.h` for the
   * complete type). Defined in Sim.cpp.
   */
  void ISSUE_SetCommandTarget(UserCommandIssueHelper* helper, const UserCommandTargetView& target);

  /**
   * Address: 0x008B4AC0 (FUN_008B4AC0, sub_8B4AC0)
   *
   * IDA signature:
   * void __stdcall sub_8B4AC0(int arg0, int a2, int a3);
   *
   * What it does:
   * Builds one local "set-type" command-issue update event (command id
   * `newCmdId`), packs `newCommandType` into the target payload's reused
   * `targetPoint` slot (the same union-style tag-data reuse
   * `ISSUE_SetCommandTarget`'s sibling events use), enqueues it onto
   * `helper`'s local ring queue, then destroys the local temporary. Sole
   * caller is `UserUnit.h`'s `RestartQueuedCommandsFromHelper`, reissuing
   * one already-queued order's command type in place (the mouse-drag
   * "restart as Patrol/FormPatrol" keystone,
   * `RestartMoveCommandAsPatrol`, CWldSession.cpp). Defined in Sim.cpp.
   */
  void ReissueCommandIssueEntryAsType(UserCommandIssueHelper& helper, CmdId newCmdId, EUnitCommandType newCommandType) noexcept;

  /**
   * Address: 0x00829B40 (FUN_00829B40, func_ProcessCommandDrag)
   *
   * What it does:
   * The click-and-drag command redirect keystone both
   * `Moho::UICommandDragger::DragMove` and `DragRelease` (moho/ui/CommandDragger.h/.cpp)
   * funnel into. See the full doc comment on the definition (CWldSession.cpp)
   * for the draw-node bookkeeping, factory-build placement re-validation, and
   * the three ways a released drag can resolve its final target. Only
   * forward-declares `UICommandGraph` here (defined in CWldSession.cpp) to
   * avoid exposing that type's internals across the TU boundary; callers
   * only ever pass a reference through. Defined in CWldSession.cpp.
   */
  void ProcessCommandDrag(const Wm3::Vector3f& mouse, UICommandGraph& graph, CmdId cmdId, bool released);

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker (FUN_00840A70):
   * clones one source selection weak-set into `destination`, returning it.
   * Wraps the CWldSession.cpp-local `CopySelectionSetFromOther` (FUN_00822210).
   */
  SSelectionSetUserEntity* CopySessionSelectionSet(
    SSelectionSetUserEntity* destination,
    const SSelectionSetUserEntity* source
  );

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker: resolves the world
   * position seeded from one unit's last-queued command-graph anchor history.
   * Wraps the CWldSession.cpp-local `ResolveCommandGraphAnchorHistoryWorldPosition`
   * (FUN_0081CFD0).
   */
  [[nodiscard]] Wm3::Vector3f ResolveLastQueuedCommandAnchorPosition(const QueuedUserCommandRecord* record);

  /**
   * Bridge for `Moho::DrawAllUnitSkirts` (FUN_0085AD80): resolves the world
   * position a pending command-issue helper is anchored at, by running the
   * helper's own issue-event ring through the command-graph anchor resolver
   * (FUN_008B4080 + FUN_008BED50) and unlinking the transient weak-owner lane.
   */
  [[nodiscard]] Wm3::Vector3f ResolveCommandIssueHelperAnchorPosition(UserCommandIssueHelper& helper);

  /**
   * Address: 0x00854930 (FUN_00854930) - bridge for `UpdateDragPreview`.
   *
   * What it does:
   * Evaluates build placement for one build-template stamp, snaps the preview
   * transform to the occupation result and returns the preview tint. The
   * binary reaches the session through the drag object's `+0x00` lane
   * (`mov ecx, [esi]` at 0x00854937); callers here pass it directly.
   */
  [[nodiscard]] std::uint32_t EvaluateBuildTemplatePlacementPreview(
    const Wm3::Vector3f& worldPosition,
    const RUnitBlueprint* buildBlueprint,
    CWldSession& session,
    VTransform& previewTransform
  );

  /**
   * Address: 0x00854860 (FUN_00854860) - bridge for `UpdateDragPreview`.
   *
   * What it does:
   * Same evaluation for the single-blueprint drag, including the
   * `COMMOD_BuildAnchored` build-distance test (`cmp [edi], 3` at 0x00854863).
   */
  [[nodiscard]] std::uint32_t EvaluateCommandModeBuildPlacementPreview(
    const CommandModeData& commandMode,
    const Wm3::Vector3f& worldPosition,
    CWldSession& session,
    VTransform& previewTransform
  );

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker: walks the whole
   * session entity map in id order and appends every live `UserUnit*` into
   * `outUnits`. Wraps the CWldSession.cpp-local `CollectSessionUserUnits`.
   */
  void GetSessionUserUnits(CWldSession* session, msvc8::vector<UserUnit*>& outUnits);

  /**
   * Address: 0x0066A550 (FUN_0066A550, Moho::WeakSet_UserEntity::next)
   * Address: 0x007B30D0 (FUN_007B30D0, std::map<unsigned int,WeakPtr<UserEntity>>::erase
   * — identical node-splice/rebalance/return-next shape, a separate
   * per-call-site emission of the same std::_Tree::erase(iterator) operation)
   *
   * What it does:
   * Erases one `UserEntity` weak-set node from a selection RB-tree, unlinks
   * its intrusive weak-owner chain lane, and returns the next in-order node.
   * Declared here (moved to external linkage from its original CWldSession.cpp
   * anonymous namespace) so `CFormation::ChooseFormation` (CFormation.cpp) can
   * prune its own selection-set walk exactly as `SSelectionSetUserEntity::
   * PruneTombstonesAndFindLive`/`EraseRange` do in this file.
   */
  [[nodiscard]] SSelectionNodeUserEntity*
    EraseSelectionNodeAndAdvance(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* node);

  /**
   * Address: 0x007B29C0 (FUN_007B29C0, sub_7B29C0)
   *
   * What it does:
   * Advances from `start` to the first live weak-set node, deleting tombstone
   * entries (null/`(void*)8` owner-link slots) as it goes. Generalized over the
   * shared `WeakEntitySetUserEntity` base (moved to external linkage from
   * `SSelectionSetUserEntity::PruneTombstonesAndFindLive`, which now forwards
   * here) so `CFormation::Finalize` (CFormation.cpp) can prune its own
   * `mParticipants` walk the same way: `mParticipants` is a `WeakUnitSetUserUnit`,
   * not an `SSelectionSetUserEntity`, but both share the identical 12-byte
   * `{allocProxy, mHead, mSize}` header this function only ever touches, and the
   * binary itself calls this exact routine (0x00838313/0x008383CC) with `this`
   * pointed straight at `CFormation::mParticipants` (offset 0 of `CFormation`).
   */
  [[nodiscard]] SSelectionNodeUserEntity** PruneTombstonesAndFindLive(
    WeakEntitySetUserEntity& set,
    SSelectionNodeUserEntity** outNode,
    SSelectionNodeUserEntity* start
  );

  /**
   * Address context:
   * - process-global world-frame action lane (`sWldFrameAction`) consumed by
   *   `WLD_Frame`.
   */
  [[nodiscard]] EWldFrameAction WLD_GetFrameAction();

  /**
   * Address: 0x0088BD20 (FUN_0088BD20, ?WLD_SetUIProvider@Moho@@YAXPAVIWldUIProvider@1@@Z)
   *
   * What it does:
   * Replaces the process-global world-UI provider ownership lane, deleting the
   * previous provider when it differs from the new one.
   */
  void WLD_SetUIProvider(IWldUIProvider* provider);

  /**
   * Address context:
   * - process-global world-frame action lane (`sWldFrameAction`) consumed by
   *   `WLD_Frame`.
   */
  void WLD_SetFrameAction(EWldFrameAction action);

  /**
   * Address: 0x0088CAE0 (FUN_0088CAE0, ?WLD_Frame@Moho@@YA_NM@Z)
   *
   * What it does:
   * Dispatches world-frame state transitions and per-state frame handlers.
   */
  [[nodiscard]] bool WLD_Frame(float deltaSeconds);

  /**
   * Address: 0x0088BEA0 (FUN_0088BEA0, ?WLD_RequestEndSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session exit when frame dispatch is currently active.
   */
  void WLD_RequestEndSession();

  /**
   * Address: 0x0088E6F0 (FUN_0088E6F0)
   *
   * What it does:
   * Console-command callback that requests world-session exit when frame
   * dispatch is currently active.
   */
  void CON_WLD_RequestEndSession(void* commandArgs);

  /**
   * Address: 0x0088BE80 (FUN_0088BE80, ?WLD_IsSessionActive@Moho@@YA_NXZ)
   *
   * What it does:
   * Returns whether world-frame dispatch is active (`!= Inactive`).
   */
  [[nodiscard]] bool WLD_IsSessionActive();

  /**
   * Address: 0x0088BE90 (FUN_0088BE90, world-frame playing-state probe)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently in the `Playing` state.
   */
  [[nodiscard]] bool WLD_IsSessionPlaying();

  /**
   * Address: 0x0088BEC0 (FUN_0088BEC0, ?WLD_RequestRestartSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session recreation when frame dispatch is active and the
   * active session carries restart launch info.
   */
  void WLD_RequestRestartSession();

  /**
   * Address: 0x00869810 (FUN_00869810, func_WldSessionLoader_GetOnTeardownCallbacks)
   *
   * What it does:
   * Lazily initializes and returns the process-global world-teardown callback
   * vector used by session-loader teardown paths.
   */
  [[nodiscard]] WldTeardownCallbackVector* WLD_GetOnTeardownCallbacks();

  /**
   * Address: 0x008699A0 (FUN_008699A0)
   *
   * What it does:
   * Resolves the process-global teardown-callback vector and dispatches each
   * registered callback against the active world session. Called during the
   * loading-to-playing handover in `WLD_DoInitializing` (0x0088C3F0).
   */
  [[nodiscard]] std::int32_t WLD_DispatchOnTeardownCallbacksCoreFromGlobalList();

  /**
   * Address: 0x00869950 (FUN_00869950)
   *
   * What it does:
   * Appends one teardown-callback pointer to the process-global teardown
   * callback vector, growing vector storage when needed.
   */
  [[nodiscard]] WldTeardownCallbackVector* WLD_AddOnTeardownCallback(IWldTeardownCallback* callback);

  /**
   * Address: 0x0088C860 (FUN_0088C860, ?WLD_Teardown@Moho@@YAXXZ)
   *
   * What it does:
   * Tears down world-session runtime ownership and returns frame action to
   * `Inactive`.
   */
  void WLD_Teardown();

  /**
   * Address: 0x0088BD40 (FUN_0088BD40, ?WLD_LoadScenarioInfo@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@3@@Z)
   *
   * What it does:
   * Executes `dataInit.lua` plus scenario script into one environment table and returns `ScenarioInfo`.
   */
  [[nodiscard]] LuaPlus::LuaObject WLD_LoadScenarioInfo(const msvc8::string& scenarioFile, LuaPlus::LuaState* state);

  /**
   * Address: 0x00897220 (FUN_00897220, ?WLD_CreateSession@Moho@@YAPAVCWldSession@1@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@4@AAV?$auto_ptr@VCWldMap@Moho@@@4@AAUSWldSessionInfo@1@@Z)
   *
   * What it does:
   * Allocates one world-session object, constructs it from transferred
   * auto_ptr lanes, and updates the global active-session pointer.
   */
  [[nodiscard]] CWldSession* WLD_CreateSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& gameRules,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  );

  /**
   * Address: 0x008972A0 (FUN_008972A0, ?WLD_DestroySession@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys the active world-session object when present and clears the
   * process-global active-session pointer.
   */
  void WLD_DestroySession();

  /**
   * Address: 0x008972F0 (FUN_008972F0, ?WLD_GetSession@Moho@@YAPAVCWldSession@1@XZ)
   *
   * What it does:
   * Returns the process-global active world-session pointer.
   */
  [[nodiscard]] CWldSession* WLD_GetSession();

  /**
   * Address: 0x0088D060 (FUN_0088D060, ?WLD_BeginSession@Moho@@YAXV?$auto_ptr@USWldSessionInfo@Moho@@@std@@@Z)
   *
   * What it does:
   * Replaces pending world-session bootstrap info and schedules preload.
   */
  void WLD_BeginSession(msvc8::auto_ptr<SWldSessionInfo> sessionInfo);

  /**
   * Address: 0x0088D0B0 (FUN_0088D0B0, ?WLD_GetSimRate@Moho@@YAMXZ)
   *
   * What it does:
   * Returns current world sim-rate scale based on client-requested rate and
   * skew-rate adjustment limits.
   */
  [[nodiscard]] float WLD_GetSimRate();

  /**
   * Address: 0x0088D170 (FUN_0088D170, session sim-rate permission probe)
   *
   * What it does:
   * Returns whether the active session context may issue local sim-rate
   * changes (`replay`, focused local army, or non-multiplayer).
   */
  [[nodiscard]] bool WLD_CanAdjustSimRate();

  /**
   * Address: 0x0088D1B0 (FUN_0088D1B0, ?WLD_IncreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Raises requested sim rate by one step (up to +50) for authorized local
   * session contexts.
   */
  void WLD_IncreaseSimRate();

  /**
   * Address: 0x0088D220 (FUN_0088D220, ?WLD_ResetSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Resets requested sim rate back to neutral (`0`) for authorized local
   * session contexts.
   */
  void WLD_ResetSimRate();

  /**
   * Address: 0x0088D280 (FUN_0088D280, ?WLD_DecreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Lowers requested sim rate by one step (down to `-10`) for authorized
   * local session contexts.
   */
  void WLD_DecreaseSimRate();

  /**
   * Address: 0x0088D2F0 (FUN_0088D2F0, ?WLD_SetGameSpeed@Moho@@YAXH@Z)
   *
   * What it does:
   * Clamps one requested game-speed lane to `[-10, 10]` and forwards it to the
   * active client manager when a sim driver is available.
   */
  void WLD_SetGameSpeed(int gameSpeed);

  /**
   * Address: 0x0088D330 (FUN_0088D330, ?WLD_GetDriver@Moho@@YAPAVISTIDriver@1@XZ)
   *
   * What it does:
   * Returns the process-global active sim-driver pointer.
   */
  [[nodiscard]] ISTIDriver* WLD_GetDriver();

  /**
   * Process-global selection cheat toggle (`0x010A645E`). When set (with cheats
   * enabled) unit selection ignores focus-army ownership.
   */
  extern bool UI_SelectAnything;

  extern float UI_StrategicProjectileLOD;  // 0x00F57B20
  // Gates the mass/hydro resource splats CRenderWorldView::Render draws through
  // CWldSession::RenderResources (tested at 0x0086EE31). Ships enabled.
  extern bool UI_RenResources;             // 0x00F57A8E
  extern bool UI_RenProjectileIcons;       // 0x00F57A8F
  extern bool UI_RenProjectileGlow;        // 0x00F57B24
  extern bool UI_forceWeaponsToYellow;     // 0x00F57B25
  extern float UI_RenProjectileGlowMin;    // 0x00F57B28
  extern float UI_RenProjectileGlowMax;    // 0x00F57B2C
  extern float UI_RenProjectileGlowPeriod; // 0x00F57B30
  extern float UI_CurGlowTime;             // 0x010A6460

  /**
   * Strategic-view LOD cutoff for the mass/hydrocarbon resource splats,
   * compared against the camera viewport matrix's row-1 depth of each deposit
   * centre by `CWldSession::RenderResources` (0x00862E68). Bound to the
   * console by `func_UI_ResourceLODCutoff_ConVarDef` (0x00BE6010); ships at 75.
   */
  extern float UI_ResourceLODCutoff; // 0x00F57B08

  /**
   * Strategic-icon and unit-bar console variables, read by the strategic-icon
   * pass (`CWldSession::RenderStrategicIcons` 0x0085B6E0 and the four emitters
   * it drives: the lifebar/fuel/shield bar stack at 0x0085CD40, the icon quad
   * stack at 0x0085D9A0, the custom-name label at 0x0085E0A0 and the
   * selection-set label at 0x0085E3A0).
   *
   * Every address is the absolute operand of the instruction that reads the
   * variable; the reading instruction's address is in the matching definition
   * comment in CWldSession.cpp. `ui_LifebarOffset` is spelled exactly as the
   * binary mangles it (`?ui_LifebarOffset@Moho@@3MA`) - lower-case `b`,
   * unlike the `ui_LifeBar*` colour/cutoff family next to it.
   */
  extern bool ui_RenderUnitBars;               // 0x00F57B26
  extern bool ui_RenderIcons;                  // 0x00F57B27
  extern float ui_lifebarHeight;               // 0x00F57B6C
  extern float ui_LifebarWidth;                // 0x00F57B70
  extern float ui_LifebarLOD;                  // 0x00F57B74
  extern float ui_LifebarOffset;               // 0x00F57B78
  extern bool ui_NisRenderIcons;               // 0x00F57B7C
  extern bool ui_RenderCustomNames;            // 0x00F57B7D
  extern bool ui_RenderSelectionSetNames;      // 0x00F57B7E
  extern std::uint32_t ui_CustomNameColor;     // 0x00F57B80
  extern std::int32_t ui_CustomNameFontSize;   // 0x00F57B84
  extern std::uint32_t ui_SelectionSetNamesColor; // 0x00F57B88
  extern float ui_StrategicIconBlinkRate;      // 0x00F57B8C
  extern float ui_FuelEmptyBlinkRate;          // 0x00F57B90
  extern float ui_StrategicIconBlinkDuration;  // 0x00F57B94
  extern std::uint32_t ui_LifeBarGoodColor;    // 0x00F57B98
  extern std::uint32_t ui_LifeBarMedColor;     // 0x00F57B9C
  extern std::uint32_t ui_LifeBarBadColor;     // 0x00F57BA0
  extern float ui_LifeBarGoodCutoff;           // 0x00F57BA4
  extern float ui_LifeBarBadCutoff;            // 0x00F57BA8
  extern std::uint32_t ui_FuelBarColor;        // 0x00F57BAC
  extern std::uint32_t ui_FuelWarningColor;    // 0x00F57BB0
  extern std::uint32_t ui_ShieldBarColor;      // 0x00F57BB4
  extern std::uint32_t ui_ProgressBarColor;    // 0x00F57BB8
  extern msvc8::string ui_CustomNameFont;      // 0x00F5B300
  extern bool ui_ForceLifbarsOnEnemy;          // 0x010A644A
  extern bool ui_AlwaysRenderStrategicIcons;   // 0x010A644B

  /**
   * Debug toggle gating `UICommandGraph::DrawCommandGraphMesh`'s path-preview
   * pass (`?ui_DrawPathPreview@Moho@@3_NA` 0x010A6443). Lies in the same
   * zero-filled `.data` tail as `UI_SelectAnything`/`UI_CurGlowTime` with no
   * file-backed initializer, so it ships off.
   */
  extern bool ui_DrawPathPreview;          // 0x010A6443

  /**
   * Switches `DrawPathPreview` between its two source paths: the
   * RDP-simplified world path sampled from the previewed army's runtime
   * cell-position scratch buffer (on) versus a straight two-point line from
   * the cursor to the deepest selected unit (off). A distinct global from
   * `ui_DrawPathPreview` above - same zero-filled `.data` tail, same
   * ships-off default (`?ui_PathPreview@Moho@@3_NA` 0x010A6448).
   */
  extern bool ui_PathPreview;              // 0x010A6448


  /**
   * Command-waypoint drawing parameters, imported from
   * `/lua/ui/game/commandwaypoint.lua` by `UICommandGraph::LoadWaypointParams`
   * and read by the command-graph draw pass.
   *
   * Addresses: `?ui_CurveSegments@Moho@@3HA` 0x00F57CC0,
   * `?ui_CurveSmoothness@Moho@@3MA` 0x00F57CC4,
   * `?ui_PathSmoothness@Moho@@3MA` 0x00F57CC8,
   * `?ui_MaxTextLOD@Moho@@3MA` 0x00F57CCC,
   * `?ui_CommandGraphMaxNodeUnits@Moho@@3HA` 0x00F57CD0,
   * `?ui_MinWaypointSize@Moho@@3MA` 0x00F57CD4,
   * `?ui_MaxWaypointSize@Moho@@3MA` 0x00F57CD8,
   * `?ui_WaypointLineScale@Moho@@3MA` 0x00F57CDC.
   */
  extern std::int32_t ui_CurveSegments;
  extern float ui_CurveSmoothness;
  extern float ui_PathSmoothness;
  extern float ui_MaxTextLOD;
  extern std::int32_t ui_CommandGraphMaxNodeUnits;
  extern float ui_MinWaypointSize;
  extern float ui_MaxWaypointSize;
  extern float ui_WaypointLineScale;

  /**
   * Not a distinct binary function - promotes the file-private
   * `ResolveCommandGraphAnchorHistoryWorldPosition` (= FUN_0081CFD0) for
   * cross-TU callers (the command-graph render pass in
   * `CRenderWorldView.cpp`). Resolves one command's fallback world-space
   * anchor: the latest build-position sample in its command-graph history,
   * or the history's cached default sample when none exists.
   */
  [[nodiscard]] Wm3::Vector3f ResolveCommandGraphAnchorWorldPosition(UserCommandIssueHelper& helper) noexcept;

  /**
   * Address: 0x00827A00 (FUN_00827A00, sub_827A00)
   *
   * Defined in CRenderWorldView.cpp (a free function, not a UICommandGraph
   * member - it has two independent callers, `UICommandGraph::
   * DrawCommandOrderline` and `Moho::DrawPathPreview`). See that definition
   * for the full doc comment.
   */
  void EmitHermiteRibbonSegments(
    CD3DPrimBatcher& batcher, const Wm3::Vector3f& p0, const Wm3::Vector3f& p1, const Wm3::Vector3f& t0,
    const Wm3::Vector3f& t1, float width, std::uint32_t color, float uStart, float aspectRatio
  );

  /**
   * Address: 0x0082A380 (FUN_0082A380, Moho::DrawPathPreview)
   *
   * Defined in CWldSession.cpp, not CRenderWorldView.cpp: it reads
   * `UICommandGraph::mSession`/`mNodes` directly, and `UICommandGraph` is
   * only a complete type here (see `ResolveCommandGraphAnchorWorldPosition`
   * above) - a free function, `__stdcall`, no `this` in the strict sense,
   * but the IDA-declared first parameter, shown as a literal `-1` at the
   * sole call site, is a decompiler artifact: every real read of it inside
   * the body is `this->mSession`/`this->mNodes[...]` at the exact offsets
   * `UICommandGraph::mSession`/`mNodes` already occupy, so it is genuinely
   * `UICommandGraph* this` passed as an explicit reference here (declared a
   * `friend` of `UICommandGraph` for that access). Sole caller is
   * `UICommandGraph::DrawCommandGraphMesh`, gated by `ui_DrawPathPreview`.
   * Draws the active move-command's path-preview ribbon overlay.
   */
  void DrawPathPreview(
    UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction
  );

  /**
   * Address: 0x00829B40 (FUN_00829B40, func_ProcessCommandDrag)
   *
   * Defined in CWldSession.cpp, not UiRuntimeTypes.cpp: like `DrawPathPreview`
   * above, it reads `UICommandGraph::mSession`/`mMapAB0` directly and
   * `UICommandGraph` is only a complete type here (declared a `friend` of
   * `UICommandGraph` for that access). Callers are `Moho::UICommandDragger::
   * DragMove`/`DragRelease` (UiRuntimeTypes.h/.cpp), which only ever see
   * `UICommandGraph` as an opaque pointer they forward through. See the
   * definition for the full doc comment (draw-node hash update, build-
   * placement re-validation, and the three-way target dispatch on release).
   */
  void ProcessCommandDrag(const Wm3::Vector3f& mouse, UICommandGraph& graph, CmdId cmdId, bool released);

  /**
   * Address: 0x0082A120 (FUN_0082A120, sub_82A120)
   *
   * Defined in CRenderWorldView.cpp (a free function, not a UICommandGraph
   * member). Sole caller is `DrawPathPreview` above. See that definition for
   * the full doc comment.
   */
  void SimplifyPathSpan(
    const msvc8::vector<Wm3::Vector3f>& points, std::int32_t first, std::int32_t last,
    msvc8::list<Wm3::Vector3f>& simplified, msvc8::list<Wm3::Vector3f>::iterator insertBefore, float tolerance
  );

  /**
   * Address: 0x0082A2B0 (FUN_0082A2B0, sub_82A2B0)
   *
   * Defined in CRenderWorldView.cpp (a free function, not a UICommandGraph
   * member). Sole caller is `DrawPathPreview` above. See that definition for
   * the full doc comment.
   */
  [[nodiscard]] UserUnit* PickPathPreviewSubject(SSelectionSetUserEntity& selection);

  /**
   * Not a distinct binary function - `UICommandGraph` is only a complete
   * type in CWldSession.cpp (see `ResolveCommandGraphAnchorWorldPosition`
   * above), so `CRenderWorldView::RenderCommandGraph` (CRenderWorldView.cpp)
   * calls `UICommandGraph::DrawCommandGraphMesh` through this wrapper rather
   * than on the bare `UICommandGraph*` it holds, which is incomplete there.
   * No-ops when `graph` is null.
   */
  void DrawCommandGraphMeshIfPresent(
    UICommandGraph* graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction
  );

  /**
   * Not a distinct binary function - `UICommandGraph` is only a complete
   * type in CWldSession.cpp (see `DrawCommandGraphMeshIfPresent` above), so
   * `Moho::CUIWorldView::UpdateSelection` (UiRuntimeTypes.cpp) calls
   * `UICommandGraph::ResolveCursorHighlightCommandId` through this wrapper
   * rather than on the bare `UICommandGraph*` its `mComGraph` holds, which is
   * incomplete there. Returns -1 (no highlighted command) when `graph` is
   * null.
   */
  [[nodiscard]] CmdId ResolveCommandGraphCursorHighlightIfPresent(
    UICommandGraph* graph, const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  );

  /**
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   *
   * What it does:
   * Returns the current active world-session pointer, or nullptr.
   */
  [[nodiscard]] CWldSession* WLD_GetActiveSession();
} // namespace moho
