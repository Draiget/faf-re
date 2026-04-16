#pragma once
#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "CArmyImpl.h"
#include "gpg/core/containers/IntrusiveLink.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "lua/LuaObject.h"
#include "moho/misc/VisionDb.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/VisibilityRect.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/task/CTaskThread.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  using EntId = std::int32_t;

  class UserArmy;
  class UserUnit;
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
  struct SBuildTemplateInfo;
  struct GeomCamera3;

  struct SBuildTemplateBuffer
  {
    SBuildTemplateInfo* mStart;         // +0x00
    SBuildTemplateInfo* mFinish;        // +0x04
    SBuildTemplateInfo* mCapacity;      // +0x08
    SBuildTemplateInfo* mOriginalStart; // +0x0C
    std::uint8_t mInlineStorage[0x2C0]; // +0x10 (16 * sizeof(SBuildTemplateInfo), 0x2C each)
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

    ECommandMode mMode;
    ERuleBPUnitCommandCaps mCommandCaps;
    void* mBlueprint;
    MouseInfo mMouseDragStart;
    MouseInfo mMouseDragEnd;
    std::int32_t mModifiers;
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

  struct SSelectionWeakRefUserEntity
  {
    void* mOwnerLinkSlot;                    // +0x00
    SSelectionWeakRefUserEntity* mNextOwner; // +0x04
  };

  static_assert(sizeof(SSelectionWeakRefUserEntity) == 0x08, "SSelectionWeakRefUserEntity size must be 0x08");
  static_assert(
    offsetof(SSelectionWeakRefUserEntity, mOwnerLinkSlot) == 0x00,
    "SSelectionWeakRefUserEntity::mOwnerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(SSelectionWeakRefUserEntity, mNextOwner) == 0x04,
    "SSelectionWeakRefUserEntity::mNextOwner offset must be 0x04"
  );

  struct SSelectionNodeUserEntity
  {
    SSelectionNodeUserEntity* mLeft;   // +0x00
    SSelectionNodeUserEntity* mParent; // +0x04
    SSelectionNodeUserEntity* mRight;  // +0x08
    std::uint32_t mKey;                // +0x0C
    SSelectionWeakRefUserEntity mEnt;  // +0x10
    std::uint8_t mColor;               // +0x18
    std::uint8_t mIsSentinel;          // +0x19
    std::uint8_t pad_1A[2];
  };

  static_assert(sizeof(SSelectionNodeUserEntity) == 0x1C, "SSelectionNodeUserEntity size must be 0x1C");
  static_assert(
    offsetof(SSelectionNodeUserEntity, mEnt) == 0x10, "SSelectionNodeUserEntity::mEnt offset must be 0x10"
  );
  static_assert(
    offsetof(SSelectionNodeUserEntity, mIsSentinel) == 0x19,
    "SSelectionNodeUserEntity::mIsSentinel offset must be 0x19"
  );

  struct SSelectionSetUserEntity
  {
    void* mAllocProxy;                 // +0x00
    SSelectionNodeUserEntity* mHead;   // +0x04
    std::uint32_t mSize;               // +0x08
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
     * Address: 0x007AF740 (FUN_007AF740, sub_7AF740)
     *
     * What it does:
     * Erases one half-open weak-set node range `[first,last)`. When the range
     * is the full tree, it tears down the entire subtree in one pass and resets
     * head links/size to the empty-state sentinel shape.
     */
    [[nodiscard]] SSelectionNodeUserEntity**
      EraseRange(SSelectionNodeUserEntity** outNode, SSelectionNodeUserEntity* first, SSelectionNodeUserEntity* last);

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

  private:
    /**
     * Address: 0x007B0870 (FUN_007B0870, sub_7B0870)
     *
     * What it does:
     * Recursively destroys one weak-set subtree and unlinks each node from its
     * user-entity weak-owner intrusive lane before delete.
     */
    void DestroySubtree(SSelectionNodeUserEntity* node);
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
     * What it does:
     * Draws command-link splats/quads between selected units and their command targets.
     */
    void DrawCommandSplats();

    /**
     * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
     *
     * What it does:
     * Builds/updates transient formation preview mesh instances.
     */
    void RenderMeshPreviews();

    /**
     * Address: 0x0085B6E0 (FUN_0085B6E0,
     * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
     *
     * What it does:
     * Classifies visible units and renders strategic icons, overlays, and lifebars.
     */
    void RenderStrategicIcons(CameraImpl* camera, CD3DPrimBatcher* primBatcher, CWldMap* map);

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

  public:
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
     * Address: 0x00895F70 (FUN_00895F70, ?DirtyCommandGraph@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Locks the cached UI command-graph weak handle, marks it dirty when
     * present, and releases the temporary shared hold.
     */
    void DirtyCommandGraph();

  private:
    /**
     * Address: 0x00895EB0 (FUN_00895EB0,
     * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
     *
     * What it does:
     * Locks/returns cached command-graph weak handle and optionally creates it.
     */
    [[nodiscard]] boost::SharedPtrRaw<UICommandGraph> GetCommandGraph(bool allowCreate);

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
    void* mSessionRes1;                                     // 0x03FC
    CFormation* mCurFormation;                              // 0x0400
    UICommandGraph* mUICommandGraphPx;                      // 0x0404
    boost::detail::sp_counted_base* mUICommandGraphControl; // 0x0408 (weak control block for mUICommandGraphPx)
    boost::SharedPtrRaw<void> mUnknownShared40C;            // 0x040C
    boost::SharedPtrRaw<CDebugCanvas> mDebugCanvas;         // 0x0414
    boost::SharedPtrRaw<void> mUnknownShared41C;            // 0x041C
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
    char pad_048D[19];                                      // 0x048D
    SSelectionSetUserEntity mSelection;                     // 0x04A0
    std::uint8_t mCursorWorldState[4];                      // 0x04B0
    Wm3::Vector3f CursorWorldPos;                           // 0x04B4
    char pad_04C0[8];                                       // 0x04C0
    int32_t HighlightCommandId;                             // 0x04C8
    Wm3::Vector2f CursorScreenPos;                          // 0x04CC
    bool IsCheatsEnabled;                                   // 0x04D4
    char pad_04D5[3];                                       // 0x04D5
    msvc8::vector<msvc8::string> mOverlayFilters;           // 0x04D8
    bool DisplayEconomyOverlay;                             // 0x04E8
    bool mTeamColorMode;                                    // 0x04E9
    char pad_04EA[2];                                       // 0x04EA
    gpg::MemBuffer<char> mEdgeFog;                          // 0x04EC
    char pad_04FC[12];                                      // 0x04FC
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
    offsetof(CWldSession, mOverlayFilters) == 0x4D8, "CWldSession::mOverlayFilters offset must be 0x4D8"
  );
  static_assert(offsetof(CWldSession, mEdgeFog) == 0x4EC, "CWldSession::mEdgeFog offset must be 0x4EC");

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
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   *
   * What it does:
   * Returns the current active world-session pointer, or nullptr.
   */
  [[nodiscard]] CWldSession* WLD_GetActiveSession();
} // namespace moho
