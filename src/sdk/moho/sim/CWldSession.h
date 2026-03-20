#pragma once
#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "CArmyImpl.h"
#include "gpg/core/containers/IntrusiveLink.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/misc/VisionDb.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/VisibilityRect.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/task/CTaskThread.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  class UserArmy;
  class EntityCategoryLookupResolver;
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

  enum ERuleBPUnitCommandCaps : std::int32_t
  {
    RULEUCC_None = 0,
    RULEUCC_Transport = 1,
    RULEUCC_CallTransport = 2,
  };

  struct CommandModeData
  {
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

  struct SSessionSaveData
  {
    SSessionSaveNodeMap mNodeMap; // +0x00

    /**
     * Address: 0x00896F00 init path (FUN_00896F00 -> sub_89A930).
     *
     * What it does:
     * Initializes save-data RB-tree header node and resets map size.
     */
    SSessionSaveData();

    /**
     * Address: 0x008971A0 cleanup path (FUN_008971A0 + sub_89AC40).
     *
     * What it does:
     * Releases all map nodes and their string payloads.
     */
    ~SSessionSaveData();

    /**
     * Address: 0x008992D0/0x00899DC0/0x0089A970 helper chain.
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
     * Address: 0x008B9580 callsite through session->mWldMap->mTerrainRes.
     *
     * What it does:
     * Reads terrain playable-bounds rectangle used by user-entity visibility checks.
     */
    [[nodiscard]] bool TryGetPlayableMapRect(VisibilityRect& outRect) const;

    /**
     * Address: 0x008B9580 callsite (focus army lookup path).
     *
     * What it does:
     * Returns the currently focused user army, or nullptr for invalid focus.
     */
    [[nodiscard]] UserArmy* GetFocusUserArmy();
    [[nodiscard]] const UserArmy* GetFocusUserArmy() const;

    /**
     * Address: 0x008B97C0/0x008621B0 callsites (rule category lookup path).
     *
     * What it does:
     * Returns typed category resolver interface for `rules`.
     */
    [[nodiscard]] EntityCategoryLookupResolver* GetCategoryLookupResolver();
    [[nodiscard]] const EntityCategoryLookupResolver* GetCategoryLookupResolver() const;

    /**
     * Address: 0x008B85E0 callsite (UserEntity ctor, sub_501A80 path).
     *
     * What it does:
     * Returns storage root used as SpatialDB_MeshInstance owner for user-entity DB entries.
     */
    [[nodiscard]] void* GetEntitySpatialDbStorage();
    [[nodiscard]] const void* GetEntitySpatialDbStorage() const;

    /**
     * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
     *
     * What it does:
     * Removes an entity from the world-session viz-update RB-tree.
     */
    void RemoveFromVizUpdate(UserEntity* entity);

    /**
     * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
     *
     * What it does:
     * Runs one world-session frame: Lua rules update, sync beat drain, command-graph
     * mesh build, and task-stage user frame.
     */
    void SessionFrame(float deltaSeconds);

    /**
     * Address: 0x00896F00 (FUN_00896F00,
     * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
     *
     * What it does:
     * Builds a save-data snapshot for current world-session entities.
     */
    [[nodiscard]] boost::shared_ptr<SSessionSaveData> GetSaveData() const;

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

  private:
    /**
     * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
     *
     * What it does:
     * Releases build-template entry strings, resets inline storage pointers,
     * and clears template placement args.
     */
    void ClearBuildTemplates();

    /**
     * Address: 0x00895EB0 (FUN_00895EB0,
     * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
     *
     * What it does:
     * Locks/returns cached command-graph weak handle and optionally creates it.
     */
    [[nodiscard]] boost::SharedPtrRaw<UICommandGraph> GetCommandGraph(bool allowCreate);

  public:
    gpg::core::IntrusiveLink<CWldSession*> head0;
    gpg::core::IntrusiveLink<CWldSession*> head1;

    LuaPlus::LuaState* mState;                              // 0x0010
    CTaskStage* mCurThread;                                 // 0x0014
    RRuleGameRulesImpl* mRules;                             // 0x0018
    CWldMap* mWldMap;                                       // 0x001C
    uint32_t mCanRestart;                                   // 0x0020
    void* mUnknownOwnerToken24;                             // 0x0024
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
    int32_t GameTimeSeconds;                                // 0x0458
    int32_t IsRunning;                                      // 0x045C
    float GameTimeMilliSeconds;                             // 0x0460
    uint8_t IsPaused;                                       // 0x0464
    uint8_t N00001903;                                      // 0x0465
    uint8_t IsPausedB;                                      // 0x0466
    char pad_0467[5];                                       // 0x0467
    uint8_t N0000315B;                                      // 0x046C
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
    void* selectedUnitUnknownPtr1;                          // 0x04A0
    void* selectedUnitListPtr;                              // 0x04A4
    int32_t selectedUnitCount1;                             // 0x04A8
    int32_t selectedUnitCount2;                             // 0x04AC
    char pad_04B0[4];                                       // 0x04B0
    Wm3::Vector3f CursorWorldPos;                           // 0x04B4
    char pad_04C0[8];                                       // 0x04C0
    int32_t HighlightCommandId;                             // 0x04C8
    Wm3::Vector2f CursorScreenPos;                          // 0x04CC
    bool IsCheatsEnabled;                                   // 0x04D4
    char pad_04D5[19];                                      // 0x04D5
    bool DisplayEconomyOverlay;                             // 0x04E8
    bool mTeamColorMode;                                    // 0x04E9
    char pad_04EA[30];                                      // 0x04EA
  };

  static_assert(sizeof(CWldSession) == 0x508, "CWldSession size must be 0x508");
  static_assert(offsetof(CWldSession, mWldMap) == 0x1C, "CWldSession::mWldMap offset must be 0x1C");
  static_assert(
    offsetof(CWldSession, mSaveSourceTreeHead) == 0x48, "CWldSession::mSaveSourceTreeHead offset must be 0x48"
  );
  static_assert(
    offsetof(CWldSession, mEntitySpatialDbStorage) == 0x50, "CWldSession::mEntitySpatialDbStorage offset must be 0x50"
  );
  static_assert(offsetof(CWldSession, mBuildTemplates) == 0xF0, "CWldSession::mBuildTemplates offset must be 0xF0");
  static_assert(
    offsetof(CWldSession, mBuildTemplateArg1) == 0x3C0, "CWldSession::mBuildTemplateArg1 offset must be 0x3C0"
  );
  static_assert(offsetof(CWldSession, mVizUpdateRoot) == 0x438, "CWldSession::mVizUpdateRoot offset must be 0x438");
  static_assert(offsetof(CWldSession, mScenarioInfo) == 0x444, "CWldSession::mScenarioInfo offset must be 0x444");
  static_assert(offsetof(CWldSession, FocusArmy) == 0x488, "CWldSession::FocusArmy offset must be 0x488");
} // namespace moho
