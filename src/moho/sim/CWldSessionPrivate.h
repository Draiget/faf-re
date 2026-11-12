#pragma once

// Private to moho/sim: helpers the pieces of the former CWldSession.cpp share.

#include "moho/sim/WldSessionState.h"
#include "CWldSession.h"

#include "platform/shell/Shell.h"
#include "platform/shell/app.h"

#include "legacy/algorithms/Sort.h"
#include "legacy/containers/HashMap.h"
#include "legacy/math/X87Math.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/RenderProfiler.h"
#include "moho/render/ProjectileIconRenderer.h"
#include "moho/render/StrategicIconClassifyShader.h"
#include "moho/render/StrategicIconRenderer.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/BVSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/animation/CAniPose.h"
#include "moho/mesh/Mesh.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/command/CommandManager.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientManager.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/resource/RResId.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/app/UserWorkerPool.h"
#include "lua/LuaTableIterator.h"
#include "moho/sim/CArmyLuaFunctionRegistrations.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EGenericIconTypeTypeInfo.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/sim/DesyncRecorder.h"
#include "moho/sim/SDesyncInfo.h"
#include "moho/misc/TimeBar.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/RCamManager.h"
#include "moho/render/WRenViewport.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CFormation.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/client/Localization.h"
#include "moho/misc/SessionStartup.h"
#include "moho/sim/ReplayTimeline.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/PauseListener.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SSelectionEvent.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/ESTITargetTypeTypeInfo.h"
#include "moho/sim/UserArmy.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/ui/CUIManager.h"
#include "moho/unit/core/EFireStateTypeInfo.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/math/MathReflection.h"
#include "moho/unit/core/IUnit.h"
#include "moho/ui/IUIManager.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "moho/sim/Sim.h"
#if FAF_SERVER_MODE
#include "remote/client/NetworkSimDriver.h"
#include "remote/client/RemoteSimDriver.h"
#include "remote/client/SessionSummary.h"
#endif

/**
 * One formation-placement ghost: the preview mesh `MeshRenderer` handed back
 * and the "UnitFormationPreview" material it was shaded with.
 *
 * The implicit destructor is the binary's FUN_00859E90 - it drops the
 * last-declared member first (`mMaterial`, then `mMesh`), which is exactly
 * what MSVC emits for this member order. No source line spells it out.
 */
struct SFormationPreviewGhost
{
  boost::shared_ptr<moho::MeshInstance> mMesh;     // +0x00
  boost::shared_ptr<moho::MeshMaterial> mMaterial; // +0x08
};
static_assert(sizeof(SFormationPreviewGhost) == 0x10, "SFormationPreviewGhost size must be 0x10");
extern fa::vector<SFormationPreviewGhost> gFormationPreviews;
namespace moho
{
  /** Engine addition (replay timeline): a new sim is on its way behind the session, which takes no beats until then. */
  [[nodiscard]] bool WLD_IsReplaySimSwapping();

  extern std::uint64_t gUserSyncBeats;

  struct UICommandGraphNode
  {
    boost::SharedPtrRaw<void> mOrderlineTexture{}; // +0x00 (shared `(px,pi)` pair)
    float mOrderlineAspectRatio = 0.0f;            // +0x08
    float mOrderlineAnimRate = 0.0f;               // +0x0C
    std::uint32_t mOrderlineColor = 0;             // +0x10
    std::uint32_t mOrderlineSelectedColor = 0;     // +0x14
    std::uint32_t mOrderlineHighlightColor = 0;    // +0x18
    float mOrderlineGlow = 0.0f;                   // +0x1C
    float mOrderlineSelectedGlow = 0.0f;           // +0x20
    float mOrderlineHighlightGlow = 0.0f;          // +0x24
    std::uint32_t mWaypointColor = 0;              // +0x28
    std::uint32_t mWaypointSelectedColor = 0;      // +0x2C
    std::uint32_t mWaypointHighlightColor = 0;     // +0x30
    float mWaypointScale = 0.0f;                   // +0x34
    float mWaypointSelectedScale = 0.0f;           // +0x38
    float mWaypointHighlightScale = 0.0f;          // +0x3C
    float mArrowheadCapOffset = 0.0f;              // +0x40
    boost::SharedPtrRaw<void> mWaypointTexture{};  // +0x44 (shared `(px,pi)` pair)
    boost::SharedPtrRaw<void> mArrowheadTexture{}; // +0x4C (shared `(px,pi)` pair)

    /**
     * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one command-graph node style payload with default
     * orderline/waypoint scales and cleared texture shared pointers.
     */
    UICommandGraphNode();

    /**
     * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Releases command-graph texture shared-control lanes in arrowhead,
     * waypoint, then orderline teardown order.
     */
    ~UICommandGraphNode();

    /**
     * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
     *
     * What it does:
     * Copies one command-graph style node payload, including shared-texture
     * control lanes for orderline/waypoint/arrowhead textures. Each lane is a
     * strong retain-then-release rebind through FUN_004229B0
     * (`sp_counted_base::release()`, see BoostWrappers.h) - see the definition
     * for the 2026-08-20 audit note.
     */
    UICommandGraphNode* CopyFrom(const UICommandGraphNode& other);

    /**
     * Address: 0x00825570 (FUN_00825570)
     * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
     *
     * What it does:
     * Loads command-graph texture/style lanes from one Lua table entry, honoring
     * `inherit_from` recursion before overriding local orderline/waypoint/
     * arrowhead keys.
     */
    void LoadTextures(LuaPlus::LuaObject rootTable, const char* key, LuaPlus::LuaState* state);
  };

  static_assert(sizeof(UICommandGraphNode) == 0x54, "UICommandGraphNode size must be 0x54");
  static_assert(
    offsetof(UICommandGraphNode, mWaypointTexture) == 0x44,
    "UICommandGraphNode::mWaypointTexture offset must be 0x44"
  );
  static_assert(
    offsetof(UICommandGraphNode, mArrowheadTexture) == 0x4C,
    "UICommandGraphNode::mArrowheadTexture offset must be 0x4C"
  );

  class UICommandGraph
  {
  public:
    friend class CWldSession;

    /**
     * Its real caller (`sub_829190`) always passes `this` explicitly - see
     * `DrawPathPreview`'s own doc comment in CWldSession.h for why the IDA
     * decompile's declared first parameter is misleading here.
     */
    friend void DrawPathPreview(
      UICommandGraph& graph,
      const GeomCamera3& camera,
      CD3DPrimBatcher& batcher,
      std::int32_t tick,
      float tickFraction
    );

    /**
     * `func_ProcessCommandDrag` (0x00829B40, `UICommandDragger::DragMove`/
     * `DragRelease`'s worker in UiRuntimeTypes.cpp) needs `mSession` and
     * `mMapAB0` plus the hash primitives below.
     */
    friend void ProcessCommandDrag(const Wm3::Vector3f& mouse, UICommandGraph& graph, CmdId cmdId, bool released);

    /**
     * `sub_82A030` (`UICommandDragger::OnCurrentDraggerReplaced`'s worker in
     * UiRuntimeTypes.cpp) needs `mSession` and `mMapAB0` for the same reason
     * `ProcessCommandDrag` does.
     */
    friend void ReanchorCommandGraphDrawNode(UICommandGraph& graph, CmdId cmdId);

    /**
     * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds command-graph caches, map/index containers, debug font handle,
     * and synchronizes command-graph UI visibility in Lua.
     */
    explicit UICommandGraph(CWldSession* session);

    /**
     * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
     */
    ~UICommandGraph();

  public:
    using CommandGraphNode = UICommandGraphNode;

    struct CommandGraphEdge;

    /**
     * Payload of one command-graph hash node — the drawable record for a single
     * command. `mMapAB0` keys these by the issuing command, `mMapAB1` by the
     * head command of a queue, in which case `mPositionSum`/`mWeight` accumulate
     * across every unit sharing that queue so the graph can draw one node at
     * their centroid.
     *
     * This payload is *not* trivially destructible: it owns two heap-capable
     * dword lanes and one weak reference, which is why the binary's map-erase
     * paths call the destructor below before freeing the node.
     */
    struct UICommandGraphDrawNode
    {
      CmdId mCommandId; // +0x00
      /// The command's issue helper; its chain holds every draw node for it.
      WeakPtr<UserCommandIssueHelper> mHelperLink; // +0x04
      Wm3::Vector3f mPositionSum;                  // +0x0C
      float mWeight;                               // +0x18
      std::uint8_t mHasResolvedPosition;           // +0x1C
      std::uint8_t mIsChainBoundary;               // +0x1D
      std::uint8_t mIsVisible;                     // +0x1E
      /**
       * The node's drawable mesh, owned strongly. `sub_826550` decrements the
       * control block's use count at +0x04 and calls disposal on last release.
       * Normal shared_ptr copy, assignment and destruction preserve that
       * ownership, including constructor failure while copying the edge lists.
       */
      boost::shared_ptr<MeshInstance> mMeshInstance; // +0x20
      /**
       * Orderline tangent override: 0x008288D0 reads this as one `Vector3f`
       * (previously mis-split as `field_0x28`(uint32)/`field_0x2C`/
       * `field_0x30`, three separate scalars - it is one 12-byte vector) and
       * uses it in place of the computed from/to tangent whenever it's
       * non-zero.
       */
      Wm3::Vector3f mOrientationHint;  // +0x28
      Wm3::Vector3f mPreviousCentroid; // +0x34
      /**
       * Render scale driven by how busy the node is: `RecomputeDrawNodeOrientation`
       * sets it to `sqrt(units on the busier edge lane)`, and the waypoint and
       * ETA-label passes multiply their style scale by it. Was `field_0x40`
       * until 0x008275B0's write at 0x008279E8 pinned the meaning.
       */
      float mUnitCountScale; // +0x40
      /**
       * The game tick this order is estimated to finish on, propagated through
       * the edge graph by `ResolveDrawNodeCompletionTick`. `DisplayCommandNode`
       * subtracts the current tick from it to render "ETA: mm:ss". Was
       * `field_0x44` until 0x008272A0's write at 0x008272E0 pinned the meaning.
       */
      std::uint32_t mCompletionTick; // +0x44
      /**
       * The two edge lists: `mLaneA` holds the edges arriving here, `mLaneB`
       * the edges leaving. Each holds one inline edge, with 8-byte alignment;
       * growth, copy and release go through the template (`push_back`, the
       * copy constructor, `ResetStorageToInline`).
       */
      gpg::fastvector_n<CommandGraphEdge*, 1> mLaneA; // +0x48
      gpg::fastvector_n<CommandGraphEdge*, 1> mLaneB; // +0x60

      /**
       * Address: 0x00824600 (FUN_00824600, sub_824600)
       *
       * What it does:
       * A fresh node: no command (`-1`), not linked to any helper, zero
       * position sum/weight/orientation/centroid/scale/ETA, no mesh, visible,
       * both edge lanes empty on their inline storage. Callers:
       * `DrawNodeMap::operator[]` (0x0082B300) and
       * `AddCommandQueueToCommandGraph` (0x00826140).
       */
      UICommandGraphDrawNode();

      /**
       * Address: 0x00826550 (FUN_00826550, sub_826550)
       *
       * What it does:
       * Releases both dword lanes back to inline storage (freeing any spilled
       * heap block), drops the weak owner reference, and unlinks the node from
       * its command's intrusive chain.
       */
      ~UICommandGraphDrawNode();
    };

    /**
     * `mCommandGraphTree`'s value: a texture-keyed bucket of orderline edges.
     * The tree is a real msvc8-shaped red-black tree (`mColorOrAllocated` /
     * `mIsSentinel` at the offsets a real `_Tree` node uses) whose nodes carry
     * this pair by value at +0x0C.
     */
    struct CommandGraphTreeBucket
    {
      /// An `ID3DTextureSheet`, not a `CD3DBatchTexture`. `orderline_texture`
      /// is loaded through `ID3DDeviceResources::GetTexture`, which hands back
      /// an `RD3DTextureResource` -- and that derives from `ID3DTextureSheet`.
      /// The binary agrees from the consuming side: the two orderline passes
      /// call `SetTexture(boost::shared_ptr<ID3DTextureSheet>)` at 0x00829226
      /// and 0x00829396, and only the flat-white node pass at 0x0082952C takes
      /// the `CD3DBatchTexture` overload.
      boost::SharedPtrRaw<ID3DTextureSheet> mTexture; // +0x00
      fa::vector<CommandGraphEdge*> mEdges;           // +0x08
    };
    static_assert(sizeof(CommandGraphTreeBucket) == 0x18, "CommandGraphTreeBucket size must be 0x18");

    /**
     * One `mCommandGraphTree` node. The bucket used to sit in a 0x18-byte raw
     * payload array and was reinterpreted in place, which only fits on x86.
     * Nodes are still bought raw (`operator new` + `InitCommandGraphTreeBucketValue`
     * for the bucket) and released raw, as the binary does.
     */
    struct CommandGraphTreeNode
    {
      CommandGraphTreeNode* mLeft;    // +0x00
      CommandGraphTreeNode* mParent;  // +0x04
      CommandGraphTreeNode* mRight;   // +0x08
      CommandGraphTreeBucket mBucket; // +0x0C
      std::uint8_t mColorOrAllocated; // +0x24
      std::uint8_t mIsSentinel;       // +0x25
      std::uint8_t pad_26[2];
    };
    static_assert(offsetof(CommandGraphTreeNode, mBucket) == 0x0C, "CommandGraphTreeNode::mBucket offset must be 0x0C");
    static_assert(
      offsetof(CommandGraphTreeNode, mColorOrAllocated) == 0x24,
      "CommandGraphTreeNode::mColorOrAllocated offset must be 0x24"
    );

    struct CommandGraphTree
    {
      void* mAllocProxy;           // +0x00
      CommandGraphTreeNode* mHead; // +0x04
      std::uint32_t mSize;         // +0x08
    };

    /**
     * One drawn segment of a queued-order "orderline" - the ribbon connecting
     * two command-graph draw nodes. `mCommandGraphTree` buckets these by
     * texture: each tree node's `mBucket` holds a
     * `{boost::SharedPtrRaw<ID3DTextureSheet>, fa::vector<CommandGraphEdge*>}`
     * pair, and the render pass walks the bucket's vector once per texture.
     *
     * In the original EdgeMap list node, the two pointer keys occupy +8/+12
     * and this payload begins at +16, giving it a proven x86 size of 0x1C.
     */
    struct CommandGraphEdge
    {
      /**
       * Touch/visit refcount: 0x00826960 increments this by one every time
       * a queued order resolves to this (fromNode,toNode) edge, and reads
       * it back (clamped to `ui_CommandGraphMaxNodeUnits`) as the edge's
       * apparent unit weight in 0x008275B0's orientation-hint accumulation.
       */
      std::uint32_t mTouchCount{};         // +0x00, confirmed by FUN_00826960/FUN_008275B0
      float mBaseWidth{};                  // +0x04, confirmed by FUN_008288D0.c:85 and FUN_00826960
      UICommandGraphDrawNode* mFromNode{}; // +0x08
      UICommandGraphDrawNode* mToNode{};   // +0x0C
      /**
       * Per-lane bundle-spacing index, both written by 0x008275B0 as
       * `(loopIndex / max(laneCount - 1, 1)) - 0.5`: `mLaneBDistribution`
       * while walking `mFromNode->mLaneB` (this edge seen from its "from"
       * endpoint), `mLaneADistribution` while walking `mToNode->mLaneA`
       * (this edge seen from its "to" endpoint).
       */
      float mLaneBDistribution{}; // +0x10, confirmed by FUN_008275B0
      float mLaneADistribution{}; // +0x14, confirmed by FUN_008275B0
      /**
       * When set, 0x008288D0 skips `ResolveDrawNodeHighlightState` entirely
       * and draws this edge with the owning `CommandGraphNode`'s
       * mOrderlineHighlightColor/mOrderlineHighlightGlow directly - i.e. this
       * forces the "highlighted" style, it does not carry a per-edge custom
       * color (an earlier read of this struct assumed `+0x1C`/`+0x28` held a
       * per-edge override color/alpha; neither offset is actually read
       * anywhere in 0x008288D0, so that guess has been dropped).
       */
      bool mForceHighlightStyle{};        // +0x18
      std::uint8_t mUnknown19_1B[0x03]{}; // +0x19, unconfirmed - not touched by FUN_00826960/FUN_008275B0
    };

    static_assert(sizeof(CommandGraphEdge) == 0x1C, "CommandGraphEdge size must be 0x1C");
    static_assert(offsetof(CommandGraphEdge, mBaseWidth) == 0x04, "CommandGraphEdge::mBaseWidth offset must be 0x04");
    static_assert(offsetof(CommandGraphEdge, mFromNode) == 0x08, "CommandGraphEdge::mFromNode offset must be 0x08");
    static_assert(offsetof(CommandGraphEdge, mToNode) == 0x0C, "CommandGraphEdge::mToNode offset must be 0x0C");
    static_assert(
      offsetof(CommandGraphEdge, mLaneBDistribution) == 0x10,
      "CommandGraphEdge::mLaneBDistribution offset must be 0x10"
    );
    static_assert(
      offsetof(CommandGraphEdge, mLaneADistribution) == 0x14,
      "CommandGraphEdge::mLaneADistribution offset must be 0x14"
    );
    static_assert(
      offsetof(CommandGraphEdge, mForceHighlightStyle) == 0x18,
      "CommandGraphEdge::mForceHighlightStyle offset must be 0x18"
    );

    using DrawNodeMap = fa::hash_map<UserCommandIssueHelper*, UICommandGraphDrawNode>;
    using DrawNodePair = std::pair<UICommandGraphDrawNode*, UICommandGraphDrawNode*>;

    // The original pair hash combines both pointer words before the VC8
    // Park-Miller step. Ordering always compares the complete pointers.
    struct EdgeKeyHashCompare
    {
      static constexpr std::size_t bucket_size = 4;
      static constexpr std::size_t min_buckets = 8;
      std::size_t operator()(const DrawNodePair& key) const noexcept;
      bool operator()(const DrawNodePair& lhs, const DrawNodePair& rhs) const noexcept;
    };

    using EdgeMap = fa::hash_map<DrawNodePair, CommandGraphEdge, EdgeKeyHashCompare>;
    using WidthMap = fa::hash_map<std::uint32_t, float>;

    static_assert(sizeof(CountedPtr<CD3DFont>) == 0x04, "Debug font handle size must be 0x04");
    static_assert(sizeof(DrawNodeMap) == 0x28, "DrawNodeMap size must be 0x28");
    static_assert(sizeof(DrawNodeMap::value_type) == 0x80, "DrawNodeMap value size must be 0x80");
    static_assert(offsetof(DrawNodeMap::value_type, second) == 0x08, "DrawNodeMap payload offset must be 0x08");
    static_assert(sizeof(DrawNodePair) == 0x08, "DrawNodePair size must be 0x08");
    static_assert(sizeof(EdgeKeyHashCompare) == 0x01, "EdgeKeyHashCompare size must be 0x01");
    static_assert(sizeof(EdgeMap) == 0x28, "EdgeMap size must be 0x28");
    static_assert(sizeof(EdgeMap::value_type) == 0x24, "EdgeMap value size must be 0x24");
    static_assert(offsetof(EdgeMap::value_type, second) == 0x08, "EdgeMap payload offset must be 0x08");
    static_assert(sizeof(WidthMap) == 0x28, "WidthMap size must be 0x28");
    static_assert(sizeof(WidthMap::value_type) == 0x08, "WidthMap value size must be 0x08");

    /**
     * `EstimateDrawNodeWorkTicks` (0x00826F10) reaches the game rules through
     * `mSession` to build the "assisting unit" category: 0x0082700F loads
     * `graph+0x0D24` and 0x00827015 the rules at `session+0x18` before the two
     * `GetEntityCategory` dispatches. Declared here rather than beside the
     * other friends above because it names `UICommandGraphDrawNode`, which is
     * only complete from this point on.
     */
    friend std::int32_t EstimateDrawNodeWorkTicks(UICommandGraph& graph, UICommandGraphDrawNode& drawNode);

    /**
     * `LinkCommandGraphEdge` (0x00826960) needs `mMapC`/`mMapD`/`mNodes` and
     * the private find-or-insert primitives built on them - declared here
     * (rather than with the other friends above) for the same reason
     * `EstimateDrawNodeWorkTicks` is: it names `UICommandGraphDrawNode`,
     * only complete from this point on. See its own doc comment, on the
     * out-of-line definition, for the full address decomposition.
     */
    friend void LinkCommandGraphEdge(
      UICommandGraphDrawNode& toNode,
      UICommandGraphDrawNode& fromNode,
      UICommandGraph& graph,
      bool forceHighlight
    );

    /**
     * `AddCommandQueueToCommandGraph` (0x00826140) needs `mMapAB0`/`mMapAB1`/
     * `mSession` and the pointer-keyed draw maps - declared here for
     * the same reason `LinkCommandGraphEdge` is.
     */
    friend void AddCommandQueueToCommandGraph(UserEntity& entity, UICommandGraph& graph, UserCommandQueue* queue);

    /**
     * Tri-state highlight the render pass picks a waypoint/orderline style
     * color and scale from - see `ResolveDrawNodeHighlightState`.
     */
    enum class ECommandNodeHighlightState : std::int32_t
    {
      Normal = 0,
      Highlighted = 1,
      Selected = 2,
    };

    /**
     * Address: 0x00828280 (FUN_00828280, sub_828280)
     *
     * IDA signature:
     * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
     *
     * What it does:
     * The "selected" test `ResolveDrawNodeHighlightState` ends on: resolves the
     * draw node's owning command-issue helper, asks that helper for the entity
     * set the command is aimed at, and reports whether that set shares any live
     * entity with the session's current selection. A node with no owning helper
     * is never selected.
     *
     * Its own null-helper guard is kept even though the only caller has already
     * checked the same field - the binary re-tests it here.
     */
    [[nodiscard]] bool DrawNodeSharesLiveEntityWithSelection(const UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x008281E0 (FUN_008281E0, sub_8281E0)
     * Address: 0x00831110 (FUN_00831110, sub_831110) - now
     * `WeakSet<UserEntity>::HasCommonLiveEntityWith`
     *
     * What it does:
     * Picks the style state a command-graph draw node renders with this
     * frame: `Highlighted` when the cursor is hovering a unit the node's
     * command affects, or when the node's command is the session's
     * currently-interacting one; `Selected` when the node's affected-entity
     * set shares any live entity with the current selection; `Normal`
     * otherwise, and always `Normal` for a node with no owning command.
     *
     * The binary's `mIsDragger` comparison (0x00828249: `cmp ebx,[esi+18h]`)
     * reads `MouseInfo::mIsDragger` as a `CmdId`, not a boolean "currently
     * dragging" flag - it is genuinely the id of whichever command the
     * session is presently interacting with. Preserved as a raw field read
     * with this comment rather than renaming the widely-shared `MouseInfo`
     * field.
     */
    [[nodiscard]] ECommandNodeHighlightState
    ResolveDrawNodeHighlightState(const UICommandGraphDrawNode& drawNode) const;

  private:
    /**
     * Address: 0x008300D0 (FUN_008300D0)
     */
    static CommandGraphTreeNode* AllocateTreeSentinelNode();

    static void InitTree(CommandGraphTree& tree);

    /**
     * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
     *
     * What it does:
     * Frees one command-graph tree bucket's edge-pointer vector storage (if
     * spilled off the vector's inline/proxy state to a heap buffer) and
     * releases its owned batch-texture control block. Does not free the
     * owning tree node - callers do that immediately afterward. Before this
     * recovery pass, `DestroyTree`'s node-delete walk never called this,
     * leaking `mEdges`' heap buffer and the texture refcount on every
     * teardown (including the class destructor) - see the fix in
     * `DestroyTree` below.
     */
    static void ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept;

    /**
     * Not a distinct binary function - the post-order (right subtree, this
     * node, left subtree) node-destroy walk that 0x00824B50 (`DestroyTree`)
     * inlines in the binary (0x0082CDE0 is that copy). A second binary copy
     * at 0x00826000 (`PrepareForRebuild`, see below) inlines the identical
     * walk for its rebuild-reset path - both are now recovered against this
     * one shared helper, so the bucket-resource release runs on every node
     * from both call sites. Lifted into one shared helper here per the
     * intent-first helper contract instead of duplicating the walk.
     */
    static void DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* sentinelHead, CommandGraphTreeNode* node);

    /**
     * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
     *
     * What it does:
     * Destroys one command-graph runtime tree (nodes + head sentinel) and
     * clears head/size lanes. Releases each node's bucket resources
     * (texture refcount + edge-vector heap buffer) via
     * `ReleaseCommandGraphTreeBucket` before freeing the node.
     */
    static void DestroyTree(CommandGraphTree& tree);

    /**
     * Address: 0x0082D330 (FUN_0082D330, sub_82D330)
     *
     * What it does:
     * Constructs one `CommandGraphTreeBucket` in place: retains a new
     * strong reference on `texture`'s shared control block (matching
     * `boost::shared_ptr`'s copy constructor - `_InterlockedExchangeAdd`
     * on the control block in the binary) and default-constructs the edge
     * vector.
     */
    static CommandGraphTreeBucket* InitCommandGraphTreeBucketValue(
      CommandGraphTreeBucket* destination,
      const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x00830010 (FUN_00830010)
     *
     * What it does:
     * Standard red-black left rotation, transcribed against
     * `CommandGraphTreeNode`'s own field names - same shape as
     * `legacy/containers/RbTree.h`'s `rotate_left` (already cited there for
     * this exact tree instantiation).
     */
    static void PivotCommandGraphTreeLeft(CommandGraphTree& tree, CommandGraphTreeNode* n) noexcept;

    /**
     * Address: 0x00830080 (FUN_00830080)
     *
     * What it does:
     * Mirror of `PivotCommandGraphTreeLeft` - same shape as
     * `legacy/containers/RbTree.h`'s `rotate_right` (already cited there
     * for this exact tree instantiation).
     */
    static void PivotCommandGraphTreeRight(CommandGraphTree& tree, CommandGraphTreeNode* n) noexcept;

    /**
     * Address: 0x0082E320 (FUN_0082E320, sub_82E320), buy+link+rebalance half
     *
     * What it does:
     * Allocates one fresh tree node, retains `texture` into its bucket
     * payload, links it under `where`/`addLeft`, then repairs the
     * red-red violation - the exact shape `legacy/containers/RbTree.h`'s
     * `insert_at` (`buy_node` + `link_and_rebalance`) already documents for
     * this map instantiation, transcribed against `CommandGraphTreeNode`'s
     * own field names rather than routed through `detail::rb_tree<Traits>`:
     * `boost::SharedPtrRaw<T>` is an explicit-retain, non-owning view by
     * design (see `BoostWrappers.h`), so a generic value-type copy
     * constructor would silently skip the add-ref the binary performs
     * explicitly via `sub_82D330` (`InitCommandGraphTreeBucketValue` above).
     */
    static CommandGraphTreeNode* AttachCommandGraphNodeAt(
      CommandGraphTree& tree,
      bool addLeft,
      CommandGraphTreeNode* where,
      const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x0082E170 (FUN_0082E170, sub_82E170)
     *
     * What it does:
     * Plain unique insert: descends comparing the owner-based key (the
     * texture's control-block pointer), confirms uniqueness against the
     * in-order predecessor when the descent bottomed out on a left branch,
     * and links via `AttachCommandGraphNodeAt`. Same shape as
     * `legacy/containers/RbTree.h`'s `insert_unique`, already cited there
     * for this map instantiation.
     */
    static CommandGraphTreeNode*
    AttachCommandGraphNodeUnique(CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture);

    /**
     * Address: 0x0082CC80 (FUN_0082CC80, sub_82CC80)
     *
     * What it does:
     * Hinted unique insert: the empty-tree fast path, `hint == leftmost()`
     * check, `hint == end()` check against `rightmost()`, then the
     * decrement/increment straddle checks, each tailing into
     * `AttachCommandGraphNodeAt` with the decided `addLeft`, and a final
     * fallback to `AttachCommandGraphNodeUnique`. Same shape as
     * `legacy/containers/RbTree.h`'s `insert_hint`, already cited there for
     * this exact map instantiation - `mCommandGraphTree[texture]`'s
     * `lower_bound` result feeding straight back in as the hint.
     */
    static CommandGraphTreeNode* AttachCommandGraphNodeHinted(
      CommandGraphTree& tree,
      CommandGraphTreeNode* hint,
      const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x0082B8B0 (FUN_0082B8B0, sub_82B8B0)
     *
     * What it does:
     * `mCommandGraphTree[texture]` (VC8 `map::operator[]`): descends
     * comparing the owner-based key (the texture's control-block pointer,
     * `pi`) against each candidate bucket's own `pi` lane, records the last
     * node the search went left at, and on a miss inserts a fresh bucket
     * retaining `texture` via `AttachCommandGraphNodeHinted`. Returns
     * the resolved bucket's edge vector - `LinkCommandGraphEdge`
     * (0x00826960) pushes the new edge straight into it via
     * `CommandGraphTreeBucket::mEdges.push_back` (0x0082BCB0).
     */
    static fa::vector<CommandGraphEdge*>&
    FindOrInsertCommandGraphBucket(CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture);

    /**
     * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
     */
    static void OnCommandGraphShow(LuaPlus::LuaState* state, bool visible);

    /**
     * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
     */
    void LoadPathParams();

    /**
     * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
     */
    static void LoadWaypointParams();

    /**
     * Address: 0x00828FB0 (FUN_00828FB0, Moho::UICommandGraph::CreateMeshes)
     *
     * IDA signature:
     * void callcnv_33 Moho::UICommandGraph::CreateMeshes(Moho::UICommandGraph *a1);
     *
     * What it does:
     * The command graph's once-per-frame build pass. When the graph is dirty it
     * rebuilds every queued-order node and edge from the live command queues and
     * recomputes each node's orderline orientation. It then re-binds every
     * draw node to whichever command-issue helper currently owns its command id
     * (commands retire and are re-issued between frames, so the intrusive chain
     * has to be re-pointed), seeding a node's world anchor from the helper's
     * command history the first time that node resolves. On a rebuild frame it
     * additionally propagates completion-tick estimates through the edge graph
     * and creates the translucent "UnitPlace" preview mesh for mobile-build
     * orders. Finally it drives the console path-preview overlay.
     */
    void CreateMeshes();

    /**
     * Address: 0x00826740 (FUN_00826740, sub_826740)
     *
     * IDA signature:
     * void __thiscall sub_826740(Moho::UICommandGraph *this);
     *
     * What it does:
     * Rebuilds the whole command-graph node/edge set from scratch. Resets the
     * per-frame containers, collects every mesh-bearing entity in the session's
     * spatial database, and folds each significant unit's command queue into
     * the graph - plus the separate factory build queue for stationary
     * factories.
     */
    void RebuildCommandQueueNodes();

    /**
     * Address: 0x00826000 (FUN_00826000, sub_826000)
     *
     * IDA signature:
     * void __usercall sub_826000(Moho::UICommandGraph *this@<edi>);
     *
     * What it does:
     * Clears everything a rebuild pass regenerates: the edge hash table and its
     * buckets, the texture-keyed orderline tree, and both draw-node tables' edge
     * lanes. Queue-head nodes (`mMapAB1`) additionally have their accumulated
     * centroid and weight zeroed, because the rebuild re-accumulates them across
     * every unit sharing the queue.
     */
    void PrepareForRebuild();

    /**
     * Address: 0x00826BA0 (FUN_00826BA0, sub_826BA0)
     *
     * IDA signature:
     * _DWORD **__usercall sub_826BA0@<eax>(Moho::UICommandGraph *this@<ebx>);
     *
     * What it does:
     * Recomputes the orderline orientation hint of every draw node, queue-head
     * table first and per-command table second.
     */
    void RecomputeAllDrawNodeOrientations();

    /**
     * Address: 0x008275B0 (FUN_008275B0, sub_8275B0)
     *
     * IDA signature:
     * void __usercall sub_8275B0(Moho::UICommandGraph::UICommandGraphDrawNode *this@<esi>);
     *
     * What it does:
     * Derives one draw node's orderline tangent from the edges on both of its
     * lanes: each edge contributes the unit vector towards its far endpoint's
     * centroid, scaled by that edge's unit count (clamped to
     * `ui_CommandGraphMaxNodeUnits`). The summed direction is normalized into
     * `mOrientationHint`, and the node's render scale becomes the square root of
     * the busier lane's unit total. Each edge also records where it sits in its
     * lane's ribbon bundle, so parallel orderlines fan out instead of
     * overlapping.
     */
    static void RecomputeDrawNodeOrientation(UICommandGraphDrawNode& drawNode);

    /**
     * Address: 0x008272A0 (FUN_008272A0, sub_8272A0)
     *
     * IDA signature:
     * void __thiscall sub_8272A0(Moho::UICommandGraph *this, _DWORD *drawNode);
     *
     * What it does:
     * Resolves the game tick one queued order is estimated to complete on, by
     * depth-first walking the edges it depends on. Writing the current tick into
     * the node up front doubles as the cycle guard: a node already being
     * resolved returns immediately, so a cyclic order graph terminates.
     */
    void ResolveDrawNodeCompletionTick(UICommandGraphDrawNode& drawNode);

    /**
     * Address: 0x00827360 (FUN_00827360, sub_827360)
     *
     * IDA signature:
     * void __userpurge sub_827360(
     *   Moho::UICommandGraph::UICommandGraphDrawNode *drawNode@<esi>, Moho::UICommandGraph *graph);
     *
     * What it does:
     * Gives a pending mobile-build order its translucent green placement mesh -
     * the ghost of the unit that order will produce, stanced at the order's
     * position. Only builds one when the node has no mesh yet and its command is
     * a `BuildMobile`; every other order draws with waypoint markers alone.
     *
     * The chain, with the three offsets an earlier pass could not place now
     * resolved against the disassembly:
     *  - `helper+0x20` is `mConstantData.blueprint` (`mConstantData` sits at
     *    helper+0x04, `blueprint` at its own +0x1C), an `REntityBlueprint*`;
     *  - virtual slot 5 (0x008273B2, `[eax+0x14]`) is
     *    `REntityBlueprint::IsUnitBlueprint`, returning the `RUnitBlueprint`
     *    whose `Display` subobject starts at +0x200 - which is what makes
     *    +0x21C `Display.MeshBlueprint` (an `RResId`, *not* the `VTransform`
     *    the decompiler infers from its 0x1C-byte width) and +0x270
     *    `Display.UniformScale`;
     *  - virtual slot 15 (0x008273D3, `[edx+0x3C]`) on `CWldSession::mRules`
     *    is `RRuleGameRules::GetMeshBlueprint(const RResId&)`, which is why
     *    the +0x21C `RResId` is the argument handed to it;
     *  - the "+0x64 string triple" is not a field of `RMeshBlueprint` at all.
     *    `mLods` starts at +0x60 and +0x64 is its `first_` lane, so the three
     *    strings the binary addresses at +0x1C/+0x38/+0x54 off that pointer
     *    are `mAlbedoName`/`mNormalsName`/`mSpecularName` of `mLods[0]`.
     *
     * Note the colour appears twice and the decompiler folds them together:
     * `CreateMeshInstance` is handed 0xFF00FF00, then the instance's own
     * colour lane is overwritten with 0xD800D800 - the alpha-0xD8 translucent
     * green the ghost actually renders in.
     */
    static void CreateBuildPreviewMesh(UICommandGraphDrawNode& drawNode, UICommandGraph& graph);

    void MarkDirty() noexcept
    {
      mNeedsRebuild = 1u;
    }

    /**
     * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
     *
     * What it does:
     * Draws one command node's waypoint marker quad: a flat square centered
     * on the node's averaged position, sized to a roughly-constant apparent
     * screen size via the camera's viewport perspective-width row, colored
     * and scaled by `ResolveDrawNodeHighlightState`.
     */
    void
    DrawWaypointMarker(const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
     *
     * What it does:
     * Poses the node's owned mesh instance at its resolved (or history-
     * resolved fallback) anchor and, when that anchor came from a real unit
     * blueprint, draws the unit's footprint skirt there too.
     */
    void DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const;

    /**
     * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
     *
     * What it does:
     * Draws the "ETA: mm:ss" text label above one command-graph draw node.
     */
    void DisplayCommandNode(
      const GeomCamera3& camera,
      const UICommandGraphDrawNode& drawNode,
      CD3DPrimBatcher& batcher
    ) const;

    /**
     * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
     *
     * What it does:
     * Draws one command-graph "orderline" ribbon segment between two draw
     * nodes' averaged positions.
     */
    void DrawCommandOrderline(
      const GeomCamera3& camera,
      CD3DPrimBatcher& batcher,
      std::int32_t tick,
      float tickFraction,
      const CommandGraphEdge& edge,
      bool isGlow
    ) const;

  public:
    /**
     * Address: 0x00829190 (FUN_00829190, sub_829190)
     *
     * What it does:
     * The per-frame command-graph render pass: draws every queued-order
     * orderline (opaque then glow, grouped by texture), every waypoint
     * marker, positions each node's anchored mesh/skirt, the path-preview
     * overlay, then switches to a screen-space projection and draws every
     * node's ETA text label.
     *
     * IDA's `__userpurge` signature adds two register arguments (typed
     * `CRenderWorldView*` and `boost::shared_ptr<UICommandGraph>&` in the
     * analyst database) that are only the caller's leftover `ecx`/`edx`; this
     * body never reads either.
     *
     * Public (unlike its `DrawWaypointMarker`/`DrawCommandOrderline`/etc.
     * siblings above, which are only ever called from here): its real caller
     * is `CWldSession::RenderCommandGraph` (0x0085AF40), outside this class.
     */
    void
    DrawCommandGraphMesh(const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction);

    /**
     * Address: 0x00829800 (FUN_00829800, sub_829800)
     *
     * IDA signature:
     * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
     *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
     *
     * What it does:
     * Per-frame cursor/waypoint hit test for the command graph: walks every
     * draw node in `mMapAB0`'s hash list, frustum-culls its averaged anchor
     * (`mPositionSum / mWeight`) against the camera's view solid, and for
     * every surviving node compares its projected screen position against
     * `cursorScreenPos` within a depth-scaled, `ui_MinWaypointSize`/
     * `ui_MaxWaypointSize`-clamped tolerance (`ui_WaypointLineScale` applied
     * on top - the decompiled read shows as `ui_CommandClickScale`, which is
     * not a real symbol; see `UICommandGraph::LoadPathParams`'s doc comment
     * on why both Lua keys resolve to `ui_WaypointLineScale`), the same
     * style knobs `DrawWaypointMarker` uses for the visible marker size).
     * Ferry-command nodes get a small (0.1) tolerance bonus,
     * matching the binary's dedicated `UNITCOMMAND_Ferry` branch. Among the
     * nodes within tolerance, the closest wins unless a farther node's
     * cursor-entity set already shares a live entity with the current
     * session selection, in which case that node preempts distance.
     *
     * Returns the winning node's command id, or -1 when none qualifies.
     */
    [[nodiscard]] CmdId
    ResolveCursorHighlightCommandId(const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos) const;

  private:
    std::uint8_t mNeedsRebuild; // +0x0000
    std::uint8_t pad_0001[3];
    CommandGraphNode mNodes[40];        // +0x0004
    CWldSession* mSession;              // +0x0D24
    void* mSessionRes1;                 // +0x0D28
    CountedPtr<CD3DFont> mDebugFont;    // +0x0D2C
    DrawNodeMap mMapAB0;                // +0x0D30
    DrawNodeMap mMapAB1;                // +0x0D58
    EdgeMap mMapC;                      // +0x0D80
    WidthMap mMapD;                     // +0x0DA8
    CommandGraphTree mCommandGraphTree; // +0x0DD0
  };

  static_assert(sizeof(UICommandGraph::CommandGraphNode) == 0x54, "UICommandGraph::CommandGraphNode size must be 0x54");
  static_assert(
    sizeof(UICommandGraph::UICommandGraphDrawNode::mLaneA) == 0x18,
    "UICommandGraph::UICommandGraphDrawNode::mLaneA size must be 0x18"
  );
  static_assert(
    sizeof(UICommandGraph::UICommandGraphDrawNode) == 0x78,
    "UICommandGraph::UICommandGraphDrawNode size must be 0x78"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mHelperLink) == 0x04,
    "UICommandGraphDrawNode::mHelperLink offset must be 0x04"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPositionSum) == 0x0C,
    "UICommandGraphDrawNode::mPositionSum offset must be 0x0C"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mWeight) == 0x18,
    "UICommandGraphDrawNode::mWeight offset must be 0x18"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mMeshInstance) == 0x20,
    "UICommandGraphDrawNode::mMeshInstance offset must be 0x20"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mOrientationHint) == 0x28,
    "UICommandGraphDrawNode::mOrientationHint offset must be 0x28"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPreviousCentroid) == 0x34,
    "UICommandGraphDrawNode::mPreviousCentroid offset must be 0x34"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneA) == 0x48,
    "UICommandGraphDrawNode::mLaneA offset must be 0x48"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneB) == 0x60,
    "UICommandGraphDrawNode::mLaneB offset must be 0x60"
  );
  static_assert(
    sizeof(UICommandGraph::CommandGraphTreeNode) == 0x28,
    "UICommandGraph::CommandGraphTreeNode size must be 0x28"
  );
  static_assert(sizeof(UICommandGraph::CommandGraphTree) == 0x0C, "UICommandGraph::CommandGraphTree size must be 0x0C");
  static_assert(sizeof(UICommandGraph) == 0xDDC, "UICommandGraph size must be 0xDDC");
  extern std::unique_ptr<ISTIDriver> sSimDriver;

  /**
   * Address: 0x00826F10 (FUN_00826F10, sub_826F10)
   *
   * IDA signature:
   * int __stdcall sub_826F10(Moho::UICommandGraph *graph,
   *                          Moho::UICommandGraph::UICommandGraphDrawNode *drawNode);
   *
   * What it does:
   * Build time in game ticks for one order: asks `/lua/game.lua`'s
   * `GetConstructEconomyModel` for each assisting engineer/factory's build rate,
   * sums their reciprocals, and divides the remaining work fraction (derived
   * from the part-built unit's health ratio) by that combined rate. Returns 0
   * for any command that is not a `BuildMobile`/`BuildFactory`.
   *
   * Body below, after the anonymous-namespace helpers it uses.
   */
  [[nodiscard]] std::int32_t
  EstimateDrawNodeWorkTicks(UICommandGraph& graph, UICommandGraph::UICommandGraphDrawNode& drawNode);

  /**
   * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
   *
   * Defined in Sim.cpp; declared here rather than pulling in Sim.h for one
   * symbol.
   */
  [[nodiscard]] EUnitCommandType UnitCommandCapToCommandType(ERuleBPUnitCommandCaps commandCap);
  namespace
  {

    // GetHoveredUserEntity is now CWldSession::GetHoveredUserEntity, a public
    // member (declared near GetCursorInfo() in the header) - promoted so the
    // command-graph render pass in CUIWorldView.cpp can call it too.

    // ResolveIUnitBridge was a duplicate of UserUnit.h's GetIUnitBridge -
    // callers below now use that instead.

    [[nodiscard]] bool ContainsUnitPtr(
      const fa::vector<UserUnit*>& units,
      const UserUnit* const unit
    )
    {
      return std::find(units.begin(), units.end(), unit) != units.end();
    }

    void AppendUnitUnique(
      fa::vector<UserUnit*>& units,
      UserUnit* const unit
    )
    {
      if (unit == nullptr || ContainsUnitPtr(units, unit)) {
        return;
      }
      units.push_back(unit);
    }

    // `UserTarget` (UserTarget.h) is what the three padded "anchor" views that
    // used to live here described: `{kind, weak entity link, position}` at
    // +0x00/+0x04/+0x0C is `UserTarget` member for member, the "history" was
    // the whole `UserCommandIssueHelper` (its local event queue at +0xB8, the
    // replicated entity ids at +0x40 and target at +0x5C), and a "history
    // entry" was one `UserCommandIssueLocalEvent`.

    /**
     * Address: 0x008BEC40 (FUN_008BEC40)
     *
     * What it does:
     * Converts one replicated command target (`SSTITarget`: kind, entity id,
     * ground position) into the UI-side `UserTarget`. An entity target is
     * resolved through the active session's entity map (the id is the one
     * dword at +0x04, 0x008BEC5F) and linked weakly; a ground target copies
     * its position, which sits at +0x08 in the source and +0x0C in the
     * destination (0x008BEC94..0x008BECAA). Any other kind sets only the kind.
     */
    [[nodiscard]] UserTarget MakeUserTargetFromSSTITarget(
      const SSTITarget& source
    )
    {
      UserTarget target{};
      target.targetType = static_cast<UserTargetType>(source.mType);

      if (target.targetType == UserTargetType::Entity) {
        UserEntity* entity = nullptr;
        if (CWldSession* const activeSession = moho::WLD_GetActiveSession(); activeSession != nullptr) {
          entity = activeSession->LookupEntityId(static_cast<moho::EntId>(source.mEnt));
        }
        target.targetEntity.ResetFromObject(entity);
      } else if (target.targetType == UserTargetType::Position) {
        target.position = source.mPos;
      }

      return target;
    }

    /**
     * Address: 0x008B4080 (FUN_008B4080)
     * Address: 0x008B40F0 (FUN_008B40F0 -- `UserTarget`'s implicit copy
     * constructor: the kind, the `targetEntity` weak link re-linked at its
     * owner's chain head, the position. Returned out of here for the event's
     * target, and run per event by `UserCommandIssueLocalEvent`'s own copy
     * constructor 0x008B56F0.)
     * Address: 0x0081D010 (FUN_0081D010 -- `UserTarget`'s implicit destructor:
     * `targetEntity`'s unlink from its owner chain, without clearing the two
     * link words. Every transient `UserTarget` below dies through it.)
     *
     * What it does:
     * The helper's current target: the newest unconfirmed `SetTarget` edit in
     * `mLocalQueue`, walked from the back (block size 1, so the map slot is
     * `off + i`, less `_Mapsize` once it wraps), else the replicated
     * `mVariableData.mTarget1`. An empty queue goes straight to the fallback,
     * which is how a command with no local edits gets its sim-side target.
     */
    [[nodiscard]] UserTarget ResolveCommandIssueTarget(
      const UserCommandIssueHelper& helper
    )
    {
      for (std::size_t index = helper.mLocalQueue.size(); index != 0u; --index) {
        const UserCommandIssueLocalEvent& event = helper.mLocalQueue[index - 1u];
        if (event.mType == ECommandIssueEvent::SetTarget) {
          return event.mTarget;
        }
      }

      return MakeUserTargetFromSSTITarget(helper.mVariableData.mTarget1);
    }

    /**
     * Address: 0x00824550 (FUN_00824550, sub_824550)
     *
     * Misclassified `external_dependency` by an earlier automated pass (its
     * sole callee `sub_8B4080` walks the helper's own event queue, not
     * external runtime state).
     *
     * What it does:
     * The live entity the helper's current target names, or null for a
     * ground target or an entity that has gone away. The transient target is
     * released before returning. Callers: `func_ProcessCommandDrag`
     * (0x00829B40) and `EstimateDrawNodeWorkTicks` (0x00826F10).
     */
    [[maybe_unused]] [[nodiscard]] UserEntity* ResolveCommandTargetEntity(
      const UserCommandIssueHelper& helper
    )
    {
      const UserTarget target = ResolveCommandIssueTarget(helper);
      return target.targetType == UserTargetType::Entity ? target.targetEntity.GetObjectPtr() : nullptr;
    }
    /**
     * Address: 0x0081CFD0 (FUN_0081CFD0)
     *
     * What it does:
     * The world position of the helper's current target
     * (`ResolveCommandIssueTarget`, then `ResolvePositionFromTarget`,
     * 0x008BED50): the named entity's position, the ground position, or the
     * invalid vector. The transient target is released on the way out.
     */
    [[maybe_unused]] [[nodiscard]] Wm3::Vector3f* ResolveCommandIssueTargetPosition(
      Wm3::Vector3f* const outPosition,
      const UserCommandIssueHelper& helper
    )
    {
      if (outPosition == nullptr) {
        return nullptr;
      }

      *outPosition = ResolvePositionFromTarget(ResolveCommandIssueTarget(helper));
      return outPosition;
    }

    [[maybe_unused]] void CollectSessionUserUnits(
      CWldSession* const session,
      fa::vector<UserUnit*>& outUnits
    )
    {
      outUnits.clear();
      if (session == nullptr) {
        return;
      }

      for (const auto& [entityId, entity] : session->mEntities) {
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr) {
          continue;
        }

        AppendUnitUnique(outUnits, unit);
      }
    }

    /**
     * Address: 0x00894E11..0x00894E45 (inside FUN_00894530)
     *
     * What it does:
     * Looks one live command-issue helper up by id, returning null when the
     * manager's map has no entry (the walk lands on the sentinel head).
     */
    [[maybe_unused]] [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelper(
      CommandManager& manager,
      const CmdId commandId
    )
    {
      const auto found = manager.mCommands.find(commandId);
      return found == manager.mCommands.end() ? nullptr : found->second;
    }
  } // namespace

} // namespace moho

namespace moho
{
  extern bool gSessionShowedTick;
  extern bool gFrameClockResetPending;
  extern bool gReadyAfterFirstFrame;
} // namespace moho
