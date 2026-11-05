#include "moho/sim/CWldSessionPrivate.h"


// Defined at file scope (global namespace, external linkage) in
// CrtRuntimeExportedHelpers.cpp - shared by every legacy VC8 "<container> too
// long" throw lane. Forward-declared here rather than duplicated so
// UICommandGraph's own hash-table growth guard (CheckedIncrementListSize) can
// reuse the identical message/exception construction instead of re-emitting it
// inline a second time. The bucket vector's own overflow lane (FUN_00830620)
// is fa::vector<void*>::throw_too_long and is cited there.
[[noreturn]] void EngineThrowContainerTooLong(const char* message);

// Forward declaration: this symbol is referenced by the linker at global
// scope (not inside namespace moho), so its definition stays at global scope
// near the end of this file - but `DrawPathPreview` (namespace moho, below)
// needs to call it ahead of that point.
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession);
namespace moho
{

  // Command-waypoint drawing parameters; see the declarations in CWldSession.h
  // for the per-symbol addresses. All seven are zero at image load and stay so
  // until `UICommandGraph::LoadWaypointParams` imports them.
  std::int32_t ui_CurveSegments = 20;          // 0x00F57CC0
  // 0x010A6443 lies past ForgedAlliance.exe's raw .data (zero-filled BSS tail),
  // so the path-preview overlay ships off.
  bool ui_DrawPathPreview = false;          // 0x010A6443
  bool ui_PathPreview = false;              // 0x010A6448


  // Initial values from the shipped .data; commandwaypoint.lua may override the
  // waypoint/path ones (UICommandGraph::LoadPathParams), missing keys keep these.
  float ui_CurveSmoothness = 50.0f;            // 0x00F57CC4
  float ui_PathSmoothness = 2.0f;              // 0x00F57CC8
  float ui_MaxTextLOD = 80.0f;                 // 0x00F57CCC
  std::int32_t ui_CommandGraphMaxNodeUnits = 1; // 0x00F57CD0

  /**
   * Degenerate-length cutoff `RecomputeDrawNodeOrientation` compares its summed
   * edge direction against before normalizing (`flt_D71BFC`, loaded at
   * 0x00827979). Below it the node keeps a zero orientation hint rather than
   * normalizing noise into an arbitrary direction.
   */
  constexpr float kCommandGraphOrientationEpsilon = 1.0e-6f;
  float ui_MinWaypointSize = 7.0f;             // 0x00F57CD4
  float ui_MaxWaypointSize = 100.0f;           // 0x00F57CD8
  float ui_WaypointLineScale = 1.0f;           // 0x00F57CDC

  /**
   * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Seeds one command-graph style node with default animation/scaling lanes
   * and clears orderline/waypoint/arrowhead texture shared pointers.
   */
  UICommandGraphNode::UICommandGraphNode()
  {
    mOrderlineTexture.px = nullptr;
    mOrderlineTexture.pi = nullptr;
    mOrderlineAnimRate = 0.1f;
    mOrderlineAspectRatio = 1.0f;
    mOrderlineColor = 0u;
    mOrderlineSelectedColor = 0u;
    mOrderlineHighlightColor = 0u;
    mOrderlineGlow = 0.0f;
    mOrderlineSelectedGlow = 0.0f;
    mOrderlineHighlightGlow = 0.0f;
    mWaypointColor = 0u;
    mWaypointSelectedColor = 0u;
    mWaypointHighlightColor = 0u;
    mWaypointScale = 1.0f;
    mWaypointSelectedScale = 1.0f;
    mWaypointHighlightScale = 1.0f;
    mWaypointTexture.px = nullptr;
    mWaypointTexture.pi = nullptr;
    mArrowheadTexture.px = nullptr;
    mArrowheadTexture.pi = nullptr;
  }

  /**
   * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Releases command-graph texture shared-control lanes in arrowhead, waypoint,
   * then orderline teardown order.
   */
  UICommandGraphNode::~UICommandGraphNode()
  {
    mArrowheadTexture.release();
    mWaypointTexture.release();
    mOrderlineTexture.release();
  }

  /**
   * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
   *
   * NOTE (2026-08-20 audit): all three texture-lane releases below previously
   * called `.weak_release()`. FUN_00825060 confirms all three inline copies of
   * the retain/release pattern call FUN_004229B0 for the release step
   * (verified by manual displacement calculation at 0x00825087, 0x0082510E,
   * 0x0082513B), which is `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()` to match.
   *
   * What it does:
   * Copies one command-graph style node payload, including shared-texture
   * control lanes for orderline/waypoint/arrowhead textures.
   */
  UICommandGraphNode* UICommandGraphNode::CopyFrom(const UICommandGraphNode& other)
  {
    mOrderlineTexture.px = other.mOrderlineTexture.px;
    boost::detail::sp_counted_base* incomingControl = other.mOrderlineTexture.pi;
    if (incomingControl != mOrderlineTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mOrderlineTexture.pi != nullptr) {
        mOrderlineTexture.pi->release();
      }
      mOrderlineTexture.pi = incomingControl;
    }

    mOrderlineAspectRatio = other.mOrderlineAspectRatio;
    mOrderlineAnimRate = other.mOrderlineAnimRate;
    mOrderlineColor = other.mOrderlineColor;
    mOrderlineSelectedColor = other.mOrderlineSelectedColor;
    mOrderlineHighlightColor = other.mOrderlineHighlightColor;
    mOrderlineGlow = other.mOrderlineGlow;
    mOrderlineSelectedGlow = other.mOrderlineSelectedGlow;
    mOrderlineHighlightGlow = other.mOrderlineHighlightGlow;
    mWaypointColor = other.mWaypointColor;
    mWaypointSelectedColor = other.mWaypointSelectedColor;
    mWaypointHighlightColor = other.mWaypointHighlightColor;
    mWaypointScale = other.mWaypointScale;
    mWaypointSelectedScale = other.mWaypointSelectedScale;
    mWaypointHighlightScale = other.mWaypointHighlightScale;
    mArrowheadCapOffset = other.mArrowheadCapOffset;

    mWaypointTexture.px = other.mWaypointTexture.px;
    incomingControl = other.mWaypointTexture.pi;
    if (incomingControl != mWaypointTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mWaypointTexture.pi != nullptr) {
        mWaypointTexture.pi->release();
      }
      mWaypointTexture.pi = incomingControl;
    }

    mArrowheadTexture.px = other.mArrowheadTexture.px;
    incomingControl = other.mArrowheadTexture.pi;
    if (incomingControl != mArrowheadTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mArrowheadTexture.pi != nullptr) {
        mArrowheadTexture.pi->release();
      }
      mArrowheadTexture.pi = incomingControl;
    }

    return this;
  }

  /**
   * Address: 0x00825570 (FUN_00825570)
   * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
   *
   * NOTE (2026-08-20 audit): all three texture-lane assignments below
   * (orderline/waypoint/arrowhead) previously called `.weak_release()` in the
   * shared `assignSharedLane` lambda. FUN_00825570 confirms all three call
   * sites (0x008256E4, 0x00825B26, 0x00825EF9, xref-verified) target
   * FUN_004229B0, i.e. `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()`; the lambda was renamed from
   * `assignWeakSharedLane` to match (function-local, no external callers).
   *
   * What it does:
   * Loads command-graph texture/style lanes from one Lua table entry, honoring
   * `inherit_from` recursion before overriding local orderline/waypoint/
   * arrowhead keys.
   */
  void UICommandGraphNode::LoadTextures(LuaPlus::LuaObject rootTable, const char* const key, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject nodeTable = rootTable[key];
    if (nodeTable.IsNil()) {
      return;
    }

    LuaPlus::LuaObject inheritFrom = nodeTable["inherit_from"];
    if (!inheritFrom.IsNil()) {
      LoadTextures(LuaPlus::LuaObject(rootTable), inheritFrom.GetString(), state);
    }

    const auto hasKey = [&nodeTable](const char* const fieldName) -> bool {
      LuaPlus::LuaObject probe = nodeTable[fieldName];
      return !probe.IsNil();
    };

    const auto assignSharedLane = [](
                                    boost::SharedPtrRaw<void>& destination,
                                    void* const sourcePx,
                                    boost::detail::sp_counted_base* const sourceControl
                                  ) {
      destination.px = sourcePx;
      if (sourceControl != destination.pi) {
        if (sourceControl != nullptr) {
          sourceControl->add_ref_copy();
        }
        if (destination.pi != nullptr) {
          destination.pi->release();
        }
        destination.pi = sourceControl;
      }
    };

    if (hasKey("orderline_texture")) {
      if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          LuaPlus::LuaObject textureValue = nodeTable["orderline_texture"];
          ID3DDeviceResources::TextureResourceHandle loadedTexture{};
          resources->GetTexture(loadedTexture, textureValue.GetString(), 0, true);

          const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
          assignSharedLane(mOrderlineTexture, loadedRaw.px, loadedRaw.pi);
        }
      }
    }

    if (hasKey("orderline_uv_aspect_ratio")) {
      mOrderlineAspectRatio = static_cast<float>(nodeTable["orderline_uv_aspect_ratio"].GetNumber());
    }

    if (hasKey("orderline_anim_rate")) {
      mOrderlineAnimRate = static_cast<float>(nodeTable["orderline_anim_rate"].GetNumber());
    }

    if (hasKey("orderline_color")) {
      mOrderlineColor = SCR_DecodeColor(state, nodeTable["orderline_color"]);
    }

    if (hasKey("orderline_selected_color")) {
      mOrderlineSelectedColor = SCR_DecodeColor(state, nodeTable["orderline_selected_color"]);
    }

    if (hasKey("orderline_highlight_color")) {
      mOrderlineHighlightColor = SCR_DecodeColor(state, nodeTable["orderline_highlight_color"]);
    }

    if (hasKey("orderline_glow")) {
      mOrderlineGlow = static_cast<float>(nodeTable["orderline_glow"].GetNumber());
    }

    if (hasKey("orderline_selected_glow")) {
      mOrderlineSelectedGlow = static_cast<float>(nodeTable["orderline_selected_glow"].GetNumber());
    }

    if (hasKey("orderline_highlight_glow")) {
      mOrderlineHighlightGlow = static_cast<float>(nodeTable["orderline_highlight_glow"].GetNumber());
    }

    if (hasKey("waypoint_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["waypoint_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mWaypointTexture, loadedRaw.px, loadedRaw.pi);
    }

    if (hasKey("waypoint_color")) {
      mWaypointColor = SCR_DecodeColor(state, nodeTable["waypoint_color"]);
    }

    if (hasKey("waypoint_selected_color")) {
      mWaypointSelectedColor = SCR_DecodeColor(state, nodeTable["waypoint_selected_color"]);
    }

    if (hasKey("waypoint_highlight_color")) {
      mWaypointHighlightColor = SCR_DecodeColor(state, nodeTable["waypoint_highlight_color"]);
    }

    if (hasKey("waypoint_scale")) {
      mWaypointScale = static_cast<float>(nodeTable["waypoint_scale"].GetNumber());
    }

    if (hasKey("waypoint_selected_scale")) {
      mWaypointSelectedScale = static_cast<float>(nodeTable["waypoint_selected_scale"].GetNumber());
    }

    if (hasKey("waypoint_highlight_scale")) {
      mWaypointHighlightScale = static_cast<float>(nodeTable["waypoint_highlight_scale"].GetNumber());
    }

    if (hasKey("arrowhead_cap_offset")) {
      mArrowheadCapOffset = static_cast<float>(nodeTable["arrowhead_cap_offset"].GetNumber());
    }

    if (hasKey("arrowhead_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["arrowhead_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mArrowheadTexture, loadedRaw.px, loadedRaw.pi);
    }
  }

  /**
   * Address: 0x00824600 (FUN_00824600, sub_824600)
   *
   * What it does:
   * Seeds a fresh draw node in the binary's store order: `mCommandId = -1`,
   * the helper link nulled, the +0x0C..+0x18 float run zeroed, the two
   * flag bytes cleared and `mIsVisible = 1` (+0x1E; the pad byte at +0x1F is
   * not written), no mesh, the +0x28..+0x44 run zeroed, then both lanes armed
   * on their inline windows. It was a free function over a padded 0x78-byte
   * view that the map insertion then reinterpreted as this
   * type.
   *
   * Each edge vector has one inline slot, as the +4 capacity stores prove.
   */
  UICommandGraph::UICommandGraphDrawNode::UICommandGraphDrawNode()
    : mCommandId(-1)
    , mHelperLink()
    , mPositionSum(0.0f, 0.0f, 0.0f)
    , mWeight(0.0f)
    , mHasResolvedPosition(0u)
    , mIsChainBoundary(0u)
    , mIsVisible(1u)
    , mMeshInstance{}
    , mOrientationHint(0.0f, 0.0f, 0.0f)
    , mPreviousCentroid(0.0f, 0.0f, 0.0f)
    , mUnitCountScale(0.0f)
    , mCompletionTick(0u)
    , mLaneA()
    , mLaneB()
  {}

  /**
   * Address: 0x00826550 (FUN_00826550)
   *
   * What it does:
   * Destroys outgoing then incoming edges, releases the mesh, and unlinks
   * the helper reference through the members' normal reverse destruction.
   */
  UICommandGraph::UICommandGraphDrawNode::~UICommandGraphDrawNode() = default;

  std::size_t UICommandGraph::EdgeKeyHashCompare::operator()(const DrawNodePair& key) const noexcept
  {
    const auto fromAddress = reinterpret_cast<std::uintptr_t>(key.first);
    const auto toAddress = reinterpret_cast<std::uintptr_t>(key.second);
    // Hash only: retain the binary's 32-bit combine; equality uses full pointers.
    const auto combined = static_cast<std::uint32_t>(
      3863u * fromAddress + 7919u * toAddress + 53849u * (fromAddress ^ toAddress)
    );
    return fa::hash_value(static_cast<long>(combined));
  }

  bool UICommandGraph::EdgeKeyHashCompare::operator()(const DrawNodePair& lhs, const DrawNodePair& rhs) const noexcept
  {
    const std::less<UICommandGraphDrawNode*> less;
    return less(lhs.first, rhs.first) || (!less(rhs.first, lhs.first) && less(lhs.second, rhs.second));
  }

  /**
   * Address: 0x008300D0 (FUN_008300D0)
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AllocateTreeSentinelNode()
  {
    auto* const node = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    std::memset(static_cast<void*>(node), 0, sizeof(CommandGraphTreeNode));
    node->mColorOrAllocated = 1u;
    node->mIsSentinel = 0u;
    return node;
  }

  void UICommandGraph::InitTree(CommandGraphTree& tree)
  {
    tree.mAllocProxy = nullptr;
    tree.mHead = AllocateTreeSentinelNode();
    tree.mHead->mIsSentinel = 1u;
    tree.mHead->mLeft = tree.mHead;
    tree.mHead->mParent = tree.mHead;
    tree.mHead->mRight = tree.mHead;
    tree.mSize = 0u;
  }

  /**
   * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
   */
  void UICommandGraph::ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept
  {
    if (bucket.mEdges.data() != nullptr) {
      ::operator delete(bucket.mEdges.data());
    }
    bucket.mEdges.release_storage_without_free();
    bucket.mTexture.release();
  }

  /**
   * Address: 0x0082CDE0 (FUN_0082CDE0, sub_82CDE0, `DestroyTree`'s copy of this walk)
   */
  void UICommandGraph::DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* const sentinelHead, CommandGraphTreeNode* node)
  {
    if (node == nullptr || node == sentinelHead || node->mIsSentinel != 0u) {
      return;
    }

    DestroyCommandGraphTreeSubtree(sentinelHead, node->mRight);
    CommandGraphTreeNode* const left = node->mLeft;
    ReleaseCommandGraphTreeBucket(node->mBucket);
    ::operator delete(node);
    DestroyCommandGraphTreeSubtree(sentinelHead, left);
  }

  /**
   * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
   *
   * What it does:
   * Destroys command-graph runtime tree nodes rooted at `mHead->mParent`,
   * releasing each node's bucket resources first, then releases the head
   * sentinel and clears head/size lanes.
   */
  void UICommandGraph::DestroyTree(CommandGraphTree& tree)
  {
    if (tree.mHead) {
      DestroyCommandGraphTreeSubtree(tree.mHead, tree.mHead->mParent);
      ::operator delete(tree.mHead);
    }

    tree.mHead = nullptr;
    tree.mSize = 0u;
    tree.mAllocProxy = nullptr;
  }
namespace
{

  // Forward declarations: reopens the same file-scope anonymous namespace
  // that defines these two sentinel-headed RB-tree walkers further below,
  // so `AttachCommandGraphNodeUnique`/`AttachCommandGraphNodeHinted`
  // below - the first command-graph callers that need them - can call them
  // here, ahead of their point of definition (mirrors the later reopening
  // for `DrawCommandGraphMesh`'s own needs).
      template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node);
}


  /**
   * Address: 0x0082D330 (FUN_0082D330, sub_82D330) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeBucket* UICommandGraph::InitCommandGraphTreeBucketValue(
    CommandGraphTreeBucket* const destination, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    ::new (static_cast<void*>(destination)) CommandGraphTreeBucket();
    destination->mTexture = texture.clone_retained();
    return destination;
  }

  /**
   * Address: 0x00830010 (FUN_00830010) - see the declaration's doc comment.
   */
  void UICommandGraph::PivotCommandGraphTreeLeft(CommandGraphTree& tree, CommandGraphTreeNode* const n) noexcept
  {
    CommandGraphTreeNode* const pivot = n->mRight;
    n->mRight = pivot->mLeft;
    if (pivot->mLeft->mIsSentinel == 0u) {
      pivot->mLeft->mParent = n;
    }
    pivot->mParent = n->mParent;

    if (n == tree.mHead->mParent) {
      tree.mHead->mParent = pivot;
    } else if (n == n->mParent->mLeft) {
      n->mParent->mLeft = pivot;
    } else {
      n->mParent->mRight = pivot;
    }

    pivot->mLeft = n;
    n->mParent = pivot;
  }

  /**
   * Address: 0x00830080 (FUN_00830080) - see the declaration's doc comment.
   */
  void UICommandGraph::PivotCommandGraphTreeRight(CommandGraphTree& tree, CommandGraphTreeNode* const n) noexcept
  {
    CommandGraphTreeNode* const pivot = n->mLeft;
    n->mLeft = pivot->mRight;
    if (pivot->mRight->mIsSentinel == 0u) {
      pivot->mRight->mParent = n;
    }
    pivot->mParent = n->mParent;

    if (n == tree.mHead->mParent) {
      tree.mHead->mParent = pivot;
    } else if (n == n->mParent->mRight) {
      n->mParent->mRight = pivot;
    } else {
      n->mParent->mLeft = pivot;
    }

    pivot->mRight = n;
    n->mParent = pivot;
  }

  /**
   * Address: 0x0082E320 (FUN_0082E320, sub_82E320) - see the declaration's
   * doc comment. `0xAAAAAA9u` is this map's own `max_size() - 1u` bound for
   * its 0x18-byte `pair<shared_ptr<ID3DTextureSheet>, vector<CommandGraphEdge*>>`
   * value_type (`0xFFFFFFFF / 0x18 - 1 == 0xAAAAAA9`), already confirmed
   * against this exact instantiation in `legacy/containers/RbTree.h`'s
   * `insert_at` citation.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeAt(
    CommandGraphTree& tree, const bool addLeft, CommandGraphTreeNode* const where,
    const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    if (0xAAAAAA9u <= tree.mSize) {
      EngineThrowContainerTooLong("map/set<T> too long");
    }

    auto* const fresh = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    fresh->mLeft = tree.mHead;
    fresh->mParent = tree.mHead;
    fresh->mRight = tree.mHead;
    fresh->mColorOrAllocated = 0u; // kRbRed
    fresh->mIsSentinel = 0u;
    try {
      InitCommandGraphTreeBucketValue(&fresh->mBucket, texture);
    } catch (...) {
      ::operator delete(fresh);
      throw;
    }

    ++tree.mSize;
    if (where == tree.mHead) {
      tree.mHead->mParent = fresh;
      tree.mHead->mLeft = fresh;
      tree.mHead->mRight = fresh;
    } else if (addLeft) {
      where->mLeft = fresh;
      if (where == tree.mHead->mLeft) {
        tree.mHead->mLeft = fresh;
      }
    } else {
      where->mRight = fresh;
      if (where == tree.mHead->mRight) {
        tree.mHead->mRight = fresh;
      }
    }
    fresh->mParent = where;

    for (CommandGraphTreeNode* n = fresh; n->mParent->mColorOrAllocated == 0u;) {
      CommandGraphTreeNode* const parent = n->mParent;
      CommandGraphTreeNode* const grand = parent->mParent;

      if (parent == grand->mLeft) {
        CommandGraphTreeNode* const uncle = grand->mRight;
        if (uncle->mColorOrAllocated == 0u) {
          parent->mColorOrAllocated = 1u;
          uncle->mColorOrAllocated = 1u;
          grand->mColorOrAllocated = 0u;
          n = grand;
        } else {
          if (n == parent->mRight) {
            n = parent;
            PivotCommandGraphTreeLeft(tree, n);
          }
          n->mParent->mColorOrAllocated = 1u;
          n->mParent->mParent->mColorOrAllocated = 0u;
          PivotCommandGraphTreeRight(tree, n->mParent->mParent);
        }
      } else {
        CommandGraphTreeNode* const uncle = grand->mLeft;
        if (uncle->mColorOrAllocated == 0u) {
          parent->mColorOrAllocated = 1u;
          uncle->mColorOrAllocated = 1u;
          grand->mColorOrAllocated = 0u;
          n = grand;
        } else {
          if (n == parent->mLeft) {
            n = parent;
            PivotCommandGraphTreeRight(tree, n);
          }
          n->mParent->mColorOrAllocated = 1u;
          n->mParent->mParent->mColorOrAllocated = 0u;
          PivotCommandGraphTreeLeft(tree, n->mParent->mParent);
        }
      }
    }

    tree.mHead->mParent->mColorOrAllocated = 1u; // root()->color = black
    return fresh;
  }

  /**
   * Address: 0x0082E170 (FUN_0082E170, sub_82E170) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeUnique(
    CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    CommandGraphTreeNode* where = tree.mHead;
    bool addLeft = true;
    for (CommandGraphTreeNode* node = tree.mHead->mParent; node->mIsSentinel == 0u;) {
      where = node;
      addLeft = texture.pi < node->mBucket.mTexture.pi;
      node = addLeft ? node->mLeft : node->mRight;
    }

    CommandGraphTreeNode* probe = where;
    if (addLeft) {
      if (where == tree.mHead->mLeft) {
        return AttachCommandGraphNodeAt(tree, true, where, texture);
      }
      probe = PrevTreeNode(where);
    }

    if (probe->mBucket.mTexture.pi < texture.pi) {
      return AttachCommandGraphNodeAt(tree, addLeft, where, texture);
    }
    return probe;
  }

  /**
   * Address: 0x0082CC80 (FUN_0082CC80, sub_82CC80) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeHinted(
    CommandGraphTree& tree, CommandGraphTreeNode* const hint, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    if (tree.mSize == 0u) {
      return AttachCommandGraphNodeAt(tree, true, tree.mHead, texture);
    }

    if (hint == tree.mHead->mLeft) {
      if (texture.pi < hint->mBucket.mTexture.pi) {
        return AttachCommandGraphNodeAt(tree, true, hint, texture);
      }
    } else if (hint->mIsSentinel != 0u) {
      CommandGraphTreeNode* const rightmost = tree.mHead->mRight;
      if (rightmost->mBucket.mTexture.pi < texture.pi) {
        return AttachCommandGraphNodeAt(tree, false, rightmost, texture);
      }
    } else if (texture.pi < hint->mBucket.mTexture.pi) {
      CommandGraphTreeNode* const before = PrevTreeNode(hint);
      if (before->mBucket.mTexture.pi < texture.pi) {
        return (before->mRight->mIsSentinel != 0u) ? AttachCommandGraphNodeAt(tree, false, before, texture)
                                                     : AttachCommandGraphNodeAt(tree, true, hint, texture);
      }
    } else if (hint->mBucket.mTexture.pi < texture.pi) {
      CommandGraphTreeNode* const after = NextTreeNode(hint);
      if (after->mIsSentinel != 0u || texture.pi < after->mBucket.mTexture.pi) {
        return (hint->mRight->mIsSentinel != 0u) ? AttachCommandGraphNodeAt(tree, false, hint, texture)
                                                  : AttachCommandGraphNodeAt(tree, true, after, texture);
      }
    }

    return AttachCommandGraphNodeUnique(tree, texture);
  }

  /**
   * Address: 0x0082B8B0 (FUN_0082B8B0, sub_82B8B0) - see the declaration's
   * doc comment.
   */
  fa::vector<UICommandGraph::CommandGraphEdge*>& UICommandGraph::FindOrInsertCommandGraphBucket(
    CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    CommandGraphTreeNode* candidate = tree.mHead;
    for (CommandGraphTreeNode* node = tree.mHead->mParent; node->mIsSentinel == 0u;) {
      if (texture.pi <= node->mBucket.mTexture.pi) {
        candidate = node;
        node = node->mLeft;
      } else {
        node = node->mRight;
      }
    }

    if (candidate != tree.mHead && !(texture.pi < candidate->mBucket.mTexture.pi)) {
      return candidate->mBucket.mEdges;
    }

    CommandGraphTreeNode* const inserted = AttachCommandGraphNodeHinted(tree, candidate, texture);
    return inserted->mBucket.mEdges;
  }

  /**
   * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
   */
  void UICommandGraph::OnCommandGraphShow(LuaPlus::LuaState* const state, const bool visible)
  {
    try {
      const LuaPlus::LuaObject commandGraph = SCR_Import(state, "/lua/ui/game/commandgraph.lua");
      const LuaPlus::LuaFunction<> onShow{commandGraph["OnCommandGraphShow"]};
      onShow.Call_Bool(visible);
    } catch (const std::exception& error) {
      gpg::Warnf("Error running '/lua/ui/game/commandgraph.lua:OnCommandGraphShow': %s", error.what());
    }
  }

  /**
   * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
   *
   * IDA signature:
   * void __stdcall Moho::UICommandGraph::LoadPathParams(Moho::UICommandGraph *a1);
   *
   * What it does:
   * Imports `/lua/ui/game/commandgraphparams.lua` on the UI Lua state, builds
   * one node from its `default` entry, then gives every command type its own
   * node: the default is copied in first, and the per-type entry (keyed
   * `<enum prefix><lexical name>`, e.g. `UNITCOMMAND_Attack`) is layered over
   * it. A command type with no entry in the table keeps the default.
   */
  void UICommandGraph::LoadPathParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandgraphparams.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandGraphParams"];
    if (!params.IsTable()) {
      return;
    }

    // 0x00824DE9 open-codes the node constructor here rather than calling it.
    UICommandGraphNode defaults{};
    defaults.LoadTextures(params, "default", state);

    for (std::int32_t index = 0; index < static_cast<std::int32_t>(std::size(mNodes)); ++index) {
      (void)mNodes[index].CopyFrom(defaults);

      auto commandType = static_cast<EUnitCommandType>(index);
      gpg::RRef commandTypeRef{};
      commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&commandType);

      // The reflected type is always the EUnitCommandType enum descriptor, so
      // the binary reads `mPrefix` straight off it at 0x00824F3E rather than
      // going through the IsEnumType() virtual.
      const auto* const enumType = static_cast<const gpg::REnumType*>(commandTypeRef.mType);
      const fa::string lexicalName = commandTypeRef.GetLexical();
      const fa::string key = gpg::STR_Printf("%s%s", enumType->mPrefix, lexicalName.c_str());

      mNodes[index].LoadTextures(params, key.c_str(), state);
    }
  }

  /**
   * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
   *
   * IDA signature:
   * LuaPlus::LuaObject *sub_825150();
   *
   * What it does:
   * Imports `/lua/ui/game/commandwaypoint.lua` on the UI Lua state and copies
   * its `CommandWaypointParams` table into the seven command-waypoint globals.
   * Each key is optional: a missing or nil entry leaves the global at whatever
   * the previous import (or image load) left there.
   */
  void UICommandGraph::LoadWaypointParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandwaypoint.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandWaypointParams"];
    if (!params.IsTable()) {
      return;
    }

    // The binary re-reads each key after the nil test rather than reusing the
    // probe object, and tests every key even once one is missing.
    if (!params["ui_CurveSegments"].IsNil()) {
      ui_CurveSegments = static_cast<std::int32_t>(params["ui_CurveSegments"].GetNumber());
    }
    if (!params["ui_CurveSmoothness"].IsNil()) {
      ui_CurveSmoothness = static_cast<float>(params["ui_CurveSmoothness"].GetNumber());
    }
    if (!params["ui_PathSmoothness"].IsNil()) {
      ui_PathSmoothness = static_cast<float>(params["ui_PathSmoothness"].GetNumber());
    }
    if (!params["ui_CommandGraphMaxNodeUnits"].IsNil()) {
      ui_CommandGraphMaxNodeUnits =
        static_cast<std::int32_t>(params["ui_CommandGraphMaxNodeUnits"].GetNumber());
    }
    if (!params["ui_MinWaypointSize"].IsNil()) {
      ui_MinWaypointSize = static_cast<float>(params["ui_MinWaypointSize"].GetNumber());
    }
    if (!params["ui_MaxWaypointSize"].IsNil()) {
      ui_MaxWaypointSize = static_cast<float>(params["ui_MaxWaypointSize"].GetNumber());
    }
    if (!params["ui_WaypointLineScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_WaypointLineScale"].GetNumber());
    }

    // Not a transcription slip: 0x00825524 stores the `ui_CommandClickScale`
    // value into `ui_WaypointLineScale` (0x00F57CDC), the same global the
    // block above writes. There is no `ui_CommandClickScale` symbol in the
    // image at all, so whichever of the two keys the Lua table defines last
    // wins the line scale. Preserved because the original does it.
    if (!params["ui_CommandClickScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_CommandClickScale"].GetNumber());
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::CreateBuildPreviewMesh(UICommandGraphDrawNode& drawNode, UICommandGraph& graph)
  {
    // 0x008274D7 hands CreateMeshInstance an opaque green, then 0x008274FB
    // immediately overwrites the instance's own colour lane with the
    // alpha-0xD8 shade the placement ghost actually draws in.
    constexpr std::int32_t kPreviewCreateColor = static_cast<std::int32_t>(0xFF00FF00u);
    constexpr std::int32_t kPreviewTranslucentGreen = static_cast<std::int32_t>(0xD800D800u);

    // Already has its ghost - the mesh outlives the rebuild that made it.
    if (drawNode.mMeshInstance != nullptr) {
      return;
    }

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    // Only a queued mobile build produces a unit to preview; every other order
    // type draws with waypoint markers and orderlines alone.
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile) {
      return;
    }

    const REntityBlueprint* const entityBlueprint = helper->mConstantData.blueprint;
    if (entityBlueprint == nullptr) {
      return;
    }

    const RUnitBlueprint* const unitBlueprint = entityBlueprint->IsUnitBlueprint();
    if (unitBlueprint == nullptr) {
      return;
    }

    RMeshBlueprint* const meshBlueprint =
      graph.mSession->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
    if (meshBlueprint == nullptr) {
      return;
    }

    const float uniformScale = unitBlueprint->Display.UniformScale;
    const Wm3::Vec3f previewScale{uniformScale, uniformScale, uniformScale};

    // 0x008273F1 loads `mLods.first_` once and addresses the LOD's texture
    // names off it (+0x1C/+0x38/+0x54) with no empty-vector guard - a mesh
    // blueprint that resolved this far always carries at least one LOD.
    const RMeshBlueprintLOD* const lod = meshBlueprint->mLods.begin();

    // The ghost keeps the LOD's real albedo/normals/specular maps but swaps the
    // shader for "UnitPlace"; the lookup and secondary slots stay empty. This
    // is why the six-string Create overload is called directly instead of the
    // `Create(const RMeshBlueprintLOD&, ...)` one, which would carry
    // `lod->mShaderName` through.
    const fa::string shaderName("UnitPlace");
    const fa::string emptyLookupName;
    const fa::string emptySecondaryName;
    const boost::shared_ptr<MeshMaterial> material = MeshMaterial::Create(
      shaderName,
      lod->mAlbedoName,
      lod->mNormalsName,
      lod->mSpecularName,
      emptyLookupName,
      emptySecondaryName,
      nullptr
    );

    MeshInstance* const meshInstance = MeshRenderer::GetInstance()->CreateMeshInstance(
      graph.mSession->mGameTick, kPreviewCreateColor, meshBlueprint, previewScale, false, material
    );

    drawNode.mMeshInstance.reset(meshInstance);
    drawNode.mMeshInstance->color = kPreviewTranslucentGreen;

    // The binary builds the stance at the origin (0x00827514..0x00827532) and
    // only afterwards divides the node's accumulated position by its weight,
    // storing the centroid straight into the transform's translation lane - so
    // the zero vector here is the constructor argument the original passed, not
    // a placeholder.
    VTransform stance{Wm3::Vec3f{0.0f, 0.0f, 0.0f}, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
    const float invWeight = 1.0f / drawNode.mWeight;
    stance.pos_ = Wm3::Vec3f{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    // Same transform as both start and end: the placement ghost snaps to the
    // order's position rather than interpolating toward it.
    drawNode.mMeshInstance->SetStance(stance, stance);
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::CreateMeshes()
  {
    bool rebuilt = false;
    if (mNeedsRebuild != 0u) {
      mNeedsRebuild = 0u;
      RebuildCommandQueueNodes();
      RecomputeAllDrawNodeOrientations();
      rebuilt = true;
    }

    for (auto& entry : mMapAB0) {
      UICommandGraphDrawNode& drawNode = entry.second;

      // Commands retire and are re-issued between frames while their draw node
      // survives, so a node that is currently chained to *some* helper is
      // re-pointed at whichever helper owns its command id right now. A node
      // with no chain membership at all is left alone - it never had an owner
      // and the rebuild pass is what gives it one.
      if (drawNode.mHelperLink.HasValue()) {
        drawNode.mHelperLink.ResetFromObject(FindCommandIssueHelperInSession(mSession, drawNode.mCommandId));
      }

      // First time this node resolves to a live command, seed its anchor from
      // the command's own history. `mWeight` becomes 1 because this table keys
      // one node per command - the centroid is that single position, unlike the
      // queue-head table where the weight counts the units sharing the queue.
      if (drawNode.mHelperLink.HasValue() && drawNode.mHasResolvedPosition == 0u) {
        drawNode.mPositionSum = ResolveCommandGraphAnchorWorldPosition(*drawNode.mHelperLink.GetObjectPtr());
        drawNode.mWeight = 1.0f;
      }
    }

    if (rebuilt) {
      for (auto& entry : mMapAB0) {
        ResolveDrawNodeCompletionTick(entry.second);
      }

      for (auto& entry : mMapAB0) {
        CreateBuildPreviewMesh(entry.second, *this);
      }
    }

    // The binary inlines `MAUI_KeyIsDown` (0x0079CB70) here in full - the
    // foreground test, the focus-owner guard and the `wxCharCodeWXToMSW` +
    // `GetKeyState` sign test at 0x0082911C..0x0082915D are that function's
    // three steps, in its order.
    if (ui_PathPreview) {
      CON_Executef("path_GeneratePreview %s", MAUI_KeyIsDown(MKEY_SHIFT) ? "end" : "start");
    }
  }

  /**
   * `LinkCommandGraphEdge` (0x00826960) and `AddCommandQueueToCommandGraph`
   * (0x00826140) are both defined later in this file, after
   * `LowerBoundWeakEntitySetNode`/`ResolveCommandIssueTarget`/
   * `ResolveCommandGraphAnchorWorldPosition` and the rest of the
   * command-issue-history helper cluster they call - see the doc comment on
   * `AddCommandQueueToCommandGraph`'s real definition for the full address
   * decomposition. `RebuildCommandQueueNodes` below still calls
   * `AddCommandQueueToCommandGraph` by name; that resolves through the
   * `friend` declarations on `UICommandGraph` (found via ADL on the
   * `UICommandGraph&` argument), so textual order here does not matter.
   */

  /**
   * Address: 0x00826C50 (FUN_00826C50, sub_826C50)
   *
   * IDA signature:
   * int __stdcall sub_826C50(Moho::UICommandGraph::CommandGraphEdge *edge);
   *
   * What it does:
   * Travel time in game ticks along one orderline: the distance between the two
   * endpoint centroids divided by the slowest speed among the units the command
   * targets (air units use `Air.MaxAirspeed`, everything else
   * `Physics.MaxSpeed`), at 10 ticks per second, rounded up. Returns 0 for
   * command types that do not involve movement.
   *
   * Body below, after the anonymous-namespace helpers it uses.
   */
  [[nodiscard]] std::int32_t EstimateEdgeTravelTicks(const UICommandGraph::CommandGraphEdge& edge);

  /**
   * What it does: see the header.
   */
  void UICommandGraph::RebuildCommandQueueNodes()
  {
    PrepareForRebuild();

    // Heap-backed on purpose, like every other `Collect` site - see the note in
    // `DoBeat` for the full reasoning. The binary's local here really is a
    // 400-byte inline stack buffer, but `Collect` takes its destination by the
    // `gpg::fastvector<T>` base, and the base's grow path frees `start_`
    // unconditionally because it has no `originalVec_` word to test against.
    // An inline `FastVectorN` therefore hands `operator delete` a stack address
    // the first time more than 100 units are on screen - observed as
    // push_back -> PushBack -> Reserve -> FreeElements -> free faulting while
    // the Shift command graph rebuilt its nodes. The inline lane can come back
    // once the binary's per-vector-type collect template is restored.
    gpg::fastvector<UserEntity*> entities;
    (void)mSession->GetEntitySpatialDbStorage()
      ->Collect(entities, ENTITYTYPE_Unit);

    for (UserEntity* const entity : entities) {
      if (entity == nullptr) {
        continue;
      }

      // Wall segments, walls and other decorative units never contribute an
      // order line even when they carry a queue.
      if (entity->IsInCategory(fa::string{"INSIGNIFICANTUNIT", 17u})) {
        continue;
      }

      AddCommandQueueToCommandGraph(*entity, *this, entity->GetCommandQueue());

      // A stationary factory's build queue is a second, separate order chain -
      // mobile factories (engineers, hives) carry theirs on the normal queue
      // above and must not be folded in twice.
      const bool isFactory = entity->IsInCategory(fa::string{"FACTORY", 7u});
      const bool isMobileFactory = isFactory && entity->IsInCategory(fa::string{"MOBILE", 6u});
      if (isFactory && !isMobileFactory) {
        AddCommandQueueToCommandGraph(*entity, *this, entity->GetFactoryCommandQueue());
      }
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::ResolveDrawNodeCompletionTick(UICommandGraphDrawNode& drawNode)
  {
    // Non-zero means "already solved this pass". Seeding it with the current
    // tick before recursing is what makes a cyclic order graph terminate: a
    // node reached again while it is still being solved returns immediately.
    if (drawNode.mCompletionTick != 0u) {
      return;
    }

    drawNode.mCompletionTick = static_cast<std::uint32_t>(mSession->mGameTick);

    std::uint32_t startTick = static_cast<std::uint32_t>(mSession->mGameTick);
    const std::int32_t incomingCount = static_cast<std::int32_t>(drawNode.mLaneA.Size());
    for (std::int32_t index = 0; index < incomingCount; ++index) {
      auto* const edge = drawNode.mLaneA[static_cast<std::size_t>(index)];
      UICommandGraphDrawNode* const predecessor = edge->mFromNode;
      if (predecessor != nullptr) {
        ResolveDrawNodeCompletionTick(*predecessor);
        const std::uint32_t readyTick =
          predecessor->mCompletionTick + static_cast<std::uint32_t>(EstimateEdgeTravelTicks(*edge));
        if (startTick < readyTick) {
          startTick = readyTick;
        }
      }
    }

    const std::uint32_t finishTick =
      startTick + static_cast<std::uint32_t>(EstimateDrawNodeWorkTicks(*this, drawNode));

    // The already-stored tick winning means this order costs nothing and has no
    // unfinished predecessor; the binary still steps it back by one so the node
    // sorts before whatever depends on it.
    if (drawNode.mCompletionTick >= finishTick) {
      drawNode.mCompletionTick = drawNode.mCompletionTick - 1u;
    } else {
      drawNode.mCompletionTick = finishTick;
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::PrepareForRebuild()
  {
    mMapC.clear();

    // Texture-keyed orderline tree: free every bucket, then re-empty the
    // sentinel in place. Unlike `DestroyTree` the head survives - the rebuild
    // pass immediately refills the tree through it.
    DestroyCommandGraphTreeSubtree(mCommandGraphTree.mHead, mCommandGraphTree.mHead->mParent);
    mCommandGraphTree.mHead->mParent = mCommandGraphTree.mHead;
    mCommandGraphTree.mSize = 0u;
    mCommandGraphTree.mHead->mLeft = mCommandGraphTree.mHead;
    mCommandGraphTree.mHead->mRight = mCommandGraphTree.mHead;

    // Draw nodes survive a rebuild; only the edge lanes they own are dropped,
    // back to inline storage so the common single-edge case never re-allocates.
    for (auto& entry : mMapAB0) {
      entry.second.mLaneA.ResetStorageToInline();
      entry.second.mLaneB.ResetStorageToInline();
    }

    // Queue-head nodes additionally lose their accumulated centroid: the
    // rebuild re-adds one weighted position per unit sharing the queue, so
    // leaving the old sum in place would double-count every frame.
    for (auto& entry : mMapAB1) {
      entry.second.mLaneA.ResetStorageToInline();
      entry.second.mLaneB.ResetStorageToInline();
      entry.second.mPositionSum = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
      entry.second.mWeight = 0.0f;
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::RecomputeAllDrawNodeOrientations()
  {
    for (auto& entry : mMapAB1) {
      RecomputeDrawNodeOrientation(entry.second);
    }

    for (auto& entry : mMapAB0) {
      RecomputeDrawNodeOrientation(entry.second);
    }
  }
namespace
{
    /**
     * One lane's contribution to a draw node's orderline tangent.
     *
     * Both lanes accumulate the same way - the only differences are which
     * endpoint of each edge is the "far" one and which distribution field
     * records the ribbon offset - so the shared mechanic is lifted here rather
     * than written twice. `lengthSquared` is supplied by the caller because the
     * binary sums the three squares in a different component order per lane and
     * float addition is not associative.
     */
    struct DrawNodeOrientationAccumulator
    {
      Wm3::Vector3f mDirectionSum{0.0f, 0.0f, 0.0f};
      std::int32_t mUnitTotal = 0;
    };

    /**
     * The node's centroid: draw nodes accumulate a position *sum* plus a weight
     * so several units sharing one queue average into a single anchor.
     */
    [[nodiscard]] Wm3::Vector3f DrawNodeCentroid(
      const moho::UICommandGraph::UICommandGraphDrawNode& drawNode
    ) noexcept
    {
      const float inverseWeight = 1.0f / drawNode.mWeight;
      return Wm3::Vector3f{
        drawNode.mPositionSum.x * inverseWeight,
        drawNode.mPositionSum.y * inverseWeight,
        drawNode.mPositionSum.z * inverseWeight
      };
    }

    /**
     * Where one edge sits across its lane's ribbon bundle, in [-0.5, +0.5].
     * A lane of one edge yields -0.5 rather than 0 because the binary clamps
     * the divisor, not the result.
     */
    [[nodiscard]] float LaneBundleDistribution(const std::int32_t index, const float laneSpan) noexcept
    {
      const float divisor = (laneSpan < 1.0f) ? 1.0f : laneSpan;
      return (static_cast<float>(index) / divisor) - 0.5f;
    }
}


  /**
   * What it does: see the header.
   */
  void UICommandGraph::RecomputeDrawNodeOrientation(UICommandGraphDrawNode& drawNode)
  {
    const std::int32_t maxNodeUnits = ui_CommandGraphMaxNodeUnits;
    const Wm3::Vector3f centroid = DrawNodeCentroid(drawNode);

    // Lane A holds the edges this node is the *destination* of, so the far
    // endpoint is each edge's `mFromNode` and the direction points inbound.
    DrawNodeOrientationAccumulator laneA{};
    {
      const std::int32_t count = static_cast<std::int32_t>(drawNode.mLaneA.Size());
      const float laneSpan = static_cast<float>(count) - 1.0f;
      for (std::int32_t index = 0; index < count; ++index) {
        auto* const edge = drawNode.mLaneA[static_cast<std::size_t>(index)];
        const Wm3::Vector3f farCentroid = DrawNodeCentroid(*edge->mFromNode);

        float dx = centroid.x - farCentroid.x;
        float dy = centroid.y - farCentroid.y;
        float dz = centroid.z - farCentroid.z;

        const std::int32_t edgeUnits =
          (static_cast<std::int32_t>(edge->mTouchCount) >= maxNodeUnits)
            ? maxNodeUnits
            : static_cast<std::int32_t>(edge->mTouchCount);

        const float lengthSquared = ((dx * dx) + (dy * dy)) + (dz * dz);
        if (lengthSquared > 0.0f) {
          const float scale = static_cast<float>(edgeUnits) / std::sqrt(lengthSquared);
          dx = dx * scale;
          dy = dy * scale;
          dz = scale * dz;
        }

        laneA.mDirectionSum.x += dx;
        laneA.mDirectionSum.y += dy;
        laneA.mDirectionSum.z += dz;
        laneA.mUnitTotal += edgeUnits;

        edge->mLaneADistribution = LaneBundleDistribution(index, laneSpan);
      }
    }

    // Lane B holds the edges leaving this node, so the far endpoint is each
    // edge's `mToNode` and the direction points outbound.
    DrawNodeOrientationAccumulator laneB{};
    {
      const std::int32_t count = static_cast<std::int32_t>(drawNode.mLaneB.Size());
      const float laneSpan = static_cast<float>(count) - 1.0f;
      for (std::int32_t index = 0; index < count; ++index) {
        auto* const edge = drawNode.mLaneB[static_cast<std::size_t>(index)];
        const Wm3::Vector3f farCentroid = DrawNodeCentroid(*edge->mToNode);

        float dx = farCentroid.x - centroid.x;
        float dy = farCentroid.y - centroid.y;
        float dz = farCentroid.z - centroid.z;

        const std::int32_t edgeUnits =
          (static_cast<std::int32_t>(edge->mTouchCount) >= maxNodeUnits)
            ? maxNodeUnits
            : static_cast<std::int32_t>(edge->mTouchCount);

        // Component order differs from lane A's sum above; preserved because
        // float addition is not associative and this is the binary's order.
        const float lengthSquared = ((dz * dz) + (dy * dy)) + (dx * dx);
        if (lengthSquared > 0.0f) {
          const float scale = static_cast<float>(edgeUnits) / std::sqrt(lengthSquared);
          dx = dx * scale;
          dy = dy * scale;
          dz = scale * dz;
        }

        laneB.mDirectionSum.x += dx;
        laneB.mDirectionSum.y += dy;
        laneB.mDirectionSum.z += dz;
        laneB.mUnitTotal += edgeUnits;

        edge->mLaneBDistribution = LaneBundleDistribution(index, laneSpan);
      }
    }

    const float totalX = laneB.mDirectionSum.x + laneA.mDirectionSum.x;
    const float totalY = laneB.mDirectionSum.y + laneA.mDirectionSum.y;
    const float totalZ = laneB.mDirectionSum.z + laneA.mDirectionSum.z;

    const float length = std::sqrt(((totalZ * totalZ) + (totalY * totalY)) + (totalX * totalX));
    if (length <= kCommandGraphOrientationEpsilon) {
      drawNode.mOrientationHint = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    } else {
      const float inverseLength = 1.0f / length;
      drawNode.mOrientationHint =
        Wm3::Vector3f{totalX * inverseLength, totalY * inverseLength, totalZ * inverseLength};
    }

    const std::int32_t busierLaneUnits =
      (laneA.mUnitTotal < laneB.mUnitTotal) ? laneB.mUnitTotal : laneA.mUnitTotal;
    drawNode.mUnitCountScale = std::sqrt(static_cast<float>(busierLaneUnits));
  }

  /**
   * What it does: see the header.
   */
  UICommandGraph::ECommandNodeHighlightState UICommandGraph::ResolveDrawNodeHighlightState(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = drawNode.mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return ECommandNodeHighlightState::Normal;
    }

    if (UserEntity* const hoveredEntity = mSession->GetHoveredUserEntity(); hoveredEntity != nullptr) {
      if (UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit(); hoveredUnit != nullptr) {
        WeakSet<UserUnit>* const cursorEntities = ResolveCommandIssueCursorEntities(*ownerHelper);
        if (cursorEntities->Find(hoveredUnit) != cursorEntities->end()) {
          return ECommandNodeHighlightState::Highlighted;
        }
      }
    }

    if (ownerHelper->mConstantData.cmd == mSession->GetCursorInfo().mIsDragger) {
      return ECommandNodeHighlightState::Highlighted;
    }

    if (DrawNodeSharesLiveEntityWithSelection(drawNode)) {
      return ECommandNodeHighlightState::Selected;
    }

    return ECommandNodeHighlightState::Normal;
  }
namespace
{
    /**
     * Address: 0x00831110 (FUN_00831110)
     *
     * IDA signature:
     * bool __usercall sub_831110@<al>(Moho::WeakSet_UserUnit *units@<eax>,
     *     Moho::WeakSet_UserEntity *entities@<ecx>);
     *
     * What it does:
     * Whether a unit set and an entity set share a live member. Both are ordered
     * by address, so it walks them together: the lower front steps (`++`
     * 0x0066ADD0 + 0x0066A330 on the entities, 0x007B4D90 + 0x007B29C0 on the
     * units), an equal pair is a hit, and either set running out is a miss.
     * Callers `DrawNodeSharesLiveEntityWithSelection` (0x00828280) and
     * `ResolveCursorHighlightCommandId` (0x00829800).
     */
    [[nodiscard]] bool SharesALiveEntity(const WeakSet<UserEntity>& entities, const WeakSet<UserUnit>& units)
    {
      auto entity = entities.begin();
      if (entity == entities.end()) {
        return false;
      }
      auto unit = units.begin();
      if (unit == units.end()) {
        return false;
      }

      for (;;) {
        UserEntity* const left = *entity;
        UserEntity* const right = *unit;
        if (left < right) {
          if (++entity == entities.end()) {
            return false;
          }
        } else if (right < left) {
          if (++unit == units.end()) {
            return false;
          }
        } else {
          return true;
        }
      }
    }
}


  /**
   * Address: 0x00828280 (FUN_00828280, sub_828280)
   *
   * IDA signature:
   * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
   *
   * What it does:
   * Reports whether the draw node's command is aimed at anything the player
   * currently has selected. See the declaration for why the null-helper guard
   * is repeated here.
   */
  bool UICommandGraph::DrawNodeSharesLiveEntityWithSelection(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = drawNode.mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return false;
    }

    return SharesALiveEntity(mSession->GetSelection(), *ResolveCommandIssueCursorEntities(*ownerHelper));
  }

  /**
   * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
   *
   * IDA signature:
   * void __thiscall sub_8282B0(UICommandGraph *this, GeomCamera3 *camera,
   *   CD3DPrimBatcher *batcher, UICommandGraphDrawNode *drawNode);
   *
   * What it does:
   * Draws one command node's waypoint marker: a flat quad centered on the
   * node's averaged position, colored/scaled by
   * `ResolveDrawNodeHighlightState`, sized to a roughly-constant apparent
   * screen size via the camera viewport's perspective-width row
   * (`ProjectViewportWidthRow2`, the same shape as the already-recovered
   * `ProjectViewportDepthRow1`, one row over) and clamped to
   * `[ui_MinWaypointSize, ui_MaxWaypointSize]`.
   */
  void UICommandGraph::DrawWaypointMarker(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    boost::shared_ptr<CD3DBatchTexture> texture = boost::SharedPtrFromRawRetained(
      reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(node.mWaypointTexture)
    );

    std::uint32_t color = 0;
    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(drawNode)) {
    case ECommandNodeHighlightState::Normal:
      color = node.mWaypointColor;
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      color = node.mWaypointHighlightColor;
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      color = node.mWaypointSelectedColor;
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    if (!texture) {
      texture = CD3DBatchTexture::FromSolidColor(0xFF30F030u);
    }

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);

    // The clamp is in SCREEN units, the quad is in world units. 0x008282B0
    // divides the style scale by the projected depth, clamps that against
    // `ui_MinWaypointSize`/`ui_MaxWaypointSize` (7 and 100 pixels, from
    // `/lua/ui/game/commandwaypoint.lua`), and then multiplies the clamped
    // value BACK by the same depth to get the world half-extent
    // (`v21 * v20` at 0x0082838E..0x008283C4). Without that second multiply
    // the marker was drawn at its pixel size in world units, so the minimum
    // clamp alone made every waypoint tens of map units across.
    const float screenSize =
      std::clamp((drawNode.mUnitCountScale * styleScale) / depthW, ui_MinWaypointSize, ui_MaxWaypointSize);
    const float size = screenSize * depthW;

    batcher.SetTexture(texture);

    const CD3DPrimBatcher::Vertex topLeft{avg.x - size, avg.y, avg.z + size, color, 0.0f, 1.0f};
    const CD3DPrimBatcher::Vertex topRight{avg.x - size, avg.y, avg.z - size, color, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomRight{avg.x + size, avg.y, avg.z - size, color, 1.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomLeft{avg.x + size, avg.y, avg.z + size, color, 1.0f, 1.0f};
    batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  /**
   * Address: 0x00829800 (FUN_00829800, sub_829800)
   *
   * IDA signature:
   * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
   *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
   *
   * What it does: see the declaration.
   */
  CmdId UICommandGraph::ResolveCursorHighlightCommandId(
    const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  ) const
  {
    if (mMapAB0.empty()) {
      return -1;
    }

    float bestScaledDistance = gpg::pInf;
    CmdId bestCommandId = -1;

    for (auto& entry : mMapAB0) {
      const UICommandGraphDrawNode& drawNode = entry.second;

      const float invWeight = 1.0f / drawNode.mWeight;
      const Wm3::Vector3f avg{
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };

      // Frustum-cull the averaged anchor against the camera's view solid
      // before spending a projection + hit test on it.
      //
      // `CGeomSolid3` carries *outward*-facing plane normals, so a point is
      // outside the solid when its signed distance is positive - the same
      // convention `SolidContainsAabb` (moho/mesh/Mesh.cpp) rejects on, and
      // exactly what 0x008298B2..0x008298BE spells:
      //
      //   0x008298B2  subss  xmm0, [edx+0Ch]        ; d = n.X - constant
      //   0x008298B7  comiss xmm0, ds:dword_E4F6E0  ; the .rdata word is 0.0f
      //   0x008298BE  ja     loc_829B12             ; d > 0 -> next node
      //
      // Testing `<= 0` here instead inverted the whole predicate: every
      // command node actually on screen was discarded, the walk always fell
      // through to `bestCommandId == -1`, and so `CUIWorldView::
      // UpdateSelection` never wrote a real `CmdId` into `MouseInfo::
      // mIsDragger`. With that sentinel permanently -1, `DefaultModeFromDrag`
      // only ever answered COMMOD_Move, the "grab this command node" arm that
      // builds a `UICommandDragger` never ran, and no issued order could be
      // picked up and dragged anywhere.
      bool culledByFrustum = false;
      for (const Wm3::Plane3f& plane : camera.solid2.planes_) {
        const float signedDistance =
          ((plane.Normal.x * avg.x) + (plane.Normal.y * avg.y) + (plane.Normal.z * avg.z)) - plane.Constant;
        if (signedDistance > 0.0f) {
          culledByFrustum = true;
          break;
        }
      }
      if (culledByFrustum) {
        continue;
      }

      const Wm3::Vector2f screenPos = camera.Project(avg);
      const float dx = screenPos.x - cursorScreenPos.x;
      const float dy = screenPos.y - cursorScreenPos.y;
      const float pixelDistance = std::sqrt((dx * dx) + (dy * dy));

      const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);
      float worldTolerance = drawNode.mUnitCountScale / depthW;
      worldTolerance = std::clamp(worldTolerance, ui_MinWaypointSize, ui_MaxWaypointSize);

      const float scaledTolerance = worldTolerance * depthW;
      float scaledDistance = depthW * pixelDistance;

      auto* const helper = drawNode.mHelperLink.GetObjectPtr();
      if (helper != nullptr && ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_Ferry) {
        // Ferry waypoints get a small extra tolerance bonus so a ferry order's
        // markers are easier to pick back up under the cursor.
        scaledDistance -= 0.1f;
      }

      // `ui_CommandClickScale` (the decompiled global name at this read) is
      // not a real symbol - see the `ui_WaypointLineScale` doc comment in
      // `UICommandGraph::LoadPathParams` above: both the `ui_WaypointLineScale`
      // and `ui_CommandClickScale` Lua keys write the same global
      // (0x00F57CDC), and that is what this address reads.
      if ((ui_WaypointLineScale * scaledTolerance) < scaledDistance) {
        continue;
      }

      bool preemptsByLiveSelection = false;
      if (helper != nullptr) {
        preemptsByLiveSelection = SharesALiveEntity(mSession->GetSelection(), *ResolveCommandIssueCursorEntities(*helper));
      }

      if (bestScaledDistance > scaledDistance || preemptsByLiveSelection) {
        bestScaledDistance = scaledDistance;
        bestCommandId = drawNode.mCommandId;
      }
    }

    return bestCommandId;
  }

  /**
   * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
   *
   * IDA signature:
   * void __usercall sub_828DD0(UICommandGraphDrawNode *drawNode@<?>,
   *   UICommandGraph *graph, CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Poses the node's owned mesh instance at its resolved position (the
   * averaged `mPositionSum/mWeight` anchor when `mHasResolvedPosition`,
   * otherwise the anchor `ResolveCommandGraphAnchorWorldPosition` resolves
   * from the owning command's history) with identity orientation (a snap,
   * not an interpolated move - `SetStance` is called with the same
   * transform as both its start and end). When the anchor came from a real
   * unit blueprint, additionally draws that unit's footprint skirt there.
   *
   * The decompile carries the documented "positive sp value has been
   * detected" reliability warning; the temporary `VTransform` construction
   * it mis-attributes to a stack slot 24 bytes off was re-derived from the
   * raw x86 (0x00828E19..0x00828E3A) instead. The observable geometry
   * (position = averaged anchor, orientation = identity,
   * `SetStance(anchor, anchor)`) matches for both branches regardless.
   */
  void UICommandGraph::DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const
  {
    if (!drawNode.mMeshInstance) {
      return;
    }
    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    Wm3::Vector3f anchor{};
    const RUnitBlueprint* unitBlueprint = nullptr;

    if (drawNode.mHasResolvedPosition) {
      const REntityBlueprint* const blueprint = helper->mConstantData.blueprint;
      if (blueprint == nullptr || !blueprint->IsUnitBlueprint()) {
        return;
      }
      unitBlueprint = static_cast<const RUnitBlueprint*>(blueprint);

      const float invWeight = 1.0f / drawNode.mWeight;
      anchor = {
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };
    } else {
      anchor = ResolveCommandGraphAnchorWorldPosition(*helper);
    }

    const VTransform transform{anchor, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
    drawNode.mMeshInstance->SetStance(transform, transform);

    if (unitBlueprint == nullptr) {
      return;
    }

    CHeightField* const heightField = mSession->mWldMap->mTerrainRes->GetHeightField();
    CameraImpl* const camera = CAM_GetCamera(gpg::StrArg("WorldCamera"));
    // 0x00828F09..0x00828F1A picks the skirt colour branchlessly:
    //
    //   mov  cl, [edi+1Eh]        ; mIsVisible
    //   neg  cl                   ; CF set when it is non-zero
    //   sbb  ecx, ecx             ; ecx = -1 when visible, 0 when not
    //   and  ecx, 0FF28D800h
    //   add  ecx, 0D8D80000h
    //
    // so a placeable node gets 0xFF28D800 + 0xD8D80000 = 0xD800D800 (ARGB:
    // 84% alpha, pure green) and a rejected one gets 0xD8D80000 (same alpha,
    // pure red). The two constants here had lost their colour bytes
    // entirely - 0xD8000000 is transparent black, which is exactly how the
    // footprint outline drew under a dragged building: visible, but with no
    // indication of whether the drop would be accepted.
    const std::uint32_t color = drawNode.mIsVisible ? 0xD800D800u : 0xD8D80000u;
    DrawUnitSkirt(heightField, unitBlueprint, camera->CameraGetView(), anchor, mSession, &batcher, color);
  }

  /**
   * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
   *
   * IDA signature:
   * void __userpurge Moho::DisplayCommandNode(UICommandGraph *this@<ecx>,
   *   GeomCamera3 *camera@<ebx>, UICommandGraphDrawNode *drawNode@<esi>,
   *   CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Draws the "ETA: mm:ss" text label above one command-graph draw node,
   * gated by the "display_eta" option, the command not yet being due
   * (`drawNode.mCompletionTick - mSession->mGameTick < 0` skips), and - only for
   * the non-highlighted/non-selected state - an LOD distance test against
   * `ui_MaxTextLOD` using the camera viewport's depth row (the same
   * `ProjectViewportDepthRow1` shape used throughout this file).
   *
   * Glyph size is `mUnitCountScale * (style scale for the resolved highlight
   * state)`; the label anchors at the node's averaged position offset by
   * that glyph size in X/-Z, then is projected to screen space and nudged
   * by `mDebugFont.tex->mDescent + 1` pixels vertically.
   */
  void UICommandGraph::DisplayCommandNode(
    const GeomCamera3& camera, const UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher
  ) const
  {
    if (!drawNode.mHelperLink.HasValue()) {
      return;
    }

    const std::int32_t beatsUntilDue = static_cast<std::int32_t>(drawNode.mCompletionTick) - mSession->mGameTick;
    if (beatsUntilDue < 0) {
      return;
    }

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(const_cast<UICommandGraphDrawNode&>(drawNode))) {
    case ECommandNodeHighlightState::Normal:
      if (camera.viewport.ProjectViewportDepthRow1(avg) >= ui_MaxTextLOD) {
        return;
      }
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    const float glyphScale = drawNode.mUnitCountScale * styleScale;

    if (!OPTIONS_GetBool("display_eta")) {
      return;
    }

    const float seconds = static_cast<float>(beatsUntilDue) * 0.1f;
    const auto truncSeconds = static_cast<std::int32_t>(std::trunc(seconds));
    const fa::string label = gpg::STR_Printf("ETA: %d.%02d", truncSeconds / 60, truncSeconds % 60);

    const Wm3::Vector3f textAnchor{avg.x + glyphScale, avg.y, avg.z - glyphScale};
    const Wm3::Vector2f projected = camera.Project(textAnchor);
    const Wm3::Vector2f screenPos{
      static_cast<float>(static_cast<std::int32_t>(projected.x + 1.0f)),
      static_cast<float>(static_cast<std::int32_t>(projected.y - (mDebugFont.tex->mDescent + 1.0f)))
    };

    // Color/scale/maxAdvance are elided register args at this callsite the
    // decompile doesn't show explicitly; `NAN` for maxAdvance is the one
    // value the raw decompile states literally, preserved as-is (an
    // unclipped label). Color/scale use this file's other text-draw
    // defaults (opaque white, unscaled) pending a dedicated re-verification.
    mDebugFont.tex->Render2D(gpg::StrArg(label.c_str()), &batcher, screenPos, 0xFFFFFFFFu, 1.0f, std::numeric_limits<float>::quiet_NaN());
  }

  /**
   * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
   *
   * IDA signature:
   * void __thiscall sub_8288D0(GeomCamera3 *this, UICommandGraph *graph,
   *   CD3DPrimBatcher *batcher, int tick, float tickFraction,
   *   CommandGraphEdge *edge, char isGlow);
   *
   * What it does:
   * Draws one command-graph "orderline" ribbon segment between two draw
   * nodes' averaged positions via `EmitHermiteRibbonSegments`.
   *
   * Verified against the raw x86 (every `*0.0` term in the endpoint-offset
   * block resolves to a hardware-confirmed zero, exactly the pattern
   * already documented on `EmitHermiteRibbonSegments`): the spline's two
   * control points are the *unmodified* averaged from/to positions, and the
   * two tangents fed to the Hermite blend are each endpoint's own tangent
   * (its `mOrientationHint` when non-zero, else the normalized from-to
   * direction) scaled by a smoothness radius
   * (`min(segmentLength * 0.25, ui_CurveSmoothness * width)`).
   *
   * Color/glow selection: when `edge.mForceHighlightStyle` is set, this
   * skips `ResolveDrawNodeHighlightState` entirely and uses the owning
   * node's `mOrderlineHighlightColor`/`mOrderlineHighlightGlow` directly -
   * i.e. the flag forces the "highlighted" appearance, it does not carry a
   * per-edge custom color (see the field's own doc comment). Otherwise the
   * usual 0/1/2 dispatch picks Normal/Highlighted/Selected colors. For the
   * glow pass (`isGlow`), the color's alpha byte is replaced by the style's
   * glow scalar.
   */
  void UICommandGraph::DrawCommandOrderline(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction,
    const CommandGraphEdge& edge, const bool isGlow
  ) const
  {
    UICommandGraphDrawNode* const fromNode = edge.mFromNode;
    if (fromNode == nullptr) {
      return;
    }
    UICommandGraphDrawNode* const toNode = edge.mToNode;
    if (toNode == nullptr) {
      return;
    }
    auto* const ownerHelper = toNode->mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return;
    }

    const float fromInvWeight = 1.0f / fromNode->mWeight;
    const Wm3::Vector3f fromPos{
      fromNode->mPositionSum.x * fromInvWeight, fromNode->mPositionSum.y * fromInvWeight,
      fromNode->mPositionSum.z * fromInvWeight
    };
    const float toInvWeight = 1.0f / toNode->mWeight;
    const Wm3::Vector3f toPos{
      toNode->mPositionSum.x * toInvWeight, toNode->mPositionSum.y * toInvWeight, toNode->mPositionSum.z * toInvWeight
    };

    const float widthFromDepth = camera.viewport.ProjectViewportWidthRow2(fromPos) * 2.0f;
    const float widthToDepth = camera.viewport.ProjectViewportWidthRow2(toPos) * 2.0f;
    const float width = (edge.mBaseWidth + std::max(widthFromDepth, widthToDepth)) * ui_WaypointLineScale;

    Wm3::Vector3f direction{toPos.x - fromPos.x, toPos.y - fromPos.y, toPos.z - fromPos.z};
    direction.Normalize();

    Wm3::Vector3f fromTangent = direction;
    if (fromNode->mOrientationHint.x != 0.0f || fromNode->mOrientationHint.y != 0.0f
        || fromNode->mOrientationHint.z != 0.0f) {
      fromTangent = fromNode->mOrientationHint;
    }
    Wm3::Vector3f toTangent = direction;
    if (toNode->mOrientationHint.x != 0.0f || toNode->mOrientationHint.y != 0.0f
        || toNode->mOrientationHint.z != 0.0f) {
      toTangent = toNode->mOrientationHint;
    }

    const float segmentLength = std::sqrt(
      ((toPos.x - fromPos.x) * (toPos.x - fromPos.x) + (toPos.y - fromPos.y) * (toPos.y - fromPos.y))
      + (toPos.z - fromPos.z) * (toPos.z - fromPos.z)
    );
    const float smoothRadius = std::min(segmentLength * 0.25f, ui_CurveSmoothness * width);

    const auto commandType = ResolveCommandIssueHelperCommandType(*ownerHelper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    std::uint32_t color;
    float glow;
    if (edge.mForceHighlightStyle) {
      color = node.mOrderlineHighlightColor;
      glow = node.mOrderlineHighlightGlow;
    } else {
      switch (ResolveDrawNodeHighlightState(*toNode)) {
      case ECommandNodeHighlightState::Selected:
        color = node.mOrderlineSelectedColor;
        glow = node.mOrderlineSelectedGlow;
        break;
      case ECommandNodeHighlightState::Highlighted:
        color = node.mOrderlineHighlightColor;
        glow = node.mOrderlineHighlightGlow;
        break;
      case ECommandNodeHighlightState::Normal:
      default:
        color = node.mOrderlineColor;
        glow = node.mOrderlineGlow;
        break;
      }
    }
    if (isGlow) {
      color &= static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24;
    }

    const float uStart = 1.0f - fa::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    EmitHermiteRibbonSegments(
      batcher, fromPos, toPos, Wm3::Vector3f{fromTangent.x * smoothRadius, fromTangent.y * smoothRadius, fromTangent.z * smoothRadius},
      Wm3::Vector3f{toTangent.x * smoothRadius, toTangent.y * smoothRadius, toTangent.z * smoothRadius}, width, color,
      uStart, node.mOrderlineAspectRatio
    );
  }
namespace
{

  // Forward declarations: reopens the same file-scope anonymous namespace
  // that defines these two sentinel-headed RB-tree walkers further below (by
  // the selection/save-tree helpers), so `DrawCommandGraphMesh` below - the
  // only command-graph draw method that needs them - can call them here,
  // ahead of their point of definition.
      template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node);
}


  /**
   * Address: 0x00829190 (FUN_00829190, sub_829190)
   *
   * What it does:
   * The per-frame command-graph render pass. Six sub-passes, each under its
   * own primbatcher technique:
   *   A) "TCommand"        - opaque orderlines, walking `mCommandGraphTree`
   *      (a texture-bucketed red-black tree; each node's payload is a
   *      `{texture, fa::vector<CommandGraphEdge*>}` pair) and drawing
   *      every edge in every bucket with `isGlow=false`.
   *   B) "TCommandGlow"    - the same tree walk again with `isGlow=true`.
   *   C) "TAlphaBlendLinearSampleNoDepth" - waypoint marker billboards,
   *      walking `mMapAB0` (the sentinel-headed draw-node list).
   *   D) "TAlphaBlendLinearSample" - position-node meshes/skirts, same
   *      `mMapAB0` walk, with a flat white texture bound first.
   *   E) "TCommandOther"   - the optional path-preview overlay (gated on
   *      `ui_DrawPathPreview`), then a screen-space pixel projection.
   *   F) (still under TCommandOther) - per-node ETA text labels, a third
   *      `mMapAB0` walk.
   *
   * The two tree walks and three list walks are the decompiler's
   * `boost::shared_ptr`-shaped traversal of `mCommandGraphTree`/`mMapAB0`
   * respectively (IDA mistyped both containers as chains of
   * `boost::detail::sp_counted_base_vtbl`/`CD3DBatchTexture` because their
   * node layouts happen to alias those types' field shapes at the read
   * offsets) - recovered here as the same typed RB-tree/list walks every
   * sibling command-graph function already uses.
   *
   * IDA's `__userpurge` signature adds two register arguments (typed
   * `CRenderWorldView*` and `boost::shared_ptr<UICommandGraph>&` in the
   * analyst database) that are only the caller's leftover `ecx`/`edx`
   * (`CWldSession::RenderCommandGraph`, 0x0085AF40); this body never reads
   * either.
   */
  void UICommandGraph::DrawCommandGraphMesh(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction
  )
  {
    batcher.Flush();

    // Pass A: opaque orderlines, bucketed by texture.
    (void)batcher.Setup("TCommand");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mCommandGraphTree.mHead->mLeft;
         node != nullptr && node != mCommandGraphTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = node->mBucket;
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/false);
      }
    }
    batcher.Flush();

    // Pass B: glow overlay for the same orderlines.
    (void)batcher.Setup("TCommandGlow");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mCommandGraphTree.mHead->mLeft;
         node != nullptr && node != mCommandGraphTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = node->mBucket;
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/true);
      }
    }
    batcher.Flush();

    // Pass C: waypoint marker billboards.
    (void)batcher.Setup("TAlphaBlendLinearSampleNoDepth");
    for (auto& entry : mMapAB0) {
      DrawWaypointMarker(camera, batcher, entry.second);
    }
    batcher.Flush();

    // Pass D: position-node meshes/skirts, over a flat white texture.
    (void)batcher.Setup("TAlphaBlendLinearSample");
    batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    for (auto& entry : mMapAB0) {
      DrawPositionNodeMesh(entry.second, batcher);
    }
    batcher.Flush();

    // Pass E: optional path-preview overlay, then switch to a screen-space
    // pixel projection for the ETA text pass below.
    (void)batcher.Setup("TCommandOther");
    if (ui_DrawPathPreview) {
      DrawPathPreview(*this, camera, batcher, tick, tickFraction);
    }

    batcher.SetProjectionMatrix(MakeViewportPixelProjection(camera));
    batcher.SetViewMatrix(VMatrix4::Identity());

    // Pass F: per-node ETA text labels, in the screen-space projection just set.
    for (auto& entry : mMapAB0) {
      DisplayCommandNode(camera, entry.second, batcher);
    }
    batcher.Flush();
  }

  /**
   * Not a distinct binary function - `UICommandGraph` is only a complete
   * type in this file, so `UICommandGraph::ResolveCursorHighlightCommandId`
   * needs a wrapper here. `Moho::CUIWorldView::UpdateSelection` (UiRuntimeTypes.cpp)
   * calls this through the bare `UICommandGraph*` its `mComGraph` holds.
   * Returns -1 (no highlighted command) when `graph` is null.
   */
  CmdId ResolveCommandGraphCursorHighlightIfPresent(
    UICommandGraph* const graph, const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  )
  {
    if (graph == nullptr) {
      return -1;
    }
    return graph->ResolveCursorHighlightCommandId(camera, cursorScreenPos);
  }

  // Forward declarations for functions `DrawPathPreview` below needs whose
  // own out-of-line definitions live later in this TU (`func_
  // GetRightMouseButtonAction`, at global scope, is referenced by the linker
  // at global scope so its definition stays there) or that this codebase
  // conventionally forward-declares per-TU rather than sharing a header for
  // (`MultQuadVec`, matching the same one-line declaration already repeated
  // in a dozen other .cpp files that call it).
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);

  /**
   * Address: 0x0082A380 (FUN_0082A380, sub_82A380)
   *
   * What it does:
   * Draws the active move-command's path-preview ribbon: either the
   * Ramer-Douglas-Peucker-simplified world-space path sampled from the
   * previewed army's runtime cell-position scratch buffer
   * (`ui_PathPreview` on), or a straight two-point line from the cursor to
   * the deepest selected unit's current/queued anchor position
   * (`ui_PathPreview` off). Both converge on the same ribbon-emission walk
   * used by `UICommandGraph::DrawCommandOrderline`, styled from the
   * command-graph node matching the pending right-click command, with an
   * arrowhead billboard capping the last segment when the node has one.
   *
   * `arg0`, the IDA-declared first parameter, is not a real argument - see
   * this function's declaration in CWldSession.h.
   *
   * The runtime cell-position buffer's trailing "meta" dword
   * (`SArmyVectorWithMeta::mMetaWord`, modeled as a plain pointer-sized word
   * because different consumers reuse the same bytes differently) is read here
   * as a pointer to a 3-byte `{sizeX, sizeZ, layer}` footprint descriptor -
   * confirmed against the raw disassembly, not just the decompile, so the
   * reinterpret is applied at this call site rather than changing the
   * field's canonical type.
   */
  void DrawPathPreview(
    UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick,
    const float tickFraction
  )
  {
    CWldSession* const session = graph.mSession;

    const std::int32_t focusArmy = session->FocusArmy;
    if (focusArmy < 0) {
      return;
    }
    UserArmy* const army = session->userArmies[focusArmy];
    if (army == nullptr) {
      return;
    }

    SArmyVectorWithMeta& scratch = army->mVarDat.mWordVectorWithMeta;
    const std::size_t cellCount = scratch.mWords.size();
    // The meta dword is only ever a real descriptor pointer once the army's
    // scratch buffer has been populated for STI/path-preview display; a
    // fresh/never-populated army leaves it null.
    const auto* const footprintDescriptor = reinterpret_cast<const std::uint8_t*>(scratch.mMetaWord);

    fa::list<Wm3::Vector3f> simplifiedPath{};
    float capWidthSeed = 0.0f;

    if (ui_PathPreview) {
      if (footprintDescriptor == nullptr || cellCount < 2) {
        return;
      }

      capWidthSeed = static_cast<float>(footprintDescriptor[0]);

      STIMap* const stiMap = session->GetSTIMap();
      const auto* const cellPositions = reinterpret_cast<const SOCellPos*>(scratch.mWords.begin());

      // This count-only constructor call is FUN_0082A46C's `call sub_7E3730`
      // in the raw disassembly (Moho::DrawPathPreview is FUN_0082A380) --
      // VC8's `vector(size_type)` materialises a default `Wm3::Vector3f()`
      // temporary and forwards into the same allocate-then-fill path as
      // `vector(count, value)` (FUN_007E3730 -> FUN_007E4370 -> FUN_007E6460,
      // Vector.h). Every slot is overwritten by the loop immediately below,
      // so the broadcast fill value never survives to be observed.
      fa::vector<Wm3::Vector3f> worldPts(cellCount);
      for (std::size_t i = 0; i < cellCount; ++i) {
        worldPts[i] = COORDS_ToWorldPos(
          stiMap, cellPositions[i], static_cast<ELayer>(footprintDescriptor[2]), footprintDescriptor[0],
          footprintDescriptor[1]
        );
      }

      simplifiedPath.push_back(worldPts.front());
      simplifiedPath.push_back(worldPts.back());
      SimplifyPathSpan(
        worldPts, 0, static_cast<std::int32_t>(cellCount) - 1, simplifiedPath, --simplifiedPath.end(),
        ui_PathSmoothness
      );
    } else {
      if (!session->CursorInfo().mHitValid) {
        return;
      }

      UserUnit* const subject = PickPathPreviewSubject(const_cast<WeakSet<UserEntity>&>(session->GetSelection()));
      if (subject == nullptr) {
        return;
      }

      IUnit* const subjectBridge = GetIUnitBridge(subject);
      // 0x0082A60D..0x0082A62A: `GetBlueprint()` (IUnit slot 7), `add eax,
      // 0D8h` / `movzx eax, byte ptr [eax]` -- the first byte of the
      // blueprint's inline `REntityBlueprint::mFootprint` (+0xD8), i.e. the
      // same footprint `mSizeX` the ui_PathPreview branch above reads from
      // its descriptor. It was a raw `[216]` byte index into the blueprint.
      capWidthSeed = static_cast<float>(subjectBridge->GetBlueprint()->mFootprint.mSizeX);

      Wm3::Vector3f endPos = subjectBridge->GetPosition();
      if (MAUI_KeyIsDown(MKEY_SHIFT)) {
        // `GetLastQueuedUserCommandAnchor` and `ResolveCommandGraphAnchorWorldPosition`
        // both ultimately view the same binary object (the unit's most
        // recently queued command-issue helper) through different recovered
        // type lanes - see the former's doc comment in UserUnit.cpp.
        const auto* const anchorHelper =
          reinterpret_cast<const UserCommandIssueHelper*>(GetLastQueuedUserCommandAnchor(subject));
        if (anchorHelper != nullptr) {
          endPos = ResolveCommandGraphAnchorWorldPosition(const_cast<UserCommandIssueHelper&>(*anchorHelper));
        }
      }

      simplifiedPath.push_back(session->CursorInfo().mMouseWorldPos);
      simplifiedPath.push_back(endPos);
    }

    // Two distinct distance-based scale terms, both read off the camera's
    // world/view-matrix row via the front preview point - confirmed distinct
    // (not the same term reused) by their different scale constants and by
    // `capDivisor` alone folding in `capWidthSeed` as a floor:
    //   capDivisor - denominator for the arrowhead cap offset below.
    //   maxWidthTerm - the ribbon half-width term, maxed against the back
    //     point too (matching `DrawCommandOrderline`'s sibling formula)
    //     rather than the single-point read the raw decompile's redundant
    //     reloads collapse to.
    const float frontProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.front());
    const float capDivisor = std::max(capWidthSeed, frontProjected * 3.0f) * 0.2f;

    float maxWidthTerm = frontProjected * 2.0f;
    const float backProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.back()) * 2.0f;
    if (backProjected > maxWidthTerm) {
      maxWidthTerm = backProjected;
    }

    const LuaPlus::LuaObject waypointModule = SCR_Import(g_UIManager->mLuaState, "/lua/ui/game/commandwaypoint.lua");
    LuaPlus::LuaFunction<float> calculateWaypointLineWidth{waypointModule["CalculateWaypointLineWidth"]};
    const float luaWidth = calculateWaypointLineWidth(static_cast<unsigned int>(session->GetSelection().Size()));

    const float finalWidth = (maxWidthTerm + luaWidth) * ui_WaypointLineScale;

    // Side-effect-only: the binary re-fills a scratch SCommandModeData via
    // GetLeftMouseButtonAction, then immediately overwrites it with a copy of
    // the resolved commandData and destroys it - net zero data effect, since
    // neither commandData nor anything outside this scratch's own lifetime is
    // touched. Mode 7 is `COMMOD_CancelCommandMode`, the value
    // `func_GetRightMouseButtonAction` writes at 0x0081ED4E when a UI command
    // mode is already engaged - this comparison is how that value was first
    // sighted, and it was dead until the writer was restored.
    CommandModeData commandData{};
    (void)func_GetRightMouseButtonAction(&commandData, &session->CursorInfo(), 0, session);
    if (commandData.mMode == COMMOD_CancelCommandMode) {
      CommandModeData scratch{};
      (void)session->GetLeftMouseButtonAction(&scratch, &session->CursorInfo(), 0);
    }

    const ERuleBPUnitCommandCaps caps =
      (commandData.mMode == COMMOD_Order) ? commandData.mCommandCaps : RULEUCC_Move;
    UICommandGraph::CommandGraphNode& node = graph.mNodes[static_cast<std::size_t>(UnitCommandCapToCommandType(caps))];

    if (node.mOrderlineTexture.px != nullptr) {
      batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
        node.mOrderlineTexture
      )));
    } else {
      batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    }

    const bool hasArrowhead = node.mArrowheadTexture.px != nullptr;
    const float uStart = 1.0f - fa::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    for (auto it = simplifiedPath.begin(); it != simplifiedPath.end(); ++it) {
      auto next = it;
      ++next;
      if (next == simplifiedPath.end()) {
        break;
      }

      Wm3::Vector3f p0 = *it;
      Wm3::Vector3f p1 = *next;
      const bool isLastSegment = [&] {
        auto afterNext = next;
        ++afterNext;
        return afterNext == simplifiedPath.end();
      }();

      if (isLastSegment && hasArrowhead) {
        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        p1 = Wm3::Vector3f{p1.x + direction.x * finalWidth, p1.y + direction.y * finalWidth, p1.z + direction.z * finalWidth};
      }

      auto prevOfIt = it;
      const bool hasPrevOfIt = (it != simplifiedPath.begin());
      if (hasPrevOfIt) {
        --prevOfIt;
      }
      auto afterNext = next;
      ++afterNext;
      const bool hasAfterNext = (afterNext != simplifiedPath.end());

      Wm3::Vector3f t0{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasPrevOfIt) {
        t0 = Wm3::Vector3f{p1.x - prevOfIt->x, p1.y - prevOfIt->y, p1.z - prevOfIt->z};
      }
      const float t0Len = std::sqrt(t0.x * t0.x + t0.y * t0.y + t0.z * t0.z);
      if (t0Len > ui_PathSmoothness && t0Len > 0.0f) {
        const float scale = ui_PathSmoothness / t0Len;
        t0 = Wm3::Vector3f{t0.x * scale, t0.y * scale, t0.z * scale};
      }

      Wm3::Vector3f t1{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasAfterNext) {
        t1 = Wm3::Vector3f{afterNext->x - p0.x, afterNext->y - p0.y, afterNext->z - p0.z};
      }
      const float t1Len = std::sqrt(t1.x * t1.x + t1.y * t1.y + t1.z * t1.z);
      if (t1Len > ui_PathSmoothness && t1Len > 0.0f) {
        const float scale = ui_PathSmoothness / t1Len;
        t1 = Wm3::Vector3f{t1.x * scale, t1.y * scale, t1.z * scale};
      }

      EmitHermiteRibbonSegments(
        batcher, p0, p1, t0, t1, finalWidth, node.mOrderlineSelectedColor, uStart, node.mOrderlineAspectRatio
      );

      if (isLastSegment && hasArrowhead) {
        const float capOffset = (finalWidth / capDivisor) * node.mArrowheadCapOffset;
        batcher.Flush();
        batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
          node.mArrowheadTexture
        )));

        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        const Wm3::Vector3f capCenter{
          p1.x + direction.x * capOffset, p1.y + direction.y * capOffset, p1.z + direction.z * capOffset};
        const Wm3::Quaternionf orient = COORDS_Orient(direction);

        Wm3::Vector3f corners[4] = {
          {-finalWidth, 0.0f, -finalWidth}, {-finalWidth, 0.0f, finalWidth}, {finalWidth, 0.0f, finalWidth},
          {finalWidth, 0.0f, -finalWidth}};
        for (Wm3::Vector3f& corner : corners) {
          Wm3::Vector3f rotated{};
          (void)MultQuadVec(&rotated, &corner, &orient);
          corner = Wm3::Vector3f{capCenter.x + rotated.x, capCenter.y + rotated.y, capCenter.z + rotated.z};
        }

        batcher.DrawQuad(
          CD3DPrimBatcher::Vertex{corners[0].x, corners[0].y, corners[0].z, 0xFFFFFFFFu, 0.0f, 1.0f},
          CD3DPrimBatcher::Vertex{corners[1].x, corners[1].y, corners[1].z, 0xFFFFFFFFu, 0.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[2].x, corners[2].y, corners[2].z, 0xFFFFFFFFu, 1.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[3].x, corners[3].y, corners[3].z, 0xFFFFFFFFu, 1.0f, 1.0f}
        );
      }
    }
  }

  /**
   * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
   */
  UICommandGraph::UICommandGraph(CWldSession* const session)
    : mNeedsRebuild(1u)
    , pad_0001{0, 0, 0}
    , mNodes{}
    , mSession(session)
    , mSessionRes1(session ? session->mCommandManager : nullptr)
    , mDebugFont()
    , mMapAB0{}
    , mMapAB1{}
    , mMapC{}
    , mMapD{}
    , mCommandGraphTree{}
  {
    InitTree(mCommandGraphTree);

    try {
      boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(10, "Andale Mono");
      mDebugFont.reset(createdFont.px);
      createdFont.release();

      LoadPathParams();
      LoadWaypointParams();
      CreateMeshes();
      OnCommandGraphShow(mSession ? mSession->mState : nullptr, true);
    } catch (...) {
      // The binary's constructor unwind releases this tree at 0x00BC186A.
      // Its existing manual representation needs the same cleanup here;
      // the typed maps and counted font then unwind as ordinary members.
      DestroyTree(mCommandGraphTree);
      throw;
    }
  }

  /**
   * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
   */
  UICommandGraph::~UICommandGraph()
  {
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, false);
    DestroyTree(mCommandGraphTree);
  }
namespace
{
    // The orphan and visibility sets are `CWldSession::mOrphans` (+0x42C) and
    // `CWldSession::mVizUpdates` (+0x438), two bare 12-byte `WeakSet<UserEntity>`
    // headers; they were reached through two padded overlays here that laid a
    // 16-byte `WeakSet<UserEntity>` over each. The cursor snapshot at
    // +0x4B0 is `CWldSession::CursorInfo()`, not a third padded overlay.

    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* const node)
    {
      return !node || node->mIsSentinel != 0u;
    }

    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node)
    {
      if (!node || IsSentinelNode(node)) {
        return node;
      }

      if (!IsSentinelNode(node->mRight)) {
        node = node->mRight;
        while (!IsSentinelNode(node->mLeft)) {
          node = node->mLeft;
        }
        return node;
      }

      TNode* parent = node->mParent;
      while (!IsSentinelNode(parent) && node == parent->mRight) {
        node = parent;
        parent = parent->mParent;
      }
      return parent;
    }

    /**
     * Predecessor mirror of `NextTreeNode` above - not separately confirmed
     * against a `mCommandGraphTree`-specific `rb_decrement` address (only
     * its increment sibling, 0x0082EC10, is directly cited for this tree in
     * `legacy/containers/RbTree.h`), but the shape is the generic VC8
     * `_Dec` walk every other instantiation in that file uses - left
     * subtree's rightmost node, or the nearest ancestor whose right
     * subtree contains `node`. Used only by
     * `AttachCommandGraphNodeHinted`'s straddle checks below, which
     * never call it on the header sentinel itself, so the `_Dec`-specific
     * "`--end()` yields rightmost" header case does not apply here.
     */
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node)
    {
      if (!node || IsSentinelNode(node)) {
        return node;
      }

      if (!IsSentinelNode(node->mLeft)) {
        node = node->mLeft;
        while (!IsSentinelNode(node->mRight)) {
          node = node->mRight;
        }
        return node;
      }

      TNode* parent = node->mParent;
      while (!IsSentinelNode(parent) && node == parent->mLeft) {
        node = parent;
        parent = parent->mParent;
      }
      return parent;
    }
}


  /**
   * Ten sim ticks a second - the rate both order-graph estimators below convert
   * their real-time answer into the tick numbers `ResolveDrawNodeCompletionTick`
   * propagates. Folded into 0x00826C50 and 0x00826F10 as the literal 10.0f at
   * `ds:dword_DFF31C`.
   */
  constexpr float kCommandGraphTicksPerSecond = 10.0f;

  /**
   * Address: 0x00826C50 (FUN_00826C50, sub_826C50)
   *
   * IDA signature:
   * int __stdcall sub_826C50(Moho::UICommandGraph::CommandGraphEdge *edge);
   *
   * What it does: see the declaration above `RebuildCommandQueueNodes`.
   *
   * The edge takes its command from the order it leads *to*, not the one it
   * leaves: 0x00826C79 pins `esi` to `edge+0x0C` (`mToNode`) and every later
   * `[esi+4]` reads that node's helper head.
   *
   * The successor step inside the walk is the `map<EntId, WeakPtr<UserEntity>>`
   * `_Inc` emission at 0x007B4D90 (carried on `fa::detail::rb_increment`).
   * It is spelled with this file's `WeakSet<UserEntity>::Iterator_inc`
   * shape, which is the same body over the same node type and matches the
   * binary's `_Node**` out-parameter call at 0x00826DE8.
   */
  std::int32_t EstimateEdgeTravelTicks(const UICommandGraph::CommandGraphEdge& edge)
  {
    // Both endpoints accumulate a position *sum* plus a weight so several units
    // sharing one queue average into a single anchor; each side divides by its
    // own weight before the separation is taken.
    const Wm3::Vector3f fromCentroid = DrawNodeCentroid(*edge.mFromNode);
    const Wm3::Vector3f toCentroid = DrawNodeCentroid(*edge.mToNode);

    const float deltaX = fromCentroid.x - toCentroid.x;
    const float deltaY = fromCentroid.y - toCentroid.y;
    const float deltaZ = fromCentroid.z - toCentroid.z;
    const float distance = std::sqrt(((deltaX * deltaX) + (deltaY * deltaY)) + (deltaZ * deltaZ));

    // Unguarded exactly as the binary is (0x00826CFB feeds `[esi+4]` straight
    // into the type resolver): an edge only exists because `LinkCommandGraphEdge`
    // published it from two draw nodes that already carry a helper.
    auto* const helper = edge.mToNode->mHelperLink.GetObjectPtr();

    switch (ResolveCommandIssueHelperCommandType(*helper)) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
        break;

      default:
        // Nothing else walks a unit across the map, so it costs no travel time.
        // This is the binary's jump-table default at 0x00826D1A.
        return 0;
    }

    // The walk runs over a copy of the helper's units rather than the live
    // cache: the copy constructor (the set's range constructor 0x00831310)
    // drops the source's dead entries as it reads. The copy's destructor is
    // the erase-range + `operator delete(mHead)` pair at 0x00826E6D/0x00826EC0,
    // which runs on both the answered and the gave-up exit.
    const WeakSet<UserUnit> liveTargets(*ResolveCommandIssueCursorEntities(*helper));

    float slowestSpeed = std::numeric_limits<float>::max();
    for (UserUnit* const unit : liveTargets) {
      // Air units are held to their airspeed and everything else to its ground
      // speed. A unit with no positive speed of either kind is skipped rather
      // than making the whole orderline infinitely slow.
      const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();
      const float unitSpeed =
        (blueprint->Air.CanFly != 0u) ? blueprint->Air.MaxAirspeed : blueprint->Physics.MaxSpeed;
      if (unitSpeed > 0.0f && slowestSpeed > unitSpeed) {
        slowestSpeed = unitSpeed;
      }
    }

    // A set with nothing movable in it leaves the seed untouched, and the
    // binary re-tests both ends of the range before dividing by it.
    if (slowestSpeed >= std::numeric_limits<float>::max() || slowestSpeed <= 0.0f) {
      return 0;
    }

    // Rounded up: the binary spells the ceiling as `(int)rint(t) + (t > rint(t))`
    // (0x00826E4C..0x00826E5F), which agrees with `ceil` on every finite value
    // because the correction only fires when round-to-nearest went down.
    return static_cast<std::int32_t>(
      std::ceil((distance * kCommandGraphTicksPerSecond) / slowestSpeed)
    );
  }
namespace
{

    /**
     * Address: 0x00824500 (FUN_00824500, sub_824500)
     *
     * IDA signature:
     * Moho::UserEntity *__usercall sub_824500@<eax>(Moho::UserUnit *unit@<eax>);
     *
     * What it does:
     * Resolves the entity `unit` is currently focused on (building, repairing,
     * assisting): reads the replicated focus id at `unit+0x210` --
     * `mUnitVarDat` (+0x198) `.mFocusUnit` (+0x78) -- and looks it up in the
     * active session's entity map (0x00898DC0), null when absent. The only
     * caller, `EstimateDrawNodeWorkTicks` (0x008270DA), passes the assisting
     * unit in `eax`; it was typed here as an anonymous "command owner" with a
     * padded overlay over the +0x210 dword.
     */
    [[nodiscard]] UserEntity* ResolveUnitFocusEntity(const UserUnit* const unit)
    {
      CWldSession* const session = moho::WLD_GetSession();
      if (unit == nullptr || session == nullptr) {
        return nullptr;
      }

      return session->LookupEntityId(unit->mUnitVarDat.mFocusUnit);
    }
}


  /**
   * Address: 0x00826F10 (FUN_00826F10, sub_826F10)
   *
   * IDA signature:
   * int __stdcall sub_826F10(Moho::UICommandGraph *graph,
   *                          Moho::UICommandGraph::UICommandGraphDrawNode *drawNode);
   *
   * What it does: see the declaration above `RebuildCommandQueueNodes`.
   *
   * It sits here rather than beside `EstimateEdgeTravelTicks` because it needs
   * `ResolveUnitFocusEntity` from the anonymous namespace above.
   *
   * Two shapes worth keeping honest, both read off the disassembly rather than
   * the decompiler, which renders them misleadingly:
   *
   * - the blueprint fetch at 0x0082708A takes no argument. The decompiler shows
   *   a stale `v33` (the FACTORY category) riding along; the actual instructions
   *   are `lea ecx,[esi+148h]` + `call [vptr+1Ch]`, i.e. plain
   *   `IUnit::GetBlueprint()` through the `UserUnit+0x148` bridge.
   * - the loop body is wrapped in a real `try`/`catch`. The decompiler hides it
   *   entirely; the funclet at 0x008271C9 pulls the message off the caught
   *   object and warns "Error estimating work time: %s", then resumes at
   *   0x008271EE, which is the iterator advance - so one unit whose Lua model
   *   throws is skipped rather than abandoning the whole estimate.
   */
  std::int32_t EstimateDrawNodeWorkTicks(
    UICommandGraph& graph, UICommandGraph::UICommandGraphDrawNode& drawNode
  )
  {
    LuaPlus::LuaState* const state = GetUiManagerGlobalLaneA()->mLuaState;

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return 0;
    }

    // Kept at two calls exactly as 0x00826F52/0x00826F5E emit them, and the
    // virtual's result really is dropped at 0x00826F6A (slot 3, `IsUserUnit`).
    // The resolver is not pure - it unlinks the transient anchor sample from
    // whatever weak-entity chain the lookup joined it to - so collapsing the
    // pair would drop a side effect the original source performs twice.
    if (ResolveCommandTargetEntity(*helper) != nullptr) {
      (void)ResolveCommandTargetEntity(*helper)->IsUserUnit();
    }

    REntityBlueprint* const orderedBlueprint = helper->mConstantData.blueprint;

    // Seeds: a command nobody is working on yet still has all of its work left,
    // and no assisting unit means no build rate at all.
    float remainingWorkFraction = 1.0f;
    float combinedBuildRate = 0.0f;

    // Only the two build orders carry work; the order graph treats everything
    // else as costing no time. The binary re-resolves the type for the second
    // test rather than reusing the first result.
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile
      && ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildFactory) {
      return 0;
    }

    LuaPlus::LuaObject gameModule = SCR_Import(state, "/lua/game.lua");
    LuaPlus::LuaObject constructEconomyModelObject = gameModule["GetConstructEconomyModel"];
    LuaPlus::LuaFunction<> getConstructEconomyModel(constructEconomyModelObject);

    // Engineers and factories are the two things that can pour build power into
    // an order, so the walk below tests membership of their union once per unit.
    const EntityCategorySet* const factoryCategory =
      graph.mSession->mRules->GetEntityCategory("FACTORY");
    const EntityCategorySet* const engineerCategory =
      graph.mSession->mRules->GetEntityCategory("ENGINEER");
    EntityCategorySet assistingCategory{};
    (void)func_EntityCategoryAdd(engineerCategory, &assistingCategory, factoryCategory);

    for (UserUnit* const unit : *ResolveCommandIssueCursorEntities(*helper)) {
      const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();

      if (assistingCategory.ContainsBit(blueprint->mCategoryBitIndex) && orderedBlueprint != nullptr) {
        // How much of the job is left is read off whatever this unit is
        // currently working on, and only while it is working on *this* order -
        // an engineer queued to help later must not shorten the estimate.
        if (UserEntity* const workTarget = ResolveUnitFocusEntity(unit);
            workTarget != nullptr) {
          if (ResolveUserUnitFrontCommandIssueHelper(unit->GetCommandQueue()) == helper) {
            const float maxHealth = workTarget->mVariableData.mMaxHealth;
            if (maxHealth > 0.0f) {
              const float remaining = 1.0f - (workTarget->mVariableData.mHealth / maxHealth);
              if (remainingWorkFraction > remaining) {
                remainingWorkFraction = remaining;
              }
            }
          }
        }

        // Rates add as reciprocals: each assister contributes 1/buildTime, and
        // the combined rate is what the remaining fraction is divided by below.
        try {
          LuaPlus::LuaObject luaBlueprint = orderedBlueprint->GetLuaBlueprint(state);
          const auto buildRate = static_cast<float>(getConstructEconomyModel.Call_UserunitObject_Num(
            unit != nullptr ? &unit->mLuaObj : nullptr, luaBlueprint["Economy"]
          ));
          if (buildRate > 0.0f) {
            combinedBuildRate += 1.0f / buildRate;
          }
        } catch (const std::exception& exception) {
          gpg::Warnf("Error estimating work time: %s", exception.what());
        }
      }
    }

    if (combinedBuildRate <= 0.0f) {
      return 0;
    }

    // Truncated, not rounded: 0x0082725F ORs 0xC00 into the x87 control word
    // (round toward zero) for the one `fistp` and restores it straight after.
    return static_cast<std::int32_t>(
      (remainingWorkFraction * kCommandGraphTicksPerSecond) / combinedBuildRate
    );
  }

  /**
   * Bridge for `Moho::DrawAllUnitSkirts` (FUN_0085AD80): resolves the world
   * position a pending command-issue helper is anchored at. The binary inlines
   * FUN_0081CFD0's resolve-target / target-to-position / release trio straight
   * into the skirt loop (asm 0x0085AE88..0x0085AEB7).
   */
  Wm3::Vector3f ResolveCommandIssueHelperAnchorPosition(UserCommandIssueHelper& helper)
  {
    Wm3::Vector3f out{};
    (void)ResolveCommandIssueTargetPosition(&out, helper);
    return out;
  }

  /**
   * Address: 0x0082A030 (FUN_0082A030, sub_82A030)
   *
   * IDA signature:
   * void __userpurge sub_82A030(Moho::UICommandGraph *graph@<eax>, unsigned int a2);
   *
   * What it does:
   * Looks the dragged command up in the session's command manager; a command
   * with no live helper (already retired) is left alone. `mMapAB0` keys its
   * draw nodes by the helper's own pointer identity, not the command id
   * (0x0082A039/0x0082A051, the same convention `ProcessCommandDrag` uses) -
   * a node only exists here if the drag actually moved the mouse at least
   * once, so a helper with no existing node is also left alone
   * (0x0082A085..0x0082A0AE: an inlined equal-range walk over
   * the legacy map's equal range, now expressed by `count`). Otherwise finds that node
   * (0x0082A0BD, `DrawNodeMap::operator[]`) and snaps it back to a
   * single-contributor anchor at the command's own real position
   * (0x0082A0D2, `ResolveCommandIssueHelperAnchorPosition`), replacing
   * `mPositionSum`, forcing `mWeight` back to `1.0f`, and clearing
   * `mHasResolvedPosition` so the next per-tick rebuild recomputes the node
   * from real queue data rather than leaving the drag preview position
   * sitting there. This is "drop the dragged command's highlight": the
   * only thing `OnCurrentDraggerReplaced` (0x00824290) does before
   * `delete this`.
   */
  void ReanchorCommandGraphDrawNode(UICommandGraph& graph, const CmdId cmdId)
  {
    CommandManager* const commandManager = graph.mSession->mCommandManager;

    UserCommandIssueHelper* helper = nullptr;
    if (const auto found = commandManager->mCommands.find(cmdId); found != commandManager->mCommands.end()) {
      helper = found->second;
    }
    if (helper == nullptr) {
      return;
    }

    // Same keying convention as ProcessCommandDrag's own note: mMapAB0's
    // draw-node hash is keyed by the helper's own pointer identity.

    if (graph.mMapAB0.count(helper) != 0) {
      UICommandGraph::UICommandGraphDrawNode* const drawNode =
        &graph.mMapAB0[helper];

      drawNode->mPositionSum = ResolveCommandIssueHelperAnchorPosition(*helper);
      drawNode->mWeight = 1.0f;
      drawNode->mHasResolvedPosition = 0u;
    }
  }

  /**
   * Not a distinct binary function - promotes the file-private
   * `ResolveCommandIssueTargetPosition` (= FUN_0081CFD0) so
   * `UICommandGraph::DrawPositionNodeMesh` (a different TU) can resolve a
   * command's world-space anchor.
   */
  Wm3::Vector3f ResolveCommandGraphAnchorWorldPosition(UserCommandIssueHelper& helper) noexcept
  {
    Wm3::Vector3f position{};
    (void)ResolveCommandIssueTargetPosition(&position, helper);
    return position;
  }

  /**
   * Address: 0x00826960 (FUN_00826960, sub_826960)
   *
   * IDA signature:
   * void __fastcall sub_826960(int a1, int a2, int a3, int a4);
   * (a1@ecx = toNode, a2@edx = fromNode, a3 = graph, a4 = forceHighlight)
   *
   * What it does:
   * Finds-or-creates the `{fromNode, toNode}` edge in `graph.mMapC`
   * (`EdgeMap::operator[]`, 0x0082B490), and on first touch wires
   * its `mFromNode`/`mToNode`, appends it into both endpoints' dword lanes
   * (`fromNode.mLaneB`, `toNode.mLaneA`), retains its owning command's
   * per-command-type orderline texture (`graph.mNodes[commandType]`) into
   * `graph.mCommandGraphTree[texture]`'s edge bucket
   * (`FindOrInsertCommandGraphBucket`, 0x0082B8B0) and pushes the edge
   * into it. Every call bumps the edge's touch count and (re)prices its
   * orderline width: `graph.mMapD` caches `CalculateWaypointLineWidth`'s
   * Lua result keyed by touch count, so repeat visits within the same
   * rebuild skip the Lua round-trip.
   *
   * Native pointer-keyed EdgeMap and the integral WidthMap provide the
   * original legacy hash-table find/insert behavior.
   */
  void LinkCommandGraphEdge(
    UICommandGraph::UICommandGraphDrawNode& toNode, UICommandGraph::UICommandGraphDrawNode& fromNode,
    UICommandGraph& graph, const bool forceHighlight
  )
  {
    UICommandGraph::CommandGraphEdge* const edge =
      &graph.mMapC[UICommandGraph::DrawNodePair{&fromNode, &toNode}];

    if (edge->mToNode == nullptr) {
      edge->mFromNode = &fromNode;
      edge->mToNode = &toNode;

      // `fastvector_n<CommandGraphEdge*, 2>::push_back` on both endpoints.
      fromNode.mLaneB.push_back(edge);
      toNode.mLaneA.push_back(edge);

      auto* const helper = toNode.mHelperLink.GetObjectPtr();
      const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
      const UICommandGraph::CommandGraphNode& style = graph.mNodes[static_cast<std::size_t>(commandType)];

      const boost::shared_ptr<ID3DTextureSheet> texture = boost::SharedPtrFromRawRetained(
        reinterpret_cast<const boost::SharedPtrRaw<ID3DTextureSheet>&>(style.mOrderlineTexture)
      );
      if (texture) {
        fa::vector<UICommandGraph::CommandGraphEdge*>& bucket = UICommandGraph::FindOrInsertCommandGraphBucket(
          graph.mCommandGraphTree, boost::SharedPtrRawFromSharedBorrow(texture)
        );
        bucket.push_back(edge);
      }
    }

    ++edge->mTouchCount;
    edge->mForceHighlightStyle = forceHighlight;

    const auto cached = graph.mMapD.find(edge->mTouchCount);
    float width;
    if (cached == graph.mMapD.end()) {
      const LuaPlus::LuaObject waypointModule = SCR_Import(g_UIManager->mLuaState, "/lua/ui/game/commandwaypoint.lua");
      LuaPlus::LuaFunction<float> calculateWaypointLineWidth{waypointModule["CalculateWaypointLineWidth"]};
      width = calculateWaypointLineWidth(edge->mTouchCount);

      graph.mMapD.insert(std::make_pair(edge->mTouchCount, width));
    } else {
      width = cached->second;
    }
    edge->mBaseWidth = width;
  }

  /**
   * The command-graph rebuild frontier: `CreateMeshes`'s chain calls this.
   *
   * Address: 0x00826140 (FUN_00826140, sub_826140)
   *
   * IDA signature:
   * void __thiscall sub_826140(Moho::UserEntity *this, Moho::UICommandGraph *graph,
   *                            Moho::UserCommandQueue *queue);
   *
   * What it does:
   * Folds one entity's command queue into the graph: walks the queue's resolved
   * command-issue helpers, finds-or-creates a draw node per command, adds this
   * entity's position into the queue-head node's centroid accumulator, and
   * chains consecutive orders together through `LinkCommandGraphEdge`
   * (0x00826960, recovered above).
   *
   * `CWldSession+0x4C0`'s former layout gap - `0x0082624C`'s
   * load/subtract-8/vtable-slot-3 dispatch - is `CWldSession::GetHoveredUserEntity()`
   * (already promoted to a public accessor "so the command-graph render pass
   * can call it too" - its own doc comment already anticipated this exact
   * call site).
   *
   * The queue pre-scan (0x00826295-0x008262E2) walks the queue's entries,
   * asking each command's helper for its entities-under-cursor set
   * (`GetEntitiesUnderCursor`) and testing the hovered entity against it with
   * `WeakSet<UserUnit>::Find` (0x0082CEA0, set `find` 0x0082E560).
   *
   * A draw node that has no helper yet joins the one it was just found for
   * (0x008261B0-0x00826200): the unlink the binary runs first is a no-op on
   * the empty `WeakPtr`, so it is `ResetFromObject(helper)`.
   *
   * The Attack/FormAttack anchor test reads the kind of the helper's current
   * `UserTarget` (`ResolveCommandIssueTarget`, 0x008B4080) and releases that
   * transient target (`~UserTarget`, 0x0081D010) before testing it.
   */
  void AddCommandQueueToCommandGraph(UserEntity& entity, UICommandGraph& graph, UserCommandQueue* const queue)
  {
    if (queue == nullptr) {
      return;
    }

    // 0x00826173 / 0x008261A2: the binary asks the queue for its live link run
    // twice -- `struct_UserUnitManager::Get(a3)` -- once for the emptiness test
    // and once for the head entry. That accessor answers `primaryLinks` while
    // no issue is pending and only falls back to the rebuilt `resolvedLinks`
    // view when the pending-issue ring has something in it. Reading
    // `resolvedLinks` directly, as this did, sees an empty run in the steady
    // state, so no unit ever contributed a node and the whole shift-held
    // command graph drew nothing.
    auto* const queueLinks = GetUserUnitManagerQueueLinks(queue);
    if (queueLinks == nullptr || queueLinks->empty()) {
      return;
    }

    UserUnit* const asUnit = entity.IsUserUnit();
    IUnit* const iunit = asUnit != nullptr ? GetIUnitBridge(asUnit) : nullptr;
    if (asUnit != nullptr && iunit != nullptr && iunit->IsUnitState(UNITSTATE_BeingUpgraded)) {
      return;
    }

    // Queue-head node: keyed by the first resolved link's helper pointer,
    // accumulates every unit sharing this queue's centroid.
    UICommandGraph::UICommandGraphDrawNode* queueHeadNode =
      &graph.mMapAB1[queueLinks->front().GetObjectPtr()];
    queueHeadNode->mPositionSum.x += entity.mVariableData.mCurTransform.pos_.x;
    queueHeadNode->mPositionSum.y += entity.mVariableData.mCurTransform.pos_.y;
    queueHeadNode->mPositionSum.z += entity.mVariableData.mCurTransform.pos_.z;
    queueHeadNode->mWeight += 1.0f;

    UserEntity* const hoveredEntity = graph.mSession->GetHoveredUserEntity();

    // Pre-scan: does any queued command's entities-under-cursor set contain
    // the hovered entity, or does any command's id match the session's
    // currently-highlighted command? Either forces every edge in this
    // queue's chain to render highlighted, until the matching command is
    // reached.
    bool anyHighlight = false;
    for (const WeakPtr<UserCommandIssueHelper>& link : *queueLinks) {
      UserCommandIssueHelper* const helper = link.GetObjectPtr();
      if (helper == nullptr) {
        continue;
      }

      if (hoveredEntity != nullptr) {
        WeakSet<UserUnit>* const cursorEntities = ResolveCommandIssueCursorEntities(*helper);
        if (cursorEntities->Find(static_cast<UserUnit*>(hoveredEntity)) != cursorEntities->end()) {
          anyHighlight = true;
          break;
        }
      }
      if (helper->mConstantData.cmd == graph.mSession->HighlightCommandId) {
        anyHighlight = true;
        break;
      }
    }

    // Command types this graph never draws an order node for.
    constexpr std::uint64_t kExcludedCommandTypeMask = 0x2D80000EAULL;

    UICommandGraph::UICommandGraphDrawNode* previousNode = queueHeadNode;
    std::int32_t previousCommandType = 0;
    UICommandGraph::UICommandGraphDrawNode* anchorNode = nullptr;

    for (const WeakPtr<UserCommandIssueHelper>& link : *queueLinks) {
      UserCommandIssueHelper* const helper = link.GetObjectPtr();
      if (helper == nullptr) {
        continue;
      }

      const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
      const std::uint64_t typeBit = std::uint64_t{1} << static_cast<std::int32_t>(commandType);
      if ((typeBit & kExcludedCommandTypeMask) != 0u) {
        continue;
      }

      UICommandGraph::UICommandGraphDrawNode* const currentNode =
        &graph.mMapAB0[helper];

      if (!currentNode->mHelperLink.HasValue()) {
        // 0x00826374/0x00826386: reset an expired node before binding a new helper.
        *currentNode = UICommandGraph::UICommandGraphDrawNode{};
        // First touch: publish the command id, join the owning helper's
        // draw-node chain, and seed the node's own anchor position/weight
        // from the helper's command history.
        currentNode->mCommandId = static_cast<CmdId>(helper->mConstantData.cmd);
        currentNode->mHelperLink.ResetFromObject(helper);
        currentNode->mPositionSum = ResolveCommandGraphAnchorWorldPosition(*helper);
        currentNode->mWeight = 1.0f;
      }

      currentNode->mIsChainBoundary = 0u;
      if (previousCommandType != 0 && previousCommandType != static_cast<std::int32_t>(commandType)) {
        previousNode->mIsChainBoundary = 1u;
      }
      previousCommandType = static_cast<std::int32_t>(commandType);

      const float invWeight = 1.0f / previousNode->mWeight;
      currentNode->mPreviousCentroid.x = previousNode->mPositionSum.x * invWeight;
      currentNode->mPreviousCentroid.y = previousNode->mPositionSum.y * invWeight;
      currentNode->mPreviousCentroid.z = previousNode->mPositionSum.z * invWeight;

      if (anchorNode == nullptr) {
        switch (commandType) {
        case EUnitCommandType::UNITCOMMAND_Attack:
        case EUnitCommandType::UNITCOMMAND_FormAttack: {
          // The transient target is released at the end of this full
          // expression, before the kind test, as the binary orders it.
          const bool targetsGround = ResolveCommandIssueTarget(*helper).targetType == UserTargetType::Position;
          if (targetsGround) {
            anchorNode = currentNode;
          }
          break;
        }
        case EUnitCommandType::UNITCOMMAND_Guard:
        case EUnitCommandType::UNITCOMMAND_Patrol:
        case EUnitCommandType::UNITCOMMAND_FormPatrol:
          anchorNode = currentNode;
          break;
        default:
          break;
        }
      }

      if (anyHighlight && helper->mConstantData.cmd == graph.mSession->HighlightCommandId) {
        anyHighlight = false;
      }
      LinkCommandGraphEdge(*currentNode, *previousNode, graph, anyHighlight);

      previousNode = currentNode;
    }

    previousNode->mIsChainBoundary = 1u;
    if (anchorNode != nullptr && anchorNode != previousNode) {
      LinkCommandGraphEdge(*anchorNode, *previousNode, graph, anyHighlight);
    }
  }

  /**
   * Address: 0x0085AF40 (FUN_0085AF40, sub_85AF40)
   *
   * What it does:
   * Peeks at the command graph - `GetCommandGraph(false)` (0x0085AF61), so
   * this never creates one - and draws its mesh when one is alive
   * (0x0085AF8E), releasing the temporary afterwards (0x0085AF9B..0x0085AFCB).
   */
  void CWldSession::RenderCommandGraph(
    const GeomCamera3& camera, CD3DPrimBatcher* const batcher, const std::int32_t gameTick, const float tickFraction
  )
  {
    if (const boost::shared_ptr<UICommandGraph> graph = GetCommandGraph(false)) {
      graph->DrawCommandGraphMesh(camera, *batcher, gameTick, tickFraction);
    }
  }
}

