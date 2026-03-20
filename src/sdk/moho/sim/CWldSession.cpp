#include "CWldSession.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "gpg/core/utils/Logging.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  class CD3DFont
  {
  public:
    /**
     * Address: 0x00425290 (FUN_00425290,
     * ?Create@CD3DFont@Moho@@SA?AV?$CountedPtr@VCD3DFont@Moho@@@2@HVStrArg@gpg@@@Z)
     */
    static boost::SharedPtrRaw<CD3DFont> Create(std::int32_t pointSize, const char* faceName);

    /**
     * Address: slot-0 release callsite in 0x00824810.
     */
    virtual void Release(std::int32_t destroyNow) = 0;

  public:
    std::int32_t mRefCount; // +0x04
  };

  class UICommandGraph
  {
  public:
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
    struct CommandGraphNode
    {
      std::uint8_t mRaw[0x54];
    };

    template <std::size_t kNodeSize>
    struct HashListNode
    {
      HashListNode* mNext;
      HashListNode* mPrev;
      std::uint8_t mPayload[kNodeSize - 8];
    };

    using HashListNode88 = HashListNode<0x88>;
    using HashListNode2C = HashListNode<0x2C>;
    using HashListNode10 = HashListNode<0x10>;

    struct HashBucketVector
    {
      void* mAllocProxy; // +0x00
      void** mStart;     // +0x04
      void** mFinish;    // +0x08
      void** mEnd;       // +0x0C
    };

    template <typename TNode>
    struct HashTable
    {
      std::uint8_t mOwnerByte; // +0x00
      std::uint8_t pad_01[7];
      TNode* mListHead;           // +0x08
      std::uint32_t mListSize;    // +0x0C
      HashBucketVector mBuckets;  // +0x10
      std::uint32_t mBucketMask;  // +0x20
      std::uint32_t mBucketCount; // +0x24
    };

    struct CommandGraphTreeNode
    {
      CommandGraphTreeNode* mLeft;    // +0x00
      CommandGraphTreeNode* mParent;  // +0x04
      CommandGraphTreeNode* mRight;   // +0x08
      std::uint8_t mPayload[0x18];    // +0x0C
      std::uint8_t mColorOrAllocated; // +0x24
      std::uint8_t mIsSentinel;       // +0x25
      std::uint8_t pad_26[2];
    };

    struct CommandGraphTree
    {
      void* mAllocProxy;           // +0x00
      CommandGraphTreeNode* mHead; // +0x04
      std::uint32_t mSize;         // +0x08
    };

  private:
    static void ReleaseIntrusive(CD3DFont*& font);
    static void AssignIntrusive(CD3DFont*& dst, CD3DFont* src);
    static void DestroyBuckets(HashBucketVector& buckets);
    static void InitBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082F030 (FUN_0082F030)
     */
    static HashListNode88* AllocateMapABListSentinel();

    /**
     * Address: 0x0082F5B0 (FUN_0082F5B0)
     */
    static HashListNode2C* AllocateMapCListSentinel();

    /**
     * Address: 0x0082FAF0 (FUN_0082FAF0)
     */
    static HashListNode10* AllocateMapDListSentinel();

    /**
     * Address: 0x0082F110 (FUN_0082F110)
     */
    static void InitMapABBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082F680 (FUN_0082F680)
     */
    static void InitMapCBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082FB80 (FUN_0082FB80)
     */
    static void InitMapDBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082BF40 (FUN_0082BF40)
     */
    static void InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C400 (FUN_0082C400)
     */
    static void InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C8D0 (FUN_0082C8D0)
     */
    static void InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* owner);

    template <typename TNode>
    static void DestroyMap(HashTable<TNode>& table);

    /**
     * Address: 0x008300D0 (FUN_008300D0)
     */
    static CommandGraphTreeNode* AllocateTreeSentinelNode();

    static void InitTree(CommandGraphTree& tree);
    static void DestroyTree(CommandGraphTree& tree);

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
     */
    void CreateMeshes();

  private:
    std::uint8_t mNeedsRebuild; // +0x0000
    std::uint8_t pad_0001[3];
    CommandGraphNode mNodes[40];        // +0x0004
    CWldSession* mSession;              // +0x0D24
    void* mSessionRes1;                 // +0x0D28
    CD3DFont* mDebugFont;               // +0x0D2C
    HashTable<HashListNode88> mMapAB0;  // +0x0D30
    HashTable<HashListNode88> mMapAB1;  // +0x0D58
    HashTable<HashListNode2C> mMapC;    // +0x0D80
    HashTable<HashListNode10> mMapD;    // +0x0DA8
    CommandGraphTree mGraphRuntimeTree; // +0x0DD0
  };

  static_assert(sizeof(UICommandGraph::CommandGraphNode) == 0x54, "UICommandGraph::CommandGraphNode size must be 0x54");
  static_assert(sizeof(UICommandGraph::HashListNode88) == 0x88, "UICommandGraph::HashListNode88 size must be 0x88");
  static_assert(sizeof(UICommandGraph::HashListNode2C) == 0x2C, "UICommandGraph::HashListNode2C size must be 0x2C");
  static_assert(sizeof(UICommandGraph::HashListNode10) == 0x10, "UICommandGraph::HashListNode10 size must be 0x10");
  static_assert(sizeof(UICommandGraph::HashBucketVector) == 0x10, "UICommandGraph::HashBucketVector size must be 0x10");
  static_assert(
    sizeof(UICommandGraph::HashTable<UICommandGraph::HashListNode88>) == 0x28,
    "UICommandGraph::HashTable size must be 0x28"
  );
  static_assert(
    sizeof(UICommandGraph::CommandGraphTreeNode) == 0x28, "UICommandGraph::CommandGraphTreeNode size must be 0x28"
  );
  static_assert(sizeof(UICommandGraph::CommandGraphTree) == 0x0C, "UICommandGraph::CommandGraphTree size must be 0x0C");
  static_assert(sizeof(UICommandGraph) == 0xDDC, "UICommandGraph size must be 0xDDC");

  struct SBuildTemplateInfo
  {
    Wm3::Vector3f mPos;         // +0x00
    float mHeading;             // +0x0C
    msvc8::string mBlueprintId; // +0x10
  };

  static_assert(sizeof(SBuildTemplateInfo) == 0x2C, "SBuildTemplateInfo size must be 0x2C");
  static_assert(
    offsetof(SBuildTemplateInfo, mBlueprintId) == 0x10, "SBuildTemplateInfo::mBlueprintId offset must be 0x10"
  );

  namespace
  {
    struct VizUpdateNode
    {
      VizUpdateNode* left;          // +0x00
      VizUpdateNode* parent;        // +0x04
      VizUpdateNode* right;         // +0x08
      std::uintptr_t key;           // +0x0C
      std::uintptr_t ownerLinkHead; // +0x10
      std::uintptr_t ownerNextLink; // +0x14
      std::uint8_t color;           // +0x18 (0=red, 1=black)
      std::uint8_t isSentinel;      // +0x19
      std::uint8_t pad_1A[2];
    };

    static_assert(sizeof(VizUpdateNode) == 0x1C, "VizUpdateNode size must be 0x1C");

    struct VizUpdateTree
    {
      void* debugProxy;    // +0x00
      VizUpdateNode* head; // +0x04
      std::uint32_t size;  // +0x08
    };

    static_assert(sizeof(VizUpdateTree) == 0x0C, "VizUpdateTree size must be 0x0C");

    [[nodiscard]] VizUpdateTree* GetVizUpdateTree(CWldSession* session)
    {
      return reinterpret_cast<VizUpdateTree*>(&session->mVizUpdateRoot);
    }

    [[nodiscard]] const VizUpdateTree* GetVizUpdateTree(const CWldSession* session)
    {
      return reinterpret_cast<const VizUpdateTree*>(&session->mVizUpdateRoot);
    }

    void DestroyBuildTemplateRange(SBuildTemplateInfo* first, SBuildTemplateInfo* last)
    {
      while (first != last) {
        if (first->mBlueprintId.myRes >= 0x10u) {
          ::operator delete(first->mBlueprintId.bx.ptr);
        }
        first->mBlueprintId.myRes = 15;
        first->mBlueprintId.mySize = 0;
        first->mBlueprintId.bx.buf[0] = '\0';
        ++first;
      }
    }

    template <typename T>
    void ReleaseSharedRaw(boost::SharedPtrRaw<T>& value)
    {
      if (value.pi) {
        value.pi->release();
      }
      value.px = nullptr;
      value.pi = nullptr;
    }

    [[nodiscard]] boost::detail::sp_counted_base* CreateBoostControlForUICommandGraph(UICommandGraph* const graph)
    {
      if (!graph) {
        return nullptr;
      }

      auto* const control = new (std::nothrow) boost::detail::sp_counted_impl_p<UICommandGraph*>(graph);
      if (!control) {
        delete graph;
        return nullptr;
      }
      return control;
    }

    [[nodiscard]] boost::SharedPtrRaw<UICommandGraph>
    LockWeakCommandGraph(UICommandGraph* px, boost::detail::sp_counted_base* control)
    {
      if (!px || !control) {
        return {};
      }

      if (!control->add_ref_lock()) {
        return {};
      }

      boost::SharedPtrRaw<UICommandGraph> out{};
      out.px = px;
      out.pi = control;
      return out;
    }

    void AssignSharedCommandGraph(boost::SharedPtrRaw<UICommandGraph>& out, UICommandGraph* const graph)
    {
      boost::detail::sp_counted_base* const newControl = CreateBoostControlForUICommandGraph(graph);
      UICommandGraph* const ownedGraph = newControl ? graph : nullptr;

      if (out.pi) {
        out.pi->release();
      }

      out.px = ownedGraph;
      out.pi = newControl;
    }

    void CopySharedToWeakCommandGraph(
      const boost::SharedPtrRaw<UICommandGraph>& shared,
      UICommandGraph*& weakPx,
      boost::detail::sp_counted_base*& weakControl
    )
    {
      if (shared.pi) {
        shared.pi->weak_add_ref();
      }

      if (weakControl) {
        weakControl->weak_release();
      }

      weakPx = shared.px;
      weakControl = shared.pi;
    }

    void ReleaseWeakCommandGraph(UICommandGraph*& px, boost::detail::sp_counted_base*& control)
    {
      if (control) {
        control->weak_release();
      }
      px = nullptr;
      control = nullptr;
    }

    template <typename TNode>
    [[nodiscard]] TNode* AllocateSelfLinkedNode()
    {
      auto* const node = static_cast<TNode*>(::operator new(sizeof(TNode)));
      std::memset(node, 0, sizeof(TNode));
      node->mNext = node;
      node->mPrev = node;
      return node;
    }

  } // namespace

  void UICommandGraph::ReleaseIntrusive(CD3DFont*& font)
  {
    if (!font) {
      return;
    }

    --font->mRefCount;
    if (font->mRefCount == 0) {
      font->Release(1);
    }
    font = nullptr;
  }

  void UICommandGraph::AssignIntrusive(CD3DFont*& dst, CD3DFont* const src)
  {
    if (dst == src) {
      return;
    }

    ReleaseIntrusive(dst);
    dst = src;
    if (dst) {
      ++dst->mRefCount;
    }
  }

  void UICommandGraph::DestroyBuckets(HashBucketVector& buckets)
  {
    if (buckets.mStart) {
      ::operator delete(buckets.mStart);
    }

    buckets.mAllocProxy = nullptr;
    buckets.mStart = nullptr;
    buckets.mFinish = nullptr;
    buckets.mEnd = nullptr;
  }

  void UICommandGraph::InitBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    buckets.mAllocProxy = nullptr;
    buckets.mStart = static_cast<void**>(::operator new(9u * sizeof(void*)));
    buckets.mFinish = buckets.mStart;
    buckets.mEnd = buckets.mStart + 9;
    for (void** it = buckets.mStart; it != buckets.mEnd; ++it) {
      *it = sentinel;
    }
    buckets.mFinish = buckets.mEnd;
  }

  /**
   * Address: 0x0082F030 (FUN_0082F030)
   */
  UICommandGraph::HashListNode88* UICommandGraph::AllocateMapABListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode88>();
  }

  /**
   * Address: 0x0082F5B0 (FUN_0082F5B0)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::AllocateMapCListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode2C>();
  }

  /**
   * Address: 0x0082FAF0 (FUN_0082FAF0)
   */
  UICommandGraph::HashListNode10* UICommandGraph::AllocateMapDListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode10>();
  }

  /**
   * Address: 0x0082F110 (FUN_0082F110)
   */
  void UICommandGraph::InitMapABBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082F680 (FUN_0082F680)
   */
  void UICommandGraph::InitMapCBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082FB80 (FUN_0082FB80)
   */
  void UICommandGraph::InitMapDBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082BF40 (FUN_0082BF40)
   */
  void UICommandGraph::InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapABListSentinel();
    table.mListSize = 0u;
    InitMapABBuckets(table.mBuckets, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C400 (FUN_0082C400)
   */
  void UICommandGraph::InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapCListSentinel();
    table.mListSize = 0u;
    InitMapCBuckets(table.mBuckets, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C8D0 (FUN_0082C8D0)
   */
  void UICommandGraph::InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapDListSentinel();
    table.mListSize = 0u;
    InitMapDBuckets(table.mBuckets, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  template <typename TNode>
  void UICommandGraph::DestroyMap(HashTable<TNode>& table)
  {
    TNode* current = table.mListHead ? table.mListHead->mNext : nullptr;
    while (current && current != table.mListHead) {
      TNode* const next = current->mNext;
      ::operator delete(current);
      current = next;
    }

    if (table.mListHead) {
      ::operator delete(table.mListHead);
      table.mListHead = nullptr;
    }

    table.mListSize = 0u;
    DestroyBuckets(table.mBuckets);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x008300D0 (FUN_008300D0)
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AllocateTreeSentinelNode()
  {
    auto* const node = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    std::memset(node, 0, sizeof(CommandGraphTreeNode));
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

  void UICommandGraph::DestroyTree(CommandGraphTree& tree)
  {
    if (tree.mHead) {
      ::operator delete(tree.mHead);
    }
    tree.mHead = nullptr;
    tree.mSize = 0u;
    tree.mAllocProxy = nullptr;
  }

  /**
   * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
   */
  void UICommandGraph::OnCommandGraphShow(LuaPlus::LuaState* const state, const bool visible)
  {
    if (!state) {
      return;
    }

    lua_State* const cstate = state->GetCState();
    if (!cstate) {
      return;
    }

    const int savedTop = lua_gettop(cstate);
    lua_getglobal(cstate, "import");
    if (!lua_isfunction(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    lua_pushstring(cstate, "/lua/ui/game/commandgraph.lua");
    if (lua_pcall(cstate, 1, 1, 0) != 0) {
      lua_settop(cstate, savedTop);
      return;
    }

    if (!lua_istable(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    // Lua 5.0-era ABI: use push+gettable instead of lua_getfield.
    lua_pushstring(cstate, "OnCommandGraphShow");
    lua_gettable(cstate, -2);
    if (!lua_isfunction(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    lua_pushboolean(cstate, visible ? 1 : 0);
    lua_pcall(cstate, 1, 0, 0);
    lua_settop(cstate, savedTop);
  }

  /**
   * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
   */
  void UICommandGraph::LoadPathParams()
  {
    // Remaining parameter-table merge chain (0x00825570) is pending deep lift.
  }

  /**
   * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
   */
  void UICommandGraph::LoadWaypointParams()
  {
    // Remaining waypoint cvar/Lua sync chain is pending deep lift.
  }

  /**
   * Address: 0x00828FB0 (FUN_00828FB0, Moho::UICommandGraph::CreateMeshes)
   */
  void UICommandGraph::CreateMeshes()
  {
    // Remaining command-graph mesh build pass (0x00829190 chain) is pending deep lift.
  }

  /**
   * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
   */
  UICommandGraph::UICommandGraph(CWldSession* const session)
    : mNeedsRebuild(1u)
    , pad_0001{0, 0, 0}
    , mNodes{}
    , mSession(session)
    , mSessionRes1(session ? session->mSessionRes1 : nullptr)
    , mDebugFont(nullptr)
    , mMapAB0{}
    , mMapAB1{}
    , mMapC{}
    , mMapD{}
    , mGraphRuntimeTree{}
  {
    InitMapAB(mMapAB0, this);
    InitMapAB(mMapAB1, this);
    InitMapC(mMapC, this);
    InitMapD(mMapD, this);
    InitTree(mGraphRuntimeTree);

    boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(10, "Andale Mono");
    AssignIntrusive(mDebugFont, createdFont.px);
    ReleaseSharedRaw(createdFont);

    LoadPathParams();
    LoadWaypointParams();
    CreateMeshes();
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, true);
  }

  /**
   * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
   */
  UICommandGraph::~UICommandGraph()
  {
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, false);
    DestroyTree(mGraphRuntimeTree);
    DestroyMap(mMapD);
    DestroyMap(mMapC);
    DestroyMap(mMapAB1);
    DestroyMap(mMapAB0);
    ReleaseIntrusive(mDebugFont);
    mSessionRes1 = nullptr;
    mSession = nullptr;
    mNeedsRebuild = 0u;
  }

  namespace
  {
    struct SessionSaveSourceNode
    {
      SessionSaveSourceNode* mLeft;   // +0x00
      SessionSaveSourceNode* mParent; // +0x04
      SessionSaveSourceNode* mRight;  // +0x08
      std::uint32_t mCommandSourceId; // +0x0C
      void* mProvider;                // +0x10
      std::uint8_t mColor;            // +0x14
      std::uint8_t mIsSentinel;       // +0x15
      std::uint8_t pad_16[2];
    };

    static_assert(sizeof(SessionSaveSourceNode) == 0x18, "SessionSaveSourceNode size must be 0x18");
    static_assert(
      offsetof(SessionSaveSourceNode, mCommandSourceId) == 0x0C,
      "SessionSaveSourceNode::mCommandSourceId offset must be 0x0C"
    );
    static_assert(
      offsetof(SessionSaveSourceNode, mProvider) == 0x10, "SessionSaveSourceNode::mProvider offset must be 0x10"
    );
    static_assert(
      offsetof(SessionSaveSourceNode, mIsSentinel) == 0x15, "SessionSaveSourceNode::mIsSentinel offset must be 0x15"
    );

    struct SessionSaveTagNode
    {
      SessionSaveTagNode* mLeft;   // +0x00
      SessionSaveTagNode* mParent; // +0x04
      SessionSaveTagNode* mRight;  // +0x08
      msvc8::string mTagName;      // +0x0C
      std::uint8_t mColor;         // +0x28
      std::uint8_t mIsSentinel;    // +0x29
      std::uint8_t pad_2A[2];
    };

    static_assert(sizeof(SessionSaveTagNode) == 0x2C, "SessionSaveTagNode size must be 0x2C");
    static_assert(offsetof(SessionSaveTagNode, mTagName) == 0x0C, "SessionSaveTagNode::mTagName offset must be 0x0C");
    static_assert(
      offsetof(SessionSaveTagNode, mIsSentinel) == 0x29, "SessionSaveTagNode::mIsSentinel offset must be 0x29"
    );

    struct SessionSaveNodeOwnerView
    {
      std::uint8_t pad_0000[0x3D4];
      SessionSaveTagNode* mTagTreeHead; // +0x3D4
    };

    static_assert(
      offsetof(SessionSaveNodeOwnerView, mTagTreeHead) == 0x3D4,
      "SessionSaveNodeOwnerView::mTagTreeHead offset must be 0x3D4"
    );

    class ISessionSaveSourceProvider
    {
    public:
      virtual ~ISessionSaveSourceProvider() = default;
      virtual void* Slot04() = 0;
      virtual void* Slot08() = 0;
      virtual void* GetSaveNodeOwner() = 0; // vtable +0x0C
    };

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

    [[nodiscard]] SessionSaveSourceNode* GetSaveSourceTreeHead(const CWldSession* const session)
    {
      return static_cast<SessionSaveSourceNode*>(session->mSaveSourceTreeHead);
    }

    /**
     * Address: 0x0089A970 allocation path (FUN_0089A970) for insert-node creation.
     *
     * Source-side typed helper used to keep node allocation/layout explicit.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* AllocateSaveDataMapNode()
    {
      auto* const raw = ::operator new(sizeof(SSessionSaveNodeMapNode));
      auto* const node = new (raw) SSessionSaveNodeMapNode{};
      node->mColor = 0u;
      node->mIsSentinel = 0u;
      return node;
    }

    /**
     * Address: 0x0089AC40 cleanup chain (FUN_008971A0 -> FUN_0089AC40 call path).
     */
    void DestroySaveDataMapNode(SSessionSaveNodeMapNode* const node)
    {
      if (!node) {
        return;
      }

      node->~SSessionSaveNodeMapNode();
      ::operator delete(node);
    }

    /**
     * Address: 0x0089A930 (FUN_0089A930) sentinel header-node allocation/init path.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* CreateSaveDataMapHead()
    {
      SSessionSaveNodeMapNode* const head = AllocateSaveDataMapNode();
      head->mColor = 1u;
      head->mIsSentinel = 1u;
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      return head;
    }

    /**
     * Address: 0x0089A8E0 (FUN_0089A8E0).
     */
    void RotateSaveDataLeft(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSentinelNode(pivot->mLeft)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x0089A880 (FUN_0089A880).
     */
    void RotateSaveDataRight(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSentinelNode(pivot->mRight)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x00899DC0 (FUN_00899DC0) RB-tree insert rebalance sequence.
     *
     * Source-side typed split of the original monolithic helper body.
     */
    void FixupSaveDataInsert(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      while (node->mParent->mColor == 0u) {
        SSessionSaveNodeMapNode* const parent = node->mParent;
        SSessionSaveNodeMapNode* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SSessionSaveNodeMapNode* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSaveDataLeft(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataRight(map, node->mParent->mParent);
          }
        } else {
          SSessionSaveNodeMapNode* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSaveDataRight(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataLeft(map, node->mParent->mParent);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    /**
     * Address: 0x008992D0/0x00899DC0/0x0089A970
     * (FUN_008992D0 -> FUN_00899DC0 -> FUN_0089A970 chain).
     *
     * Source-side typed split around search/insert/fixup stages.
     */
    void InsertSaveDataLabelNode(SSessionSaveNodeMap& map, const SSessionSaveNodeLabel& label)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* parent = head;
      SSessionSaveNodeMapNode* current = head->mParent;
      bool insertLeft = true;

      while (!IsSentinelNode(current)) {
        parent = current;
        insertLeft = (label.mCommandSourceId < current->mLabel.mCommandSourceId);
        current = insertLeft ? current->mLeft : current->mRight;
      }

      SSessionSaveNodeMapNode* const node = AllocateSaveDataMapNode();
      node->mLabel.mCommandSourceId = label.mCommandSourceId;
      node->mLabel.mSaveNodeName = label.mSaveNodeName;
      node->mLeft = head;
      node->mRight = head;
      node->mParent = parent;

      ++map.mSize;
      if (parent == head) {
        head->mParent = node;
        head->mLeft = node;
        head->mRight = node;
      } else if (insertLeft) {
        parent->mLeft = node;
        if (parent == head->mLeft) {
          head->mLeft = node;
        }
      } else {
        parent->mRight = node;
        if (parent == head->mRight) {
          head->mRight = node;
        }
      }

      FixupSaveDataInsert(map, node);
    }

    /**
     * Address: 0x008971A0 cleanup path (FUN_008971A0 + FUN_0089AC40).
     *
     * Source-side typed cleanup helper equivalent.
     */
    void DestroySaveDataSubtree(SSessionSaveNodeMapNode* const node, SSessionSaveNodeMapNode* const head)
    {
      if (!node || node == head || node->mIsSentinel != 0u) {
        return;
      }

      DestroySaveDataSubtree(node->mLeft, head);
      DestroySaveDataSubtree(node->mRight, head);
      DestroySaveDataMapNode(node);
    }

    /**
     * Address: 0x008971A0 cleanup path (FUN_008971A0 + FUN_0089AC40).
     */
    void ClearSaveDataMap(SSessionSaveNodeMap& map)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      if (!head) {
        map.mSize = 0u;
        return;
      }

      DestroySaveDataSubtree(head->mParent, head);
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      map.mSize = 0u;
    }

    [[nodiscard]] ECommandMode DefaultModeFromDrag(const std::int32_t dragWord) noexcept
    {
      const std::uint32_t dragMask = static_cast<std::uint32_t>(dragWord) & 0xFF000000u;
      return (dragMask != 0xFF000000u) ? COMMOD_Reclaim : COMMOD_Move;
    }

    [[nodiscard]] LuaPlus::LuaObject ImportLuaModule(LuaPlus::LuaState* state, const char* modulePath)
    {
      if (!state || !modulePath || !*modulePath) {
        return {};
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return {};
      }

      const int savedTop = lua_gettop(lstate);
      lua_getglobal(lstate, "import");
      if (!lua_isfunction(lstate, -1)) {
        lua_settop(lstate, savedTop);
        return {};
      }

      lua_pushstring(lstate, modulePath);
      if (lua_pcall(lstate, 1, 1, 0) != 0) {
        lua_settop(lstate, savedTop);
        return {};
      }

      LuaPlus::LuaObject moduleObj{LuaPlus::LuaStackObject(state, -1)};
      lua_settop(lstate, savedTop);
      return moduleObj;
    }

    [[nodiscard]] LuaPlus::LuaObject
    GetLuaField(LuaPlus::LuaState* state, const LuaPlus::LuaObject& tableObj, const char* fieldName)
    {
      if (!state || !fieldName || !*fieldName || !tableObj || !tableObj.IsTable()) {
        return {};
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return {};
      }

      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(lstate);
      lua_pushstring(lstate, fieldName);
      lua_gettable(lstate, -2);
      LuaPlus::LuaObject result{LuaPlus::LuaStackObject(state, -1)};
      lua_settop(lstate, savedTop);
      return result;
    }

    [[nodiscard]] LuaPlus::LuaObject
    GetLuaIndex(LuaPlus::LuaState* state, const LuaPlus::LuaObject& tableObj, const std::int32_t index)
    {
      if (!state || !tableObj || !tableObj.IsTable()) {
        return {};
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return {};
      }

      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(lstate);
      // Lua 5.0-era ABI: integer index is pushed as number.
      lua_pushnumber(lstate, static_cast<lua_Number>(index));
      lua_gettable(lstate, -2);
      LuaPlus::LuaObject result{LuaPlus::LuaStackObject(state, -1)};
      lua_settop(lstate, savedTop);
      return result;
    }

    [[nodiscard]] bool IsLuaFunction(LuaPlus::LuaState* state, const LuaPlus::LuaObject& obj)
    {
      if (!state || !obj) {
        return false;
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return false;
      }

      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(obj).PushStack(lstate);
      const bool isFn = lua_isfunction(lstate, -1) != 0;
      lua_settop(lstate, savedTop);
      return isFn;
    }

    struct UICommandModeData
    {
      msvc8::string mode;
      LuaPlus::LuaObject obj;
    };

    [[nodiscard]] bool TryGetUICommandMode(LuaPlus::LuaState* state, UICommandModeData& out)
    {
      LuaPlus::LuaObject module = ImportLuaModule(state, "/lua/ui/game/commandmode.lua");
      if (!module || !module.IsTable()) {
        return false;
      }

      LuaPlus::LuaObject getCommandMode = GetLuaField(state, module, "GetCommandMode");
      if (!IsLuaFunction(state, getCommandMode)) {
        return false;
      }

      LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{getCommandMode};
      LuaPlus::LuaObject result = fn();
      if (!result || !result.IsTable()) {
        return false;
      }

      LuaPlus::LuaObject modeField = GetLuaIndex(state, result, 1);
      if (modeField && modeField.IsString()) {
        const char* const modeName = modeField.GetString();
        out.mode = modeName ? modeName : "";
      }

      LuaPlus::LuaObject payloadField = GetLuaIndex(state, result, 2);
      if (payloadField && payloadField.IsTable()) {
        out.obj = payloadField;
      }

      return true;
    }

    [[nodiscard]] VizUpdateNode* TreeMin(VizUpdateNode* node, VizUpdateNode* head)
    {
      while (node != nullptr && node != head && node->left != head) {
        node = node->left;
      }
      return node ? node : head;
    }

    [[nodiscard]] VizUpdateNode* TreeMax(VizUpdateNode* node, VizUpdateNode* head)
    {
      while (node != nullptr && node != head && node->right != head) {
        node = node->right;
      }
      return node ? node : head;
    }

    [[nodiscard]] VizUpdateNode* FindVizUpdateNode(VizUpdateTree* tree, const std::uintptr_t key)
    {
      if (!tree || !tree->head) {
        return nullptr;
      }

      VizUpdateNode* candidate = tree->head;
      VizUpdateNode* current = tree->head->parent;
      while (current && current->isSentinel == 0) {
        if (current->key >= key) {
          candidate = current;
          current = current->left;
        } else {
          current = current->right;
        }
      }

      if (!candidate || candidate == tree->head || key < candidate->key) {
        return tree->head;
      }
      return candidate;
    }

    void RotateLeft(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const pivot = node->right;
      node->right = pivot->left;
      if (pivot->left && pivot->left->isSentinel == 0) {
        pivot->left->parent = node;
      }

      pivot->parent = node->parent;
      if (node == tree->head->parent) {
        tree->head->parent = pivot;
      } else if (node == node->parent->left) {
        node->parent->left = pivot;
      } else {
        node->parent->right = pivot;
      }

      pivot->left = node;
      node->parent = pivot;
    }

    void RotateRight(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const pivot = node->left;
      node->left = pivot->right;
      if (pivot->right && pivot->right->isSentinel == 0) {
        pivot->right->parent = node;
      }

      pivot->parent = node->parent;
      if (node == tree->head->parent) {
        tree->head->parent = pivot;
      } else if (node == node->parent->right) {
        node->parent->right = pivot;
      } else {
        node->parent->left = pivot;
      }

      pivot->right = node;
      node->parent = pivot;
    }

    void Transplant(VizUpdateTree* tree, VizUpdateNode* from, VizUpdateNode* to)
    {
      if (from->parent == tree->head) {
        tree->head->parent = to;
      } else if (from == from->parent->left) {
        from->parent->left = to;
      } else {
        from->parent->right = to;
      }

      if (to != tree->head) {
        to->parent = from->parent;
      }
    }

    void UnlinkOwnerChain(VizUpdateNode* node)
    {
      if (!node || node->ownerLinkHead == 0u) {
        return;
      }

      auto* slot = reinterpret_cast<std::uintptr_t*>(node->ownerLinkHead);
      const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&node->ownerLinkHead);

      std::size_t guard = 0;
      while (slot && *slot != target && guard < 65536u) {
        slot = reinterpret_cast<std::uintptr_t*>(*slot + sizeof(std::uintptr_t));
        ++guard;
      }

      if (slot && *slot == target) {
        *slot = node->ownerNextLink;
      }

      node->ownerLinkHead = 0u;
      node->ownerNextLink = 0u;
    }

    void DeleteFixup(VizUpdateTree* tree, VizUpdateNode* node, VizUpdateNode* parentHint)
    {
      VizUpdateNode* head = tree->head;
      VizUpdateNode* parent = (node != head) ? node->parent : parentHint;

      while (node != head->parent && (node == head || node->color == 1u)) {
        if (!parent) {
          break;
        }

        if (node == parent->left) {
          VizUpdateNode* sibling = parent->right;
          if (sibling == head) {
            break;
          }

          if (sibling->color == 0u) {
            sibling->color = 1u;
            parent->color = 0u;
            RotateLeft(tree, parent);
            sibling = parent->right;
          }

          const bool siblingLeftBlack = (sibling->left == head) || (sibling->left->color == 1u);
          const bool siblingRightBlack = (sibling->right == head) || (sibling->right->color == 1u);
          if (siblingLeftBlack && siblingRightBlack) {
            sibling->color = 0u;
            node = parent;
            parent = node->parent;
          } else {
            if ((sibling->right == head) || (sibling->right->color == 1u)) {
              if (sibling->left != head) {
                sibling->left->color = 1u;
              }
              sibling->color = 0u;
              RotateRight(tree, sibling);
              sibling = parent->right;
            }

            sibling->color = parent->color;
            parent->color = 1u;
            if (sibling->right != head) {
              sibling->right->color = 1u;
            }
            RotateLeft(tree, parent);
            node = head->parent;
            break;
          }
        } else {
          VizUpdateNode* sibling = parent->left;
          if (sibling == head) {
            break;
          }

          if (sibling->color == 0u) {
            sibling->color = 1u;
            parent->color = 0u;
            RotateRight(tree, parent);
            sibling = parent->left;
          }

          const bool siblingRightBlack = (sibling->right == head) || (sibling->right->color == 1u);
          const bool siblingLeftBlack = (sibling->left == head) || (sibling->left->color == 1u);
          if (siblingRightBlack && siblingLeftBlack) {
            sibling->color = 0u;
            node = parent;
            parent = node->parent;
          } else {
            if ((sibling->left == head) || (sibling->left->color == 1u)) {
              if (sibling->right != head) {
                sibling->right->color = 1u;
              }
              sibling->color = 0u;
              RotateLeft(tree, sibling);
              sibling = parent->left;
            }

            sibling->color = parent->color;
            parent->color = 1u;
            if (sibling->left != head) {
              sibling->left->color = 1u;
            }
            RotateRight(tree, parent);
            node = head->parent;
            break;
          }
        }
      }

      if (node != head) {
        node->color = 1u;
      }
    }

    void EraseVizUpdateNode(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const head = tree->head;
      VizUpdateNode* y = node;
      std::uint8_t yOriginalColor = y->color;
      VizUpdateNode* x = head;
      VizUpdateNode* xParent = nullptr;

      if (node->left == head) {
        x = node->right;
        xParent = node->parent;
        Transplant(tree, node, node->right);
      } else if (node->right == head) {
        x = node->left;
        xParent = node->parent;
        Transplant(tree, node, node->left);
      } else {
        y = TreeMin(node->right, head);
        yOriginalColor = y->color;
        x = y->right;
        if (y->parent == node) {
          xParent = y;
          if (x != head) {
            x->parent = y;
          }
        } else {
          Transplant(tree, y, y->right);
          y->right = node->right;
          y->right->parent = y;
          xParent = y->parent;
        }
        Transplant(tree, node, y);
        y->left = node->left;
        y->left->parent = y;
        y->color = node->color;
      }

      if (head->left == node) {
        head->left =
          (node->left != head) ? TreeMax(node->left, head) : ((node->parent != nullptr) ? node->parent : head);
      }
      if (head->right == node) {
        head->right =
          (node->right != head) ? TreeMin(node->right, head) : ((node->parent != nullptr) ? node->parent : head);
      }

      UnlinkOwnerChain(node);
      ::operator delete(node);
      if (tree->size > 0u) {
        --tree->size;
      }

      if (yOriginalColor == 1u) {
        DeleteFixup(tree, x, xParent);
      }
    }
  } // namespace

  /**
   * Address: 0x00896F00 init path (FUN_00896F00 -> sub_89A930).
   */
  SSessionSaveData::SSessionSaveData()
  {
    mNodeMap.mAllocProxy = nullptr;
    mNodeMap.mHead = CreateSaveDataMapHead();
    mNodeMap.mSize = 0u;
  }

  /**
   * Address: 0x008971A0 cleanup path (FUN_008971A0 + sub_89AC40).
   */
  SSessionSaveData::~SSessionSaveData()
  {
    ClearSaveDataMap(mNodeMap);
    DestroySaveDataMapNode(mNodeMap.mHead);
    mNodeMap.mHead = nullptr;
    mNodeMap.mAllocProxy = nullptr;
    mNodeMap.mSize = 0u;
  }

  /**
   * Address: 0x008992D0/0x00899DC0/0x0089A970 helper chain.
   */
  void SSessionSaveData::InsertNodeLabel(const std::uint32_t commandSourceId, const msvc8::string& saveNodeName)
  {
    SSessionSaveNodeLabel label{};
    label.mCommandSourceId = commandSourceId;
    label.mSaveNodeName = saveNodeName;
    InsertSaveDataLabelNode(mNodeMap, label);
  }

  /**
   * Address: 0x00893160 (FUN_00893160,
   * ??0CWldSession@Moho@@QAE@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@3@AAV?$auto_ptr@VCWldMap@Moho@@@3@AAUSWldSessionInfo@1@@Z)
   */
  CWldSession::CWldSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& rulesOwner,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    // Partial lift of 0x00893160: ownership transfers + proven field initialization.
    // Remaining helper-heavy initialization chain (vision/task/lua options/spatial builders)
    // is tracked for subsequent recovery pass.
    head0.prev = this;
    head0.next = this;
    head1.prev = this;
    head1.next = this;

    mState = state.release();
    mCurThread = nullptr;
    mRules = static_cast<RRuleGameRulesImpl*>(rulesOwner.release());
    mWldMap = wldMap.release();

    mCanRestart = 0;
    mUnknownOwnerToken24 = nullptr;
    mMapName = sessionInfo.mMapName;
    mUnknownOwner44 = nullptr;
    mSaveSourceTreeHead = nullptr;
    mSaveSourceTreeSize = 0u;

    std::memset(mEntitySpatialDbStorage, 0, sizeof(mEntitySpatialDbStorage));
    SBuildTemplateInfo* const inlineStart = reinterpret_cast<SBuildTemplateInfo*>(&mBuildTemplates.mInlineStorage[0]);
    SBuildTemplateInfo* const inlineCapacity =
      reinterpret_cast<SBuildTemplateInfo*>(mBuildTemplates.mInlineStorage + sizeof(mBuildTemplates.mInlineStorage));
    mBuildTemplates.mStart = inlineStart;
    mBuildTemplates.mFinish = inlineStart;
    mBuildTemplates.mCapacity = inlineCapacity;
    mBuildTemplates.mOriginalStart = inlineStart;
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;

    mSessionRes1 = nullptr;
    mCurFormation = nullptr;
    mUICommandGraphPx = nullptr;
    mUICommandGraphControl = nullptr;
    mUnknownShared40C = {};
    mDebugCanvas = {};
    mUnknownShared41C = {};
    mSimResources = {};
    mAuxUpdateRoot = nullptr;
    mAuxUpdateHead = nullptr;
    mAuxUpdateSize = 0;
    mVizUpdateRoot = nullptr;
    mVizUpdateHead = nullptr;
    mVizUpdateSize = 0;

    GameTimeSeconds = 0;
    IsRunning = 0;
    GameTimeMilliSeconds = 0.0f;
    IsPaused = 0;
    N00001903 = 0;
    IsPausedB = 0;
    N0000315B = 0;

    ourCmdSource = static_cast<std::int32_t>(sessionInfo.mSourceId);
    IsReplay = sessionInfo.mIsReplay;
    IsBeingRecorded = sessionInfo.mIsBeingRecorded;
    IsMultiplayer = sessionInfo.mIsMultiplayer;
    IsObservingAllowed = sessionInfo.mIsReplay;
    FocusArmy = -1;
    IsGameOver = 0;

    selectedUnitUnknownPtr1 = nullptr;
    selectedUnitListPtr = nullptr;
    selectedUnitCount1 = 0;
    selectedUnitCount2 = 0;

    CursorWorldPos.x = 0.0f;
    CursorWorldPos.y = 0.0f;
    CursorWorldPos.z = 0.0f;
    CursorScreenPos.x = 0.0f;
    CursorScreenPos.y = 0.0f;
    HighlightCommandId = -1;

    IsCheatsEnabled = false;
    DisplayEconomyOverlay = false;
    mTeamColorMode = false;

    ClearBuildTemplates();
  }

  /**
   * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
   */
  CWldSession::~CWldSession()
  {
    // Partial lift of 0x00893A60: core owner releases + recovered shared/weak cleanup.
    ReleaseWeakCommandGraph(mUICommandGraphPx, mUICommandGraphControl);
    ReleaseSharedRaw(mSimResources);
    ReleaseSharedRaw(mUnknownShared41C);
    ReleaseSharedRaw(mDebugCanvas);
    ReleaseSharedRaw(mUnknownShared40C);
    ClearBuildTemplates();

    if (mRules) {
      delete mRules;
      mRules = nullptr;
    }

    if (mWldMap) {
      delete mWldMap;
      mWldMap = nullptr;
    }

    if (mState) {
      delete mState;
      mState = nullptr;
    }

    head0.prev = this;
    head0.next = this;
    head1.prev = this;
    head1.next = this;
  }

  /**
   * Address: 0x008B9580 callsite through session->mWldMap->mTerrainRes.
   */
  bool CWldSession::TryGetPlayableMapRect(VisibilityRect& outRect) const
  {
    if (!mWldMap) {
      return false;
    }
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
    if (!terrainRes) {
      return false;
    }
    terrainRes->GetPlayableMapRect(outRect);
    return true;
  }

  /**
   * Address: 0x008B9580 callsite (focus army lookup path).
   */
  UserArmy* CWldSession::GetFocusUserArmy()
  {
    return const_cast<UserArmy*>(static_cast<const CWldSession*>(this)->GetFocusUserArmy());
  }

  /**
   * Address: 0x008B9580 callsite (focus army lookup path).
   */
  const UserArmy* CWldSession::GetFocusUserArmy() const
  {
    if (FocusArmy < 0) {
      return nullptr;
    }

    const std::size_t focusIndex = static_cast<std::size_t>(FocusArmy);
    if (focusIndex >= userArmies.size()) {
      return nullptr;
    }

    return userArmies[focusIndex];
  }

  /**
   * Address: 0x008B97C0/0x008621B0 callsites (rule category lookup path).
   */
  EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver()
  {
    return const_cast<EntityCategoryLookupResolver*>(
      static_cast<const CWldSession*>(this)->GetCategoryLookupResolver()
    );
  }

  /**
   * Address: 0x008B97C0/0x008621B0 callsites (rule category lookup path).
   */
  const EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver() const
  {
    if (!mRules) {
      return nullptr;
    }

    // RRuleGameRulesImpl exposes the category-lookup contract in the same primary
    // vtable; this is a typed interface view, not a separate base subobject.
    return reinterpret_cast<const EntityCategoryLookupResolver*>(mRules);
  }

  /**
   * Address: 0x008B85E0 callsite (UserEntity ctor, sub_501A80 path).
   */
  void* CWldSession::GetEntitySpatialDbStorage()
  {
    return mEntitySpatialDbStorage;
  }

  /**
   * Address: 0x008B85E0 callsite (UserEntity ctor, sub_501A80 path).
   */
  const void* CWldSession::GetEntitySpatialDbStorage() const
  {
    return mEntitySpatialDbStorage;
  }

  /**
   * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   */
  void CWldSession::RemoveFromVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    VizUpdateTree* const tree = GetVizUpdateTree(this);
    if (!tree || !tree->head) {
      return;
    }

    VizUpdateNode* const node = FindVizUpdateNode(tree, reinterpret_cast<std::uintptr_t>(entity));
    if (!node || node == tree->head) {
      return;
    }

    EraseVizUpdateNode(tree, node);
  }

  /**
   * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::ClearBuildTemplates()
  {
    SBuildTemplateInfo* start = mBuildTemplates.mStart;
    SBuildTemplateInfo* finish = mBuildTemplates.mFinish;
    if (start && finish && start <= finish) {
      DestroyBuildTemplateRange(start, finish);
    }

    SBuildTemplateInfo* const inlineStart = mBuildTemplates.mOriginalStart
      ? mBuildTemplates.mOriginalStart
      : reinterpret_cast<SBuildTemplateInfo*>(&mBuildTemplates.mInlineStorage[0]);
    if (start && start != inlineStart) {
      ::operator delete[](start);
      mBuildTemplates.mStart = inlineStart;
      mBuildTemplates.mCapacity =
        reinterpret_cast<SBuildTemplateInfo*>(mBuildTemplates.mInlineStorage + sizeof(mBuildTemplates.mInlineStorage));
    }

    mBuildTemplates.mFinish = mBuildTemplates.mStart;
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;
  }

  /**
   * Address: 0x00895EB0 (FUN_00895EB0,
   * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
   */
  boost::SharedPtrRaw<UICommandGraph> CWldSession::GetCommandGraph(const bool allowCreate)
  {
    boost::SharedPtrRaw<UICommandGraph> graph = LockWeakCommandGraph(mUICommandGraphPx, mUICommandGraphControl);
    if (!graph.px && allowCreate) {
      UICommandGraph* createdGraph = nullptr;
      void* const raw = ::operator new(sizeof(UICommandGraph), std::nothrow);
      if (raw) {
        createdGraph = new (raw) UICommandGraph(this);
      }

      AssignSharedCommandGraph(graph, createdGraph);
      CopySharedToWeakCommandGraph(graph, mUICommandGraphPx, mUICommandGraphControl);
    }

    return graph;
  }

  /**
   * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
   */
  void CWldSession::SessionFrame(const float deltaSeconds)
  {
    if (mRules && mState) {
      static_cast<RRuleGameRules*>(mRules)->UpdateLuaState(mState);
    }

    if (!IsRunning) {
      GameTimeMilliSeconds = 1.0f;
    } else {
      GameTimeMilliSeconds += deltaSeconds * 10.0f;
    }

    GameTimeMilliSeconds = std::max(0.0f, std::min(GameTimeMilliSeconds, 1.0f));

    const std::int32_t targetTick = GameTimeSeconds + static_cast<std::int32_t>(std::floor(GameTimeMilliSeconds));
    (void)targetTick; // Full sync-driver beat drain still depends on recovered `sSimDriver` ownership path.

    boost::SharedPtrRaw<UICommandGraph> commandGraph = GetCommandGraph(false);
    ReleaseSharedRaw(commandGraph);

    if (mCurThread) {
      mCurThread->UserFrame();
    }
  }

  /**
   * Address: 0x00896F00 (FUN_00896F00,
   * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<SSessionSaveData> CWldSession::GetSaveData() const
  {
    boost::shared_ptr<SSessionSaveData> saveData{new SSessionSaveData()};
    SessionSaveSourceNode* const sourceHead = GetSaveSourceTreeHead(this);
    if (!sourceHead) {
      return saveData;
    }

    for (SessionSaveSourceNode* sourceNode = sourceHead->mLeft; sourceNode && sourceNode != sourceHead;
         sourceNode = NextTreeNode(sourceNode)) {
      auto* const provider = static_cast<ISessionSaveSourceProvider*>(sourceNode->mProvider);
      if (!provider) {
        continue;
      }

      auto* const owner = static_cast<SessionSaveNodeOwnerView*>(provider->GetSaveNodeOwner());
      if (!owner || !owner->mTagTreeHead) {
        continue;
      }

      SessionSaveTagNode* const tagHead = owner->mTagTreeHead;
      for (SessionSaveTagNode* tagNode = tagHead->mLeft; tagNode && tagNode != tagHead;
           tagNode = NextTreeNode(tagNode)) {
        saveData->InsertNodeLabel(sourceNode->mCommandSourceId, tagNode->mTagName);
      }
    }

    return saveData;
  }

  /**
   * Address: 0x0081F7B0 (FUN_0081F7B0,
   * ?GetLeftMouseButtonAction@CWldSession@Moho@@QAEAAUCommandModeData@2@PAU32@PBUstruct_MouseInfo@@H@Z)
   */
  CommandModeData* CWldSession::GetLeftMouseButtonAction(
    CommandModeData* const outMode, const MouseInfo* const mouseInfo, const int modifiers
  )
  {
    if (!outMode) {
      return nullptr;
    }

    CommandModeData mode{};
    mode.mMode = COMMOD_None;
    mode.mCommandCaps = RULEUCC_None;
    mode.mBlueprint = nullptr;
    mode.mModifiers = modifiers;
    mode.mIsDragged = -1;
    mode.mReserved5C = -1;
    mode.mMouseDragEnd = MouseInfo{};
    mode.mMouseDragEnd.mIsDragger = -1;

    if (mouseInfo) {
      mode.mMouseDragStart = *mouseInfo;
      mode.mIsDragged = mouseInfo->mIsDragger;

      if (mouseInfo->mHitValid != 0u) {
        bool resolvedByUi = false;
        if (mState && FocusArmy >= 0) {
          const std::size_t focusIndex = static_cast<std::size_t>(FocusArmy);
          if (focusIndex < userArmies.size() && userArmies[focusIndex] != nullptr) {
            UICommandModeData uiMode{};
            if (TryGetUICommandMode(mState, uiMode)) {
              if (uiMode.mode.empty()) {
                resolvedByUi = false;
              } else if (uiMode.mode == "order") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Order;

                LuaPlus::LuaObject commandName = GetLuaField(mState, uiMode.obj, "name");
                if (commandName && commandName.IsString()) {
                  const char* const commandCapsName = commandName.GetString();
                  if (commandCapsName && std::strcmp(commandCapsName, "Transport") == 0) {
                    mode.mCommandCaps = RULEUCC_Transport;
                  } else if (commandCapsName && std::strcmp(commandCapsName, "CallTransport") == 0) {
                    mode.mCommandCaps = RULEUCC_CallTransport;
                  }
                }
              } else if (uiMode.mode == "build" || uiMode.mode == "buildanchored") {
                resolvedByUi = true;
                LuaPlus::LuaObject blueprintNameField = GetLuaField(mState, uiMode.obj, "name");
                if (blueprintNameField && blueprintNameField.IsString()) {
                  const char* const blueprintName = blueprintNameField.GetString();
                  RResId blueprintId{};
                  blueprintId.name = blueprintName ? blueprintName : "";

                  void* const blueprint =
                    mRules ? static_cast<RRuleGameRules*>(mRules)->GetUnitBlueprint(blueprintId) : nullptr;
                  if (blueprint) {
                    mode.mMode = (uiMode.mode == "build") ? COMMOD_Build : COMMOD_BuildAnchored;
                    mode.mBlueprint = blueprint;
                  }
                }
              } else if (uiMode.mode == "ping") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Ping;
              } else if (!uiMode.mode.empty()) {
                resolvedByUi = true;
                gpg::Warnf("CWldSession::GetLeftMouseButtonAction invalid command mode: %s", uiMode.mode.c_str());
              }
            }
          }
        }

        if (!resolvedByUi) {
          mode.mMode = DefaultModeFromDrag(mouseInfo->mIsDragger);
        }
      }
    }

    *outMode = mode;
    return outMode;
  }

  /**
   * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::DrawCommandSplats()
  {
    // Recovered 0x008515B0 high-level flow:
    // 1) Walk selection RB-tree/map and build unique source-entity set.
    // 2) Pull sim links and build line/teleport beacon quad batches.
    // 3) Bind primbatcher textures:
    //    "/textures/ui/common/game/waypoints/attack_btn_up.dds"
    //    "/textures/ui/common/game/waypoints/teleport_btn_up.dds"
    // 4) Emit quads and flush primbatcher.
    //
    // Deep lift blockers (typed dependencies still missing in SDK):
    // CD3DDevice/CD3DDeviceResources/CD3DPrimBatcher/CD3DBatchTexture render API,
    // UserEntity selection-link map internals, and CAniPoseBone debug-pose chain.
  }

  /**
   * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
   */
  void CWldSession::RenderMeshPreviews()
  {
    // Recovered 0x008599D0 high-level flow:
    // 1) Validate current formation + instance readiness.
    // 2) Iterate formation units, query formation position/orientation.
    // 3) Sample terrain elevation from STIMap/CHeightField.
    // 4) Create "UnitFormationPreview" mesh material + mesh instances.
    // 5) Set stance/orientation and tint preview mesh instances.
    //
    // Deep lift blockers:
    // CFormation runtime layout, CAiFormationInstance accessors, MeshMaterial/MeshRenderer
    // creation chain, and preview-instance ownership container at 0x010C425C/0x010C4260.
  }

  /**
   * Address: 0x0085B6E0 (FUN_0085B6E0,
   * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
   */
  void CWldSession::
    RenderStrategicIcons(CameraImpl* const /*camera*/, CD3DPrimBatcher* const /*primBatcher*/, CWldMap* const /*map*/)
  {
    // Recovered 0x0085B6E0 high-level flow:
    // 1) Lazy-create icon auxiliary cache object (0x0085B2A0/0x0085FA20).
    // 2) Classify units into icon/lifebar buckets (vec1..vec5).
    // 3) Render strategic icons via RenderUnitIcon (0x0085D9A0).
    // 4) Render formation icon pass and unit lifebar pass.
    //
    // Helper-chain anchors:
    // 0x0085CA20, 0x0085CD40, 0x0085D880, 0x0085E0A0, 0x0085E3A0, 0x0085EED0.
    //
    // Deep lift blockers:
    // struct_IconAux/UnitIconData concrete layouts and CD3D* render interfaces.
  }

  /**
   * Address: 0x008621B0 (FUN_008621B0,
   * ?RenderProjectileIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCRenderWorldView@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@M@Z)
   */
  void CWldSession::RenderProjectileIcons(
    CameraImpl* const /*camera*/,
    CRenderWorldView* const /*worldView*/,
    CD3DPrimBatcher* const /*primBatcher*/,
    CWldMap* const /*map*/,
    const float /*deltaSeconds*/
  )
  {
    // Recovered 0x008621B0 high-level flow:
    // 1) Build strategic projection matrix from camera viewport.
    // 2) Resolve PROJECTILE category from rule resolver.
    // 3) Iterate POI entities, filter by projectile nibble/category bitset and visibility.
    // 4) Resolve icon texture (blueprint icon or army color fallback).
    // 5) Draw billboard quad (+ optional glow pulse pass), then flush.
    //
    // Deep lift blockers:
    // CameraImpl/CRenderWorldView typed query API, CD3DPrimBatcher texture setup API,
    // and projectile UI CVars/glow state ownership.
  }

  /**
   * Address: 0x00862A80 (FUN_00862A80, ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
   */
  void CWldSession::RenderResources(GeomCamera3* const /*camera*/, CD3DPrimBatcher* const /*primBatcher*/)
  {
    // Recovered 0x00862A80 high-level flow:
    // 1) Bind TResourceIcon technique and push primbatcher time shader var.
    // 2) Build strategic projection matrix from GeomCamera3 viewport.
    // 3) Query deposit collisions against camera solid, bucket mass/hydro points.
    // 4) Render strategic splats from:
    //    "/env/common/splats/mass_strategic.dds"
    //    "/env/common/splats/hydrocarbon_strategic.dds"
    // 5) Flush primbatcher and release temporary vectors/textures.
    //
    // Deep lift blockers:
    // IResources::DepositCollides typed contract, CD3DBatchTexture/CD3DPrimBatcher full API,
    // and transient fastvector wrappers used by collision query output.
  }
} // namespace moho
