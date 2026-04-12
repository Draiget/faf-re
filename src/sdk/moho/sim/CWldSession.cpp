#include "CWldSession.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/resource/RResId.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/unit/core/IUnit.h"
#include "moho/ui/IUIManager.h"
#include "moho/unit/core/UserUnit.h"

namespace gpg
{
  class RMultiMapType_EntId_string : public RType
  {
  public:
    /**
     * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
     *
     * What it does:
     * Returns the cached lexical label for the reflected
     * `multimap<EntId,std::string>` lane.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current multimap element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
  };
} // namespace gpg

namespace
{
  msvc8::string gEntIdStringMultiMapTypeName;
  std::uint32_t gEntIdStringMultiMapTypeNameInitGuard = 0;
  gpg::RType* gEntIdStringMultiMapKeyType = nullptr;
  gpg::RType* gEntIdStringMultiMapValueType = nullptr;

  [[nodiscard]] gpg::RType* ResolveEntIdTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapKeyType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "EntId",
        "Moho::EntId",
        "int",
        "signed int",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapKeyType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapKeyType == nullptr) {
        gEntIdStringMultiMapKeyType = gpg::LookupRType(typeid(std::int32_t));
      }
    }

    return gEntIdStringMultiMapKeyType;
  }

  [[nodiscard]] gpg::RType* ResolveStringTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapValueType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "std::string",
        "msvc8::string",
        "string",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapValueType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapValueType == nullptr) {
        gEntIdStringMultiMapValueType = gpg::LookupRType(typeid(msvc8::string));
      }
    }

    return gEntIdStringMultiMapValueType;
  }

  /**
   * Address: 0x00C082E0 (FUN_00C082E0, cleanup_RMultiMapType_EntId_string_Name)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RMultiMapType_EntId_string::GetName`.
   */
  void cleanup_RMultiMapType_EntId_string_Name()
  {
    gEntIdStringMultiMapTypeName.clear();
    gEntIdStringMultiMapTypeNameInitGuard = 0;
  }
} // namespace

/**
 * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
 *
 * What it does:
 * Lazily builds and caches one reflection label for the
 * `multimap<EntId,std::string>` lane.
 */
const char* gpg::RMultiMapType_EntId_string::GetName() const
{
  if ((gEntIdStringMultiMapTypeNameInitGuard & 1u) == 0u) {
    gEntIdStringMultiMapTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = ResolveEntIdTypeForMultiMapName();
    const gpg::RType* const valueType = ResolveStringTypeForMultiMapName();
    const char* const keyName = keyType != nullptr ? keyType->GetName() : "EntId";
    const char* const valueName = valueType != nullptr ? valueType->GetName() : "std::string";

    gEntIdStringMultiMapTypeName = gpg::STR_Printf("multimap<%s,%s>", keyName, valueName);
    (void)std::atexit(&cleanup_RMultiMapType_EntId_string_Name);
  }

  return gEntIdStringMultiMapTypeName.c_str();
}

/**
 * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
 *
 * What it does:
 * Formats inherited lexical text and appends current multimap element count.
 */
msvc8::string gpg::RMultiMapType_EntId_string::GetLexical(const gpg::RRef& ref) const
{
  struct MultiMapRuntimeView
  {
    void* allocProxy;
    void* head;
    std::uint32_t size;
  };

  const msvc8::string base = gpg::RType::GetLexical(ref);
  const auto* const map = static_cast<const MultiMapRuntimeView*>(ref.mObj);
  const int size = map ? static_cast<int>(map->size) : 0;
  return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
}

namespace moho
{
  // Address lanes:
  // - 0x010A645D (`ui_DebugAltClick`)
  // - 0x010A645E (`UI_SelectAnything`)
  // Recovered as process-global convar-backed toggles used by selection paths.
  bool ui_DebugAltClick = false;
  bool UI_SelectAnything = false;

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
    CWldSession* gActiveWldSession = nullptr;
    SWldSessionInfo* gPendingWldSessionInfo = nullptr;
    EWldFrameAction gWldFrameAction = EWldFrameAction::Inactive;
    WldTeardownCallbackVector gWldTeardownCallbacks{};
    std::uint32_t gWldTeardownCallbacksInitMask = 0;

    void CleanupWldTeardownCallbacks()
    {
      gWldTeardownCallbacks.clear();
      gWldTeardownCallbacksInitMask &= ~1u;
    }

    [[nodiscard]] bool RunLuaScriptWithEnv(
      LuaPlus::LuaState* const state, const char* const scriptPath, const LuaPlus::LuaObject& environment
    )
    {
      if (!state || !scriptPath || !*scriptPath) {
        return false;
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return false;
      }

      const int savedTop = lua_gettop(lstate);
      lua_getglobal(lstate, "doscript");
      if (!lua_isfunction(lstate, -1)) {
        lua_settop(lstate, savedTop);
        return false;
      }

      lua_pushstring(lstate, scriptPath);
      const_cast<LuaPlus::LuaObject&>(environment).PushStack(lstate);
      if (lua_pcall(lstate, 2, 0, 0) != 0) {
        const char* const errorText = lua_tostring(lstate, -1);
        gpg::Warnf("WLD_LoadScenarioInfo: doscript(%s) failed: %s", scriptPath, errorText ? errorText : "<unknown>");
        lua_settop(lstate, savedTop);
        return false;
      }

      lua_settop(lstate, savedTop);
      return true;
    }

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

    struct SessionPauseCallbackLink
    {
      SessionPauseCallbackLink* prev;
      SessionPauseCallbackLink* next;
    };

    class ISessionPauseCallback
    {
    public:
      virtual void OnSessionPauseStateChanged(bool isPaused) = 0;
    };

    struct SessionPauseCallbackOwnerLayout
    {
      void* vftable;
      SessionPauseCallbackLink link;
    };

    static_assert(sizeof(SessionPauseCallbackLink) == 0x8, "SessionPauseCallbackLink size must be 0x8");
    static_assert(
      offsetof(SessionPauseCallbackOwnerLayout, link) == sizeof(void*),
      "SessionPauseCallbackOwnerLayout::link offset must follow vftable lane"
    );

    [[nodiscard]] SessionPauseCallbackLink* AsSessionPauseCallbackLink(gpg::core::IntrusiveLink<CWldSession*>* link) noexcept
    {
      return reinterpret_cast<SessionPauseCallbackLink*>(link);
    }

    [[nodiscard]] ISessionPauseCallback* AsSessionPauseCallbackOwner(SessionPauseCallbackLink* const link) noexcept
    {
      constexpr std::size_t kCallbackLinkOffset = offsetof(SessionPauseCallbackOwnerLayout, link);
      auto* const raw = reinterpret_cast<std::uint8_t*>(link) - kCallbackLinkOffset;
      return reinterpret_cast<ISessionPauseCallback*>(raw);
    }

    void InitSessionPauseCallbackHead(gpg::core::IntrusiveLink<CWldSession*>& head) noexcept
    {
      auto* const link = AsSessionPauseCallbackLink(&head);
      link->prev = link;
      link->next = link;
    }

    [[nodiscard]] bool IsSessionPauseCallbackHeadEmpty(const gpg::core::IntrusiveLink<CWldSession*>& head) noexcept
    {
      const SessionPauseCallbackLink* const link =
        reinterpret_cast<const SessionPauseCallbackLink*>(&head);
      return link->next == link;
    }

    void UnlinkSessionPauseCallbackNode(SessionPauseCallbackLink* const link) noexcept
    {
      link->prev->next = link->next;
      link->next->prev = link->prev;
      link->prev = link;
      link->next = link;
    }

    void LinkSessionPauseCallbackNodeBefore(
      SessionPauseCallbackLink* const anchor,
      SessionPauseCallbackLink* const link
    ) noexcept
    {
      link->prev = anchor->prev;
      link->next = anchor;
      anchor->prev->next = link;
      anchor->prev = link;
    }

    void DispatchSessionPauseCallbacks(gpg::core::IntrusiveLink<CWldSession*>& head, const bool isPaused)
    {
      if (IsSessionPauseCallbackHeadEmpty(head)) {
        return;
      }

      SessionPauseCallbackLink staging{};
      staging.prev = &staging;
      staging.next = &staging;

      SessionPauseCallbackLink* const headLink = AsSessionPauseCallbackLink(&head);
      staging.prev = headLink->prev;
      staging.next = headLink->next;
      staging.prev->next = &staging;
      staging.next->prev = &staging;
      headLink->prev = headLink;
      headLink->next = headLink;

      while (staging.next != &staging) {
        SessionPauseCallbackLink* const callbackLink = staging.next;
        UnlinkSessionPauseCallbackNode(callbackLink);
        LinkSessionPauseCallbackNodeBefore(headLink, callbackLink);
        AsSessionPauseCallbackOwner(callbackLink)->OnSessionPauseStateChanged(isPaused);
      }
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

    struct StrategicIconAuxView
    {
      std::uint8_t mUnknown00[0x38];
      boost::shared_ptr<CD3DBatchTexture> mPauseRestTexture;   // +0x38
      boost::shared_ptr<CD3DBatchTexture> mStunnedRestTexture; // +0x40

      /**
       * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
       *
       * What it does:
       * Imports strategic icon Lua tables and refreshes pause/stunned overlay
       * rest textures for one icon-aux runtime object.
       */
      void LoadPauseAndStunnedRestTextures(CWldSession* session);
    };

    static_assert(
      offsetof(StrategicIconAuxView, mPauseRestTexture) == 0x38,
      "StrategicIconAuxView::mPauseRestTexture offset must be 0x38"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mStunnedRestTexture) == 0x40,
      "StrategicIconAuxView::mStunnedRestTexture offset must be 0x40"
    );

    /**
     * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
     *
     * What it does:
     * Imports strategic icon Lua tables and refreshes pause/stunned overlay
     * rest textures for one icon-aux runtime object.
     */
    void StrategicIconAuxView::LoadPauseAndStunnedRestTextures(CWldSession* const session)
    {
      LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject pauseIcons = iconTable.GetByName("PauseIcons");
      LuaPlus::LuaObject pauseRest = pauseIcons.GetByName("PauseRest");
      if (pauseRest.IsString()) {
        mPauseRestTexture = CD3DBatchTexture::FromFile(pauseRest.GetString(), 0u);
      }

      iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject stunnedIcons = iconTable.GetByName("StunnedIcons");
      LuaPlus::LuaObject stunnedRest = stunnedIcons.GetByName("StunnedRest");
      if (stunnedRest.IsString()) {
        mStunnedRestTexture = CD3DBatchTexture::FromFile(stunnedRest.GetString(), 0u);
      }
    }

    [[nodiscard]] boost::detail::sp_counted_base* CreateBoostControlForUICommandGraph(UICommandGraph* const graph)
    {
      if (!graph) {
        return nullptr;
      }

      auto* const control = new (std::nothrow) boost::detail::sp_counted_impl_p<UICommandGraph>(graph);
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

      boost::SharedPtrRaw<UICommandGraph> out{};
      out.px = px;
      out.pi = control;
      if (!out.add_ref_lock()) {
        return {};
      }
      return out;
    }

    void AssignSharedCommandGraph(boost::SharedPtrRaw<UICommandGraph>& out, UICommandGraph* const graph)
    {
      boost::detail::sp_counted_base* const newControl = CreateBoostControlForUICommandGraph(graph);
      UICommandGraph* const ownedGraph = newControl ? graph : nullptr;

      out.release();

      out.px = ownedGraph;
      out.pi = newControl;
    }

    void CopySharedToWeakCommandGraph(
      const boost::SharedPtrRaw<UICommandGraph>& shared,
      UICommandGraph*& weakPx,
      boost::detail::sp_counted_base*& weakControl
    )
    {
      shared.weak_add_ref();

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
    createdFont.release();

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

    struct SessionEntityMapNode
    {
      SessionEntityMapNode* mLeft;   // +0x00
      SessionEntityMapNode* mParent; // +0x04
      SessionEntityMapNode* mRight;  // +0x08
      std::uint32_t mEntityId;       // +0x0C
      UserEntity* mEntity;           // +0x10
      std::uint8_t pad_14_17[4];     // +0x14
      std::uint8_t mColor;           // +0x18
      std::uint8_t mIsSentinel;      // +0x19
      std::uint8_t pad_1A[2];
    };

    static_assert(sizeof(SessionEntityMapNode) == 0x1C, "SessionEntityMapNode size must be 0x1C");
    static_assert(
      offsetof(SessionEntityMapNode, mEntityId) == 0x0C,
      "SessionEntityMapNode::mEntityId offset must be 0x0C"
    );
    static_assert(
      offsetof(SessionEntityMapNode, mEntity) == 0x10,
      "SessionEntityMapNode::mEntity offset must be 0x10"
    );
    static_assert(
      offsetof(SessionEntityMapNode, mIsSentinel) == 0x19,
      "SessionEntityMapNode::mIsSentinel offset must be 0x19"
    );

    struct SessionEntityMap
    {
      void* mAllocProxy;            // +0x00
      SessionEntityMapNode* mHead;  // +0x04
      std::uint32_t mSize;          // +0x08
    };

    static_assert(sizeof(SessionEntityMap) == 0x0C, "SessionEntityMap size must be 0x0C");
    static_assert(offsetof(SessionEntityMap, mHead) == 0x04, "SessionEntityMap::mHead offset must be 0x04");
    static_assert(offsetof(SessionEntityMap, mSize) == 0x08, "SessionEntityMap::mSize offset must be 0x08");

    struct UserEntityWeakLinkSlotRuntimeView
    {
      void* mOwnerLinkSlot; // +0x00
    };

    static_assert(
      sizeof(UserEntityWeakLinkSlotRuntimeView) == sizeof(void*),
      "UserEntityWeakLinkSlotRuntimeView size must be pointer-sized"
    );

    struct CursorInfoRuntimeView
    {
      std::uint8_t mHitValid; // +0x00
      std::uint8_t pad_01[3];
      Wm3::Vector3f mMouseWorldPos;            // +0x04
      UserEntityWeakLinkSlotRuntimeView mUnitHover; // +0x10
      UserEntityWeakLinkSlotRuntimeView mPrevious;  // +0x14
      std::int32_t mIsDragger;                 // +0x18
      Wm3::Vector2f mMouseScreenPos;           // +0x1C
    };

    static_assert(sizeof(CursorInfoRuntimeView) == 0x24, "CursorInfoRuntimeView size must be 0x24");
    static_assert(offsetof(CursorInfoRuntimeView, mUnitHover) == 0x10, "CursorInfoRuntimeView::mUnitHover offset must be 0x10");
    static_assert(offsetof(CursorInfoRuntimeView, mPrevious) == 0x14, "CursorInfoRuntimeView::mPrevious offset must be 0x14");
    static_assert(
      offsetof(CursorInfoRuntimeView, mIsDragger) == 0x18, "CursorInfoRuntimeView::mIsDragger offset must be 0x18"
    );

    struct CWldSessionCursorRuntimeView
    {
      std::uint8_t pad_0000_04AF[0x4B0];
      CursorInfoRuntimeView mCursorInfo; // +0x4B0
    };

    static_assert(
      offsetof(CWldSessionCursorRuntimeView, mCursorInfo) == 0x4B0,
      "CWldSessionCursorRuntimeView::mCursorInfo offset must be 0x4B0"
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

    [[nodiscard]] UserEntity* DecodeSelectedUserEntity(const SSelectionWeakRefUserEntity& weakRef)
    {
      if (!weakRef.mOwnerLinkSlot) {
        return nullptr;
      }

      constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kSelectionOwnerLinkOffset == 0x08, "UserEntity selection weak-link offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
      if (raw < kSelectionOwnerLinkOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kSelectionOwnerLinkOffset);
    }

    [[nodiscard]] UserEntity* DecodeUserEntityWeakRef(const CameraUserEntityWeakRef& weakRef)
    {
      constexpr std::uintptr_t kUserEntityWeakOwnerOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kUserEntityWeakOwnerOffset == 0x08, "UserEntity weak-ref owner offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
      if (raw == 0u || raw == kUserEntityWeakOwnerOffset || raw < kUserEntityWeakOwnerOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kUserEntityWeakOwnerOffset);
    }

    [[nodiscard]] UserEntity* DecodeUserEntityWeakLinkSlot(const UserEntityWeakLinkSlotRuntimeView& weakSlot)
    {
      constexpr std::uintptr_t kUserEntityWeakOwnerOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kUserEntityWeakOwnerOffset == 0x08, "UserEntity weak-link owner offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakSlot.mOwnerLinkSlot);
      if (raw == 0u || raw == kUserEntityWeakOwnerOffset || raw < kUserEntityWeakOwnerOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kUserEntityWeakOwnerOffset);
    }

    [[nodiscard]] UserEntity* GetHoveredUserEntity(const CWldSession* const session) noexcept
    {
      if (session == nullptr) {
        return nullptr;
      }

      const auto* const sessionView = reinterpret_cast<const CWldSessionCursorRuntimeView*>(session);
      return DecodeUserEntityWeakLinkSlot(sessionView->mCursorInfo.mUnitHover);
    }

    [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const userUnit) noexcept
    {
      return userUnit ? reinterpret_cast<const IUnit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
    }

    [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const userUnit) noexcept
    {
      return userUnit ? reinterpret_cast<IUnit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
    }

    [[nodiscard]] bool ContainsUnitPtr(const msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      return std::find(units.begin(), units.end(), unit) != units.end();
    }

    void AppendUnitUnique(msvc8::vector<UserUnit*>& units, UserUnit* const unit)
    {
      if (unit == nullptr || ContainsUnitPtr(units, unit)) {
        return;
      }
      units.push_back(unit);
    }

    void RemoveUnitIfPresent(msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      msvc8::vector<UserUnit*> filteredUnits{};
      filteredUnits.reserve(units.size());
      for (UserUnit* const candidate : units) {
        if (candidate != unit) {
          filteredUnits.push_back(candidate);
        }
      }
      units = filteredUnits;
    }

    [[nodiscard]] bool ContainsEntityPtr(const msvc8::vector<UserEntity*>& entities, const UserEntity* const entity)
    {
      return std::find(entities.begin(), entities.end(), entity) != entities.end();
    }

    void CollectSelectionEntities(const SSelectionSetUserEntity& selection, msvc8::vector<UserEntity*>& outEntities)
    {
      outEntities.clear();

      const SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return;
      }

      for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        if (entity == nullptr || ContainsEntityPtr(outEntities, entity)) {
          continue;
        }
        outEntities.push_back(entity);
      }
    }

    [[nodiscard]] bool
    AreEntitySetsEqual(const msvc8::vector<UserEntity*>& lhs, const msvc8::vector<UserEntity*>& rhs)
    {
      if (lhs.size() != rhs.size()) {
        return false;
      }

      for (const UserEntity* const entity : lhs) {
        if (!ContainsEntityPtr(rhs, entity)) {
          return false;
        }
      }

      return true;
    }

    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
    EraseSelectionNodeAndAdvance(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* node);

    void ClearSelectionSet(SSelectionSetUserEntity& selection)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        selection.mSize = 0u;
        selection.mSizeMirrorOrUnused = 0u;
        return;
      }

      for (SSelectionNodeUserEntity* node = head->mLeft; node && node != head;) {
        node = EraseSelectionNodeAndAdvance(selection, node);
      }

      selection.mSize = 0u;
      selection.mSizeMirrorOrUnused = 0u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
    }

    struct CWldSessionSelectionStatsRuntimeView
    {
      std::uint8_t pad_0000_04AC[0x4AC];
      std::int32_t maxSelectionSize; // +0x4AC
    };
    static_assert(
      offsetof(CWldSessionSelectionStatsRuntimeView, maxSelectionSize) == 0x4AC,
      "CWldSessionSelectionStatsRuntimeView::maxSelectionSize offset must be 0x4AC"
    );

    void BuildSelectionSyncMask(const SSelectionSetUserEntity& selection, SSyncFilterMaskBlock& outMask)
    {
      BVIntSet selectionIds{};
      const SSelectionNodeUserEntity* const head = selection.mHead;
      if (head != nullptr) {
        for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
          UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
          if (entity == nullptr || entity->IsUserUnit() == nullptr) {
            continue;
          }
          (void)selectionIds.Add(static_cast<unsigned int>(entity->mParams.mEntityId));
        }
      }

      outMask.rawWord = selectionIds.mFirstWordIndex;
      outMask.maskVectorAuxWord = selectionIds.mReservedMetaWord;
      outMask.masks.ResetFrom(selectionIds.mWords);
    }

    [[nodiscard]] bool IsSelectionNil(const SSelectionNodeUserEntity* const node)
    {
      return node == nullptr || node->mIsSentinel != 0u;
    }

    [[nodiscard]] SSelectionNodeUserEntity*
    SelectionMin(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head)
    {
      while (!IsSelectionNil(node) && !IsSelectionNil(node->mLeft)) {
        node = node->mLeft;
      }
      return IsSelectionNil(node) ? head : node;
    }

    [[nodiscard]] SSelectionNodeUserEntity*
    SelectionMax(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head)
    {
      while (!IsSelectionNil(node) && !IsSelectionNil(node->mRight)) {
        node = node->mRight;
      }
      return IsSelectionNil(node) ? head : node;
    }

    void RecomputeSelectionExtrema(SSelectionSetUserEntity& selection)
    {
      if (selection.mHead == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const root = head->mParent;
      if (IsSelectionNil(root)) {
        head->mParent = head;
        head->mLeft = head;
        head->mRight = head;
        return;
      }

      head->mLeft = SelectionMin(root, head);
      head->mRight = SelectionMax(root, head);
    }

    void ReplaceSelectionSubtree(
      SSelectionSetUserEntity& selection,
      SSelectionNodeUserEntity* const oldNode,
      SSelectionNodeUserEntity* const newNode
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (oldNode->mParent == head) {
        head->mParent = newNode;
      } else if (oldNode == oldNode->mParent->mLeft) {
        oldNode->mParent->mLeft = newNode;
      } else {
        oldNode->mParent->mRight = newNode;
      }

      if (!IsSelectionNil(newNode)) {
        newNode->mParent = oldNode->mParent;
      }
    }

    void RotateSelectionLeft(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSelectionNil(pivot->mLeft)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    void RotateSelectionRight(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSelectionNil(pivot->mRight)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    [[nodiscard]] std::uint32_t SelectionKeyFromEntity(const UserEntity* const entity) noexcept
    {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entity));
    }

    [[nodiscard]] SSelectionNodeUserEntity*
    FindSelectionNodeByKey(const SSelectionSetUserEntity& selection, const std::uint32_t key)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return nullptr;
      }

      SSelectionNodeUserEntity* node = head->mParent;
      while (!IsSelectionNil(node)) {
        if (key < node->mKey) {
          node = node->mLeft;
        } else if (node->mKey < key) {
          node = node->mRight;
        } else {
          return node;
        }
      }

      return head;
    }

    void LinkSelectionWeakOwnerRef(UserEntity* const entity, SSelectionWeakRefUserEntity& weakRef)
    {
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
      if (entity == nullptr) {
        return;
      }

      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
      weakRef.mOwnerLinkSlot = ownerLinkSlot;
      weakRef.mNextOwner = *ownerLinkSlot;
      *ownerLinkSlot = &weakRef;
    }

    void FixupAfterSelectionInsert(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      while (node != head->mParent && node->mParent->mColor == 0u) {
        SSelectionNodeUserEntity* const parent = node->mParent;
        SSelectionNodeUserEntity* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SSelectionNodeUserEntity* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSelectionLeft(selection, node);
            }
            node->mParent->mColor = 1u;
            grand->mColor = 0u;
            RotateSelectionRight(selection, grand);
          }
        } else {
          SSelectionNodeUserEntity* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSelectionRight(selection, node);
            }
            node->mParent->mColor = 1u;
            grand->mColor = 0u;
            RotateSelectionLeft(selection, grand);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    [[nodiscard]] bool InsertSelectionEntity(SSelectionSetUserEntity& selection, UserEntity* const entity)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr || entity == nullptr) {
        return false;
      }

      const std::uint32_t key = SelectionKeyFromEntity(entity);
      SSelectionNodeUserEntity* parent = head;
      SSelectionNodeUserEntity* probe = head->mParent;
      while (!IsSelectionNil(probe)) {
        parent = probe;
        if (key < probe->mKey) {
          probe = probe->mLeft;
        } else if (probe->mKey < key) {
          probe = probe->mRight;
        } else {
          return false;
        }
      }

      auto* const inserted = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
      inserted->mLeft = head;
      inserted->mRight = head;
      inserted->mParent = parent;
      inserted->mKey = key;
      inserted->mColor = 0u;
      inserted->mIsSentinel = 0u;
      inserted->pad_1A[0] = 0u;
      inserted->pad_1A[1] = 0u;
      LinkSelectionWeakOwnerRef(entity, inserted->mEnt);

      if (parent == head) {
        head->mParent = inserted;
      } else if (key < parent->mKey) {
        parent->mLeft = inserted;
      } else {
        parent->mRight = inserted;
      }

      ++selection.mSize;
      FixupAfterSelectionInsert(selection, inserted);
      RecomputeSelectionExtrema(selection);
      return true;
    }

    [[nodiscard]] bool EraseSelectionEntity(SSelectionSetUserEntity& selection, UserEntity* const entity)
    {
      const SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr || entity == nullptr) {
        return false;
      }

      SSelectionNodeUserEntity* const node = FindSelectionNodeByKey(selection, SelectionKeyFromEntity(entity));
      if (node == nullptr || node == head) {
        return false;
      }

      (void)EraseSelectionNodeAndAdvance(selection, node);
      return true;
    }

    void FixupAfterSelectionErase(
      SSelectionSetUserEntity& selection,
      SSelectionNodeUserEntity* node,
      SSelectionNodeUserEntity* nodeParent
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* parent = !IsSelectionNil(node) ? node->mParent : nodeParent;
      while (node != head->mParent && (IsSelectionNil(node) || node->mColor == 1u)) {
        if (parent == nullptr) {
          break;
        }

        if (node == parent->mLeft) {
          SSelectionNodeUserEntity* sibling = parent->mRight;
          if (sibling == head) {
            node = parent;
            parent = node->mParent;
            continue;
          }
          if (sibling->mColor == 0u) {
            sibling->mColor = 1;
            parent->mColor = 0;
            RotateSelectionLeft(selection, parent);
            sibling = parent->mRight;
          }

          const bool leftBlack = IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u;
          const bool rightBlack = IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u;
          if (leftBlack && rightBlack) {
            sibling->mColor = 0;
            node = parent;
            parent = node->mParent;
            continue;
          }

          if (IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u) {
            if (!IsSelectionNil(sibling->mLeft)) {
              sibling->mLeft->mColor = 1;
            }
            sibling->mColor = 0;
            RotateSelectionRight(selection, sibling);
            sibling = parent->mRight;
          }

          sibling->mColor = parent->mColor;
          parent->mColor = 1;
          if (!IsSelectionNil(sibling->mRight)) {
            sibling->mRight->mColor = 1;
          }
          RotateSelectionLeft(selection, parent);
          node = head->mParent;
          break;
        }

        SSelectionNodeUserEntity* sibling = parent->mLeft;
        if (sibling == head) {
          node = parent;
          parent = node->mParent;
          continue;
        }
        if (sibling->mColor == 0u) {
          sibling->mColor = 1;
          parent->mColor = 0;
          RotateSelectionRight(selection, parent);
          sibling = parent->mLeft;
        }

        const bool rightBlack = IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u;
        const bool leftBlack = IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u;
        if (rightBlack && leftBlack) {
          sibling->mColor = 0;
          node = parent;
          parent = node->mParent;
          continue;
        }

        if (IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u) {
          if (!IsSelectionNil(sibling->mRight)) {
            sibling->mRight->mColor = 1;
          }
          sibling->mColor = 0;
          RotateSelectionLeft(selection, sibling);
          sibling = parent->mLeft;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = 1;
        if (!IsSelectionNil(sibling->mLeft)) {
          sibling->mLeft->mColor = 1;
        }
        RotateSelectionRight(selection, parent);
        node = head->mParent;
        break;
      }

      if (!IsSelectionNil(node)) {
        node->mColor = 1u;
      }
    }

    void UnlinkSelectionWeakOwnerRef(SSelectionWeakRefUserEntity& weakRef)
    {
      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(weakRef.mOwnerLinkSlot);
      if (ownerLinkSlot == nullptr) {
        return;
      }

      while (*ownerLinkSlot != nullptr && *ownerLinkSlot != &weakRef) {
        ownerLinkSlot = &(*ownerLinkSlot)->mNextOwner;
      }

      if (*ownerLinkSlot == &weakRef) {
        *ownerLinkSlot = weakRef.mNextOwner;
      }
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
    }

    /**
     * Address: 0x0066A550 (FUN_0066A550, Moho::WeakSet_UserEntity::next)
     *
     * What it does:
     * Erases one `UserEntity` weak-set node from the selection RB-tree, unlinks
     * its intrusive weak-owner chain lane, and returns the next in-order node.
     */
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
    EraseSelectionNodeAndAdvance(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node)
    {
      if (selection.mHead == nullptr || IsSelectionNil(node)) {
        throw std::out_of_range("invalid map/set<T> iterator");
      }

      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const next = NextTreeNode(node);

      SSelectionNodeUserEntity* removed = node;
      SSelectionNodeUserEntity* spliceTarget = node;
      std::uint8_t removedColor = spliceTarget->mColor;
      SSelectionNodeUserEntity* fixNode = head;
      SSelectionNodeUserEntity* fixParent = head;

      if (IsSelectionNil(node->mLeft)) {
        fixNode = node->mRight;
        fixParent = node->mParent;
        ReplaceSelectionSubtree(selection, node, node->mRight);
      } else if (IsSelectionNil(node->mRight)) {
        fixNode = node->mLeft;
        fixParent = node->mParent;
        ReplaceSelectionSubtree(selection, node, node->mLeft);
      } else {
        spliceTarget = SelectionMin(node->mRight, head);
        removedColor = spliceTarget->mColor;
        fixNode = spliceTarget->mRight;
        if (spliceTarget->mParent == node) {
          fixParent = spliceTarget;
          if (!IsSelectionNil(fixNode)) {
            fixNode->mParent = spliceTarget;
          }
        } else {
          fixParent = spliceTarget->mParent;
          ReplaceSelectionSubtree(selection, spliceTarget, spliceTarget->mRight);
          spliceTarget->mRight = node->mRight;
          spliceTarget->mRight->mParent = spliceTarget;
        }

        ReplaceSelectionSubtree(selection, node, spliceTarget);
        spliceTarget->mLeft = node->mLeft;
        spliceTarget->mLeft->mParent = spliceTarget;
        spliceTarget->mColor = node->mColor;
      }

      UnlinkSelectionWeakOwnerRef(removed->mEnt);
      ::operator delete(removed);

      if (selection.mSize > 0u) {
        --selection.mSize;
      }
      if (removedColor == 1u) {
        FixupAfterSelectionErase(selection, fixNode, fixParent);
      }

      RecomputeSelectionExtrema(selection);
      return next;
    }

    [[nodiscard]] SessionSaveSourceNode* GetSaveSourceTreeHead(const CWldSession* const session)
    {
      return static_cast<SessionSaveSourceNode*>(session->mSaveSourceTreeHead);
    }

    [[nodiscard]] SessionEntityMap& GetSessionEntityMap(CWldSession* const session)
    {
      static_assert(offsetof(CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");
      static_assert(
        offsetof(CWldSession, mSaveSourceTreeHead) == 0x48,
        "CWldSession::mSaveSourceTreeHead offset must be 0x48"
      );
      static_assert(
        offsetof(CWldSession, mSaveSourceTreeSize) == 0x4C,
        "CWldSession::mSaveSourceTreeSize offset must be 0x4C"
      );
      return *reinterpret_cast<SessionEntityMap*>(&session->mUnknownOwner44);
    }

    void CollectSessionUserUnits(CWldSession* const session, msvc8::vector<UserUnit*>& outUnits)
    {
      outUnits.clear();
      if (session == nullptr) {
        return;
      }

      SessionEntityMap& entityMap = GetSessionEntityMap(session);
      SessionEntityMapNode* const head = entityMap.mHead;
      if (head == nullptr || head->mLeft == head) {
        return;
      }

      for (SessionEntityMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
        UserEntity* const entity = node->mEntity;
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

    struct TerrainResMapBridge
    {
      void* mVftable; // +0x00
      STIMap* mMap;   // +0x04
    };

    static_assert(sizeof(TerrainResMapBridge) == 0x08, "TerrainResMapBridge size must be 0x08");
    static_assert(offsetof(TerrainResMapBridge, mMap) == 0x04, "TerrainResMapBridge::mMap offset must be 0x04");

    [[nodiscard]] bool ApplyTerrainPlayableRect(IWldTerrainRes* const terrainRes, const gpg::Rect2i& playableRect)
    {
      if (terrainRes == nullptr) {
        return false;
      }

      auto* const terrainBridge = reinterpret_cast<TerrainResMapBridge*>(terrainRes);
      if (terrainBridge->mMap == nullptr) {
        return false;
      }

      return terrainBridge->mMap->SetPlayableMapRect(playableRect);
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

    /**
     * Address: 0x0083DDA0 (FUN_0083DDA0, Moho::UI_GetCommandMode)
     *
     * What it does:
     * Imports `/lua/ui/game/commandmode.lua`, calls `GetCommandMode()`, and
     * extracts `(modeString, payloadTable)` when present.
     */
    [[nodiscard]] bool TryGetUICommandMode(LuaPlus::LuaState* state, UICommandModeData& out)
    {
      LuaPlus::LuaObject module = moho::SCR_ImportLuaModule(state, "/lua/ui/game/commandmode.lua");
      if (!module || !module.IsTable()) {
        return false;
      }

      LuaPlus::LuaObject getCommandMode = moho::SCR_GetLuaTableField(state, module, "GetCommandMode");
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
        out.mMode = modeName ? modeName : "";
      }

      LuaPlus::LuaObject payloadField = GetLuaIndex(state, result, 2);
      if (payloadField && payloadField.IsTable()) {
        out.mPayload = payloadField;
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

    [[nodiscard]] bool IsVizNodeNil(const VizUpdateNode* const node) noexcept
    {
      return node == nullptr || node->isSentinel != 0u;
    }

    void RecomputeVizUpdateExtrema(VizUpdateTree* tree)
    {
      if (!tree || !tree->head) {
        return;
      }

      VizUpdateNode* const head = tree->head;
      VizUpdateNode* const root = head->parent;
      if (IsVizNodeNil(root)) {
        head->parent = head;
        head->left = head;
        head->right = head;
        return;
      }

      head->left = TreeMin(root, head);
      head->right = TreeMax(root, head);
    }

    void LinkVizUpdateOwner(UserEntity* const entity, VizUpdateNode* const node)
    {
      node->ownerLinkHead = 0u;
      node->ownerNextLink = 0u;
      if (entity == nullptr) {
        return;
      }

      auto* const ownerLinkSlot = reinterpret_cast<std::uintptr_t*>(&entity->mIUnitChainHead);
      node->ownerLinkHead = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
      node->ownerNextLink = *ownerLinkSlot;
      *ownerLinkSlot = reinterpret_cast<std::uintptr_t>(&node->ownerLinkHead);
    }

    void RotateLeft(VizUpdateTree* tree, VizUpdateNode* node);
    void RotateRight(VizUpdateTree* tree, VizUpdateNode* node);

    void FixupAfterVizInsert(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const head = tree->head;
      while (node != head->parent && node->parent->color == 0u) {
        VizUpdateNode* const parent = node->parent;
        VizUpdateNode* const grand = parent->parent;
        if (parent == grand->left) {
          VizUpdateNode* const uncle = grand->right;
          if (uncle->color == 0u) {
            parent->color = 1u;
            uncle->color = 1u;
            grand->color = 0u;
            node = grand;
          } else {
            if (node == parent->right) {
              node = parent;
              RotateLeft(tree, node);
            }
            node->parent->color = 1u;
            grand->color = 0u;
            RotateRight(tree, grand);
          }
        } else {
          VizUpdateNode* const uncle = grand->left;
          if (uncle->color == 0u) {
            parent->color = 1u;
            uncle->color = 1u;
            grand->color = 0u;
            node = grand;
          } else {
            if (node == parent->left) {
              node = parent;
              RotateRight(tree, node);
            }
            node->parent->color = 1u;
            grand->color = 0u;
            RotateLeft(tree, grand);
          }
        }
      }

      head->parent->color = 1u;
    }

    [[nodiscard]] bool InsertVizUpdateNode(VizUpdateTree* tree, UserEntity* const entity)
    {
      if (!tree || !tree->head || entity == nullptr) {
        return false;
      }

      const std::uintptr_t key = reinterpret_cast<std::uintptr_t>(entity);
      VizUpdateNode* const head = tree->head;
      VizUpdateNode* parent = head;
      VizUpdateNode* probe = head->parent;
      while (!IsVizNodeNil(probe)) {
        parent = probe;
        if (key < probe->key) {
          probe = probe->left;
        } else if (probe->key < key) {
          probe = probe->right;
        } else {
          return false;
        }
      }

      auto* const inserted = static_cast<VizUpdateNode*>(::operator new(sizeof(VizUpdateNode)));
      inserted->left = head;
      inserted->parent = parent;
      inserted->right = head;
      inserted->key = key;
      inserted->color = 0u;
      inserted->isSentinel = 0u;
      inserted->pad_1A[0] = 0u;
      inserted->pad_1A[1] = 0u;
      LinkVizUpdateOwner(entity, inserted);

      if (parent == head) {
        head->parent = inserted;
      } else if (key < parent->key) {
        parent->left = inserted;
      } else {
        parent->right = inserted;
      }

      ++tree->size;
      FixupAfterVizInsert(tree, inserted);
      RecomputeVizUpdateExtrema(tree);
      return true;
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
   * Address: 0x007B59B0 (FUN_007B59B0, Moho::WeakSet_UserEntity::size)
   *
   * What it does:
   * Counts live weak-set tree nodes by in-order traversal of the selection
   * RB-tree lane.
   */
  std::int32_t SSelectionSetUserEntity::size() const
  {
    const SSelectionNodeUserEntity* const head = mHead;
    if (head == nullptr) {
      return 0;
    }

    auto isSentinel = [](const SSelectionNodeUserEntity* const node) -> bool {
      return node == nullptr || node->mIsSentinel != 0u;
    };

    std::int32_t count = 0;
    const SSelectionNodeUserEntity* node = head->mLeft;
    while (!isSentinel(node) && node != head) {
      ++count;

      if (!isSentinel(node->mRight)) {
        node = node->mRight;
        while (!isSentinel(node->mLeft)) {
          node = node->mLeft;
        }
        continue;
      }

      const SSelectionNodeUserEntity* parent = node->mParent;
      while (!isSentinel(parent) && node == parent->mRight) {
        node = parent;
        parent = parent->mParent;
      }
      node = parent;
    }

    return count;
  }

  /**
   * Address: 0x0066ADD0 (FUN_0066ADD0, Moho::WeakSet_UserEntity::Iterator::inc)
   *
   * What it does:
   * Standard MSVC red-black tree successor iterator. If the current node has
   * a non-sentinel right subtree, descends to its leftmost descendant. Otherwise
   * climbs ancestors until reaching one whose right child is not the current
   * traversal path. No-op when already at the sentinel.
   */
  void SSelectionSetUserEntity::Iterator_inc(SSelectionNodeUserEntity** const cursor)
  {
    SSelectionNodeUserEntity* node = *cursor;
    if (node->mIsSentinel != 0u) {
      return;
    }

    SSelectionNodeUserEntity* right = node->mRight;
    if (right->mIsSentinel != 0u) {
      // No right subtree: climb until we find an ancestor that we came from the left of.
      SSelectionNodeUserEntity* parent = node->mParent;
      while (parent->mIsSentinel == 0u) {
        if (*cursor != parent->mRight) {
          break;
        }
        *cursor = parent;
        parent = parent->mParent;
      }
      *cursor = parent;
    } else {
      // Has right subtree: leftmost descendant of right child is the successor.
      SSelectionNodeUserEntity* leftmost = right->mLeft;
      while (leftmost->mIsSentinel == 0u) {
        right = leftmost;
        leftmost = leftmost->mLeft;
      }
      *cursor = right;
    }
  }

  /**
   * Address: 0x0066A330 (FUN_0066A330, Moho::WeakSet_UserEntity::find)
   *
   * What it does:
   * Walks forward from `start` through the RB-tree using `Iterator_inc`,
   * skipping tombstone entries (whose embedded `WeakObject_IUnit*` is null
   * or the sentinel `(void*)8`), and returns the first live entry or `mHead`
   * (sentinel) if none remains. Result is also written to `*outNode`.
   */
  SSelectionNodeUserEntity* SSelectionSetUserEntity::find(
    SSelectionSetUserEntity* const set,
    SSelectionNodeUserEntity* const start,
    SSelectionNodeUserEntity** const outNode)
  {
    SSelectionNodeUserEntity* node = start;
    SSelectionNodeUserEntity* cursor = nullptr;
    while (node != set->mHead) {
      void* const ent = node->mEnt.mOwnerLinkSlot;
      if (ent != nullptr && ent != reinterpret_cast<void*>(8)) {
        break;
      }
      cursor = node;
      Iterator_inc(&cursor);
      node = cursor;
    }
    *outNode = node;
    return node;
  }

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
    InitSessionPauseCallbackHead(head0);
    InitSessionPauseCallbackHead(head1);

    mState = state.release();
    mCurThread = nullptr;
    mRules = static_cast<RRuleGameRulesImpl*>(rulesOwner.release());
    mWldMap = wldMap.release();
    mLaunchInfo = sessionInfo.mLaunchInfo;

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

    mGameTick = 0;
    mLastBeatWasTick = 0;
    mTimeSinceLastTick = 0.0f;
    mSessionPauseStateA = 0;
    mRequestingPauseState = 0;
    mRequestingPause = 0;
    mPauseRequester = 0;
    mReplayIsPaused = 0;

    ourCmdSource = static_cast<std::int32_t>(sessionInfo.mSourceId);
    IsReplay = sessionInfo.mIsReplay;
    IsBeingRecorded = sessionInfo.mIsBeingRecorded;
    IsMultiplayer = sessionInfo.mIsMultiplayer;
    IsObservingAllowed = sessionInfo.mIsReplay;
    FocusArmy = -1;
    IsGameOver = 0;

    mSelection.mAllocProxy = nullptr;
    mSelection.mHead = nullptr;
    mSelection.mSize = 0;
    mSelection.mSizeMirrorOrUnused = 0;

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
    gActiveWldSession = this;
  }

  /**
   * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
   */
  CWldSession::~CWldSession()
  {
    // Partial lift of 0x00893A60: core owner releases + recovered shared/weak cleanup.
    ReleaseWeakCommandGraph(mUICommandGraphPx, mUICommandGraphControl);
    mSimResources.release();
    mUnknownShared41C.release();
    mDebugCanvas.release();
    mUnknownShared40C.release();
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
    mLaunchInfo.reset();

    InitSessionPauseCallbackHead(head0);
    InitSessionPauseCallbackHead(head1);

    if (gActiveWldSession == this) {
      gActiveWldSession = nullptr;
    }
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
   * Address: 0x008965E0 (FUN_008965E0, ?RequestFocusArmy@CWldSession@Moho@@QAEXH@Z)
   *
   * What it does:
   * Validates one zero-based focus-army index (`-1` allowed) and forwards
   * accepted changes to the active sim driver.
   */
  void CWldSession::RequestFocusArmy(const int index)
  {
    const int maxArmyIndex = static_cast<int>(userArmies.size()) - 1;
    if (index < -1 || index > maxArmyIndex) {
      gpg::Logf(
        "CWldSession::RequestFocusArmy(): invalid army index %d.  Must be between -1 and %d inclusive",
        index,
        maxArmyIndex
      );
      return;
    }

    if (!ValidateFocusArmyRequest(index)) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver()) {
      activeDriver->SetArmyIndex(index);
    }
  }

  /**
   * Address: 0x00896670 (FUN_00896670, ?ValidateFocusArmyRequest@CWldSession@Moho@@AAE_NH@Z)
   *
   * What it does:
   * Returns whether one focus-army switch is allowed for the current command
   * source/session observation state.
   */
  bool CWldSession::ValidateFocusArmyRequest(const int index)
  {
    const unsigned int localCommandSource = static_cast<unsigned int>(ourCmdSource);

    bool hasDirectCommandSourceAccess = false;
    if (index != -1 && index >= 0) {
      const std::size_t focusIndex = static_cast<std::size_t>(index);
      if (focusIndex < userArmies.size()) {
        const UserArmy* const targetArmy = userArmies[focusIndex];
        if (targetArmy != nullptr) {
          hasDirectCommandSourceAccess = targetArmy->mVarDat.mValidCommandSources.Contains(localCommandSource);
        }
      }
    }

    if (localCommandSource == 0xFFu || IsCheatsEnabled || hasDirectCommandSourceAccess || IsGameOver != 0u) {
      return true;
    }

    if (!IsObservingAllowed) {
      return false;
    }

    for (UserArmy* const army : userArmies) {
      if (army == nullptr) {
        continue;
      }

      if (army->mVarDat.mValidCommandSources.Contains(localCommandSource) && army->mVarDat.mIsOutOfGame == 0u) {
        return false;
      }
    }

    return true;
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
   * Address context: 0x00896870 (`ClearExtraSelectList`) field lane.
   */
  SSelectionSetUserEntity& CWldSession::ExtraSelectionView()
  {
    constexpr std::size_t kExtraSelectionOffsetInStorage = 0x90;
    static_assert(
      offsetof(CWldSession, mEntitySpatialDbStorage) + kExtraSelectionOffsetInStorage == 0xE0,
      "CWldSession::ExtraSelectionView offset must be 0xE0"
    );
    return *reinterpret_cast<SSelectionSetUserEntity*>(mEntitySpatialDbStorage + kExtraSelectionOffsetInStorage);
  }

  /**
   * Address context: 0x00896870 (`ClearExtraSelectList`) field lane.
   */
  const SSelectionSetUserEntity& CWldSession::ExtraSelectionView() const
  {
    return const_cast<CWldSession*>(this)->ExtraSelectionView();
  }

  /**
   * Address: 0x00896780 (FUN_00896780, ?AddToExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Starts transport order command mode and inserts one entity into the
   * world-session extra-selection weak-set.
   */
  void CWldSession::AddToExtraSelectList(UserEntity* const entity)
  {
    UICommandModeData commandModeData{};
    commandModeData.mMode = msvc8::string("order", 5u);
    commandModeData.mPayload.AssignNewTable(mState, 0, 0);
    commandModeData.mPayload.SetString("name", "RULEUCC_Transport");
    UI_StartCommandMode(commandModeData);

    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    (void)InsertSelectionEntity(extraSelection, entity);
  }

  /**
   * Address: 0x00896830 (FUN_00896830, ?RemoveFromExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity from the world-session extra-selection weak-set and
   * exits command mode when the set becomes empty.
   */
  void CWldSession::RemoveFromExtraSelectList(UserEntity* const entity)
  {
    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    if (!EraseSelectionEntity(extraSelection, entity)) {
      return;
    }

    SSelectionNodeUserEntity* const head = extraSelection.mHead;
    if (head != nullptr && head->mLeft == head) {
      UI_EndCommandMode();
    }
  }

  /**
   * Address: 0x00896870 (FUN_00896870, ?ClearExtraSelectList@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears world-session extra selection weak-set and exits command mode when
   * any entries were present.
   */
  void CWldSession::ClearExtraSelectList()
  {
    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    SSelectionNodeUserEntity* const head = extraSelection.mHead;
    if (head == nullptr || head->mLeft == head) {
      return;
    }

    for (SSelectionNodeUserEntity* node = head->mLeft; node != nullptr && node != head;) {
      node = EraseSelectionNodeAndAdvance(extraSelection, node);
    }

    head->mParent = head;
    head->mLeft = head;
    head->mRight = head;
    extraSelection.mSize = 0u;
    UI_EndCommandMode();
  }

  /**
   * Address: 0x00894210 (FUN_00894210, ?AddToVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   */
  void CWldSession::AddToVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    VizUpdateTree* const tree = GetVizUpdateTree(this);
    if (!tree || !tree->head) {
      return;
    }

    (void)InsertVizUpdateNode(tree, entity);
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
   * Address: 0x008942B0 (FUN_008942B0, ?RequestPause@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::RequestPause()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (IsReplay) {
      if (mReplayIsPaused == 0u) {
        mReplayIsPaused = 1;
        simDriver->IncrementOutstandingRequests();
      }
    } else {
      simDriver->RequestPause(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 1;
      mPauseRequester = commandCookie;
    }

    DispatchSessionPauseCallbacks(head0, true);
  }

  /**
   * Address: 0x00894330 (FUN_00894330, ?Resume@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::Resume()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (IsReplay) {
      if (mReplayIsPaused != 0u) {
        mReplayIsPaused = 0;
        simDriver->DecrementOutstandingRequestsAndSignal();
      }
    } else {
      simDriver->Resume(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 0;
      mPauseRequester = commandCookie;
    }

    DispatchSessionPauseCallbacks(head0, false);
  }

  /**
   * Address: 0x008943E0 (FUN_008943E0, ?CheckForNecessaryUIRefresh@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the current selection when stale/dead weak entries are detected
   * or selected entities requested a UI refresh during beat processing.
   */
  void CWldSession::CheckForNecessaryUIRefresh()
  {
    const std::uint32_t previousSelectionSize = mSelection.mSize;
    bool needsSelectionRefresh = false;

    msvc8::vector<UserEntity*> filteredSelection{};
    filteredSelection.reserve(static_cast<std::size_t>(previousSelectionSize));

    const SSelectionNodeUserEntity* const head = mSelection.mHead;
    if (head != nullptr) {
      for (const SSelectionNodeUserEntity* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)
      ) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        if (entity == nullptr) {
          needsSelectionRefresh = true;
          continue;
        }

        if (entity->RequiresUIRefresh()) {
          needsSelectionRefresh = true;
        }

        if (entity->mVariableData.mIsDead != 0u) {
          needsSelectionRefresh = true;
          continue;
        }

        if (!ContainsEntityPtr(filteredSelection, entity)) {
          filteredSelection.push_back(entity);
        }
      }
    }

    const std::int32_t maxSelectionSizeRuntime =
      reinterpret_cast<const CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize;
    const std::uint32_t maxSelectionSize = maxSelectionSizeRuntime > 0 ? static_cast<std::uint32_t>(maxSelectionSizeRuntime)
                                                                        : 0u;
    const std::uint32_t liveSelectionSize = static_cast<std::uint32_t>(filteredSelection.size());

    if (!needsSelectionRefresh && !(previousSelectionSize < maxSelectionSize) && !(liveSelectionSize < previousSelectionSize
        )) {
      return;
    }

    msvc8::vector<UserEntity*> previousSelection{};
    CollectSelectionEntities(mSelection, previousSelection);
    const bool selectionChanged = !AreEntitySetsEqual(previousSelection, filteredSelection);

    ClearSelectionSet(mSelection);
    for (UserEntity* const entity : filteredSelection) {
      (void)InsertSelectionEntity(mSelection, entity);
    }

    mSelection.mSizeMirrorOrUnused = mSelection.mSize;
    reinterpret_cast<CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize =
      static_cast<std::int32_t>(mSelection.mSize);

    if (!selectionChanged) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      SSyncFilterMaskBlock selectionMask{};
      BuildSelectionSyncMask(mSelection, selectionMask);
      activeDriver->SetSyncFilterMaskB(selectionMask);
    }

    UI_EndCommandMode();
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

    if (mLastBeatWasTick == 0) {
      mTimeSinceLastTick = 1.0f;
    } else {
      mTimeSinceLastTick += deltaSeconds * 10.0f;
    }

    mTimeSinceLastTick = std::max(0.0f, std::min(mTimeSinceLastTick, 1.0f));

    const std::int32_t targetTick = mGameTick + static_cast<std::int32_t>(std::floor(mTimeSinceLastTick));
    (void)targetTick; // Full sync-driver beat drain still depends on recovered `sSimDriver` ownership path.

    boost::SharedPtrRaw<UICommandGraph> commandGraph = GetCommandGraph(false);
    commandGraph.release();

    if (mCurThread) {
      mCurThread->UserFrame();
    }
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   */
  void CWldSession::GetSelectionUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const SSelectionNodeUserEntity* const head = mSelection.mHead;
    if (!head) {
      return;
    }

    for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
      if (!entity) {
        continue;
      }

      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (std::find(outUnits.begin(), outUnits.end(), userUnit) == outUnits.end()) {
        outUnits.push_back(userUnit);
      }
    }
  }

  void CWldSession::SetSelectionUnits(const msvc8::vector<UserUnit*>& units)
  {
    msvc8::vector<UserEntity*> desiredEntities{};
    desiredEntities.reserve(units.size());
    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      UserEntity* const entity = reinterpret_cast<UserEntity*>(unit);
      if (!ContainsEntityPtr(desiredEntities, entity)) {
        desiredEntities.push_back(entity);
      }
    }

    msvc8::vector<UserEntity*> previousEntities{};
    CollectSelectionEntities(mSelection, previousEntities);
    const bool selectionChanged = !AreEntitySetsEqual(previousEntities, desiredEntities);

    ClearSelectionSet(mSelection);
    for (UserEntity* const entity : desiredEntities) {
      (void)InsertSelectionEntity(mSelection, entity);
    }

    mSelection.mSizeMirrorOrUnused = mSelection.mSize;
    reinterpret_cast<CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize =
      static_cast<std::int32_t>(mSelection.mSize);

    if (!selectionChanged) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      SSyncFilterMaskBlock selectionMask{};
      BuildSelectionSyncMask(mSelection, selectionMask);
      activeDriver->SetSyncFilterMaskB(selectionMask);
    }

    UI_EndCommandMode();
  }

  /**
   * Address: 0x00865830 (FUN_00865830, ?CanSelectUnit@CWldSession@Moho@@QBE_NPAVUserUnit@2@@Z)
   */
  bool CWldSession::CanSelectUnit(UserUnit* const unit) const
  {
    const UserEntity* const entity = reinterpret_cast<const UserEntity*>(unit);
    const bool selectableByArmy = entity != nullptr && entity->IsSelectable() && entity->mArmy == GetFocusUserArmy();
    return selectableByArmy || (UI_SelectAnything && this != nullptr && IsCheatsEnabled);
  }

  /**
   * Address: 0x00865920 (FUN_00865920, ?ReleaseDrag@CWldSession@Moho@@QAEXW4EMauiEventModifier@2@@Z)
   */
  void CWldSession::ReleaseDrag(const EMauiEventModifier modifiers)
  {
    constexpr std::uint32_t kShiftMask = static_cast<std::uint32_t>(MEM_Shift);
    constexpr std::uint32_t kCtrlMask = static_cast<std::uint32_t>(MEM_Ctrl);
    constexpr std::uint32_t kAltMask = static_cast<std::uint32_t>(MEM_Alt);
    constexpr std::uint32_t kShiftCtrlMask = kShiftMask | kCtrlMask;

    const std::uint32_t modifierBits = static_cast<std::uint32_t>(modifiers);
    msvc8::vector<UserUnit*> nextSelection{};

    UserEntity* const hoveredEntity = GetHoveredUserEntity(this);
    UserUnit* const hoveredUnit = hoveredEntity != nullptr ? hoveredEntity->IsUserUnit() : nullptr;

    if (ui_DebugAltClick && (modifierBits & kAltMask) != 0u && hoveredEntity != nullptr) {
      UserArmy* const hoveredArmy = hoveredEntity->mArmy;
      if (hoveredArmy != nullptr && hoveredArmy != GetFocusUserArmy()) {
        SetSelectionUnits(nextSelection);
        RequestFocusArmy(static_cast<int>(hoveredArmy->mArmyIndex));
        return;
      }
    }

    if (!CanSelectUnit(hoveredUnit)) {
      if ((modifierBits & kShiftCtrlMask) == 0u) {
        SetSelectionUnits(nextSelection);
      }
      return;
    }

    if ((modifierBits & kCtrlMask) != 0u) {
      msvc8::vector<UserUnit*> currentSelection{};
      GetSelectionUnits(currentSelection);

      const IUnit* const hoveredBridge = ResolveIUnitBridge(hoveredUnit);
      const RUnitBlueprint* const targetBlueprint = hoveredBridge != nullptr ? hoveredBridge->GetBlueprint() : nullptr;

      if ((modifierBits & kShiftMask) != 0u) {
        if (ContainsUnitPtr(currentSelection, hoveredUnit)) {
          for (UserUnit* const selectedUnit : currentSelection) {
            const IUnit* const selectedBridge = ResolveIUnitBridge(selectedUnit);
            if (selectedBridge == nullptr || selectedBridge->GetBlueprint() != targetBlueprint) {
              AppendUnitUnique(nextSelection, selectedUnit);
            }
          }

          SetSelectionUnits(nextSelection);
          return;
        }

        nextSelection = currentSelection;
      }

      msvc8::vector<UserUnit*> allSessionUnits{};
      CollectSessionUserUnits(this, allSessionUnits);
      const UserArmy* const focusArmy = GetFocusUserArmy();
      for (UserUnit* const sessionUnit : allSessionUnits) {
        if (sessionUnit == nullptr || sessionUnit->IsBeingBuilt()) {
          continue;
        }

        const IUnit* const sessionBridge = ResolveIUnitBridge(sessionUnit);
        if (sessionBridge == nullptr || sessionBridge->IsDead()) {
          continue;
        }

        const UserEntity* const sessionEntity = reinterpret_cast<const UserEntity*>(sessionUnit);
        if (sessionEntity == nullptr || sessionEntity->mArmy != focusArmy) {
          continue;
        }

        if (sessionBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        AppendUnitUnique(nextSelection, sessionUnit);
      }

      SetSelectionUnits(nextSelection);
      return;
    }

    if ((modifierBits & kShiftMask) != 0u) {
      GetSelectionUnits(nextSelection);
      if (ContainsUnitPtr(nextSelection, hoveredUnit)) {
        RemoveUnitIfPresent(nextSelection, hoveredUnit);
      } else {
        AppendUnitUnique(nextSelection, hoveredUnit);
      }
    } else {
      AppendUnitUnique(nextSelection, hoveredUnit);
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00865E20 (FUN_00865E20, ?HandleDoubleClickSelection@CWldSession@Moho@@QAEXPAVCameraImpl@2@@Z)
   */
  void CWldSession::HandleDoubleClickSelection(CameraImpl* const camera)
  {
    UserEntity* const hoveredEntity = GetHoveredUserEntity(this);
    if (hoveredEntity == nullptr) {
      return;
    }

    UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    if (hoveredEntity->IsInCategory(msvc8::string("WALL"))) {
      return;
    }

    if (hoveredEntity->mArmy != GetFocusUserArmy()) {
      return;
    }

    const IUnit* const hoveredBridge = ResolveIUnitBridge(hoveredUnit);
    if (hoveredBridge == nullptr) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = hoveredBridge->GetBlueprint();
    msvc8::vector<UserUnit*> nextSelection{};
    GetSelectionUnits(nextSelection);

    CameraFrustumUserEntityList* const frustumUnits = camera != nullptr ? camera->GetArmyUnitsInFrustum() : nullptr;
    if (frustumUnits != nullptr) {
      for (CameraUserEntityWeakRef* weakRef = frustumUnits->mStart;
           weakRef != nullptr && weakRef != frustumUnits->mFinish;
           ++weakRef) {
        UserEntity* const entity = DecodeUserEntityWeakRef(*weakRef);
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit == hoveredUnit) {
          continue;
        }

        IUnit* const unitBridge = ResolveIUnitBridge(unit);
        if (unitBridge == nullptr || unitBridge->IsDead() || unitBridge->DestroyQueued()) {
          continue;
        }

        if (!CanSelectUnit(unit)) {
          continue;
        }

        if (unitBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        if (unitBridge->IsUnitState(UNITSTATE_BeingUpgraded)) {
          continue;
        }

        AppendUnitUnique(nextSelection, unit);
      }
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00896900 (FUN_00896900, ?GetDelayToNextBeat@CWldSession@Moho@@QBEMXZ)
   */
  float CWldSession::GetDelayToNextBeat() const
  {
    if (mReplayIsPaused != 0u && mLastBeatWasTick != 0) {
      return (std::numeric_limits<float>::infinity)();
    }

    if (mTimeSinceLastTick < 1.0f) {
      return (1.0f - mTimeSinceLastTick) / (WLD_GetSimRate() * 10.0f);
    }

    return 0.0f;
  }

  /**
   * Address: 0x00896960 (FUN_00896960, ?SyncPlayableRect@CWldSession@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Applies one playable rectangle to terrain and updates user-entity mesh
   * hidden flags to match whether each entity lies inside that rectangle.
   */
  void CWldSession::SyncPlayableRect(const gpg::Rect2i& playableRect)
  {
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      (void)ApplyTerrainPlayableRect(mWldMap->mTerrainRes, playableRect);
    }

    SessionEntityMap& entityMap = GetSessionEntityMap(this);
    SessionEntityMapNode* const head = entityMap.mHead;
    if (head == nullptr || head->mLeft == head) {
      return;
    }

    for (SessionEntityMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = node->mEntity;
      if (entity == nullptr) {
        continue;
      }

      MeshInstance* const meshInstance = entity->mMeshInstance;
      if (meshInstance == nullptr) {
        continue;
      }

      const int mapX = static_cast<int>(entity->mVariableData.mCurTransform.pos_.x);
      const int mapZ = static_cast<int>(entity->mVariableData.mCurTransform.pos_.z);
      const bool insidePlayableRect = mapX >= playableRect.x0 && mapX < playableRect.x1 && mapZ >= playableRect.z0 &&
        mapZ < playableRect.z1;
      meshInstance->isHidden = insidePlayableRect ? 0u : 1u;
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
              if (uiMode.mMode.empty()) {
                resolvedByUi = false;
              } else if (uiMode.mMode == "order") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Order;

                LuaPlus::LuaObject commandName = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (commandName && commandName.IsString()) {
                  const char* const commandCapsName = commandName.GetString();
                  if (commandCapsName && std::strcmp(commandCapsName, "Transport") == 0) {
                    mode.mCommandCaps = RULEUCC_Transport;
                  } else if (commandCapsName && std::strcmp(commandCapsName, "CallTransport") == 0) {
                    mode.mCommandCaps = RULEUCC_CallTransport;
                  }
                }
              } else if (uiMode.mMode == "build" || uiMode.mMode == "buildanchored") {
                resolvedByUi = true;
                LuaPlus::LuaObject blueprintNameField = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (blueprintNameField && blueprintNameField.IsString()) {
                  const char* const blueprintName = blueprintNameField.GetString();
                  RResId blueprintId{};
                  blueprintId.name = blueprintName ? blueprintName : "";

                  void* const blueprint =
                    mRules ? static_cast<RRuleGameRules*>(mRules)->GetUnitBlueprint(blueprintId) : nullptr;
                  if (blueprint) {
                    mode.mMode = (uiMode.mMode == "build") ? COMMOD_Build : COMMOD_BuildAnchored;
                    mode.mBlueprint = blueprint;
                  }
                }
              } else if (uiMode.mMode == "ping") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Ping;
              } else if (!uiMode.mMode.empty()) {
                resolvedByUi = true;
                gpg::Warnf("CWldSession::GetLeftMouseButtonAction invalid command mode: %s", uiMode.mMode.c_str());
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

  namespace
  {
    void WLD_DoPreload()
    {
      // `FUN_0088BEE0` starts preload by tearing down any active world/session
      // runtime before moving to the loading action.
      WLD_Teardown();

      if (LuaPlus::LuaState* const state = USER_GetLuaState(); state != nullptr) {
        (void)UI_StartGameUI(state);
      }

      if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
        loader->SetCreated();
      }

      gWldFrameAction = EWldFrameAction::Loading;
    }

    void WLD_DoLoading(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      if (loader == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      if (loader->IsLoaded()) {
        gWldFrameAction = EWldFrameAction::CreateSession;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
      }
    }

    void WLD_DoInitializing(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      if (simDriver->HasSyncData()) {
        if (gActiveWldSession != nullptr && gActiveWldSession->mState != nullptr) {
          (void)UI_StartGameUI(gActiveWldSession->mState);
        }
        gWldFrameAction = EWldFrameAction::PostInitialize;
      }
    }

    void WLD_DoPostInitializing(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
      } else {
        gWldFrameAction = EWldFrameAction::Waiting;
      }
    }

    void WLD_DoWaiting(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
      } else {
        (void)UI_UpdateDisconnectDialogCallback();
      }
    }

    void WLD_DoPlayingAction(const float deltaSeconds)
    {
      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        simDriver->Dispatch();
      }

      if (CWldSession* const activeSession = WLD_GetActiveSession(); activeSession != nullptr) {
        activeSession->SessionFrame(deltaSeconds);
      }

      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        simDriver->NoOp();
      }

      (void)UI_UpdateDisconnectDialogCallback();
    }

    void WLD_CreateSessionInfo()
    {
      // Full `FUN_0088C9D0` session-info recreation still depends on
      // unrecovered LaunchInfoNew/session bootstrap ownership lanes.
      gWldFrameAction = EWldFrameAction::Preload;
    }
  } // namespace

  EWldFrameAction WLD_GetFrameAction()
  {
    return gWldFrameAction;
  }

  void WLD_SetFrameAction(const EWldFrameAction action)
  {
    gWldFrameAction = action;
  }

  /**
   * Address: 0x0088CAE0 (FUN_0088CAE0, ?WLD_Frame@Moho@@YA_NM@Z)
   */
  bool WLD_Frame(const float deltaSeconds)
  {
    if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
      loader->Update();
    }

    for (;;) {
      bool continueDispatch = false;
      switch (gWldFrameAction) {
        case EWldFrameAction::Inactive:
          if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
            loader->SetCreated();
          }
          return true;
        case EWldFrameAction::Preload:
          WLD_DoPreload();
          return true;
        case EWldFrameAction::Loading:
          WLD_DoLoading(&continueDispatch);
          break;
        case EWldFrameAction::Initialize:
          WLD_DoInitializing(&continueDispatch);
          break;
        case EWldFrameAction::PostInitialize:
          WLD_DoPostInitializing(&continueDispatch);
          break;
        case EWldFrameAction::Waiting:
          WLD_DoWaiting(&continueDispatch);
          break;
        case EWldFrameAction::Playing:
          WLD_DoPlayingAction(deltaSeconds);
          return true;
        case EWldFrameAction::CreateSession:
          WLD_CreateSessionInfo();
          return true;
        case EWldFrameAction::Exit:
          WLD_Teardown();
          (void)UI_StartFrontEnd();
          return true;
        default:
          return true;
      }

      if (continueDispatch) {
        continue;
      }

      return true;
    }
  }

  /**
   * Address: 0x00869810 (FUN_00869810, func_WldSessionLoader_GetOnTeardownCallbacks)
   */
  WldTeardownCallbackVector* WLD_GetOnTeardownCallbacks()
  {
    if ((gWldTeardownCallbacksInitMask & 1u) == 0u) {
      gWldTeardownCallbacksInitMask |= 1u;
      gWldTeardownCallbacks.clear();
      (void)std::atexit(&CleanupWldTeardownCallbacks);
    }

    return &gWldTeardownCallbacks;
  }

  /**
   * Address: 0x0088C860 (FUN_0088C860, ?WLD_Teardown@Moho@@YAXXZ)
   */
  void WLD_Teardown()
  {
    if (ISTIDriver* const simDriver = SIM_DetachActiveDriver(); simDriver != nullptr) {
      simDriver->ShutDown();
      delete simDriver;
    }

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      (void)uiManager->SetNewLuaState(nullptr);
    }

    if (IUserSoundManager* const userSound = USER_GetSound(); userSound != nullptr) {
      userSound->StopAllSounds();
    }

    CWldSession* const activeSession = WLD_GetActiveSession();
    for (IWldTeardownCallback* const callback : *WLD_GetOnTeardownCallbacks()) {
      if (callback != nullptr) {
        (void)callback->OnWldSessionTeardown(activeSession);
      }
    }

    if (activeSession != nullptr) {
      delete activeSession;
    }

    gWldFrameAction = EWldFrameAction::Inactive;
  }

  /**
   * Address: 0x0088BD40 (FUN_0088BD40)
   */
  LuaPlus::LuaObject WLD_LoadScenarioInfo(const msvc8::string& scenarioFile, LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return {};
    }

    LuaPlus::LuaObject scenarioEnv(state);
    if (FILE_GetFileInfo(scenarioFile.c_str(), nullptr, false)) {
      scenarioEnv.AssignNewTable(state, 0, 0);
      (void)RunLuaScriptWithEnv(state, "/lua/dataInit.lua", scenarioEnv);
      (void)RunLuaScriptWithEnv(state, scenarioFile.c_str(), scenarioEnv);
    }

    if (scenarioEnv.IsNil()) {
      return scenarioEnv;
    }

    return scenarioEnv["ScenarioInfo"];
  }

  /**
   * Address: 0x0088D060 (FUN_0088D060, ?WLD_BeginSession@Moho@@YAXV?$auto_ptr@USWldSessionInfo@Moho@@@std@@@Z)
   *
   * What it does:
   * Replaces pending world-session bootstrap info and schedules preload.
   */
  void WLD_BeginSession(msvc8::auto_ptr<SWldSessionInfo> sessionInfo)
  {
    SWldSessionInfo* const nextSessionInfo = sessionInfo.release();
    if (nextSessionInfo != gPendingWldSessionInfo && gPendingWldSessionInfo != nullptr) {
      delete gPendingWldSessionInfo;
    }

    gPendingWldSessionInfo = nextSessionInfo;
    gWldFrameAction = EWldFrameAction::Preload;
  }

  /**
   * Address: 0x0088D0B0 (FUN_0088D0B0, ?WLD_GetSimRate@Moho@@YAMXZ)
   */
  float WLD_GetSimRate()
  {
    extern float wld_SkewRateAdjustBase;
    extern float wld_SkewRateAdjustMax;

    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr) {
      return 1.0f;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager == nullptr) {
      return 1.0f;
    }

    const float requestedSimScale =
      static_cast<float>(std::pow(10.0, static_cast<double>(clientManager->GetSimRate()) * 0.1));

    const float skewRateMin = 1.0f / wld_SkewRateAdjustMax;
    const float skewRateSample =
      static_cast<float>(std::pow(static_cast<double>(wld_SkewRateAdjustBase), -simDriver->GetSimSpeed()));
    const float clampedSkewRate = std::max(skewRateMin, std::min(wld_SkewRateAdjustMax, skewRateSample));
    return clampedSkewRate * requestedSimScale;
  }

  /**
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   */
  CWldSession* WLD_GetActiveSession()
  {
    return gActiveWldSession;
  }
} // namespace moho
