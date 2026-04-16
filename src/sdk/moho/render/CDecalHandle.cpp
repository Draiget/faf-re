#include "moho/render/CDecalHandle.h"

#include <Windows.h>

#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"

namespace moho
{
  namespace
  {
    /**
     * Address: 0x00778890 (FUN_00778890)
     *
     * What it does:
     * Returns the lazily cached reflection descriptor for `CDecalHandle`.
     */
    [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCDecalHandleTypeBridge()
    {
      gpg::RType* type = CDecalHandle::sType;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(CDecalHandle));
        CDecalHandle::sType = type;
      }
      return type;
    }

    [[nodiscard]] gpg::RType* CachedCScriptObjectType()
    {
      gpg::RType* type = CScriptObject::sType;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(CScriptObject));
        CScriptObject::sType = type;
      }
      return type;
    }

    [[nodiscard]] gpg::RType* CachedSDecalInfoType()
    {
      gpg::RType* type = SDecalInfo::sType;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(SDecalInfo));
        SDecalInfo::sType = type;
      }
      return type;
    }

    struct DecalHandleListNodeRuntimeView
    {
      DecalHandleListNodeRuntimeView* next; // +0x00
      DecalHandleListNodeRuntimeView* prev; // +0x04
    };
    static_assert(sizeof(DecalHandleListNodeRuntimeView) == 0x08, "DecalHandleListNodeRuntimeView size must be 0x08");

    [[nodiscard]] CDecalHandle* DecalHandleFromListNodeRuntime(DecalHandleListNodeRuntimeView* const node) noexcept
    {
      if (node == nullptr) {
        return nullptr;
      }

      auto* const nodeBytes = reinterpret_cast<std::uint8_t*>(node);
      return reinterpret_cast<CDecalHandle*>(nodeBytes - offsetof(CDecalHandle, mListNode));
    }

    /**
     * Address: 0x0077A1A0 (FUN_0077A1A0)
     *
     * What it does:
     * Rewires one intrusive list node to self-links (`next=self`, `prev=self`).
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView* ResetDecalHandleListNodeLinks(
      DecalHandleListNodeRuntimeView* const node
    ) noexcept
    {
      node->prev = node;
      node->next = node;
      return node;
    }

    /**
     * Address: 0x0077AD60 (FUN_0077AD60)
     *
     * What it does:
     * Unlinks one intrusive list node from its neighbors and rewires it to
     * self-links.
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView* UnlinkDecalHandleListNode(
      DecalHandleListNodeRuntimeView* const node
    ) noexcept
    {
      node->next->prev = node->prev;
      node->prev->next = node->next;
      node->prev = node;
      node->next = node;
      return node;
    }

    /**
     * Address: 0x0077AD80 (FUN_0077AD80)
     *
     * What it does:
     * Unlinks one intrusive list node from its current list and links it
     * immediately before the provided anchor node.
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView* LinkDecalHandleListNodeBeforeAnchor(
      DecalHandleListNodeRuntimeView* const node,
      DecalHandleListNodeRuntimeView* const anchor
    ) noexcept
    {
      (void)UnlinkDecalHandleListNode(node);
      node->next = anchor->next;
      node->prev = anchor;
      anchor->next = node;
      node->next->prev = node;
      return node;
    }

    /**
     * Address: 0x0077A1E0 (FUN_0077A1E0)
     *
     * What it does:
     * Resolves one handle's embedded list node (`+0x34`), unlinks it, and
     * inserts it before the provided anchor node.
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView* LinkDecalHandleBeforeAnchor(
      CDecalHandle* const handle,
      DecalHandleListNodeRuntimeView* const anchor
    ) noexcept
    {
      auto* const node = reinterpret_cast<DecalHandleListNodeRuntimeView*>(
        reinterpret_cast<std::uint8_t*>(handle) + offsetof(CDecalHandle, mListNode)
      );
      return LinkDecalHandleListNodeBeforeAnchor(node, anchor);
    }

    struct DecalHandleNodeSlotRuntimeView
    {
      DecalHandleListNodeRuntimeView* node; // +0x00
    };
    static_assert(sizeof(DecalHandleNodeSlotRuntimeView) == 0x04, "DecalHandleNodeSlotRuntimeView size must be 0x04");

    struct DecalHandleIteratorRuntimeView
    {
      std::uint32_t lane00;                        // +0x00
      DecalHandleListNodeRuntimeView* lane04;      // +0x04
      DecalHandleListNodeRuntimeView* ownerOrNull; // +0x08
    };
    static_assert(
      offsetof(DecalHandleIteratorRuntimeView, ownerOrNull) == 0x08,
      "DecalHandleIteratorRuntimeView::ownerOrNull offset must be 0x08"
    );

    /**
     * Address: 0x0077A210 (FUN_0077A210)
     *
     * What it does:
     * Returns owning `CDecalHandle*` from one iterator lane that stores the
     * next node pointer at offset `+0x04`.
     */
    [[maybe_unused]] CDecalHandle* DecalHandleFromIteratorNextNode(
      DecalHandleIteratorRuntimeView* const iterator
    ) noexcept
    {
      return DecalHandleFromListNodeRuntime(iterator->lane04);
    }

    /**
     * Address: 0x0077A3A0 (FUN_0077A3A0)
     *
     * What it does:
     * Writes `anchor->next` into one output slot.
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView** WriteAnchorNextNodeToSlotPrimary(
      DecalHandleListNodeRuntimeView** const outSlot,
      DecalHandleListNodeRuntimeView* const anchor
    ) noexcept
    {
      *outSlot = anchor->next;
      return outSlot;
    }

    /**
     * Address: 0x0077A910 (FUN_0077A910)
     *
     * What it does:
     * Secondary entrypoint for writing `anchor->next` into one output slot.
     */
    [[maybe_unused]] DecalHandleListNodeRuntimeView** WriteAnchorNextNodeToSlotSecondary(
      DecalHandleListNodeRuntimeView** const outSlot,
      DecalHandleListNodeRuntimeView* const anchor
    ) noexcept
    {
      *outSlot = anchor->next;
      return outSlot;
    }

    /**
     * Address: 0x0077A3B0 (FUN_0077A3B0)
     *
     * What it does:
     * Returns true when one iterator owner/context lane is null.
     */
    [[maybe_unused]] bool IsDecalHandleIteratorOwnerNull(const DecalHandleIteratorRuntimeView* const iterator) noexcept
    {
      return iterator->ownerOrNull == nullptr;
    }

    /**
     * Address: 0x0077AAA0 (FUN_0077AAA0)
     *
     * What it does:
     * Returns owning `CDecalHandle*` from one slot that stores a list-node
     * pointer in lane `+0x00`.
     */
    [[maybe_unused]] CDecalHandle* DecalHandleFromNodeSlotPrimary(DecalHandleNodeSlotRuntimeView* const slot) noexcept
    {
      return DecalHandleFromListNodeRuntime(slot->node);
    }

    /**
     * Address: 0x0077AAB0 (FUN_0077AAB0)
     *
     * What it does:
     * Secondary entrypoint for owner recovery from one list-node slot lane.
     */
    [[maybe_unused]] CDecalHandle* DecalHandleFromNodeSlotSecondary(DecalHandleNodeSlotRuntimeView* const slot) noexcept
    {
      return DecalHandleFromListNodeRuntime(slot->node);
    }

    /**
     * Address: 0x0077D910 (FUN_0077D910)
     *
     * What it does:
     * Thunk lane that forwards directly to `CDecalHandle::MemberDeserialize`.
     */
    [[maybe_unused]] void DeserializeCDecalHandleMemberLaneA(
      CDecalHandle* const handle,
      gpg::ReadArchive* const archive
    )
    {
      handle->MemberDeserialize(archive);
    }

    /**
     * Address: 0x0077E6C0 (FUN_0077E6C0)
     *
     * What it does:
     * Secondary thunk lane for `CDecalHandle::MemberDeserialize`.
     */
    [[maybe_unused]] void DeserializeCDecalHandleMemberLaneB(
      CDecalHandle* const handle,
      gpg::ReadArchive* const archive
    )
    {
      handle->MemberDeserialize(archive);
    }
  } // namespace

  gpg::RType* CDecalHandle::sType = nullptr;
  CScrLuaMetatableFactory<CDecalHandle> CScrLuaMetatableFactory<CDecalHandle>::sInstance{};

  CScrLuaMetatableFactory<CDecalHandle>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CDecalHandle>& CScrLuaMetatableFactory<CDecalHandle>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CDecalHandle>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x0077ADC0 (FUN_0077ADC0, Moho::InstanceCounter<Moho::CDecalHandle>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for CDecalHandle
   * instance counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::CDecalHandle>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CDecalHandle).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x0077A160 (FUN_0077A160)
   *
   * What it does:
   * Atomically increments the CDecalHandle instance-counter stat value lane
   * and returns one pass-through integer argument unchanged.
   */
  [[maybe_unused]] std::int32_t IncrementCDecalHandleStatCounterPassThrough(const std::int32_t passThrough) noexcept
  {
    ::InterlockedExchangeAdd(
      reinterpret_cast<volatile long*>(&InstanceCounter<CDecalHandle>::GetStatItem()->mPrimaryValueBits),
      1L
    );
    return passThrough;
  }

  /**
   * Address: 0x007788B0 (FUN_007788B0, Moho::CDecalHandle::GetClass)
   */
  gpg::RType* CDecalHandle::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CDecalHandle));
    }
    return sType;
  }

  /**
   * Address: 0x007788F0 (FUN_007788F0, Moho::CDecalHandle::CDecalHandle)
   */
  CDecalHandle::CDecalHandle()
    : mListNode()
    , mInfo()
    , mArmyVisibilityFlags(0)
    , mVisibleInFocus(0)
    , mPadD1{0, 0, 0}
    , mCreatedAtTick(0)
  {
    ++InstanceCounter<CDecalHandle>::s_count;
  }

  /**
   * Address: 0x00778980 (FUN_00778980, Moho::CDecalHandle::CDecalHandle)
   */
  CDecalHandle::CDecalHandle(
    LuaPlus::LuaState* const state,
    const std::uint32_t objectId,
    const SDecalInfo& info,
    const std::uint32_t createdAtTick
  )
    : CScriptObject()
    , mListNode()
    , mInfo(info)
    , mArmyVisibilityFlags(0)
    , mVisibleInFocus(0)
    , mPadD1{0, 0, 0}
    , mCreatedAtTick(createdAtTick)
  {
    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg1{};
    LuaPlus::LuaObject scriptFactory{};
    (void)func_CreateCDecalHandleObject(&scriptFactory, state);
    CreateLuaObject(scriptFactory, arg1, arg2, arg3);

    ++InstanceCounter<CDecalHandle>::s_count;
    mInfo.mObj = objectId;
  }

  /**
   * Address: 0x00778AD0 (FUN_00778AD0)
   *
   * What it does:
   * Tests whether one army-index visibility bit is set in
   * `mArmyVisibilityFlags`.
   */
  bool CDecalHandle::IsArmyVisibleForIndex(const std::uint8_t armyIndex) const noexcept
  {
    const std::uint32_t mask = (1u << (static_cast<std::uint32_t>(armyIndex) & 31u));
    return (mArmyVisibilityFlags & mask) != 0u;
  }

  /**
   * Address: 0x00778AF0 (FUN_00778AF0)
   *
   * What it does:
   * Sets one army-index visibility bit in `mArmyVisibilityFlags` and returns
   * this handle.
   */
  CDecalHandle* CDecalHandle::SetArmyVisibleForIndex(const std::uint8_t armyIndex) noexcept
  {
    const std::uint32_t mask = (1u << (static_cast<std::uint32_t>(armyIndex) & 31u));
    mArmyVisibilityFlags |= mask;
    return this;
  }

  /**
   * Address: 0x00778B00 (FUN_00778B00)
   *
   * What it does:
   * Returns the handle creation tick lane.
   */
  std::uint32_t CDecalHandle::GetCreatedAtTickValue() const noexcept
  {
    return mCreatedAtTick;
  }

  /**
   * Address: 0x00778B10 (FUN_00778B10)
   *
   * What it does:
   * Returns true when the focus-visibility flag lane is non-zero.
   */
  bool CDecalHandle::IsVisibleInFocusFlagSet() const noexcept
  {
    return mVisibleInFocus != 0u;
  }

  /**
   * Address: 0x0077F1E0 (FUN_0077F1E0, Moho::CDecalHandle::MemberDeserialize)
   *
   * What it does:
   * Loads CScriptObject base lanes, then decal payload and decal visibility
   * tick fields from one archive stream.
   */
  void CDecalHandle::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef baseOwnerRef{};
    archive->Read(CachedCScriptObjectType(), static_cast<CScriptObject*>(this), baseOwnerRef);

    const gpg::RRef decalOwnerRef{};
    archive->Read(CachedSDecalInfoType(), &mInfo, decalOwnerRef);

    archive->ReadUInt(&mArmyVisibilityFlags);

    int createdAtTick = 0;
    archive->ReadInt(&createdAtTick);
    mCreatedAtTick = static_cast<std::uint32_t>(createdAtTick);
  }

  /**
   * Address: 0x0077F280 (FUN_0077F280, Moho::CDecalHandle::MemberSerialize)
   *
   * What it does:
   * Saves CScriptObject base lanes, then serializes decal payload and decal
   * visibility/tick fields into one archive stream.
   */
  void CDecalHandle::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef baseOwnerRef{};
    archive->Write(CachedCScriptObjectType(), static_cast<const CScriptObject*>(this), baseOwnerRef);

    const gpg::RRef decalOwnerRef{};
    archive->Write(CachedSDecalInfoType(), &mInfo, decalOwnerRef);

    archive->WriteUInt(mArmyVisibilityFlags);
    archive->WriteInt(static_cast<int>(mCreatedAtTick));
  }

  /**
    * Alias of FUN_007788B0 (non-canonical helper lane).
   */
  gpg::RType* CDecalHandle::GetClass() const
  {
    return StaticGetClass();
  }

  /**
   * Address: 0x007788D0 (FUN_007788D0, Moho::CDecalHandle::GetDerivedObjectRef)
   */
  gpg::RRef CDecalHandle::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x00778B40 (FUN_00778B40, Moho::CDecalHandle::dtr)
   * Address: 0x00778C10 (FUN_00778C10, Moho::CDecalHandle::~CDecalHandle body)
   */
  CDecalHandle::~CDecalHandle()
  {
    mListNode.ListUnlink();
    --InstanceCounter<CDecalHandle>::s_count;
  }

  CDecalHandle* CDecalHandle::FromListNode(CDecalHandleListNode* const node) noexcept
  {
    return CDecalHandleList::owner_from_member<CDecalHandle, CDecalHandleListNode, &CDecalHandle::mListNode>(node);
  }

  const CDecalHandle* CDecalHandle::FromListNode(const CDecalHandleListNode* const node) noexcept
  {
    return CDecalHandleList::owner_from_member<CDecalHandle, CDecalHandleListNode, &CDecalHandle::mListNode>(node);
  }
} // namespace moho
