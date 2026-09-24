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
  gpg::RType* CDecalHandle::sPointerType = nullptr;
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
   * Address: 0x0077E9F0 (FUN_0077E9F0, Moho::CDecalHandle::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflected pointer type for `CDecalHandle*`
   * by driving the startup registrar `preregister_CDecalHandlePointerTypeStartup`
   * (FUN_0077EBA0), falling back to a plain `LookupRType` when the descriptor
   * is not yet registered.
   */
  gpg::RType* CDecalHandle::GetPointerType()
  {
    (void)StaticGetClass();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::preregister_CDecalHandlePointerTypeStartup();
      if (!cached) {
        cached = gpg::LookupRType(typeid(CDecalHandle*));
      }
      sPointerType = cached;
    }

    return cached;
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
  {}

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
