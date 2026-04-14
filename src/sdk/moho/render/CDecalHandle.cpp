#include "moho/render/CDecalHandle.h"

#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/Stats.h"

namespace moho
{
  namespace
  {
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
   * Address: 0x007788B0 (FUN_007788B0, Moho::CDecalHandle::GetClass)
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
