#include "moho/render/CDecalHandle.h"

#include <typeinfo>

namespace moho
{
  gpg::RType* CDecalHandle::sType = nullptr;

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
    , mInfo{}
    , mArmyVisibilityFlags(0)
    , mVisibleInFocus(0)
    , mPadD1{0, 0, 0}
    , mCreatedAtTick(0)
  {
    ++InstanceCounter<CDecalHandle>::s_count;
    mInfo.mFidelity = 1;
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
