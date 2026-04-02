#include "moho/unit/CUnitMotionSerializer.h"

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  /**
   * Address: 0x006BA2E0 (FUN_006BA2E0, Moho::CUnitMotionSerializer::Deserialize)
   */
  void CUnitMotionSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const motion = reinterpret_cast<CUnitMotion*>(objectPtr);
    if (archive == nullptr || motion == nullptr) {
      return;
    }

    CUnitMotion::MemberDeserialize(archive, motion);
  }

  /**
   * Address: 0x006BA2F0 (FUN_006BA2F0, Moho::CUnitMotionSerializer::Serialize)
   */
  void CUnitMotionSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const motion = reinterpret_cast<CUnitMotion*>(objectPtr);
    if (archive == nullptr || motion == nullptr) {
      return;
    }

    CUnitMotion::MemberSerialize(motion, archive);
  }

  /**
   * Address: 0x006BA870 (FUN_006BA870, gpg::SerSaveLoadHelper_CUnitMotion::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_6BA870(void (__cdecl **this)(...)))(...);
   */
  void CUnitMotionSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CUnitMotion::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
