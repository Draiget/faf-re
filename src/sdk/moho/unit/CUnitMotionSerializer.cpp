#include "moho/unit/CUnitMotionSerializer.h"

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  /**
   * Address: 0x00BD7280 (FUN_00BD7280, register_CUnitMotionSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitMotionSerializer::CUnitMotionSerializer()
    : mLoadCallback(reinterpret_cast<gpg::RType::load_func_t>(&CUnitMotionSerializer::Deserialize))
    , mSaveCallback(reinterpret_cast<gpg::RType::save_func_t>(&CUnitMotionSerializer::Serialize))
  {}

  /**
   * Address: 0x00BFE0A0 (FUN_00BFE0A0, Moho::CUnitMotionSerializer::~CUnitMotionSerializer)
   */
  CUnitMotionSerializer::~CUnitMotionSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006BA2E0 (FUN_006BA2E0, Moho::CUnitMotionSerializer::Deserialize)
   *
   * What it does:
   * Forwards one reflected load callback into `CUnitMotion::MemberDeserialize`.
   * Real body is an unconditional call with no null guard.
   */
  void CUnitMotionSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    CUnitMotion::MemberDeserialize(archive, reinterpret_cast<CUnitMotion*>(objectPtr));
  }

  /**
   * Address: 0x006BA2F0 (FUN_006BA2F0, Moho::CUnitMotionSerializer::Serialize)
   *
   * What it does:
   * Forwards one reflected save callback into `CUnitMotion::MemberSerialize`.
   * Real body is an unconditional call with no null guard and no `ownerRef`
   * branch -- the prior recovery fabricated an `ownerRef`-conditional
   * dispatch through a dead one-instruction jump-thunk pair
   * (`j_Moho::CUnitMotion::MemberSerialize`/`_0` at 0x006BACB0/0x006BACD0,
   * both zero-xref, both jumping straight to the same
   * `CUnitMotion::MemberSerialize` this call already reaches directly).
   */
  void CUnitMotionSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    CUnitMotion::MemberSerialize(reinterpret_cast<CUnitMotion*>(objectPtr), archive);
  }

  /**
   * Address: 0x006BA870 (FUN_006BA870, gpg::SerSaveLoadHelper_CUnitMotion::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_6BA870(void (__cdecl **this)(...)))(...);
   */
  void CUnitMotionSerializer::Init()
  {
    gpg::RType* const type = CUnitMotion::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
