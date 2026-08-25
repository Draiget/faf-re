#include "moho/unit/CUnitMotionConstruct.h"

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  /**
   * Address: 0x006BAC40 (FUN_006BAC40, destroy_CUnitMotion)
   *
   * What it does:
   * Runs `CUnitMotion` teardown and frees the backing allocation when present.
   */
  void destroy_CUnitMotion(void* const objectPtr)
  {
    auto* const motion = static_cast<CUnitMotion*>(objectPtr);
    if (!motion) {
      return;
    }

    motion->~CUnitMotion();
    ::operator delete(motion);
  }

  /**
   * Address: 0x00BD7240 (FUN_00BD7240, register_CUnitMotionConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  CUnitMotionConstruct::CUnitMotionConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CUnitMotion::MemberConstruct))
    , mDeleteCallback(&destroy_CUnitMotion)
  {}

  /**
   * Address: 0x00BFE070 (FUN_00BFE070, cleanup_CUnitMotionConstruct)
   */
  CUnitMotionConstruct::~CUnitMotionConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006BA7F0 (FUN_006BA7F0, gpg::SerConstructHelper_CUnitMotion::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_6BA7F0(void (__cdecl **this)(void *)))(...);
   */
  void CUnitMotionConstruct::Init()
  {
    gpg::RType* const type = CUnitMotion::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
