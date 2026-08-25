#include "moho/unit/tasks/CAcquireTargetTaskSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCAcquireTargetTaskType()
  {
    gpg::RType* type = moho::CAcquireTargetTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAcquireTargetTask));
      moho::CAcquireTargetTask::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BCE930 (FUN_00BCE930, dynamic initializer for the global
   * `CAcquireTargetTaskSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`).
   */
  moho::CAcquireTargetTaskSerializer gCAcquireTargetTaskSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCE930 (FUN_00BCE930, register_CAcquireTargetTaskSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields directly to
   * `CAcquireTargetTask::MemberDeserialize`/`MemberSerialize`.
   */
  CAcquireTargetTaskSerializer::CAcquireTargetTaskSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&CAcquireTargetTask::MemberDeserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&CAcquireTargetTask::MemberSerialize))
  {}

  /**
   * Address: 0x00BF84C0 (FUN_00BF84C0, Moho::CAcquireTargetTaskSerializer::~CAcquireTargetTaskSerializer)
   */
  CAcquireTargetTaskSerializer::~CAcquireTargetTaskSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x005DC190 (FUN_005DC190)
   *
   * What it does:
   * Lazily resolves `CAcquireTargetTask` RTTI and installs load/save
   * callbacks from this helper object into the type descriptor.
   */
  void CAcquireTargetTaskSerializer::Init()
  {
    gpg::RType* const type = CachedCAcquireTargetTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
