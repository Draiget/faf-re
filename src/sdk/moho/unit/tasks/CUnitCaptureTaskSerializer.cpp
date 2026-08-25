#include "moho/unit/tasks/CUnitCaptureTaskSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCaptureTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCaptureTask));
    }
    return cached;
  }

  /**
   * Address: 0x00BCFFD0 (FUN_00BCFFD0, dynamic initializer for the global
   * `CUnitCaptureTaskSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`).
   */
  moho::CUnitCaptureTaskSerializer gCUnitCaptureTaskSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x006042B0 (FUN_006042B0, Moho::CUnitCaptureTaskSerializer::Deserialize)
   */
  void CUnitCaptureTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    reinterpret_cast<CUnitCaptureTask*>(objectPtr)->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006042C0 (FUN_006042C0, Moho::CUnitCaptureTaskSerializer::Serialize)
   */
  void CUnitCaptureTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    reinterpret_cast<CUnitCaptureTask*>(objectPtr)->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BCFFD0 (FUN_00BCFFD0, register_CUnitCaptureTaskSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCaptureTaskSerializer::CUnitCaptureTaskSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&CUnitCaptureTaskSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&CUnitCaptureTaskSerializer::Serialize))
  {}

  /**
   * Address: 0x00BF9880 (FUN_00BF9880, Moho::CUnitCaptureTaskSerializer::~CUnitCaptureTaskSerializer)
   */
  CUnitCaptureTaskSerializer::~CUnitCaptureTaskSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00605320 (FUN_00605320, Moho::CUnitCaptureTaskSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Lazily resolves the `CUnitCaptureTask` reflected type and installs
   * this helper's load/save callbacks into its type descriptor.
   */
  void CUnitCaptureTaskSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitCaptureTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
