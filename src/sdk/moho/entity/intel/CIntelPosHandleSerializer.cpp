#include "moho/entity/intel/CIntelPosHandleSerializer.h"

#include "moho/entity/intel/CIntelPosHandle.h"

namespace moho
{
  /**
   * Address: 0x0076F3D0 (FUN_0076F3D0, Moho::CIntelPosHandleSerializer::Deserialize)
   */
  void CIntelPosHandleSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const handle = reinterpret_cast<CIntelPosHandle*>(objectPtr);
    handle->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0076F3E0 (FUN_0076F3E0, Moho::CIntelPosHandleSerializer::Serialize)
   */
  void CIntelPosHandleSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const handle = reinterpret_cast<const CIntelPosHandle*>(objectPtr);
    handle->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BDCCF0 (FUN_00BDCCF0, dynamic initializer for the global
   * `CIntelPosHandleSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CIntelPosHandleSerializer::CIntelPosHandleSerializer()
    : mLoadCallback(&CIntelPosHandleSerializer::Deserialize)
    , mSaveCallback(&CIntelPosHandleSerializer::Serialize)
  {}

  /**
   * Address: 0x00C01ED0 (FUN_00C01ED0, Moho::CIntelPosHandleSerializer::~CIntelPosHandleSerializer)
   */
  CIntelPosHandleSerializer::~CIntelPosHandleSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0076FB00 (FUN_0076FB00, gpg::SerSaveLoadHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleSerializer::Init()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010BB414 -- process-global `CIntelPosHandleSerializer`
  // singleton. Constructing it runs CIntelPosHandleSerializer::
  // CIntelPosHandleSerializer() (0x00BDCCF0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; InitNewHelpers() later dispatches
  // Init() on it.
  moho::CIntelPosHandleSerializer gCIntelPosHandleSerializer{};
} // namespace
