#include "moho/entity/intel/CIntelCounterHandleSerializer.h"

#include "moho/entity/intel/CIntelCounterHandle.h"

namespace moho
{
  /**
   * Address: 0x0076F990 (FUN_0076F990, Moho::CIntelCounterHandleSerializer::Deserialize)
   */
  void CIntelCounterHandleSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const handle = reinterpret_cast<CIntelCounterHandle*>(objectPtr);
    handle->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0076F9A0 (FUN_0076F9A0, Moho::CIntelCounterHandleSerializer::Serialize)
   */
  void CIntelCounterHandleSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const handle = reinterpret_cast<const CIntelCounterHandle*>(objectPtr);
    handle->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BDCD90 (FUN_00BDCD90, dynamic initializer for the global
   * `CIntelCounterHandleSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CIntelCounterHandleSerializer::CIntelCounterHandleSerializer()
    : mLoadCallback(&CIntelCounterHandleSerializer::Deserialize)
    , mSaveCallback(&CIntelCounterHandleSerializer::Serialize)
  {}

  /**
   * Address: 0x00C01F90 (FUN_00C01F90, Moho::CIntelCounterHandleSerializer::~CIntelCounterHandleSerializer)
   */
  CIntelCounterHandleSerializer::~CIntelCounterHandleSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0076FC20 (FUN_0076FC20, gpg::SerSaveLoadHelper_CIntelCounterHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelCounterHandle RTTI and installs load/save
   * callbacks from this helper into the type descriptor.
   */
  void CIntelCounterHandleSerializer::Init()
  {
    gpg::RType* const type = CIntelCounterHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010BB48C -- process-global `CIntelCounterHandleSerializer`
  // singleton. Constructing it runs CIntelCounterHandleSerializer::
  // CIntelCounterHandleSerializer() (0x00BDCD90), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; InitNewHelpers() later dispatches
  // Init() on it.
  moho::CIntelCounterHandleSerializer gCIntelCounterHandleSerializer{};
} // namespace
