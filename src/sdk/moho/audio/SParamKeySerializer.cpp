#include "moho/audio/SParamKeySerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

namespace
{
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

  // Address: 0x010A9364 -- process-global `SParamKeySerializer` singleton.
  // Constructing it runs SParamKeySerializer::SParamKeySerializer()
  // (0x00BC6860), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::SParamKeySerializer gSParamKeySerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC6860 (FUN_00BC6860, register_SParamKeySerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SParamKeySerializer::SParamKeySerializer()
    : mDeserialize(&SParamKeySerializer::Deserialize)
    , mSerialize(&SParamKeySerializer::Serialize)
  {}

  /**
   * Address: 0x00BF0E50 (FUN_00BF0E50, Moho::SParamKeySerializer::~SParamKeySerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SParamKeySerializer::~SParamKeySerializer() noexcept
  {
    ResetLinks();
  }

  /**
   * Address: 0x004DEFD0 (FUN_004DEFD0, Moho::SParamKeySerializer::Deserialize)
   */
  void SParamKeySerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const key = reinterpret_cast<SParamKey*>(objectPtr);
    if (archive == nullptr || key == nullptr) {
      return;
    }

    archive->ReadString(&key->mCueName);
    archive->ReadString(&key->mBankName);
    archive->ReadString(&key->mLodCutoffVariableName);
    archive->ReadString(&key->mRpcLoopVariableName);
  }

  /**
   * Address: 0x004DF010 (FUN_004DF010, Moho::SParamKeySerializer::Serialize)
   */
  void SParamKeySerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const key = reinterpret_cast<SParamKey*>(objectPtr);
    if (archive == nullptr || key == nullptr) {
      return;
    }

    archive->WriteString(&key->mCueName);
    archive->WriteString(&key->mBankName);
    archive->WriteString(&key->mLodCutoffVariableName);
    archive->WriteString(&key->mRpcLoopVariableName);
  }

  /**
   * Address: 0x004E1600 (FUN_004E1600, gpg::SerSaveLoadHelper_SParamKey::Init)
   */
  void SParamKeySerializer::Init()
  {
    gpg::RType* type = SParamKey::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SParamKey));
      SParamKey::sType = type;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationSourcePath);
    }
    type->serLoadFunc_ = mDeserialize;

    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
