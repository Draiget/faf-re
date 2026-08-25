#include "moho/audio/SAudioRequestSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"

namespace
{
  constexpr int kSerializationLoadLine = 84;
  constexpr int kSerializationSaveLine = 87;
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kLoadAssertText = "!type->mSerLoadFunc";
  constexpr const char* kSaveAssertText = "!type->mSerSaveFunc";

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveSAudioRequestType()
  {
    gpg::RType* type = moho::SAudioRequest::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SAudioRequest));
      moho::SAudioRequest::sType = type;
    }
    return type;
  }

  // Address: 0x010A933C -- process-global `SAudioRequestSerializer` singleton.
  // Constructing it runs SAudioRequestSerializer::SAudioRequestSerializer()
  // (0x00BC6A50), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::SAudioRequestSerializer gSAudioRequestSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC6A50 (FUN_00BC6A50, register_SAudioRequestSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SAudioRequestSerializer::SAudioRequestSerializer()
    : mDeserialize(&SAudioRequestSerializer::Deserialize)
    , mSerialize(&SAudioRequestSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF1080 (FUN_00BF1080, Moho::SAudioRequestSerializer::~SAudioRequestSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SAudioRequestSerializer::~SAudioRequestSerializer() noexcept
  {
    ResetLinks();
  }

  /**
   * Address: 0x004E4D30 (FUN_004E4D30, Moho::SAudioRequest::MemberDeserialize)
   */
  void SAudioRequest::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    const gpg::RRef ownerRef{};
    archive->Read(ResolveVector3fType(), &position, ownerRef);
    archive->ReadInt(reinterpret_cast<int*>(&layer));
    (void)archive->ReadPointer_CSndParams(&params, &ownerRef);
    (void)archive->ReadPointer_HSound(&sound, &ownerRef);
  }

  /**
   * Address: 0x004E4DB0 (FUN_004E4DB0, Moho::SAudioRequest::MemberSerialize)
   */
  void SAudioRequest::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    const gpg::RRef ownerRef{};
    archive->Write(ResolveVector3fType(), &position, ownerRef);
    archive->WriteInt(static_cast<int>(layer));

    gpg::RRef paramsRef{};
    gpg::RRef_CSndParams(&paramsRef, params);
    gpg::WriteRawPointer(archive, paramsRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RRef soundRef{};
    gpg::RRef_HSound(&soundRef, sound);
    gpg::WriteRawPointer(archive, soundRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  /**
   * Address: 0x004E1040 (FUN_004E1040, Moho::SAudioRequestSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SAudioRequest`. Forwards the
   * reflected object pointer to `SAudioRequest::MemberDeserialize`.
   */
  void SAudioRequestSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const request = reinterpret_cast<SAudioRequest*>(objectPtr);
    if (request != nullptr) {
      request->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x004E1050 (FUN_004E1050, Moho::SAudioRequestSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SAudioRequest`. Forwards the
   * reflected object pointer to `SAudioRequest::MemberSerialize`.
   */
  void SAudioRequestSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const request = reinterpret_cast<const SAudioRequest*>(objectPtr);
    if (request != nullptr) {
      request->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x004E1EB0 (FUN_004E1EB0, gpg::SerSaveLoadHelper<Moho::SAudioRequest>::Init)
   */
  void SAudioRequestSerializer::Init()
  {
    gpg::RType* const type = ResolveSAudioRequestType();
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure(kLoadAssertText, kSerializationLoadLine, kSerializationSourcePath);
    }
    type->serLoadFunc_ = mDeserialize;

    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure(kSaveAssertText, kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
