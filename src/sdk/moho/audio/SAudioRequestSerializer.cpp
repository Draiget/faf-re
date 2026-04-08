#include "moho/audio/SAudioRequestSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"

namespace
{
  using Serializer = moho::SAudioRequestSerializer;

  constexpr int kSerializationLoadLine = 84;
  constexpr int kSerializationSaveLine = 87;
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kLoadAssertText = "!type->mSerLoadFunc";
  constexpr const char* kSaveAssertText = "!type->mSerSaveFunc";

  alignas(Serializer) unsigned char gSAudioRequestSerializerStorage[sizeof(Serializer)];
  bool gSAudioRequestSerializerConstructed = false;

  [[nodiscard]] Serializer& GetSAudioRequestSerializer() noexcept
  {
    if (!gSAudioRequestSerializerConstructed) {
      new (gSAudioRequestSerializerStorage) Serializer();
      gSAudioRequestSerializerConstructed = true;
    }

    return *reinterpret_cast<Serializer*>(gSAudioRequestSerializerStorage);
  }

  [[nodiscard]] gpg::SerHelperBase* SelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  void UnlinkNode(Serializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeNode(serializer);
  }

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

  void cleanup_SAudioRequestSerializer()
  {
    if (!gSAudioRequestSerializerConstructed) {
      return;
    }

    GetSAudioRequestSerializer().~SAudioRequestSerializer();
    gSAudioRequestSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004E1EB0 (FUN_004E1EB0, gpg::SerSaveLoadHelper<Moho::SAudioRequest>::Init)
   */
  void SAudioRequestSerializer::RegisterSerializeFunctions()
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
   */
  void SAudioRequestSerializer::Deserialize(gpg::ReadArchive* const archive, SAudioRequest* const request)
  {
    request->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004E1050 (FUN_004E1050, Moho::SAudioRequestSerializer::Serialize)
   */
  void SAudioRequestSerializer::Serialize(gpg::WriteArchive* const archive, SAudioRequest* const request)
  {
    request->MemberSerialize(archive);
  }

  /**
   * Address: 0x004E10C0 (FUN_004E10C0, Moho::SAudioRequestSerializer::dtr)
   */
  SAudioRequestSerializer::~SAudioRequestSerializer() noexcept
  {
    UnlinkNode(*this);
  }

  /**
   * Address: 0x00BC6A50 (FUN_00BC6A50, register_SAudioRequestSerializer)
   */
  void register_SAudioRequestSerializer()
  {
    SAudioRequestSerializer& serializer = GetSAudioRequestSerializer();
    InitializeNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&SAudioRequestSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&SAudioRequestSerializer::Serialize);
    (void)std::atexit(&cleanup_SAudioRequestSerializer);
  }
} // namespace moho

namespace
{
  struct SAudioRequestSerializerBootstrap
  {
    SAudioRequestSerializerBootstrap()
    {
      moho::register_SAudioRequestSerializer();
    }
  };

  [[maybe_unused]] SAudioRequestSerializerBootstrap gSAudioRequestSerializerBootstrap;
} // namespace
