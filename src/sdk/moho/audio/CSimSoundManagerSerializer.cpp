#include "moho/audio/CSimSoundManagerSerializer.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/ISoundManager.h"

namespace
{
  using LoopNode = moho::TDatListItem<moho::HSound, void>;
  moho::CSimSoundManagerSerializer gCSimSoundManagerSerializer{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(moho::CSimSoundManagerSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(moho::CSimSoundManagerSerializer& serializer) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00761350 (FUN_00761350)
   *
   * What it does:
   * Unlinks startup `CSimSoundManagerSerializer` helper links and rewires the
   * node into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCSimSoundManagerSerializerNodeVariantA() noexcept
  {
    return UnlinkSerializerNode(gCSimSoundManagerSerializer);
  }

  /**
   * Address: 0x00761380 (FUN_00761380)
   *
   * What it does:
   * Duplicate unlink/reset lane for the startup `CSimSoundManagerSerializer`
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCSimSoundManagerSerializerNodeVariantB() noexcept
  {
    return UnlinkSerializerNode(gCSimSoundManagerSerializer);
  }

  void SerializeAudioRequestFastVectorRuntime(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef
  );

  [[nodiscard]] gpg::RType* CachedISoundManagerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ISoundManager));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedAudioRequestVectorType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::fastvector<moho::SAudioRequest>));
      if (type != nullptr && type->serSaveFunc_ == nullptr) {
        type->serSaveFunc_ =
          reinterpret_cast<gpg::RType::save_func_t>(&SerializeAudioRequestFastVectorRuntime);
      }
    }
    return type;
  }

  /**
   * Address: 0x007622B0 (FUN_007622B0)
   *
   * What it does:
   * Serializes one `fastvector<SAudioRequest>` payload by writing count and
   * each request element through reflected write callbacks.
   */
  void SerializeAudioRequestFastVectorRuntime(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const requests = reinterpret_cast<const gpg::fastvector<moho::SAudioRequest>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    const unsigned int count = requests != nullptr
      ? static_cast<unsigned int>(requests->end_ - requests->start_)
      : 0u;
    archive->WriteUInt(count);
    if (count == 0u || requests == nullptr) {
      return;
    }

    gpg::RType* requestType = moho::SAudioRequest::sType;
    if (requestType == nullptr) {
      requestType = gpg::LookupRType(typeid(moho::SAudioRequest));
      moho::SAudioRequest::sType = requestType;
    }
    GPG_ASSERT(requestType != nullptr);
    if (requestType == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(
        requestType,
        const_cast<moho::SAudioRequest*>(requests->start_ + static_cast<std::ptrdiff_t>(i)),
        owner
      );
    }
  }

  /**
   * Address: 0x00761440 (FUN_00761440)
   *
   * What it does:
   * Reads unowned `HSound*` lanes until a null terminator and relinks each
   * handle into the `CSimSoundManager` active-loop intrusive list.
   */
  void DeserializeCSimSoundManagerLoopList(moho::CSimSoundManager* const manager, gpg::ReadArchive* const archive)
  {
    if (!manager || !archive) {
      return;
    }

    auto* const listHead = static_cast<LoopNode*>(&manager->mActiveLoops);
    for (;;) {
      moho::HSound* sound = nullptr;
      const gpg::RRef owner{};
      archive->ReadPointer_HSound(&sound, &owner);
      if (!sound) {
        break;
      }

      sound->mSimLoopLink.ListLinkAfter(listHead);
    }
  }

  /**
   * Address: 0x007613B0 (FUN_007613B0)
   *
   * What it does:
   * Serializes each active loop-handle pointer as one unowned tracked pointer
   * lane, then emits a null pointer terminator.
   */
  void SerializeCSimSoundManagerLoopList(const moho::CSimSoundManager* const manager, gpg::WriteArchive* const archive)
  {
    if (!manager || !archive) {
      return;
    }

    const auto* const listHead = static_cast<const LoopNode*>(&manager->mActiveLoops);
    for (const LoopNode* node = listHead->mNext; node != listHead; node = node->mNext) {
      const moho::HSound* const sound =
        moho::TDatList<moho::HSound, void>::owner_from_member_node<moho::HSound, &moho::HSound::mSimLoopLink>(
          const_cast<LoopNode*>(node)
        );

      gpg::RRef soundRef{};
      gpg::RRef_HSound(&soundRef, const_cast<moho::HSound*>(sound));
      gpg::WriteRawPointer(archive, soundRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    }

    gpg::RRef nullRef{};
    gpg::RRef_HSound(&nullRef, nullptr);
    gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

  /**
   * Address: 0x00762B40 (FUN_00762B40)
   *
   * What it does:
   * Deserializes one `CSimSoundManager` lane by loading `ISoundManager` base
   * state, queued request vector lanes, then active-loop pointer lanes.
   */
  void DeserializeCSimSoundManagerSerializerBody(moho::CSimSoundManager* const manager, gpg::ReadArchive* const archive)
  {
    if (!manager || !archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedISoundManagerType(), static_cast<moho::ISoundManager*>(manager), owner);
    archive->Read(CachedAudioRequestVectorType(), &manager->mRequests, owner);
    DeserializeCSimSoundManagerLoopList(manager, archive);
  }

  /**
   * Address: 0x00762810 (FUN_00762810)
   *
   * What it does:
   * Bridge thunk that forwards one `CSimSoundManager` deserialize lane to the
   * canonical serializer body.
   */
  [[maybe_unused]] void DeserializeCSimSoundManagerSerializerBodyThunk(
    moho::CSimSoundManager* const manager,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCSimSoundManagerSerializerBody(manager, archive);
  }

  /**
   * Address: 0x00762820 (FUN_00762820)
   * Address: 0x00762BC0 (FUN_00762BC0)
   *
   * What it does:
   * Serializes one `CSimSoundManager` lane by writing `ISoundManager` base
   * state, queued request vector lanes, then active-loop pointer lanes.
   */
  void SerializeCSimSoundManagerSerializerBody(const moho::CSimSoundManager* const manager, gpg::WriteArchive* const archive)
  {
    if (!manager || !archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(
      CachedISoundManagerType(),
      const_cast<moho::ISoundManager*>(static_cast<const moho::ISoundManager*>(manager)),
      owner
    );
    archive->Write(CachedAudioRequestVectorType(), &manager->mRequests, owner);
    SerializeCSimSoundManagerLoopList(manager, archive);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00762440 (FUN_00762440)
   * Address: 0x007690E0 (FUN_007690E0)
   *
   * What it does:
   * Reflection load callback wrapper for `CSimSoundManager`.
   */
  void CSimSoundManagerSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef
  )
  {
    (void)version;
    (void)ownerRef;

    auto* const manager = reinterpret_cast<CSimSoundManager*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    DeserializeCSimSoundManagerSerializerBody(manager, archive);
  }

  /**
   * Address: 0x00762450 (FUN_00762450)
   *
   * What it does:
   * Reflection save callback wrapper for `CSimSoundManager`.
   */
  void CSimSoundManagerSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef
  )
  {
    (void)version;
    (void)ownerRef;

    auto* const manager = reinterpret_cast<CSimSoundManager*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    SerializeCSimSoundManagerSerializerBody(manager, archive);
  }

  /**
   * Address: 0x00761E90 (FUN_00761E90, gpg::SerSaveLoadHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs load/save callbacks.
   */
  void CSimSoundManagerSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }
} // namespace moho
