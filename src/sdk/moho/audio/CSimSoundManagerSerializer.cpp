
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/ISoundManager.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  using LoopNode = moho::TDatListItem<moho::HSound, void>;

  void SerializeAudioRequestFastVector(
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
          reinterpret_cast<gpg::RType::save_func_t>(&SerializeAudioRequestFastVector);
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
  void SerializeAudioRequestFastVector(
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
      archive->ReadPointer(&sound, &owner);
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

      archive->WritePointer<moho::HSound>(const_cast<moho::HSound*>(sound), gpg::TrackedPointerState::Unowned, gpg::RRef{});
    }

    archive->WritePointer<moho::HSound>(nullptr, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00762B40 (FUN_00762B40)
   *
   * What it does:
   * Deserializes one `CSimSoundManager` lane by loading `ISoundManager` base
   * state, queued request vector lanes, then active-loop pointer lanes.
   */
  void CSimSoundManager::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedISoundManagerType(), static_cast<moho::ISoundManager*>(this), owner);
    archive->Read(CachedAudioRequestVectorType(), &mRequests, owner);
    DeserializeCSimSoundManagerLoopList(this, archive);
  }

  /**
   * Address: 0x00762820 (FUN_00762820)
   * Address: 0x00762BC0 (FUN_00762BC0)
   *
   * What it does:
   * Serializes one `CSimSoundManager` lane by writing `ISoundManager` base
   * state, queued request vector lanes, then active-loop pointer lanes.
   */
  void CSimSoundManager::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(
      CachedISoundManagerType(),
      const_cast<moho::ISoundManager*>(static_cast<const moho::ISoundManager*>(this)),
      owner
    );
    archive->Write(CachedAudioRequestVectorType(), &mRequests, owner);
    SerializeCSimSoundManagerLoopList(this, archive);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CSimSoundManager>`, vtable 0x00E35ABC.
   *
   * Address: 0x00BDC590 (FUN_00BDC590 -- constructs the global and registers its destructor.)
   * Address: 0x00C015C0 (FUN_00C015C0 -- the global's destructor.)
   * Address: 0x00762810 (FUN_00762810 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x00762440 (FUN_00762440 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x00762450 (FUN_00762450 -- an unreferenced copy of `Serialize`.)
   * Address: 0x00761E90 (FUN_00761E90 -- `Init`.)
   * Address: 0x007612E0 (FUN_007612E0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00761300 (FUN_00761300 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CSimSoundManagerSerializer : gpg::SerSaveLoadHelper<CSimSoundManager>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BAF04 -- process-global `CSimSoundManagerSerializer` singleton.
  moho::CSimSoundManagerSerializer gCSimSoundManagerSerializer;
} // namespace
