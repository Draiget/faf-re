
#include <cstddef>
#include "moho/audio/SAudioRequest.h"
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x004E4D30 (FUN_004E4D30, Moho::SAudioRequest::MemberDeserialize)
   */
  void SAudioRequest::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    const gpg::RRef ownerRef{};
    archive->Read(ResolveVector3fType(), &position, ownerRef);
    archive->ReadInt(reinterpret_cast<int*>(&layer));
    (void)archive->ReadPointer(&params, &ownerRef);
    (void)archive->ReadPointer(&sound, &ownerRef);
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

    archive->WritePointer<moho::CSndParams>(params, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->WritePointer<moho::HSound>(sound, gpg::TrackedPointerState::Unowned, ownerRef);
  }

} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SAudioRequest>`, vtable 0x00E0BAD8.
   *
   * Address: 0x00BC6A50 (FUN_00BC6A50 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1080 (FUN_00BF1080 -- the global's destructor.)
   * Address: 0x004E1EB0 (FUN_004E1EB0 -- `Init`.)
   * Address: 0x004E1040 (FUN_004E1040 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x004E1050 (FUN_004E1050 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SAudioRequestSerializer : gpg::SerSaveLoadHelper<SAudioRequest>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A933C -- process-global `SAudioRequestSerializer` singleton.
  moho::SAudioRequestSerializer gSAudioRequestSerializer;
} // namespace
