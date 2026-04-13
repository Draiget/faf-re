#include "moho/entity/CTextureScroller.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedScrollerType()
  {
    if (moho::SScroller::sType == nullptr) {
      moho::SScroller::sType = gpg::LookupRType(typeid(moho::SScroller));
    }
    return moho::SScroller::sType;
  }

  /**
   * Address: 0x007785B0 (FUN_007785B0)
   *
   * What it does:
   * Deserializes one reflected `SScroller` payload lane and returns the input
   * archive pointer for callback chaining.
   */
  [[maybe_unused]] gpg::ReadArchive*
  DeserializeScrollerPayload(gpg::ReadArchive* const archive, void* const payload, gpg::RRef* const ownerRef)
  {
    if (archive == nullptr || payload == nullptr) {
      return archive;
    }

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);

    const gpg::RRef nullOwner{};
    archive->Read(scrollerType, payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }
} // namespace

namespace moho
{
  gpg::RType* SScroller::sType = nullptr;

  /**
   * Address: 0x00778470 (FUN_00778470, Moho::CTextureScroller::MemberDeserialize)
   *
   * What it does:
   * Deserializes owner entity pointer, scroller configuration payload, then
   * reads direction/speed lanes.
   */
  void CTextureScroller::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_Entity(&mEntity, &nullOwner);

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);
    archive->Read(scrollerType, &mScroller, nullOwner);

    bool dir0 = false;
    bool dir1 = false;
    archive->ReadBool(&dir0);
    archive->ReadBool(&dir1);
    mDir[0] = static_cast<std::uint8_t>(dir0 ? 1u : 0u);
    mDir[1] = static_cast<std::uint8_t>(dir1 ? 1u : 0u);

    archive->ReadInt(&mSpeed[0]);
    archive->ReadInt(&mSpeed[1]);
  }

  /**
   * Address: 0x00778510 (FUN_00778510, Moho::CTextureScroller::MemberSerialize)
   *
   * What it does:
   * Serializes owner entity pointer, scroller configuration payload, then
   * emits direction/speed lanes.
   */
  void CTextureScroller::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RRef entityRef{};
    gpg::RRef_Entity(&entityRef, mEntity);
    gpg::WriteRawPointer(archive, entityRef, gpg::TrackedPointerState::Unowned, nullOwner);

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);
    archive->Write(scrollerType, &mScroller, nullOwner);

    archive->WriteBool(mDir[0] != 0u);
    archive->WriteBool(mDir[1] != 0u);
    archive->WriteInt(mSpeed[0]);
    archive->WriteInt(mSpeed[1]);
  }
} // namespace moho
