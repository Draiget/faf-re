
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  [[nodiscard]] moho::IEffect* DecodeTrackedIEffect(const gpg::TrackedPointerInfo& tracked)
  {
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, moho::IEffect::StaticGetClass());
    return static_cast<moho::IEffect*>(upcast.mObj);
  }

  [[nodiscard]] moho::IEffect* ReadOwnedIEffectPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      tracked.state = gpg::TrackedPointerState::Owned;
    } else {
      GPG_ASSERT(tracked.state == gpg::TrackedPointerState::Owned);
    }

    return DecodeTrackedIEffect(tracked);
  }

  void WriteOwnedIEffectPointer(gpg::WriteArchive* const archive, moho::IEffect* const effect, const gpg::RRef& ownerRef)
  {
    gpg::RRef effectRef{};
    if (effect) {
      effectRef = effect->GetDerivedObjectRef();
      if (!effectRef.mType) {
        effectRef.mType = moho::IEffect::StaticGetClass();
      }
    }

    gpg::WriteRawPointer(archive, effectRef, gpg::TrackedPointerState::Owned, ownerRef);
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x0066BD00 (FUN_0066BD00, DeserializeActiveEffectsList_CEffectManagerImpl)
   *
   * What it does:
   * Reads owned `IEffect` pointers from archive until null terminator and
   * relinks each effect into `CEffectManagerImpl::mActiveEffects`.
   */
  void CEffectManagerImpl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    for (;;) {
      moho::IEffect* const effect = ReadOwnedIEffectPointer(archive, gpg::RRef{});
      if (effect == nullptr) {
        break;
      }
      effect->ListLinkBefore(&mActiveEffects);
    }
  }

  /**
   * Address: 0x0066BC80 (FUN_0066BC80, SerializeActiveEffectsList_CEffectManagerImpl)
   *
   * What it does:
   * Writes `mActiveEffects` entries as owned tracked pointers, followed by a
   * null-pointer terminator.
   */
  void CEffectManagerImpl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    for (moho::IEffect* const effect : mActiveEffects.owners()) {
      WriteOwnedIEffectPointer(archive, effect, gpg::RRef{});
    }

    WriteOwnedIEffectPointer(archive, nullptr, gpg::RRef{});
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CEffectManagerImpl>`, vtable 0x00E25E80.
   *
   * Address: 0x00BD4600 (FUN_00BD4600 -- constructs the global and registers its destructor.)
   * Address: 0x00BFC060 (FUN_00BFC060 -- the global's destructor.)
   * Address: 0x0066C160 (FUN_0066C160 -- `Init`.)
   * Address: 0x0066BBD0 (FUN_0066BBD0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0066BBE0 (FUN_0066BBE0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CEffectManagerImplSerializer : gpg::SerSaveLoadHelper<CEffectManagerImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B3D2C -- process-global `CEffectManagerImplSerializer` singleton.
  moho::CEffectManagerImplSerializer gCEffectManagerImplSerializer;
} // namespace
