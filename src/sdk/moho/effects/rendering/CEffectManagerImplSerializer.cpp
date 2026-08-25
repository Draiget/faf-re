#include "moho/effects/rendering/CEffectManagerImplSerializer.h"

#include <cstdint>
#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"

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

  /**
   * Address: 0x0066BD00 (FUN_0066BD00, DeserializeActiveEffectsList_CEffectManagerImpl)
   *
   * What it does:
   * Reads owned `IEffect` pointers from archive until null terminator and
   * relinks each effect into `CEffectManagerImpl::mActiveEffects`.
   */
  void DeserializeActiveEffectsList_CEffectManagerImpl(
    gpg::ReadArchive* const archive, moho::CEffectManagerImpl* const object
  )
  {
    if (!archive || !object) {
      return;
    }

    for (;;) {
      moho::IEffect* const effect = ReadOwnedIEffectPointer(archive, gpg::RRef{});
      if (effect == nullptr) {
        break;
      }
      effect->mManagerListNode.ListLinkBefore(&object->mActiveEffects);
    }
  }

  /**
   * Address: 0x0066BC80 (FUN_0066BC80, SerializeActiveEffectsList_CEffectManagerImpl)
   *
   * What it does:
   * Writes `mActiveEffects` entries as owned tracked pointers, followed by a
   * null-pointer terminator.
   */
  void SerializeActiveEffectsList_CEffectManagerImpl(
    const moho::CEffectManagerImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    for (auto* node = object->mActiveEffects.mNext; node != &object->mActiveEffects; node = node->mNext) {
      auto* const effect = moho::IEffect::ManagerList::owner_from_member<
        moho::IEffect,
        moho::IEffect::ManagerListNode,
        &moho::IEffect::mManagerListNode>(node);
      WriteOwnedIEffectPointer(archive, effect, gpg::RRef{});
    }

    WriteOwnedIEffectPointer(archive, nullptr, gpg::RRef{});
  }

  /**
   * Address: 0x0066BBD0 (FUN_0066BBD0, Deserialize_CEffectManagerImpl)
   *
   * What it does:
   * Serializer callback wrapper that forwards to the active-effects list load
   * routine.
   */
  void Deserialize_CEffectManagerImpl(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<moho::CEffectManagerImpl*>(static_cast<std::uintptr_t>(objectPtr));
    DeserializeActiveEffectsList_CEffectManagerImpl(archive, object);
  }

  /**
   * Address: 0x0066BBE0 (FUN_0066BBE0, Serialize_CEffectManagerImpl)
   *
   * What it does:
   * Serializer callback wrapper that forwards to the active-effects list save
   * routine.
   */
  void Serialize_CEffectManagerImpl(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<moho::CEffectManagerImpl*>(static_cast<std::uintptr_t>(objectPtr));
    SerializeActiveEffectsList_CEffectManagerImpl(object, archive);
  }

  // Address: 0x010B3D2C -- process-global `CEffectManagerImplSerializer`
  // singleton. Constructing it runs
  // CEffectManagerImplSerializer::CEffectManagerImplSerializer()
  // (0x00BD4600), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEffectManagerImplSerializer gCEffectManagerImplSerializer;

  /**
   * Address: 0x00BFC060 (FUN_00BFC060, cleanup_CEffectManagerImplSerializer)
   *
   * What it does:
   * Process-exit cleanup that unlinks the `CEffectManagerImplSerializer`
   * helper node. The real ctor pushes this plain free function (not a
   * mangled destructor) as its atexit target.
   */
  void cleanup_CEffectManagerImplSerializer()
  {
    gCEffectManagerImplSerializer.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD4600 (FUN_00BD4600, register_CEffectManagerImplSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields, then registers
   * `cleanup_CEffectManagerImplSerializer` as the explicit atexit teardown.
   */
  CEffectManagerImplSerializer::CEffectManagerImplSerializer()
    : mLoadCallback(&Deserialize_CEffectManagerImpl)
    , mSaveCallback(&Serialize_CEffectManagerImpl)
  {
    (void)std::atexit(&cleanup_CEffectManagerImplSerializer);
  }

  /**
   * Address: 0x0066C160 (FUN_0066C160, gpg::SerSaveLoadHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_CEffectManagerImpl::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *obj, int version, const gpg::RRef *a5)))
   * (gpg::ReadArchive *arch, void *obj, int cont, gpg::RRef *res);
   */
  void CEffectManagerImplSerializer::Init()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
