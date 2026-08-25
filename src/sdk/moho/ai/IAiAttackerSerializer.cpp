#include "moho/ai/IAiAttackerSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiAttacker.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiAttackerType()
  {
    gpg::RType* type = IAiAttacker::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiAttacker));
      IAiAttacker::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedAttackerBroadcasterType()
  {
    gpg::RType* type = Broadcaster_EAiAttackerEvent::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Broadcaster_EAiAttackerEvent));
      Broadcaster_EAiAttackerEvent::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005D5C50 (FUN_005D5C50)
   *
   * What it does:
   * Forwards one IAiAttacker load-callback lane to
   * `IAiAttackerSerializer::Deserialize`.
   */
  void IAiAttackerDeserializeThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    IAiAttackerSerializer::Deserialize(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x005D5C60 (FUN_005D5C60)
   *
   * What it does:
   * Forwards one IAiAttacker save-callback lane to
   * `IAiAttackerSerializer::Serialize`.
   */
  void IAiAttackerSerializeThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    IAiAttackerSerializer::Serialize(archive, objectPtr, version, ownerRef);
  }

  // Address: 0x010B0344 -- process-global `IAiAttackerSerializer` singleton.
  // Constructing it runs IAiAttackerSerializer::IAiAttackerSerializer()
  // (0x00BCE7D0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::IAiAttackerSerializer gIAiAttackerSerializer;

  /**
   * Address: 0x00BF82E0 (FUN_00BF82E0, sub_BF82E0)
   *
   * What it does:
   * Unlinks the `IAiAttackerSerializer` helper node from whatever intrusive
   * list it currently sits in and restores a self-linked sentinel state.
   * Registered by the real dynamic initializer (0x00BCE7D0) as the global's
   * `atexit` teardown.
   */
  void cleanup_IAiAttackerSerializer()
  {
    gIAiAttackerSerializer.ResetLinks();
  }

  /**
   * Address: 0x005D5CA0 (FUN_005D5CA0)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks the `IAiAttackerSerializer` helper
   * links and restores self-links.
   */
  [[maybe_unused]] void cleanup_IAiAttackerSerializerStartupThunkA()
  {
    gIAiAttackerSerializer.ResetLinks();
  }

  /**
   * Address: 0x005D5CD0 (FUN_005D5CD0)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same `IAiAttackerSerializer`
   * helper unlink/reset path.
   */
  [[maybe_unused]] void cleanup_IAiAttackerSerializerStartupThunkB()
  {
    gIAiAttackerSerializer.ResetLinks();
  }
} // namespace

/**
 * Address: 0x005DE8D0 (FUN_005DE8D0, sub_5DE8D0)
 */
void IAiAttackerSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  IAiAttacker* const attacker = reinterpret_cast<IAiAttacker*>(static_cast<std::uintptr_t>(objectPtr));
  void* const broadcasterLane = (attacker != nullptr) ? static_cast<void*>(&attacker->mListeners) : nullptr;
  gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Read(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x005DE920 (FUN_005DE920, sub_5DE920)
 */
void IAiAttackerSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  const IAiAttacker* const attacker = reinterpret_cast<const IAiAttacker*>(static_cast<std::uintptr_t>(objectPtr));
  const void* const broadcasterLane = (attacker != nullptr) ? static_cast<const void*>(&attacker->mListeners) : nullptr;
  gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Write(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x00BCE7D0 (FUN_00BCE7D0, dynamic initializer for the global
 * `IAiAttackerSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the load/save callback fields, and registers
 * process-exit cleanup.
 */
IAiAttackerSerializer::IAiAttackerSerializer()
  : mLoadCallback(&IAiAttackerDeserializeThunk)
  , mSaveCallback(&IAiAttackerSerializeThunk)
{
  (void)std::atexit(&cleanup_IAiAttackerSerializer);
}

/**
 * Address: 0x005DBC90 (FUN_005DBC90, gpg::SerSaveLoadHelper_IAiAttacker::Init)
 *
 * What it does:
 * Lazily resolves IAiAttacker RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void IAiAttackerSerializer::Init()
{
  gpg::RType* const type = CachedIAiAttackerType();

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x010B0344 caller lane (`IAiAttacker.cpp`'s reflection bootstrap
 * sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `IAiAttackerSerializer` singleton from an explicit registration sequence.
 * `gIAiAttackerSerializer` is now a genuine namespace-scope global, so its
 * constructor already runs unconditionally at static-init time; this call is
 * kept only so `IAiAttacker.cpp`'s existing bootstrap sequence does not need
 * editing.
 */
int moho::register_IAiAttackerSerializer()
{
  return 0;
}
