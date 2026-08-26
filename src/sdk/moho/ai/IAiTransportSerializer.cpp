#include "moho/ai/IAiTransportSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"

using namespace moho;

namespace
{
  // Address: 0x010B06D4 -- process-global `IAiTransportSerializer`
  // singleton. Constructing it runs
  // IAiTransportSerializer::IAiTransportSerializer() (0x00BCEEB0), which
  // splices this helper into gpg::SerHelperBase::sNewHelpers;
  // gpg::SerHelperBase::InitNewHelpers() later dispatches Init() on it from
  // within the first ReadArchive/WriteArchive construction.
  moho::IAiTransportSerializer gIAiTransportSerializer;

  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    gpg::RType* type = IAiTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiTransport));
      IAiTransport::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedTransportBroadcasterType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::BroadcasterEventTag<moho::EAiTransportEvent>));
    }
    return cached;
  }

  /**
   * Address: 0x005EBC80 (FUN_005EBC80)
   *
   * What it does:
   * Deserializes one `Broadcaster<EAiTransportEvent>` base lane from the
   * archive into `broadcasterLane`.
   */
  void ReadEAiTransportBroadcasterLane(void* const broadcasterLane, gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RType* const broadcasterType = CachedTransportBroadcasterType();
    GPG_ASSERT(broadcasterType != nullptr);
    const gpg::RRef ownerRef{};
    archive->Read(broadcasterType, broadcasterLane, ownerRef);
  }

  /**
   * Address: 0x005EBCD0 (FUN_005EBCD0)
   *
   * What it does:
   * Serializes one `Broadcaster<EAiTransportEvent>` base lane from
   * `broadcasterLane` into the archive.
   */
  void WriteEAiTransportBroadcasterLane(const void* const broadcasterLane, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RType* const broadcasterType = CachedTransportBroadcasterType();
    GPG_ASSERT(broadcasterType != nullptr);
    const gpg::RRef ownerRef{};
    archive->Write(broadcasterType, broadcasterLane, ownerRef);
  }

  /**
   * Address: 0x00BF8BB0 (FUN_00BF8BB0, sub_BF8BB0)
   *
   * What it does:
   * Unlinks the `IAiTransportSerializer` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BCEEB0) as the
   * global's `atexit` teardown.
   */
  void cleanup_IAiTransportSerializer()
  {
    gIAiTransportSerializer.ResetLinks();
  }

  // Addresses 0x005E48D0/0x005E4900 (the "StartupThunkA"/"StartupThunkB"
  // unlink/reset duplicates formerly modeled here) are dead: zero
  // data_refs/call_edges for both, and no source-level caller anywhere in
  // src/sdk/**. `cleanup_IAiTransportSerializer` above is the real,
  // atexit-registered teardown (see the ctor below).
} // namespace

/**
 * Address: 0x005E4880 (FUN_005E4880, IAiTransportSerializer::Deserialize)
 */
void IAiTransportSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const transport = reinterpret_cast<IAiTransport*>(static_cast<std::uintptr_t>(objectPtr));
  auto* const broadcasterLane = static_cast<void*>(static_cast<Broadcaster*>(transport));
  ReadEAiTransportBroadcasterLane(broadcasterLane, archive);
}

/**
 * Address: 0x005E4890 (FUN_005E4890, IAiTransportSerializer::Serialize)
 */
void IAiTransportSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const transport = reinterpret_cast<const IAiTransport*>(static_cast<std::uintptr_t>(objectPtr));
  auto* const broadcasterLane = static_cast<const void*>(static_cast<const Broadcaster*>(transport));
  WriteEAiTransportBroadcasterLane(broadcasterLane, archive);
}

/**
 * Address: 0x00BCEEB0 (FUN_00BCEEB0, dynamic initializer for the global
 * `IAiTransportSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the load/save callback fields, and registers
 * process-exit cleanup.
 */
IAiTransportSerializer::IAiTransportSerializer()
  : mLoadCallback(&IAiTransportSerializer::Deserialize)
  , mSaveCallback(&IAiTransportSerializer::Serialize)
{
  (void)std::atexit(&cleanup_IAiTransportSerializer);
}

/**
 * Address: 0x005E9530 (FUN_005E9530, gpg::SerSaveLoadHelper_IAiTransport::Init)
 *
 * What it does:
 * Lazily resolves IAiTransport RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiTransportSerializer::Init()
{
  gpg::RType* const type = CachedIAiTransportType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x010B06D4 caller lane (`IAiTransport.cpp`'s reflection
 * bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `IAiTransportSerializer` singleton from an explicit registration
 * sequence. `gIAiTransportSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
 * sequence does not need editing.
 */
int moho::register_IAiTransportSerializer()
{
  return 0;
}
