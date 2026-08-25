#include "moho/ai/SAttachPointSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSAttachPointType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SAttachPoint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  /**
   * Address: 0x005EB980 (FUN_005EB980)
   *
   * What it does:
   * Deserializes one `SAttachPoint` payload lane (`index`, `localPos`,
   * `distSq`) from the archive.
   */
  int ReadSAttachPointPayload(SAttachPoint* const point, gpg::ReadArchive* const archive)
  {
    if (point == nullptr || archive == nullptr) {
      return 0;
    }

    archive->ReadUInt(&point->index);

    const gpg::RRef ownerRef{};
    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Read(vectorType, &point->localPos, ownerRef);

    archive->ReadFloat(&point->distSq);
    return 1;
  }

  /**
   * Address: 0x005EB9E0 (FUN_005EB9E0)
   *
   * What it does:
   * Serializes one `SAttachPoint` payload lane (`index`, `localPos`,
   * `distSq`) into the archive.
   */
  int WriteSAttachPointPayload(const SAttachPoint* const point, gpg::WriteArchive* const archive)
  {
    if (point == nullptr || archive == nullptr) {
      return 0;
    }

    archive->WriteUInt(point->index);

    const gpg::RRef ownerRef{};
    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Write(vectorType, &point->localPos, ownerRef);

    archive->WriteFloat(point->distSq);
    return 1;
  }

  // Address: 0x010B07C4 -- process-global `SAttachPointSerializer`
  // singleton. Constructing it runs SAttachPointSerializer::
  // SAttachPointSerializer() (0x00BCEDF0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers and explicitly registers this
  // translation unit's unlink callback via `atexit` (this class has no
  // user-declared destructor).
  SAttachPointSerializer gSAttachPointSerializer;

  /**
   * Address: 0x00BF8A90 (FUN_00BF8A90)
   *
   * What it does:
   * Unlinks the global `SAttachPointSerializer` helper node from the
   * intrusive serializer chain and restores it to a self-linked node.
   * Registered by the real dynamic initializer (0x00BCEDF0) as the global's
   * `atexit` teardown.
   */
  void CleanupSAttachPointSerializer()
  {
    gSAttachPointSerializer.ResetLinks();
  }
} // namespace

/**
 * Address: 0x005E42E0 (FUN_005E42E0, SAttachPointSerializer::Deserialize)
 */
void SAttachPointSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<SAttachPoint*>(static_cast<std::uintptr_t>(objectPtr));
  (void)ReadSAttachPointPayload(point, archive);
}

/**
 * Address: 0x005E42F0 (FUN_005E42F0, SAttachPointSerializer::Serialize)
 */
void SAttachPointSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<const SAttachPoint*>(static_cast<std::uintptr_t>(objectPtr));
  (void)WriteSAttachPointPayload(point, archive);
}

/**
 * Address: 0x00BCEDF0 (FUN_00BCEDF0, dynamic initializer for the global
 * `SAttachPointSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the load/save callback fields, and explicitly
 * registers `atexit` cleanup.
 */
SAttachPointSerializer::SAttachPointSerializer()
  : mLoadCallback(&SAttachPointSerializer::Deserialize)
  , mSaveCallback(&SAttachPointSerializer::Serialize)
{
  (void)std::atexit(&CleanupSAttachPointSerializer);
}

void SAttachPointSerializer::Init()
{
  gpg::RType* const type = CachedSAttachPointType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEDF0 caller lane (`IAiTransport.cpp`'s reflection bootstrap
 * sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `SAttachPointSerializer` singleton from an explicit registration
 * sequence. `gSAttachPointSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
 * sequence does not need editing.
 */
int moho::register_SAttachPointSerializer()
{
  return 0;
}
