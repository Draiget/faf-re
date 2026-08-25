#include "moho/ai/SAiReservedTransportBoneSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  // Address: 0x010B0864 -- process-global `SAiReservedTransportBoneSerializer`
  // singleton. Constructing it runs SAiReservedTransportBoneSerializer::
  // SAiReservedTransportBoneSerializer() (0x00BCED90), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~SAiReservedTransportBoneSerializer, 0x00BF8A00) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  SAiReservedTransportBoneSerializer gSAiReservedTransportBoneSerializer;

  [[nodiscard]] gpg::RType* CachedWeakUnitType()
  {
    gpg::RType* type = WeakPtr<Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(WeakPtr<Unit>));
      WeakPtr<Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIntVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<int>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSAiReservedTransportBoneType()
  {
    gpg::RType* type = SAiReservedTransportBone::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SAiReservedTransportBone));
      SAiReservedTransportBone::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E8230 (FUN_005E8230, sub_5E8230)
 *
 * What it does:
 * Releases one reserved-bones vector heap payload, clears the vector lanes,
 * and unlinks the reserved-unit weak node from its owner chain.
 */
void* moho::ResetReservedTransportBoneEntry(SAiReservedTransportBone& bone)
{
  // Free the block and null all three lanes: VC8 _Tidy().
  bone.reservedBones = decltype(bone.reservedBones){};

  void* result = bone.reservedUnit.ownerLinkSlot;
  if (result != nullptr) {
    auto** linkSlot = reinterpret_cast<WeakPtr<Unit>**>(result);
    WeakPtr<Unit>* const thisNode = &bone.reservedUnit;
    if (*linkSlot != thisNode) {
      do {
        linkSlot = &(*linkSlot)->nextInOwner;
      } while (*linkSlot != thisNode);
    }
    *linkSlot = thisNode->nextInOwner;
    result = linkSlot;
  }

  return result;
}

/**
 * Address: 0x005EE820 (FUN_005EE820, sub_5EE820)
 *
 * What it does:
 * Jump-only alias lane that forwards to `ResetReservedTransportBoneEntry`.
 */
void* moho::ResetReservedTransportBoneEntryThunkA(SAiReservedTransportBone& bone)
{
  return ResetReservedTransportBoneEntry(bone);
}

/**
 * Address: 0x005EF8B0 (FUN_005EF8B0, sub_5EF8B0)
 *
 * What it does:
 * Jump-only alias lane that forwards to `ResetReservedTransportBoneEntry`.
 */
void* moho::ResetReservedTransportBoneEntryThunkB(SAiReservedTransportBone& bone)
{
  return ResetReservedTransportBoneEntry(bone);
}

/**
 * Address: 0x005EA550 (FUN_005EA550, std::vector_SAiReservedTransportBone::reset_storage)
 *
 * What it does:
 * Destroys one `vector<SAiReservedTransportBone>` payload, releases the
 * backing heap block, and clears the vector storage lanes to empty.
 */
void moho::ResetReservedTransportBoneVectorStorage(msvc8::vector<SAiReservedTransportBone>& storage)
{
  // Element sweep first, then VC8 _Tidy().
  if (!storage.empty()) {
    (void)DestroyReservedTransportBoneRange(storage.begin(), storage.end());
  }
  storage = msvc8::vector<SAiReservedTransportBone>{};
}

/**
 * Address: 0x005EE360 (FUN_005EE360, destroy_SAiReservedTransportBone_range)
 *
 * What it does:
 * Walks one half-open bone range, frees each reserved-bones heap lane, zeros
 * vector pointers, and unlinks each reserved-unit weak node from owner chain.
 */
void* moho::DestroyReservedTransportBoneRange(SAiReservedTransportBone* begin, SAiReservedTransportBone* end)
{
  void* result = begin;
  for (SAiReservedTransportBone* bone = begin; bone != end; ++bone) {
    result = ResetReservedTransportBoneEntry(*bone);
  }

  return result;
}

/**
 * Address: 0x005EE740 (FUN_005EE740, Moho::SAiReservedTransportBone::operator=)
 *
 * What it does:
 * Copies the transport/attach bone indices directly, relinks the
 * `reservedUnit` weak-pointer node onto the source's owner-chain slot, and
 * assigns the nested `reservedBones` vector via its own `operator=`. The
 * binary tail-calls into `msvc8::vector<int>::operator=` (0x005ED190) for
 * the vector member; the equivalent here is the plain `vector<int>`
 * assignment expression, which resolves to that same canonical template
 * method.
 */
SAiReservedTransportBone& SAiReservedTransportBone::operator=(const SAiReservedTransportBone& other)
{
  transportBoneIndex = other.transportBoneIndex;
  attachBoneIndex = other.attachBoneIndex;

  AssignWeakPtrLaneWithRelink(
    reinterpret_cast<WeakPtr<void>&>(reservedUnit),
    reinterpret_cast<const WeakPtr<void>&>(other.reservedUnit)
  );

  reservedBones = other.reservedBones;
  return *this;
}

/**
 * Address: 0x005EB860 (FUN_005EB860, Moho::SAiReservedTransportBone::MemberDeserialize)
 *
 * What it does:
 * Loads transport/attach indices, reserved-unit weak link, and reserved
 * attach-bone list from one archive payload.
 */
void SAiReservedTransportBone::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  archive->ReadUInt(&transportBoneIndex);
  archive->ReadUInt(&attachBoneIndex);

  const gpg::RRef ownerRef{};

  gpg::RType* const weakUnitType = CachedWeakUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Read(weakUnitType, &reservedUnit, ownerRef);

  gpg::RType* const intVectorType = CachedIntVectorType();
  GPG_ASSERT(intVectorType != nullptr);
  archive->Read(intVectorType, &reservedBones, ownerRef);
}

/**
 * Address: 0x005EB8F0 (FUN_005EB8F0, Moho::SAiReservedTransportBone::MemberSerialize)
 *
 * What it does:
 * Stores transport/attach indices, reserved-unit weak link, and reserved
 * attach-bone list into one archive payload.
 */
void SAiReservedTransportBone::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  archive->WriteUInt(transportBoneIndex);
  archive->WriteUInt(attachBoneIndex);

  const gpg::RRef ownerRef{};

  gpg::RType* const weakUnitType = CachedWeakUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Write(weakUnitType, &reservedUnit, ownerRef);

  gpg::RType* const intVectorType = CachedIntVectorType();
  GPG_ASSERT(intVectorType != nullptr);
  archive->Write(intVectorType, &reservedBones, ownerRef);
}

/**
 * Address: 0x005E40A0 (FUN_005E40A0, SAiReservedTransportBoneSerializer::Deserialize)
 */
void SAiReservedTransportBoneSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const bone = reinterpret_cast<SAiReservedTransportBone*>(static_cast<std::uintptr_t>(objectPtr));
  bone->MemberDeserialize(archive);
}

/**
 * Address: 0x005E40B0 (FUN_005E40B0, SAiReservedTransportBoneSerializer::Serialize)
 */
void SAiReservedTransportBoneSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const bone = reinterpret_cast<const SAiReservedTransportBone*>(static_cast<std::uintptr_t>(objectPtr));
  bone->MemberSerialize(archive);
}

/**
 * Address: 0x00BCED90 (FUN_00BCED90, dynamic initializer for the global
 * `SAiReservedTransportBoneSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
SAiReservedTransportBoneSerializer::SAiReservedTransportBoneSerializer()
  : mLoadCallback(&SAiReservedTransportBoneSerializer::Deserialize)
  , mSaveCallback(&SAiReservedTransportBoneSerializer::Serialize)
{}

/**
 * Address: 0x00BF8A00 (FUN_00BF8A00, ??1SAiReservedTransportBoneSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
SAiReservedTransportBoneSerializer::~SAiReservedTransportBoneSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005E8F70 (FUN_005E8F70)
 *
 * What it does:
 * Lazily resolves SAiReservedTransportBone RTTI and installs load/save
 * callbacks from this helper object into the type descriptor.
 */
void SAiReservedTransportBoneSerializer::Init()
{
  gpg::RType* const type = CachedSAiReservedTransportBoneType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCED90 caller lane (`IAiTransport.cpp`'s reflection bootstrap
 * sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `SAiReservedTransportBoneSerializer` singleton from an explicit
 * registration sequence. `gSAiReservedTransportBoneSerializer` is now a
 * genuine namespace-scope global, so its constructor already runs
 * unconditionally at static-init time; this call is kept only so
 * `IAiTransport.cpp`'s existing bootstrap sequence does not need editing.
 */
int moho::register_SAiReservedTransportBoneSerializer()
{
  return 0;
}
