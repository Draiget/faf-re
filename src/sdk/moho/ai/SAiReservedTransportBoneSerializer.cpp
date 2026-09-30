
#include <cstdint>
#include <typeinfo>

#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{

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

} // namespace

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

  reservedUnit = other.reservedUnit;

  reservedBones = other.reservedBones;
  return *this;
}

/**
 * Address: 0x005EAC50 (FUN_005EAC50,
 * Moho::SAiReservedTransportBone::SAiReservedTransportBone(const SAiReservedTransportBone&))
 *
 * What it does:
 * Memberwise copy construction: both bone indices, the weak unit link (which
 * links the new node into the same owner chain) and the reserved-bones
 * vector. Reached per element from `msvc8::vector<SAiReservedTransportBone>`'s
 * `_Uninit_copy` (0x005EFF70) and `resize` (0x005EA590).
 */
SAiReservedTransportBone::SAiReservedTransportBone(const SAiReservedTransportBone& other)
  : transportBoneIndex(other.transportBoneIndex)
  , attachBoneIndex(other.attachBoneIndex)
  , reservedUnit(other.reservedUnit)
  , reservedBones(other.reservedBones)
{
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

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SAiReservedTransportBone>`, vtable 0x00E1F270.
   *
   * Address: 0x00BCED90 (FUN_00BCED90 -- constructs the global and registers its destructor.)
   * Address: 0x00BF8A00 (FUN_00BF8A00 -- the global's destructor.)
   * Address: 0x005E8F70 (FUN_005E8F70 -- `Init`.)
   * Address: 0x005E40A0 (FUN_005E40A0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005E40B0 (FUN_005E40B0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SAiReservedTransportBoneSerializer : gpg::SerSaveLoadHelper<SAiReservedTransportBone>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B0864 -- process-global `SAiReservedTransportBoneSerializer` singleton.
  moho::SAiReservedTransportBoneSerializer gSAiReservedTransportBoneSerializer;
} // namespace
