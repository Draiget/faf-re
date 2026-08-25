#include "moho/ai/CFormationInstanceSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

namespace
{
  // Address: 0x010AD2EC -- process-global `CFormationInstanceSerializer`
  // singleton. Constructing it runs CFormationInstanceSerializer::
  // CFormationInstanceSerializer() (0x00BCAC40), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~CFormationInstanceSerializer, 0x00BF5AA0) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  CFormationInstanceSerializer gCFormationInstanceSerializer;

  [[nodiscard]] gpg::RType* CachedCFormationInstanceType()
  {
    gpg::RType* type = CFormationInstance::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CFormationInstance));
      CFormationInstance::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x0056A860 (FUN_0056A860, Moho::CFormationInstanceSerializer::Deserialize)
 *
 * IDA signature:
 * void __cdecl Moho::CFormationInstanceSerializer::Deserialize(
 *     gpg::ReadArchive* archive, Moho::CFormationInstance* formation);
 */
void CFormationInstanceSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const formation = reinterpret_cast<CFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  formation->MemberDeserialize(archive);
}

/**
 * Address: 0x0056A870 (FUN_0056A870, Moho::CFormationInstanceSerializer::Serialize)
 */
void CFormationInstanceSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const formation = reinterpret_cast<const CFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  formation->MemberSerialize(archive);
}

/**
 * Address: 0x00BCAC40 (FUN_00BCAC40, dynamic initializer for the global
 * `CFormationInstanceSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CFormationInstanceSerializer::CFormationInstanceSerializer()
  : mLoadCallback(&CFormationInstanceSerializer::Deserialize)
  , mSaveCallback(&CFormationInstanceSerializer::Serialize)
{}

/**
 * Address: 0x00BF5AA0 (FUN_00BF5AA0, ??1CFormationInstanceSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks the helper node from the intrusive serializer chain and re-points
 * both links at itself, leaving a valid one-element ring.
 */
CFormationInstanceSerializer::~CFormationInstanceSerializer()
{
  ResetLinks();
}

/**
 * What it does:
 * Lazily resolves the `CFormationInstance` descriptor and installs this
 * helper's load/save callbacks into it.
 */
void CFormationInstanceSerializer::Init()
{
  gpg::RType* const type = CachedCFormationInstanceType();
  if (type == nullptr) {
    return;
  }

  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}
