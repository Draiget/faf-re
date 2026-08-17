#include "moho/ai/CFormationInstanceSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

namespace
{
  alignas(CFormationInstanceSerializer) unsigned char
    gCFormationInstanceSerializerStorage[sizeof(CFormationInstanceSerializer)] = {};
  bool gCFormationInstanceSerializerConstructed = false;

  [[nodiscard]] CFormationInstanceSerializer* AcquireCFormationInstanceSerializer()
  {
    if (!gCFormationInstanceSerializerConstructed) {
      new (gCFormationInstanceSerializerStorage) CFormationInstanceSerializer();
      gCFormationInstanceSerializerConstructed = true;
    }

    return reinterpret_cast<CFormationInstanceSerializer*>(gCFormationInstanceSerializerStorage);
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(CFormationInstanceSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(CFormationInstanceSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::RType* CachedCFormationInstanceType()
  {
    gpg::RType* type = CFormationInstance::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CFormationInstance));
      CFormationInstance::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF5AA0 (FUN_00BF5AA0, ??1CFormationInstanceSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks the helper node from the intrusive serializer chain and re-points
   * both links at itself, leaving a valid one-element ring.
   */
  void cleanup_CFormationInstanceSerializer()
  {
    if (!gCFormationInstanceSerializerConstructed) {
      return;
    }

    CFormationInstanceSerializer& serializer = *AcquireCFormationInstanceSerializer();
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
  }

  struct CFormationInstanceSerializerStartupBootstrap
  {
    CFormationInstanceSerializerStartupBootstrap()
    {
      moho::register_CFormationInstanceSerializer();
    }
  };

  [[maybe_unused]] CFormationInstanceSerializerStartupBootstrap gCFormationInstanceSerializerStartupBootstrap;
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
 * What it does:
 * Lazily resolves the `CFormationInstance` descriptor and installs this
 * helper's load/save callbacks into it.
 */
void CFormationInstanceSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCFormationInstanceType();
  if (type == nullptr) {
    return;
  }

  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCAC40 (FUN_00BCAC40, register_CFormationInstanceSerializer)
 *
 * What it does:
 * Initializes the global `CFormationInstance` serializer helper, binds its
 * load/save callbacks, and installs process-exit cleanup.
 */
void moho::register_CFormationInstanceSerializer()
{
  CFormationInstanceSerializer* const serializer = AcquireCFormationInstanceSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CFormationInstanceSerializer::Deserialize;
  serializer->mSaveCallback = &CFormationInstanceSerializer::Serialize;
  (void)std::atexit(&cleanup_CFormationInstanceSerializer);
}
