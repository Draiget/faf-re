#include "moho/serialization/CPrefetchSetSerializer.h"

#include "gpg/core/utils/Global.h"
#include "moho/serialization/CPrefetchSet.h"
#include "moho/serialization/PrefetchHandleBaseVectorReflection.h"

namespace moho
{
  /**
   * Address: 0x00BC5990 (FUN_00BC5990, dynamic initializer for the global
   * `CPrefetchSetSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CPrefetchSetSerializer::CPrefetchSetSerializer()
    : mDeserialize(&CPrefetchSetSerializer::Deserialize)
    , mSerialize(&CPrefetchSetSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF03A0 (FUN_00BF03A0, Moho::CPrefetchSetSerializer::~CPrefetchSetSerializer)
   */
  CPrefetchSetSerializer::~CPrefetchSetSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004A55F0 (FUN_004A55F0, Moho::CPrefetchSetSerializer::Deserialize)
   */
  void CPrefetchSetSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const setObject = reinterpret_cast<CPrefetchSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(setObject != nullptr);
    if (!archive || !setObject) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(gpg::ResolvePrefetchHandleBaseVectorType(), setObject, owner);
  }

  /**
   * Address: 0x004A5630 (FUN_004A5630, Moho::CPrefetchSetSerializer::Serialize)
   */
  void CPrefetchSetSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const setObject = reinterpret_cast<CPrefetchSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(setObject != nullptr);
    if (!archive || !setObject) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(gpg::ResolvePrefetchHandleBaseVectorType(), setObject, owner);
  }

  /**
   * Address: 0x004A5F50 (FUN_004A5F50)
   */
  void CPrefetchSetSerializer::Init()
  {
    gpg::RType* const type = CPrefetchSet::StaticGetClass();
    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  // Address: 0x010A87D4 -- process-global `CPrefetchSetSerializer` singleton.
  moho::CPrefetchSetSerializer gCPrefetchSetSerializer;
} // namespace
