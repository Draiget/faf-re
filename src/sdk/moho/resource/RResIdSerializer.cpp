#include "moho/resource/RResIdSerializer.h"

#include <cstdlib>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"

namespace
{
  // Address: 0x010A8924 -- process-global `RResIdSerializer` singleton
  // (constructed by FUN_00BC5A80, self-registering via `__xc_a`; see
  // RResIdSerializer.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  moho::RResIdSerializer gRResIdSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x004A9690 (FUN_004A9690, Moho::RResIdSerializer::Deserialize)
   */
  void RResIdSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const resourceId = reinterpret_cast<RResId*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(resourceId != nullptr);
    if (!archive || !resourceId) {
      return;
    }

    archive->ReadString(&resourceId->name);
  }

  /**
   * Address: 0x004A96B0 (FUN_004A96B0, Moho::RResIdSerializer::Serialize)
   */
  void RResIdSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const resourceId = reinterpret_cast<RResId*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(resourceId != nullptr);
    if (!archive || !resourceId) {
      return;
    }

    archive->WriteString(&resourceId->name);
  }

  /**
   * Address: 0x004A9790 (FUN_004A9790, gpg::SerSaveLoadHelper<Moho::RResId>::Init)
   */
  void RResIdSerializer::Init()
  {
    gpg::RType* const type = RResId::StaticGetClass();
    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC5A80 (FUN_00BC5A80, dynamic initializer for the global
   * `RResIdSerializer` singleton)
   */
  RResIdSerializer::RResIdSerializer()
    : mDeserialize(&RResIdSerializer::Deserialize)
    , mSerialize(&RResIdSerializer::Serialize)
  {}

  RResIdSerializer::~RResIdSerializer()
  {
    ResetLinks();
  }
} // namespace moho

