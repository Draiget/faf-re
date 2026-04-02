#include "moho/serialization/PrefetchHandleBaseSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  /**
   * Address: 0x004ABD20 (FUN_004ABD20, nullsub_694)
   */
  void nullsub_694() {}

  /**
   * Address: 0x004ABD30 (FUN_004ABD30, Moho::PrefetchHandleBaseSerializer::Deserialize)
   */
  void PrefetchHandleBaseSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const handle = reinterpret_cast<PrefetchHandleBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(handle != nullptr);
    if (!archive || !handle) {
      return;
    }

    handle->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004ABD40 (FUN_004ABD40)
   */
  void PrefetchHandleBaseSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const handle = reinterpret_cast<PrefetchHandleBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(handle != nullptr);
    if (!archive || !handle) {
      return;
    }

    GPG_ASSERT(handle->mPtr.get() != nullptr && handle->mPtr->mRequest != nullptr);
    if (!handle->mPtr || handle->mPtr->mRequest == nullptr) {
      msvc8::string emptyPath{};
      archive->WriteString(&emptyPath);
      archive->WriteRefCounts(nullptr);
      return;
    }

    archive->WriteString(&handle->mPtr->mRequest->mResourceId.name);
    archive->WriteRefCounts(handle->mPtr->mRequest->mResourceType);
  }

  /**
   * Address: 0x004ACCF0 (FUN_004ACCF0)
   */
  void PrefetchHandleBaseSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = PrefetchHandleBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(PrefetchHandleBase));
      PrefetchHandleBase::sType = type;
    }
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
