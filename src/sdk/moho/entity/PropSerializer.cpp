#include "moho/entity/PropSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Prop.h"

namespace
{
  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializerType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006F9BE0 (FUN_006F9BE0, Moho::SPropPriorityInfoSerializer::Deserialize)
   */
  void SPropPriorityInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<SPropPriorityInfo*>(objectPtr);
    if (archive == nullptr || info == nullptr) {
      return;
    }

    archive->ReadInt(&info->mPriority);
    archive->ReadInt(&info->mBoundedTick);
  }

  /**
   * Address: 0x006F9C10 (FUN_006F9C10, Moho::SPropPriorityInfoSerializer::Serialize)
   */
  void SPropPriorityInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const info = reinterpret_cast<const SPropPriorityInfo*>(objectPtr);
    if (archive == nullptr || info == nullptr) {
      return;
    }

    archive->WriteInt(info->mPriority);
    archive->WriteInt(info->mBoundedTick);
  }

  /**
   * Address: 0x00BD9840 (FUN_00BD9840, dynamic initializer for the global
   * `SPropPriorityInfoSerializer` singleton)
   */
  SPropPriorityInfoSerializer::SPropPriorityInfoSerializer()
    : mDeserialize(&SPropPriorityInfoSerializer::Deserialize)
    , mSerialize(&SPropPriorityInfoSerializer::Serialize)
  {}

  SPropPriorityInfoSerializer::~SPropPriorityInfoSerializer() = default;

  /**
   * Address: 0x006FA8C0 (FUN_006FA8C0, gpg::SerSaveLoadHelper_SPropPriorityInfo::Init)
   */
  void SPropPriorityInfoSerializer::Init()
  {
    gpg::RType* const type = ResolveSerializerType<SPropPriorityInfo>(SPropPriorityInfo::sType);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

} // namespace moho

namespace
{
  moho::SPropPriorityInfoSerializer gSPropPriorityInfoSerializer;
} // namespace
