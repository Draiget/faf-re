#include "moho/ai/CAiPathFinderSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  alignas(CAiPathFinderSerializer) unsigned char gCAiPathFinderSerializerStorage[sizeof(CAiPathFinderSerializer)] = {};
  bool gCAiPathFinderSerializerConstructed = false;

  [[nodiscard]] CAiPathFinderSerializer* AcquireCAiPathFinderSerializer()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      new (gCAiPathFinderSerializerStorage) CAiPathFinderSerializer();
      gCAiPathFinderSerializerConstructed = true;
    }

    return reinterpret_cast<CAiPathFinderSerializer*>(gCAiPathFinderSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    gpg::RType* type = CAiPathFinder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathFinder));
      CAiPathFinder::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7240 (FUN_00BF7240, cleanup_CAiPathFinderSerializer)
   *
   * What it does:
   * Unlinks the global path-finder serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiPathFinderSerializer()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathFinderSerializer());
  }

  void cleanup_CAiPathFinderSerializer_atexit()
  {
    (void)cleanup_CAiPathFinderSerializer();
  }
} // namespace

/**
 * Address: 0x005AAC30 (FUN_005AAC30, Moho::CAiPathFinderSerializer::Deserialize)
 */
void CAiPathFinderSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberDeserialize(archive, version);
}

/**
 * Address: 0x005AAC40 (FUN_005AAC40, Moho::CAiPathFinderSerializer::Serialize)
 */
void CAiPathFinderSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberSerialize(archive, version);
}

/**
 * Address: 0x005AB210 (FUN_005AB210)
 *
 * What it does:
 * Lazily resolves CAiPathFinder RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathFinderSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiPathFinderType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCCD70 (FUN_00BCCD70, register_CAiPathFinderSerializer)
 *
 * What it does:
 * Initializes the global path-finder serializer helper callbacks and installs
 * process-exit cleanup.
 */
int moho::register_CAiPathFinderSerializer()
{
  CAiPathFinderSerializer* const serializer = AcquireCAiPathFinderSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiPathFinderSerializer::Deserialize;
  serializer->mSaveCallback = &CAiPathFinderSerializer::Serialize;
  return std::atexit(&cleanup_CAiPathFinderSerializer_atexit);
}

namespace
{
  struct CAiPathFinderSerializerBootstrap
  {
    CAiPathFinderSerializerBootstrap()
    {
      (void)moho::register_CAiPathFinderSerializer();
    }
  };

  [[maybe_unused]] CAiPathFinderSerializerBootstrap gCAiPathFinderSerializerBootstrap;
} // namespace
