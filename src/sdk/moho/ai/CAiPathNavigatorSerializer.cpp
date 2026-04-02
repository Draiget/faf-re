#include "moho/ai/CAiPathNavigatorSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

namespace
{
  alignas(CAiPathNavigatorSerializer) unsigned char gCAiPathNavigatorSerializerStorage[sizeof(CAiPathNavigatorSerializer)];
  bool gCAiPathNavigatorSerializerConstructed = false;

  [[nodiscard]] CAiPathNavigatorSerializer* AcquireCAiPathNavigatorSerializer()
  {
    if (!gCAiPathNavigatorSerializerConstructed) {
      new (gCAiPathNavigatorSerializerStorage) CAiPathNavigatorSerializer();
      gCAiPathNavigatorSerializerConstructed = true;
    }

    return reinterpret_cast<CAiPathNavigatorSerializer*>(gCAiPathNavigatorSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    gpg::RType* type = CAiPathNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathNavigator));
      CAiPathNavigator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF73C0 (FUN_00BF73C0, cleanup_CAiPathNavigatorSerializer)
   *
   * What it does:
   * Unlinks the static serializer helper node from the intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiPathNavigatorSerializer()
  {
    if (!gCAiPathNavigatorSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathNavigatorSerializer());
  }

  void CleanupCAiPathNavigatorSerializerAtexit()
  {
    (void)cleanup_CAiPathNavigatorSerializer();
  }
} // namespace

/**
 * Address: 0x005AFBE0 (FUN_005AFBE0, Moho::CAiPathNavigatorSerializer::Deserialize)
 */
void CAiPathNavigatorSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const)
{
  auto* const navigator = reinterpret_cast<CAiPathNavigator*>(static_cast<std::uintptr_t>(objectPtr));
  navigator->MemberDeserialize(archive, version);
}

/**
 * Address: 0x005AFC00 (FUN_005AFC00, Moho::CAiPathNavigatorSerializer::Serialize)
 */
void CAiPathNavigatorSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const)
{
  auto* const navigator = reinterpret_cast<CAiPathNavigator*>(static_cast<std::uintptr_t>(objectPtr));
  navigator->MemberSerialize(archive, version);
}

/**
 * Address: 0x005B0130 (FUN_005B0130)
 *
 * What it does:
 * Lazily resolves CAiPathNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathNavigatorSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiPathNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCD040 (FUN_00BCD040, register_CAiPathNavigatorSerializer)
 *
 * What it does:
 * Initializes the global path navigator serializer helper callbacks and
 * installs process-exit cleanup.
 */
int moho::register_CAiPathNavigatorSerializer()
{
  CAiPathNavigatorSerializer* const serializer = AcquireCAiPathNavigatorSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiPathNavigatorSerializer::Deserialize;
  serializer->mSaveCallback = &CAiPathNavigatorSerializer::Serialize;
  return std::atexit(&CleanupCAiPathNavigatorSerializerAtexit);
}

namespace
{
  struct CAiPathNavigatorSerializerBootstrap
  {
    CAiPathNavigatorSerializerBootstrap()
    {
      (void)moho::register_CAiPathNavigatorSerializer();
    }
  };

  [[maybe_unused]] CAiPathNavigatorSerializerBootstrap gCAiPathNavigatorSerializerBootstrap;
} // namespace
