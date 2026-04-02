#include "moho/ai/CAiFormationDBImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationDBImpl.h"

using namespace moho;

namespace
{
  alignas(CAiFormationDBImplSerializer)
  unsigned char gCAiFormationDBImplSerializerStorage[sizeof(CAiFormationDBImplSerializer)] = {};
  bool gCAiFormationDBImplSerializerConstructed = false;

  [[nodiscard]] CAiFormationDBImplSerializer* AcquireCAiFormationDBImplSerializer()
  {
    if (!gCAiFormationDBImplSerializerConstructed) {
      new (gCAiFormationDBImplSerializerStorage) CAiFormationDBImplSerializer();
      gCAiFormationDBImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiFormationDBImplSerializer*>(gCAiFormationDBImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiFormationDBImplType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(CAiFormationDBImpl));
    }
    return sCachedType;
  }

  /**
   * Address: 0x00BF6890 (FUN_00BF6890, cleanup_CAiFormationDBImplSerializer)
   *
   * What it does:
   * Unlinks recovered CAiFormationDBImpl serializer helper node from
   * intrusive serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiFormationDBImplSerializer()
  {
    if (!gCAiFormationDBImplSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiFormationDBImplSerializer());
  }

  void cleanup_CAiFormationDBImplSerializer_atexit()
  {
    (void)cleanup_CAiFormationDBImplSerializer();
  }
} // namespace

/**
 * Address: 0x0059C670 (FUN_0059C670, Moho::CAiFormationDBImplSerializer::Deserialize)
 */
void CAiFormationDBImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const formationDb = reinterpret_cast<CAiFormationDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  formationDb->MemberDeserialize(archive);
}

/**
 * Address: 0x0059C680 (FUN_0059C680, Moho::CAiFormationDBImplSerializer::Serialize)
 */
void CAiFormationDBImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const formationDb = reinterpret_cast<const CAiFormationDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  formationDb->MemberSerialize(archive);
}

/**
 * Address: 0x0059CBA0 (FUN_0059CBA0)
 *
 * What it does:
 * Lazily resolves CAiFormationDBImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationDBImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiFormationDBImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC1D0 (FUN_00BCC1D0, register_CAiFormationDBImplSerializer)
 *
 * What it does:
 * Initializes the global formation-DB serializer helper callbacks and installs
 * process-exit cleanup.
 */
void moho::register_CAiFormationDBImplSerializer()
{
  CAiFormationDBImplSerializer* const serializer = AcquireCAiFormationDBImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiFormationDBImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiFormationDBImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiFormationDBImplSerializer_atexit);
}

namespace
{
  struct CAiFormationDBImplSerializerBootstrap
  {
    CAiFormationDBImplSerializerBootstrap()
    {
      moho::register_CAiFormationDBImplSerializer();
    }
  };

  [[maybe_unused]] CAiFormationDBImplSerializerBootstrap gCAiFormationDBImplSerializerBootstrap;
} // namespace
