#include "moho/sim/SMassInfoSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/SMassInfo.h"

using namespace moho;

namespace
{
  alignas(SMassInfoSerializer) unsigned char gSMassInfoSerializerStorage[sizeof(SMassInfoSerializer)] = {};
  bool gSMassInfoSerializerConstructed = false;

  [[nodiscard]] SMassInfoSerializer* AcquireSMassInfoSerializer()
  {
    if (!gSMassInfoSerializerConstructed) {
      new (gSMassInfoSerializerStorage) SMassInfoSerializer();
      gSMassInfoSerializerConstructed = true;
    }

    return reinterpret_cast<SMassInfoSerializer*>(gSMassInfoSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedSMassInfoType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(SMassInfo));
    }
    return sCachedType;
  }

  /**
   * Address: 0x00BF64C0 (FUN_00BF64C0, cleanup_SMassInfoSerializer)
   *
   * What it does:
   * Unlinks recovered SMassInfo serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_SMassInfoSerializer()
  {
    if (!gSMassInfoSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireSMassInfoSerializer());
  }

  /**
   * Address: 0x00585E70 (FUN_00585E70)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * SMassInfo serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SMassInfoSerializerStartupThunkA()
  {
    return cleanup_SMassInfoSerializer();
  }

  /**
   * Address: 0x00585EA0 (FUN_00585EA0)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * SMassInfo serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SMassInfoSerializerStartupThunkB()
  {
    return cleanup_SMassInfoSerializer();
  }

  void cleanup_SMassInfoSerializer_atexit()
  {
    (void)cleanup_SMassInfoSerializer();
  }
} // namespace

/**
 * Address: 0x00585E10 (FUN_00585E10, Moho::SMassInfoSerializer::Deserialize)
 */
void SMassInfoSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const info = reinterpret_cast<SMassInfo*>(static_cast<std::uintptr_t>(objectPtr));
  info->MemberDeserialize(archive);
}

/**
 * Address: 0x00585E20 (FUN_00585E20, Moho::SMassInfoSerializer::Serialize)
 */
void SMassInfoSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const info = reinterpret_cast<const SMassInfo*>(static_cast<std::uintptr_t>(objectPtr));
  info->MemberSerialize(archive);
}

/**
 * Address: 0x00591B90 (FUN_00591B90)
 *
 * What it does:
 * Lazily resolves SMassInfo RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void SMassInfoSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSMassInfoType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCB700 (FUN_00BCB700, register_SMassInfoSerializer)
 *
 * What it does:
 * Initializes the global SMassInfo serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_SMassInfoSerializer()
{
  SMassInfoSerializer* const serializer = AcquireSMassInfoSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &SMassInfoSerializer::Deserialize;
  serializer->mSaveCallback = &SMassInfoSerializer::Serialize;
  (void)std::atexit(&cleanup_SMassInfoSerializer_atexit);
}

namespace
{
  struct SMassInfoSerializerBootstrap
  {
    SMassInfoSerializerBootstrap()
    {
      moho::register_SMassInfoSerializer();
    }
  };

  [[maybe_unused]] SMassInfoSerializerBootstrap gSMassInfoSerializerBootstrap;
} // namespace
