#include "moho/unit/tasks/CAcquireTargetTaskSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"

namespace
{
  using Serializer = moho::CAcquireTargetTaskSerializer;

  alignas(Serializer) unsigned char gCAcquireTargetTaskSerializerStorage[sizeof(Serializer)];
  bool gCAcquireTargetTaskSerializerConstructed = false;

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  /**
   * Address: 0x005D98D0 (FUN_005D98D0)
   *
   * What it does:
   * Splices this serializer helper node out of its intrusive lane when linked,
   * then resets helper links to self and returns the self node pointer.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkAcquireTargetTaskSerializerHelperNodeVariantA(
    Serializer& serializer
  ) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
    return SerializerSelfNode(serializer);
  }

  /**
   * Address: 0x005D9900 (FUN_005D9900)
   *
   * What it does:
   * Secondary helper-node unlink/reset variant that preserves the same
   * intrusive unlink semantics and returns the helper self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkAcquireTargetTaskSerializerHelperNodeVariantB(
    Serializer& serializer
  ) noexcept
  {
    return UnlinkAcquireTargetTaskSerializerHelperNodeVariantA(serializer);
  }

  [[nodiscard]] Serializer* AcquireSerializer()
  {
    if (!gCAcquireTargetTaskSerializerConstructed) {
      new (gCAcquireTargetTaskSerializerStorage) Serializer();
      gCAcquireTargetTaskSerializerConstructed = true;
    }

    return reinterpret_cast<Serializer*>(gCAcquireTargetTaskSerializerStorage);
  }

  void cleanup_CAcquireTargetTaskSerializer()
  {
    if (!gCAcquireTargetTaskSerializerConstructed) {
      return;
    }

    Serializer& serializer = *AcquireSerializer();
    (void)UnlinkAcquireTargetTaskSerializerHelperNodeVariantA(serializer);
    serializer.~CAcquireTargetTaskSerializer();
    gCAcquireTargetTaskSerializerConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCAcquireTargetTaskType()
  {
    gpg::RType* type = moho::CAcquireTargetTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAcquireTargetTask));
      moho::CAcquireTargetTask::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005DC190 (FUN_005DC190)
 *
 * What it does:
 * Lazily resolves `CAcquireTargetTask` RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void moho::CAcquireTargetTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAcquireTargetTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mDeserialize;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x00BCE930 (FUN_00BCE930, register_CAcquireTargetTaskSerializer)
 *
 * What it does:
 * Constructs the global serializer owner and installs process-exit cleanup.
 */
int moho::register_CAcquireTargetTaskSerializer()
{
  Serializer* const serializer = AcquireSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&moho::CAcquireTargetTask::MemberDeserialize);
  serializer->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&moho::CAcquireTargetTask::MemberSerialize);
  return std::atexit(&cleanup_CAcquireTargetTaskSerializer);
}
