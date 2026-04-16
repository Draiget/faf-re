#include "moho/ai/CAiTargetSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTarget.h"

using namespace moho;

namespace
{
  alignas(CAiTargetSerializer) unsigned char gCAiTargetSerializerStorage[sizeof(CAiTargetSerializer)];
  bool gCAiTargetSerializerConstructed = false;

  [[nodiscard]] CAiTargetSerializer* AcquireCAiTargetSerializer()
  {
    if (!gCAiTargetSerializerConstructed) {
      new (gCAiTargetSerializerStorage) CAiTargetSerializer();
      gCAiTargetSerializerConstructed = true;
    }

    return reinterpret_cast<CAiTargetSerializer*>(gCAiTargetSerializerStorage);
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
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
    return self;
  }

  /**
   * Address: 0x005E2E60 (FUN_005E2E60)
   *
   * What it does:
   * Unlinks the global `CAiTargetSerializer` helper node from the intrusive
   * serializer chain and restores it to a self-linked node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiTargetSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(*AcquireCAiTargetSerializer());
  }

  /**
   * Address: 0x005E2E90 (FUN_005E2E90)
   *
   * What it does:
   * Secondary unlink/reset thunk for the global `CAiTargetSerializer` helper
   * node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiTargetSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(*AcquireCAiTargetSerializer());
  }

  void cleanup_CAiTargetSerializer()
  {
    if (!gCAiTargetSerializerConstructed) {
      return;
    }

    CAiTargetSerializer* const serializer = AcquireCAiTargetSerializer();
    (void)cleanup_CAiTargetSerializerStartupThunkA();
    serializer->~CAiTargetSerializer();
    gCAiTargetSerializerConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTarget));
      CAiTarget::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E3540 (FUN_005E3540)
 *
 * What it does:
 * Lazily resolves CAiTarget RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiTargetSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiTargetType();
  const gpg::RType::load_func_t loadCallback = mLoadCallback ? mLoadCallback : &CAiTarget::DeserializeFromArchive;
  const gpg::RType::save_func_t saveCallback = mSaveCallback ? mSaveCallback : &CAiTarget::SerializeToArchive;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = loadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = saveCallback;
}

/**
 * Address: 0x00BCEC50 (FUN_00BCEC50, register_CAiTargetSerializer)
 *
 * What it does:
 * Registers `CAiTarget` serializer callbacks and installs process-exit
 * cleanup.
 */
int moho::register_CAiTargetSerializer()
{
  CAiTargetSerializer* const serializer = AcquireCAiTargetSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiTarget::DeserializeFromArchive;
  serializer->mSaveCallback = &CAiTarget::SerializeToArchive;
  return std::atexit(&cleanup_CAiTargetSerializer);
}
