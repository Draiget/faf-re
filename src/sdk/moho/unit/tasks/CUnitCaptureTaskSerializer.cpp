#include "moho/unit/tasks/CUnitCaptureTaskSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"

namespace
{
  moho::CUnitCaptureTaskSerializer gCUnitCaptureTaskSerializer;

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(
    moho::CUnitCaptureTaskSerializer& serializer
  ) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(
    moho::CUnitCaptureTaskSerializer& serializer
  ) noexcept
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

  void ResetSerializerNode(moho::CUnitCaptureTaskSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext == nullptr || serializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mHelperPrev = self;
      serializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedCUnitCaptureTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCaptureTask));
    }
    return cached;
  }

  void CleanupCUnitCaptureTaskSerializerAtExit()
  {
    (void)moho::cleanup_CUnitCaptureTaskSerializer();
  }

  /**
   * Address: 0x00604330 (FUN_00604330, mirrored intrusive-unlink helper lane)
   *
   * What it does:
   * Mirrored helper-node unlink lane that performs the same
   * intrusive-list unlink/self-link sequence as the primary cleanup.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitCaptureTaskSerializerNodeSecondary()
  {
    return UnlinkSerializerNode(gCUnitCaptureTaskSerializer);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006042B0 (FUN_006042B0, Moho::CUnitCaptureTaskSerializer::Deserialize)
   */
  void CUnitCaptureTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitCaptureTask*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006042C0 (FUN_006042C0, Moho::CUnitCaptureTaskSerializer::Serialize)
   */
  void CUnitCaptureTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitCaptureTask*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00605320 (FUN_00605320, Moho::CUnitCaptureTaskSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Lazily resolves the `CUnitCaptureTask` reflected type and installs
   * this helper's load/save callbacks into its type descriptor.
   */
  void CUnitCaptureTaskSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitCaptureTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00604300 (FUN_00604300, cleanup_CUnitCaptureTaskSerializer)
   */
  gpg::SerHelperBase* cleanup_CUnitCaptureTaskSerializer()
  {
    return UnlinkSerializerNode(gCUnitCaptureTaskSerializer);
  }

  /**
   * Address: 0x00BCFFD0 (FUN_00BCFFD0, register_CUnitCaptureTaskSerializer)
   */
  void register_CUnitCaptureTaskSerializer()
  {
    ResetSerializerNode(gCUnitCaptureTaskSerializer);
    gCUnitCaptureTaskSerializer.mDeserialize = &CUnitCaptureTaskSerializer::Deserialize;
    gCUnitCaptureTaskSerializer.mSerialize = &CUnitCaptureTaskSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitCaptureTaskSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitCaptureTaskSerializerBootstrap
  {
    CUnitCaptureTaskSerializerBootstrap()
    {
      moho::register_CUnitCaptureTaskSerializer();
    }
  };

  CUnitCaptureTaskSerializerBootstrap gCUnitCaptureTaskSerializerBootstrap;
} // namespace
