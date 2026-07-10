#include "moho/unit/tasks/CUnitMobileBuildTaskSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"

namespace
{
  moho::CUnitMobileBuildTaskSerializer gCUnitMobileBuildTaskSerializer;

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(
    moho::CUnitMobileBuildTaskSerializer& serializer
  ) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(
    moho::CUnitMobileBuildTaskSerializer& serializer
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

  void ResetSerializerNode(moho::CUnitMobileBuildTaskSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext == nullptr || serializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mHelperPrev = self;
      serializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedCUnitMobileBuildTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitMobileBuildTask));
    }
    return cached;
  }

  void CleanupCUnitMobileBuildTaskSerializerAtExit()
  {
    (void)moho::cleanup_CUnitMobileBuildTaskSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F6A10 (FUN_005F6A10, Moho::CUnitMobileBuildTaskSerializer::Deserialize)
   *
   * IDA signature:
   * int __cdecl Deserialize(ReadArchive* archive, void* objectPtr, ...);
   *
   * What it does:
   * Reflection load-callback facade. The binary loads `eax`=archive (arg_0),
   * `ecx`=objectPtr (arg_4) and tail-jumps to the member load body, so the
   * modern form forwards `objectPtr->MemberDeserialize(archive)`.
   */
  void CUnitMobileBuildTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitMobileBuildTask*>(
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
   * Address: 0x005F6A20 (FUN_005F6A20, Moho::CUnitMobileBuildTaskSerializer::Serialize)
   *
   * IDA signature:
   * int __cdecl Serialize(WriteArchive* archive, void* objectPtr, ...);
   *
   * What it does:
   * Reflection save-callback facade. The binary loads `eax`=objectPtr (arg_4),
   * `esi`=archive (arg_0) and calls the member save body, so the modern form
   * forwards `objectPtr->MemberSerialize(archive)`.
   */
  void CUnitMobileBuildTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitMobileBuildTask*>(
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
   * What it does:
   * Lazily resolves the `CUnitMobileBuildTask` reflected type and installs this
   * helper's load/save callbacks into its type descriptor.
   */
  void CUnitMobileBuildTaskSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitMobileBuildTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF9330 (FUN_00BF9330, cleanup_CUnitMobileBuildTaskSerializer)
   */
  gpg::SerHelperBase* cleanup_CUnitMobileBuildTaskSerializer()
  {
    return UnlinkSerializerNode(gCUnitMobileBuildTaskSerializer);
  }

  /**
   * Address: 0x00BCF890 (FUN_00BCF890, register_CUnitMobileBuildTaskSerializer)
   */
  void register_CUnitMobileBuildTaskSerializer()
  {
    ResetSerializerNode(gCUnitMobileBuildTaskSerializer);
    gCUnitMobileBuildTaskSerializer.mDeserialize = &CUnitMobileBuildTaskSerializer::Deserialize;
    gCUnitMobileBuildTaskSerializer.mSerialize = &CUnitMobileBuildTaskSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitMobileBuildTaskSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitMobileBuildTaskSerializerBootstrap
  {
    CUnitMobileBuildTaskSerializerBootstrap()
    {
      moho::register_CUnitMobileBuildTaskSerializer();
    }
  };

  CUnitMobileBuildTaskSerializerBootstrap gCUnitMobileBuildTaskSerializerBootstrap;
} // namespace
