#include "moho/script/CUnitScriptTaskSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/script/CUnitScriptTask.h"

namespace
{
  moho::CUnitScriptTaskSerializer gCUnitScriptTaskSerializer;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
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

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext == nullptr || serializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mHelperPrev = self;
      serializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    gpg::RType* type = moho::CUnitScriptTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitScriptTask));
      moho::CUnitScriptTask::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00623B80 (FUN_00623B80)
   */
  void InitializeCUnitScriptTaskSerializer()
  {
    ResetSerializerNode(gCUnitScriptTaskSerializer);
    gCUnitScriptTaskSerializer.mLoadCallback = &moho::CUnitScriptTaskSerializer::Deserialize;
    gCUnitScriptTaskSerializer.mSaveCallback = &moho::CUnitScriptTaskSerializer::Serialize;
  }

  void CleanupCUnitScriptTaskSerializerAtExit()
  {
    (void)moho::cleanup_CUnitScriptTaskSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00622EA0 (FUN_00622EA0, Moho::CUnitScriptTaskSerializer::Deserialize)
   */
  void CUnitScriptTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    CUnitScriptTask::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitScriptTask*>(static_cast<std::uintptr_t>(objectPtr)),
      version
    );
  }

  /**
   * Address: 0x00622EC0 (FUN_00622EC0, Moho::CUnitScriptTaskSerializer::Serialize)
   */
  void CUnitScriptTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    CUnitScriptTask::MemberSerialize(
      reinterpret_cast<CUnitScriptTask*>(static_cast<std::uintptr_t>(objectPtr)),
      archive,
      version
    );
  }

  /**
   * Address: 0x00623BB0 (FUN_00623BB0)
   */
  void CUnitScriptTaskSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitScriptTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BFA470 (FUN_00BFA470)
   */
  gpg::SerHelperBase* cleanup_CUnitScriptTaskSerializer()
  {
    return UnlinkSerializerNode(gCUnitScriptTaskSerializer);
  }

  /**
   * Address: 0x00622F10 (FUN_00622F10, cleanup_CUnitScriptTaskSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the global `CUnitScriptTaskSerializer`
   * node and restores its self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitScriptTaskSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCUnitScriptTaskSerializer);
  }

  /**
   * Address: 0x00622F40 (FUN_00622F40, cleanup_CUnitScriptTaskSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the global
   * `CUnitScriptTaskSerializer` node and restores its self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitScriptTaskSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCUnitScriptTaskSerializer);
  }

  /**
   * Address: 0x00BD19A0 (FUN_00BD19A0)
   */
  void register_CUnitScriptTaskSerializer()
  {
    InitializeCUnitScriptTaskSerializer();
    (void)std::atexit(&CleanupCUnitScriptTaskSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitScriptTaskSerializerBootstrap
  {
    CUnitScriptTaskSerializerBootstrap()
    {
      moho::register_CUnitScriptTaskSerializer();
    }
  };

  CUnitScriptTaskSerializerBootstrap gCUnitScriptTaskSerializerBootstrap;
} // namespace
