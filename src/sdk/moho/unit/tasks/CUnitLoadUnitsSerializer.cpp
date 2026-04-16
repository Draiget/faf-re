#include "moho/unit/tasks/CUnitLoadUnitsSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"

namespace
{
  moho::CUnitLoadUnitsSerializer gCUnitLoadUnitsSerializer;

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

  [[nodiscard]] gpg::RType* CachedCUnitLoadUnitsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitLoadUnits));
    }
    return cached;
  }

  void CleanupCUnitLoadUnitsSerializerAtExit()
  {
    (void)moho::cleanup_CUnitLoadUnitsSerializer();
  }

  /**
   * Address: 0x00627FB0 (FUN_00627FB0)
   *
   * What it does:
   * Wrapper thunk lane that forwards one serializer read callback into
   * `CUnitLoadUnits::MemberDeserialize`.
   */
  [[maybe_unused]] int DeserializeMemberWrapperA(moho::CUnitLoadUnits* const task, gpg::ReadArchive* const archive)
  {
    if (task == nullptr || archive == nullptr) {
      return 0;
    }

    task->MemberDeserialize(archive);
    return 1;
  }

  /**
   * Address: 0x00627FC0 (FUN_00627FC0)
   *
   * What it does:
   * Wrapper thunk lane that forwards one serializer write callback into
   * `CUnitLoadUnits::MemberSerialize`.
   */
  [[maybe_unused]] int SerializeMemberWrapperA(const moho::CUnitLoadUnits* const task, gpg::WriteArchive* const archive)
  {
    if (task == nullptr || archive == nullptr) {
      return 0;
    }

    task->MemberSerialize(archive);
    return 1;
  }

  /**
   * Address: 0x00628720 (FUN_00628720)
   *
   * What it does:
   * Secondary wrapper thunk lane forwarding to `MemberDeserialize`.
   */
  [[maybe_unused]] int DeserializeMemberWrapperB(moho::CUnitLoadUnits* const task, gpg::ReadArchive* const archive)
  {
    return DeserializeMemberWrapperA(task, archive);
  }

  /**
   * Address: 0x00628730 (FUN_00628730)
   *
   * What it does:
   * Secondary wrapper thunk lane forwarding to `MemberSerialize`.
   */
  [[maybe_unused]] int SerializeMemberWrapperB(const moho::CUnitLoadUnits* const task, gpg::WriteArchive* const archive)
  {
    return SerializeMemberWrapperA(task, archive);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00624FF0 (FUN_00624FF0, Moho::CUnitLoadUnitsSerializer::Deserialize)
   */
  void CUnitLoadUnitsSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<CUnitLoadUnits*>(
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
   * Address: 0x00625000 (FUN_00625000, Moho::CUnitLoadUnitsSerializer::Serialize)
   */
  void CUnitLoadUnitsSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<CUnitLoadUnits*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  void CUnitLoadUnitsSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitLoadUnitsType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFA5B0 (FUN_00BFA5B0, cleanup_CUnitLoadUnitsSerializer)
   */
  gpg::SerHelperBase* cleanup_CUnitLoadUnitsSerializer()
  {
    return UnlinkSerializerNode(gCUnitLoadUnitsSerializer);
  }

  /**
   * Address: 0x00625050 (FUN_00625050, cleanup_CUnitLoadUnitsSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the global `CUnitLoadUnitsSerializer`
   * node and restores its self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitLoadUnitsSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCUnitLoadUnitsSerializer);
  }

  /**
   * Address: 0x00625080 (FUN_00625080, cleanup_CUnitLoadUnitsSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the global
   * `CUnitLoadUnitsSerializer` node and restores its self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitLoadUnitsSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCUnitLoadUnitsSerializer);
  }

  /**
   * Address: 0x00BD1CB0 (FUN_00BD1CB0, register_CUnitLoadUnitsSerializer)
   */
  void register_CUnitLoadUnitsSerializer()
  {
    ResetSerializerNode(gCUnitLoadUnitsSerializer);
    gCUnitLoadUnitsSerializer.mDeserialize = &CUnitLoadUnitsSerializer::Deserialize;
    gCUnitLoadUnitsSerializer.mSerialize = &CUnitLoadUnitsSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitLoadUnitsSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitLoadUnitsSerializerBootstrap
  {
    CUnitLoadUnitsSerializerBootstrap()
    {
      moho::register_CUnitLoadUnitsSerializer();
    }
  };

  CUnitLoadUnitsSerializerBootstrap gCUnitLoadUnitsSerializerBootstrap;
} // namespace
