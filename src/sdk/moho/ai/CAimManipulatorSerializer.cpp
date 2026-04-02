#include "moho/ai/CAimManipulatorSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAimManipulator.h"

namespace
{
  alignas(moho::CAimManipulatorSerializer) unsigned char gCAimManipulatorSerializerStorage[sizeof(moho::CAimManipulatorSerializer)] = {};
  bool gCAimManipulatorSerializerConstructed = false;

  [[nodiscard]] moho::CAimManipulatorSerializer* AcquireCAimManipulatorSerializer()
  {
    if (!gCAimManipulatorSerializerConstructed) {
      new (gCAimManipulatorSerializerStorage) moho::CAimManipulatorSerializer();
      gCAimManipulatorSerializerConstructed = true;
    }

    return reinterpret_cast<moho::CAimManipulatorSerializer*>(gCAimManipulatorSerializerStorage);
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
  void UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedCAimManipulatorType()
  {
    gpg::RType* type = moho::CAimManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAimManipulator));
      moho::CAimManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BFA960 (FUN_00BFA960, cleanup_CAimManipulatorSerializer)
   *
   * What it does:
   * Unlinks static serializer helper storage for `CAimManipulator`.
   */
  void cleanup_CAimManipulatorSerializer()
  {
    if (!gCAimManipulatorSerializerConstructed) {
      return;
    }

    moho::CAimManipulatorSerializer* const serializer = AcquireCAimManipulatorSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~CAimManipulatorSerializer();
    gCAimManipulatorSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00630030 (FUN_00630030, Moho::CAimManipulatorSerializer::Deserialize)
   */
  void CAimManipulatorSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CAimManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    if (!archive || !object) {
      return;
    }

    CAimManipulator::MemberDeserialize(object, archive);
  }

  /**
   * Address: 0x00630040 (FUN_00630040, Moho::CAimManipulatorSerializer::Serialize)
   */
  void CAimManipulatorSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<const CAimManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    if (!archive || !object) {
      return;
    }

    CAimManipulator::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00632D80 (FUN_00632D80)
   *
   * What it does:
   * Lazily resolves CAimManipulator RTTI and installs load/save callbacks from
   * this helper object into the type descriptor.
   */
  void CAimManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCAimManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD2290 (FUN_00BD2290, register_CAimManipulatorSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `CAimManipulator` and installs
   * process-exit cleanup.
   */
  void register_CAimManipulatorSerializer()
  {
    CAimManipulatorSerializer* const serializer = AcquireCAimManipulatorSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &CAimManipulatorSerializer::Deserialize;
    serializer->mSerialize = &CAimManipulatorSerializer::Serialize;
    serializer->RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_CAimManipulatorSerializer);
  }
} // namespace moho
