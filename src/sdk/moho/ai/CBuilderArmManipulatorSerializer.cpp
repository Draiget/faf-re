#include "moho/ai/CBuilderArmManipulatorSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CBuilderArmManipulator.h"

namespace
{
  alignas(moho::CBuilderArmManipulatorSerializer
  ) unsigned char gCBuilderArmManipulatorSerializerStorage[sizeof(moho::CBuilderArmManipulatorSerializer)] = {};
  bool gCBuilderArmManipulatorSerializerConstructed = false;

  [[nodiscard]] moho::CBuilderArmManipulatorSerializer* AcquireCBuilderArmManipulatorSerializer()
  {
    if (!gCBuilderArmManipulatorSerializerConstructed) {
      new (gCBuilderArmManipulatorSerializerStorage) moho::CBuilderArmManipulatorSerializer();
      gCBuilderArmManipulatorSerializerConstructed = true;
    }

    return reinterpret_cast<moho::CBuilderArmManipulatorSerializer*>(gCBuilderArmManipulatorSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCBuilderArmManipulatorType()
  {
    gpg::RType* type = moho::CBuilderArmManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CBuilderArmManipulator));
      moho::CBuilderArmManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00635B20 (FUN_00635B20)
   *
   * What it does:
   * Constructs the process-global `CBuilderArmManipulatorSerializer` helper,
   * points its load/save lanes at the two reflection adapters, and returns the
   * helper so the caller can splice it into the pending-helper list.
   */
  [[nodiscard]] moho::CBuilderArmManipulatorSerializer* InitializeCBuilderArmManipulatorSerializerStartupThunk()
  {
    moho::CBuilderArmManipulatorSerializer* const serializer = AcquireCBuilderArmManipulatorSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &moho::CBuilderArmManipulatorSerializer::Deserialize;
    serializer->mSerialize = &moho::CBuilderArmManipulatorSerializer::Serialize;
    return serializer;
  }

  /**
   * Address: 0x00635B50 (FUN_00635B50, cleanup_CBuilderArmManipulatorSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the `CBuilderArmManipulator`
   * serializer node and restores self-links.
   */
  gpg::SerHelperBase* cleanup_CBuilderArmManipulatorSerializerStartupThunkA()
  {
    moho::CBuilderArmManipulatorSerializer* const serializer = AcquireCBuilderArmManipulatorSerializer();
    UnlinkSerializerNode(*serializer);
    return SerializerSelfNode(*serializer);
  }

  /**
   * Address: 0x00635B80 (FUN_00635B80, cleanup_CBuilderArmManipulatorSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the `CBuilderArmManipulator`
   * serializer node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CBuilderArmManipulatorSerializerStartupThunkB()
  {
    moho::CBuilderArmManipulatorSerializer* const serializer = AcquireCBuilderArmManipulatorSerializer();
    UnlinkSerializerNode(*serializer);
    return SerializerSelfNode(*serializer);
  }

  /**
   * Address: 0x00BFAAC0 (FUN_00BFAAC0, cleanup_CBuilderArmManipulatorSerializer)
   *
   * What it does:
   * Unlinks static serializer helper storage for `CBuilderArmManipulator`.
   */
  void cleanup_CBuilderArmManipulatorSerializer()
  {
    if (!gCBuilderArmManipulatorSerializerConstructed) {
      return;
    }

    moho::CBuilderArmManipulatorSerializer* const serializer = AcquireCBuilderArmManipulatorSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~CBuilderArmManipulatorSerializer();
    gCBuilderArmManipulatorSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00635AF0 (FUN_00635AF0, Moho::CBuilderArmManipulatorSerializer::Deserialize)
   */
  void CBuilderArmManipulatorSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<CBuilderArmManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CBuilderArmManipulator::MemberDeserialize(object, archive);
  }

  /**
   * Address: 0x00635B00 (FUN_00635B00, Moho::CBuilderArmManipulatorSerializer::Serialize)
   */
  void CBuilderArmManipulatorSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<const CBuilderArmManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CBuilderArmManipulator::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00636F80 (FUN_00636F80)
   * Slot: 0
   *
   * What it does:
   * Lazily resolves `CBuilderArmManipulator` RTTI and installs this helper's
   * load/save callbacks into the type descriptor.
   */
  void CBuilderArmManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCBuilderArmManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD25B0 (FUN_00BD25B0, register_CBuilderArmManipulatorSerializer)
   *
   * What it does:
   * Initializes the global `CBuilderArmManipulator` serializer helper
   * callbacks and installs process-exit cleanup.
   */
  void register_CBuilderArmManipulatorSerializer()
  {
    (void)InitializeCBuilderArmManipulatorSerializerStartupThunk();
    (void)std::atexit(&cleanup_CBuilderArmManipulatorSerializer);
  }
} // namespace moho

namespace
{
  // The binary runs `register_CBuilderArmManipulatorSerializer` from the CRT
  // static-initializer array; a file-scope bootstrap object reproduces that.
  struct CBuilderArmManipulatorSerializerStartupBootstrap
  {
    CBuilderArmManipulatorSerializerStartupBootstrap()
    {
      moho::register_CBuilderArmManipulatorSerializer();
    }
  };

  [[maybe_unused]] CBuilderArmManipulatorSerializerStartupBootstrap gCBuilderArmManipulatorSerializerStartupBootstrap;
} // namespace
