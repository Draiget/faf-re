#include "moho/ai/ESiloTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::ESiloTypeTypeInfo) unsigned char gESiloTypeTypeInfoStorage[sizeof(moho::ESiloTypeTypeInfo)]{};
  bool gESiloTypeTypeInfoConstructed = false;
  bool gESiloTypeTypeInfoPreregistered = false;

  alignas(moho::ESiloTypePrimitiveSerializer)
    unsigned char gESiloTypePrimitiveSerializerStorage[sizeof(moho::ESiloTypePrimitiveSerializer)]{};
  bool gESiloTypePrimitiveSerializerConstructed = false;

  [[nodiscard]] moho::ESiloTypeTypeInfo* AcquireESiloTypeTypeInfo()
  {
    if (!gESiloTypeTypeInfoConstructed) {
      new (gESiloTypeTypeInfoStorage) moho::ESiloTypeTypeInfo();
      gESiloTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ESiloTypeTypeInfo*>(gESiloTypeTypeInfoStorage);
  }

  [[nodiscard]] moho::ESiloTypePrimitiveSerializer* AcquireESiloTypePrimitiveSerializer()
  {
    if (!gESiloTypePrimitiveSerializerConstructed) {
      new (gESiloTypePrimitiveSerializerStorage) moho::ESiloTypePrimitiveSerializer();
      gESiloTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::ESiloTypePrimitiveSerializer*>(gESiloTypePrimitiveSerializerStorage);
  }

  [[nodiscard]] gpg::RType* ResolveESiloType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ESiloType));
    }
    return cached;
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

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  /**
   * Address: 0x00BF1FD0 (FUN_00BF1FD0, cleanup_ESiloTypeTypeInfo)
   */
  void cleanup_ESiloTypeTypeInfo()
  {
    if (!gESiloTypeTypeInfoConstructed) {
      return;
    }

    AcquireESiloTypeTypeInfo()->~ESiloTypeTypeInfo();
    gESiloTypeTypeInfoConstructed = false;
    gESiloTypeTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BF1FE0 (FUN_00BF1FE0, cleanup_ESiloTypePrimitiveSerializer)
   */
  void cleanup_ESiloTypePrimitiveSerializer()
  {
    if (!gESiloTypePrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireESiloTypePrimitiveSerializer());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF1FD0 (FUN_00BF1FD0, Moho::ESiloTypeTypeInfo::dtr)
   */
  ESiloTypeTypeInfo::~ESiloTypeTypeInfo() = default;

  /**
   * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
   */
  const char* ESiloTypeTypeInfo::GetName() const
  {
    return "ESiloType";
  }

  /**
   * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
   */
  void ESiloTypeTypeInfo::Init()
  {
    size_ = sizeof(ESiloType);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0050AA70 (FUN_0050AA70, PrimitiveSerHelper<ESiloType>::Deserialize)
   */
  void ESiloTypePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<ESiloType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ESiloType>(value);
  }

  /**
   * Address: 0x0050AA90 (FUN_0050AA90, PrimitiveSerHelper<ESiloType>::Serialize)
   */
  void ESiloTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const ESiloType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050A810 (FUN_0050A810, gpg::PrimitiveSerHelper<Moho::ESiloType,int>::Init)
   */
  void ESiloTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveESiloType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   */
  gpg::REnumType* preregister_ESiloTypeTypeInfo()
  {
    auto* const typeInfo = AcquireESiloTypeTypeInfo();
    if (!gESiloTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ESiloType), typeInfo);
      gESiloTypeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   */
  int register_ESiloTypeTypeInfo()
  {
    (void)preregister_ESiloTypeTypeInfo();
    return std::atexit(&cleanup_ESiloTypeTypeInfo);
  }

  /**
   * Address: 0x00BC7B50 (FUN_00BC7B50, register_ESiloTypePrimitiveSerializer)
   */
  int register_ESiloTypePrimitiveSerializer()
  {
    auto* const serializer = AcquireESiloTypePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &ESiloTypePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &ESiloTypePrimitiveSerializer::Serialize;

    return std::atexit(&cleanup_ESiloTypePrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct ESiloTypeTypeInfoBootstrap
  {
    ESiloTypeTypeInfoBootstrap()
    {
      (void)moho::register_ESiloTypeTypeInfo();
      (void)moho::register_ESiloTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] ESiloTypeTypeInfoBootstrap gESiloTypeTypeInfoBootstrap;
} // namespace
