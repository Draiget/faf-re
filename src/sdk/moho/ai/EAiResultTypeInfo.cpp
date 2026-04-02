#include "moho/ai/EAiResultTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include "moho/ai/EAiResult.h"

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

using namespace moho;

namespace
{
  class EAiResultPrimitiveSerializer
  {
  public:
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(EAiResultPrimitiveSerializer, mNext) == 0x04, "EAiResultPrimitiveSerializer::mNext offset must be 0x04");
  static_assert(offsetof(EAiResultPrimitiveSerializer, mPrev) == 0x08, "EAiResultPrimitiveSerializer::mPrev offset must be 0x08");
  static_assert(
    offsetof(EAiResultPrimitiveSerializer, mDeserialize) == 0x0C,
    "EAiResultPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiResultPrimitiveSerializer, mSerialize) == 0x10,
    "EAiResultPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EAiResultPrimitiveSerializer) == 0x14, "EAiResultPrimitiveSerializer size must be 0x14");

  alignas(moho::EAiResultTypeInfo) unsigned char gEAiResultTypeInfoStorage[sizeof(moho::EAiResultTypeInfo)]{};
  bool gEAiResultTypeInfoConstructed = false;
  EAiResultPrimitiveSerializer gEAiResultPrimitiveSerializer{};

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mNext);
  }

  template <class TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mNext = self;
    serializer.mPrev = self;
  }

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mNext != nullptr && serializer.mPrev != nullptr) {
      serializer.mNext->mPrev = serializer.mPrev;
      serializer.mPrev->mNext = serializer.mNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mPrev = self;
    serializer.mNext = self;
    return self;
  }

  [[nodiscard]] moho::EAiResultTypeInfo& GetEAiResultTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::EAiResultTypeInfo*>(gEAiResultTypeInfoStorage);
  }

  /**
   * Address: 0x00608B70 (FUN_00608B70, sub_608B70)
   *
   * What it does:
   * Constructs static `EAiResult` enum type-info storage and preregisters RTTI.
   */
  gpg::REnumType* construct_EAiResultTypeInfo()
  {
    if (!gEAiResultTypeInfoConstructed) {
      new (gEAiResultTypeInfoStorage) moho::EAiResultTypeInfo();
      gpg::PreRegisterRType(typeid(moho::EAiResult), &GetEAiResultTypeInfo());
      gEAiResultTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(&GetEAiResultTypeInfo());
  }

  /**
   * Address: 0x00BF9AA0 (FUN_00BF9AA0, sub_BF9AA0)
   *
   * What it does:
   * Tears down static `EAiResult` type-info storage at process exit.
   */
  void cleanup_EAiResultTypeInfo()
  {
    if (!gEAiResultTypeInfoConstructed) {
      return;
    }

    GetEAiResultTypeInfo().~EAiResultTypeInfo();
    gEAiResultTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF9AB0 (FUN_00BF9AB0, sub_BF9AB0)
   *
   * What it does:
   * Unlinks static `EAiResult` primitive serializer helper node.
   */
  gpg::SerHelperBase* cleanup_EAiResultPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEAiResultPrimitiveSerializer);
  }

  void cleanup_EAiResultPrimitiveSerializer_atexit()
  {
    (void)cleanup_EAiResultPrimitiveSerializer();
  }

  /**
   * Address: 0x0060BCD0 (FUN_0060BCD0, sub_60BCD0)
   *
   * What it does:
   * Reads one archive `int` lane and stores it into one `EAiResult` value.
   */
  void Deserialize_EAiResult(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::EAiResult*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<moho::EAiResult>(value);
  }

  /**
   * Address: 0x0060BCF0 (FUN_0060BCF0, sub_60BCF0)
   *
   * What it does:
   * Writes one `EAiResult` lane to archive as `int`.
   */
  void Serialize_EAiResult(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto* const value = reinterpret_cast<const moho::EAiResult*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(*value));
  }

  void EAiResultPrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = gpg::LookupRType(typeid(moho::EAiResult));
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }
} // namespace

/**
 * Address: 0x00608C00 (FUN_00608C00, scalar deleting thunk)
 */
EAiResultTypeInfo::~EAiResultTypeInfo() = default;

/**
 * Address: 0x00608BF0 (FUN_00608BF0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiResult.
 */
const char* EAiResultTypeInfo::GetName() const
{
  return "EAiResult";
}

/**
 * Address: 0x00608BD0 (FUN_00608BD0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiResultTypeInfo::Init()
{
  size_ = sizeof(EAiResult);
  gpg::RType::Init();
  Finish();
}

namespace moho
{
  /**
   * Address: 0x00BD0510 (FUN_00BD0510, sub_BD0510)
   *
   * What it does:
   * Registers static `EAiResult` type-info storage and schedules teardown.
   */
  int register_EAiResultTypeInfo()
  {
    (void)construct_EAiResultTypeInfo();
    return std::atexit(&cleanup_EAiResultTypeInfo);
  }

  /**
   * Address: 0x00BD0530 (FUN_00BD0530, sub_BD0530)
   *
   * What it does:
   * Initializes `EAiResult` primitive serializer helper callbacks and binds
   * them onto the reflected enum type descriptor.
   */
  int register_EAiResultPrimitiveSerializer()
  {
    InitializeSerializerNode(gEAiResultPrimitiveSerializer);
    gEAiResultPrimitiveSerializer.mDeserialize = &Deserialize_EAiResult;
    gEAiResultPrimitiveSerializer.mSerialize = &Serialize_EAiResult;
    gEAiResultPrimitiveSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_EAiResultPrimitiveSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct EAiResultTypeInfoBootstrap
  {
    EAiResultTypeInfoBootstrap()
    {
      (void)moho::register_EAiResultTypeInfo();
      (void)moho::register_EAiResultPrimitiveSerializer();
    }
  };

  EAiResultTypeInfoBootstrap gEAiResultTypeInfoBootstrap;
} // namespace
