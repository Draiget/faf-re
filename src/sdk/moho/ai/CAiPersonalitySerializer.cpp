#include "moho/ai/CAiPersonalitySerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPersonality.h"

using namespace moho;

namespace
{
  using SValuePair = moho::SAiPersonalityRange;

  /**
   * VFTABLE: 0x00E1CA88
   * COL:  0x00E72A48
   */
  class SValuePairTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005B6660 (FUN_005B6660, Moho::SValuePairTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      return "SValuePair";
    }

    /**
     * Address: 0x005B6640 (FUN_005B6640, Moho::SValuePairTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(SValuePair);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(SValuePairTypeInfo) == 0x64, "SValuePairTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E1CA80
   * COL:  0x00E729FC
   */
  class SValuePairSerializer
  {
  public:
    /**
     * Address: 0x005B6720 (FUN_005B6720, Moho::SValuePairSerializer::Deserialize)
     *
     * What it does:
     * Loads both `float` lanes of one `SValuePair`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B6750 (FUN_005B6750, Moho::SValuePairSerializer::Serialize)
     *
     * What it does:
     * Saves both `float` lanes of one `SValuePair`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B6770 (FUN_005B6770, serializer callback binder lane)
     *
     * What it does:
     * Binds `SValuePair` load/save callbacks into the reflected type
     * descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };
  static_assert(offsetof(SValuePairSerializer, mHelperNext) == 0x04, "SValuePairSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SValuePairSerializer, mHelperPrev) == 0x08, "SValuePairSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SValuePairSerializer, mDeserialize) == 0x0C, "SValuePairSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SValuePairSerializer, mSerialize) == 0x10, "SValuePairSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SValuePairSerializer) == 0x14, "SValuePairSerializer size must be 0x14");

  alignas(SValuePairTypeInfo) unsigned char gSValuePairTypeInfoStorage[sizeof(SValuePairTypeInfo)];
  bool gSValuePairTypeInfoConstructed = false;

  alignas(SValuePairSerializer) unsigned char gSValuePairSerializerStorage[sizeof(SValuePairSerializer)];
  bool gSValuePairSerializerConstructed = false;

  alignas(CAiPersonalitySerializer) unsigned char gCAiPersonalitySerializerStorage[sizeof(CAiPersonalitySerializer)];
  bool gCAiPersonalitySerializerConstructed = false;

  [[nodiscard]] SValuePairTypeInfo* AcquireSValuePairTypeInfo()
  {
    if (!gSValuePairTypeInfoConstructed) {
      new (gSValuePairTypeInfoStorage) SValuePairTypeInfo();
      gSValuePairTypeInfoConstructed = true;
    }

    return reinterpret_cast<SValuePairTypeInfo*>(gSValuePairTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedSValuePairType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SValuePair));
    }
    return cached;
  }

  /**
   * Address: 0x005B65E0 (FUN_005B65E0, preregister_SValuePairTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI for `SValuePair`.
   */
  [[nodiscard]] gpg::RType* preregister_SValuePairTypeInfo()
  {
    SValuePairTypeInfo* const typeInfo = AcquireSValuePairTypeInfo();
    gpg::PreRegisterRType(typeid(SValuePair), typeInfo);
    return typeInfo;
  }

  [[nodiscard]] SValuePairSerializer* AcquireSValuePairSerializer()
  {
    if (!gSValuePairSerializerConstructed) {
      new (gSValuePairSerializerStorage) SValuePairSerializer();
      gSValuePairSerializerConstructed = true;
    }

    return reinterpret_cast<SValuePairSerializer*>(gSValuePairSerializerStorage);
  }

  [[nodiscard]] CAiPersonalitySerializer* AcquireCAiPersonalitySerializer()
  {
    if (!gCAiPersonalitySerializerConstructed) {
      new (gCAiPersonalitySerializerStorage) CAiPersonalitySerializer();
      gCAiPersonalitySerializerConstructed = true;
    }

    return reinterpret_cast<CAiPersonalitySerializer*>(gCAiPersonalitySerializerStorage);
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
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BF7620 (FUN_00BF7620, cleanup_SValuePairTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SValuePair` reflection type descriptor.
   */
  void cleanup_SValuePairTypeInfo()
  {
    if (!gSValuePairTypeInfoConstructed) {
      return;
    }

    AcquireSValuePairTypeInfo()->~SValuePairTypeInfo();
    gSValuePairTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF7640 (FUN_00BF7640, cleanup_SValuePairSerializer)
   *
   * What it does:
   * Unlinks startup `SValuePairSerializer` helper node from the intrusive
   * serializer helper chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_SValuePairSerializer()
  {
    if (!gSValuePairSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireSValuePairSerializer());
  }

  void CleanupSValuePairSerializerAtexit()
  {
    (void)cleanup_SValuePairSerializer();
  }

  [[nodiscard]] gpg::RType* CachedCAiPersonalityType()
  {
    gpg::RType* type = CAiPersonality::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPersonality));
      CAiPersonality::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7740 (FUN_00BF7740, cleanup_CAiPersonalitySerializer)
   *
   * What it does:
   * Unlinks the static serializer helper node from the intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiPersonalitySerializer()
  {
    if (!gCAiPersonalitySerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPersonalitySerializer());
  }

  void CleanupCAiPersonalitySerializerAtexit()
  {
    (void)cleanup_CAiPersonalitySerializer();
  }
} // namespace

/**
 * Address: 0x005B6720 (FUN_005B6720, Moho::SValuePairSerializer::Deserialize)
 */
void SValuePairSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const valuePair = reinterpret_cast<SValuePair*>(static_cast<std::uintptr_t>(objectPtr));
  archive->ReadFloat(&valuePair->mMinValue);
  archive->ReadFloat(&valuePair->mMaxValue);
}

/**
 * Address: 0x005B6750 (FUN_005B6750, Moho::SValuePairSerializer::Serialize)
 */
void SValuePairSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const valuePair = reinterpret_cast<const SValuePair*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteFloat(valuePair->mMinValue);
  archive->WriteFloat(valuePair->mMaxValue);
}

void SValuePairSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSValuePairType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x00BCD5A0 (FUN_00BCD5A0)
 *
 * What it does:
 * Preregisters startup RTTI for the legacy AI `SValuePair` lane and installs
 * process-exit cleanup.
 */
int moho::register_SValuePairTypeInfo()
{
  (void)preregister_SValuePairTypeInfo();
  return std::atexit(&cleanup_SValuePairTypeInfo);
}

/**
 * Address: 0x00BCD5C0 (FUN_00BCD5C0, register_SValuePairSerializer)
 *
 * What it does:
 * Initializes startup serializer callbacks for `SValuePair` and installs
 * process-exit helper unlink cleanup.
 */
int moho::register_SValuePairSerializer()
{
  SValuePairSerializer* const serializer = AcquireSValuePairSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mDeserialize = &SValuePairSerializer::Deserialize;
  serializer->mSerialize = &SValuePairSerializer::Serialize;
  return std::atexit(&CleanupSValuePairSerializerAtexit);
}

/**
 * Address: 0x005B6A80 (FUN_005B6A80, Moho::CAiPersonalitySerializer::Deserialize)
 */
void CAiPersonalitySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const personality = reinterpret_cast<CAiPersonality*>(static_cast<std::uintptr_t>(objectPtr));
  personality->MemberDeserialize(archive);
}

/**
 * Address: 0x005B6A90 (FUN_005B6A90, Moho::CAiPersonalitySerializer::Serialize)
 */
void CAiPersonalitySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const personality = reinterpret_cast<CAiPersonality*>(static_cast<std::uintptr_t>(objectPtr));
  personality->MemberSerialize(archive);
}

/**
 * Address: 0x005B9350 (FUN_005B9350)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPersonalitySerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiPersonalityType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCD660 (FUN_00BCD660, register_CAiPersonalitySerializer)
 *
 * What it does:
 * Initializes global CAiPersonality serializer helper callbacks and installs
 * process-exit cleanup.
 */
int moho::register_CAiPersonalitySerializer()
{
  CAiPersonalitySerializer* const serializer = AcquireCAiPersonalitySerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiPersonalitySerializer::Deserialize;
  serializer->mSaveCallback = &CAiPersonalitySerializer::Serialize;
  return std::atexit(&CleanupCAiPersonalitySerializerAtexit);
}

namespace
{
  struct CAiPersonalitySerializerBootstrap
  {
    CAiPersonalitySerializerBootstrap()
    {
      (void)moho::register_SValuePairTypeInfo();
      (void)moho::register_SValuePairSerializer();
      (void)moho::register_CAiPersonalitySerializer();
    }
  };

  [[maybe_unused]] CAiPersonalitySerializerBootstrap gCAiPersonalitySerializerBootstrap;
} // namespace
