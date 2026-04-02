#include "moho/entity/EntityMotorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::MotorTypeInfo;
  using Serializer = moho::MotorSerializer;

  alignas(TypeInfo) unsigned char gMotorTypeInfoStorage[sizeof(TypeInfo)];
  bool gMotorTypeInfoConstructed = false;
  Serializer gMotorSerializer{};

  [[nodiscard]] TypeInfo& GetMotorTypeInfo() noexcept
  {
    if (!gMotorTypeInfoConstructed) {
      new (gMotorTypeInfoStorage) TypeInfo();
      gMotorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gMotorTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedMotorType()
  {
    if (!moho::EntityMotor::sType) {
      moho::EntityMotor::sType = gpg::LookupRType(typeid(moho::EntityMotor));
    }

    GPG_ASSERT(moho::EntityMotor::sType != nullptr);
    return moho::EntityMotor::sType;
  }

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return &serializer.mHelperLinks;
  }

  template <class TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mNext = self;
    serializer.mHelperLinks.mPrev = self;
  }

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    serializer.mHelperLinks.mNext->mPrev = serializer.mHelperLinks.mPrev;
    serializer.mHelperLinks.mPrev->mNext = serializer.mHelperLinks.mNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mPrev = self;
    serializer.mHelperLinks.mNext = self;
    return self;
  }

  void cleanup_MotorTypeInfo_Atexit()
  {
    if (!gMotorTypeInfoConstructed) {
      return;
    }

    GetMotorTypeInfo().~MotorTypeInfo();
    gMotorTypeInfoConstructed = false;
    moho::EntityMotor::sType = nullptr;
  }

  void cleanup_MotorSerializer_Atexit()
  {
    (void)moho::cleanup_MotorSerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* EntityMotor::sType = nullptr;

  /**
   * Address: 0x00694800 (FUN_00694800, Moho::MotorTypeInfo::MotorTypeInfo)
   */
  MotorTypeInfo::MotorTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntityMotor), this);
  }

  /**
   * Address: 0x00BFCF00 (FUN_00BFCF00, Moho::MotorTypeInfo::~MotorTypeInfo)
   */
  MotorTypeInfo::~MotorTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00694880 (FUN_00694880, Moho::MotorTypeInfo::GetName)
   */
  const char* MotorTypeInfo::GetName() const
  {
    return "Motor";
  }

  /**
   * Address: 0x00694860 (FUN_00694860, Moho::MotorTypeInfo::Init)
   */
  void MotorTypeInfo::Init()
  {
    size_ = sizeof(EntityMotor);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00694940 (FUN_00694940, Moho::MotorSerializer::Deserialize)
   */
  void MotorSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef)
  {
    (void)archive;
    (void)objectPtr;
    (void)version;
    (void)ownerRef;
  }

  /**
   * Address: 0x00694950 (FUN_00694950, Moho::MotorSerializer::Serialize)
   */
  void MotorSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef)
  {
    (void)archive;
    (void)objectPtr;
    (void)version;
    (void)ownerRef;
  }

  /**
   * Address: 0x00694A20 (FUN_00694A20, gpg::SerSaveLoadHelper<Moho::Motor>::Init)
   */
  void MotorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedMotorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFCF60 (FUN_00BFCF60)
   */
  gpg::SerHelperBase* cleanup_MotorSerializer()
  {
    return UnlinkSerializerNode(gMotorSerializer);
  }

  /**
   * Address: 0x00BD5910 (FUN_00BD5910, register_MotorTypeInfo)
   */
  void register_MotorTypeInfo()
  {
    (void)GetMotorTypeInfo();
    (void)std::atexit(&cleanup_MotorTypeInfo_Atexit);
  }

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   */
  void register_MotorSerializer()
  {
    InitializeSerializerNode(gMotorSerializer);
    gMotorSerializer.mDeserialize = &MotorSerializer::Deserialize;
    gMotorSerializer.mSerialize = &MotorSerializer::Serialize;
    (void)std::atexit(&cleanup_MotorSerializer_Atexit);
  }
} // namespace moho

namespace
{
  struct MotorReflectionBootstrap
  {
    MotorReflectionBootstrap()
    {
      moho::register_MotorTypeInfo();
      moho::register_MotorSerializer();
    }
  };

  [[maybe_unused]] MotorReflectionBootstrap gMotorReflectionBootstrap;
} // namespace


