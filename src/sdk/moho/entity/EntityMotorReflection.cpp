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

  /**
   * Address: 0x006831D0 (FUN_006831D0)
   *
   * What it does:
   * Resolves and caches RTTI for the legacy `Moho::Motor` alias lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyMotorAliasType()
  {
    gpg::RType* type = moho::EntityMotor::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::Motor));
      moho::EntityMotor::sType = type;
    }
    return type;
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
    if (serializer.mHelperLinks.mNext != nullptr && serializer.mHelperLinks.mPrev != nullptr) {
      serializer.mHelperLinks.mNext->mPrev = serializer.mHelperLinks.mPrev;
      serializer.mHelperLinks.mPrev->mNext = serializer.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mPrev = self;
    serializer.mHelperLinks.mNext = self;
    return self;
  }

  /**
   * Address: 0x00694990 (FUN_00694990)
   *
   * What it does:
   * Unlinks global `MotorSerializer` helper links and resets the node to the
   * canonical self-linked state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkMotorSerializerHelperNodePrimary() noexcept
  {
    return UnlinkSerializerNode(gMotorSerializer);
  }

  /**
   * Address: 0x006949C0 (FUN_006949C0)
   *
   * What it does:
   * Secondary unlink/reset entry for the global `MotorSerializer` helper node.
   */
  [[nodiscard, maybe_unused]] gpg::SerHelperBase* UnlinkMotorSerializerHelperNodeSecondary() noexcept
  {
    return UnlinkSerializerNode(gMotorSerializer);
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
   * Address: 0x006948F0 (FUN_006948F0, MotorTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `MotorTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyMotorTypeInfoBody(MotorTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00BFCF00 (FUN_00BFCF00, Moho::MotorTypeInfo::~MotorTypeInfo)
   */
  MotorTypeInfo::~MotorTypeInfo()
  {
    DestroyMotorTypeInfoBody(this);
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
    return UnlinkMotorSerializerHelperNodePrimary();
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
   * Address: 0x00694960 (FUN_00694960)
   *
   * What it does:
   * Startup leaf that initializes global `MotorSerializer` callback lanes and
   * returns its serializer helper pointer.
   */
  [[maybe_unused]] gpg::SerHelperBase* construct_MotorSerializer_StartupLeaf()
  {
    InitializeSerializerNode(gMotorSerializer);
    gMotorSerializer.mDeserialize = &MotorSerializer::Deserialize;
    gMotorSerializer.mSerialize = &MotorSerializer::Serialize;
    return SerializerSelfNode(gMotorSerializer);
  }

  /**
   * Address: 0x006949F0 (FUN_006949F0)
   *
   * What it does:
   * Alternate startup leaf that rebuilds global `MotorSerializer` helper links,
   * rewires deserialize/serialize callbacks, and returns the helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* construct_MotorSerializer_SaveLoadStartupLeaf()
  {
    InitializeSerializerNode(gMotorSerializer);
    gMotorSerializer.mDeserialize = &MotorSerializer::Deserialize;
    gMotorSerializer.mSerialize = &MotorSerializer::Serialize;
    return SerializerSelfNode(gMotorSerializer);
  }

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   */
  void register_MotorSerializer()
  {
    (void)construct_MotorSerializer_StartupLeaf();
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
