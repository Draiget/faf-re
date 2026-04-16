#include "moho/command/EUnitCommandTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EUnitCommandTypeTypeInfo)
    unsigned char gEUnitCommandTypeTypeInfoStorage[sizeof(moho::EUnitCommandTypeTypeInfo)];
  bool gEUnitCommandTypeTypeInfoConstructed = false;
  bool gEUnitCommandTypeTypeInfoPreregistered = false;

  alignas(moho::EUnitCommandTypePrimitiveSerializer)
    unsigned char gEUnitCommandTypePrimitiveSerializerStorage[sizeof(moho::EUnitCommandTypePrimitiveSerializer)];
  bool gEUnitCommandTypePrimitiveSerializerConstructed = false;

  gpg::RType* gEUnitCommandTypeCachedType = nullptr;

  [[nodiscard]] moho::EUnitCommandTypeTypeInfo* AcquireEUnitCommandTypeTypeInfo()
  {
    if (!gEUnitCommandTypeTypeInfoConstructed) {
      new (gEUnitCommandTypeTypeInfoStorage) moho::EUnitCommandTypeTypeInfo();
      gEUnitCommandTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EUnitCommandTypeTypeInfo*>(gEUnitCommandTypeTypeInfoStorage);
  }

  [[nodiscard]] moho::EUnitCommandTypePrimitiveSerializer* AcquireEUnitCommandTypePrimitiveSerializer()
  {
    if (!gEUnitCommandTypePrimitiveSerializerConstructed) {
      new (gEUnitCommandTypePrimitiveSerializerStorage) moho::EUnitCommandTypePrimitiveSerializer();
      gEUnitCommandTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::EUnitCommandTypePrimitiveSerializer*>(gEUnitCommandTypePrimitiveSerializerStorage);
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
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
    return self;
  }

  [[nodiscard]] gpg::RType* ResolveEUnitCommandType()
  {
    if (!gEUnitCommandTypeCachedType) {
      gEUnitCommandTypeCachedType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return gEUnitCommandTypeCachedType;
  }

  /**
   * Address: 0x00BF4950 (FUN_00BF4950, cleanup_EUnitCommandTypeTypeInfo)
   */
  void cleanup_EUnitCommandTypeTypeInfo()
  {
    if (!gEUnitCommandTypeTypeInfoConstructed) {
      return;
    }

    AcquireEUnitCommandTypeTypeInfo()->~EUnitCommandTypeTypeInfo();
    gEUnitCommandTypeTypeInfoConstructed = false;
    gEUnitCommandTypeTypeInfoPreregistered = false;
    gEUnitCommandTypeCachedType = nullptr;
  }

  /**
   * Address: 0x00BF4960 (FUN_00BF4960, cleanup_EUnitCommandTypePrimitiveSerializer)
   */
  void cleanup_EUnitCommandTypePrimitiveSerializer()
  {
    if (!gEUnitCommandTypePrimitiveSerializerConstructed) {
      return;
    }

    (void)UnlinkSerializerNode(*AcquireEUnitCommandTypePrimitiveSerializer());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00552140 (FUN_00552140, Moho::EUnitCommandTypeTypeInfo::dtr)
   */
  EUnitCommandTypeTypeInfo::~EUnitCommandTypeTypeInfo() = default;

  /**
   * Address: 0x00552130 (FUN_00552130, Moho::EUnitCommandTypeTypeInfo::GetName)
   */
  const char* EUnitCommandTypeTypeInfo::GetName() const
  {
    return "EUnitCommandType";
  }

  /**
   * Address: 0x00552110 (FUN_00552110, Moho::EUnitCommandTypeTypeInfo::Init)
   */
  void EUnitCommandTypeTypeInfo::Init()
  {
    size_ = sizeof(EUnitCommandType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00552170 (FUN_00552170, Moho::EUnitCommandTypeTypeInfo::AddEnums)
   */
  void EUnitCommandTypeTypeInfo::AddEnums()
  {
    mPrefix = "UNITCOMMAND_";
    AddEnum(StripPrefix("UNITCOMMAND_None"), 0);
    AddEnum(StripPrefix("UNITCOMMAND_Stop"), 1);
    AddEnum(StripPrefix("UNITCOMMAND_Move"), 2);
    AddEnum(StripPrefix("UNITCOMMAND_Dive"), 3);
    AddEnum(StripPrefix("UNITCOMMAND_FormMove"), 4);
    AddEnum(StripPrefix("UNITCOMMAND_BuildSiloTactical"), 5);
    AddEnum(StripPrefix("UNITCOMMAND_BuildSiloNuke"), 6);
    AddEnum(StripPrefix("UNITCOMMAND_BuildFactory"), 7);
    AddEnum(StripPrefix("UNITCOMMAND_BuildMobile"), 8);
    AddEnum(StripPrefix("UNITCOMMAND_BuildAssist"), 9);
    AddEnum(StripPrefix("UNITCOMMAND_Attack"), 10);
    AddEnum(StripPrefix("UNITCOMMAND_FormAttack"), 11);
    AddEnum(StripPrefix("UNITCOMMAND_Nuke"), 12);
    AddEnum(StripPrefix("UNITCOMMAND_Tactical"), 13);
    AddEnum(StripPrefix("UNITCOMMAND_Teleport"), 14);
    AddEnum(StripPrefix("UNITCOMMAND_Guard"), 15);
    AddEnum(StripPrefix("UNITCOMMAND_Patrol"), 16);
    AddEnum(StripPrefix("UNITCOMMAND_Ferry"), 17);
    AddEnum(StripPrefix("UNITCOMMAND_FormPatrol"), 18);
    AddEnum(StripPrefix("UNITCOMMAND_Reclaim"), 19);
    AddEnum(StripPrefix("UNITCOMMAND_Repair"), 20);
    AddEnum(StripPrefix("UNITCOMMAND_Capture"), 21);
    AddEnum(StripPrefix("UNITCOMMAND_TransportLoadUnits"), 22);
    AddEnum(StripPrefix("UNITCOMMAND_TransportReverseLoadUnits"), 23);
    AddEnum(StripPrefix("UNITCOMMAND_TransportUnloadUnits"), 24);
    AddEnum(StripPrefix("UNITCOMMAND_TransportUnloadSpecificUnits"), 25);
    AddEnum(StripPrefix("UNITCOMMAND_DetachFromTransport"), 26);
    AddEnum(StripPrefix("UNITCOMMAND_Upgrade"), 27);
    AddEnum(StripPrefix("UNITCOMMAND_Script"), 28);
    AddEnum(StripPrefix("UNITCOMMAND_AssistCommander"), 29);
    AddEnum(StripPrefix("UNITCOMMAND_KillSelf"), 30);
    AddEnum(StripPrefix("UNITCOMMAND_DestroySelf"), 31);
    AddEnum(StripPrefix("UNITCOMMAND_Sacrifice"), 32);
    AddEnum(StripPrefix("UNITCOMMAND_Pause"), 33);
    AddEnum(StripPrefix("UNITCOMMAND_OverCharge"), 34);
    AddEnum(StripPrefix("UNITCOMMAND_AggressiveMove"), 35);
    AddEnum(StripPrefix("UNITCOMMAND_FormAggressiveMove"), 36);
    AddEnum(StripPrefix("UNITCOMMAND_AssistMove"), 37);
    AddEnum(StripPrefix("UNITCOMMAND_SpecialAction"), 38);
    AddEnum(StripPrefix("UNITCOMMAND_Dock"), 39);
  }

  /**
   * Address: 0x00553540 (FUN_00553540, Deserialize_EUnitCommandType_Primitive)
   */
  void EUnitCommandTypePrimitiveSerializer::Deserialize(
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
    *reinterpret_cast<EUnitCommandType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EUnitCommandType>(value);
  }

  /**
   * Address: 0x00553560 (FUN_00553560, Serialize_EUnitCommandType_Primitive)
   */
  void EUnitCommandTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const EUnitCommandType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x00552D60 (FUN_00552D60, gpg::SerSaveLoadHelper_EUnitCommandType::Init)
   */
  void EUnitCommandTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveEUnitCommandType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x005520B0 (FUN_005520B0, preregister_EUnitCommandTypeTypeInfo)
   */
  gpg::REnumType* preregister_EUnitCommandTypeTypeInfo()
  {
    auto* const typeInfo = AcquireEUnitCommandTypeTypeInfo();
    if (!gEUnitCommandTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(EUnitCommandType), typeInfo);
      gEUnitCommandTypeTypeInfoPreregistered = true;
    }

    gEUnitCommandTypeCachedType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BC9C20 (FUN_00BC9C20, register_EUnitCommandTypeTypeInfo)
   */
  int register_EUnitCommandTypeTypeInfo()
  {
    (void)preregister_EUnitCommandTypeTypeInfo();
    return std::atexit(&cleanup_EUnitCommandTypeTypeInfo);
  }

  /**
   * Address: 0x00BC9C40 (FUN_00BC9C40, register_EUnitCommandTypePrimitiveSerializer)
   */
  int register_EUnitCommandTypePrimitiveSerializer()
  {
    auto* const serializer = AcquireEUnitCommandTypePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &EUnitCommandTypePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &EUnitCommandTypePrimitiveSerializer::Serialize;
    return std::atexit(&cleanup_EUnitCommandTypePrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct EUnitCommandTypeTypeInfoBootstrap
  {
    EUnitCommandTypeTypeInfoBootstrap()
    {
      (void)moho::register_EUnitCommandTypeTypeInfo();
      (void)moho::register_EUnitCommandTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EUnitCommandTypeTypeInfoBootstrap gEUnitCommandTypeTypeInfoBootstrap;
} // namespace

