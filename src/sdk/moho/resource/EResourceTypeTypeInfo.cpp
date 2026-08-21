#include "moho/resource/EResourceTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EResourceTypeTypeInfo) unsigned char gEResourceTypeTypeInfoStorage[sizeof(moho::EResourceTypeTypeInfo)];

  void CleanupEResourceTypeTypeInfoAtexit()
  {
    reinterpret_cast<moho::EResourceTypeTypeInfo*>(gEResourceTypeTypeInfoStorage)->~EResourceTypeTypeInfo();
  }

  moho::EResourceTypePrimitiveSerializer gEResourceTypePrimitiveSerializer{};

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

  /**
   * Address: 0x00547380 (FUN_00547380)
   *
   * What it does:
   * Reinitializes startup helper storage for `EResourceType` primitive
   * serialization and binds enum load/save callbacks.
   */
  [[maybe_unused]] [[nodiscard]] moho::EResourceTypePrimitiveSerializer*
  InitializeEResourceTypePrimitiveSerializerStartupThunk()
  {
    InitializeSerializerNode(gEResourceTypePrimitiveSerializer);
    gEResourceTypePrimitiveSerializer.mDeserialize = &moho::EResourceTypePrimitiveSerializer::Deserialize;
    gEResourceTypePrimitiveSerializer.mSerialize = &moho::EResourceTypePrimitiveSerializer::Serialize;
    return &gEResourceTypePrimitiveSerializer;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00545A50 (FUN_00545A50, Moho::EResourceTypeTypeInfo::EResourceTypeTypeInfo)
   *
   * What it does:
   * Preregisters this type descriptor under `typeid(EResourceType)` so
   * `gpg::LookupRType` can resolve it later. The base `REnumType`/`RType`
   * subobject and vtable install are handled by the compiler-generated base
   * ctor chain; this constructor's only own work is the preregistration
   * call.
   */
  EResourceTypeTypeInfo::EResourceTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EResourceType), this);
  }

  /**
   * Address: 0x00BF4190 (FUN_00BF4190, Moho::EResourceTypeTypeInfo::~EResourceTypeTypeInfo)
   * Address: 0x00545AE0 (FUN_00545AE0, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   *
   * The vtable-slot-0 deleting-destructor thunk (FUN_00545AE0, `this,
   * deleteFlags` shape: runs this destructor then conditionally frees the
   * object) is the compiler-generated override the `override` destructor
   * below already emits -- no separate hand-written body needed.
   */
  EResourceTypeTypeInfo::~EResourceTypeTypeInfo() = default;

  /**
   * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
   */
  const char* EResourceTypeTypeInfo::GetName() const
  {
    return "EResourceType";
  }

  /**
   * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
   */
  void EResourceTypeTypeInfo::Init()
  {
    size_ = sizeof(EResourceType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
   */
  void EResourceTypeTypeInfo::AddEnums()
  {
    mPrefix = "RESTYPE_";

    AddEnum(StripPrefix("RESTYPE_None"), static_cast<std::int32_t>(RESTYPE_None));
    AddEnum(StripPrefix("RESTYPE_Mass"), static_cast<std::int32_t>(RESTYPE_Mass));
    AddEnum(StripPrefix("RESTYPE_Hydrocarbon"), static_cast<std::int32_t>(RESTYPE_Hydrocarbon));
    AddEnum(StripPrefix("RESTYPE_Max"), static_cast<std::int32_t>(RESTYPE_Max));
  }

  /**
   * Address: 0x005478E0 (FUN_005478E0, PrimitiveSerHelper<EResourceType>::Deserialize)
   */
  void EResourceTypePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EResourceType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EResourceType>(value);
  }

  /**
   * Address: 0x00547900 (FUN_00547900, PrimitiveSerHelper<EResourceType>::Serialize)
   */
  void EResourceTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EResourceType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EResourceTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EResourceType));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC95F0 (FUN_00BC95F0, register_EResourceTypeTypeInfo)
   *
   * What it does:
   * Constructs the global `EResourceTypeTypeInfo` descriptor (preregistering
   * it under `typeid(EResourceType)` as a side effect of its constructor)
   * and schedules its teardown at process exit.
   */
  void register_EResourceTypeTypeInfo()
  {
    new (gEResourceTypeTypeInfoStorage) EResourceTypeTypeInfo();
    (void)std::atexit(&CleanupEResourceTypeTypeInfoAtexit);
  }
} // namespace moho

namespace
{
  struct EResourceTypeTypeInfoBootstrap
  {
    EResourceTypeTypeInfoBootstrap()
    {
      moho::register_EResourceTypeTypeInfo();
    }
  };

  [[maybe_unused]] EResourceTypeTypeInfoBootstrap gEResourceTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType(typeid(EResourceType)). See
// StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EResourceTypeTypeInfo_bc95f0, moho::register_EResourceTypeTypeInfo)
