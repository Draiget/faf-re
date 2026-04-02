#include "moho/unit/core/SInfoCacheReflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::SInfoCacheTypeInfo;
  using Serializer = moho::SInfoCacheSerializer;
  using SInfoCacheView = moho::SInfoCache;

  alignas(TypeInfo) unsigned char gSInfoCacheTypeInfoStorage[sizeof(TypeInfo)];
  bool gSInfoCacheTypeInfoConstructed = false;

  Serializer gSInfoCacheSerializer{};

  [[nodiscard]] TypeInfo& AcquireSInfoCacheTypeInfo()
  {
    if (!gSInfoCacheTypeInfoConstructed) {
      new (gSInfoCacheTypeInfoStorage) TypeInfo();
      gSInfoCacheTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gSInfoCacheTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedRType(const std::type_info& typeInfo)
  {
    return gpg::LookupRType(typeInfo);
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = CachedRType(typeid(TObject));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    return CachedRType<moho::IFormationInstance>();
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrIUnitType()
  {
    return CachedRType<moho::WeakPtr<moho::IUnit>>();
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    return CachedRType<moho::Vector3f>();
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeTrackedRef(const TObject* const object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRType<TObject>();
    if (!object) {
      return out;
    }

    gpg::RType* runtimeType = out.mType;
    try {
      runtimeType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      runtimeType = out.mType;
    }

    if (!runtimeType || !out.mType) {
      out.mObj = const_cast<TObject*>(object);
      out.mType = runtimeType ? runtimeType : out.mType;
      return out;
    }

    std::int32_t baseOffset = 0;
    const bool derived = runtimeType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = const_cast<TObject*>(object);
      out.mType = runtimeType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(
      reinterpret_cast<std::uintptr_t>(const_cast<TObject*>(object)) - static_cast<std::uintptr_t>(baseOffset)
    );
    out.mType = runtimeType;
    return out;
  }

  template <class TObject>
  [[nodiscard]] TObject* ReadTrackedPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RType* const expectedType = CachedRType<TObject>();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<TObject*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "null";
    const char* const actual = tracked.type ? tracked.type->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected,
      actual
    );
    throw gpg::SerializationError(message.c_str());
  }

  template <class TObject>
  void WriteTrackedPointer(
    gpg::WriteArchive* const archive,
    const TObject* const object,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTrackedRef(object);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  [[nodiscard]] SInfoCacheView* AsSInfoCacheView(int objectPtr) noexcept
  {
    return reinterpret_cast<SInfoCacheView*>(objectPtr);
  }

  [[nodiscard]] const SInfoCacheView* AsConstSInfoCacheView(int objectPtr) noexcept
  {
    return reinterpret_cast<const SInfoCacheView*>(objectPtr);
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::RType* ResolveSInfoCacheType()
  {
    return gpg::LookupRType(typeid(SInfoCacheView));
  }

  /**
   * Address: 0x006B04B0 (FUN_006B04B0, Moho::SInfoCacheSerializer::Deserialize)
   *
   * What it does:
   * Loads the raw formation pointer, reflected weak unit pointer, and trailing
   * scalar/vector lanes for `SInfoCache`.
   */
  void LoadSInfoCacheBody(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    auto* const info = AsSInfoCacheView(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    info->mFormationLayer =
      reinterpret_cast<moho::CFormationInstance*>(ReadTrackedPointer<moho::IFormationInstance>(archive, owner));

    archive->Read(CachedWeakPtrIUnitType(), &info->mFormationLeadRef, owner);
    archive->ReadInt(&info->mFormationPriorityOrder);
    archive->ReadBool(&info->mHasFormationSpeedData);
    archive->ReadFloat(&info->mFormationTopSpeed);
    archive->ReadFloat(&info->mFormationDistanceMetric);
    archive->Read(CachedVector3fType(), &info->mFormationHeadingHint, owner);
  }

  /**
   * Address: 0x006B0580 (FUN_006B0580, Moho::SInfoCacheSerializer::Serialize)
   *
   * What it does:
   * Saves the raw formation pointer, reflected weak unit pointer, and trailing
   * scalar/vector lanes for `SInfoCache`.
   */
  void SaveSInfoCacheBody(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    const auto* const info = AsConstSInfoCacheView(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    WriteTrackedPointer(
      archive,
      reinterpret_cast<const moho::IFormationInstance*>(info->mFormationLayer),
      gpg::TrackedPointerState::Unowned,
      owner
    );

    archive->Write(CachedWeakPtrIUnitType(), &info->mFormationLeadRef, owner);
    archive->WriteInt(info->mFormationPriorityOrder);
    archive->WriteBool(info->mHasFormationSpeedData);
    archive->WriteFloat(info->mFormationTopSpeed);
    archive->WriteFloat(info->mFormationDistanceMetric);
    archive->Write(CachedVector3fType(), &info->mFormationHeadingHint, owner);
  }

  /**
   * Address: 0x00BFD940 (FUN_00BFD940, sub_BFD940)
   *
   * What it does:
   * Unlinks the serializer helper-node and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_SInfoCacheSerializer_00BFD940_Impl()
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(gSInfoCacheSerializer);
    if (gSInfoCacheSerializer.mHelperNext == nullptr || gSInfoCacheSerializer.mHelperPrev == nullptr) {
      gSInfoCacheSerializer.mHelperPrev = self;
      gSInfoCacheSerializer.mHelperNext = self;
      return self;
    }

    gSInfoCacheSerializer.mHelperNext->mPrev = gSInfoCacheSerializer.mHelperPrev;
    gSInfoCacheSerializer.mHelperPrev->mNext = gSInfoCacheSerializer.mHelperNext;
    gSInfoCacheSerializer.mHelperPrev = self;
    gSInfoCacheSerializer.mHelperNext = self;
    return self;
  }

  void cleanup_SInfoCacheSerializer_00BFD940_AtExit()
  {
    (void)cleanup_SInfoCacheSerializer_00BFD940_Impl();
  }

  /**
   * Address: 0x00BFD8E0 (FUN_00BFD8E0, sub_BFD8E0)
   *
   * What it does:
   * Releases reflected `SInfoCacheTypeInfo` field/base vectors at exit.
   */
  void cleanup_SInfoCacheTypeInfo_00BFD8E0_Impl()
  {
    if (!gSInfoCacheTypeInfoConstructed) {
      return;
    }

    AcquireSInfoCacheTypeInfo().~TypeInfo();
    gSInfoCacheTypeInfoConstructed = false;
  }

  void cleanup_SInfoCacheTypeInfo_00BFD8E0_AtExit()
  {
    cleanup_SInfoCacheTypeInfo_00BFD8E0_Impl();
  }

  /**
   * Address: 0x00BD6A70 (FUN_00BD6A70, register_SInfoCacheTypeInfo)
   *
   * What it does:
   * Forces `SInfoCacheTypeInfo` construction and schedules exit cleanup.
   */
  int register_SInfoCacheTypeInfo_Impl()
  {
    (void)moho::construct_SInfoCacheTypeInfo();
    return std::atexit(&cleanup_SInfoCacheTypeInfo_00BFD8E0_AtExit);
  }

  /**
   * Address: 0x00BD6A90 (FUN_00BD6A90, register_SInfoCacheSerializer)
   *
   * What it does:
   * Initializes `SInfoCacheSerializer` callbacks and schedules exit cleanup.
   */
  void register_SInfoCacheSerializer_Impl()
  {
    InitializeSerializerNode(gSInfoCacheSerializer);
    gSInfoCacheSerializer.mDeserialize = &moho::SInfoCacheSerializer::Deserialize;
    gSInfoCacheSerializer.mSerialize = &moho::SInfoCacheSerializer::Serialize;
    gSInfoCacheSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SInfoCacheSerializer_00BFD940_AtExit);
  }

  struct SInfoCacheReflectionBootstrap
  {
    SInfoCacheReflectionBootstrap()
    {
      (void)moho::register_SInfoCacheTypeInfo();
      moho::register_SInfoCacheSerializer();
    }
  };

  SInfoCacheReflectionBootstrap gSInfoCacheReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006A4E60 (FUN_006A4E60, sub_6A4E60)
   */
  SInfoCacheTypeInfo::SInfoCacheTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SInfoCacheView), this);
  }

  /**
   * Address: 0x006A4EF0 (FUN_006A4EF0, sub_6A4EF0)
   */
  SInfoCacheTypeInfo::~SInfoCacheTypeInfo()
  {
    fields_ = msvc8::vector<gpg::RField>{};
    bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x006A4EE0 (FUN_006A4EE0, Moho::SInfoCacheTypeInfo::GetName)
   */
  const char* SInfoCacheTypeInfo::GetName() const
  {
    return "SInfoCache";
  }

  /**
   * Address: 0x006A4EC0 (FUN_006A4EC0, Moho::SInfoCacheTypeInfo::Init)
   */
  void SInfoCacheTypeInfo::Init()
  {
    size_ = sizeof(SInfoCacheView);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006A4E60 (FUN_006A4E60, sub_6A4E60)
   */
  gpg::RType* construct_SInfoCacheTypeInfo()
  {
    return &AcquireSInfoCacheTypeInfo();
  }

  /**
   * Address: 0x00BFD8E0 (FUN_00BFD8E0, sub_BFD8E0)
   */
  void cleanup_SInfoCacheTypeInfo()
  {
    cleanup_SInfoCacheTypeInfo_00BFD8E0_Impl();
  }

  /**
   * Address: 0x00BD6A70 (FUN_00BD6A70, register_SInfoCacheTypeInfo)
   */
  int register_SInfoCacheTypeInfo()
  {
    return register_SInfoCacheTypeInfo_Impl();
  }

  /**
   * Address: 0x006B04B0 (FUN_006B04B0, Moho::SInfoCacheSerializer::Deserialize)
   */
  void SInfoCacheSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    LoadSInfoCacheBody(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006B0580 (FUN_006B0580, Moho::SInfoCacheSerializer::Serialize)
   */
  void SInfoCacheSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SaveSInfoCacheBody(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00BD6A90 (FUN_00BD6A90, register_SInfoCacheSerializer)
   */
  void SInfoCacheSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSInfoCacheType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD940 (FUN_00BFD940, sub_BFD940)
   */
  gpg::SerHelperBase* cleanup_SInfoCacheSerializer()
  {
    return cleanup_SInfoCacheSerializer_00BFD940_Impl();
  }

  /**
   * Address: 0x00BD6A90 (FUN_00BD6A90, register_SInfoCacheSerializer)
   */
  void register_SInfoCacheSerializer()
  {
    register_SInfoCacheSerializer_Impl();
  }
} // namespace moho
