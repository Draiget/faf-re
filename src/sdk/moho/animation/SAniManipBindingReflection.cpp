#include "moho/animation/IAniManipulator.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SAniManipBindingTypeInfo final : public gpg::RType
  {
  public:
    ~SAniManipBindingTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  class SAniManipBindingSerializer
  {
  public:
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(sizeof(SAniManipBindingTypeInfo) == 0x64, "SAniManipBindingTypeInfo size must be 0x64");
  static_assert(offsetof(SAniManipBindingSerializer, mHelperNext) == 0x04, "SAniManipBindingSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SAniManipBindingSerializer, mHelperPrev) == 0x08, "SAniManipBindingSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(SAniManipBindingSerializer, mLoadCallback) == 0x0C,
    "SAniManipBindingSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SAniManipBindingSerializer, mSaveCallback) == 0x10,
    "SAniManipBindingSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SAniManipBindingSerializer) == 0x14, "SAniManipBindingSerializer size must be 0x14");

  /**
   * Address: 0x0063B270 (FUN_0063B270, preregister_SAniManipBindingTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `SAniManipBinding`.
   */
  gpg::RType* preregister_SAniManipBindingTypeInfo();

  /**
   * Address: 0x00BFAD30 (FUN_00BFAD30, cleanup_SAniManipBindingTypeInfo)
   *
   * What it does:
   * Releases startup-owned `SAniManipBinding` type-info storage.
   */
  void cleanup_SAniManipBindingTypeInfo();

  /**
   * Address: 0x00BD2BA0 (FUN_00BD2BA0, register_SAniManipBindingTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `SAniManipBinding` RTTI and installs process-exit cleanup.
   */
  int register_SAniManipBindingTypeInfoAtexit();

  /**
   * Address: 0x00BFAD90 (FUN_00BFAD90, cleanup_SAniManipBindingSerializer)
   *
   * What it does:
   * Unlinks and tears down startup serializer helper ownership.
   */
  void cleanup_SAniManipBindingSerializer();

  /**
   * Address: 0x00BD2BC0 (FUN_00BD2BC0, register_SAniManipBindingSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `SAniManipBinding` and schedules teardown.
   */
  void register_SAniManipBindingSerializer();

  /**
   * Address: 0x0063D0E0 (FUN_0063D0E0, preregister_FastVectorSAniManipBindingType)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `gpg::fastvector<SAniManipBinding>`.
   */
  gpg::RType* preregister_FastVectorSAniManipBindingType();

  /**
   * Address: 0x00BFAE80 (FUN_00BFAE80, cleanup_FastVectorSAniManipBindingType)
   *
   * What it does:
   * Releases startup-owned `fastvector<SAniManipBinding>` reflection storage.
   */
  void cleanup_FastVectorSAniManipBindingType();

  /**
   * Address: 0x00BD2CC0 (FUN_00BD2CC0, register_FastVectorSAniManipBindingTypeAtexit)
   *
   * What it does:
   * Preregisters `fastvector<SAniManipBinding>` RTTI and installs process-exit cleanup.
   */
  int register_FastVectorSAniManipBindingTypeAtexit();
} // namespace moho

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::SAniManipBinding> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SAniManipBinding>) == 0x68,
    "RFastVectorType<SAniManipBinding> size must be 0x68"
  );
} // namespace gpg

namespace
{
  using SAniManipBindingTypeInfo = moho::SAniManipBindingTypeInfo;
  using SAniManipBindingSerializer = moho::SAniManipBindingSerializer;
  using FastVectorSAniManipBindingType = gpg::RFastVectorType<moho::SAniManipBinding>;

  alignas(SAniManipBindingTypeInfo) unsigned char gSAniManipBindingTypeInfoStorage[sizeof(SAniManipBindingTypeInfo)]{};
  bool gSAniManipBindingTypeInfoConstructed = false;

  alignas(SAniManipBindingSerializer) unsigned char gSAniManipBindingSerializerStorage[sizeof(SAniManipBindingSerializer)]{};
  bool gSAniManipBindingSerializerConstructed = false;

  alignas(FastVectorSAniManipBindingType)
    unsigned char gFastVectorSAniManipBindingTypeStorage[sizeof(FastVectorSAniManipBindingType)]{};
  bool gFastVectorSAniManipBindingTypeConstructed = false;

  msvc8::string gFastVectorSAniManipBindingTypeName;
  bool gFastVectorSAniManipBindingTypeNameCleanupRegistered = false;

  [[nodiscard]] SAniManipBindingTypeInfo* AcquireSAniManipBindingTypeInfo()
  {
    if (!gSAniManipBindingTypeInfoConstructed) {
      new (gSAniManipBindingTypeInfoStorage) SAniManipBindingTypeInfo();
      gSAniManipBindingTypeInfoConstructed = true;
    }

    return reinterpret_cast<SAniManipBindingTypeInfo*>(gSAniManipBindingTypeInfoStorage);
  }

  [[nodiscard]] SAniManipBindingSerializer* AcquireSAniManipBindingSerializer()
  {
    if (!gSAniManipBindingSerializerConstructed) {
      new (gSAniManipBindingSerializerStorage) SAniManipBindingSerializer();
      gSAniManipBindingSerializerConstructed = true;
    }

    return reinterpret_cast<SAniManipBindingSerializer*>(gSAniManipBindingSerializerStorage);
  }

  [[nodiscard]] FastVectorSAniManipBindingType* AcquireFastVectorSAniManipBindingType()
  {
    if (!gFastVectorSAniManipBindingTypeConstructed) {
      new (gFastVectorSAniManipBindingTypeStorage) FastVectorSAniManipBindingType();
      gFastVectorSAniManipBindingTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorSAniManipBindingType*>(gFastVectorSAniManipBindingTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedSAniManipBindingType()
  {
    if (!moho::SAniManipBinding::sType) {
      moho::SAniManipBinding::sType = gpg::LookupRType(typeid(moho::SAniManipBinding));
    }
    return moho::SAniManipBinding::sType;
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

  /**
   * Address: 0x00BFAE50 (FUN_00BFAE50, cleanup_FastVectorSAniManipBindingTypeName)
   *
   * What it does:
   * Releases cached lexical type-name storage for `fastvector<SAniManipBinding>`.
   */
  void cleanup_FastVectorSAniManipBindingTypeName()
  {
    gFastVectorSAniManipBindingTypeName = msvc8::string{};
    gFastVectorSAniManipBindingTypeNameCleanupRegistered = false;
  }

  void DeserializeSAniManipBindingFields(
    moho::SAniManipBinding* const binding,
    gpg::ReadArchive* const archive,
    const int version
  )
  {
    if (version < 2) {
      const gpg::RRef nullOwner{};
      (void)gpg::ReadRawPointer(archive, nullOwner);
    }

    archive->ReadInt(&binding->mBoneIndex);
    unsigned short lowFlags = 0;
    short highFlags = 0;
    archive->ReadUShort(&lowFlags);
    archive->ReadShort(&highFlags);

    const std::uint32_t combined =
      static_cast<std::uint32_t>(lowFlags)
      | (static_cast<std::uint32_t>(static_cast<std::uint16_t>(highFlags)) << 16);
    binding->mFlags = static_cast<std::int32_t>(combined);
  }

  void SerializeSAniManipBindingFields(
    const moho::SAniManipBinding* const binding,
    gpg::WriteArchive* const archive,
    const int version
  )
  {
    if (version < 2) {
      const gpg::RRef nullRef{};
      const gpg::RRef nullOwner{};
      gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

    archive->WriteInt(binding->mBoneIndex);
    const std::uint32_t rawFlags = static_cast<std::uint32_t>(binding->mFlags);
    archive->WriteUShort(static_cast<unsigned short>(rawFlags & 0xFFFFu));
    archive->WriteShort(static_cast<short>((rawFlags >> 16) & 0xFFFFu));
  }

  /**
   * Address: 0x0063C7A0 (FUN_0063C7A0, gpg::RFastVectorType_SAniManipBinding::SerLoad)
   *
   * What it does:
   * Loads a `fastvector<SAniManipBinding>` runtime view and deserializes each element.
   */
  void LoadFastVectorSAniManipBinding(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAniManipBinding>(reinterpret_cast<void*>(objectPtr));
    moho::SAniManipBinding fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    gpg::RType* const elementType = CachedSAniManipBindingType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x0063C830 (FUN_0063C830, gpg::RFastVectorType_SAniManipBinding::SerSave)
   *
   * What it does:
   * Saves a `fastvector<SAniManipBinding>` runtime view and serializes each element.
   */
  void SaveFastVectorSAniManipBinding(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SAniManipBinding>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSAniManipBindingType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &view.begin[i], owner);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* SAniManipBinding::sType = nullptr;

  /**
   * Address: 0x0063B300 (FUN_0063B300, Moho::SAniManipBindingTypeInfo::dtr)
   */
  SAniManipBindingTypeInfo::~SAniManipBindingTypeInfo() = default;

  /**
   * Address: 0x0063B2F0 (FUN_0063B2F0, Moho::SAniManipBindingTypeInfo::GetName)
   */
  const char* SAniManipBindingTypeInfo::GetName() const
  {
    return "SAniManipBinding";
  }

  /**
   * Address: 0x0063B2D0 (FUN_0063B2D0, Moho::SAniManipBindingTypeInfo::Init)
   */
  void SAniManipBindingTypeInfo::Init()
  {
    size_ = sizeof(SAniManipBinding);
    gpg::RType::Init();
    version_ = 2;
    Finish();
  }

  /**
   * Address: 0x0063B3B0 (FUN_0063B3B0, Moho::SAniManipBindingSerializer::Deserialize)
   */
  void SAniManipBindingSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    DeserializeSAniManipBindingFields(reinterpret_cast<SAniManipBinding*>(objectPtr), archive, version);
  }

  /**
   * Address: 0x0063B3D0 (FUN_0063B3D0, Moho::SAniManipBindingSerializer::Serialize)
   */
  void SAniManipBindingSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    SerializeSAniManipBindingFields(reinterpret_cast<const SAniManipBinding*>(objectPtr), archive, version);
  }

  /**
   * Address: 0x0063C2B0 (FUN_0063C2B0, Moho::SAniManipBindingSerializer::RegisterSerializeFunctions)
   */
  void SAniManipBindingSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSAniManipBindingType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
    type->serLoadFunc_ = mLoadCallback;
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x0063B270 (FUN_0063B270, preregister_SAniManipBindingTypeInfo)
   */
  gpg::RType* preregister_SAniManipBindingTypeInfo()
  {
    SAniManipBindingTypeInfo* const typeInfo = AcquireSAniManipBindingTypeInfo();
    gpg::PreRegisterRType(typeid(SAniManipBinding), typeInfo);
    SAniManipBinding::sType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BFAD30 (FUN_00BFAD30, cleanup_SAniManipBindingTypeInfo)
   */
  void cleanup_SAniManipBindingTypeInfo()
  {
    if (!gSAniManipBindingTypeInfoConstructed) {
      return;
    }

    AcquireSAniManipBindingTypeInfo()->~SAniManipBindingTypeInfo();
    SAniManipBinding::sType = nullptr;
    gSAniManipBindingTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD2BA0 (FUN_00BD2BA0, register_SAniManipBindingTypeInfoAtexit)
   */
  int register_SAniManipBindingTypeInfoAtexit()
  {
    (void)preregister_SAniManipBindingTypeInfo();
    return std::atexit(&cleanup_SAniManipBindingTypeInfo);
  }

  /**
   * Address: 0x00BFAD90 (FUN_00BFAD90, cleanup_SAniManipBindingSerializer)
   */
  void cleanup_SAniManipBindingSerializer()
  {
    if (!gSAniManipBindingSerializerConstructed) {
      return;
    }

    SAniManipBindingSerializer* const serializer = AcquireSAniManipBindingSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~SAniManipBindingSerializer();
    gSAniManipBindingSerializerConstructed = false;
  }

  /**
   * Address: 0x00BD2BC0 (FUN_00BD2BC0, register_SAniManipBindingSerializer)
   */
  void register_SAniManipBindingSerializer()
  {
    SAniManipBindingSerializer* const serializer = AcquireSAniManipBindingSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &SAniManipBindingSerializer::Deserialize;
    serializer->mSaveCallback = &SAniManipBindingSerializer::Serialize;
    serializer->RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SAniManipBindingSerializer);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0063C320 (FUN_0063C320, gpg::RFastVectorType_SAniManipBinding::GetName)
   */
  const char* RFastVectorType<moho::SAniManipBinding>::GetName() const
  {
    if (gFastVectorSAniManipBindingTypeName.empty()) {
      const gpg::RType* const elementType = CachedSAniManipBindingType();
      const char* const elementName = elementType ? elementType->GetName() : "SAniManipBinding";
      gFastVectorSAniManipBindingTypeName =
        gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SAniManipBinding");
      if (!gFastVectorSAniManipBindingTypeNameCleanupRegistered) {
        gFastVectorSAniManipBindingTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSAniManipBindingTypeName);
      }
    }

    return gFastVectorSAniManipBindingTypeName.c_str();
  }

  /**
   * Address: 0x0063C3E0 (FUN_0063C3E0, gpg::RFastVectorType_SAniManipBinding::GetLexical)
   */
  msvc8::string RFastVectorType<moho::SAniManipBinding>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0063C470 (FUN_0063C470, gpg::RFastVectorType_SAniManipBinding::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::SAniManipBinding>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0063C3C0 (FUN_0063C3C0, gpg::RFastVectorType_SAniManipBinding::Init)
   */
  void RFastVectorType<moho::SAniManipBinding>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorSAniManipBinding;
    serSaveFunc_ = &SaveFastVectorSAniManipBinding;
  }

  gpg::RRef RFastVectorType<moho::SAniManipBinding>::SubscriptIndex(void* obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedSAniManipBindingType();
    out.mObj = nullptr;
    if (!obj || ind < 0) {
      return out;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAniManipBinding>(obj);
    if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    out.mObj = view.begin + ind;
    return out;
  }

  size_t RFastVectorType<moho::SAniManipBinding>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SAniManipBinding>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  void RFastVectorType<moho::SAniManipBinding>::SetCount(void* obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAniManipBinding>(obj);
    moho::SAniManipBinding fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0063D0E0 (FUN_0063D0E0, preregister_FastVectorSAniManipBindingType)
   */
  gpg::RType* preregister_FastVectorSAniManipBindingType()
  {
    FastVectorSAniManipBindingType* const typeInfo = AcquireFastVectorSAniManipBindingType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<SAniManipBinding>), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFAE80 (FUN_00BFAE80, cleanup_FastVectorSAniManipBindingType)
   */
  void cleanup_FastVectorSAniManipBindingType()
  {
    if (!gFastVectorSAniManipBindingTypeConstructed) {
      return;
    }

    AcquireFastVectorSAniManipBindingType()->~FastVectorSAniManipBindingType();
    gFastVectorSAniManipBindingTypeConstructed = false;
  }

  /**
   * Address: 0x00BD2CC0 (FUN_00BD2CC0, register_FastVectorSAniManipBindingTypeAtexit)
   */
  int register_FastVectorSAniManipBindingTypeAtexit()
  {
    (void)preregister_FastVectorSAniManipBindingType();
    return std::atexit(&cleanup_FastVectorSAniManipBindingType);
  }
} // namespace moho

namespace
{
  struct SAniManipBindingReflectionBootstrap
  {
    SAniManipBindingReflectionBootstrap()
    {
      (void)moho::register_SAniManipBindingTypeInfoAtexit();
      moho::register_SAniManipBindingSerializer();
      (void)moho::register_FastVectorSAniManipBindingTypeAtexit();
    }
  };

  [[maybe_unused]] SAniManipBindingReflectionBootstrap gSAniManipBindingReflectionBootstrap;
} // namespace
