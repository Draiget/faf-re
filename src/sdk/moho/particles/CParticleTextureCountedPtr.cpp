#include "moho/particles/CParticleTextureCountedPtr.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/CParticleTextureReflection.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::CountedPtr_CParticleTexture> final : public gpg::RType, public gpg::RIndexed
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
    sizeof(RFastVectorType<moho::CountedPtr_CParticleTexture>) == 0x68,
    "RFastVectorType<CountedPtr<CParticleTexture>> size must be 0x68"
  );
} // namespace gpg

namespace
{
  using CountedPtrType = moho::RCountedPtrType<moho::CParticleTexture>;
  using CountedPtrFastVectorType = gpg::RFastVectorType<moho::CountedPtr_CParticleTexture>;

  alignas(CountedPtrType) unsigned char gCountedPtrCParticleTextureTypeStorage[sizeof(CountedPtrType)]{};
  bool gCountedPtrCParticleTextureTypeConstructed = false;

  alignas(CountedPtrFastVectorType) unsigned char gCountedPtrFastVectorTypeStorage[sizeof(CountedPtrFastVectorType)]{};
  bool gCountedPtrFastVectorTypeConstructed = false;

  msvc8::string gCountedPtrCParticleTextureTypeName;
  bool gCountedPtrCParticleTextureTypeNameCleanupRegistered = false;

  msvc8::string gCountedPtrFastVectorTypeName;
  bool gCountedPtrFastVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] CountedPtrType* AcquireCountedPtrCParticleTextureType()
  {
    if (!gCountedPtrCParticleTextureTypeConstructed) {
      new (gCountedPtrCParticleTextureTypeStorage) CountedPtrType();
      gCountedPtrCParticleTextureTypeConstructed = true;
    }

    return reinterpret_cast<CountedPtrType*>(gCountedPtrCParticleTextureTypeStorage);
  }

  [[nodiscard]] CountedPtrFastVectorType* AcquireCountedPtrFastVectorType()
  {
    if (!gCountedPtrFastVectorTypeConstructed) {
      new (gCountedPtrFastVectorTypeStorage) CountedPtrFastVectorType();
      gCountedPtrFastVectorTypeConstructed = true;
    }

    return reinterpret_cast<CountedPtrFastVectorType*>(gCountedPtrFastVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedCParticleTextureType()
  {
    return moho::resource_reflection::ResolveCParticleTextureType();
  }

  [[nodiscard]] gpg::RType* CachedCountedPtrCParticleTextureType()
  {
    if (moho::CountedPtr_CParticleTexture::sType == nullptr) {
      moho::CountedPtr_CParticleTexture::sType = gpg::LookupRType(typeid(moho::CountedPtr_CParticleTexture));
    }

    return moho::CountedPtr_CParticleTexture::sType;
  }

  [[nodiscard]] gpg::RRef MakeCParticleTextureRef(moho::CParticleTexture* const value)
  {
    gpg::RRef out{};
    gpg::RRef_CParticleTexture(&out, value);
    if (out.mType == nullptr) {
      out.mType = CachedCParticleTextureType();
    }
    return out;
  }

  [[nodiscard]] moho::CParticleTexture* ReadPointerSharedCParticleTexture(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RType* const expectedType = CachedCParticleTextureType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<moho::CParticleTexture*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "CParticleTexture";
    const char* const actual = tracked.type ? tracked.type->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected,
      actual
    );
    throw gpg::SerializationError(message.c_str());
  }

  void cleanup_CountedPtrCParticleTextureTypeName()
  {
    gCountedPtrCParticleTextureTypeName = msvc8::string{};
    gCountedPtrCParticleTextureTypeNameCleanupRegistered = false;
  }

  void cleanup_CountedPtrFastVectorTypeName()
  {
    gCountedPtrFastVectorTypeName = msvc8::string{};
    gCountedPtrFastVectorTypeNameCleanupRegistered = false;
  }

  void LoadCountedPtrCParticleTexture(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(objectPtr);
    if (!counted || !archive) {
      return;
    }

    moho::CParticleTexture* const texture =
      ReadPointerSharedCParticleTexture(archive, ownerRef ? *ownerRef : gpg::RRef{});
    (void)moho::AssignCountedParticleTexturePtr(counted, texture);
  }

  void SaveCountedPtrCParticleTexture(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(objectPtr);
    if (!counted || !archive) {
      return;
    }

    const gpg::RRef objectRef = MakeCParticleTextureRef(moho::GetCountedParticleTextureRawPointer(*counted));
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Shared, owner);
  }

  void LoadFastVectorCountedPtrCParticleTexture(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::CountedPtr_CParticleTexture fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    gpg::RType* const elementType = CachedCountedPtrCParticleTextureType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  void SaveFastVectorCountedPtrCParticleTexture(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedCountedPtrCParticleTextureType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &view.begin[i], owner);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004954E0 (FUN_004954E0, sub_4954E0)
   *
   * What it does:
   * Returns the raw particle-texture pointer lane from one counted-pointer
   * wrapper.
   */
  CParticleTexture* GetCountedParticleTextureRawPointer(const CountedPtr_CParticleTexture& countedTexture) noexcept
  {
    return countedTexture.tex;
  }

  /**
   * Address: 0x004954B0 (FUN_004954B0, sub_4954B0)
   *
   * What it does:
   * Releases one counted particle-texture pointer lane and clears it.
   */
  void ResetCountedParticleTexturePtr(CountedPtr_CParticleTexture& countedTexture) noexcept
  {
    if (countedTexture.tex != nullptr) {
      countedTexture.tex->ReleaseReferenceAtomic();
    }
    countedTexture.tex = nullptr;
  }

  /**
   * Address: 0x004954F0 (FUN_004954F0, sub_4954F0)
   *
   * What it does:
   * Rebinds one counted particle-texture pointer lane while preserving
   * intrusive reference-count semantics.
   */
  CountedPtr_CParticleTexture* AssignCountedParticleTexturePtr(
    CountedPtr_CParticleTexture* const target,
    CParticleTexture* const texture
  ) noexcept
  {
    if (target == nullptr) {
      return nullptr;
    }

    if (target->tex != texture) {
      if (target->tex != nullptr) {
        target->tex->ReleaseReferenceAtomic();
      }

      target->tex = texture;

      if (texture != nullptr) {
        texture->AddReferenceAtomic();
      }
    }

    return target;
  }

  /**
   * Address: 0x0065AAD0 family
   */
  RCountedPtrType<moho::CParticleTexture>::RCountedPtrType()
    : gpg::RType()
    , gpg::RIndexed()
  {
    gpg::PreRegisterRType(typeid(moho::CountedPtr<moho::CParticleTexture>), this);
  }

  /**
   * Address: 0x0065AAD0 family
   */
  RCountedPtrType<moho::CParticleTexture>::~RCountedPtrType() = default;

  /**
   * Address: 0x0065AAD0 family
   */
  const char* RCountedPtrType<moho::CParticleTexture>::GetName() const
  {
    if (gCountedPtrCParticleTextureTypeName.empty()) {
      const char* const pointeeName = CachedCParticleTextureType() ? CachedCParticleTextureType()->GetName() : "CParticleTexture";
      gCountedPtrCParticleTextureTypeName = gpg::STR_Printf("CountedPtr<%s>", pointeeName ? pointeeName : "CParticleTexture");
      if (!gCountedPtrCParticleTextureTypeNameCleanupRegistered) {
        gCountedPtrCParticleTextureTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_CountedPtrCParticleTextureTypeName);
      }
    }

    return gCountedPtrCParticleTextureTypeName.c_str();
  }

  /**
   * Address: 0x0065AAD0 family
   */
  msvc8::string RCountedPtrType<moho::CParticleTexture>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const counted = reinterpret_cast<const moho::CountedPtr_CParticleTexture*>(ref.mObj);
    if (!counted || !counted->tex) {
      return msvc8::string("NULL");
    }

    const gpg::RRef textureRef = MakeCParticleTextureRef(counted->tex);
    const msvc8::string inner = textureRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x0065AAD0 family
   */
  const gpg::RIndexed* RCountedPtrType<moho::CParticleTexture>::IsIndexed() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x0065AAD0 family
   */
  const gpg::RIndexed* RCountedPtrType<moho::CParticleTexture>::IsPointer() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x0065AAD0 family
   */
  void RCountedPtrType<moho::CParticleTexture>::Init()
  {
    size_ = sizeof(moho::CountedPtr_CParticleTexture);
    version_ = 1;
    serLoadFunc_ = &SerLoad;
    serSaveFunc_ = &SerSave;
  }

  /**
   * Address: 0x0065AAD0 family
   */
  gpg::RRef RCountedPtrType<moho::CParticleTexture>::SubscriptIndex(void* obj, const int) const
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(obj);
    return MakeCParticleTextureRef(counted ? counted->tex : nullptr);
  }

  /**
   * Address: 0x0065AAD0 family
   */
  size_t RCountedPtrType<moho::CParticleTexture>::GetCount(void* obj) const
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(obj);
    return (counted && counted->tex) ? 1u : 0u;
  }

  /**
   * Address: 0x0065AAD0 family
   */
  void RCountedPtrType<moho::CParticleTexture>::SerLoad(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    LoadCountedPtrCParticleTexture(archive, objectPtr, 0, ownerRef);
  }

  /**
   * Address: 0x0065AAD0 family
   */
  void RCountedPtrType<moho::CParticleTexture>::SerSave(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    SaveCountedPtrCParticleTexture(archive, objectPtr, 0, ownerRef);
  }

  /**
   * Address: 0x0065AAD0 (FUN_0065AAD0, preregister_CountedPtrCParticleTextureType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `CountedPtr<CParticleTexture>`.
   */
  gpg::RType* preregister_CountedPtrCParticleTextureType()
  {
    CountedPtrType* const type = AcquireCountedPtrCParticleTextureType();
    moho::CountedPtr_CParticleTexture::sType = type;
    gpg::PreRegisterRType(typeid(moho::CountedPtr<moho::CParticleTexture>), type);
    return type;
  }

  /**
   * Address: 0x00BFBBD0 (FUN_00BFBBD0, cleanup_CountedPtrCParticleTextureType)
   *
   * What it does:
   * Tears down startup-owned `CountedPtr<CParticleTexture>` reflection storage.
   */
  void cleanup_CountedPtrCParticleTextureType()
  {
    if (!gCountedPtrCParticleTextureTypeConstructed) {
      return;
    }

    AcquireCountedPtrCParticleTextureType()->~CountedPtrType();
    gCountedPtrCParticleTextureTypeConstructed = false;
    moho::CountedPtr_CParticleTexture::sType = nullptr;
  }

  /**
   * Address: 0x00BD4140 (FUN_00BD4140, register_CountedPtrCParticleTextureTypeAtexit)
   *
   * What it does:
   * Registers `CountedPtr<CParticleTexture>` reflection and installs process-exit teardown.
   */
  int register_CountedPtrCParticleTextureTypeAtexit()
  {
    (void)preregister_CountedPtrCParticleTextureType();
    return std::atexit(&cleanup_CountedPtrCParticleTextureType);
  }

  /**
   * Address: 0x0065AB40 (FUN_0065AB40, preregister_FastVectorCountedPtrCParticleTextureType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `fastvector<CountedPtr<CParticleTexture>>`.
   */
  gpg::RType* preregister_FastVectorCountedPtrCParticleTextureType()
  {
    CountedPtrFastVectorType* const type = AcquireCountedPtrFastVectorType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::CountedPtr<moho::CParticleTexture>>), type);
    return type;
  }

  /**
   * Address: 0x00BFBB70 (FUN_00BFBB70, cleanup_FastVectorCountedPtrCParticleTextureType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<CountedPtr<CParticleTexture>>` reflection storage.
   */
  void cleanup_FastVectorCountedPtrCParticleTextureType()
  {
    if (!gCountedPtrFastVectorTypeConstructed) {
      return;
    }

    AcquireCountedPtrFastVectorType()->~CountedPtrFastVectorType();
    gCountedPtrFastVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4160 (FUN_00BD4160, register_FastVectorCountedPtrCParticleTextureTypeAtexit)
   *
   * What it does:
   * Registers `fastvector<CountedPtr<CParticleTexture>>` reflection and installs process-exit teardown.
   */
  int register_FastVectorCountedPtrCParticleTextureTypeAtexit()
  {
    (void)preregister_FastVectorCountedPtrCParticleTextureType();
    return std::atexit(&cleanup_FastVectorCountedPtrCParticleTextureType);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0065AB40 family
   */
  const char* RFastVectorType<moho::CountedPtr_CParticleTexture>::GetName() const
  {
    if (gCountedPtrFastVectorTypeName.empty()) {
      const char* const elementName =
        CachedCountedPtrCParticleTextureType() ? CachedCountedPtrCParticleTextureType()->GetName() : "CountedPtr<CParticleTexture>";
      gCountedPtrFastVectorTypeName =
        gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "CountedPtr<CParticleTexture>");
      if (!gCountedPtrFastVectorTypeNameCleanupRegistered) {
        gCountedPtrFastVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_CountedPtrFastVectorTypeName);
      }
    }

    return gCountedPtrFastVectorTypeName.c_str();
  }

  /**
   * Address: 0x0065AB40 family
   */
  msvc8::string RFastVectorType<moho::CountedPtr_CParticleTexture>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0065AB40 family
   */
  const gpg::RIndexed* RFastVectorType<moho::CountedPtr_CParticleTexture>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0065AB40 family
   */
  void RFastVectorType<moho::CountedPtr_CParticleTexture>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorCountedPtrCParticleTexture;
    serSaveFunc_ = &SaveFastVectorCountedPtrCParticleTexture;
  }

  /**
   * Address: 0x0065AB40 family
   */
  gpg::RRef RFastVectorType<moho::CountedPtr_CParticleTexture>::SubscriptIndex(void* obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedCountedPtrCParticleTextureType();
    out.mObj = nullptr;
    if (!obj || ind < 0) {
      return out;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(obj);
    if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    out.mObj = view.begin + ind;
    return out;
  }

  /**
   * Address: 0x0065AB40 family
   */
  size_t RFastVectorType<moho::CountedPtr_CParticleTexture>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x0065AB40 family
   */
  void RFastVectorType<moho::CountedPtr_CParticleTexture>::SetCount(void* obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(obj);
    moho::CountedPtr_CParticleTexture fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }
} // namespace gpg

namespace
{
  struct CParticleTextureCountedPtrReflectionBootstrap
  {
    CParticleTextureCountedPtrReflectionBootstrap()
    {
      (void)moho::register_CountedPtrCParticleTextureTypeAtexit();
      (void)moho::register_FastVectorCountedPtrCParticleTextureTypeAtexit();
    }
  };

  [[maybe_unused]] CParticleTextureCountedPtrReflectionBootstrap gCParticleTextureCountedPtrReflectionBootstrap;
} // namespace
