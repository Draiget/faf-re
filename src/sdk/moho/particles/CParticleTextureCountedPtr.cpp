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
    /**
     * Address: 0x0065ACE0 (FUN_0065ACE0, gpg::RFastVectorType_CountedPtr_CParticleTexture::dtr)
     */
    ~RFastVectorType() override;
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x00659F20 (FUN_00659F20, gpg::RFastVectorType_CountedPtr_CParticleTexture::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `fastvector<CountedPtr<CParticleTexture>>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    /**
     * Address: 0x00659FB0 (FUN_00659FB0, gpg::RFastVectorType_CountedPtr_CParticleTexture::IsIndexed)
     *
     * What it does:
     * Returns this indexed-interface lane for
     * `fastvector<CountedPtr<CParticleTexture>>` reflection.
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    /**
     * Address: 0x00659F00 (FUN_00659F00, gpg::RFastVectorType_CountedPtr_CParticleTexture::Init)
     *
     * What it does:
     * Configures reflected element size/version and binds counted-pointer
     * fastvector serializer callbacks.
     */
    void Init() override;
    /**
     * Address: 0x0065A020 (FUN_0065A020, gpg::RFastVectorType_CountedPtr_CParticleTexture::SubscriptIndex)
     *
     * What it does:
     * Builds one reflected element reference for
     * `fastvector<CountedPtr<CParticleTexture>>[ind]`.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    /**
     * Address: 0x00659FC0 (FUN_00659FC0, gpg::RFastVectorType_CountedPtr_CParticleTexture::GetCount)
     *
     * What it does:
     * Returns runtime element count for one reflected
     * `fastvector<CountedPtr<CParticleTexture>>`.
     */
    size_t GetCount(void* obj) const override;
    /**
     * Address: 0x00659FD0 (FUN_00659FD0, gpg::RFastVectorType_CountedPtr_CParticleTexture::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<CountedPtr<CParticleTexture>>` and
     * default-fills new lanes.
     */
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

  [[nodiscard]] unsigned int ResizeFastVectorCountedPtrCParticleTexture(
    gpg::fastvector_runtime_view<moho::CountedPtr_CParticleTexture>& view,
    const moho::CountedPtr_CParticleTexture* fillValue,
    unsigned int requestedCount
  );

  /**
   * Address: 0x0065A4C0 (FUN_0065A4C0, gpg::RFastVectorType_CountedPtr_CParticleTexture::SerLoad)
   *
   * What it does:
   * Loads one reflected `fastvector<CountedPtr<CParticleTexture>>` payload
   * from archive count + lanes.
   */
  void LoadFastVectorCountedPtrCParticleTexture(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::CountedPtr_CParticleTexture fill{};
    (void)ResizeFastVectorCountedPtrCParticleTexture(view, &fill, count);

    gpg::RType* const elementType = CachedCountedPtrCParticleTextureType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x0065A570 (FUN_0065A570, gpg::RFastVectorType_CountedPtr_CParticleTexture::SerSave)
   *
   * What it does:
   * Saves one reflected `fastvector<CountedPtr<CParticleTexture>>` payload as
   * archive count + lanes.
   */
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

  /**
   * Address: 0x00657900 (FUN_00657900)
   *
   * What it does:
   * Resizes one runtime `fastvector<CountedPtr<CParticleTexture>>` lane,
   * releasing trimmed references and retaining the fill texture for appended
   * lanes.
   */
  [[nodiscard]] unsigned int ResizeFastVectorCountedPtrCParticleTexture(
    gpg::fastvector_runtime_view<moho::CountedPtr_CParticleTexture>& view,
    const moho::CountedPtr_CParticleTexture* const fillValue,
    const unsigned int requestedCount
  )
  {
    const unsigned int currentCount = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    if (requestedCount < currentCount) {
      moho::CountedPtr_CParticleTexture* const newEnd = view.begin + requestedCount;
      for (moho::CountedPtr_CParticleTexture* cursor = newEnd; cursor != view.end; ++cursor) {
        moho::ResetCountedParticleTexturePtr(*cursor);
      }
      view.end = newEnd;
      return requestedCount;
    }

    if (requestedCount > currentCount) {
      gpg::FastVectorRuntimeEnsureCapacity(static_cast<std::size_t>(requestedCount), view);
      moho::CParticleTexture* const fillTexture = fillValue ? fillValue->tex : nullptr;
      moho::CountedPtr_CParticleTexture* const requestedEnd = view.begin + requestedCount;
      while (view.end != requestedEnd) {
        moho::CountedPtr_CParticleTexture* const slot = view.end;
        view.end = slot + 1;
        (void)moho::AssignCountedParticleTexturePtr(slot, fillTexture);
      }
    }

    return view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
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
   * Address: 0x006576F0 (FUN_006576F0)
   *
   * What it does:
   * Initializes one counted particle-texture pointer lane to null and returns
   * the same storage lane.
   */
  [[maybe_unused]] CountedPtr_CParticleTexture* ConstructCountedParticleTexturePtrNull(
    CountedPtr_CParticleTexture* const countedTexture
  ) noexcept
  {
    if (countedTexture == nullptr) {
      return nullptr;
    }

    countedTexture->tex = nullptr;
    return countedTexture;
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
   * Address: 0x0065AC80 (FUN_0065AC80, Moho::RCountedPtrType_CParticleTexture::dtr)
   *
   * What it does:
   * Releases dynamic reflection field/base lanes and resets object vtable to
   * `gpg::RObject` during teardown.
   */
  RCountedPtrType<moho::CParticleTexture>::~RCountedPtrType() = default;

  /**
   * Address: 0x00659BC0 (FUN_00659BC0, Moho::RCountedPtrType_CParticleTexture::GetName)
   *
   * What it does:
   * Lazily builds and caches `CountedPtr<element>` reflection text using the
   * resolved particle-texture type name.
   */
  const char* RCountedPtrType<moho::CParticleTexture>::GetName() const
  {
    if (gCountedPtrCParticleTextureTypeName.empty()) {
      gpg::RType* const pointeeType = CachedCParticleTextureType();
      const char* const pointeeName = pointeeType ? pointeeType->GetName() : "CParticleTexture";
      gCountedPtrCParticleTextureTypeName = gpg::STR_Printf("CountedPtr<%s>", pointeeName ? pointeeName : "CParticleTexture");
      if (!gCountedPtrCParticleTextureTypeNameCleanupRegistered) {
        gCountedPtrCParticleTextureTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_CountedPtrCParticleTextureTypeName);
      }
    }

    return gCountedPtrCParticleTextureTypeName.c_str();
  }

  /**
   * Address: 0x00659C80 (FUN_00659C80, Moho::RCountedPtrType_CParticleTexture::GetLexical)
   *
   * What it does:
   * Returns `"NULL"` for empty counted pointers; otherwise returns bracketed
   * pointee lexical text for the texture object.
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
   * Address: 0x00659E00 (FUN_00659E00, Moho::RCountedPtrType_CParticleTexture::IsIndexed)
   *
   * What it does:
   * Returns this indexed-interface lane for counted-pointer reflection.
   */
  const gpg::RIndexed* RCountedPtrType<moho::CParticleTexture>::IsIndexed() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x00659E10 (FUN_00659E10, Moho::RCountedPtrType_CParticleTexture::IsPointer)
   *
   * What it does:
   * Returns this pointer/indexed interface lane for counted-pointer reflection.
   */
  const gpg::RIndexed* RCountedPtrType<moho::CParticleTexture>::IsPointer() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x00659C60 (FUN_00659C60, Moho::RCountedPtrType_CParticleTexture::Init)
   *
   * What it does:
   * Configures reflected counted-pointer size/version and binds serializer
   * callbacks.
   */
  void RCountedPtrType<moho::CParticleTexture>::Init()
  {
    size_ = sizeof(moho::CountedPtr_CParticleTexture);
    version_ = 1;
    serLoadFunc_ = &SerLoad;
    serSaveFunc_ = &SerSave;
  }

  /**
   * Address: 0x00659E30 (FUN_00659E30, Moho::RCountedPtrType_CParticleTexture::SubscriptIndex)
   *
   * What it does:
   * Builds one reflected pointer reference to the counted texture lane.
   */
  gpg::RRef RCountedPtrType<moho::CParticleTexture>::SubscriptIndex(void* obj, const int) const
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(obj);
    return MakeCParticleTextureRef(counted ? counted->tex : nullptr);
  }

  /**
   * Address: 0x00659E20 (FUN_00659E20, Moho::RCountedPtrType_CParticleTexture::GetCount)
   *
   * What it does:
   * Returns `1` when counted pointer stores a texture; otherwise returns `0`.
   */
  size_t RCountedPtrType<moho::CParticleTexture>::GetCount(void* obj) const
  {
    auto* const counted = reinterpret_cast<moho::CountedPtr_CParticleTexture*>(obj);
    return (counted && counted->tex) ? 1u : 0u;
  }

  /**
   * Address: 0x0065A430 (FUN_0065A430, Moho::RCountedPtrType_CParticleTexture::SerLoad)
   *
   * What it does:
   * Loads one counted-pointer texture lane through shared-pointer archive path.
   */
  void RCountedPtrType<moho::CParticleTexture>::SerLoad(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    LoadCountedPtrCParticleTexture(archive, objectPtr, 0, ownerRef);
  }

  /**
   * Address: 0x0065A490 (FUN_0065A490, Moho::RCountedPtrType_CParticleTexture::SerSave)
   *
   * What it does:
   * Saves one counted-pointer texture lane through shared-pointer archive path.
   */
  void RCountedPtrType<moho::CParticleTexture>::SerSave(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    SaveCountedPtrCParticleTexture(archive, objectPtr, 0, ownerRef);
  }

  /**
    * Alias of FUN_0065AAD0 (non-canonical helper lane).
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
   * Address: 0x0065ACE0 (FUN_0065ACE0, gpg::RFastVectorType_CountedPtr_CParticleTexture::dtr)
   *
   * What it does:
   * Releases reflection field/base lanes for counted-pointer fastvector
   * descriptor teardown.
   */
  RFastVectorType<moho::CountedPtr_CParticleTexture>::~RFastVectorType() = default;

  /**
   * Address: 0x00659E60 (FUN_00659E60, gpg::RFastVectorType_CountedPtr_CParticleTexture::GetName)
   *
   * What it does:
   * Lazily builds and caches `fastvector<element>` reflection text using the
   * resolved counted-particle-texture type name.
   */
  const char* RFastVectorType<moho::CountedPtr_CParticleTexture>::GetName() const
  {
    if (gCountedPtrFastVectorTypeName.empty()) {
      gpg::RType* const elementType = CachedCountedPtrCParticleTextureType();
      const char* const elementName = elementType ? elementType->GetName() : "CountedPtr<CParticleTexture>";
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
   * Address: 0x00659F20 (FUN_00659F20, gpg::RFastVectorType_CountedPtr_CParticleTexture::GetLexical)
   *
   * What it does:
   * Returns base lexical text plus reflected vector size for one
   * `fastvector<CountedPtr<CParticleTexture>>` instance.
   */
  msvc8::string RFastVectorType<moho::CountedPtr_CParticleTexture>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x00659FB0 (FUN_00659FB0, gpg::RFastVectorType_CountedPtr_CParticleTexture::IsIndexed)
   *
   * What it does:
   * Returns this indexed-interface lane for
   * `fastvector<CountedPtr<CParticleTexture>>` reflection.
   */
  const gpg::RIndexed* RFastVectorType<moho::CountedPtr_CParticleTexture>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00659F00 (FUN_00659F00, gpg::RFastVectorType_CountedPtr_CParticleTexture::Init)
   *
   * What it does:
   * Configures reflected element size/version and binds counted-pointer
   * fastvector serializer callbacks.
   */
  void RFastVectorType<moho::CountedPtr_CParticleTexture>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorCountedPtrCParticleTexture;
    serSaveFunc_ = &SaveFastVectorCountedPtrCParticleTexture;
  }

  /**
   * Address: 0x0065A020 (FUN_0065A020, gpg::RFastVectorType_CountedPtr_CParticleTexture::SubscriptIndex)
   *
   * What it does:
   * Builds one reflected element reference for
   * `fastvector<CountedPtr<CParticleTexture>>[ind]`.
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
   * Address: 0x00659FC0 (FUN_00659FC0, gpg::RFastVectorType_CountedPtr_CParticleTexture::GetCount)
   *
   * What it does:
   * Returns runtime element count for one reflected
   * `fastvector<CountedPtr<CParticleTexture>>`.
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
   * Address: 0x00659FD0 (FUN_00659FD0, gpg::RFastVectorType_CountedPtr_CParticleTexture::SetCount)
   *
   * What it does:
   * Resizes one reflected `fastvector<CountedPtr<CParticleTexture>>` and
   * default-fills new lanes.
   */
  void RFastVectorType<moho::CountedPtr_CParticleTexture>::SetCount(void* obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CountedPtr_CParticleTexture>(obj);
    moho::CountedPtr_CParticleTexture fill{};
    (void)ResizeFastVectorCountedPtrCParticleTexture(view, &fill, static_cast<unsigned int>(count));
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
