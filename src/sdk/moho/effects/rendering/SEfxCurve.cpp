#include "moho/effects/rendering/SEfxCurve.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::SEfxCurve> final : public gpg::RType, public gpg::RIndexed
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

  static_assert(sizeof(RFastVectorType<moho::SEfxCurve>) == 0x68, "RFastVectorType<SEfxCurve> size must be 0x68");
} // namespace gpg

namespace
{
  using FastVectorSEfxCurveType = gpg::RFastVectorType<moho::SEfxCurve>;

  alignas(FastVectorSEfxCurveType) unsigned char gFastVectorSEfxCurveTypeStorage[sizeof(FastVectorSEfxCurveType)]{};
  bool gFastVectorSEfxCurveTypeConstructed = false;
  msvc8::string gFastVectorSEfxCurveTypeName;
  bool gFastVectorSEfxCurveTypeNameCleanupRegistered = false;

  [[nodiscard]] FastVectorSEfxCurveType* AcquireFastVectorSEfxCurveType()
  {
    if (!gFastVectorSEfxCurveTypeConstructed) {
      new (gFastVectorSEfxCurveTypeStorage) FastVectorSEfxCurveType();
      gFastVectorSEfxCurveTypeConstructed = true;
    }
    return reinterpret_cast<FastVectorSEfxCurveType*>(gFastVectorSEfxCurveTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedSEfxCurveType()
  {
    return moho::SEfxCurve::StaticGetClass();
  }

  void cleanup_FastVectorSEfxCurveTypeName()
  {
    gFastVectorSEfxCurveTypeName = msvc8::string{};
    gFastVectorSEfxCurveTypeNameCleanupRegistered = false;
  }

  void LoadFastVectorSEfxCurve(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::SEfxCurve fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    gpg::RType* const elementType = CachedSEfxCurveType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  void SaveFastVectorSEfxCurve(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSEfxCurveType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &view.begin[i], owner);
    }
  }
} // namespace

namespace gpg
{
  const char* RFastVectorType<moho::SEfxCurve>::GetName() const
  {
    if (gFastVectorSEfxCurveTypeName.empty()) {
      const char* const elementName = CachedSEfxCurveType() ? CachedSEfxCurveType()->GetName() : "SEfxCurve";
      gFastVectorSEfxCurveTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SEfxCurve");
      if (!gFastVectorSEfxCurveTypeNameCleanupRegistered) {
        gFastVectorSEfxCurveTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSEfxCurveTypeName);
      }
    }

    return gFastVectorSEfxCurveTypeName.c_str();
  }

  msvc8::string RFastVectorType<moho::SEfxCurve>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* RFastVectorType<moho::SEfxCurve>::IsIndexed() const
  {
    return this;
  }

  void RFastVectorType<moho::SEfxCurve>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorSEfxCurve;
    serSaveFunc_ = &SaveFastVectorSEfxCurve;
  }

  gpg::RRef RFastVectorType<moho::SEfxCurve>::SubscriptIndex(void* obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedSEfxCurveType();
    out.mObj = nullptr;
    if (!obj || ind < 0) {
      return out;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    out.mObj = view.begin + ind;
    return out;
  }

  size_t RFastVectorType<moho::SEfxCurve>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  void RFastVectorType<moho::SEfxCurve>::SetCount(void* obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    moho::SEfxCurve fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }
} // namespace gpg

namespace moho
{
  SEfxCurve::SEfxCurve(const SEfxCurve& other)
    : mBoundsMin(other.mBoundsMin)
    , mBoundsMax(other.mBoundsMax)
    , mKeys()
  {
    mKeys.ResetFrom(other.mKeys);
  }

  SEfxCurve& SEfxCurve::operator=(const SEfxCurve& other)
  {
    if (this == &other) {
      return *this;
    }

    mBoundsMin = other.mBoundsMin;
    mBoundsMax = other.mBoundsMax;
    mKeys.ResetFrom(other.mKeys);
    return *this;
  }

  gpg::RType* SEfxCurve::sType = nullptr;

  gpg::RType* SEfxCurve::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SEfxCurve));
    }
    return sType;
  }

  /**
   * Address: 0x00514D40 (FUN_00514D40, Moho::SEfxCurveSerializer::Deserialize)
   */
  void SEfxCurve::DeserializeFromArchive(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const curve = reinterpret_cast<SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00514D50 (FUN_00514D50, Moho::SEfxCurveSerializer::Serialize)
   */
  void SEfxCurve::SerializeToArchive(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const curve = reinterpret_cast<const SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberSerialize(archive);
  }

  /**
   * Address: 0x00516D20 (FUN_00516D20, Moho::SEfxCurve::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall func_ReadArchive_SEfxCurve(Moho::SEfxCurve *a1@<eax>, gpg::ReadArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Read(vector2Type, &mBoundsMin, nullOwner);
    archive->Read(vector2Type, &mBoundsMax, nullOwner);
    archive->Read(keyVectorType, &mKeys, nullOwner);
  }

  /**
   * Address: 0x00516DD0 (FUN_00516DD0, Moho::SEfxCurve::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::SEfxCurve::MemberSerialize(Moho::SEfxCurve *a1@<eax>, BinaryWriteArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Write(vector2Type, &mBoundsMin, nullOwner);
    archive->Write(vector2Type, &mBoundsMax, nullOwner);
    archive->Write(keyVectorType, &mKeys, nullOwner);
  }

  /**
   * Address: 0x0065FBA0 (FUN_0065FBA0, preregister_FastVectorSEfxCurveType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `gpg::fastvector<SEfxCurve>`.
   */
  gpg::RType* preregister_FastVectorSEfxCurveType()
  {
    FastVectorSEfxCurveType* const type = AcquireFastVectorSEfxCurveType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<SEfxCurve>), type);
    return type;
  }

  /**
   * Address: 0x00BFBED0 (FUN_00BFBED0, cleanup_FastVectorSEfxCurveType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<SEfxCurve>` reflection storage.
   */
  void cleanup_FastVectorSEfxCurveType()
  {
    if (!gFastVectorSEfxCurveTypeConstructed) {
      return;
    }

    AcquireFastVectorSEfxCurveType()->~FastVectorSEfxCurveType();
    gFastVectorSEfxCurveTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4430 (FUN_00BD4430, register_FastVectorSEfxCurveTypeAtexit)
   *
   * What it does:
   * Registers `fastvector<SEfxCurve>` reflection and installs process-exit teardown.
   */
  int register_FastVectorSEfxCurveTypeAtexit()
  {
    (void)preregister_FastVectorSEfxCurveType();
    return std::atexit(&cleanup_FastVectorSEfxCurveType);
  }
} // namespace moho

namespace
{
  struct SEfxCurveFastVectorReflectionBootstrap
  {
    SEfxCurveFastVectorReflectionBootstrap()
    {
      (void)moho::register_FastVectorSEfxCurveTypeAtexit();
    }
  };

  [[maybe_unused]] SEfxCurveFastVectorReflectionBootstrap gSEfxCurveFastVectorReflectionBootstrap;
} // namespace
