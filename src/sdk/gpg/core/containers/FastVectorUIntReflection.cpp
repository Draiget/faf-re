#include "gpg/core/containers/FastVectorUIntReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace gpg
{
  template <>
  class RFastVectorType<float> final : public gpg::RType, public gpg::RIndexed
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

  static_assert(sizeof(RFastVectorType<float>) == 0x68, "RFastVectorType<float> size must be 0x68");

  template <>
  class RFastVectorType<msvc8::string> final : public gpg::RType, public gpg::RIndexed
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

  static_assert(sizeof(RFastVectorType<msvc8::string>) == 0x68, "RFastVectorType<msvc8::string> size must be 0x68");
} // namespace gpg

namespace
{
  /**
   * Address: 0x00402890 (FUN_00402890)
   *
   * What it does:
   * Lazily resolves and caches reflection type descriptor for `unsigned int`.
   */
  [[nodiscard]] gpg::RType* CachedUIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(unsigned int));
    }
    return cached;
  }

  /**
   * Address: 0x004022D0 (FUN_004022D0, gpg::fastvector_uint_resize)
   *
   * What it does:
   * Resizes reflected unsigned-int fastvector storage and fills newly appended
   * lanes with `*fillValue`.
   */
  void FastVectorUIntResize(const unsigned int* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  /**
   * Address: 0x004027F0 (FUN_004027F0)
   *
   * What it does:
   * Reads vector count and serialized uint lanes into reflected fastvector storage.
   */
  void LoadFastVectorUInt(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    const unsigned int fill = 0;
    FastVectorUIntResize(&fill, count, storage);

    auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->ReadUInt(view.ElementAtUnchecked(i));
    }
  }

  /**
   * Address: 0x00402840 (FUN_00402840)
   *
   * What it does:
   * Writes vector count and serialized uint lanes from reflected fastvector storage.
   */
  void SaveFastVectorUInt(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);
    for (unsigned int i = 0; i < count; ++i) {
      archive->WriteUInt(*view.ElementAtUnchecked(i));
    }
  }

  gpg::RFastVectorType<unsigned int> gFastVectorUIntType;

  using FastVectorFloatType = gpg::RFastVectorType<float>;

  alignas(FastVectorFloatType) unsigned char gFastVectorFloatTypeStorage[sizeof(FastVectorFloatType)]{};
  bool gFastVectorFloatTypeConstructed = false;

  msvc8::string gFastVectorFloatTypeName;
  bool gFastVectorFloatTypeNameCleanupRegistered = false;

  /**
   * Address: 0x0065AA60 family helper
   *
   * What it does:
   * Acquires startup-owned storage for `RFastVectorType<float>`.
   */
  [[nodiscard]] FastVectorFloatType* AcquireFastVectorFloatType()
  {
    if (!gFastVectorFloatTypeConstructed) {
      new (gFastVectorFloatTypeStorage) FastVectorFloatType();
      gFastVectorFloatTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorFloatType*>(gFastVectorFloatTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  void cleanup_FastVectorFloatTypeName()
  {
    gFastVectorFloatTypeName = msvc8::string{};
    gFastVectorFloatTypeNameCleanupRegistered = false;
  }

  void FastVectorFloatResize(const float* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<float>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  void LoadFastVectorFloat(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    const float fill = 0.0f;
    FastVectorFloatResize(&fill, count, storage);

    auto& view = gpg::AsFastVectorRuntimeView<float>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->ReadFloat(view.ElementAtUnchecked(i));
    }
  }

  void SaveFastVectorFloat(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<float>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);
    for (unsigned int i = 0; i < count; ++i) {
      archive->WriteFloat(*view.ElementAtUnchecked(i));
    }
  }

  using FastVectorStringType = gpg::RFastVectorType<msvc8::string>;

  alignas(FastVectorStringType) unsigned char gFastVectorStringTypeStorage[sizeof(FastVectorStringType)]{};
  bool gFastVectorStringTypeConstructed = false;

  msvc8::string gFastVectorStringTypeName;
  bool gFastVectorStringTypeNameCleanupRegistered = false;

  [[nodiscard]] FastVectorStringType* AcquireFastVectorStringType()
  {
    if (!gFastVectorStringTypeConstructed) {
      new (gFastVectorStringTypeStorage) FastVectorStringType();
      gFastVectorStringTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorStringType*>(gFastVectorStringTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  void cleanup_FastVectorStringTypeName()
  {
    gFastVectorStringTypeName = msvc8::string{};
    gFastVectorStringTypeNameCleanupRegistered = false;
  }

  void FastVectorStringResize(const msvc8::string* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<msvc8::string>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  void LoadFastVectorString(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    const msvc8::string fill{};
    FastVectorStringResize(&fill, count, storage);

    auto& view = gpg::AsFastVectorRuntimeView<msvc8::string>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->ReadString(view.ElementAtUnchecked(i));
    }
  }

  void SaveFastVectorString(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<msvc8::string>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);
    for (unsigned int i = 0; i < count; ++i) {
      archive->WriteString(const_cast<msvc8::string*>(view.ElementAtUnchecked(i)));
    }
  }
} // namespace

gpg::RType* gpg::ResolveFastVectorUIntType()
{
  return gpg::LookupRType(typeid(gpg::fastvector<unsigned int>));
}

/**
 * Address: 0x00402E30 (FUN_00402E30, gpg::RFastVectorType_uint::RFastVectorType_uint)
 */
gpg::RFastVectorType<unsigned int>::RFastVectorType()
  : gpg::RType()
  , gpg::RIndexed()
{
  gpg::PreRegisterRType(typeid(gpg::fastvector<unsigned int>), this);
}

/**
 * Address: 0x00402EA0 (FUN_00402EA0, gpg::RFastVectorType_uint::dtr)
 */
gpg::RFastVectorType<unsigned int>::~RFastVectorType() = default;

/**
 * Address: 0x00402420 (FUN_00402420, gpg::RFastVectorType_uint::GetName)
 */
const char* gpg::RFastVectorType<unsigned int>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const char* const elementName = CachedUIntType()->GetName();
    sName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "unsigned int");
  }
  return sName.c_str();
}

/**
 * Address: 0x004024E0 (FUN_004024E0)
 */
msvc8::string gpg::RFastVectorType<unsigned int>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00402570 (FUN_00402570)
 */
const gpg::RIndexed* gpg::RFastVectorType<unsigned int>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x004024C0 (FUN_004024C0)
 */
void gpg::RFastVectorType<unsigned int>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorUInt;
  serSaveFunc_ = &SaveFastVectorUInt;
}

/**
 * Address: 0x004025B0 (FUN_004025B0)
 */
gpg::RRef gpg::RFastVectorType<unsigned int>::SubscriptIndex(void* obj, const int ind) const
{
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(obj != nullptr);
  if (!obj) {
    gpg::RRef out{};
    out.mType = CachedUIntType();
    out.mObj = nullptr;
    return out;
  }

  auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(obj);
  GPG_ASSERT(view.Data() != nullptr);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  out.mType = CachedUIntType();
  if (ind < 0 || !view.Data() || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    out.mObj = nullptr;
    return out;
  }

  out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
  return out;
}

/**
 * Address: 0x00402580 (FUN_00402580)
 */
size_t gpg::RFastVectorType<unsigned int>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(obj);
  if (!view.Data()) {
    return 0u;
  }
  return view.Size();
}

/**
 * Address: 0x00402590 (FUN_00402590)
 */
void gpg::RFastVectorType<unsigned int>::SetCount(void* obj, const int count) const
{
  GPG_ASSERT(obj != nullptr);
  GPG_ASSERT(count >= 0);
  if (!obj || count < 0) {
    return;
  }

  const unsigned int fill = 0;
  FastVectorUIntResize(&fill, static_cast<unsigned int>(count), obj);
}

/**
 * Address: 0x0065AA60 (FUN_0065AA60, preregister_FastVectorFloatType)
 *
 * What it does:
 * Constructs and preregisters startup RTTI descriptor for `gpg::fastvector<float>`.
 */
namespace gpg
{
  gpg::RType* preregister_FastVectorFloatType()
  {
    FastVectorFloatType* const type = AcquireFastVectorFloatType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<float>), type);
    return type;
  }

  /**
   * Address: 0x00BFBC30 (FUN_00BFBC30, cleanup_FastVectorFloatType)
   *
   * What it does:
   * Process-exit teardown for startup-owned `gpg::fastvector<float>` descriptor storage.
   */
  void cleanup_FastVectorFloatType()
  {
    if (!gFastVectorFloatTypeConstructed) {
      return;
    }

    AcquireFastVectorFloatType()->~FastVectorFloatType();
    gFastVectorFloatTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4120 (FUN_00BD4120, register_FastVectorFloatTypeAtexit)
   *
   * What it does:
   * Startup wrapper that preregisters `gpg::fastvector<float>` and installs
   * process-exit teardown through `atexit`.
   */
  int register_FastVectorFloatTypeAtexit()
  {
    (void)preregister_FastVectorFloatType();
    return std::atexit(&cleanup_FastVectorFloatType);
  }
} // namespace gpg

/**
 * Address: 0x0065AA60 family
 */
const char* gpg::RFastVectorType<float>::GetName() const
{
  if (gFastVectorFloatTypeName.empty()) {
    const char* const elementName = CachedFloatType() ? CachedFloatType()->GetName() : "float";
    gFastVectorFloatTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "float");
    if (!gFastVectorFloatTypeNameCleanupRegistered) {
      gFastVectorFloatTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorFloatTypeName);
    }
  }

  return gFastVectorFloatTypeName.c_str();
}

/**
 * Address: 0x0065AA60 family
 */
msvc8::string gpg::RFastVectorType<float>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0065AA60 family
 */
const gpg::RIndexed* gpg::RFastVectorType<float>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0065AA60 family
 */
void gpg::RFastVectorType<float>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorFloat;
  serSaveFunc_ = &SaveFastVectorFloat;
}

/**
 * Address: 0x0065AA60 family
 */
gpg::RRef gpg::RFastVectorType<float>::SubscriptIndex(void* obj, const int ind) const
{
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(obj != nullptr);
  if (!obj) {
    gpg::RRef out{};
    out.mType = CachedFloatType();
    out.mObj = nullptr;
    return out;
  }

  auto& view = gpg::AsFastVectorRuntimeView<float>(obj);
  GPG_ASSERT(view.Data() != nullptr);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  out.mType = CachedFloatType();
  if (ind < 0 || !view.Data() || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    out.mObj = nullptr;
    return out;
  }

  out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
  return out;
}

/**
 * Address: 0x0065AA60 family
 */
size_t gpg::RFastVectorType<float>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<float>(obj);
  if (!view.Data()) {
    return 0u;
  }
  return view.Size();
}

/**
 * Address: 0x0065AA60 family
 */
void gpg::RFastVectorType<float>::SetCount(void* obj, const int count) const
{
  GPG_ASSERT(obj != nullptr);
  GPG_ASSERT(count >= 0);
  if (!obj || count < 0) {
    return;
  }

  const float fill = 0.0f;
  FastVectorFloatResize(&fill, static_cast<unsigned int>(count), obj);
}

/**
 * Address: 0x0065ABB0 (FUN_0065ABB0, preregister_FastVectorStringType)
 *
 * What it does:
 * Constructs and preregisters startup RTTI descriptor for `gpg::fastvector<msvc8::string>`.
 */
namespace gpg
{
  gpg::RType* preregister_FastVectorStringType()
  {
    FastVectorStringType* const type = AcquireFastVectorStringType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<msvc8::string>), type);
    return type;
  }

  /**
   * Address: 0x00BFBB10 (FUN_00BFBB10, cleanup_FastVectorStringType)
   *
   * What it does:
   * Process-exit teardown for startup-owned `gpg::fastvector<msvc8::string>` descriptor storage.
   */
  void cleanup_FastVectorStringType()
  {
    if (!gFastVectorStringTypeConstructed) {
      return;
    }

    AcquireFastVectorStringType()->~FastVectorStringType();
    gFastVectorStringTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4180 (FUN_00BD4180, register_FastVectorStringTypeAtexit)
   *
   * What it does:
   * Startup wrapper that preregisters `gpg::fastvector<msvc8::string>` and installs
   * process-exit teardown through `atexit`.
   */
  int register_FastVectorStringTypeAtexit()
  {
    (void)preregister_FastVectorStringType();
    return std::atexit(&cleanup_FastVectorStringType);
  }
} // namespace gpg

/**
 * Address: 0x0065ABB0 family
 */
const char* gpg::RFastVectorType<msvc8::string>::GetName() const
{
  if (gFastVectorStringTypeName.empty()) {
    const char* const elementName = CachedStringType() ? CachedStringType()->GetName() : "msvc8::string";
    gFastVectorStringTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "msvc8::string");
    if (!gFastVectorStringTypeNameCleanupRegistered) {
      gFastVectorStringTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorStringTypeName);
    }
  }

  return gFastVectorStringTypeName.c_str();
}

/**
 * Address: 0x0065ABB0 family
 */
msvc8::string gpg::RFastVectorType<msvc8::string>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0065ABB0 family
 */
const gpg::RIndexed* gpg::RFastVectorType<msvc8::string>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0065ABB0 family
 */
void gpg::RFastVectorType<msvc8::string>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorString;
  serSaveFunc_ = &SaveFastVectorString;
}

/**
 * Address: 0x0065ABB0 family
 */
gpg::RRef gpg::RFastVectorType<msvc8::string>::SubscriptIndex(void* obj, const int ind) const
{
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(obj != nullptr);
  if (!obj) {
    gpg::RRef out{};
    out.mType = CachedStringType();
    out.mObj = nullptr;
    return out;
  }

  auto& view = gpg::AsFastVectorRuntimeView<msvc8::string>(obj);
  GPG_ASSERT(view.Data() != nullptr);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  out.mType = CachedStringType();
  if (ind < 0 || !view.Data() || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    out.mObj = nullptr;
    return out;
  }

  out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
  return out;
}

/**
 * Address: 0x0065ABB0 family
 */
size_t gpg::RFastVectorType<msvc8::string>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<msvc8::string>(obj);
  if (!view.Data()) {
    return 0u;
  }
  return view.Size();
}

/**
 * Address: 0x0065ABB0 family
 */
void gpg::RFastVectorType<msvc8::string>::SetCount(void* obj, const int count) const
{
  GPG_ASSERT(obj != nullptr);
  GPG_ASSERT(count >= 0);
  if (!obj || count < 0) {
    return;
  }

  const msvc8::string fill{};
  FastVectorStringResize(&fill, static_cast<unsigned int>(count), obj);
}

namespace
{
  struct FastVectorFloatReflectionBootstrap
  {
    FastVectorFloatReflectionBootstrap()
    {
      (void)gpg::register_FastVectorFloatTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorFloatReflectionBootstrap gFastVectorFloatReflectionBootstrap;

  struct FastVectorStringReflectionBootstrap
  {
    FastVectorStringReflectionBootstrap()
    {
      (void)gpg::register_FastVectorStringTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorStringReflectionBootstrap gFastVectorStringReflectionBootstrap;
} // namespace

