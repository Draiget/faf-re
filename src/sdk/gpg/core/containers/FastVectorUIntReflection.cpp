#include "gpg/core/containers/FastVectorUIntReflection.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/sim/SOCellPos.h"
#include "Wm3Vector3.h"

namespace gpg
{
  template <>
  class RFastVectorType<float> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x00659AA0 (FUN_00659AA0, gpg::RFastVectorType_float::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `fastvector<float>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    /**
     * Address: 0x00659B30 (FUN_00659B30, gpg::RFastVectorType_float::IsIndexed)
     *
     * What it does:
     * Returns this indexed-interface lane for `fastvector<float>` reflection.
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    /**
     * Address: 0x00659A80 (FUN_00659A80, gpg::RFastVectorType_float::Init)
     *
     * What it does:
     * Configures reflected element size/version and binds float fastvector
     * serializer callbacks.
     */
    void Init() override;
    /**
     * Address: 0x00659B80 (FUN_00659B80, gpg::RFastVectorType_float::SubscriptIndex)
     *
     * What it does:
     * Builds one reflected element reference for `fastvector<float>[ind]`.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    /**
     * Address: 0x00659B40 (FUN_00659B40, gpg::RFastVectorType_float::GetCount)
     *
     * What it does:
     * Returns runtime element count for one reflected `fastvector<float>`.
     */
    size_t GetCount(void* obj) const override;
    /**
     * Address: 0x00659B50 (FUN_00659B50, gpg::RFastVectorType_float::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<float>` and zero-fills new lanes.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<float>) == 0x68, "RFastVectorType<float> size must be 0x68");

  template <>
  class RFastVectorType<msvc8::string> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x0065A120 (FUN_0065A120, gpg::RFastVectorType_String::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `fastvector<msvc8::string>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    /**
     * Address: 0x0065A1B0 (FUN_0065A1B0, gpg::RFastVectorType_String::IsIndexed)
     *
     * What it does:
     * Returns this indexed-interface lane for `fastvector<msvc8::string>`
     * reflection.
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    /**
     * Address: 0x0065A100 (FUN_0065A100, gpg::RFastVectorType_String::Init)
     *
     * What it does:
     * Configures reflected element size/version and binds string fastvector
     * serializer callbacks.
     */
    void Init() override;
    /**
     * Address: 0x0065A250 (FUN_0065A250, gpg::RFastVectorType_String::SubscriptIndex)
     *
     * What it does:
     * Builds one reflected element reference for
     * `fastvector<msvc8::string>[ind]`.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    /**
     * Address: 0x0065A1C0 (FUN_0065A1C0, gpg::RFastVectorType_String::GetCount)
     *
     * What it does:
     * Returns runtime element count for one reflected
     * `fastvector<msvc8::string>`.
     */
    size_t GetCount(void* obj) const override;
    /**
     * Address: 0x0065A1E0 (FUN_0065A1E0, gpg::RFastVectorType_String::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<msvc8::string>` and default-fills new
     * lanes with empty strings.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<msvc8::string>) == 0x68, "RFastVectorType<msvc8::string> size must be 0x68");

  template <>
  class RFastVectorType<Wm3::Vector3f> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x005159E0 (FUN_005159E0, gpg::RFastVectorType_Vector3f::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `fastvector<Wm3::Vector3f>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    /**
     * Address: 0x00515F40 (FUN_00515F40, gpg::RFastVectorType_Vector3f::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<Wm3::Vector3f>` lane and zero-fills
     * appended elements.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<Wm3::Vector3f>) == 0x68, "RFastVectorType<Vector3f> size must be 0x68");
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

  struct FastVectorUIntRuntimeView
  {
    unsigned int* begin;
    unsigned int* end;
    unsigned int* capacityEnd;
    unsigned int* metadata;
  };

  struct FastVectorUIntInlineScratchView
  {
    unsigned int* begin;
    unsigned int* end;
    unsigned int* capacityEnd;
    unsigned int* metadata;
    unsigned int inlineStorage[2];
  };
  static_assert(offsetof(FastVectorUIntInlineScratchView, inlineStorage) == 0x10, "FastVectorUIntInlineScratchView::inlineStorage offset must be 0x10");

  /**
   * Address: 0x00552050 (FUN_00552050)
   *
   * What it does:
   * Writes the invalid `EntId` sentinel word (`0xF0000000`) to output
   * storage.
   */
  [[maybe_unused]] [[nodiscard]] unsigned int* WriteInvalidEntIdSentinelWordLaneA(unsigned int* const outWord) noexcept
  {
    *outWord = 0xF0000000u;
    return outWord;
  }

  /**
   * Address: 0x00552080 (FUN_00552080)
   *
   * What it does:
   * Writes the all-bits-set sentinel word (`0xFFFFFFFF`) to output storage.
   */
  [[maybe_unused]] [[nodiscard]] unsigned int* WriteAllBitsSetWordLaneA(unsigned int* const outWord) noexcept
  {
    *outWord = 0xFFFFFFFFu;
    return outWord;
  }

  /**
   * Address: 0x00552C40 (FUN_00552C40)
   *
   * What it does:
   * Initializes one inline-backed dword fastvector scratch lane to empty
   * state with two-word inline capacity.
   */
  [[maybe_unused]] [[nodiscard]] FastVectorUIntInlineScratchView* InitializeInlineUIntScratchViewLaneA(
    FastVectorUIntInlineScratchView* const view
  ) noexcept
  {
    view->begin = view->inlineStorage;
    view->end = view->inlineStorage;
    view->capacityEnd = view->inlineStorage + 2;
    view->metadata = view->inlineStorage;
    return view;
  }

  /**
   * Address: 0x00552CE0 (FUN_00552CE0)
   *
   * What it does:
   * Secondary entrypoint for the same inline scratch-view initialization lane.
   */
  [[maybe_unused]] [[nodiscard]] FastVectorUIntInlineScratchView* InitializeInlineUIntScratchViewLaneB(
    FastVectorUIntInlineScratchView* const view
  ) noexcept
  {
    return InitializeInlineUIntScratchViewLaneA(view);
  }

  /**
   * Address: 0x00553430 (FUN_00553430)
   *
   * What it does:
   * Binds one dword fastvector runtime view to external `[buffer, buffer +
   * elementCount)` storage and records `buffer` as metadata lane.
   */
  [[maybe_unused]] [[nodiscard]] FastVectorUIntRuntimeView* BindUIntRuntimeViewToExternalStorageLaneA(
    FastVectorUIntRuntimeView* const view,
    const unsigned int elementCount,
    unsigned int* const buffer
  ) noexcept
  {
    view->begin = buffer;
    view->end = buffer;
    view->capacityEnd = buffer + elementCount;
    view->metadata = buffer;
    return view;
  }

  /**
   * Address: 0x00553500 (FUN_00553500)
   *
   * What it does:
   * Secondary entrypoint for the same external-storage bind lane.
   */
  [[maybe_unused]] [[nodiscard]] FastVectorUIntRuntimeView* BindUIntRuntimeViewToExternalStorageLaneB(
    FastVectorUIntRuntimeView* const view,
    const unsigned int elementCount,
    unsigned int* const buffer
  ) noexcept
  {
    return BindUIntRuntimeViewToExternalStorageLaneA(view, elementCount, buffer);
  }

  /**
   * Address: 0x004022D0 (FUN_004022D0, gpg::fastvector_uint_resize)
   * Address: 0x00553480 (FUN_00553480)
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

  /**
   * Address: 0x00BEDF40 (FUN_00BEDF40, ??1RFastVectorType_uint@gpg@@QAE@@Z)
   *
   * What it does:
   * Process-exit cleanup for global `RFastVectorType<unsigned int>` dynamic
   * field/base lanes.
   */
  void cleanup_RFastVectorType_uint()
  {
    gFastVectorUIntType.fields_.clear();
    gFastVectorUIntType.bases_.clear();
  }

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

  struct DwordVectorHeaderRuntimeView
  {
    std::uint32_t* begin = nullptr; // +0x00
    std::uint32_t* end = nullptr; // +0x04
    std::uint32_t* capacityEnd = nullptr; // +0x08
    std::uint32_t* metadata = nullptr; // +0x0C
  };
  static_assert(sizeof(DwordVectorHeaderRuntimeView) == 0x10, "DwordVectorHeaderRuntimeView size must be 0x10");
  static_assert(offsetof(DwordVectorHeaderRuntimeView, begin) == 0x00, "DwordVectorHeaderRuntimeView::begin offset must be 0x00");
  static_assert(offsetof(DwordVectorHeaderRuntimeView, end) == 0x04, "DwordVectorHeaderRuntimeView::end offset must be 0x04");
  static_assert(
    offsetof(DwordVectorHeaderRuntimeView, capacityEnd) == 0x08,
    "DwordVectorHeaderRuntimeView::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(DwordVectorHeaderRuntimeView, metadata) == 0x0C,
    "DwordVectorHeaderRuntimeView::metadata offset must be 0x0C"
  );

  template <std::size_t InlineCapacityWords>
  [[nodiscard]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeader(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    auto* const inlineStorage = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::byte*>(outHeader) + 0x10u);
    outHeader->begin = inlineStorage;
    outHeader->end = inlineStorage;
    outHeader->capacityEnd = inlineStorage + InlineCapacityWords;
    outHeader->metadata = inlineStorage;
    return outHeader;
  }

  template <std::size_t CapacityWords>
  [[nodiscard]] DwordVectorHeaderRuntimeView* BindDwordVectorHeaderToExternalStorage(
    DwordVectorHeaderRuntimeView* const outHeader,
    std::uint32_t* const base
  ) noexcept
  {
    outHeader->begin = base;
    outHeader->end = base;
    outHeader->capacityEnd = base + CapacityWords;
    outHeader->metadata = base;
    return outHeader;
  }

  /**
   * Address: 0x00659980 (FUN_00659980)
   *
   * What it does:
   * Initializes one inline dword-vector header with 26-word inline capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeaderCapacity26(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    return InitializeInlineDwordVectorHeader<26u>(outHeader);
  }

  /**
   * Address: 0x006599A0 (FUN_006599A0)
   *
   * What it does:
   * Initializes one inline dword-vector header with 2-word inline capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeaderCapacity2(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    return InitializeInlineDwordVectorHeader<2u>(outHeader);
  }

  /**
   * Address: 0x006599C0 (FUN_006599C0)
   *
   * What it does:
   * Initializes one inline dword-vector header with 14-word inline capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeaderCapacity14(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    return InitializeInlineDwordVectorHeader<14u>(outHeader);
  }

  /**
   * Address: 0x0065A340 (FUN_0065A340)
   *
   * What it does:
   * Binds one dword-vector header to external storage with 26-word capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* BindDwordVectorHeaderCapacity26(
    DwordVectorHeaderRuntimeView* const outHeader,
    std::uint32_t* const base
  ) noexcept
  {
    return BindDwordVectorHeaderToExternalStorage<26u>(outHeader, base);
  }

  /**
   * Address: 0x0065A350 (FUN_0065A350)
   *
   * What it does:
   * Binds one dword-vector header to external storage with 2-word capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* BindDwordVectorHeaderCapacity2(
    DwordVectorHeaderRuntimeView* const outHeader,
    std::uint32_t* const base
  ) noexcept
  {
    return BindDwordVectorHeaderToExternalStorage<2u>(outHeader, base);
  }

  /**
   * Address: 0x00657820 (FUN_00657820)
   *
   * What it does:
   * Resizes one runtime `fastvector<float>` lane to `newSize`, truncating or
   * appending `*fillValue` as needed.
   */
  [[nodiscard]] unsigned int FastVectorFloatResize(const float* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<float>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
    return static_cast<unsigned int>(view.begin ? (view.end - view.begin) : 0u);
  }

  /**
   * Address: 0x0065A380 (FUN_0065A380, gpg::RFastVectorType_float::SerLoad)
   *
   * What it does:
   * Loads one reflected `fastvector<float>` payload from archive count + lanes.
   */
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

  /**
   * Address: 0x0065A3E0 (FUN_0065A3E0, gpg::RFastVectorType_float::SerSave)
   *
   * What it does:
   * Saves one reflected `fastvector<float>` payload as archive count + lanes.
   */
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

  /**
   * Address: 0x0065A5E0 (FUN_0065A5E0, gpg::RFastVectorType_String::SerLoad)
   *
   * What it does:
   * Loads one reflected `fastvector<msvc8::string>` payload from archive count
   * + lanes.
   */
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

  /**
   * Address: 0x0065A6A0 (FUN_0065A6A0, gpg::RFastVectorType_String::SerSave)
   *
   * What it does:
   * Saves one reflected `fastvector<msvc8::string>` payload as archive count +
   * lanes.
   */
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

  using FastVectorVector3fType = gpg::RFastVectorType<Wm3::Vector3f>;

  alignas(FastVectorVector3fType) unsigned char gFastVectorVector3fTypeStorage[sizeof(FastVectorVector3fType)]{};
  bool gFastVectorVector3fTypeConstructed = false;

  msvc8::string gFastVectorVector3fTypeName;
  bool gFastVectorVector3fTypeNameCleanupRegistered = false;

  [[nodiscard]] FastVectorVector3fType* AcquireFastVectorVector3fType()
  {
    if (!gFastVectorVector3fTypeConstructed) {
      new (gFastVectorVector3fTypeStorage) FastVectorVector3fType();
      gFastVectorVector3fTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorVector3fType*>(gFastVectorVector3fTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kEntIdTypeCandidates[] = {"EntId", "Moho::EntId", "int", "signed int"};
      for (const char* const candidate : kEntIdTypeCandidates) {
        if (!candidate) {
          continue;
        }

        cached = gpg::REF_FindTypeNamed(candidate);
        if (cached != nullptr) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(int));
      }
    }

    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSOCellPosType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SOCellPos));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSSTIEntityAttachInfoType()
  {
    gpg::RType* type = moho::SSTIEntityAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SSTIEntityAttachInfo));
      moho::SSTIEntityAttachInfo::sType = type;
    }
    return type;
  }

  msvc8::string gFastVectorEntIdTypeName;
  bool gFastVectorEntIdTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSOCellPosTypeName;
  bool gFastVectorSOCellPosTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSSTIEntityAttachInfoTypeName;
  bool gFastVectorSSTIEntityAttachInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorUnitWeaponInfoTypeName;
  bool gFastVectorUnitWeaponInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSOffsetInfoTypeName;
  bool gFastVectorSOffsetInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSAssignedLocInfoTypeName;
  bool gFastVectorSAssignedLocInfoTypeNameCleanupRegistered = false;

  void cleanup_FastVectorEntIdTypeName()
  {
    gFastVectorEntIdTypeName = msvc8::string{};
    gFastVectorEntIdTypeNameCleanupRegistered = false;
  }

  void cleanup_FastVectorSOCellPosTypeName()
  {
    gFastVectorSOCellPosTypeName = msvc8::string{};
    gFastVectorSOCellPosTypeNameCleanupRegistered = false;
  }

  void cleanup_FastVectorSSTIEntityAttachInfoTypeName()
  {
    gFastVectorSSTIEntityAttachInfoTypeName = msvc8::string{};
    gFastVectorSSTIEntityAttachInfoTypeNameCleanupRegistered = false;
  }

  void cleanup_FastVectorUnitWeaponInfoTypeName()
  {
    gFastVectorUnitWeaponInfoTypeName = msvc8::string{};
    gFastVectorUnitWeaponInfoTypeNameCleanupRegistered = false;
  }

  void cleanup_FastVectorSOffsetInfoTypeName()
  {
    gFastVectorSOffsetInfoTypeName = msvc8::string{};
    gFastVectorSOffsetInfoTypeNameCleanupRegistered = false;
  }

  void cleanup_FastVectorSAssignedLocInfoTypeName()
  {
    gFastVectorSAssignedLocInfoTypeName = msvc8::string{};
    gFastVectorSAssignedLocInfoTypeNameCleanupRegistered = false;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponInfoType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::UnitWeaponInfo");
      if (!cached) {
        cached = gpg::LookupRType(typeid(int));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSOffsetInfoTypeCompat()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::SOffsetInfo");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::SUnitOffsetInfo");
      }
      if (!cached) {
        cached = gpg::LookupRType(typeid(int));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoTypeCompat()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::SAssignedLocInfo");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::SFormationOccupiedSlot");
      }
      if (!cached) {
        cached = gpg::LookupRType(typeid(int));
      }
    }
    return cached;
  }

  /**
   * Address: 0x00552E70 (FUN_00552E70, gpg::RFastVectorType_EntId::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<EntId>` type name.
   */
  [[maybe_unused]] const char* GetFastVectorEntIdTypeName()
  {
    if (gFastVectorEntIdTypeName.empty()) {
      gpg::RType* const elementType = CachedEntIdType();
      const char* const elementName = elementType ? elementType->GetName() : "EntId";
      gFastVectorEntIdTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "EntId");
      if (!gFastVectorEntIdTypeNameCleanupRegistered) {
        gFastVectorEntIdTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorEntIdTypeName);
      }
    }
    return gFastVectorEntIdTypeName.c_str();
  }

  /**
   * Address: 0x00553050 (FUN_00553050, gpg::RFastVectorType_SOCellPos::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<SOCellPos>` type name.
   */
  [[maybe_unused]] const char* GetFastVectorSOCellPosTypeName()
  {
    if (gFastVectorSOCellPosTypeName.empty()) {
      gpg::RType* const elementType = CachedSOCellPosType();
      const char* const elementName = elementType ? elementType->GetName() : "SOCellPos";
      gFastVectorSOCellPosTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SOCellPos");
      if (!gFastVectorSOCellPosTypeNameCleanupRegistered) {
        gFastVectorSOCellPosTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSOCellPosTypeName);
      }
    }
    return gFastVectorSOCellPosTypeName.c_str();
  }

  /**
   * Address: 0x00558C30 (FUN_00558C30, gpg::RFastVectorType_SSTIEntityAttachInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected
   * `fastvector<SSTIEntityAttachInfo>` type name.
   */
  [[maybe_unused]] const char* GetFastVectorSSTIEntityAttachInfoTypeName()
  {
    if (gFastVectorSSTIEntityAttachInfoTypeName.empty()) {
      gpg::RType* const elementType = CachedSSTIEntityAttachInfoType();
      const char* const elementName = elementType ? elementType->GetName() : "SSTIEntityAttachInfo";
      gFastVectorSSTIEntityAttachInfoTypeName = gpg::STR_Printf(
        "fastvector<%s>",
        elementName ? elementName : "SSTIEntityAttachInfo"
      );
      if (!gFastVectorSSTIEntityAttachInfoTypeNameCleanupRegistered) {
        gFastVectorSSTIEntityAttachInfoTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSSTIEntityAttachInfoTypeName);
      }
    }
    return gFastVectorSSTIEntityAttachInfoTypeName.c_str();
  }

  /**
   * Address: 0x0055CBF0 (FUN_0055CBF0, gpg::RFastVectorType_UnitWeaponInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<UnitWeaponInfo>` type
   * name.
   */
  [[maybe_unused]] const char* GetFastVectorUnitWeaponInfoTypeName()
  {
    if (gFastVectorUnitWeaponInfoTypeName.empty()) {
      gpg::RType* const elementType = CachedUnitWeaponInfoType();
      const char* const elementName = elementType ? elementType->GetName() : "UnitWeaponInfo";
      gFastVectorUnitWeaponInfoTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "UnitWeaponInfo");
      if (!gFastVectorUnitWeaponInfoTypeNameCleanupRegistered) {
        gFastVectorUnitWeaponInfoTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorUnitWeaponInfoTypeName);
      }
    }
    return gFastVectorUnitWeaponInfoTypeName.c_str();
  }

  /**
   * Address: 0x0056C020 (FUN_0056C020, gpg::RFastVectorType_SOffsetInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<SOffsetInfo>` type
   * name.
   */
  [[maybe_unused]] const char* GetFastVectorSOffsetInfoTypeName()
  {
    if (gFastVectorSOffsetInfoTypeName.empty()) {
      gpg::RType* const elementType = CachedSOffsetInfoTypeCompat();
      const char* const elementName = elementType ? elementType->GetName() : "SOffsetInfo";
      gFastVectorSOffsetInfoTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SOffsetInfo");
      if (!gFastVectorSOffsetInfoTypeNameCleanupRegistered) {
        gFastVectorSOffsetInfoTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSOffsetInfoTypeName);
      }
    }
    return gFastVectorSOffsetInfoTypeName.c_str();
  }

  /**
   * Address: 0x0056C240 (FUN_0056C240, gpg::RFastVectorType_SAssignedLocInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<SAssignedLocInfo>` type
   * name.
   */
  [[maybe_unused]] const char* GetFastVectorSAssignedLocInfoTypeName()
  {
    if (gFastVectorSAssignedLocInfoTypeName.empty()) {
      gpg::RType* const elementType = CachedSAssignedLocInfoTypeCompat();
      const char* const elementName = elementType ? elementType->GetName() : "SAssignedLocInfo";
      gFastVectorSAssignedLocInfoTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SAssignedLocInfo");
      if (!gFastVectorSAssignedLocInfoTypeNameCleanupRegistered) {
        gFastVectorSAssignedLocInfoTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSAssignedLocInfoTypeName);
      }
    }
    return gFastVectorSAssignedLocInfoTypeName.c_str();
  }

  void cleanup_FastVectorVector3fTypeName()
  {
    gFastVectorVector3fTypeName = msvc8::string{};
    gFastVectorVector3fTypeNameCleanupRegistered = false;
  }

  void FastVectorVector3fResize(const Wm3::Vector3f* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<Wm3::Vector3f>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  void FastVectorSOCellPosResize(const moho::SOCellPos* fillValue, const unsigned int newSize, void* objectStorage)
  {
    auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  /**
   * Address: 0x00558EC0 (FUN_00558EC0, gpg::fastvector_n1_SSTIEntityAttachInfo::resize_fill)
   *
   * What it does:
   * Resizes one runtime `fastvector<moho::SSTIEntityAttachInfo>` lane and
   * fills appended elements from `*fillValue`.
   */
  void FastVectorSSTIEntityAttachInfoResize(
    const moho::SSTIEntityAttachInfo* fillValue,
    const unsigned int newSize,
    void* objectStorage
  )
  {
    auto& view = gpg::AsFastVectorRuntimeView<moho::SSTIEntityAttachInfo>(objectStorage);
    gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
  }

  /**
   * Address: 0x00515FF0 (FUN_00515FF0, gpg::RFastVectorType_Vector3f::SerLoad)
   *
   * What it does:
   * Reads serialized count for one reflected `fastvector<Wm3::Vector3f>`,
   * resizes backing storage with zeroed fill lanes, then deserializes each
   * element through `ReadArchive::Read`.
   */
  void LoadFastVectorVector3f(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    const Wm3::Vector3f fill{};
    FastVectorVector3fResize(&fill, count, storage);

    auto& view = gpg::AsFastVectorRuntimeView<Wm3::Vector3f>(storage);
    gpg::RType* const vector3Type = CachedVector3fType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(vector3Type, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x005535B0 (FUN_005535B0, gpg::RFastVectorType_EntId::SerLoad)
   *
   * What it does:
   * Reads serialized lane count for one reflected `fastvector<EntId>`,
   * resizes storage with invalid-id sentinel fill, then deserializes each lane
   * through `ReadArchive::Read`.
   */
  [[maybe_unused]] void LoadFastVectorEntId(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    constexpr unsigned int kInvalidEntIdFill = 0xF0000000u;
    FastVectorUIntResize(&kInvalidEntIdFill, count, storage);

    gpg::RType* const entIdType = CachedEntIdType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(entIdType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x005536A0 (FUN_005536A0, gpg::RFastVectorType_SOCellPos::SerLoad)
   *
   * What it does:
   * Reads count for one reflected `fastvector<moho::SOCellPos>`, resizes with
   * invalid-cell sentinel fill (`-32768,-32768`), then deserializes each lane
   * through `ReadArchive::Read`.
   */
  [[maybe_unused]] void LoadFastVectorSOCellPos(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    constexpr moho::SOCellPos fill{-32768, -32768};
    FastVectorSOCellPosResize(&fill, count, storage);

    gpg::RType* const soCellPosType = CachedSOCellPosType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(soCellPosType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00558F80 (FUN_00558F80, gpg::RFastVectorType_SSTIEntityAttachInfo::SerLoad)
   *
   * What it does:
   * Reads count for one reflected `fastvector<moho::SSTIEntityAttachInfo>`,
   * resizes with invalid-id sentinel fill (`0xF0000000`), then deserializes
   * each lane through `ReadArchive::Read`.
   */
  [[maybe_unused]] void LoadFastVectorSSTIEntityAttachInfo(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::SSTIEntityAttachInfo fill{};
    fill.mPlaceholderState = 0xF0000000u;
    FastVectorSSTIEntityAttachInfoResize(&fill, count, storage);

    gpg::RType* const attachInfoType = CachedSSTIEntityAttachInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<moho::SSTIEntityAttachInfo>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(attachInfoType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00516080 (FUN_00516080, gpg::RFastVectorType_Vector3f::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<Wm3::Vector3f>` payload as archive count
   * plus per-lane `WriteArchive::Write` serialization.
   */
  void SaveFastVectorVector3f(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<Wm3::Vector3f>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const vector3Type = CachedVector3fType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(vector3Type, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00553630 (FUN_00553630, gpg::RFastVectorType_EntId::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<EntId>` payload as archive count plus
   * per-lane reflected `EntId` serialization.
   */
  [[maybe_unused]] void SaveFastVectorEntId(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
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

    gpg::RType* const entIdType = CachedEntIdType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(entIdType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00553720 (FUN_00553720, gpg::RFastVectorType_SOCellPos::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<moho::SOCellPos>` payload as archive
   * count plus per-lane reflected `SOCellPos` serialization.
   */
  [[maybe_unused]] void SaveFastVectorSOCellPos(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const soCellPosType = CachedSOCellPosType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(soCellPosType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00559000 (FUN_00559000, gpg::RFastVectorType_SSTIEntityAttachInfo::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<moho::SSTIEntityAttachInfo>` payload as
   * archive count plus per-lane reflected attach-info serialization.
   */
  [[maybe_unused]] void SaveFastVectorSSTIEntityAttachInfo(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SSTIEntityAttachInfo>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const attachInfoType = CachedSSTIEntityAttachInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(attachInfoType, view.ElementAtUnchecked(i), owner);
    }
  }
} // namespace

gpg::RType* gpg::ResolveFastVectorUIntType()
{
  return gpg::LookupRType(typeid(gpg::fastvector<unsigned int>));
}

/**
 * Address: 0x00BC2D40 (FUN_00BC2D40, register_RFastVectorType_uint)
 *
 * What it does:
 * Materializes startup reflection storage for `fastvector<unsigned int>` and
 * registers process-exit teardown.
 */
void gpg::register_RFastVectorType_uint()
{
  (void)gFastVectorUIntType;
  (void)std::atexit(&cleanup_RFastVectorType_uint);
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
  * Alias of FUN_0065AA60 (non-canonical helper lane).
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
 * Address: 0x006599E0 (FUN_006599E0, gpg::RFastVectorType_float::GetName)
 *
 * What it does:
 * Lazily builds and caches `fastvector<element>` reflection text using the
 * resolved `float` type name.
 */
const char* gpg::RFastVectorType<float>::GetName() const
{
  if (gFastVectorFloatTypeName.empty()) {
    gpg::RType* const elementType = CachedFloatType();
    const char* const elementName = elementType ? elementType->GetName() : "float";
    gFastVectorFloatTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "float");
    if (!gFastVectorFloatTypeNameCleanupRegistered) {
      gFastVectorFloatTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorFloatTypeName);
    }
  }

  return gFastVectorFloatTypeName.c_str();
}

/**
 * Address: 0x00659AA0 (FUN_00659AA0, gpg::RFastVectorType_float::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `fastvector<float>` instance.
 */
msvc8::string gpg::RFastVectorType<float>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00659B30 (FUN_00659B30, gpg::RFastVectorType_float::IsIndexed)
 *
 * What it does:
 * Returns this indexed-interface lane for `fastvector<float>` reflection.
 */
const gpg::RIndexed* gpg::RFastVectorType<float>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00659A80 (FUN_00659A80, gpg::RFastVectorType_float::Init)
 *
 * What it does:
 * Configures reflected element size/version and binds float fastvector
 * serializer callbacks.
 */
void gpg::RFastVectorType<float>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorFloat;
  serSaveFunc_ = &SaveFastVectorFloat;
}

/**
 * Address: 0x00659B80 (FUN_00659B80, gpg::RFastVectorType_float::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<float>[ind]`.
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
 * Address: 0x00659B40 (FUN_00659B40, gpg::RFastVectorType_float::GetCount)
 *
 * What it does:
 * Returns runtime element count for one reflected `fastvector<float>`.
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
 * Address: 0x00659B50 (FUN_00659B50, gpg::RFastVectorType_float::SetCount)
 *
 * What it does:
 * Resizes one reflected `fastvector<float>` and zero-fills new lanes.
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
 * Address: 0x0065A060 (FUN_0065A060, gpg::RFastVectorType_String::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected `fastvector<msvc8::string>` name and
 * registers process-exit cleanup for the cached string storage.
 */
const char* gpg::RFastVectorType<msvc8::string>::GetName() const
{
  if (gFastVectorStringTypeName.empty()) {
    const gpg::RType* const elementType = CachedStringType();
    const char* const elementName = elementType ? elementType->GetName() : "msvc8::string";
    gFastVectorStringTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "msvc8::string");
    if (!gFastVectorStringTypeNameCleanupRegistered) {
      gFastVectorStringTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorStringTypeName);
    }
  }

  return gFastVectorStringTypeName.c_str();
}

/**
 * Address: 0x0065A120 (FUN_0065A120, gpg::RFastVectorType_String::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `fastvector<msvc8::string>` instance.
 */
msvc8::string gpg::RFastVectorType<msvc8::string>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0065A1B0 (FUN_0065A1B0, gpg::RFastVectorType_String::IsIndexed)
 *
 * What it does:
 * Returns this indexed-interface lane for `fastvector<msvc8::string>`
 * reflection.
 */
const gpg::RIndexed* gpg::RFastVectorType<msvc8::string>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0065A100 (FUN_0065A100, gpg::RFastVectorType_String::Init)
 *
 * What it does:
 * Configures reflected element size/version and binds string fastvector
 * serializer callbacks.
 */
void gpg::RFastVectorType<msvc8::string>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorString;
  serSaveFunc_ = &SaveFastVectorString;
}

/**
 * Address: 0x0065A250 (FUN_0065A250, gpg::RFastVectorType_String::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<msvc8::string>[ind]`.
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
 * Address: 0x0065A1C0 (FUN_0065A1C0, gpg::RFastVectorType_String::GetCount)
 *
 * What it does:
 * Returns runtime element count for one reflected
 * `fastvector<msvc8::string>`.
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
 * Address: 0x0065A1E0 (FUN_0065A1E0, gpg::RFastVectorType_String::SetCount)
 *
 * What it does:
 * Resizes one reflected `fastvector<msvc8::string>` and default-fills new
 * lanes with empty strings.
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

namespace gpg
{
/**
  * Alias of FUN_005173B0 (non-canonical helper lane).
 *
 * What it does:
 * Constructs and preregisters startup RTTI descriptor for
 * `gpg::fastvector<Wm3::Vector3<float>>`.
 */
gpg::RType* preregister_FastVectorVector3fType()
{
  FastVectorVector3fType* const type = AcquireFastVectorVector3fType();
  gpg::PreRegisterRType(typeid(gpg::fastvector<Wm3::Vector3f>), type);
  return type;
}

/**
 * Address: 0x00BF2B80 (FUN_00BF2B80, cleanup_FastVectorVector3fType)
 *
 * What it does:
 * Process-exit teardown for startup-owned
 * `gpg::fastvector<Wm3::Vector3<float>>` descriptor storage.
 */
void cleanup_FastVectorVector3fType()
{
  if (!gFastVectorVector3fTypeConstructed) {
    return;
  }

  AcquireFastVectorVector3fType()->~FastVectorVector3fType();
  gFastVectorVector3fTypeConstructed = false;
}

/**
 * Address: 0x00BC84C0 (FUN_00BC84C0, register_FastVectorVector3fTypeAtexit)
 *
 * What it does:
 * Startup wrapper that preregisters `gpg::fastvector<Wm3::Vector3<float>>`
 * and installs process-exit teardown through `atexit`.
 */
int register_FastVectorVector3fTypeAtexit()
{
  (void)preregister_FastVectorVector3fType();
  return std::atexit(&cleanup_FastVectorVector3fType);
}
} // namespace gpg

/**
 * Address: 0x00515920 (FUN_00515920, gpg::RFastVectorType_Vector3f::GetName)
 *
 * What it does:
 * Builds and caches lexical reflection name `fastvector<element>` for
 * `gpg::fastvector<Wm3::Vector3f>`.
 */
const char* gpg::RFastVectorType<Wm3::Vector3f>::GetName() const
{
  if (gFastVectorVector3fTypeName.empty()) {
    const char* const elementName = CachedVector3fType() ? CachedVector3fType()->GetName() : "Vector3f";
    gFastVectorVector3fTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "Vector3f");
    if (!gFastVectorVector3fTypeNameCleanupRegistered) {
      gFastVectorVector3fTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorVector3fTypeName);
    }
  }

  return gFastVectorVector3fTypeName.c_str();
}

/**
 * Address: 0x005159E0 (FUN_005159E0, gpg::RFastVectorType_Vector3f::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `fastvector<Wm3::Vector3f>` instance.
 */
msvc8::string gpg::RFastVectorType<Wm3::Vector3f>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x005173B0 family
 */
const gpg::RIndexed* gpg::RFastVectorType<Wm3::Vector3f>::IsIndexed() const
{
  return this;
}

/**
  * Alias of FUN_005173B0 (non-canonical helper lane).
 */
void gpg::RFastVectorType<Wm3::Vector3f>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorVector3f;
  serSaveFunc_ = &SaveFastVectorVector3f;
}

/**
  * Alias of FUN_005173B0 (non-canonical helper lane).
 */
gpg::RRef gpg::RFastVectorType<Wm3::Vector3f>::SubscriptIndex(void* obj, const int ind) const
{
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(obj != nullptr);
  if (!obj) {
    gpg::RRef out{};
    out.mType = CachedVector3fType();
    out.mObj = nullptr;
    return out;
  }

  auto& view = gpg::AsFastVectorRuntimeView<Wm3::Vector3f>(obj);
  GPG_ASSERT(view.Data() != nullptr);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  out.mType = CachedVector3fType();
  if (ind < 0 || !view.Data() || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    out.mObj = nullptr;
    return out;
  }

  out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
  return out;
}

/**
  * Alias of FUN_005173B0 (non-canonical helper lane).
 */
size_t gpg::RFastVectorType<Wm3::Vector3f>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<Wm3::Vector3f>(obj);
  if (!view.Data()) {
    return 0u;
  }
  return view.Size();
}

/**
 * Address: 0x00515F40 (FUN_00515F40, gpg::RFastVectorType_Vector3f::SetCount)
 *
 * What it does:
 * Resizes one reflected `fastvector<Wm3::Vector3f>` lane and zero-fills
 * appended elements.
 */
void gpg::RFastVectorType<Wm3::Vector3f>::SetCount(void* obj, const int count) const
{
  GPG_ASSERT(obj != nullptr);
  GPG_ASSERT(count >= 0);
  if (!obj || count < 0) {
    return;
  }

  const Wm3::Vector3f fill{};
  FastVectorVector3fResize(&fill, static_cast<unsigned int>(count), obj);
}

namespace
{
  struct FastVectorUIntReflectionBootstrap
  {
    FastVectorUIntReflectionBootstrap()
    {
      gpg::register_RFastVectorType_uint();
    }
  };

  [[maybe_unused]] FastVectorUIntReflectionBootstrap gFastVectorUIntReflectionBootstrap;

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

  struct FastVectorVector3fReflectionBootstrap
  {
    FastVectorVector3fReflectionBootstrap()
    {
      (void)gpg::register_FastVectorVector3fTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorVector3fReflectionBootstrap gFastVectorVector3fReflectionBootstrap;
} // namespace

