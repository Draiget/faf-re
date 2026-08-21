#include "gpg/core/containers/FastVectorUIntReflection.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/core/Unit.h"
#include "Wm3Vector3.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * VFTABLE: 0x00E17F2C (primary, 11 slots) / 0x00E17F5C (RIndexed subobject @ +0x64, 4 slots)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::SSTIEntityAttachInfo>`.
   * The element is a bare 4-byte entity id, so `GetCount` divides the byte span
   * by 4 with a shift rather than a reciprocal multiply.
   */
  template <>
  class RFastVectorType<moho::SSTIEntityAttachInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00559650 (FUN_00559650, gpg::RFastVectorType_SSTIEntityAttachInfo::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x00558C30 (FUN_00558C30, gpg::RFastVectorType_SSTIEntityAttachInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00558CF0 (FUN_00558CF0, gpg::RFastVectorType_SSTIEntityAttachInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00558D80 (FUN_00558D80, gpg::RFastVectorType_SSTIEntityAttachInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00558CD0 (FUN_00558CD0, gpg::RFastVectorType_SSTIEntityAttachInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x00558DD0 (FUN_00558DD0, gpg::RFastVectorType_SSTIEntityAttachInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00558D90 (FUN_00558D90, gpg::RFastVectorType_SSTIEntityAttachInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00558DA0 (FUN_00558DA0, gpg::RFastVectorType_SSTIEntityAttachInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SSTIEntityAttachInfo>) == 0x68,
    "RFastVectorType<Moho::SSTIEntityAttachInfo> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E1882C (primary, 11 slots) / 0x00E1885C (RIndexed subobject @ +0x64, 4 slots)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::UnitWeaponInfo>`.
   * `sizeof(UnitWeaponInfo)` is 0x98, so `GetCount` divides the byte span by
   * 152 through the compiler's reciprocal-multiply sequence
   * (`imul 6BCA1AF3h; sar edx,6`) at 0x0055CD59.
   */
  template <>
  class RFastVectorType<moho::UnitWeaponInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0055EAF0 (FUN_0055EAF0, gpg::RFastVectorType_UnitWeaponInfo::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x0055CBF0 (FUN_0055CBF0, gpg::RFastVectorType_UnitWeaponInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055CCB0 (FUN_0055CCB0, gpg::RFastVectorType_UnitWeaponInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0055CD40 (FUN_0055CD40, gpg::RFastVectorType_UnitWeaponInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0055CC90 (FUN_0055CC90, gpg::RFastVectorType_UnitWeaponInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0055CDE0 (FUN_0055CDE0, gpg::RFastVectorType_UnitWeaponInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0055CD50 (FUN_0055CD50, gpg::RFastVectorType_UnitWeaponInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0055CD70 (FUN_0055CD70, gpg::RFastVectorType_UnitWeaponInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::UnitWeaponInfo>) == 0x68,
    "RFastVectorType<Moho::UnitWeaponInfo> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E1904C (primary, 11 slots) / 0x00E1907C (RIndexed subobject @ +0x64, 4 slots)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::SOffsetInfo>`.
   * `Moho::SOffsetInfo` is the RTTI name for the formation lane entry (also
   * aliased `moho::SFormationLaneEntry` in CAiFormationInstance.h); it is
   * 0x4C bytes, so `GetCount` divides the byte span by 76.
   */
  template <>
  class RFastVectorType<moho::SOffsetInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005720E0 (FUN_005720E0, gpg::RFastVectorType_SOffsetInfo::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x0056C020 (FUN_0056C020, gpg::RFastVectorType_SOffsetInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0056C0E0 (FUN_0056C0E0, gpg::RFastVectorType_SOffsetInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0056C170 (FUN_0056C170, gpg::RFastVectorType_SOffsetInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0056C0C0 (FUN_0056C0C0, gpg::RFastVectorType_SOffsetInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0056C200 (FUN_0056C200, gpg::RFastVectorType_SOffsetInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0056C180 (FUN_0056C180, gpg::RFastVectorType_SOffsetInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0056C1A0 (FUN_0056C1A0, gpg::RFastVectorType_SOffsetInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SOffsetInfo>) == 0x68,
    "RFastVectorType<Moho::SOffsetInfo> size must be 0x68"
  );

  /**
   * VFTABLE: 0x00E19090 (primary, 11 slots) / 0x00E190C0 (RIndexed subobject @ +0x64, 4 slots)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::SAssignedLocInfo>`.
   * The element (`SAssignedLocInfo`, aliased `moho::SFormationOccupiedSlot`)
   * is a trivially-copyable 0x10-byte POD (2D position + footprint size +
   * lane token), so `GetCount` divides the byte span by 16 with a shift.
   */
  template <>
  class RFastVectorType<moho::SAssignedLocInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00572140 (FUN_00572140, gpg::RFastVectorType_SAssignedLocInfo::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x0056C240 (FUN_0056C240, gpg::RFastVectorType_SAssignedLocInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0056C300 (FUN_0056C300, gpg::RFastVectorType_SAssignedLocInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0056C390 (FUN_0056C390, gpg::RFastVectorType_SAssignedLocInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0056C2E0 (FUN_0056C2E0, gpg::RFastVectorType_SAssignedLocInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0056C3F0 (FUN_0056C3F0, gpg::RFastVectorType_SAssignedLocInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0056C3A0 (FUN_0056C3A0, gpg::RFastVectorType_SAssignedLocInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0056C3B0 (FUN_0056C3B0, gpg::RFastVectorType_SAssignedLocInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SAssignedLocInfo>) == 0x68,
    "RFastVectorType<Moho::SAssignedLocInfo> size must be 0x68"
  );

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
    /**
     * Address: 0x00517510 (FUN_00517510, gpg::RFastVectorType_Vector3f::dtr)
     */
    ~RFastVectorType() override;

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
    gpg::FastVectorUIntResize(&fill, count, storage);

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

  using FastVectorSSTIEntityAttachInfoType = gpg::RFastVectorType<moho::SSTIEntityAttachInfo>;
  using FastVectorUnitWeaponInfoType = gpg::RFastVectorType<moho::UnitWeaponInfo>;

  /**
   * Address: 0x01104CC8 (`gpg::RFastVectorType<Moho::SSTIEntityAttachInfo>` descriptor storage)
   *
   * The binary places this descriptor in `.data` and builds it in-place from
   * FUN_00559580; the RIndexed sub-object vtable lands at 0x01104D2C, i.e.
   * storage + 0x64.
   */
  alignas(FastVectorSSTIEntityAttachInfoType)
    unsigned char gFastVectorSSTIEntityAttachInfoTypeStorage[sizeof(FastVectorSSTIEntityAttachInfoType)]{};
  bool gFastVectorSSTIEntityAttachInfoTypeConstructed = false;

  /**
   * Address: 0x01104D98 (`gpg::RFastVectorType<Moho::UnitWeaponInfo>` descriptor storage)
   *
   * Built in-place from FUN_0055E9B0; the RIndexed sub-object vtable lands at
   * 0x01104DFC, i.e. storage + 0x64.
   */
  alignas(FastVectorUnitWeaponInfoType)
    unsigned char gFastVectorUnitWeaponInfoTypeStorage[sizeof(FastVectorUnitWeaponInfoType)]{};
  bool gFastVectorUnitWeaponInfoTypeConstructed = false;

  [[nodiscard]] FastVectorSSTIEntityAttachInfoType* AcquireFastVectorSSTIEntityAttachInfoType()
  {
    if (!gFastVectorSSTIEntityAttachInfoTypeConstructed) {
      new (gFastVectorSSTIEntityAttachInfoTypeStorage) FastVectorSSTIEntityAttachInfoType();
      gFastVectorSSTIEntityAttachInfoTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorSSTIEntityAttachInfoType*>(gFastVectorSSTIEntityAttachInfoTypeStorage);
  }

  [[nodiscard]] FastVectorUnitWeaponInfoType* AcquireFastVectorUnitWeaponInfoType()
  {
    if (!gFastVectorUnitWeaponInfoTypeConstructed) {
      new (gFastVectorUnitWeaponInfoTypeStorage) FastVectorUnitWeaponInfoType();
      gFastVectorUnitWeaponInfoTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorUnitWeaponInfoType*>(gFastVectorUnitWeaponInfoTypeStorage);
  }

  using FastVectorSOffsetInfoType = gpg::RFastVectorType<moho::SOffsetInfo>;
  using FastVectorSAssignedLocInfoType = gpg::RFastVectorType<moho::SAssignedLocInfo>;

  /**
   * Address: 0x01104FA0 (`gpg::RFastVectorType<Moho::SOffsetInfo>` descriptor storage)
   *
   * Built in-place from FUN_00571C00; the RIndexed sub-object vtable lands at
   * 0x01105004, i.e. storage + 0x64.
   */
  alignas(FastVectorSOffsetInfoType)
    unsigned char gFastVectorSOffsetInfoTypeStorage[sizeof(FastVectorSOffsetInfoType)]{};
  bool gFastVectorSOffsetInfoTypeConstructed = false;

  /**
   * Address: 0x01104ED0 (`gpg::RFastVectorType<Moho::SAssignedLocInfo>` descriptor storage)
   *
   * Built in-place from FUN_00571C70; the RIndexed sub-object vtable lands at
   * 0x01104F34, i.e. storage + 0x64.
   */
  alignas(FastVectorSAssignedLocInfoType)
    unsigned char gFastVectorSAssignedLocInfoTypeStorage[sizeof(FastVectorSAssignedLocInfoType)]{};
  bool gFastVectorSAssignedLocInfoTypeConstructed = false;

  [[nodiscard]] FastVectorSOffsetInfoType* AcquireFastVectorSOffsetInfoType()
  {
    if (!gFastVectorSOffsetInfoTypeConstructed) {
      new (gFastVectorSOffsetInfoTypeStorage) FastVectorSOffsetInfoType();
      gFastVectorSOffsetInfoTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorSOffsetInfoType*>(gFastVectorSOffsetInfoTypeStorage);
  }

  [[nodiscard]] FastVectorSAssignedLocInfoType* AcquireFastVectorSAssignedLocInfoType()
  {
    if (!gFastVectorSAssignedLocInfoTypeConstructed) {
      new (gFastVectorSAssignedLocInfoTypeStorage) FastVectorSAssignedLocInfoType();
      gFastVectorSAssignedLocInfoTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorSAssignedLocInfoType*>(gFastVectorSAssignedLocInfoTypeStorage);
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

  // NOTE: CachedEntIdType() (the `Moho::EntId::sType`-equivalent name-keyed
  // RType cache) and the `RFastVectorType<Moho::EntId>` SerLoad/SerSave
  // callbacks that used it now live in FastVectorEntIdReflection.cpp, next to
  // the class they serve.

  // NOTE: CachedSOCellPosType() (the `Moho::SOCellPos::sType` cache) and the
  // `RFastVectorType<Moho::SOCellPos>` SerLoad/SerSave callbacks that used it
  // now live in FastVectorSOCellPosReflection.cpp, next to the class they
  // serve.

  /**
   * Invalid-`EntId` sentinel the binary fills appended
   * `fastvector<SSTIEntityAttachInfo>` lanes with. `SSTIEntityAttachInfo` is a
   * bare 4-byte entity id, so a freshly grown lane is stamped "no entity"
   * rather than zeroed -- id 0 is a legal entity. Seen as the immediate
   * `0F0000000h` at 0x00558DAF (`SetCount`) and 0x00558FA4 (`SerLoad`).
   */
  constexpr std::int32_t kInvalidAttachedEntityId = static_cast<std::int32_t>(0xF0000000u);

  [[nodiscard]] gpg::RType* CachedSSTIEntityAttachInfoType()
  {
    gpg::RType* type = moho::SSTIEntityAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SSTIEntityAttachInfo));
      moho::SSTIEntityAttachInfo::sType = type;
    }
    return type;
  }

  msvc8::string gFastVectorSSTIEntityAttachInfoTypeName;
  bool gFastVectorSSTIEntityAttachInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorUnitWeaponInfoTypeName;
  bool gFastVectorUnitWeaponInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSOffsetInfoTypeName;
  bool gFastVectorSOffsetInfoTypeNameCleanupRegistered = false;
  msvc8::string gFastVectorSAssignedLocInfoTypeName;
  bool gFastVectorSAssignedLocInfoTypeNameCleanupRegistered = false;

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

  /**
   * Element-type cache for `SOffsetInfo`, mirroring the binary's
   * `Moho::SOffsetInfo::sType` global (0x010C6F6C).
   */
  [[nodiscard]] gpg::RType* CachedSOffsetInfoTypeCompat()
  {
    gpg::RType* type = moho::SOffsetInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SOffsetInfo));
      moho::SOffsetInfo::sType = type;
    }
    return type;
  }

  /**
   * Element-type cache for `SAssignedLocInfo`, mirroring the binary's
   * `Moho::SAssignedLocInfo::sType` global.
   */
  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoTypeCompat()
  {
    gpg::RType* type = moho::SAssignedLocInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SAssignedLocInfo));
      moho::SAssignedLocInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00558C30 (FUN_00558C30, gpg::RFastVectorType_SSTIEntityAttachInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected
   * `fastvector<SSTIEntityAttachInfo>` type name.
   */
  const char* GetFastVectorSSTIEntityAttachInfoTypeName()
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
  const char* GetFastVectorUnitWeaponInfoTypeName()
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
   * Address: 0x0055CD70 (FUN_0055CD70, gpg::RFastVectorType_UnitWeaponInfo::SetCount)
   *
   * IDA signature:
   * void __stdcall gpg::RFastVectorType_UnitWeaponInfo::SetCount(
   *   gpg::fastvector_n1_UnitWeaponInfo *vector, unsigned int count);
   *
   * What it does:
   * `RIndexed::SetCount` slot of the `fastvector<UnitWeaponInfo>` reflection
   * descriptor. Default-constructs one prototype, resizes the reflected vector
   * to `count` -- copy-constructing appended entries from that prototype and
   * destroying trimmed ones -- then tears the prototype down. The prototype is
   * a real object rather than a zeroed blob because `UnitWeaponInfo` owns two
   * `EntityCategorySet` word vectors and two `msvc8::string` lanes.
   *
   * The retail body reaches the resize through the per-`UnitWeaponInfo`
   * emissions of the shared fastvector resize template (FUN_0055D260 and its
   * copy-assign / relocate lanes); recovered source calls that shared template
   * directly, which is the canonical per-T form for these emissions.
   */
  void SetFastVectorUnitWeaponInfoCount(void* const vector, const int count)
  {
    moho::UnitWeaponInfo fill;
    gpg::FastVectorRuntimeResizeFill<moho::UnitWeaponInfo>(
      &fill,
      static_cast<unsigned int>(count),
      gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(vector)
    );
  }

  /**
   * Address: 0x0056C020 (FUN_0056C020, gpg::RFastVectorType_SOffsetInfo::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<SOffsetInfo>` type
   * name.
   */
  const char* GetFastVectorSOffsetInfoTypeName()
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
  const char* GetFastVectorSAssignedLocInfoTypeName()
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
   * Address: 0x00558F80 (FUN_00558F80, gpg::RFastVectorType_SSTIEntityAttachInfo::SerLoad)
   *
   * What it does:
   * Reads count for one reflected `fastvector<moho::SSTIEntityAttachInfo>`,
   * resizes with invalid-id sentinel fill (`0xF0000000`), then deserializes
   * each lane through `ReadArchive::Read`.
   */
  void LoadFastVectorSSTIEntityAttachInfo(
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
    fill.mAttachedEntityId = kInvalidAttachedEntityId;
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
   * Address: 0x00559000 (FUN_00559000, gpg::RFastVectorType_SSTIEntityAttachInfo::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<moho::SSTIEntityAttachInfo>` payload as
   * archive count plus per-lane reflected attach-info serialization.
   */
  void SaveFastVectorSSTIEntityAttachInfo(
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

  /**
   * Address: 0x0055D4C0 (FUN_0055D4C0, gpg::RFastVectorType_UnitWeaponInfo::SerLoad)
   *
   * IDA signature:
   * void __cdecl sub_55D4C0(gpg::ReadArchive *a1, gpg::fastvector_n1_UnitWeaponInfo *a2,
   *                         int a3, gpg::RRef *a6);
   *
   * What it does:
   * Reads the serialized lane count, grows the reflected
   * `fastvector<UnitWeaponInfo>` to that count -- copy-filling appended lanes
   * from a freshly default-constructed prototype -- then deserializes each lane
   * through `ReadArchive::Read`.
   *
   * The prototype is a real object rather than a zeroed blob because
   * `UnitWeaponInfo` owns two `EntityCategorySet` word vectors and two
   * `msvc8::string` lanes; the retail body constructs it at 0x0055D4F7 and
   * destroys it at 0x0055D523, immediately after the resize at 0x0055D50F and
   * before the read loop.
   */
  void LoadFastVectorUnitWeaponInfo(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    {
      moho::UnitWeaponInfo fill;
      gpg::FastVectorRuntimeResizeFill<moho::UnitWeaponInfo>(
        &fill,
        count,
        gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(storage)
      );
    }

    gpg::RType* const weaponInfoType = CachedUnitWeaponInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(weaponInfoType, view.ElementAtUnchecked(i), owner);
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
 * Address: 0x004022D0 (FUN_004022D0, gpg::fastvector_uint_resize)
 * Address: 0x00553480 (FUN_00553480, ICF twin)
 *
 * What it does:
 * Resizes reflected dword-array fastvector storage and fills newly appended
 * lanes with `*fillValue`.
 */
void gpg::FastVectorUIntResize(const unsigned int* fillValue, const unsigned int newSize, void* objectStorage)
{
  auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(objectStorage);
  gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
}

/**
 * Address: 0x005532F0 (FUN_005532F0)
 *
 * What it does:
 * Resizes reflected `moho::SOCellPos` fastvector storage and fills newly
 * appended lanes with `*fillValue`.
 */
void gpg::FastVectorSOCellPosResize(const moho::SOCellPos* fillValue, const unsigned int newSize, void* objectStorage)
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(objectStorage);
  gpg::FastVectorRuntimeResizeFill(fillValue, newSize, view);
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
  gpg::FastVectorUIntResize(&fill, static_cast<unsigned int>(count), obj);
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

// ---------------------------------------------------------------------------
// gpg::RFastVectorType<Moho::SSTIEntityAttachInfo>
//
// Descriptor storage 0x01104CC8, built in place by FUN_00559580. Slot map from
// the RTTI dump: primary vftable 0x00E17F2C (dtr@2, GetName@3, GetLexical@4,
// IsIndexed@6, Init@9), RIndexed vftable 0x00E17F5C at subobject offset 100
// (SubscriptIndex@0, GetCount@1, SetCount@2, AssignPointer@3 = base 0x00401320).
// ---------------------------------------------------------------------------

namespace gpg
{
  /**
   * Address: 0x00559580 (FUN_00559580, preregister_RFastVectorType_SSTIEntityAttachInfo)
   *
   * What it does:
   * Constructs the static `RFastVectorType<Moho::SSTIEntityAttachInfo>`
   * descriptor in place -- the retail body inlines the default constructor as
   * `RType::RType()` plus the two vtable-pointer stores -- and preregisters it
   * under `typeid(gpg::fastvector<Moho::SSTIEntityAttachInfo>)`.
   */
  gpg::RType* preregister_FastVectorSSTIEntityAttachInfoType()
  {
    FastVectorSSTIEntityAttachInfoType* const type = AcquireFastVectorSSTIEntityAttachInfoType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::SSTIEntityAttachInfo>), type);
    return type;
  }

  void cleanup_FastVectorSSTIEntityAttachInfoType()
  {
    if (!gFastVectorSSTIEntityAttachInfoTypeConstructed) {
      return;
    }

    AcquireFastVectorSSTIEntityAttachInfoType()->~FastVectorSSTIEntityAttachInfoType();
    gFastVectorSSTIEntityAttachInfoTypeConstructed = false;
  }

  int register_FastVectorSSTIEntityAttachInfoTypeAtexit()
  {
    (void)preregister_FastVectorSSTIEntityAttachInfoType();
    return std::atexit(&cleanup_FastVectorSSTIEntityAttachInfoType);
  }
} // namespace gpg

/**
 * Address: 0x00559650 (FUN_00559650, gpg::RFastVectorType_SSTIEntityAttachInfo::dtr)
 */
gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::~RFastVectorType() = default;

/**
 * Address: 0x00558C30 (FUN_00558C30, gpg::RFastVectorType_SSTIEntityAttachInfo::GetName)
 */
const char* gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::GetName() const
{
  return GetFastVectorSSTIEntityAttachInfoTypeName();
}

/**
 * Address: 0x00558CF0 (FUN_00558CF0, gpg::RFastVectorType_SSTIEntityAttachInfo::GetLexical)
 *
 * What it does:
 * Renders `"<base RType lexical>, size=<count>"`. The retail body reaches the
 * count by dispatching slot 1 of its own RIndexed sub-object vtable
 * (`[this+0x64] + 4`, called at 0x00558D3F with `this+0x64`), which is exactly
 * this class's `GetCount`.
 */
msvc8::string gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00558D80 (FUN_00558D80, gpg::RFastVectorType_SSTIEntityAttachInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00558CD0 (FUN_00558CD0, gpg::RFastVectorType_SSTIEntityAttachInfo::Init)
 */
void gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorSSTIEntityAttachInfo;
  serSaveFunc_ = &SaveFastVectorSSTIEntityAttachInfo;
}

/**
 * Address: 0x00558DD0 (FUN_00558DD0, gpg::RFastVectorType_SSTIEntityAttachInfo::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for
 * `fastvector<SSTIEntityAttachInfo>[ind]`. Element stride is 4 bytes
 * (`lea eax, [eax+ecx*4]`-equivalent `4 * a3` at 0x00558DD8); the retail body
 * performs no bounds or null check, so none is added here.
 */
gpg::RRef gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::SSTIEntityAttachInfo>(obj);
  gpg::RRef out{};
  gpg::RRef_SSTIEntityAttachInfo(&out, view.ElementAtUnchecked(static_cast<std::size_t>(ind)));
  return out;
}

/**
 * Address: 0x00558D90 (FUN_00558D90, gpg::RFastVectorType_SSTIEntityAttachInfo::GetCount)
 *
 * What it does:
 * Returns the lane count as `(end - begin) >> 2` -- a shift rather than a
 * reciprocal multiply, because `sizeof(SSTIEntityAttachInfo)` is 4.
 */
size_t gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<moho::SSTIEntityAttachInfo>(obj);
  return view.Size();
}

/**
 * Address: 0x00558DA0 (FUN_00558DA0, gpg::RFastVectorType_SSTIEntityAttachInfo::SetCount)
 *
 * What it does:
 * Resizes the reflected lane, stamping appended entries with the invalid-EntId
 * sentinel (`0F0000000h` at 0x00558DAF) rather than zero -- entity id 0 is a
 * legal id.
 */
void gpg::RFastVectorType<moho::SSTIEntityAttachInfo>::SetCount(void* obj, const int count) const
{
  moho::SSTIEntityAttachInfo fill{};
  fill.mAttachedEntityId = kInvalidAttachedEntityId;
  FastVectorSSTIEntityAttachInfoResize(&fill, static_cast<unsigned int>(count), obj);
}

// ---------------------------------------------------------------------------
// gpg::RFastVectorType<Moho::UnitWeaponInfo>
//
// Descriptor storage 0x01104D98, built in place by FUN_0055E9B0. Slot map from
// the RTTI dump: primary vftable 0x00E1882C (dtr@2, GetName@3, GetLexical@4,
// IsIndexed@6, Init@9), RIndexed vftable 0x00E1885C at subobject offset 100
// (SubscriptIndex@0, GetCount@1, SetCount@2, AssignPointer@3 = base 0x00401320).
// ---------------------------------------------------------------------------

namespace gpg
{
  /**
   * Address: 0x0055E9B0 (FUN_0055E9B0, preregister_RFastVectorType_UnitWeaponInfo)
   *
   * What it does:
   * Constructs the static `RFastVectorType<Moho::UnitWeaponInfo>` descriptor in
   * place -- the retail body inlines the default constructor as `RType::RType()`
   * (0x0055E9D2) plus the primary and RIndexed vtable-pointer stores
   * (0x0055E9E9 / 0x0055E9F3) -- and preregisters it under
   * `typeid(gpg::fastvector<Moho::UnitWeaponInfo>)` before returning it.
   */
  gpg::RType* preregister_FastVectorUnitWeaponInfoType()
  {
    FastVectorUnitWeaponInfoType* const type = AcquireFastVectorUnitWeaponInfoType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::UnitWeaponInfo>), type);
    return type;
  }

  void cleanup_FastVectorUnitWeaponInfoType()
  {
    if (!gFastVectorUnitWeaponInfoTypeConstructed) {
      return;
    }

    AcquireFastVectorUnitWeaponInfoType()->~FastVectorUnitWeaponInfoType();
    gFastVectorUnitWeaponInfoTypeConstructed = false;
  }

  int register_FastVectorUnitWeaponInfoTypeAtexit()
  {
    (void)preregister_FastVectorUnitWeaponInfoType();
    return std::atexit(&cleanup_FastVectorUnitWeaponInfoType);
  }
} // namespace gpg

/**
 * Address: 0x0055EAF0 (FUN_0055EAF0, gpg::RFastVectorType_UnitWeaponInfo::dtr)
 */
gpg::RFastVectorType<moho::UnitWeaponInfo>::~RFastVectorType() = default;

/**
 * Address: 0x0055CBF0 (FUN_0055CBF0, gpg::RFastVectorType_UnitWeaponInfo::GetName)
 */
const char* gpg::RFastVectorType<moho::UnitWeaponInfo>::GetName() const
{
  return GetFastVectorUnitWeaponInfoTypeName();
}

/**
 * Address: 0x0055CCB0 (FUN_0055CCB0, gpg::RFastVectorType_UnitWeaponInfo::GetLexical)
 *
 * What it does:
 * Renders `"<base RType lexical>, size=<count>"`. The retail body loads the
 * RIndexed sub-object vtable at `[this+0x64]`, takes slot 1 (`+4`) and calls it
 * with `this+0x64` and `ref.mObj` (0x0055CCF6-0x0055CD00) -- i.e. this class's
 * own `GetCount`.
 */
msvc8::string gpg::RFastVectorType<moho::UnitWeaponInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0055CD40 (FUN_0055CD40, gpg::RFastVectorType_UnitWeaponInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::UnitWeaponInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0055CC90 (FUN_0055CC90, gpg::RFastVectorType_UnitWeaponInfo::Init)
 */
void gpg::RFastVectorType<moho::UnitWeaponInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorUnitWeaponInfo;
  serSaveFunc_ = &gpg::SaveFastVectorUnitWeaponInfo;
}

/**
 * Address: 0x0055CDE0 (FUN_0055CDE0, gpg::RFastVectorType_UnitWeaponInfo::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<UnitWeaponInfo>[ind]`.
 * Element stride is 0x98 (`imul eax, 98h` at 0x0055CDE8), matching
 * `sizeof(UnitWeaponInfo)`. The retail body performs no bounds or null check.
 */
gpg::RRef gpg::RFastVectorType<moho::UnitWeaponInfo>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(obj);
  gpg::RRef out{};
  gpg::RRef_UnitWeaponInfo(&out, view.ElementAtUnchecked(static_cast<std::size_t>(ind)));
  return out;
}

/**
 * Address: 0x0055CD50 (FUN_0055CD50, gpg::RFastVectorType_UnitWeaponInfo::GetCount)
 *
 * What it does:
 * Returns the lane count as `(end - begin) / 0x98`, which the compiler emits as
 * the reciprocal-multiply sequence `imul 6BCA1AF3h; sar edx,6` at 0x0055CD59.
 */
size_t gpg::RFastVectorType<moho::UnitWeaponInfo>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(obj);
  return view.Size();
}

/**
 * Address: 0x0055CD70 (FUN_0055CD70, gpg::RFastVectorType_UnitWeaponInfo::SetCount)
 */
void gpg::RFastVectorType<moho::UnitWeaponInfo>::SetCount(void* obj, const int count) const
{
  SetFastVectorUnitWeaponInfoCount(obj, count);
}

// ---------------------------------------------------------------------------
// gpg::RFastVectorType<Moho::SOffsetInfo>
//
// Descriptor storage 0x01104FA0, built in place by FUN_00571C00. Slot map from
// the RTTI dump: primary vftable 0x00E1904C (dtr@2, GetName@3, GetLexical@4,
// IsIndexed@6, Init@9), RIndexed vftable 0x00E1907C at subobject offset 100
// (SubscriptIndex@0, GetCount@1, SetCount@2, AssignPointer@3 = base 0x00401320).
//
// The SetCount/SerLoad/SerSave bodies live in CAiFormationInstance.cpp
// (as `moho::SetFastVectorSOffsetInfoCount`/`moho::LoadFastVectorSOffsetInfo`/
// `moho::SaveFastVectorSOffsetInfo`) because they need the lane-entry
// default-prototype (sentinel-backed unit map + intrusive weak back-link) and
// resize helpers that are file-local to that translation unit.
// ---------------------------------------------------------------------------

namespace gpg
{
  /**
   * Address: 0x00571C00 (FUN_00571C00, preregister_RFastVectorType_SOffsetInfo)
   *
   * What it does:
   * Constructs the static `RFastVectorType<Moho::SOffsetInfo>` descriptor in
   * place -- the retail body inlines the default constructor as
   * `RType::RType()` plus the two vtable-pointer stores -- and preregisters it
   * under `typeid(gpg::fastvector<Moho::SOffsetInfo>)`.
   */
  gpg::RType* preregister_FastVectorSOffsetInfoType()
  {
    FastVectorSOffsetInfoType* const type = AcquireFastVectorSOffsetInfoType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::SOffsetInfo>), type);
    return type;
  }

  void cleanup_FastVectorSOffsetInfoType()
  {
    if (!gFastVectorSOffsetInfoTypeConstructed) {
      return;
    }

    AcquireFastVectorSOffsetInfoType()->~FastVectorSOffsetInfoType();
    gFastVectorSOffsetInfoTypeConstructed = false;
  }

  int register_FastVectorSOffsetInfoTypeAtexit()
  {
    (void)preregister_FastVectorSOffsetInfoType();
    return std::atexit(&cleanup_FastVectorSOffsetInfoType);
  }
} // namespace gpg

/**
 * Address: 0x005720E0 (FUN_005720E0, gpg::RFastVectorType_SOffsetInfo::dtr)
 */
gpg::RFastVectorType<moho::SOffsetInfo>::~RFastVectorType() = default;

/**
 * Address: 0x0056C020 (FUN_0056C020, gpg::RFastVectorType_SOffsetInfo::GetName)
 */
const char* gpg::RFastVectorType<moho::SOffsetInfo>::GetName() const
{
  return GetFastVectorSOffsetInfoTypeName();
}

/**
 * Address: 0x0056C0E0 (FUN_0056C0E0, gpg::RFastVectorType_SOffsetInfo::GetLexical)
 *
 * What it does:
 * Renders `"<base RType lexical>, size=<count>"`. The retail body reaches the
 * count by dispatching slot 1 of its own RIndexed sub-object vtable
 * (`[this+0x64] + 4`), matching this class's own `GetCount`.
 */
msvc8::string gpg::RFastVectorType<moho::SOffsetInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0056C170 (FUN_0056C170, gpg::RFastVectorType_SOffsetInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::SOffsetInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0056C0C0 (FUN_0056C0C0, gpg::RFastVectorType_SOffsetInfo::Init)
 */
void gpg::RFastVectorType<moho::SOffsetInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &moho::LoadFastVectorSOffsetInfo;
  serSaveFunc_ = &moho::SaveFastVectorSOffsetInfo;
}

/**
 * Address: 0x0056C200 (FUN_0056C200, gpg::RFastVectorType_SOffsetInfo::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<SOffsetInfo>[ind]`.
 * Element stride is 0x4C (`imul eax, 4Ch` in the retail body), matching
 * `sizeof(SOffsetInfo)`. The retail body performs no bounds or null check.
 */
gpg::RRef gpg::RFastVectorType<moho::SOffsetInfo>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::SOffsetInfo>(obj);
  gpg::RRef out{};
  gpg::RRef_SOffsetInfo(&out, view.ElementAtUnchecked(static_cast<std::size_t>(ind)));
  return out;
}

/**
 * Address: 0x0056C180 (FUN_0056C180, gpg::RFastVectorType_SOffsetInfo::GetCount)
 *
 * What it does:
 * Returns the lane count as `(end - begin) / 76`, matching `sizeof(SOffsetInfo)`.
 */
size_t gpg::RFastVectorType<moho::SOffsetInfo>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<moho::SOffsetInfo>(obj);
  return view.Size();
}

/**
 * Address: 0x0056C1A0 (FUN_0056C1A0, gpg::RFastVectorType_SOffsetInfo::SetCount)
 */
void gpg::RFastVectorType<moho::SOffsetInfo>::SetCount(void* obj, const int count) const
{
  moho::SetFastVectorSOffsetInfoCount(obj, count);
}

// ---------------------------------------------------------------------------
// gpg::RFastVectorType<Moho::SAssignedLocInfo>
//
// Descriptor storage 0x01104ED0, built in place by FUN_00571C70. Slot map from
// the RTTI dump: primary vftable 0x00E19090 (dtr@2, GetName@3, GetLexical@4,
// IsIndexed@6, Init@9), RIndexed vftable 0x00E190C0 at subobject offset 100
// (SubscriptIndex@0, GetCount@1, SetCount@2, AssignPointer@3 = base 0x00401320).
//
// The SetCount/SerLoad/SerSave bodies live in CAiFormationInstance.cpp for
// symmetry with `SOffsetInfo`'s, even though `SAssignedLocInfo` is a plain
// POD (no lane-entry-specific dependency); this keeps every fastvector
// callback for the formation-lane subsystem's element types in one place.
// ---------------------------------------------------------------------------

namespace gpg
{
  /**
   * Address: 0x00571C70 (FUN_00571C70, preregister_RFastVectorType_SAssignedLocInfo)
   *
   * What it does:
   * Constructs the static `RFastVectorType<Moho::SAssignedLocInfo>` descriptor
   * in place -- the retail body inlines the default constructor as
   * `RType::RType()` plus the two vtable-pointer stores -- and preregisters it
   * under `typeid(gpg::fastvector<Moho::SAssignedLocInfo>)`.
   */
  gpg::RType* preregister_FastVectorSAssignedLocInfoType()
  {
    FastVectorSAssignedLocInfoType* const type = AcquireFastVectorSAssignedLocInfoType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::SAssignedLocInfo>), type);
    return type;
  }

  void cleanup_FastVectorSAssignedLocInfoType()
  {
    if (!gFastVectorSAssignedLocInfoTypeConstructed) {
      return;
    }

    AcquireFastVectorSAssignedLocInfoType()->~FastVectorSAssignedLocInfoType();
    gFastVectorSAssignedLocInfoTypeConstructed = false;
  }

  int register_FastVectorSAssignedLocInfoTypeAtexit()
  {
    (void)preregister_FastVectorSAssignedLocInfoType();
    return std::atexit(&cleanup_FastVectorSAssignedLocInfoType);
  }
} // namespace gpg

/**
 * Address: 0x00572140 (FUN_00572140, gpg::RFastVectorType_SAssignedLocInfo::dtr)
 */
gpg::RFastVectorType<moho::SAssignedLocInfo>::~RFastVectorType() = default;

/**
 * Address: 0x0056C240 (FUN_0056C240, gpg::RFastVectorType_SAssignedLocInfo::GetName)
 */
const char* gpg::RFastVectorType<moho::SAssignedLocInfo>::GetName() const
{
  return GetFastVectorSAssignedLocInfoTypeName();
}

/**
 * Address: 0x0056C300 (FUN_0056C300, gpg::RFastVectorType_SAssignedLocInfo::GetLexical)
 */
msvc8::string gpg::RFastVectorType<moho::SAssignedLocInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0056C390 (FUN_0056C390, gpg::RFastVectorType_SAssignedLocInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::SAssignedLocInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0056C2E0 (FUN_0056C2E0, gpg::RFastVectorType_SAssignedLocInfo::Init)
 */
void gpg::RFastVectorType<moho::SAssignedLocInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &moho::LoadFastVectorSAssignedLocInfo;
  serSaveFunc_ = &moho::SaveFastVectorSAssignedLocInfo;
}

/**
 * Address: 0x0056C3F0 (FUN_0056C3F0, gpg::RFastVectorType_SAssignedLocInfo::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<SAssignedLocInfo>[ind]`.
 * Element stride is 0x10 (`shl/lea *16` in the retail body), matching
 * `sizeof(SAssignedLocInfo)`. The retail body performs no bounds or null check.
 */
gpg::RRef gpg::RFastVectorType<moho::SAssignedLocInfo>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::SAssignedLocInfo>(obj);
  gpg::RRef out{};
  gpg::RRef_SAssignedLocInfo(&out, view.ElementAtUnchecked(static_cast<std::size_t>(ind)));
  return out;
}

/**
 * Address: 0x0056C3A0 (FUN_0056C3A0, gpg::RFastVectorType_SAssignedLocInfo::GetCount)
 *
 * What it does:
 * Returns the lane count as `(end - begin) >> 4` -- a shift rather than a
 * reciprocal multiply, because `sizeof(SAssignedLocInfo)` is 16.
 */
size_t gpg::RFastVectorType<moho::SAssignedLocInfo>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<moho::SAssignedLocInfo>(obj);
  return view.Size();
}

/**
 * Address: 0x0056C3B0 (FUN_0056C3B0, gpg::RFastVectorType_SAssignedLocInfo::SetCount)
 */
void gpg::RFastVectorType<moho::SAssignedLocInfo>::SetCount(void* obj, const int count) const
{
  moho::SetFastVectorSAssignedLocInfoCount(obj, count);
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
 * Address: 0x00517510 (FUN_00517510, gpg::RFastVectorType_Vector3f::dtr)
 */
gpg::RFastVectorType<Wm3::Vector3f>::~RFastVectorType() = default;

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

  struct FastVectorSSTIEntityAttachInfoReflectionBootstrap
  {
    FastVectorSSTIEntityAttachInfoReflectionBootstrap()
    {
      (void)gpg::register_FastVectorSSTIEntityAttachInfoTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorSSTIEntityAttachInfoReflectionBootstrap gFastVectorSSTIEntityAttachInfoReflectionBootstrap;

  struct FastVectorUnitWeaponInfoReflectionBootstrap
  {
    FastVectorUnitWeaponInfoReflectionBootstrap()
    {
      (void)gpg::register_FastVectorUnitWeaponInfoTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorUnitWeaponInfoReflectionBootstrap gFastVectorUnitWeaponInfoReflectionBootstrap;

  struct FastVectorSOffsetInfoReflectionBootstrap
  {
    FastVectorSOffsetInfoReflectionBootstrap()
    {
      (void)gpg::register_FastVectorSOffsetInfoTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorSOffsetInfoReflectionBootstrap gFastVectorSOffsetInfoReflectionBootstrap;

  struct FastVectorSAssignedLocInfoReflectionBootstrap
  {
    FastVectorSAssignedLocInfoReflectionBootstrap()
    {
      (void)gpg::register_FastVectorSAssignedLocInfoTypeAtexit();
    }
  };

  [[maybe_unused]] FastVectorSAssignedLocInfoReflectionBootstrap gFastVectorSAssignedLocInfoReflectionBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_FastVectorFloatType_86ef6d, gpg::preregister_FastVectorFloatType)
GPG_PREREGISTER_INIT(register_FastVectorFloatTypeAtexit_86ef6d, gpg::register_FastVectorFloatTypeAtexit)
GPG_PREREGISTER_INIT(preregister_FastVectorStringType_86ef6d, gpg::preregister_FastVectorStringType)
GPG_PREREGISTER_INIT(register_FastVectorStringTypeAtexit_86ef6d, gpg::register_FastVectorStringTypeAtexit)
GPG_PREREGISTER_INIT(preregister_FastVectorVector3fType_86ef6d, gpg::preregister_FastVectorVector3fType)
GPG_PREREGISTER_INIT(register_FastVectorVector3fTypeAtexit_86ef6d, gpg::register_FastVectorVector3fTypeAtexit)
GPG_PREREGISTER_INIT(
  preregister_FastVectorSSTIEntityAttachInfoType_86ef6d,
  gpg::preregister_FastVectorSSTIEntityAttachInfoType
)
GPG_PREREGISTER_INIT(
  register_FastVectorSSTIEntityAttachInfoTypeAtexit_86ef6d,
  gpg::register_FastVectorSSTIEntityAttachInfoTypeAtexit
)
GPG_PREREGISTER_INIT(preregister_FastVectorUnitWeaponInfoType_86ef6d, gpg::preregister_FastVectorUnitWeaponInfoType)
GPG_PREREGISTER_INIT(
  register_FastVectorUnitWeaponInfoTypeAtexit_86ef6d,
  gpg::register_FastVectorUnitWeaponInfoTypeAtexit
)
GPG_PREREGISTER_INIT(preregister_FastVectorSOffsetInfoType_86ef6d, gpg::preregister_FastVectorSOffsetInfoType)
GPG_PREREGISTER_INIT(
  register_FastVectorSOffsetInfoTypeAtexit_86ef6d,
  gpg::register_FastVectorSOffsetInfoTypeAtexit
)
GPG_PREREGISTER_INIT(
  preregister_FastVectorSAssignedLocInfoType_86ef6d,
  gpg::preregister_FastVectorSAssignedLocInfoType
)
GPG_PREREGISTER_INIT(
  register_FastVectorSAssignedLocInfoTypeAtexit_86ef6d,
  gpg::register_FastVectorSAssignedLocInfoTypeAtexit
)
