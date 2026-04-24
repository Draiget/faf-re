#include "moho/animation/CAniPoseBoneTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"

namespace
{
  using CAniPoseBoneTypeInfo = moho::CAniPoseBoneTypeInfo;
  using FastVectorCAniPoseBoneType = gpg::RFastVectorType<moho::CAniPoseBone>;

  alignas(CAniPoseBoneTypeInfo) unsigned char gCAniPoseBoneTypeInfoStorage[sizeof(CAniPoseBoneTypeInfo)]{};
  bool gCAniPoseBoneTypeInfoConstructed = false;

  alignas(FastVectorCAniPoseBoneType)
    unsigned char gFastVectorCAniPoseBoneTypeStorage[sizeof(FastVectorCAniPoseBoneType)]{};
  bool gFastVectorCAniPoseBoneTypeConstructed = false;

  msvc8::string gFastVectorCAniPoseBoneTypeName;
  bool gFastVectorCAniPoseBoneTypeNameCleanupRegistered = false;

  [[nodiscard]] CAniPoseBoneTypeInfo* AcquireCAniPoseBoneTypeInfo()
  {
    if (!gCAniPoseBoneTypeInfoConstructed) {
      new (gCAniPoseBoneTypeInfoStorage) CAniPoseBoneTypeInfo();
      gCAniPoseBoneTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAniPoseBoneTypeInfo*>(gCAniPoseBoneTypeInfoStorage);
  }

  [[nodiscard]] FastVectorCAniPoseBoneType* AcquireFastVectorCAniPoseBoneType()
  {
    if (!gFastVectorCAniPoseBoneTypeConstructed) {
      new (gFastVectorCAniPoseBoneTypeStorage) FastVectorCAniPoseBoneType();
      gFastVectorCAniPoseBoneTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorCAniPoseBoneType*>(gFastVectorCAniPoseBoneTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAniPoseBoneType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAniPoseBone));
    }
    return cached;
  }

  [[nodiscard]] moho::CAniPoseBone MakeDefaultCAniPoseBone()
  {
    moho::CAniPoseBone fill{};
    fill.mCompositeTransform.orient_.w = 1.0f;
    fill.mCompositeTransform.orient_.x = 0.0f;
    fill.mCompositeTransform.orient_.y = 0.0f;
    fill.mCompositeTransform.orient_.z = 0.0f;
    fill.mCompositeTransform.pos_.x = 0.0f;
    fill.mCompositeTransform.pos_.y = 0.0f;
    fill.mCompositeTransform.pos_.z = 0.0f;
    fill.mCompositeDirty = 0u;
    fill.mCompositeIsLocal = 0u;

    fill.mLocalTransform.orient_.w = 1.0f;
    fill.mLocalTransform.orient_.x = 0.0f;
    fill.mLocalTransform.orient_.y = 0.0f;
    fill.mLocalTransform.orient_.z = 0.0f;
    fill.mLocalTransform.pos_.x = 0.0f;
    fill.mLocalTransform.pos_.y = 0.0f;
    fill.mLocalTransform.pos_.z = 0.0f;
    fill.mIdx = 0;
    fill.mPose = nullptr;
    fill.mParent = nullptr;
    fill.mVisible = 0u;
    fill.mSkipNextInterp = 0u;
    return fill;
  }

  /**
   * Address: 0x0054DF50 (FUN_0054DF50)
   *
   * IDA signature:
   * int __usercall sub_54DF50@<eax>(int a1@<eax>, int a2@<ecx>, int a3@<ebx>);
   *
   * What it does:
   * Copy-assigns the half-open range `[sourceBegin, sourceEnd)` of
   * `CAniPoseBone` values into contiguous destination storage starting at
   * `destinationBegin`, stepping both cursors by `sizeof(CAniPoseBone)`
   * (`0x4C`) per iteration. Returns the advanced destination cursor so
   * callers (see `AssignFastVectorCAniPoseBoneEnd` below) can restore
   * the owning `fastvector`'s `end` lane when the source and destination
   * ranges diverge. The inner copy uses the per-element copy-assign
   * lane recovered as `RuntimeCopyPackedFloatRecord74LaneA` in
   * CrtRuntimeHelpers, which emits exactly the FST/FLD pattern the
   * release binary uses for `CAniPoseBone::operator=`.
   */
  moho::CAniPoseBone* CopyAssignCAniPoseBoneRangeForward(
    const moho::CAniPoseBone* const sourceBegin,
    const moho::CAniPoseBone* const sourceEnd,
    moho::CAniPoseBone* const destinationBegin
  )
  {
    moho::CAniPoseBone* destinationCursor = destinationBegin;
    for (const moho::CAniPoseBone* sourceCursor = sourceBegin;
         sourceCursor != sourceEnd;
         ++sourceCursor, ++destinationCursor) {
      *destinationCursor = *sourceCursor;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x0054CCC0 (FUN_0054CCC0)
   *
   * IDA signature:
   * int __usercall sub_54CCC0@<eax>(int a1@<eax>, int a2@<edi>, int a3@<esi>);
   *
   * What it does:
   * When the updated range end `sourceEnd` differs from the vector's
   * existing end, rewinds the owning `fastvector<CAniPoseBone>`'s `end`
   * lane by copy-assigning the `[view.end, sourceEnd)` region starting at
   * `view.end` via the recovered range copy and then latches the advanced
   * destination cursor back into `view.end`.
   */
  void AssignFastVectorCAniPoseBoneEnd(
    gpg::fastvector_runtime_view<moho::CAniPoseBone>& view,
    const moho::CAniPoseBone* const sourceEnd
  )
  {
    if (view.end == sourceEnd) {
      return;
    }

    view.end = CopyAssignCAniPoseBoneRangeForward(view.end, sourceEnd, view.end);
  }

  /**
   * Address: 0x0054D790 (FUN_0054D790)
   *
   * IDA signature:
   * void *__fastcall sub_54D790(int a1, void **a2, int a3, int a4, int a5);
   *
   * What it does:
   * Reallocates one `fastvector<CAniPoseBone>` runtime view to a caller
   * supplied `requestedCount` capacity. Allocates a fresh element buffer via
   * the array `operator new`, copy-constructs the preserved `[begin, end)`
   * lane forward into the new buffer using the recovered per-element lane,
   * releases the old backing storage (or latches the inline-storage anchor
   * when the vector was still parked on its SBO slot), and rebinds the
   * view's begin/end/capacity triplet to the new buffer. Matches the binary
   * shape that calls `FUN_0054DCF0` (`CopyConstructCAniPoseBoneRangeForward`)
   * three times: once for the preserved prefix, once for the empty inserted
   * slot range, and once for the preserved suffix. The middle call has zero
   * length in every caller the binary exposes (see `FUN_0054CC90`'s reserve
   * trampoline), so the reconstruction preserves that shape with an explicit
   * zero-length sub-range boundary.
   */
  [[nodiscard]] moho::CAniPoseBone* PlacementCopyConstructCAniPoseBoneRange(
    moho::CAniPoseBone* destinationBegin,
    const moho::CAniPoseBone* sourceBegin,
    const moho::CAniPoseBone* sourceEnd
  )
  {
    moho::CAniPoseBone* destination = destinationBegin;
    for (const moho::CAniPoseBone* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      if (destination != nullptr) {
        ::new (destination) moho::CAniPoseBone(*source);
      }
    }
    return destination;
  }

  moho::CAniPoseBone* ReallocateFastVectorCAniPoseBone(
    const unsigned int requestedCount,
    gpg::fastvector_runtime_view<moho::CAniPoseBone>& view,
    const moho::CAniPoseBone* const insertPos,
    const moho::CAniPoseBone* const insertBegin,
    const moho::CAniPoseBone* const insertEnd
  )
  {
    auto* const newBegin = static_cast<moho::CAniPoseBone*>(
      ::operator new(static_cast<std::size_t>(requestedCount) * sizeof(moho::CAniPoseBone))
    );

    // Preserved prefix: [view.begin, insertPos)
    moho::CAniPoseBone* cursor = PlacementCopyConstructCAniPoseBoneRange(newBegin, view.begin, insertPos);

    // Inserted range: [insertBegin, insertEnd). Zero-length for plain
    // realloc paths (matches FUN_0054CC90's reserve usage exactly).
    cursor = PlacementCopyConstructCAniPoseBoneRange(cursor, insertBegin, insertEnd);

    // Preserved suffix: [insertPos, view.end). The binary walks the source
    // range one element at a time (0x4C stride) to confirm the suffix is
    // empty in every exported caller.
    if (view.begin != view.end) {
      cursor = PlacementCopyConstructCAniPoseBoneRange(cursor, insertPos, view.end);
    }

    // Release old storage, or latch the inline-storage slot when the vector
    // was still parked on its SBO anchor.
    if (view.begin == view.metadata) {
      if (view.begin) {
        // Inline-storage first word is the capacity end anchor; restore it.
        *reinterpret_cast<moho::CAniPoseBone**>(view.metadata) = view.capacityEnd;
      }
    } else {
      ::operator delete[](view.begin);
    }

    view.begin = newBegin;
    view.end = cursor;
    view.capacityEnd = newBegin + requestedCount;
    return newBegin;
  }

  /**
   * Address: 0x0054CC90 (FUN_0054CC90)
   *
   * IDA signature:
   * unsigned int __usercall sub_54CC90@<eax>(unsigned int a1@<ecx>, int *a2@<edi>);
   *
   * What it does:
   * Reserves capacity for `requestedCount` elements in one
   * `fastvector<CAniPoseBone>` runtime view. When existing capacity already
   * meets the request the current element count is returned without touching
   * storage; otherwise the reallocate lane (recovered as
   * `ReallocateFastVectorCAniPoseBone`) is invoked with a zero-length insert
   * range so existing elements are preserved 1:1.
   */
  unsigned int ReserveFastVectorCAniPoseBoneCapacity(
    const unsigned int requestedCount,
    gpg::fastvector_runtime_view<moho::CAniPoseBone>& view
  )
  {
    const unsigned int currentCount = view.begin
      ? static_cast<unsigned int>(view.end - view.begin)
      : 0u;
    if (requestedCount <= currentCount) {
      return currentCount;
    }

    moho::CAniPoseBone* const insertPos = view.begin;
    (void)ReallocateFastVectorCAniPoseBone(requestedCount, view, insertPos, insertPos, insertPos);
    return currentCount;
  }

  /**
   * Address: 0x0054C280 (FUN_0054C280)
   *
   * What it does:
   * Resizes one `fastvector<CAniPoseBone>` runtime view to `requestedCount`,
   * preserving existing lanes and fill-constructing appended lanes from
   * `fillValue` when growth is required. When shrinking, the destroyed-tail
   * fixup lane (recovered as `AssignFastVectorCAniPoseBoneEnd`) is invoked
   * explicitly so the release binary's post-shrink `end` latch stays
   * observable in source.
   */
  void ResizeFastVectorCAniPoseBoneToCount(
    const unsigned int requestedCount,
    gpg::fastvector_runtime_view<moho::CAniPoseBone>& view,
    const moho::CAniPoseBone& fillValue
  )
  {
    const unsigned int currentCount = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    if (requestedCount == currentCount) {
      return;
    }

    if (requestedCount < currentCount) {
      // Mirror the binary's shrink-side tail fixup before delegating to the
      // shared fastvector resize helper: when the shrink target coincides
      // with the existing `end`, the helper is a no-op, which matches
      // `FUN_0054CCC0`'s `if (a3 != a1)` guard.
      AssignFastVectorCAniPoseBoneEnd(view, view.end);
    } else {
      // Mirror the binary's grow-side reserve before fill: the release build
      // emits an explicit CAniPoseBone-specialized reserve lane here (see
      // `ReserveFastVectorCAniPoseBoneCapacity` / `FUN_0054CC90`) so the
      // fastvector's backing buffer is sized before the fill helper runs.
      (void)ReserveFastVectorCAniPoseBoneCapacity(requestedCount, view);
    }

    gpg::FastVectorRuntimeResizeFill(&fillValue, requestedCount, view);
  }

  /**
   * Address: 0x00BF46D0 (FUN_00BF46D0, cleanup_FastVectorCAniPoseBoneTypeName)
   *
   * What it does:
   * Releases cached lexical type-name storage for `fastvector<CAniPoseBone>`.
   */
  void cleanup_FastVectorCAniPoseBoneTypeName()
  {
    gFastVectorCAniPoseBoneTypeName = msvc8::string{};
    gFastVectorCAniPoseBoneTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x0054CE60 (FUN_0054CE60, gpg::RFastVectorType_CAniPoseBone::SerLoad)
   *
   * What it does:
   * Deserializes one `fastvector<CAniPoseBone>` count and element payload lanes.
   */
  void LoadFastVectorCAniPoseBone(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    auto& view = gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(reinterpret_cast<void*>(objectPtr));
    const moho::CAniPoseBone fill = MakeDefaultCAniPoseBone();
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    gpg::RType* const elementType = CachedCAniPoseBoneType();
    if (!elementType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x0054CF40 (FUN_0054CF40, gpg::RFastVectorType_CAniPoseBone::SerSave)
   *
   * What it does:
   * Serializes one `fastvector<CAniPoseBone>` count and element payload lanes.
   */
  void SaveFastVectorCAniPoseBone(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedCAniPoseBoneType();
    if (!elementType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &view.begin[i], owner);
    }
  }

  struct CAniPoseBoneReflectionBootstrap
  {
    CAniPoseBoneReflectionBootstrap()
    {
      (void)moho::register_CAniPoseBoneTypeInfoAtexit();
      (void)moho::register_FastVectorCAniPoseBoneTypeAtexit();
    }
  };

  CAniPoseBoneReflectionBootstrap gCAniPoseBoneReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0054BB50 (FUN_0054BB50, scalar deleting destructor thunk)
   */
  CAniPoseBoneTypeInfo::~CAniPoseBoneTypeInfo() = default;

  /**
   * Address: 0x0054BB40 (FUN_0054BB40, Moho::CAniPoseBoneTypeInfo::GetName)
   */
  const char* CAniPoseBoneTypeInfo::GetName() const
  {
    return "CAniPoseBone";
  }

  /**
   * Address: 0x0054BB20 (FUN_0054BB20, Moho::CAniPoseBoneTypeInfo::Init)
   */
  void CAniPoseBoneTypeInfo::Init()
  {
    size_ = sizeof(CAniPoseBone);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0054BAC0 (FUN_0054BAC0, preregister_CAniPoseBoneTypeInfo)
   */
  gpg::RType* preregister_CAniPoseBoneTypeInfo()
  {
    CAniPoseBoneTypeInfo* const typeInfo = AcquireCAniPoseBoneTypeInfo();
    gpg::PreRegisterRType(typeid(CAniPoseBone), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF4640 (FUN_00BF4640, cleanup_CAniPoseBoneTypeInfo)
   */
  void cleanup_CAniPoseBoneTypeInfo()
  {
    if (!gCAniPoseBoneTypeInfoConstructed) {
      return;
    }

    CAniPoseBoneTypeInfo* const typeInfo = AcquireCAniPoseBoneTypeInfo();
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x0054E310 (FUN_0054E310)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `CAniPoseBoneTypeInfo`.
   */
  [[maybe_unused]] void cleanup_CAniPoseBoneTypeInfoRTypeBase(CAniPoseBoneTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BC99A0 (FUN_00BC99A0, register_CAniPoseBoneTypeInfoAtexit)
   */
  int register_CAniPoseBoneTypeInfoAtexit()
  {
    (void)preregister_CAniPoseBoneTypeInfo();
    return std::atexit(&cleanup_CAniPoseBoneTypeInfo);
  }

  /**
   * Address: 0x0054E370 (FUN_0054E370, preregister_FastVectorCAniPoseBoneType)
   */
  gpg::RType* preregister_FastVectorCAniPoseBoneType()
  {
    FastVectorCAniPoseBoneType* const typeInfo = AcquireFastVectorCAniPoseBoneType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<CAniPoseBone>), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF4700 (FUN_00BF4700, cleanup_FastVectorCAniPoseBoneType)
   */
  void cleanup_FastVectorCAniPoseBoneType()
  {
    if (!gFastVectorCAniPoseBoneTypeConstructed) {
      return;
    }

    FastVectorCAniPoseBoneType* const typeInfo = AcquireFastVectorCAniPoseBoneType();
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BC9A00 (FUN_00BC9A00, register_FastVectorCAniPoseBoneTypeAtexit)
   */
  int register_FastVectorCAniPoseBoneTypeAtexit()
  {
    (void)preregister_FastVectorCAniPoseBoneType();
    return std::atexit(&cleanup_FastVectorCAniPoseBoneType);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0054E440 (FUN_0054E440, scalar deleting destructor thunk)
   */
  RFastVectorType<moho::CAniPoseBone>::~RFastVectorType() = default;

  /**
   * Address: 0x0054C680 (FUN_0054C680, gpg::RFastVectorType_CAniPoseBone::GetName)
   */
  const char* RFastVectorType<moho::CAniPoseBone>::GetName() const
  {
    if (gFastVectorCAniPoseBoneTypeName.empty()) {
      const gpg::RType* const elementType = CachedCAniPoseBoneType();
      const char* const elementName = elementType ? elementType->GetName() : "CAniPoseBone";
      gFastVectorCAniPoseBoneTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "CAniPoseBone");
      if (!gFastVectorCAniPoseBoneTypeNameCleanupRegistered) {
        gFastVectorCAniPoseBoneTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorCAniPoseBoneTypeName);
      }
    }
    return gFastVectorCAniPoseBoneTypeName.c_str();
  }

  /**
   * Address: 0x0054C740 (FUN_0054C740, gpg::RFastVectorType_CAniPoseBone::GetLexical)
   */
  msvc8::string RFastVectorType<moho::CAniPoseBone>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0054C7D0 (FUN_0054C7D0, gpg::RFastVectorType_CAniPoseBone::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::CAniPoseBone>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0054C720 (FUN_0054C720, gpg::RFastVectorType_CAniPoseBone::Init)
   */
  void RFastVectorType<moho::CAniPoseBone>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorCAniPoseBone;
    serSaveFunc_ = &SaveFastVectorCAniPoseBone;
  }

  /**
   * Address: 0x0054C880 (FUN_0054C880, gpg::RFastVectorType_CAniPoseBone::SubscriptIndex)
   */
  gpg::RRef RFastVectorType<moho::CAniPoseBone>::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedCAniPoseBoneType();

    if (!obj || ind < 0) {
      return out;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(obj);
    if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    gpg::RRef_CAniPoseBone(&out, &view.begin[ind]);
    return out;
  }

  /**
   * Address: 0x0054C7E0 (FUN_0054C7E0, gpg::RFastVectorType_CAniPoseBone::GetCount)
   */
  size_t RFastVectorType<moho::CAniPoseBone>::GetCount(void* const obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(obj);
    if (!view.begin) {
      return 0u;
    }
    return static_cast<size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x0054C800 (FUN_0054C800, gpg::RFastVectorType_CAniPoseBone::SetCount)
   */
  void RFastVectorType<moho::CAniPoseBone>::SetCount(void* const obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(obj);
    const moho::CAniPoseBone fill = MakeDefaultCAniPoseBone();
    ResizeFastVectorCAniPoseBoneToCount(static_cast<unsigned int>(count), view, fill);
  }
} // namespace gpg
