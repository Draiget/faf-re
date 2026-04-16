#include "moho/render/CDecalTypes.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  class RListType_SDecalInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0077A760 (FUN_0077A760, gpg::RListType_SDecalInfo::GetName)
     *
     * What it does:
     * Lazily builds and caches reflected lexical type label `list<SDecalInfo>`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0077A820 (FUN_0077A820, gpg::RListType_SDecalInfo::GetLexical)
     *
     * What it does:
     * Formats inherited list lexical text with current `SDecalInfo` list size.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0077A800 (FUN_0077A800, gpg::RListType_SDecalInfo::Init)
     *
     * What it does:
     * Configures reflected `list<SDecalInfo>` layout/version lanes and installs
     * list serializer callbacks.
     */
    void Init() override;

    /**
     * Address: 0x0077B260 (FUN_0077B260, gpg::RListType_SDecalInfo::SerLoad)
     *
     * What it does:
     * Clears one reflected `list<SDecalInfo>`, reads element count, then
     * deserializes each decal entry in archive order.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);

    /**
     * Address: 0x0077B420 (FUN_0077B420, gpg::RListType_SDecalInfo::SerSave)
     *
     * What it does:
     * Writes reflected `list<SDecalInfo>` element count, then serializes each
     * entry in list traversal order.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  };
} // namespace gpg

namespace
{
  msvc8::string gSDecalInfoListTypeName{};
  std::uint32_t gSDecalInfoListTypeNameInitGuard = 0u;

  /**
   * Address: 0x0077B940 (FUN_0077B940)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `SDecalInfo`.
   */
  [[nodiscard]] gpg::RType* CachedSDecalInfoType()
  {
    gpg::RType* type = moho::SDecalInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SDecalInfo));
      moho::SDecalInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return type;
  }

  [[nodiscard]] gpg::ReadArchive* ReadReflectedSDecalInfoPayload(
    gpg::ReadArchive* const archive,
    void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Read(CachedSDecalInfoType(), payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  [[nodiscard]] gpg::WriteArchive* WriteReflectedSDecalInfoPayload(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Write(CachedSDecalInfoType(), payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  /**
   * Address: 0x0077D9D0 (FUN_0077D9D0)
   *
   * What it does:
   * Deserializes one reflected `SDecalInfo` payload lane and returns the
   * archive for callback chaining.
   */
  [[maybe_unused]] gpg::ReadArchive* DeserializeSDecalInfoReflectedPayloadA(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    return ReadReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DA10 (FUN_0077DA10)
   *
   * What it does:
   * Serializes one reflected `SDecalInfo` payload lane and returns the archive
   * for callback chaining.
   */
  [[maybe_unused]] gpg::WriteArchive* SerializeSDecalInfoReflectedPayloadA(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    return WriteReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DF80 (FUN_0077DF80)
   *
   * What it does:
   * Secondary deserializer entrypoint for one reflected `SDecalInfo` payload
   * lane.
   */
  [[maybe_unused]] void DeserializeSDecalInfoReflectedPayloadB(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DFB0 (FUN_0077DFB0)
   *
   * What it does:
   * Secondary serializer entrypoint for one reflected `SDecalInfo` payload
   * lane.
   */
  [[maybe_unused]] void SerializeSDecalInfoReflectedPayloadB(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    (void)WriteReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  void cleanup_SDecalInfoListTypeName()
  {
    gSDecalInfoListTypeName.clear();
    gSDecalInfoListTypeNameInitGuard = 0u;
  }

  struct SerSaveLoadHelperNodeView
  {
    void* mVTable;                          // +0x00
    gpg::SerHelperBase* mHelperNext;        // +0x04
    gpg::SerHelperBase* mHelperPrev;        // +0x08
    gpg::RType::load_func_t mLoadCallback;  // +0x0C
    gpg::RType::save_func_t mSaveCallback;  // +0x10
  };
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperNodeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperNodeView::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mLoadCallback) == 0x0C,
    "SerSaveLoadHelperNodeView::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeView, mSaveCallback) == 0x10,
    "SerSaveLoadHelperNodeView::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeView) == 0x14, "SerSaveLoadHelperNodeView size must be 0x14");

  SerSaveLoadHelperNodeView gTextureScrollerSerializer{};
  SerSaveLoadHelperNodeView gSDecalInfoSerializer{};

  [[nodiscard]] gpg::SerHelperBase* HelperNodeSelf(SerSaveLoadHelperNodeView& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  void InitializeSerSaveLoadHelperNode(SerSaveLoadHelperNodeView& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperNodeSelf(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    helper.mLoadCallback = nullptr;
    helper.mSaveCallback = nullptr;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(SerSaveLoadHelperNodeView& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperNodeSelf(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  struct DecalSerializerHelperBootstrap
  {
    DecalSerializerHelperBootstrap()
    {
      InitializeSerSaveLoadHelperNode(gTextureScrollerSerializer);
      InitializeSerSaveLoadHelperNode(gSDecalInfoSerializer);
    }
  };

  DecalSerializerHelperBootstrap gDecalSerializerHelperBootstrap;

  void DeserializeSDecalInfoSerializerLane(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const decalInfo = reinterpret_cast<moho::SDecalInfo*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (decalInfo != nullptr) {
      decalInfo->MemberDeserialize(archive);
    }
  }

  void SerializeSDecalInfoSerializerLane(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const decalInfo = reinterpret_cast<moho::SDecalInfo*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (decalInfo != nullptr) {
      decalInfo->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0077A6A0 (FUN_0077A6A0)
   *
   * What it does:
   * Initializes `SDecalInfo` serializer helper links and binds archive
   * load/save callback lanes for one decal-info payload.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* InitializeSDecalInfoSerializerHelper() noexcept
  {
    InitializeSerSaveLoadHelperNode(gSDecalInfoSerializer);
    gSDecalInfoSerializer.mLoadCallback = &DeserializeSDecalInfoSerializerLane;
    gSDecalInfoSerializer.mSaveCallback = &SerializeSDecalInfoSerializerLane;
    return HelperNodeSelf(gSDecalInfoSerializer);
  }

  /**
   * Address: 0x00777D90 (FUN_00777D90)
   *
   * What it does:
   * Unlinks `CTextureScrollerSerializer` helper node from the intrusive helper
   * list, rewires self-links, and returns the helper self node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkTextureScrollerSerializerHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gTextureScrollerSerializer);
  }

  /**
   * Address: 0x00777DC0 (FUN_00777DC0)
   *
   * What it does:
   * Secondary entrypoint for `CTextureScrollerSerializer` helper-node
   * intrusive unlink + self-link reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkTextureScrollerSerializerHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gTextureScrollerSerializer);
  }

  /**
   * Address: 0x00778E70 (FUN_00778E70)
   *
   * What it does:
   * Unlinks `SDecalInfoSerializer` helper node from the intrusive helper list,
   * rewires self-links, and returns the helper self node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSDecalInfoSerializerHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gSDecalInfoSerializer);
  }

  /**
   * Address: 0x00778EA0 (FUN_00778EA0)
   *
   * What it does:
   * Secondary entrypoint for `SDecalInfoSerializer` helper-node intrusive
   * unlink + self-link reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSDecalInfoSerializerHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gSDecalInfoSerializer);
  }

  struct SDecalInfoListRuntimeView
  {
    void* mNodeProxy;      // +0x00
    void* mSentinelNode;   // +0x04
    std::uint32_t mCount;  // +0x08
  };
  static_assert(
    offsetof(SDecalInfoListRuntimeView, mCount) == 0x08, "SDecalInfoListRuntimeView::mCount offset must be 0x08"
  );
  static_assert(sizeof(SDecalInfoListRuntimeView) == 0x0C, "SDecalInfoListRuntimeView size must be 0x0C");

  [[nodiscard]] int CountSDecalInfoListElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0;
    }

    const auto* const listView = static_cast<const SDecalInfoListRuntimeView*>(object);
    return static_cast<int>(listView->mCount);
  }

  struct SDecalInfoVectorRuntimeView
  {
    void* lane00;               // +0x00
    moho::SDecalInfo* begin;    // +0x04
    moho::SDecalInfo* end;      // +0x08
    moho::SDecalInfo* capacity; // +0x0C
  };
  static_assert(offsetof(SDecalInfoVectorRuntimeView, begin) == 0x04, "SDecalInfoVectorRuntimeView::begin offset must be 0x04");
  static_assert(offsetof(SDecalInfoVectorRuntimeView, end) == 0x08, "SDecalInfoVectorRuntimeView::end offset must be 0x08");
  static_assert(
    offsetof(SDecalInfoVectorRuntimeView, capacity) == 0x0C,
    "SDecalInfoVectorRuntimeView::capacity offset must be 0x0C"
  );

  /**
   * Address: 0x0077A060 (FUN_0077A060)
   *
   * What it does:
   * Returns true when one `SDecalInfo` vector-runtime lane has no used
   * elements (`begin == 0` or `end == begin`).
   */
  [[maybe_unused]] bool IsSDecalInfoVectorRuntimeEmpty(const SDecalInfoVectorRuntimeView* const vectorView) noexcept
  {
    const moho::SDecalInfo* const begin = vectorView->begin;
    if (begin == nullptr) {
      return true;
    }
    return vectorView->end == begin;
  }

  /**
   * Address: 0x0077ACA0 (FUN_0077ACA0)
   *
   * What it does:
   * Returns used element count from one `SDecalInfo` vector-runtime lane.
   */
  [[maybe_unused]] int CountSDecalInfoVectorRuntimeUsed(const SDecalInfoVectorRuntimeView* const vectorView) noexcept
  {
    const moho::SDecalInfo* const begin = vectorView->begin;
    if (begin == nullptr) {
      return 0;
    }
    return static_cast<int>(vectorView->end - begin);
  }

  /**
   * Address: 0x0077AC70 (FUN_0077AC70)
   *
   * What it does:
   * Returns capacity element count from one `SDecalInfo` vector-runtime lane.
   */
  [[maybe_unused]] int CountSDecalInfoVectorRuntimeCapacity(const SDecalInfoVectorRuntimeView* const vectorView) noexcept
  {
    const moho::SDecalInfo* const begin = vectorView->begin;
    if (begin == nullptr) {
      return 0;
    }
    return static_cast<int>(vectorView->capacity - begin);
  }

  /**
   * Address: 0x0077C9A0 (FUN_0077C9A0)
   *
   * What it does:
   * Clears one reflected `list<SDecalInfo>` payload and resets its sentinel
   * links through the legacy list container API.
   */
  void ClearSDecalInfoListStorage(msvc8::list<moho::SDecalInfo>& list)
  {
    list.clear();
  }

  /**
   * Address: 0x0077E940 (FUN_0077E940)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` lane, including string members and trailing
   * scalar/object lanes, then returns the destination lane.
   */
  [[nodiscard]] moho::SDecalInfo* CopyAssignSDecalInfoLane(
    moho::SDecalInfo* const destination,
    const moho::SDecalInfo* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->mPos = source->mPos;
    destination->mSize = source->mSize;
    destination->mRot = source->mRot;
    destination->mTexName1 = source->mTexName1;
    destination->mTexName2 = source->mTexName2;
    destination->mIsSplat = source->mIsSplat;
    destination->mPad5D[0] = source->mPad5D[0];
    destination->mPad5D[1] = source->mPad5D[1];
    destination->mPad5D[2] = source->mPad5D[2];
    destination->mLODParam = source->mLODParam;
    destination->mStartTick = source->mStartTick;
    destination->mType = source->mType;
    destination->mObj = source->mObj;
    destination->mArmy = source->mArmy;
    destination->mFidelity = source->mFidelity;
    return destination;
  }

  /**
   * Address: 0x0077E7E0 (FUN_0077E7E0)
   * Address: 0x0077DA80 (FUN_0077DA80)
   *
   * What it does:
   * Assign-copies one contiguous `[destinationBegin, destinationEnd)` range
   * from one fixed `SDecalInfo` prototype lane.
   */
  [[maybe_unused]] moho::SDecalInfo* CopyAssignSDecalInfoRangeFromPrototype(
    moho::SDecalInfo* destinationBegin,
    moho::SDecalInfo* const destinationEnd,
    const moho::SDecalInfo* const prototype
  )
  {
    while (destinationBegin != destinationEnd) {
      (void)CopyAssignSDecalInfoLane(destinationBegin, prototype);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0077E830 (FUN_0077E830)
   * Address: 0x0077F340 (FUN_0077F340)
   * Address: 0x0077DAB0 (FUN_0077DAB0)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` range backward, returning the destination
   * begin lane after copy-backward completes.
   */
  [[maybe_unused]] moho::SDecalInfo* CopyAssignSDecalInfoRangeBackward(
    const moho::SDecalInfo* sourceEnd,
    moho::SDecalInfo* destinationEnd,
    const moho::SDecalInfo* const sourceBegin
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      (void)CopyAssignSDecalInfoLane(destinationEnd, sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0077F3A0 (FUN_0077F3A0)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` forward range and returns one-past the last
   * assigned destination lane.
   */
  [[nodiscard]] moho::SDecalInfo* CopyAssignSDecalInfoRangeForward(
    moho::SDecalInfo* destinationBegin,
    const moho::SDecalInfo* sourceBegin,
    const moho::SDecalInfo* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      (void)CopyAssignSDecalInfoLane(destinationBegin, sourceBegin);
      ++destinationBegin;
      ++sourceBegin;
    }
    return destinationBegin;
  }

  void DestroySDecalInfoRange(moho::SDecalInfo* begin, moho::SDecalInfo* end)
  {
    while (begin != end) {
      begin->~SDecalInfo();
      ++begin;
    }
  }

  /**
   * Address: 0x00741420 (FUN_00741420, sub_741420)
   *
   * What it does:
   * Thiscall adapter lane that forwards one reversed `(end, begin)` argument
   * pair into the canonical half-open `SDecalInfo` range destroy helper.
   */
  [[maybe_unused]] void DestroySDecalInfoRangeThiscallAdapter(
    moho::SDecalInfo* const end,
    moho::SDecalInfo* const begin
  )
  {
    DestroySDecalInfoRange(begin, end);
  }

  /**
   * Address: 0x0077E2D0 (FUN_0077E2D0)
   *
   * What it does:
   * Clears one `vector<SDecalInfo>` used range by destroying all live lanes
   * and rewinding `_Mylast` to `_Myfirst` without releasing capacity.
   */
  void ClearSDecalInfoVectorUsedRange(msvc8::vector<moho::SDecalInfo>& storage)
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin != view.end) {
      DestroySDecalInfoRange(view.begin, view.end);
      view.end = view.begin;
    }
  }

  [[nodiscard]] bool AllocateSDecalInfoStorage(
    msvc8::vector<moho::SDecalInfo>& storage,
    const std::size_t elementCount
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (elementCount == 0u) {
      view.begin = nullptr;
      view.end = nullptr;
      view.capacityEnd = nullptr;
      return true;
    }

    if (elementCount > (static_cast<std::size_t>(-1) / sizeof(moho::SDecalInfo))) {
      return false;
    }

    void* rawStorage = nullptr;
    try {
      rawStorage = ::operator new(sizeof(moho::SDecalInfo) * elementCount);
    } catch (...) {
      return false;
    }

    view.begin = static_cast<moho::SDecalInfo*>(rawStorage);
    view.end = view.begin;
    view.capacityEnd = view.begin + elementCount;
    return true;
  }

  /**
   * Address: 0x0077E7B0 (FUN_0077E7B0)
   * Address: 0x0077E8B0 (FUN_0077E8B0)
   * Address: 0x0077F310 (FUN_0077F310)
   * Address: 0x0077F370 (FUN_0077F370)
   * Address: 0x0077F3D0 (FUN_0077F3D0)
   * Address: 0x0077F4C0 (FUN_0077F4C0)
   * Address: 0x0077F560 (FUN_0077F560)
   *
   * What it does:
   * Copy-constructs one `SDecalInfo` range into uninitialized destination
   * storage; on construction failure it destroys already-constructed lanes and
   * rethrows.
   */
  [[nodiscard]] moho::SDecalInfo* CopyConstructSDecalInfoRangeWithRollback(
    moho::SDecalInfo* destination,
    const moho::SDecalInfo* sourceBegin,
    const moho::SDecalInfo* sourceEnd
  )
  {
    moho::SDecalInfo* write = destination;
    try {
      for (const moho::SDecalInfo* read = sourceBegin; read != sourceEnd; ++read, ++write) {
        ::new (write) moho::SDecalInfo(*read);
      }
      return write;
    } catch (...) {
      DestroySDecalInfoRange(destination, write);
      throw;
    }
  }

  /**
   * Address: 0x0077E910 (FUN_0077E910)
   *
   * What it does:
   * Fastcall adapter lane that forwards recovered stack/register argument
   * order into canonical `SDecalInfo` range copy-construction with rollback.
   */
  [[maybe_unused]] moho::SDecalInfo* CopyConstructSDecalInfoRangeFastcallAdapter(
    [[maybe_unused]] const std::uint32_t unusedLane,
    moho::SDecalInfo* const destination,
    const moho::SDecalInfo* const sourceEnd,
    const moho::SDecalInfo* const sourceBegin
  )
  {
    return CopyConstructSDecalInfoRangeWithRollback(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0077E100 (FUN_0077E100)
   *
   * What it does:
   * Assigns one `vector<SDecalInfo>` lane with VC8-style reuse/reallocate
   * behavior, preserving `SDecalInfo` string lifetime ordering on shrink,
   * growth, and full replacement paths.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::vector<moho::SDecalInfo>& AssignSDecalInfoVector(
    msvc8::vector<moho::SDecalInfo>& destination,
    const msvc8::vector<moho::SDecalInfo>& source
  )
  {
    if (&destination == &source) {
      return destination;
    }

    auto& destinationView = msvc8::AsVectorRuntimeView(destination);
    const auto& sourceView = msvc8::AsVectorRuntimeView(source);

    const std::size_t sourceCount =
      sourceView.begin ? static_cast<std::size_t>(sourceView.end - sourceView.begin) : 0u;
    if (sourceCount == 0u) {
      ClearSDecalInfoVectorUsedRange(destination);
      return destination;
    }

    const std::size_t currentCount =
      destinationView.begin ? static_cast<std::size_t>(destinationView.end - destinationView.begin) : 0u;
    const moho::SDecalInfo* const sourceBegin = sourceView.begin;
    const moho::SDecalInfo* const sourceEnd = sourceView.end;

    if (sourceCount > currentCount) {
      const std::size_t capacityCount =
        destinationView.begin ? static_cast<std::size_t>(destinationView.capacityEnd - destinationView.begin) : 0u;
      if (sourceCount <= capacityCount) {
        const moho::SDecalInfo* const sourceTailBegin = sourceBegin + currentCount;
        (void)CopyAssignSDecalInfoRangeForward(destinationView.begin, sourceBegin, sourceTailBegin);
        destinationView.end = CopyConstructSDecalInfoRangeWithRollback(destinationView.end, sourceTailBegin, sourceEnd);
        return destination;
      }

      if (destinationView.begin != nullptr) {
        DestroySDecalInfoRange(destinationView.begin, destinationView.end);
        ::operator delete(destinationView.begin);
      }

      destinationView.begin = nullptr;
      destinationView.end = nullptr;
      destinationView.capacityEnd = nullptr;
      if (AllocateSDecalInfoStorage(destination, sourceCount)) {
        try {
          destinationView.end = CopyConstructSDecalInfoRangeWithRollback(destinationView.begin, sourceBegin, sourceEnd);
        } catch (...) {
          ::operator delete(destinationView.begin);
          destinationView.begin = nullptr;
          destinationView.end = nullptr;
          destinationView.capacityEnd = nullptr;
          throw;
        }
      }
      return destination;
    }

    moho::SDecalInfo* const assignedEnd =
      CopyAssignSDecalInfoRangeForward(destinationView.begin, sourceBegin, sourceEnd);
    DestroySDecalInfoRange(assignedEnd, destinationView.end);
    destinationView.end = destinationView.begin + sourceCount;
    return destination;
  }
} // namespace

/**
 * Address: 0x0077A760 (FUN_0077A760, gpg::RListType_SDecalInfo::GetName)
 *
 * What it does:
 * Lazily builds and caches reflected lexical type label `list<SDecalInfo>`
 * from runtime RTTI metadata.
 */
const char* gpg::RListType_SDecalInfo::GetName() const
{
  if ((gSDecalInfoListTypeNameInitGuard & 1u) == 0u) {
    gSDecalInfoListTypeNameInitGuard |= 1u;

    gpg::RType* const valueType = CachedSDecalInfoType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "SDecalInfo";
    gSDecalInfoListTypeName = gpg::STR_Printf("list<%s>", valueTypeName ? valueTypeName : "SDecalInfo");
    (void)std::atexit(&cleanup_SDecalInfoListTypeName);
  }

  return gSDecalInfoListTypeName.c_str();
}

/**
 * Address: 0x0077A820 (FUN_0077A820, gpg::RListType_SDecalInfo::GetLexical)
 *
 * What it does:
 * Formats inherited list lexical text with current `SDecalInfo` list size.
 */
msvc8::string gpg::RListType_SDecalInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), CountSDecalInfoListElements(ref.mObj));
}

/**
 * Address: 0x0077A800 (FUN_0077A800, gpg::RListType_SDecalInfo::Init)
 *
 * What it does:
 * Configures reflected `list<SDecalInfo>` layout/version lanes and installs
 * list serializer callbacks.
 */
void gpg::RListType_SDecalInfo::Init()
{
  size_ = sizeof(msvc8::list<moho::SDecalInfo>);
  version_ = 1;
  serLoadFunc_ = &gpg::RListType_SDecalInfo::SerLoad;
  serSaveFunc_ = &gpg::RListType_SDecalInfo::SerSave;
}

/**
 * Address: 0x0077B260 (FUN_0077B260, gpg::RListType_SDecalInfo::SerLoad)
 *
 * What it does:
 * Clears one reflected `list<SDecalInfo>`, reads element count, then
 * deserializes each decal entry in archive order.
 */
void gpg::RListType_SDecalInfo::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const list = reinterpret_cast<msvc8::list<moho::SDecalInfo>*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  if (archive == nullptr || list == nullptr) {
    return;
  }

  unsigned int count = 0u;
  archive->ReadUInt(&count);
  ClearSDecalInfoListStorage(*list);

  gpg::RType* const elementType = CachedSDecalInfoType();
  if (elementType == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0u; i < count; ++i) {
    moho::SDecalInfo value{};
    archive->Read(elementType, &value, owner);
    list->push_back(value);
  }
}

/**
 * Address: 0x0077B420 (FUN_0077B420, gpg::RListType_SDecalInfo::SerSave)
 *
 * What it does:
 * Writes reflected `list<SDecalInfo>` element count, then serializes each
 * entry in list traversal order.
 */
void gpg::RListType_SDecalInfo::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const list = reinterpret_cast<const msvc8::list<moho::SDecalInfo>*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  if (archive == nullptr) {
    return;
  }

  const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
  archive->WriteUInt(count);
  if (list == nullptr) {
    return;
  }

  gpg::RType* const elementType = CachedSDecalInfoType();
  if (elementType == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (const moho::SDecalInfo& value : *list) {
    archive->Write(elementType, &value, owner);
  }
}

/**
 * Address: 0x0077DF00 (FUN_0077DF00, preregister_RListType_SDecalInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `msvc8::list<moho::SDecalInfo>`.
 */
[[nodiscard]] gpg::RType* preregister_RListType_SDecalInfo()
{
  static gpg::RListType_SDecalInfo typeInfo;
  gpg::PreRegisterRType(typeid(msvc8::list<moho::SDecalInfo>), &typeInfo);
  return &typeInfo;
}

namespace moho
{
  gpg::RType* SDecalInfo::sType = nullptr;

  /**
   * Address: 0x007786B0 (FUN_007786B0)
   *
   * What it does:
   * Constructs one `SDecalInfo` object in preallocated storage and returns the
   * constructed object lane.
   */
  [[maybe_unused]] SDecalInfo* ConstructSDecalInfoInPlace(SDecalInfo* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) SDecalInfo();
  }

  [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresent(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) SDecalInfo(*source);
  }

  /**
   * Address: 0x0077D360 (FUN_0077D360)
   *
   * What it does:
   * Primary adapter lane for nullable `SDecalInfo` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresentPrimary(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    return CopyConstructSDecalInfoIfPresent(destination, source);
  }

  /**
   * Address: 0x0077DCC0 (FUN_0077DCC0)
   *
   * What it does:
   * Secondary adapter lane for nullable `SDecalInfo` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresentSecondary(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    return CopyConstructSDecalInfoIfPresent(destination, source);
  }

  /**
   * Address: 0x00778B60 (FUN_00778B60, SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Initializes one default decal payload with empty textures/type and
   * default fidelity.
   */
  SDecalInfo::SDecalInfo()
    : mPos{}
    , mSize{}
    , mRot{}
    , mTexName1()
    , mTexName2()
    , mIsSplat(0)
    , mPad5D{0, 0, 0}
    , mLODParam(0.0f)
    , mStartTick(0)
    , mType()
    , mObj(0)
    , mArmy(0)
    , mFidelity(1)
  {}

  /**
   * Address: 0x0066D210 (FUN_0066D210, Moho::SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Copies position/size/rotation + texture/type strings and seeds runtime
   * decal metadata fields.
   */
  SDecalInfo::SDecalInfo(
    const Wm3::Vec3f& size,
    const Wm3::Vec3f& position,
    const Wm3::Vec3f& rotation,
    const msvc8::string& textureNamePrimary,
    const msvc8::string& textureNameSecondary,
    const bool isSplat,
    const float lodParam,
    const std::uint32_t startTick,
    const msvc8::string& typeName,
    const std::uint32_t armyIndex,
    const std::uint32_t fidelity
  )
    : mPos(position)
    , mSize(size)
    , mRot(rotation)
    , mTexName1(textureNamePrimary)
    , mTexName2(textureNameSecondary)
    , mIsSplat(isSplat ? 1u : 0u)
    , mPad5D{0, 0, 0}
    , mLODParam(lodParam)
    , mStartTick(startTick)
    , mType(typeName)
    , mObj(0)
    , mArmy(armyIndex)
    , mFidelity(fidelity)
  {}

  /**
   * Address: 0x0077D470 (FUN_0077D470, Moho::SDecalInfo::MemberDeserialize)
   *
   * What it does:
   * Loads decal position/size/rotation vectors plus texture/type lanes and
   * runtime metadata fields from archive payload.
   */
  void SDecalInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const vector3fType = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3fType, &mPos, ownerRef);
    archive->Read(vector3fType, &mSize, ownerRef);
    archive->Read(vector3fType, &mRot, ownerRef);

    archive->ReadString(&mTexName1);
    archive->ReadString(&mTexName2);

    bool isSplat = false;
    archive->ReadBool(&isSplat);
    mIsSplat = isSplat ? 1u : 0u;

    archive->ReadFloat(&mLODParam);
    archive->ReadUInt(&mStartTick);
    archive->ReadString(&mType);

    std::int32_t objectId = 0;
    std::int32_t armyIndex = 0;
    std::int32_t fidelity = 0;
    archive->ReadInt(&objectId);
    archive->ReadInt(&armyIndex);
    archive->ReadInt(&fidelity);
    mObj = static_cast<std::uint32_t>(objectId);
    mArmy = static_cast<std::uint32_t>(armyIndex);
    mFidelity = static_cast<std::uint32_t>(fidelity);
  }

  /**
   * Address: 0x0077D5A0 (FUN_0077D5A0)
   *
   * What it does:
   * Saves decal position/size/rotation vectors plus texture/type lanes and
   * runtime metadata fields to archive payload.
   */
  void SDecalInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    gpg::RType* const vector3fType = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Write(vector3fType, &mPos, ownerRef);
    archive->Write(vector3fType, &mSize, ownerRef);
    archive->Write(vector3fType, &mRot, ownerRef);

    archive->WriteString(const_cast<msvc8::string*>(&mTexName1));
    archive->WriteString(const_cast<msvc8::string*>(&mTexName2));
    archive->WriteBool(mIsSplat != 0u);
    archive->WriteFloat(mLODParam);
    archive->WriteUInt(mStartTick);
    archive->WriteString(const_cast<msvc8::string*>(&mType));
    archive->WriteInt(static_cast<int>(mObj));
    archive->WriteInt(static_cast<int>(mArmy));
    archive->WriteInt(static_cast<int>(mFidelity));
  }
} // namespace moho
