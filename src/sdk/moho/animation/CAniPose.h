#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/render/camera/VTransform.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAniSkel;
  class CAniPose;
  struct SAniSkelBone;

  class CAniPoseBone
  {
  public:
    static gpg::RType* sType;

    CAniPoseBone() = default;

    /**
     * Address: 0x0054C9C0 (FUN_0054C9C0, Moho::CAniPoseBone::CAniPoseBone)
     *
     * What it does:
     * Copy-constructs one pose-bone lane including transform, parent/pose links,
     * and visibility/interpolation flags.
     */
    CAniPoseBone(const CAniPoseBone& copy);

    /**
     * Address: 0x0054EC50 (FUN_0054EC50, Moho::CAniPoseBone::operator=)
     *
     * What it does:
     * Copy-assigns one pose-bone lane field-by-field (composite/local transforms,
     * parent/pose links, index, and visibility/interpolation flags), emitting the
     * FST/FLD per-field copy the release binary uses. Drives the per-element copy
     * in CAniPoseBoneTypeInfo's range copy-assign.
     */
    CAniPoseBone& operator=(const CAniPoseBone& copy) noexcept;

    /**
     * Address: 0x0054BE30 (FUN_0054BE30, Moho::CAniPoseBone::SetVisibleRecur)
     *
     * What it does:
     * Recursively applies one visibility state to this bone and all direct/indirect
     * children in the owning pose's packed bone array.
     */
    [[nodiscard]] std::uint32_t SetVisibleRecur(bool visible);

    /**
     * Address: 0x0054BC00 (FUN_0054BC00, Moho::CAniPoseBone::Rotate)
     *
     * What it does:
     * Applies one local quaternion delta to this bone and invalidates cached
     * composite transform lanes for recomputation.
     */
    void Rotate(const Wm3::Quaternionf& rotation);

    /**
     * Address: 0x0054BDD0 (FUN_0054BDD0)
     *
     * What it does:
     * Replaces this bone's local transform with `transform` and marks the
     * owning pose bone lane dirty for composite rebuild.
     */
    void SetLocalTransform(const VTransform& transform);

    /**
     * Address: 0x0054BEC0 (FUN_0054BEC0, Moho::CAniPoseBone::GetCompositeTransform)
     *
     * What it does:
     * Returns this bone composite transform, recomputing it from parent/local
     * lanes when dirty.
     */
    [[nodiscard]] const VTransform& GetCompositeTransform() const;

    /**
     * Address: 0x0063EE30 (FUN_0063EE30, sub_63EE30)
     *
     * What it does:
     * Resolves this pose bone's corresponding skeleton-bone lane from the
     * owning pose skeleton and returns null when the index is out of range.
     */
    [[nodiscard]] const SAniSkelBone* ResolveSkeletonBone() const;

    /**
     * Address: 0x0063A660 (FUN_0063A660, sub_63A660)
     *
     * IDA signature:
     * const char *__usercall sub_63A660@<eax>(int a1@<eax>);
     *
     * What it does:
     * Returns the skeleton-bone name string for this pose bone. Reads the
     * owning `mPose`, fetches the skeleton via `CAniPose::GetSkeleton`
     * (which yields a ref-counted `shared_ptr<const CAniSkel>`), indexes
     * `skel->mBones._Myfirst` at `mIdx`, and returns the bone's `name`
     * field. Returns null when `mIdx` is out of the skeleton's bone range.
     *
     * Implements the read of bone name through the shared-skeleton pointer
     * with the proper ref-count release on exit (matching the FUN_0063A660
     * out-of-line MSVC8 emission).
     */
    [[nodiscard]] const char* GetBoneName() const;

    /**
     * Address: 0x0054F630 (FUN_0054F630, Moho::CAniPoseBone::MemberSerialize)
     *
     * What it does:
     * Stores per-bone pose serialization lanes (local-space flag, local
     * transform, visibility, interpolation-skip flag).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0054F5C0 (FUN_0054F5C0, Moho::CAniPoseBone::MemberDeserialize)
     *
     * What it does:
     * Loads per-bone pose serialization lanes (local-transform + visibility
     * flags) and marks composite transform dirty for lazy recompute.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    VTransform mCompositeTransform;        // +0x00
    std::uint8_t mCompositeDirty;          // +0x1C
    std::uint8_t mCompositeIsLocal;        // +0x1D
    std::uint8_t pad_1E_1F[0x02]{};
    VTransform mLocalTransform;            // +0x20
    std::int32_t mIdx;                     // +0x3C
    CAniPose* mPose;                       // +0x40
    CAniPoseBone* mParent;                 // +0x44
    std::uint8_t mVisible;                 // +0x48
    std::uint8_t mSkipNextInterp;          // +0x49
    std::uint8_t pad_4A_4B[0x02]{};
  };

  struct CAniPoseBoneArray
  {
  public:
    [[nodiscard]] CAniPoseBone* begin() noexcept
    {
      return mBegin;
    }

    [[nodiscard]] const CAniPoseBone* begin() const noexcept
    {
      return mBegin;
    }

    [[nodiscard]] CAniPoseBone* end() noexcept
    {
      return mEnd;
    }

    [[nodiscard]] const CAniPoseBone* end() const noexcept
    {
      return mEnd;
    }

    /**
     * Address: 0x0054C260 (FUN_0054C260)
     *
     * Live element count, `(mEnd - mBegin) / sizeof(CAniPoseBone)`.
     */
    [[nodiscard]] std::size_t size() const noexcept
    {
      return static_cast<std::size_t>(mEnd - mBegin);
    }

    /**
     * Address: 0x0054D740 (FUN_0054D740)
     *
     * Slots the current storage can hold, `(mCapacity - mBegin) / stride`.
     */
    [[nodiscard]] std::size_t capacity() const noexcept
    {
      return static_cast<std::size_t>(mCapacity - mBegin);
    }

    [[nodiscard]] bool empty() const noexcept
    {
      return mBegin == mEnd;
    }

    /**
     * Address: 0x0054C320 (FUN_0054C320) -- mutable
     * Address: 0x0054C330 (FUN_0054C330) -- const
     *
     * Unchecked indexed access, `mBegin + index`.
     */
    [[nodiscard]] CAniPoseBone& operator[](const std::size_t index) noexcept
    {
      return mBegin[index];
    }

    [[nodiscard]] const CAniPoseBone& operator[](const std::size_t index) const noexcept
    {
      return mBegin[index];
    }

    /**
     * The raw lane stores MSVC emitted for this array's `{mBegin, mEnd,
     * mCapacity, mOriginal}` header, recovered as free functions until they were
     * collapsed here. None of them is a source-level operation: they are the
     * pointer writes inside `resize` / `reserve` / the inline-storage rebind.
     *
     * Address: 0x0054C340 (FUN_0054C340) -- clear the tail lanes
     * Address: 0x0054CD20 (FUN_0054CD20) -- clear the head lanes
     * Address: 0x0054CCE0 (FUN_0054CCE0) -- seed a single-element span
     * Address: 0x0054CDC0 (FUN_0054CDC0) -- store `mBegin`
     * Address: 0x0054CDD0 (FUN_0054CDD0) -- store `mEnd`   (primary lane)
     * Address: 0x0054CDE0 (FUN_0054CDE0) -- store `mCapacity` (primary lane)
     * Address: 0x0054D020 (FUN_0054D020) -- store `mEnd`   (secondary lane)
     * Address: 0x0054D030 (FUN_0054D030) -- store `mCapacity` (secondary lane)
     * Address: 0x0054DCF0 (FUN_0054DCF0) -- uninitialised forward copy of a
     *   `[first, last)` bone range into fresh storage
     */

    /**
     * Reads back the capacity pointer stashed in the first pointer-sized
     * slot of `mInlineStorage` the last time this array grew past inline
     * storage. `mOriginal` always points at `mInlineStorage`, so once the
     * array is rebound to heap storage (`mBegin != mOriginal`), that inline
     * slot is dead space the grow path repurposes to remember the capacity
     * it had before growing -- the same small-buffer-optimization idiom
     * already named `InlineCapacityFromHeader_`/`SaveInlineCapacity_` on
     * `gpg::core::FastVectorN<T,N>` (`gpg/core/containers/FastVector.h`),
     * applied here to this hand-rolled single-inline-element array.
     */
    [[nodiscard]] CAniPoseBone* InlineCapacityFromHeader() const noexcept
    {
      return *reinterpret_cast<CAniPoseBone* const*>(mOriginal);
    }

  public:
    /**
     * Grows or shrinks the live range to `count` bones, filling any new slots
     * with `fillValue`.
     *
     * This is the array's own operation. It was previously performed from
     * outside by `ResizePoseBoneStorage`, which reinterpreted the four header
     * pointers below as a `gpg::fastvector_runtime_view` and handed them to
     * `FastVectorRuntimeResizeFill` -- the `AsFastVectorRuntimeView` reach-in
     * that CLAUDE.md RULE ONE prohibits. The mechanics are unchanged; they just
     * live on the type that owns the pointers.
     *
     * The inline-storage rule is the one thing that makes this not a plain
     * vector: `mOriginal` always points at `mInlineStorage`, so while
     * `mBegin == mOriginal` the storage is the object's own single-slot window
     * and must never be freed. On the first grow past it the binary stashes the
     * outgoing capacity sentinel into that now-dead inline slot instead of
     * deleting anything (see `InlineCapacityFromHeader_` / `SaveInlineCapacity_`
     * on the `gpg` fastvectors, and the same branch in
     * `FastVectorRuntimeReallocateInsert`).
     */
    void resize(const std::size_t count, const CAniPoseBone& fillValue)
    {
      const std::size_t currentSize = size();
      if (count == currentSize) {
        return;
      }

      if (count < currentSize) {
        mEnd = mBegin + count;
        return;
      }

      if (count > capacity()) {
        CAniPoseBone* const grown = new CAniPoseBone[count];
        for (std::size_t i = 0; i < currentSize; ++i) {
          grown[i] = mBegin[i];
        }

        if (mBegin == mOriginal) {
          // Inline window: never freed. The outgoing capacity goes into the
          // slot the live range has just vacated.
          *reinterpret_cast<CAniPoseBone**>(mOriginal) = mCapacity;
        } else {
          delete[] mBegin;
        }

        mBegin = grown;
        mCapacity = grown + count;
      }

      mEnd = mBegin + currentSize;
      for (std::size_t i = currentSize; i < count; ++i) {
        *mEnd = fillValue;
        ++mEnd;
      }
    }

    CAniPoseBone* mBegin;         // +0x00
    CAniPoseBone* mEnd;           // +0x04
    CAniPoseBone* mCapacity;      // +0x08
    CAniPoseBone* mOriginal;      // +0x0C
    CAniPoseBone mInlineStorage;  // +0x10
  };

  class CAniPose
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
     *
     * What it does:
     * Initializes animation-pose state from skeleton + scalar pose factor.
     */
    CAniPose(boost::shared_ptr<const CAniSkel> skeleton, float scale);

    /**
     * Address: 0x0054B290 (FUN_0054B290, ??0CAniPose@Moho@@QAE@ABV01@@Z)
     *
     * What it does:
     * Initializes one pose with default storage lanes, then overwrites it from
     * another pose.
     */
    CAniPose(const CAniPose& copy);

    /**
     * Address: 0x0054DBE0 (FUN_0054DBE0, Moho::CAniPose::~CAniPose)
     *
     * What it does:
     * Releases `mBones`' heap storage when the pose has grown past its
     * single inline bone slot, rebinding begin/end/capacity back to inline
     * storage; `mSkeleton`'s shared skeleton handle is then released by its
     * own `boost::shared_ptr` destructor, which runs automatically
     * immediately afterward.
     */
    ~CAniPose();

    /**
     * Address: 0x0054B330 (FUN_0054B330, ?OverwritePose@CAniPose@Moho@@QAEXABV12@@Z)
     *
     * What it does:
     * Copies skeleton/transform/max-offset state and rebuilds per-bone parent
     * links from this pose's skeleton hierarchy.
     */
    void OverwritePose(const CAniPose& copy);

    /**
     * Address: 0x0054B5F0 (FUN_0054B5F0, ?UpdateBones@CAniPose@Moho@@QAEXXZ)
     *
     * What it does:
     * Seeds per-bone local transforms from the skeleton bind lanes, applying
     * pose scale to local position and resetting composite dirty flags.
     */
    void UpdateBones();

    /**
     * Address: 0x0054B6D0 (FUN_0054B6D0, ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z)
     * Mangled: ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z
     *
     * What it does:
     * Copies local pose transform and per-bone local lanes from one source
     * pose into this pose while marking destination composite lanes dirty.
     */
    void CopyPose(const CAniPose* sourcePose, bool preserveSourceLane);

    /**
     * Address: 0x0054B550 (FUN_0054B550, ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z)
     * Mangled: ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z
     *
     * What it does:
     * Updates pose world transform when orientation/position lanes differ and
     * marks affected non-local bone composite lanes dirty.
     */
    void SetWorldTransform(const VTransform& transform);

    /**
     * Address: 0x0054B770 (FUN_0054B770, ?InterpolatePose@CAniPose@Moho@@QAEXMPBV12@0H@Z)
     *
     * What it does:
     * Interpolates pose transforms and bone lanes from two source poses using
     * the requested blend factor.
     */
    void InterpolatePose(float interp, const CAniPose* sourcePose, const CAniPose* targetPose, int bones);

    /**
     * Address: 0x005E3B10 (FUN_005E3B10, ?GetSkeleton@CAniPose@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns a retained copy of this pose's skeleton shared handle.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

    /**
     * Address: 0x0054F380 (FUN_0054F380, Moho::CAniPose::MemberDeserialize)
     *
     * What it does:
     * Deserializes skeleton/shared lanes, local transform, and pose-bone
     * payload, then rebuilds per-bone pose/parent links from skeleton data.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0054F4F0 (FUN_0054F4F0, Moho::CAniPose::MemberSerialize)
     *
     * What it does:
     * Serializes skeleton pointer, scalar/local transform lanes, bone array
     * payload, and max-offset cache value.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    friend class CAniPoseBone;
    friend class CBoneEntityManipulator;

  private:
    /**
     * Address: 0x0054B990 (FUN_0054B990, ?MarkBoneDirty@CAniPose@Moho@@AAEXH@Z)
     *
     * What it does:
     * Marks one bone as composite-dirty, then propagates that dirty state to
     * downstream bones whose parent is already dirty.
     */
    void MarkBoneDirty(int idx);

    /**
     * Address: 0x0054BD80 (FUN_0054BD80)
     *
     * What it does:
     * Composes one pose-bone local transform with an incoming transform and
     * marks that bone dirty through its pose/index ownership lanes.
     */
    static void ApplyBoneLocalTransform(CAniPoseBone* bone, const VTransform& transform);

  public:
    boost::shared_ptr<const CAniSkel> mSkeleton; // +0x00
    float mScale;                                // +0x08
    VTransform mLocalTransform;                  // +0x0C
    CAniPoseBoneArray mBones;                    // +0x28
    std::uint8_t pad_84_87[0x04]{};
    float mMaxOffset;                            // +0x88
    std::uint8_t pad_8C_8F[0x04]{};
  };

  static_assert(offsetof(CAniPoseBone, mCompositeDirty) == 0x1C, "CAniPoseBone::mCompositeDirty offset must be 0x1C");
  static_assert(offsetof(CAniPoseBone, mCompositeIsLocal) == 0x1D, "CAniPoseBone::mCompositeIsLocal offset must be 0x1D");
  static_assert(offsetof(CAniPoseBone, mLocalTransform) == 0x20, "CAniPoseBone::mLocalTransform offset must be 0x20");
  static_assert(offsetof(CAniPoseBone, mIdx) == 0x3C, "CAniPoseBone::mIdx offset must be 0x3C");
  static_assert(offsetof(CAniPoseBone, mPose) == 0x40, "CAniPoseBone::mPose offset must be 0x40");
  static_assert(offsetof(CAniPoseBone, mParent) == 0x44, "CAniPoseBone::mParent offset must be 0x44");
  static_assert(offsetof(CAniPoseBone, mVisible) == 0x48, "CAniPoseBone::mVisible offset must be 0x48");
  static_assert(offsetof(CAniPoseBone, mSkipNextInterp) == 0x49, "CAniPoseBone::mSkipNextInterp offset must be 0x49");
  static_assert(sizeof(CAniPoseBone) == 0x4C, "CAniPoseBone size must be 0x4C");
  static_assert(offsetof(CAniPoseBoneArray, mBegin) == 0x00, "CAniPoseBoneArray::mBegin offset must be 0x00");
  static_assert(offsetof(CAniPoseBoneArray, mInlineStorage) == 0x10, "CAniPoseBoneArray::mInlineStorage offset must be 0x10");
  static_assert(sizeof(CAniPoseBoneArray) == 0x5C, "CAniPoseBoneArray size must be 0x5C");
  static_assert(offsetof(CAniPose, mSkeleton) == 0x00, "CAniPose::mSkeleton offset must be 0x00");
  static_assert(offsetof(CAniPose, mScale) == 0x08, "CAniPose::mScale offset must be 0x08");
  static_assert(offsetof(CAniPose, mLocalTransform) == 0x0C, "CAniPose::mLocalTransform offset must be 0x0C");
  static_assert(offsetof(CAniPose, mBones) == 0x28, "CAniPose::mBones offset must be 0x28");
  static_assert(offsetof(CAniPose, mMaxOffset) == 0x88, "CAniPose::mMaxOffset offset must be 0x88");
  static_assert(sizeof(CAniPose) == 0x90, "CAniPose size must be 0x90");

  /**
   * VFTABLE: 0x00E1742C
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CAniPose>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_CAniPoseSerializer`):
   *    0x00BC9960 (dead zero-xref COMDAT duplicate: 0x0054C5E0)
   *  - dtor: 0x00BF4610 (`??1CAniPoseSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x0054C610
   *  - Deserialize(): 0x0054BA00
   *  - Serialize(): 0x0054BA10
   */
  using CAniPoseSerializer = gpg::SerSaveLoadHelper<CAniPose>;

  /**
   * VFTABLE: 0x00E174B0
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CAniPoseBone>
   *
   * Per-instantiation addresses:
   *  - ctor / compiler dynamic-initializer (`register_CAniPoseBoneSerializer`):
   *    0x00BC99C0 (dead zero-xref COMDAT duplicate: 0x0054C8C0)
   *  - dtor: 0x00BF46A0 (`??1CAniPoseBoneSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x0054C8F0
   *  - Deserialize(): 0x0054BF70
   *  - Serialize(): 0x0054BF80
   */
  using CAniPoseBoneSerializer = gpg::SerSaveLoadHelper<CAniPoseBone>;
} // namespace moho
