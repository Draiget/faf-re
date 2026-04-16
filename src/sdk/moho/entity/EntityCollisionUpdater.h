#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Box3.h"
#include "Wm3Sphere3.h"
#include "Wm3Vector3.h"
#include "gpg/core/containers/FastVector.h"

namespace moho
{
  class Entity;

  struct EntityTransformPayload;

  struct EntityCollisionBoundsView
  {
    float minX;
    float minY;
    float minZ;
    float maxX;
    float maxY;
    float maxZ;
  };
  static_assert(sizeof(EntityCollisionBoundsView) == 0x18, "EntityCollisionBoundsView size must be 0x18");

  /**
   * Scratch payload passed to primitive `GetBoundingBox` slot.
   *
   * Binary evidence:
   * - Callers allocate 0x1C bytes on stack (`_BYTE[28]`) and pass to vtable slot 0.
   * - Primitive writes the first 0x18 bytes as `{min,max}` floats.
   * - Last 0x04 bytes are currently not consumed by known callers.
   */
  struct EntityCollisionBoundsScratch
  {
    EntityCollisionBoundsView bounds; // +0x00 .. +0x17
    std::uint32_t reserved18;         // +0x18
  };
  static_assert(sizeof(EntityCollisionBoundsScratch) == 0x1C, "EntityCollisionBoundsScratch size must be 0x1C");

  /**
   * Address: 0x004FE7A0 / 0x004FE860 / 0x004FF150 / 0x004FF260
   *
   * What it does:
   * Common pair-shape collision output.
   * The first 0x08 bytes are not written by these methods in observed call paths.
   */
  struct CollisionPairResult
  {
    std::uint32_t reserved00; // +0x00
    Entity* sourceEntity;     // +0x04
    Wm3::Vec3f direction;     // +0x08
    float penetrationDepth;   // +0x14
  };
  static_assert(sizeof(CollisionPairResult) == 0x18, "CollisionPairResult size must be 0x18");
  static_assert(offsetof(CollisionPairResult, direction) == 0x08, "CollisionPairResult::direction offset must be 0x08");
  static_assert(
    offsetof(CollisionPairResult, penetrationDepth) == 0x14, "CollisionPairResult::penetrationDepth offset must be 0x14"
  );

  /**
   * Address: 0x004FE9D0 / 0x004FF2D0
   *
   * What it does:
   * Segment-shape collision output. `Entity::Intersects(lineStart, lineEnd, ...)`
   * stamps the owning source entity into `sourceEntity` (+0x00) on hit.
   */
  struct CollisionLineResult
  {
    Entity* sourceEntity;        // +0x00
    Wm3::Vec3f direction;        // +0x04
    Wm3::Vec3f position;         // +0x10
    float distanceFromLineStart; // +0x1C
  };
  static_assert(sizeof(CollisionLineResult) == 0x20, "CollisionLineResult size must be 0x20");
  static_assert(offsetof(CollisionLineResult, direction) == 0x04, "CollisionLineResult::direction offset must be 0x04");
  static_assert(offsetof(CollisionLineResult, position) == 0x10, "CollisionLineResult::position offset must be 0x10");
  static_assert(
    offsetof(CollisionLineResult, distanceFromLineStart) == 0x1C,
    "CollisionLineResult::distanceFromLineStart offset must be 0x1C"
  );

  using CollisionResult = CollisionPairResult;
  using CollisionEntry = CollisionLineResult;

  /**
   * Address: 0x007237E0 (FUN_007237E0, func_CopyCollisionResultArr2)
   *
   * What it does:
   * Copies one `CollisionResult` range backward from `[sourceBegin, sourceEnd)`
   * into output ending at `outEnd`; returns the destination begin pointer.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsBackward(
    CollisionResult* outEnd,
    const CollisionResult* sourceEnd,
    const CollisionResult* sourceBegin
  ) noexcept;

  /**
   * Address: 0x00723770 (FUN_00723770, func_CopyCollisionResultArr3)
   *
   * What it does:
   * Binary twin of `CopyCollisionResultsBackward`; copies one
   * `CollisionResult` range backward from `[sourceBegin, sourceEnd)` into
   * output ending at `outEnd` and returns the destination begin pointer.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsBackwardAlt(
    CollisionResult* outEnd,
    const CollisionResult* sourceEnd,
    const CollisionResult* sourceBegin
  ) noexcept;

  /**
   * Address: 0x00723410 (FUN_00723410, func_CopyCollisionResultArr1)
   *
   * What it does:
   * Copies one `CollisionResult` range forward from `[sourceBegin, sourceEnd)`
   * into output beginning at `outBegin`; returns the destination end pointer.
   *
   * Binary note:
   * The original helper increments the destination cursor even when `outBegin`
   * is null (used as a size/cursor lane by callers). The implementation keeps
   * that behavior.
   */
  [[nodiscard]] CollisionResult* CopyCollisionResultsForward(
    CollisionResult* outBegin,
    const CollisionResult* sourceBegin,
    const CollisionResult* sourceEnd
  ) noexcept;

  /**
   * Address: 0x00723090 (FUN_00723090, sub_723090)
   *
   * What it does:
   * Inserts one `CollisionResult` range `[sourceBegin, sourceEnd)` before
   * `insertBefore` in `outCollisions`, growing storage when required, and
   * returns the rebased insertion pointer in the active storage lane.
   */
  [[nodiscard]] CollisionResult* InsertCollisionResultRange(
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions,
    CollisionResult* insertBefore,
    const CollisionResult* sourceBegin,
    const CollisionResult* sourceEnd
  ) noexcept;

  /**
   * Address: 0x0057E9D0 (FUN_0057E9D0, gpg::fastvector_n_CollisionResult::~fastvector_n_CollisionResult)
   *
   * Concrete fastvector alias that materializes the binary-observed
   * specialization `gpg::FastVectorN<Moho::CollisionResult, 10>`. The
   * destructor for this specialization is auto-generated by the
   * `gpg::core::FastVectorN` template: it calls `operator delete[]`
   * on the active heap buffer when storage has escaped the inline
   * lane, then releases the tracking pointers. `CollisionResult` is
   * trivially destructible (POD pair result), so no per-element
   * destructors are needed.
   */
  using CollisionResultFastVectorN10 = gpg::core::FastVectorN<CollisionResult, 10>;

  /**
   * Common virtual interface for collision primitive instances (`Moho::CColPrimitiveBase`).
   */
  class EntityCollisionUpdater
  {
  public:
    /**
     * Address: 0x004FFDE0 (FUN_004FFDE0, Moho::CColPrimitiveBase::CColPrimitiveBase)
     *
     * What it does:
     * Initializes one collision-primitive base runtime lane.
     */
    EntityCollisionUpdater();

    /**
     * Address: 0x004FFC20 / 0x004FF9A0
     *
     * EntityCollisionBoundsScratch*
     *
     * IDA signature:
     * int __thiscall sub_4FFC20(char* this, int scratchOut);
     *
     * What it does:
     * Writes world-space AABB to caller scratch and returns `&scratch->bounds`.
     */
    virtual const EntityCollisionBoundsView* GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const;

    /**
     * Address: 0x004FF130 / 0x004FE780
     *
     * What it does:
     * Returns a typed view to sphere payload for sphere primitive or null for box primitive.
     */
    virtual const Wm3::Sphere3f* GetSphere() const;

    /**
     * Address: 0x004FF140 / 0x004FE790
     *
     * What it does:
     * Returns a typed view to box payload for box primitive or null for sphere primitive.
     */
    virtual const Wm3::Box3f* GetBox() const;

    /**
     * Address: 0x004FF470 / 0x004FEBC0
     *
     * EntityTransformPayload const&
     *
     * IDA signature:
     * int __thiscall sub_100FF470(int this, float* transformPayload);
     *
     * What it does:
     * Applies world transform payload to local primitive state.
     */
    virtual void SetTransform(const EntityTransformPayload& transform);

    /**
     * Address: 0x004FFBE0 / 0x004FF960
     *
     * Wm3::Vector3<float>*
     *
     * IDA signature:
     * Wm3::Vector3f *__thiscall Moho::CColPrimitive::Box::GetCenter(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2);
     *
     * What it does:
     * Copies current world-space center into `outCenter` and returns it.
     */
    virtual Wm3::Vec3f* GetCenter(Wm3::Vec3f* outCenter) const;

    /**
     * Address: 0x004FFC00 / 0x004FF980
     *
     * Wm3::Vector3<float> const*
     *
     * IDA signature:
     * Wm3::Vector3f *__thiscall Moho::CColPrimitive::Box::SetCenter(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2);
     *
     * What it does:
     * Copies `*center` into primitive world-space center and returns `center`.
     */
    virtual const Wm3::Vec3f* SetCenter(const Wm3::Vec3f* center);

    /**
     * Address: 0x004FF2D0 / 0x004FE9D0
     *
     * Wm3::Vector3<float> const*, Wm3::Vector3<float> const*, CollisionLineResult*
     *
     * IDA signature:
     * char __thiscall Moho::CColPrimitive::Box::CollideLine(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2,
     * Wm3::Vector3f *a3, struct_CollisionEntry *a4);
     *
     * What it does:
     * Tests segment-vs-shape and fills direction/contact position/travel distance.
     */
    virtual bool
    CollideLine(const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult) const;

    /**
     * Address: 0x004FF260 / 0x004FE860
     *
     * Wm3::Box3<float> const*, CollisionPairResult*
     *
     * What it does:
     * Tests box-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const;

    /**
     * Address: 0x004FF150 / 0x004FE7A0
     *
     * Wm3::Sphere3<float> const*, CollisionPairResult*
     *
     * What it does:
     * Tests sphere-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const;

    /**
     * Address: 0x004FF450 / 0x004FEB60
     *
     * Wm3::Vector3<float> const*
     *
     * What it does:
     * Returns whether point lies inside primitive volume.
     */
    virtual bool PointInShape(const Wm3::Vec3f* point) const;

    /**
     * Address: 0x00676A40 (FUN_00676A40, Moho::CColPrimitiveBase::Collide)
     * Mangled: ?Collide@CColPrimitiveBase@Moho@@QAE_NPAVCColPrimitiveBase@2@PAUCollisionResult@2@@Z
     *
     * with, CollisionResult*
     *
     * What it does:
     * Dispatches shape-vs-shape collision: queries `with->GetBox()` or
     * `with->GetSphere()` to determine shape type, then calls the matching
     * `CollideBox`/`CollideSphere` virtual on `this` with the extracted shape
     * pointer.  Asserts if `with` has neither box nor sphere shape.
     */
    bool Collide(const EntityCollisionUpdater* with, CollisionPairResult* outResult) const;

  protected:
    ~EntityCollisionUpdater() = default;
  };

  /**
   * Concrete box primitive (`Moho::CColPrimitive<Wm3::Box3<float>>`).
   */
  class BoxCollisionPrimitive final : public EntityCollisionUpdater
  {
  public:
    /**
     * Address: 0x0067AC40 (FUN_0067AC40, inlined construction payload)
     */
    explicit BoxCollisionPrimitive(const Wm3::Box3f& localBox);

    /**
     * Address: 0x004FFC20 (FUN_004FFC20)
     */
    [[nodiscard]] const EntityCollisionBoundsView*
    GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const override;

    /**
     * Address: 0x004FF130 (FUN_004FF130)
     */
    [[nodiscard]] const Wm3::Sphere3f* GetSphere() const override;

    /**
     * Address: 0x004FF140 (FUN_004FF140)
     */
    [[nodiscard]] const Wm3::Box3f* GetBox() const override;

    /**
     * Address: 0x004FF470 (FUN_004FF470)
     */
    void SetTransform(const EntityTransformPayload& transform) override;

    /**
     * Address: 0x004FFBE0 (FUN_004FFBE0)
     */
    [[nodiscard]] Wm3::Vec3f* GetCenter(Wm3::Vec3f* outCenter) const override;

    /**
     * Address: 0x004FFC00 (FUN_004FFC00)
     */
    [[nodiscard]] const Wm3::Vec3f* SetCenter(const Wm3::Vec3f* center) override;

    /**
     * Address: 0x004FF2D0 (FUN_004FF2D0)
     */
    [[nodiscard]] bool
    CollideLine(const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult) const override;

    /**
     * Address: 0x004FF260 (FUN_004FF260)
     */
    [[nodiscard]] bool CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const override;

    /**
     * Address: 0x004FF150 (FUN_004FF150)
     */
    [[nodiscard]] bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const override;

    /**
     * Address: 0x004FF450 (FUN_004FF450)
     */
    [[nodiscard]] bool PointInShape(const Wm3::Vec3f* point) const override;

  public:
    Wm3::Box3f mShape;       // +0x04
    Wm3::Vec3f mLocalCenter; // +0x40
  };

  /**
   * Concrete sphere primitive (`Moho::CColPrimitive<Wm3::Sphere3<float>>`).
   */
  class SphereCollisionPrimitive final : public EntityCollisionUpdater
  {
  public:
    /**
     * Address: 0x0067AD30 (FUN_0067AD30, inlined construction payload)
     */
    SphereCollisionPrimitive(const Wm3::Vec3f& localCenter, float radius);

    /**
     * Address: 0x004FF9A0 (FUN_004FF9A0)
     */
    [[nodiscard]] const EntityCollisionBoundsView*
    GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const override;

    /**
     * Address: 0x004FE780 (FUN_004FE780)
     */
    [[nodiscard]] const Wm3::Sphere3f* GetSphere() const override;

    /**
     * Address: 0x004FE790 (FUN_004FE790)
     */
    [[nodiscard]] const Wm3::Box3f* GetBox() const override;

    /**
     * Address: 0x004FEBC0 (FUN_004FEBC0)
     */
    void SetTransform(const EntityTransformPayload& transform) override;

    /**
     * Address: 0x004FF960 (FUN_004FF960)
     */
    [[nodiscard]] Wm3::Vec3f* GetCenter(Wm3::Vec3f* outCenter) const override;

    /**
     * Address: 0x004FF980 (FUN_004FF980)
     */
    [[nodiscard]] const Wm3::Vec3f* SetCenter(const Wm3::Vec3f* center) override;

    /**
     * Address: 0x004FE9D0 (FUN_004FE9D0)
     */
    [[nodiscard]] bool
    CollideLine(const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult) const override;

    /**
     * Address: 0x004FE860 (FUN_004FE860)
     */
    [[nodiscard]] bool CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const override;

    /**
     * Address: 0x004FE7A0 (FUN_004FE7A0)
     */
    [[nodiscard]] bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const override;

    /**
     * Address: 0x004FEB60 (FUN_004FEB60)
     */
    [[nodiscard]] bool PointInShape(const Wm3::Vec3f* point) const override;

  public:
    Wm3::Sphere3f mShape;    // +0x04
    Wm3::Vec3f mLocalCenter; // +0x14
  };

#if defined(_M_IX86) || defined(__i386__)
  static_assert(sizeof(EntityCollisionUpdater) == 0x04, "EntityCollisionUpdater size must be 0x04");

  static_assert(offsetof(BoxCollisionPrimitive, mShape) == 0x04, "BoxCollisionPrimitive::mShape offset must be 0x04");
  static_assert(
    offsetof(BoxCollisionPrimitive, mLocalCenter) == 0x40, "BoxCollisionPrimitive::mLocalCenter offset must be 0x40"
  );
  static_assert(sizeof(BoxCollisionPrimitive) == 0x4C, "BoxCollisionPrimitive size must be 0x4C");

  static_assert(
    offsetof(SphereCollisionPrimitive, mShape) == 0x04, "SphereCollisionPrimitive::mShape offset must be 0x04"
  );
  static_assert(
    offsetof(SphereCollisionPrimitive, mLocalCenter) == 0x14,
    "SphereCollisionPrimitive::mLocalCenter offset must be 0x14"
  );
  static_assert(sizeof(SphereCollisionPrimitive) == 0x20, "SphereCollisionPrimitive size must be 0x20");
#endif
} // namespace moho
