#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3AxisAlignedBox3.h"
#include "Wm3Box3.h"
#include "Wm3Sphere3.h"
#include "Wm3Vector3.h"

namespace moho
{
  class Entity;

  class VTransform;

  /**
   * Address: 0x004FE7A0 (FUN_004FE7A0) / 0x004FE860 / 0x004FF150 / 0x004FF260
   *
   * What it does:
   * Common pair-shape collision output, `Moho::CollisionResult` in the
   * `Entity::Intersects(Sphere3/Box3, ...)` and `CColPrimitiveBase::Collide`
   * mangled names.
   * The first 0x08 bytes are not written by these methods in observed call paths.
   */
  struct CollisionResult
  {
    std::uint32_t reserved00; // +0x00
    Entity* sourceEntity;     // +0x04
    Wm3::Vec3f direction;     // +0x08
    float penetrationDepth;   // +0x14
  };
  static_assert(sizeof(CollisionResult) == 0x18, "CollisionResult size must be 0x18");
  static_assert(offsetof(CollisionResult, direction) == 0x08, "CollisionResult::direction offset must be 0x08");
  static_assert(
    offsetof(CollisionResult, penetrationDepth) == 0x14, "CollisionResult::penetrationDepth offset must be 0x14"
  );

  /**
   * Address: 0x004FE9D0 (FUN_004FE9D0) / 0x004FF2D0
   *
   * What it does:
   * Segment-shape collision output, `Moho::CollisionSegmentResult` in the
   * `Entity::Intersects(lineStart, lineEnd, ...)` mangling. That call stamps
   * the owning source entity into `sourceEntity` (+0x00) on hit.
   */
  struct CollisionSegmentResult
  {
    Entity* sourceEntity;        // +0x00
    Wm3::Vec3f direction;        // +0x04
    Wm3::Vec3f position;         // +0x10
    float distanceFromLineStart; // +0x1C
  };
  static_assert(sizeof(CollisionSegmentResult) == 0x20, "CollisionSegmentResult size must be 0x20");
  static_assert(
    offsetof(CollisionSegmentResult, direction) == 0x04, "CollisionSegmentResult::direction offset must be 0x04"
  );
  static_assert(
    offsetof(CollisionSegmentResult, position) == 0x10, "CollisionSegmentResult::position offset must be 0x10"
  );
  static_assert(
    offsetof(CollisionSegmentResult, distanceFromLineStart) == 0x1C,
    "CollisionSegmentResult::distanceFromLineStart offset must be 0x1C"
  );

  /**
   * Common virtual interface for collision primitive instances (`Moho::CColPrimitiveBase`).
   *
   * Every one of these ten virtuals is **pure**. `CColPrimitiveBase`'s own
   * vftable (0x00E0D3F4, 10 slots) has all ten entries pointing at
   * `_purecall` (0x00A82547), so this class contributes no bodies at all.
   *
   * The addresses annotated on each method below are the **overrides**, and
   * they come in pairs because the implementer is a template with exactly two
   * instantiations -- `Moho::CColPrimitive<Wm3::Box3f>` (vftable 0x00E0D50C)
   * and `Moho::CColPrimitive<Wm3::Sphere3f>` (vftable 0x00E0D480), both
   * deriving from this class with matching 10-slot tables. The first address
   * in each pair is the Box3f instantiation, the second the Sphere3f one.
   * Both are recovered below as explicit specializations; each keeps its
   * world-space shape at `+0x04` (see `GetSphere`/`GetBox`) followed by its
   * local center.
   *
   * GPG's own home for this was `src/core/ColMain.h`: `Collide`'s unreachable
   * assert names `c:\work\rts\main\code\src\core/ColMain.h` line 94. The
   * primitive bodies sit interleaved with the `DColPrimBox`/`DColPrimSphere`
   * reflection code (0x004FE6A0-0x00500570), which is why they live in this
   * folder rather than beside `Entity`.
   */
  class CColPrimitiveBase
  {
  public:
    /**
     * Address: 0x004FFDE0 (FUN_004FFDE0, Moho::CColPrimitiveBase::CColPrimitiveBase)
     *
     * What it does:
     * Initializes one collision-primitive base runtime lane.
     */
    CColPrimitiveBase();

    /**
     * Address: 0x004FFC20 (FUN_004FFC20) / 0x004FF9A0
     *
     * IDA signature:
     * int __thiscall sub_4FFC20(char* this, int scratchOut);
     *
     * What it does:
     * Returns the primitive's world-space axis-aligned bounds by value.
     *
     * IDA's `scratchOut` is MSVC's hidden return slot: both overrides write
     * six floats, `{Min, Max}`, to `[eax+0x00..0x14]`, hand the same pointer
     * back in EAX and end `ret 4`, and the caller at 0x004FD516 passes the
     * result straight to `func_AABoxToRect`, which takes a
     * `Wm3::AxisAlignedBox3f`.
     */
    virtual Wm3::AxisAlignedBox3f GetBoundingBox() const = 0;

    /**
     * Address: 0x004FF130 (FUN_004FF130) / 0x004FE780
     *
     * What it does:
     * Returns a typed view to sphere payload for sphere primitive or null for box primitive.
     */
    virtual const Wm3::Sphere3f* GetSphere() const = 0;

    /**
     * Address: 0x004FF140 (FUN_004FF140) / 0x004FE790
     *
     * What it does:
     * Returns a typed view to box payload for box primitive or null for sphere primitive.
     */
    virtual const Wm3::Box3f* GetBox() const = 0;

    /**
     * Address: 0x004FF470 (FUN_004FF470) / 0x004FEBC0
     *
     * Moho::VTransform const&
     *
     * IDA signature:
     * int __thiscall sub_100FF470(int this, float* transformPayload);
     *
     * What it does:
     * Applies world transform payload to local primitive state.
     */
    virtual void SetTransform(const VTransform& transform) = 0;

    /**
     * Address: 0x004FFBE0 (FUN_004FFBE0) / 0x004FF960
     *
     * Wm3::Vector3<float>*
     *
     * IDA signature:
     * Wm3::Vector3f *__thiscall Moho::CColPrimitive::Box::GetCenter(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2);
     *
     * What it does:
     * Copies current world-space center into `outCenter` and returns it.
     */
    virtual Wm3::Vec3f* GetCenter(Wm3::Vec3f* outCenter) const = 0;

    /**
     * Address: 0x004FFC00 (FUN_004FFC00) / 0x004FF980
     *
     * Wm3::Vector3<float> const*
     *
     * IDA signature:
     * Wm3::Vector3f *__thiscall Moho::CColPrimitive::Box::SetCenter(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2);
     *
     * What it does:
     * Copies `*center` into primitive world-space center and returns `center`.
     */
    virtual const Wm3::Vec3f* SetCenter(const Wm3::Vec3f* center) = 0;

    /**
     * Address: 0x004FF2D0 (FUN_004FF2D0) / 0x004FE9D0
     *
     * Wm3::Vector3<float> const*, Wm3::Vector3<float> const*, CollisionSegmentResult*
     *
     * IDA signature:
     * char __thiscall Moho::CColPrimitive::Box::CollideLine(Moho::CColPrimitive_Box *this, Wm3::Vector3f *a2,
     * Wm3::Vector3f *a3, struct_CollisionEntry *a4);
     *
     * What it does:
     * Tests segment-vs-shape and fills direction/contact position/travel distance.
     */
    virtual bool
    CollideLine(const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionSegmentResult* outResult) const = 0;

    /**
     * Address: 0x004FF260 (FUN_004FF260) / 0x004FE860
     *
     * Wm3::Box3<float> const*, CollisionResult*
     *
     * What it does:
     * Tests box-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideBox(const Wm3::Box3f* box, CollisionResult* outResult) const = 0;

    /**
     * Address: 0x004FF150 (FUN_004FF150) / 0x004FE7A0
     *
     * Wm3::Sphere3<float> const*, CollisionResult*
     *
     * What it does:
     * Tests sphere-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionResult* outResult) const = 0;

    /**
     * Address: 0x004FF450 (FUN_004FF450) / 0x004FEB60
     *
     * Wm3::Vector3<float> const*
     *
     * What it does:
     * Returns whether point lies inside primitive volume.
     */
    virtual bool PointInShape(const Wm3::Vec3f* point) const = 0;

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
    bool Collide(const CColPrimitiveBase* with, CollisionResult* outResult) const;

  protected:
    ~CColPrimitiveBase() = default;
  };

  /**
   * `Moho::CColPrimitive<T>`, the implementer of `CColPrimitiveBase`. The
   * binary instantiates it for exactly two shapes, so only those two
   * specializations exist; the primary template is never defined.
   */
  template <class TShape>
  class CColPrimitive;

  /**
   * Box primitive (`Moho::CColPrimitive<Wm3::Box3<float>>`, vftable 0x00E0D50C).
   */
  template <>
  class CColPrimitive<Wm3::Box3f> final : public CColPrimitiveBase
  {
  public:
    /**
     * Address: 0x0067AC40 (FUN_0067AC40, inlined construction payload)
     */
    explicit CColPrimitive(const Wm3::Box3f& localBox);

    /**
     * Address: 0x004FFC20 (FUN_004FFC20)
     */
    [[nodiscard]] Wm3::AxisAlignedBox3f GetBoundingBox() const override;

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
    void SetTransform(const VTransform& transform) override;

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
    [[nodiscard]] bool CollideLine(
      const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionSegmentResult* outResult
    ) const override;

    /**
     * Address: 0x004FF260 (FUN_004FF260)
     */
    [[nodiscard]] bool CollideBox(const Wm3::Box3f* box, CollisionResult* outResult) const override;

    /**
     * Address: 0x004FF150 (FUN_004FF150)
     */
    [[nodiscard]] bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionResult* outResult) const override;

    /**
     * Address: 0x004FF450 (FUN_004FF450)
     */
    [[nodiscard]] bool PointInShape(const Wm3::Vec3f* point) const override;

  public:
    Wm3::Box3f mShape;       // +0x04
    Wm3::Vec3f mLocalCenter; // +0x40
  };

  /**
   * Sphere primitive (`Moho::CColPrimitive<Wm3::Sphere3<float>>`, vftable 0x00E0D480).
   */
  template <>
  class CColPrimitive<Wm3::Sphere3f> final : public CColPrimitiveBase
  {
  public:
    /**
     * Address: 0x0067AD30 (FUN_0067AD30, inlined construction payload)
     */
    CColPrimitive(const Wm3::Vec3f& localCenter, float radius);

    /**
     * Address: 0x004FF9A0 (FUN_004FF9A0)
     */
    [[nodiscard]] Wm3::AxisAlignedBox3f GetBoundingBox() const override;

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
    void SetTransform(const VTransform& transform) override;

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
    [[nodiscard]] bool CollideLine(
      const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionSegmentResult* outResult
    ) const override;

    /**
     * Address: 0x004FE860 (FUN_004FE860)
     */
    [[nodiscard]] bool CollideBox(const Wm3::Box3f* box, CollisionResult* outResult) const override;

    /**
     * Address: 0x004FE7A0 (FUN_004FE7A0)
     */
    [[nodiscard]] bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionResult* outResult) const override;

    /**
     * Address: 0x004FEB60 (FUN_004FEB60)
     */
    [[nodiscard]] bool PointInShape(const Wm3::Vec3f* point) const override;

  public:
    Wm3::Sphere3f mShape;    // +0x04
    Wm3::Vec3f mLocalCenter; // +0x14
  };

#if defined(_M_IX86) || defined(__i386__)
  static_assert(sizeof(CColPrimitiveBase) == 0x04, "CColPrimitiveBase size must be 0x04");

  static_assert(
    offsetof(CColPrimitive<Wm3::Box3f>, mShape) == 0x04, "CColPrimitive<Wm3::Box3f>::mShape offset must be 0x04"
  );
  static_assert(
    offsetof(CColPrimitive<Wm3::Box3f>, mLocalCenter) == 0x40,
    "CColPrimitive<Wm3::Box3f>::mLocalCenter offset must be 0x40"
  );
  static_assert(sizeof(CColPrimitive<Wm3::Box3f>) == 0x4C, "CColPrimitive<Wm3::Box3f> size must be 0x4C");

  static_assert(
    offsetof(CColPrimitive<Wm3::Sphere3f>, mShape) == 0x04, "CColPrimitive<Wm3::Sphere3f>::mShape offset must be 0x04"
  );
  static_assert(
    offsetof(CColPrimitive<Wm3::Sphere3f>, mLocalCenter) == 0x14,
    "CColPrimitive<Wm3::Sphere3f>::mLocalCenter offset must be 0x14"
  );
  static_assert(sizeof(CColPrimitive<Wm3::Sphere3f>) == 0x20, "CColPrimitive<Wm3::Sphere3f> size must be 0x20");
#endif
} // namespace moho
