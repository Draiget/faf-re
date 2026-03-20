#pragma once

#include <cstddef>
#include <cstdint>

#include "wm3/Box3.h"
#include "wm3/Sphere3.h"
#include "wm3/Vector3.h"

namespace moho
{
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
    std::uint32_t reserved04; // +0x04
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
   * Segment-shape collision output.
   * Field at +0x00 is currently not touched by these methods.
   */
  struct CollisionLineResult
  {
    std::uint32_t reserved00;    // +0x00
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
   * Common virtual interface for collision primitive instances (`Moho::CColPrimitiveBase`).
   */
  class EntityCollisionUpdater
  {
  public:
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
    virtual const EntityCollisionBoundsView* GetBoundingBox(EntityCollisionBoundsScratch* scratch0x1C) const = 0;

    /**
     * Address: 0x004FF130 / 0x004FE780
     *
     * What it does:
     * Returns a typed view to sphere payload for sphere primitive or null for box primitive.
     */
    virtual const Wm3::Sphere3f* GetSphere() const = 0;

    /**
     * Address: 0x004FF140 / 0x004FE790
     *
     * What it does:
     * Returns a typed view to box payload for box primitive or null for sphere primitive.
     */
    virtual const Wm3::Box3f* GetBox() const = 0;

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
    virtual void SetTransform(const EntityTransformPayload& transform) = 0;

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
    virtual Wm3::Vec3f* GetCenter(Wm3::Vec3f* outCenter) const = 0;

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
    virtual const Wm3::Vec3f* SetCenter(const Wm3::Vec3f* center) = 0;

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
    CollideLine(const Wm3::Vec3f* lineStart, const Wm3::Vec3f* lineEnd, CollisionLineResult* outResult) const = 0;

    /**
     * Address: 0x004FF260 / 0x004FE860
     *
     * Wm3::Box3<float> const*, CollisionPairResult*
     *
     * What it does:
     * Tests box-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideBox(const Wm3::Box3f* box, CollisionPairResult* outResult) const = 0;

    /**
     * Address: 0x004FF150 / 0x004FE7A0
     *
     * Wm3::Sphere3<float> const*, CollisionPairResult*
     *
     * What it does:
     * Tests sphere-vs-shape overlap and fills penetration direction/depth on hit.
     */
    virtual bool CollideSphere(const Wm3::Sphere3f* sphere, CollisionPairResult* outResult) const = 0;

    /**
     * Address: 0x004FF450 / 0x004FEB60
     *
     * Wm3::Vector3<float> const*
     *
     * What it does:
     * Returns whether point lies inside primitive volume.
     */
    virtual bool PointInShape(const Wm3::Vec3f* point) const = 0;

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
