#pragma once

#include <cstddef>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SPhysConstants.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  class VTransform;

  /**
   * One world-space ground-penetration sample: the contact point plus the
   * terrain elevation sampled under it. Produced by
   * `CUnitMotion::HandleGroundCollision` (per-sphere terrain overlap check)
   * and consumed by `SPhysBody::ApplyGroundCollisionResponse`.
   */
  struct GroundPenetrationSample
  {
    float x;                 // +0x00
    float y;                 // +0x04
    float z;                 // +0x08
    float terrainElevation;  // +0x0C
  };
  static_assert(sizeof(GroundPenetrationSample) == 0x10, "GroundPenetrationSample size must be 0x10");

  /**
   * Address owner:
   * - 0x00679290 (FUN_00679290, Moho::Entity::GetPhysBody stack payload)
   *
   * What it does:
   * Packs mass, inertia-tensor, and collision-offset lanes used to construct
   * one `SPhysBody`.
   */
  struct SPhysBodyParams
  {
    float mass;                  // +0x00
    Wm3::Vec3f inertiaTensor;    // +0x04
    Wm3::Vec3f collisionOffset;  // +0x10
  };

  static_assert(offsetof(SPhysBodyParams, mass) == 0x00, "SPhysBodyParams::mass offset must be 0x00");
  static_assert(offsetof(SPhysBodyParams, inertiaTensor) == 0x04, "SPhysBodyParams::inertiaTensor offset must be 0x04");
  static_assert(
    offsetof(SPhysBodyParams, collisionOffset) == 0x10,
    "SPhysBodyParams::collisionOffset offset must be 0x10"
  );
  static_assert(sizeof(SPhysBodyParams) == 0x1C, "SPhysBodyParams size must be 0x1C");

  /**
   * Address evidence:
   * - 0x00697450 (FUN_00697450, SPhysBodyTypeInfo::Init, size = 0x54)
   * - 0x006981B0 (FUN_006981B0, construct defaults)
   * - 0x00698A60 (FUN_00698A60, deserialize body)
   * - 0x00698BC0 (FUN_00698BC0, serialize body)
   */
  struct SPhysBody
  {
    static gpg::RType* sType;

    SPhysBody() = default;

    /**
     * Address: 0x006831B0 (FUN_006831B0)
     *
     * What it does:
     * Returns cached reflected type metadata for `SPhysBody`, resolving it
     * through RTTI lookup on first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006975B0 (FUN_006975B0, Moho::SPhysBody::SPhysBody)
     *
     * What it does:
     * Initializes one physics body from constants pointer + physical params,
     * seeding identity/default kinematic lanes before inverse-inertia setup.
     */
    SPhysBody(SPhysConstants* constants, const SPhysBodyParams& params);

    SPhysConstants* mConstants;       // +0x00
    float mMass;                      // +0x04
    Wm3::Vec3f mInvInertiaTensor;     // +0x08
    Wm3::Vec3f mCollisionOffset;      // +0x14
    Wm3::Vec3f mPos;                  // +0x20
    Wm3::Quaternionf mOrientation;    // +0x2C
    Wm3::Vec3f mVelocity;             // +0x3C
    Wm3::Vec3f mWorldImpulse;         // +0x48

    /**
     * Address: 0x00697E70 (FUN_00697E70, Moho::SPhysBody::GetImpulse)
     *
     * What it does:
     * Projects world impulse into body-axis space with inverse-inertia scaling,
     * then reconstructs the resulting world impulse vector.
     */
    Wm3::Vec3f* GetImpulse(Wm3::Vec3f* out) const;

    /**
     * Address: 0x00697D10 (FUN_00697D10, Moho::SPhysBody::AddLocalImpulse)
     *
     * What it does:
     * Rotates one local impulse and local-application point into world space,
     * updates linear velocity by inverse-mass scaling, and accumulates angular
     * world impulse via the position/impulse cross product.
     */
    void AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint);

    /**
     * Address: 0x006976E0 (FUN_006976E0, Moho::SPhysBody::SetTransform)
     *
     * What it does:
     * Copies orientation from transform input, rotates `mCollisionOffset`, and
     * stores world-space position as `rotatedOffset + transform.pos_`.
     */
    void SetTransform(const VTransform& transform);

    /**
     * Address: 0x00697B00 (FUN_00697B00, sub_697B00)
     *
     * What it does:
     * One explicit-Euler free-fall step: accumulates `force/mass + mConstants
     * ->mGravity` into `mVelocity` over `dt`, midpoint-integrates `mPos` from
     * the old/new velocity average, then applies `angularImpulse` via
     * `IntegrateAngularImpulse`.
     */
    void IntegrateFreefallStep(const Wm3::Vec3f& force, float dt, const Wm3::Vec3f& angularImpulse);

    /**
     * Address: 0x006978D0 (FUN_006978D0, sub_6978D0)
     *
     * What it does:
     * Accumulates `angularImpulse * dt` into `mWorldImpulse`, rotates the
     * midpoint-averaged accumulated impulse into body-local space, scales it
     * by `mInvInertiaTensor`, converts the result to a delta rotation, and
     * left-multiplies it onto `mOrientation` (renormalizing in place).
     */
    void IntegrateAngularImpulse(const Wm3::Vec3f& angularImpulse, float dt);

    /**
     * Address: 0x00698350 (FUN_00698350, sub_698350)
     *
     * IDA signature:
     * int __usercall sub_698350@<eax>(Moho::SPhysBody *a1@<edx>, int edi0@<edi>);
     *
     * What it does:
     * Ground-collision impulse response. For each sample still penetrating
     * (`sample.y <= sample.terrainElevation`), computes the point velocity
     * (`mVelocity + Cross(angularVelocity, sample - mPos)`, where
     * `angularVelocity` comes from `GetImpulse`) and, for points still
     * moving downward, accumulates a cancelling linear/angular impulse and
     * the maximum penetration depth. Averages the accumulated impulses
     * across all downward-moving points, applies them to `mVelocity`/
     * `mWorldImpulse` (each damped by 0.9), and pushes `mPos.y` up by the
     * maximum penetration depth.
     */
    void ApplyGroundCollisionResponse(const gpg::fastvector_n<GroundPenetrationSample, 8>& samples);
  };

  /**
   * Address: 0x00697750 (FUN_00697750, SPhysBody world-transform export helper)
   *
   * What it does:
   * Writes one `VTransform` view from body state by copying orientation and
   * backing out world position from rotated collision-offset.
   */
  VTransform* BuildTransformFromSPhysBody(VTransform* outTransform, const SPhysBody* body);

  static_assert(offsetof(SPhysBody, mConstants) == 0x00, "SPhysBody::mConstants offset must be 0x00");
  static_assert(offsetof(SPhysBody, mMass) == 0x04, "SPhysBody::mMass offset must be 0x04");
  static_assert(offsetof(SPhysBody, mInvInertiaTensor) == 0x08, "SPhysBody::mInvInertiaTensor offset must be 0x08");
  static_assert(offsetof(SPhysBody, mCollisionOffset) == 0x14, "SPhysBody::mCollisionOffset offset must be 0x14");
  static_assert(offsetof(SPhysBody, mPos) == 0x20, "SPhysBody::mPos offset must be 0x20");
  static_assert(offsetof(SPhysBody, mOrientation) == 0x2C, "SPhysBody::mOrientation offset must be 0x2C");
  static_assert(offsetof(SPhysBody, mVelocity) == 0x3C, "SPhysBody::mVelocity offset must be 0x3C");
  static_assert(offsetof(SPhysBody, mWorldImpulse) == 0x48, "SPhysBody::mWorldImpulse offset must be 0x48");
  static_assert(sizeof(SPhysBody) == 0x54, "SPhysBody size must be 0x54");

  class SPhysBodyTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006973F0 (FUN_006973F0, Moho::SPhysBodyTypeInfo::SPhysBodyTypeInfo)
     */
    SPhysBodyTypeInfo();

    /**
     * Address: 0x00697480 (FUN_00697480, Moho::SPhysBodyTypeInfo::dtr)
     */
    ~SPhysBodyTypeInfo() override;

    /**
     * Address: 0x00697470 (FUN_00697470, Moho::SPhysBodyTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00697450 (FUN_00697450, Moho::SPhysBodyTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SPhysBodyTypeInfo) == 0x64, "SPhysBodyTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E29344 (`??_7SPhysBodySerializer@Moho@@6B@`)
   *
   * This helper's `Init()` body is byte-identical to
   * `gpg::SerSaveLoadHelper<Moho::SPhysBody>::Init()` -- the linker ICF-folds
   * both classes' slot-0 target onto the same address (FUN_00698760;
   * confirmed via two separate `vftable`-slot data xrefs into that one
   * address). The binary also contains a fully-formed, separately-emitted
   * `gpg::SerSaveConstructHelper`-style ctor for the template instantiation
   * itself (FUN_00698730, sets `gpg::SerSaveLoadHelper<Moho::SPhysBody>::
   * vftable` on this same global) -- but it has zero incoming xrefs and is
   * never invoked; the confirmed live path (FUN_00BD5F10, reachable from
   * `__xc_a`) installs `SPhysBodySerializer`'s own vtable instead. Kept as
   * its own concrete class, same precedent as `Rect2iSerializer`/
   * `Box3fSerializer`; the dead template ctor and a second dead out-of-line
   * copy of this class's own ctor (FUN_006982C0) are `skip`.
   */
  class SPhysBodySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5F10 (FUN_00BD5F10, dynamic initializer for the global
     * `SPhysBodySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SPhysBodySerializer();

    /**
     * Address: 0x00BFD390 (FUN_00BFD390, Moho::SPhysBodySerializer::~SPhysBodySerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPhysBodySerializer();

    /**
     * Address: 0x006982A0 (FUN_006982A0, Moho::SPhysBodySerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006982B0 (FUN_006982B0, Moho::SPhysBodySerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00698760 (FUN_00698760, Moho::SPhysBodySerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into `SPhysBody`'s reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(SPhysBodySerializer, mDeserialize) == 0x0C,
    "SPhysBodySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(SPhysBodySerializer, mSerialize) == 0x10, "SPhysBodySerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SPhysBodySerializer) == 0x14, "SPhysBodySerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E29324 (`??_7SPhysBodySaveConstruct@Moho@@6B@`)
   *
   * Same ICF-shared-`Init()`-with-a-dead-template-twin shape as
   * `SPhysBodySerializer` above: `Init()` (FUN_00698660) is shared with
   * `gpg::SerSaveConstructHelper<Moho::SPhysBody>::Init()`, and that
   * template's own separately-emitted ctor (FUN_00698630) plus a second
   * dead out-of-line copy of this class's own ctor (FUN_00698010) both have
   * zero incoming xrefs and are `skip`.
   */
  class SPhysBodySaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5EA0 (FUN_00BD5EA0, dynamic initializer for the global
     * `SPhysBodySaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. Confirmed from raw disassembly:
     * the installed callback is `FUN_00698040` (a thin signature-adapting
     * forward into the real save-construct-args body at `FUN_006980D0`),
     * not the real body directly.
     */
    SPhysBodySaveConstruct();

    /**
     * Address: 0x00BFD330 (FUN_00BFD330, Moho::SPhysBodySaveConstruct::~SPhysBodySaveConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPhysBodySaveConstruct();

    /**
     * Address: 0x00698660 (FUN_00698660, Moho::SPhysBodySaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into `SPhysBody`'s reflected
     * RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(SPhysBodySaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "SPhysBodySaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(SPhysBodySaveConstruct) == 0x10, "SPhysBodySaveConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00E29334 (`??_7SPhysBodyConstruct@Moho@@6B@`)
   *
   * Same ICF-shared-`Init()`-with-a-dead-template-twin shape again:
   * `Init()` (FUN_006986E0) is shared with `gpg::SerConstructHelper<
   * Moho::SPhysBody>::Init()`, and that template's own separately-emitted
   * ctor (FUN_006986B0) plus a second dead out-of-line copy of this class's
   * own ctor (FUN_00698120) both have zero incoming xrefs and are `skip`.
   */
  class SPhysBodyConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5ED0 (FUN_00BD5ED0, dynamic initializer for the global
     * `SPhysBodyConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. Confirmed from raw disassembly:
     * `mDeleteCallback` is a direct `jmp` thunk (`j_j_func_tent_Destroy_15`
     * at 0x00698830) straight to the global scalar `operator delete(void*)`,
     * not a typed per-instance delete -- `SPhysBody` has a trivial
     * destructor so the two are behaviorally identical, but this matches
     * what the binary actually installs.
     */
    SPhysBodyConstruct();

    /**
     * Address: 0x00BFD360 (FUN_00BFD360, Moho::SPhysBodyConstruct::~SPhysBodyConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPhysBodyConstruct();

    /**
     * Address: 0x006986E0 (FUN_006986E0, Moho::SPhysBodyConstruct::Init)
     *
     * What it does:
     * Binds the construct/delete callbacks into `SPhysBody`'s reflected
     * RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

  static_assert(
    offsetof(SPhysBodyConstruct, mConstructCallback) == 0x0C,
    "SPhysBodyConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SPhysBodyConstruct, mDeleteCallback) == 0x10,
    "SPhysBodyConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(SPhysBodyConstruct) == 0x14, "SPhysBodyConstruct size must be 0x14");

  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0, cleanup_SPhysBodyTypeInfo)
   */
  void cleanup_SPhysBodyTypeInfo();

  /**
   * Address: 0x00BD5E80 (FUN_00BD5E80, register_SPhysBodyTypeInfo)
   */
  void register_SPhysBodyTypeInfo();
} // namespace moho
