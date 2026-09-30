#include "moho/sim/SPhysBody.h"

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/camera/VTransform.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0, atexit destructor of the SPhysBodyTypeInfo object)
   */
  [[nodiscard]] moho::SPhysBodyTypeInfo* AcquireSPhysBodyTypeInfo()
  {
    static moho::SPhysBodyTypeInfo sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* CachedSPhysBodyType()
  {
    return moho::SPhysBody::StaticGetClass();
  }

  [[nodiscard]] gpg::RType* CachedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPhysConstants));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vec3f));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

} // namespace

namespace moho
{
  gpg::RType* SPhysBody::sType = nullptr;

  /**
   * Address: 0x00697750 (FUN_00697750, SPhysBody world-transform export helper)
   *
   * What it does:
   * Writes one `VTransform` view from body state by copying orientation and
   * backing out world position from rotated collision-offset.
   *
   * Ground truth (`FUN_00697750.c`) rotates via
   * `Moho::MultQuadVec(&v7, &a2->mCollisionOffset, &a2->mOrientation)`, not
   * the generic `Wm3::MultiplyQuaternionVector`. `mOrientation` is always in
   * this engine's scalar-first convention (it is copied byte-for-byte to/from
   * `VTransform::orient_` both here and in `SetTransform`, below).
   */
  VTransform* BuildTransformFromSPhysBody(VTransform* const outTransform, const SPhysBody* const body)
  {
    if (!outTransform || !body) {
      return outTransform;
    }

    Wm3::Vec3f rotatedOffset{};
    MultQuadVec(&rotatedOffset, &body->mCollisionOffset, &body->mOrientation);

    outTransform->orient_ = body->mOrientation;
    outTransform->pos_.x = body->mPos.x - rotatedOffset.x;
    outTransform->pos_.y = body->mPos.y - rotatedOffset.y;
    outTransform->pos_.z = body->mPos.z - rotatedOffset.z;
    return outTransform;
  }

  /**
   * Address: 0x006831B0 (FUN_006831B0)
   *
   * What it does:
   * Returns cached reflected type metadata for `SPhysBody`, resolving it
   * through RTTI lookup on first use.
   */
  gpg::RType* SPhysBody::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SPhysBody));
    }

    GPG_ASSERT(sType != nullptr);
    return sType;
  }

  /**
   * Address: 0x00697330 (FUN_00697330)
   *
   * What it does:
   * Writes reciprocal lanes for one source vector (`1/x`, `1/y`, `1/z`) into
   * `out`.
   */
  [[maybe_unused]] [[nodiscard]] Wm3::Vec3f* ReciprocalVectorLanes(
    Wm3::Vec3f* const out,
    const Wm3::Vec3f* const source
  ) noexcept
  {
    out->x = 1.0f / source->x;
    out->y = 1.0f / source->y;
    out->z = 1.0f / source->z;
    return out;
  }

  /**
   * Address: 0x006973C0 (FUN_006973C0)
   *
   * What it does:
   * Seeds one `SPhysBodyParams` payload with unit mass/inertia and zero
   * collision offset.
   */
  [[maybe_unused]] [[nodiscard]] SPhysBodyParams* InitializeSPhysBodyParamsDefaults(
    SPhysBodyParams* const params
  ) noexcept
  {
    params->mass = 1.0f;
    params->inertiaTensor.x = 1.0f;
    params->inertiaTensor.y = 1.0f;
    params->inertiaTensor.z = 1.0f;
    params->collisionOffset.x = 0.0f;
    params->collisionOffset.y = 0.0f;
    params->collisionOffset.z = 0.0f;
    return params;
  }

  /**
   * Address: 0x00697530 (FUN_00697530)
   *
   * What it does:
   * Initializes one body lane with identity/default runtime values and binds
   * the owning constants pointer.
   */
  [[maybe_unused]] [[nodiscard]] SPhysBody* InitializeSPhysBodyDefaults(
    SPhysBody* const body,
    SPhysConstants* const constants
  ) noexcept
  {
    body->mConstants = constants;
    body->mMass = 1.0f;
    body->mInvInertiaTensor.x = 1.0f;
    body->mInvInertiaTensor.y = 1.0f;
    body->mInvInertiaTensor.z = 1.0f;
    body->mCollisionOffset.x = 0.0f;
    body->mCollisionOffset.y = 0.0f;
    body->mCollisionOffset.z = 0.0f;
    body->mPos.x = 0.0f;
    body->mPos.y = 0.0f;
    body->mPos.z = 0.0f;
    body->mOrientation.w = 1.0f;
    body->mOrientation.x = 0.0f;
    body->mOrientation.y = 0.0f;
    body->mOrientation.z = 0.0f;
    body->mVelocity.x = 0.0f;
    body->mVelocity.y = 0.0f;
    body->mVelocity.z = 0.0f;
    body->mWorldImpulse.x = 0.0f;
    body->mWorldImpulse.y = 0.0f;
    body->mWorldImpulse.z = 0.0f;
    return body;
  }

  /**
   * Address: 0x00697680 (FUN_00697680)
   *
   * What it does:
   * Applies mass/inertia/collision-offset lanes from one params payload into a
   * body lane and recomputes inverse inertia tensor lanes.
   */
  [[maybe_unused]] [[nodiscard]] const SPhysBodyParams* ApplySPhysBodyParamsToBody(
    const SPhysBodyParams* const params,
    SPhysBody* const body
  ) noexcept
  {
    body->mCollisionOffset = params->collisionOffset;
    body->mMass = params->mass;

    const float massScale = params->mass;
    const Wm3::Vec3f scaledInertia{
      params->inertiaTensor.x * massScale,
      params->inertiaTensor.y * massScale,
      params->inertiaTensor.z * massScale
    };
    (void)ReciprocalVectorLanes(&body->mInvInertiaTensor, &scaledInertia);
    return params;
  }

  /**
   * Address: 0x006977C0 (FUN_006977C0)
   *
   * What it does:
   * Integrates one body's linear velocity and position from applied force,
   * gravity, and `deltaSeconds` using trapezoidal position update.
   */
  [[maybe_unused]] [[nodiscard]] SPhysBody* IntegrateSPhysBodyLinearState(
    SPhysBody* const body,
    const Wm3::Vec3f* const appliedForce,
    const float deltaSeconds
  ) noexcept
  {
    const Wm3::Vec3f priorVelocity = body->mVelocity;
    const float inverseMass = deltaSeconds / body->mMass;
    const float gravityScale = deltaSeconds;

    body->mVelocity.x += (appliedForce->x * inverseMass) + (body->mConstants->mGravity.x * gravityScale);
    body->mVelocity.y += (appliedForce->y * inverseMass) + (body->mConstants->mGravity.y * gravityScale);
    body->mVelocity.z += (appliedForce->z * inverseMass) + (body->mConstants->mGravity.z * gravityScale);

    const float halfDelta = deltaSeconds * 0.5f;
    body->mPos.x += (body->mVelocity.x + priorVelocity.x) * halfDelta;
    body->mPos.y += (body->mVelocity.y + priorVelocity.y) * halfDelta;
    body->mPos.z += (body->mVelocity.z + priorVelocity.z) * halfDelta;
    return body;
  }

  /**
   * Address: 0x00699720 (FUN_00699720)
   *
   * What it does:
   * Computes one scale factor as `(lane34 * 0.5f) / ((lane24*lane28) - (lane2C*lane20))`,
   * returning `0.0f` when the denominator is zero.
   */
  [[maybe_unused]] [[nodiscard]] float ComputeHalfScaleOverCrossDeterminant(const float* const laneBase) noexcept
  {
    const float denominator = (laneBase[9] * laneBase[10]) - (laneBase[11] * laneBase[8]);
    if (denominator == 0.0f) {
      return 0.0f;
    }

    return (laneBase[13] * 0.5f) / denominator;
  }

  /**
   * Address: 0x006975B0 (FUN_006975B0, Moho::SPhysBody::SPhysBody)
   *
   * What it does:
   * Initializes one body from constants + physical params, seeding identity
   * orientation and zeroed position/velocity/impulse lanes.
   */
  SPhysBody::SPhysBody(SPhysConstants* const constants, const SPhysBodyParams& params)
    : mConstants(nullptr)
    , mMass(1.0f)
    , mInvInertiaTensor(1.0f, 1.0f, 1.0f)
    , mCollisionOffset(0.0f, 0.0f, 0.0f)
    , mPos(0.0f, 0.0f, 0.0f)
    , mOrientation(1.0f, 0.0f, 0.0f, 0.0f)
    , mVelocity(0.0f, 0.0f, 0.0f)
    , mWorldImpulse(0.0f, 0.0f, 0.0f)
  {
    (void)InitializeSPhysBodyDefaults(this, constants);
    (void)ApplySPhysBodyParamsToBody(&params, this);
  }

  /**
   * Address: 0x006976E0 (FUN_006976E0, Moho::SPhysBody::SetTransform)
   *
   * What it does:
   * Copies incoming orientation, rotates the local collision offset into world
   * orientation space, then stores world position as offset plus transform
   * translation lanes.
   *
   * Ground truth (`FUN_006976E0.c`) rotates via
   * `Moho::MultQuadVec(&v5, &a2->mCollisionOffset, &a1->orient)`, not the
   * generic `Wm3::MultiplyQuaternionVector` -- same quaternion-convention
   * mismatch as `BuildTransformFromSPhysBody`, above.
   */
  void SPhysBody::SetTransform(const VTransform& transform)
  {
    mOrientation = transform.orient_;

    Wm3::Vec3f rotatedOffset{};
    MultQuadVec(&rotatedOffset, &mCollisionOffset, &transform.orient_);

    mPos.x = rotatedOffset.x + transform.pos_.x;
    mPos.y = rotatedOffset.y + transform.pos_.y;
    mPos.z = rotatedOffset.z + transform.pos_.z;
  }

  /**
   * Address: 0x00697F80 (FUN_00697F80, world-impulse inertia helper lane)
   *
   * What it does:
   * Rotates `mWorldImpulse` into local space using the orientation conjugate and
   * scales each axis by `mInvInertiaTensor`.
   *
   * The conjugate is the ordinary scalar-first one. 0x00697F83 copies
   * `[edi+2Ch]` (orientation lane 0) verbatim, and 0x00697F9A / 0x00697FAD /
   * 0x00697FB2 subtract `[edi+30h]` / `[edi+34h]` / `[edi+38h]` from the zero
   * constant `dword_E4F748` - keep `.w`, negate `.x/.y/.z`. A prior revision
   * recorded this as an scalar-first conjugate "confirmed throughout this
   * file"; the same lane-0-kept shape appears in `VTransform::Inverse`
   * (0x0046FBF0) and `IntegrateAngularImpulse` (0x006978D0).
   */
  [[maybe_unused]] Wm3::Vec3f* ComputeWorldImpulseFromInertiaTensor(const SPhysBody* const body, Wm3::Vec3f* const out)
  {
    if (body == nullptr || out == nullptr) {
      return out;
    }

    const Wm3::Quaternionf inverseOrientation = ConjugateQuat(body->mOrientation);

    Wm3::Vec3f localImpulse{};
    moho::MultQuadVec(&localImpulse, &body->mWorldImpulse, &inverseOrientation);

    out->x = body->mInvInertiaTensor.x * localImpulse.x;
    out->y = body->mInvInertiaTensor.y * localImpulse.y;
    out->z = body->mInvInertiaTensor.z * localImpulse.z;
    return out;
  }

  /**
   * Address: 0x00697E70 (FUN_00697E70, Moho::SPhysBody::GetImpulse)
   *
   * What it does:
   * Projects `mWorldImpulse` onto orientation basis vectors, scales by
   * inverse-inertia tensor lanes, then reconstructs world-space impulse.
   *
   * Ground truth (`FUN_00697E70.c`) builds the basis via `Moho::VAxes3::
   * VAxes3(&result, &mOrientation)` and uses its `vX`/`vY`/`vZ` members
   * directly -- NOT the previous `Quaternion::Rotate` (upstream WildMagic,
   * `.w`-scalar `ToMat3()`). An earlier pass here also tried substituting
   * `MultQuadVec` against the three standard basis vectors and found it
   * numerically disagreed with `VAxes3` -- but that was because `VAxes3`'s
   * own constructor had an independent, pre-existing bug (fixed in
   * `MathReflection.cpp`, see `VAxes3::VAxes3`'s doc comment), not because
   * the two are actually different operations: with that fixed, `VAxes3`'s
   * `vX`/`vY`/`vZ` are exactly the scalar-first rotation matrix's rows, i.e.
   * numerically identical to `MultQuadVec` against the standard basis
   * vectors. The call here matches the binary's own control flow either
   * way (it constructs `VAxes3` and reads its members directly), so no
   * code change was needed once the constructor itself was corrected.
   */
  Wm3::Vec3f* SPhysBody::GetImpulse(Wm3::Vec3f* const out) const
  {
    if (!out) {
      return nullptr;
    }

    const moho::VAxes3 axes(mOrientation);
    const Wm3::Vec3f& basisX = axes.vX;
    const Wm3::Vec3f& basisY = axes.vY;
    const Wm3::Vec3f& basisZ = axes.vZ;

    const float impulseX = mInvInertiaTensor.x * Wm3::Vec3f::Dot(mWorldImpulse, basisX);
    const float impulseY = mInvInertiaTensor.y * Wm3::Vec3f::Dot(mWorldImpulse, basisY);
    const float impulseZ = mInvInertiaTensor.z * Wm3::Vec3f::Dot(mWorldImpulse, basisZ);

    out->x = (basisX.x * impulseX) + (basisY.x * impulseY) + (basisZ.x * impulseZ);
    out->y = (basisX.y * impulseX) + (basisY.y * impulseY) + (basisZ.y * impulseZ);
    out->z = (basisX.z * impulseX) + (basisY.z * impulseY) + (basisZ.z * impulseZ);
    return out;
  }

  /**
   * Address: 0x00697C20 (FUN_00697C20)
   *
   * What it does:
   * Applies one world-space impulse at one world-space point to a body by
   * updating linear velocity (inverse-mass scale, `FLT_MAX` for zero mass) and
   * accumulating angular world impulse via `cross(lever, impulse)`.
   */
  SPhysBody* ApplyWorldImpulseAtWorldPoint(
    SPhysBody* const body,
    const Wm3::Vec3f& worldImpulse,
    const Wm3::Vec3f& worldPoint
  )
  {
    const float inverseMassOrMax = (body->mMass == 0.0f) ? std::numeric_limits<float>::max() : (1.0f / body->mMass);

    body->mVelocity.x += worldImpulse.x * inverseMassOrMax;
    body->mVelocity.y += worldImpulse.y * inverseMassOrMax;
    body->mVelocity.z += worldImpulse.z * inverseMassOrMax;

    const Wm3::Vec3f lever{
      worldPoint.x - body->mPos.x,
      worldPoint.y - body->mPos.y,
      worldPoint.z - body->mPos.z
    };

    body->mWorldImpulse.x += (lever.y * worldImpulse.z) - (lever.z * worldImpulse.y);
    body->mWorldImpulse.y += (lever.z * worldImpulse.x) - (lever.x * worldImpulse.z);
    body->mWorldImpulse.z += (lever.x * worldImpulse.y) - (lever.y * worldImpulse.x);
    return body;
  }

  /**
   * Address: 0x00697D10 (FUN_00697D10, Moho::SPhysBody::AddLocalImpulse)
   *
   * What it does:
   * Applies one local-space impulse at one local-space point to this body's
   * linear velocity and accumulated world angular impulse.
   *
   * Ground truth (`FUN_00697D10.c`) builds the body's world transform via
   * `sub_697750(&v30, a1)` (`BuildTransformFromSPhysBody`, above) and rotates
   * both the point and the impulse via two `Moho::MultQuadVec` calls against
   * that transform's `orient` -- not `Quaternion::Rotate` (upstream WildMagic,
   * same `.w`-scalar `ToMat3()` formula as `Wm3::MultiplyQuaternionVector`).
   * `mOrientation` is always in this engine's scalar-first convention (see
   * `BuildTransformFromSPhysBody`/`SetTransform`, above), so the previous
   * `.Rotate()`-based body also silently dropped the collision-offset term
   * that `BuildTransformFromSPhysBody` folds into its transform's position.
   */
  void SPhysBody::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
  {
    VTransform transform{};
    BuildTransformFromSPhysBody(&transform, this);

    Wm3::Vec3f rotatedPoint{};
    MultQuadVec(&rotatedPoint, &localPoint, &transform.orient_);
    const Wm3::Vec3f worldPoint{
      rotatedPoint.x + transform.pos_.x,
      rotatedPoint.y + transform.pos_.y,
      rotatedPoint.z + transform.pos_.z
    };

    Wm3::Vec3f worldImpulse{};
    MultQuadVec(&worldImpulse, &localImpulse, &transform.orient_);
    (void)ApplyWorldImpulseAtWorldPoint(this, worldImpulse, worldPoint);
  }

  /**
   * Address: 0x00697B00 (FUN_00697B00, sub_697B00)
   *
   * IDA signature:
   * void __userpurge sub_697B00(
   *     Moho::SPhysBody *a1@<eax>, Wm3::Vector3f *a2@<ecx>, float a3, Wm3::Vector3f *a4);
   *
   * What it does:
   * Explicit-Euler free-fall step: accumulates `force/mass + mConstants->
   * mGravity` into `mVelocity` over `dt`, midpoint-integrates `mPos` from the
   * old/new velocity average, then tail-calls `IntegrateAngularImpulse`.
   */
  void SPhysBody::IntegrateFreefallStep(const Wm3::Vec3f& force, const float dt, const Wm3::Vec3f& angularImpulse)
  {
    const Wm3::Vec3f oldVelocity = mVelocity;
    const float dtOverMass = dt / mMass;

    mVelocity.x += (force.x * dtOverMass) + (mConstants->mGravity.x * dt);
    mVelocity.y += (force.y * dtOverMass) + (mConstants->mGravity.y * dt);
    mVelocity.z += (force.z * dtOverMass) + (mConstants->mGravity.z * dt);

    const float halfDt = dt * 0.5f;
    mPos.x += (mVelocity.x + oldVelocity.x) * halfDt;
    mPos.y += (mVelocity.y + oldVelocity.y) * halfDt;
    mPos.z += (mVelocity.z + oldVelocity.z) * halfDt;

    IntegrateAngularImpulse(angularImpulse, dt);
  }

  /**
   * Address: 0x006978D0 (FUN_006978D0, sub_6978D0)
   *
   * IDA signature:
   * void __usercall sub_6978D0(Wm3::Vector3f *a1@<eax>, Moho::SPhysBody *a2@<edi>, float a3@<xmm0>);
   *
   * What it does:
   * Accumulates `angularImpulse * dt` into `mWorldImpulse`, rotates the
   * midpoint-averaged accumulated impulse into body-local space, scales it by
   * `mInvInertiaTensor`, converts the result to a delta rotation via
   * `QuatFromAxisAngleVector`, left-multiplies it onto `mOrientation`, and
   * renormalizes in place.
   *
   * Ground truth (`FUN_006978D0.c`) independently confirms both halves of the
   * engine scalar-first convention this file already established elsewhere:
   * the conjugate keeps `.x` and negates `.y/.z/.w` (manually built, then fed
   * to `Moho::MultQuadVec`) -- not `Quaternion::Conjugate().Rotate()`
   * (upstream WildMagic, keeps `.w`/negates `.x/.y/.z`, `.w`-scalar `ToMat3`)
   * -- and the final compose is the same scalar-first Hamilton product as
   * `CAniPoseBone::Rotate`/`VTransform::Compose`, with `deltaOrientation` as
   * the left/first operand and the existing `mOrientation` as the
   * right/second operand -- not `operator*` (same upstream `.w`-scalar
   * formula as `Multiply`).
   */
  void SPhysBody::IntegrateAngularImpulse(const Wm3::Vec3f& angularImpulse, const float dt)
  {
    const Wm3::Vec3f oldWorldImpulse = mWorldImpulse;
    mWorldImpulse.x += angularImpulse.x * dt;
    mWorldImpulse.y += angularImpulse.y * dt;
    mWorldImpulse.z += angularImpulse.z * dt;

    const float halfDt = dt * 0.5f;
    const Wm3::Vec3f avgWorldImpulse{
      (mWorldImpulse.x + oldWorldImpulse.x) * halfDt,
      (mWorldImpulse.y + oldWorldImpulse.y) * halfDt,
      (mWorldImpulse.z + oldWorldImpulse.z) * halfDt
    };

    const Wm3::Quaternionf conjugateOrientation = ConjugateQuat(mOrientation);
    Wm3::Vec3f localImpulse{};
    MultQuadVec(&localImpulse, &avgWorldImpulse, &conjugateOrientation);
    const Wm3::Vec3f scaledImpulse{
      mInvInertiaTensor.x * localImpulse.x,
      mInvInertiaTensor.y * localImpulse.y,
      mInvInertiaTensor.z * localImpulse.z
    };

    Wm3::Quaternionf deltaOrientation{};
    QuatFromAxisAngleVector(&deltaOrientation, scaledImpulse);

    // 0x006979F0..0x00697A38 forms the scalar term as `o0*d0 - o1*d1 - o2*d2 -
    // o3*d3` (positive in lane 0), and 0x00697A3F..0x00697A67 gives
    // `o0*d1 + o1*d0 + o2*d3 - o3*d2` - the cross-term signs of
    // `orientation * delta`, with the existing orientation as the LEFT
    // operand, exactly as `CAniPoseBone::Rotate` (0x0054BC00) composes.
    mOrientation = MultiplyQuat(mOrientation, deltaOrientation);
    NormalizeQuatInPlace(&mOrientation);
  }

  /**
   * Address: 0x00698350 (FUN_00698350, sub_698350)
   *
   * IDA signature:
   * int __usercall sub_698350@<eax>(Moho::SPhysBody *a1@<edx>, int edi0@<edi>);
   *
   * What it does: see header.
   */
  void SPhysBody::ApplyGroundCollisionResponse(const gpg::fastvector_n<GroundPenetrationSample, 8>& samples)
  {
    Wm3::Vec3f angularVelocity{};
    GetImpulse(&angularVelocity);

    float maxPenetrationDepth = 0.0f;
    std::int32_t downwardPointCount = 0;
    Wm3::Vec3f impulseAccum{};
    Wm3::Vec3f angularImpulseAccum{};

    for (const GroundPenetrationSample& sample : samples) {
      if (sample.y > sample.terrainElevation) {
        continue;
      }

      const Wm3::Vec3f relative{sample.x - mPos.x, sample.y - mPos.y, sample.z - mPos.z};
      const float penetrationDepth = sample.terrainElevation - sample.y;
      if (penetrationDepth > maxPenetrationDepth) {
        maxPenetrationDepth = penetrationDepth;
      }

      const Wm3::Vec3f pointVelocity{
        mVelocity.x + ((angularVelocity.y * relative.z) - (angularVelocity.z * relative.y)),
        mVelocity.y + ((angularVelocity.z * relative.x) - (relative.z * angularVelocity.x)),
        mVelocity.z + ((relative.y * angularVelocity.x) - (angularVelocity.y * relative.x))
      };

      if (pointVelocity.y < 0.0f) {
        impulseAccum.x -= pointVelocity.x;
        impulseAccum.y -= pointVelocity.y;
        impulseAccum.z -= pointVelocity.z;

        angularImpulseAccum.x -= (pointVelocity.z * relative.y) - (pointVelocity.y * relative.z);
        angularImpulseAccum.y -= (relative.z * pointVelocity.x) - (pointVelocity.z * relative.x);
        angularImpulseAccum.z -= (pointVelocity.y * relative.x) - (relative.y * pointVelocity.x);

        ++downwardPointCount;
      }
    }

    if (downwardPointCount <= 0) {
      return;
    }

    constexpr float kResponseDamping = 0.89999998f;

    const float invCount = 1.0f / static_cast<float>(downwardPointCount);
    const float angularScale = mMass * invCount * 0.5f;

    mWorldImpulse.x = (mWorldImpulse.x + (angularScale * angularImpulseAccum.x)) * kResponseDamping;
    mWorldImpulse.y = (mWorldImpulse.y + (angularImpulseAccum.y * angularScale)) * kResponseDamping;
    mWorldImpulse.z = (mWorldImpulse.z + (angularImpulseAccum.z * angularScale)) * kResponseDamping;

    const float linearScale = invCount * 0.5f;

    mVelocity.x = (mVelocity.x + (linearScale * impulseAccum.x)) * kResponseDamping;
    mVelocity.y = (mVelocity.y + (impulseAccum.y * linearScale)) * kResponseDamping;
    mVelocity.z = (mVelocity.z + (impulseAccum.z * linearScale)) * kResponseDamping;

    mPos.y += maxPenetrationDepth;
  }

  /**
   * Address: 0x006973F0 (FUN_006973F0, Moho::SPhysBodyTypeInfo::SPhysBodyTypeInfo)
   */
  SPhysBodyTypeInfo::SPhysBodyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPhysBody), this);
  }

  /**
   * Address: 0x006974E0 (FUN_006974E0, SPhysBodyTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `SPhysBodyTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroySPhysBodyTypeInfoBody(SPhysBodyTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00697480 (FUN_00697480, Moho::SPhysBodyTypeInfo::dtr)
   */
  SPhysBodyTypeInfo::~SPhysBodyTypeInfo()
  {
    DestroySPhysBodyTypeInfoBody(this);
  }

  /**
   * Address: 0x00697470 (FUN_00697470, Moho::SPhysBodyTypeInfo::GetName)
   */
  const char* SPhysBodyTypeInfo::GetName() const
  {
    return "SPhysBody";
  }

  /**
   * Address: 0x00697450 (FUN_00697450, Moho::SPhysBodyTypeInfo::Init)
   */
  void SPhysBodyTypeInfo::Init()
  {
    size_ = sizeof(SPhysBody);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD5E80 (FUN_00BD5E80, register_SPhysBodyTypeInfo)
   */
  void register_SPhysBodyTypeInfo()
  {
    (void)AcquireSPhysBodyTypeInfo();
  }
} // namespace moho

namespace
{
  struct SPhysBodyBootstrap
  {
    SPhysBodyBootstrap()
    {
      moho::register_SPhysBodyTypeInfo();
    }
  };

  [[maybe_unused]] SPhysBodyBootstrap gSPhysBodyBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SPhysBodyTypeInfo_dc3862, moho::register_SPhysBodyTypeInfo)

namespace moho
{
  void SPhysBody::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    SPhysConstants* constants = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&constants, &owner);
    SPhysBody* const body = new SPhysBody();
    (void)InitializeSPhysBodyDefaults(body, constants);
    result.SetUnowned(gpg::MakeRRef(body), 0u);
  }

  /**
   * Address: 0x006980D0 (FUN_006980D0)
   */
  void SPhysBody::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(mConstants, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    result.SetUnowned(0u);
  }

  /**
   * `gpg::SerSaveConstructHelper<SPhysBody>`, vtable 0x00E29324.
   *
   * Address: 0x00BD5EA0 (FUN_00BD5EA0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD330 (FUN_00BFD330 -- the global's destructor.)
   * Address: 0x00698010 (FUN_00698010 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00698660 (FUN_00698660 -- `Init`.)
   * Address: 0x00698040 (FUN_00698040 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct SPhysBodySaveConstruct : gpg::SerSaveConstructHelper<SPhysBody>
  {};

  /**
   * `gpg::SerConstructHelper<SPhysBody>`, vtable 0x00E29334.
   *
   * Address: 0x00BD5ED0 (FUN_00BD5ED0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD360 (FUN_00BFD360 -- the global's destructor.)
   * Address: 0x00698120 (FUN_00698120 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x006986E0 (FUN_006986E0 -- `Init`.)
   * Address: 0x006981B0 (FUN_006981B0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00698830 (FUN_00698830 -- `Delete`.)
   */
  struct SPhysBodyConstruct : gpg::SerConstructHelper<SPhysBody>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B538C -- process-global `SPhysBodySaveConstruct` singleton.
  moho::SPhysBodySaveConstruct gSPhysBodySaveConstruct;

  // Address: 0x010B5314 -- process-global `SPhysBodyConstruct` singleton.
  moho::SPhysBodyConstruct gSPhysBodyConstruct;
} // namespace

namespace moho
{
  /**
   * Address: 0x00698A60 (FUN_00698A60, serializer load body)
   */
  void SPhysBody::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->ReadFloat(&mMass);
    archive->Read(CachedVector3fType(), &mInvInertiaTensor, nullOwner);
    archive->Read(CachedVector3fType(), &mCollisionOffset, nullOwner);
    archive->Read(CachedVector3fType(), &mPos, nullOwner);
    archive->Read(CachedQuaternionfType(), &mOrientation, nullOwner);
    archive->Read(CachedVector3fType(), &mVelocity, nullOwner);
    archive->Read(CachedVector3fType(), &mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x00698BC0 (FUN_00698BC0, serializer save body)
   */
  void SPhysBody::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->WriteFloat(mMass);
    archive->Write(CachedVector3fType(), &mInvInertiaTensor, nullOwner);
    archive->Write(CachedVector3fType(), &mCollisionOffset, nullOwner);
    archive->Write(CachedVector3fType(), &mPos, nullOwner);
    archive->Write(CachedQuaternionfType(), &mOrientation, nullOwner);
    archive->Write(CachedVector3fType(), &mVelocity, nullOwner);
    archive->Write(CachedVector3fType(), &mWorldImpulse, nullOwner);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SPhysBody>`, vtable 0x00E29344.
   *
   * Address: 0x00BD5F10 (FUN_00BD5F10 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD390 (FUN_00BFD390 -- the global's destructor.)
   * Address: 0x006982C0 (FUN_006982C0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00698760 (FUN_00698760 -- `Init`.)
   * Address: 0x006982A0 (FUN_006982A0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006982B0 (FUN_006982B0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SPhysBodySerializer : gpg::SerSaveLoadHelper<SPhysBody>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B539C -- process-global `SPhysBodySerializer` singleton.
  moho::SPhysBodySerializer gSPhysBodySerializer;
} // namespace
