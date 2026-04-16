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
#include "moho/render/camera/VTransform.h"

#pragma init_seg(lib)

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  alignas(moho::SPhysBodyTypeInfo) unsigned char gSPhysBodyTypeInfoStorage[sizeof(moho::SPhysBodyTypeInfo)];
  bool gSPhysBodyTypeInfoConstructed = false;
  moho::SPhysBodySaveConstruct gSPhysBodySaveConstruct{};
  moho::SPhysBodyConstruct gSPhysBodyConstruct{};
  moho::SPhysBodySerializer gSPhysBodySerializer{};

  [[nodiscard]] moho::SPhysBodyTypeInfo& SPhysBodyTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SPhysBodyTypeInfo*>(gSPhysBodyTypeInfoStorage);
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

  [[nodiscard]] gpg::RRef MakeSPhysBodyRef(moho::SPhysBody* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedSPhysBodyType();
    return ref;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x006982F0 (FUN_006982F0)
   *
   * What it does:
   * Splices `SPhysBodySerializer` out of the intrusive helper lane when linked,
   * then rewires the serializer helper links to its self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSPhysBodySerializerHelperNodeVariantA() noexcept
  {
    return UnlinkHelperNode(gSPhysBodySerializer);
  }

  /**
   * Address: 0x00698320 (FUN_00698320)
   *
   * What it does:
   * Secondary serializer helper unlink/reset variant sharing the same behavior.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSPhysBodySerializerHelperNodeVariantB() noexcept
  {
    return UnlinkSPhysBodySerializerHelperNodeVariantA();
  }

  [[nodiscard]] moho::SPhysConstants* ReadSPhysConstantsPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSPhysConstantsType());
    return static_cast<moho::SPhysConstants*>(upcast.mObj);
  }

  /**
   * Address: 0x006980D0 (FUN_006980D0, save-construct args body)
   */
  void SaveConstructArgs_SPhysBodyVariant2(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    const auto* const object = reinterpret_cast<const moho::SPhysBody*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef constantsRef{};
    constantsRef.mObj = object->mConstants;
    constantsRef.mType = object->mConstants ? CachedSPhysConstantsType() : nullptr;
    gpg::WriteRawPointer(archive, constantsRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x006980C0 (FUN_006980C0)
   *
   * What it does:
   * Register-shape adapter that forwards one save-construct lane into
   * `SaveConstructArgs_SPhysBodyVariant2`.
   */
  [[maybe_unused]] int SaveConstructArgs_SPhysBodyRegisterAdapterA(
    const int objectPtr,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_SPhysBodyVariant2(archive, objectPtr, 0, result);
    return objectPtr;
  }

  /**
   * Address: 0x006987F0 (FUN_006987F0)
   *
   * What it does:
   * Secondary register-shape adapter that forwards one save-construct lane
   * into `SaveConstructArgs_SPhysBodyVariant2`.
   */
  [[maybe_unused]] int SaveConstructArgs_SPhysBodyRegisterAdapterB(
    const int objectPtr,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_SPhysBodyVariant2(archive, objectPtr, 0, result);
    return objectPtr;
  }

  /**
   * Address: 0x006981B0 (FUN_006981B0, construct callback body)
   */
  void ConstructSPhysBody(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    moho::SPhysConstants* const constants = ReadSPhysConstantsPointer(archive);
    moho::SPhysBody* const object = new (std::nothrow) moho::SPhysBody{};
    if (object) {
      object->mConstants = constants;
      object->mMass = 1.0f;
      object->mInvInertiaTensor.x = 1.0f;
      object->mInvInertiaTensor.y = 1.0f;
      object->mInvInertiaTensor.z = 1.0f;
      object->mCollisionOffset.x = 0.0f;
      object->mCollisionOffset.y = 0.0f;
      object->mCollisionOffset.z = 0.0f;
      object->mPos.x = 0.0f;
      object->mPos.y = 0.0f;
      object->mPos.z = 0.0f;
      object->mOrientation.x = 1.0f;
      object->mOrientation.y = 0.0f;
      object->mOrientation.z = 0.0f;
      object->mOrientation.w = 0.0f;
      object->mVelocity.x = 0.0f;
      object->mVelocity.y = 0.0f;
      object->mVelocity.z = 0.0f;
      object->mWorldImpulse.x = 0.0f;
      object->mWorldImpulse.y = 0.0f;
      object->mWorldImpulse.z = 0.0f;
    }

    if (!result) {
      return;
    }

    const gpg::RRef ref = MakeSPhysBodyRef(object);
    result->SetUnowned(ref, 0u);
  }

  /**
   * Address: 0x006981A0 (delete callback lane, inferred)
   */
  void DeleteConstructedSPhysBodyVariant1(void* const objectPtr)
  {
    delete static_cast<moho::SPhysBody*>(objectPtr);
  }

  /**
   * Address: 0x00698010 (FUN_00698010, sub_698010)
   *
   * What it does:
   * Initializes the global `SPhysBodySaveConstruct` helper links, binds the
   * save-construct callback lane, and returns the helper instance.
   */
  [[nodiscard]] moho::SPhysBodySaveConstruct* InitializeSPhysBodySaveConstructGenericHelperLane()
  {
    InitializeHelperNode(gSPhysBodySaveConstruct);
    gSPhysBodySaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_SPhysBodyVariant2);
    return &gSPhysBodySaveConstruct;
  }

  /**
   * Address: 0x006986B0 (FUN_006986B0)
   *
   * What it does:
   * Initializes the generic construct-helper lane for `SPhysBody`.
   */
  [[nodiscard]] moho::SPhysBodyConstruct* InitializeSPhysBodyConstructGenericHelperLane()
  {
    InitializeHelperNode(gSPhysBodyConstruct);
    gSPhysBodyConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&ConstructSPhysBody);
    gSPhysBodyConstruct.mDeleteCallback = &DeleteConstructedSPhysBodyVariant1;
    return &gSPhysBodyConstruct;
  }

  /**
   * Address: 0x00698120 (FUN_00698120)
   *
   * What it does:
   * Initializes the custom construct-helper lane for `SPhysBody`.
   */
  [[nodiscard]] moho::SPhysBodyConstruct* InitializeSPhysBodyConstructCustomHelperLane()
  {
    return InitializeSPhysBodyConstructGenericHelperLane();
  }

  /**
   * Address: 0x00698A60 (FUN_00698A60, serializer load body)
   */
  void DeserializeSPhysBodyBody(moho::SPhysBody* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->ReadFloat(&object->mMass);
    archive->Read(CachedVector3fType(), &object->mInvInertiaTensor, nullOwner);
    archive->Read(CachedVector3fType(), &object->mCollisionOffset, nullOwner);
    archive->Read(CachedVector3fType(), &object->mPos, nullOwner);
    archive->Read(CachedQuaternionfType(), &object->mOrientation, nullOwner);
    archive->Read(CachedVector3fType(), &object->mVelocity, nullOwner);
    archive->Read(CachedVector3fType(), &object->mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x00698BC0 (FUN_00698BC0, serializer save body)
   */
  void SerializeSPhysBodyBody(const moho::SPhysBody* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->WriteFloat(object->mMass);
    archive->Write(CachedVector3fType(), &object->mInvInertiaTensor, nullOwner);
    archive->Write(CachedVector3fType(), &object->mCollisionOffset, nullOwner);
    archive->Write(CachedVector3fType(), &object->mPos, nullOwner);
    archive->Write(CachedQuaternionfType(), &object->mOrientation, nullOwner);
    archive->Write(CachedVector3fType(), &object->mVelocity, nullOwner);
    archive->Write(CachedVector3fType(), &object->mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x00697750 (FUN_00697750, SPhysBody world-transform export helper)
   *
   * What it does:
   * Writes one `VTransform` view from body state by copying orientation and
   * backing out world position from rotated collision-offset.
   */
  [[maybe_unused]] moho::VTransform* BuildTransformFromSPhysBody(
    moho::VTransform* const outTransform,
    const moho::SPhysBody* const body
  )
  {
    if (!outTransform || !body) {
      return outTransform;
    }

    Wm3::Vec3f rotatedOffset{};
    Wm3::MultiplyQuaternionVector(&rotatedOffset, body->mCollisionOffset, body->mOrientation);

    outTransform->orient_ = body->mOrientation;
    outTransform->pos_.x = body->mPos.x - rotatedOffset.x;
    outTransform->pos_.y = body->mPos.y - rotatedOffset.y;
    outTransform->pos_.z = body->mPos.z - rotatedOffset.z;
    return outTransform;
  }

  void cleanup_SPhysBodySaveConstruct_atexit()
  {
    (void)moho::cleanup_SPhysBodySaveConstruct();
  }

  void cleanup_SPhysBodyConstruct_atexit()
  {
    (void)moho::cleanup_SPhysBodyConstruct();
  }

  void cleanup_SPhysBodySerializer_atexit()
  {
    moho::cleanup_SPhysBodySerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* SPhysBody::sType = nullptr;

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
    body->mOrientation.x = 1.0f;
    body->mOrientation.y = 0.0f;
    body->mOrientation.z = 0.0f;
    body->mOrientation.w = 0.0f;
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
   */
  void SPhysBody::SetTransform(const VTransform& transform)
  {
    mOrientation = transform.orient_;

    Wm3::Vec3f rotatedOffset{};
    Wm3::MultiplyQuaternionVector(&rotatedOffset, mCollisionOffset, transform.orient_);

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
   */
  [[maybe_unused]] Wm3::Vec3f* ComputeWorldImpulseFromInertiaTensor(const SPhysBody* const body, Wm3::Vec3f* const out)
  {
    if (body == nullptr || out == nullptr) {
      return out;
    }

    Wm3::Quaternionf inverseOrientation{};
    inverseOrientation.w = body->mOrientation.w;
    inverseOrientation.x = -body->mOrientation.x;
    inverseOrientation.y = -body->mOrientation.y;
    inverseOrientation.z = -body->mOrientation.z;

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
   */
  Wm3::Vec3f* SPhysBody::GetImpulse(Wm3::Vec3f* const out) const
  {
    if (!out) {
      return nullptr;
    }

    const Wm3::Vec3f basisX = mOrientation.Rotate(Wm3::Vec3f(1.0f, 0.0f, 0.0f));
    const Wm3::Vec3f basisY = mOrientation.Rotate(Wm3::Vec3f(0.0f, 1.0f, 0.0f));
    const Wm3::Vec3f basisZ = mOrientation.Rotate(Wm3::Vec3f(0.0f, 0.0f, 1.0f));

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
  [[maybe_unused]] SPhysBody* ApplyWorldImpulseAtWorldPoint(
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
   */
  void SPhysBody::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
  {
    const Wm3::Vec3f rotatedCollisionOffset = mOrientation.Rotate(mCollisionOffset);
    const Wm3::Vec3f transformOrigin{
      mPos.x - rotatedCollisionOffset.x,
      mPos.y - rotatedCollisionOffset.y,
      mPos.z - rotatedCollisionOffset.z
    };

    const Wm3::Vec3f rotatedPoint = mOrientation.Rotate(localPoint);
    const Wm3::Vec3f worldPoint{
      rotatedPoint.x + transformOrigin.x,
      rotatedPoint.y + transformOrigin.y,
      rotatedPoint.z + transformOrigin.z
    };

    const Wm3::Vec3f worldImpulse = mOrientation.Rotate(localImpulse);
    (void)ApplyWorldImpulseAtWorldPoint(this, worldImpulse, worldPoint);
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
   * Address: 0x00698040 (FUN_00698040, save-construct registration lane)
   */
  void SPhysBodySaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
    * Alias of FUN_006981B0 (non-canonical helper lane).
   */
  void SPhysBodyConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x006982A0 (FUN_006982A0, Moho::SPhysBodySerializer::Deserialize)
   */
  void SPhysBodySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    DeserializeSPhysBodyBody(reinterpret_cast<SPhysBody*>(objectPtr), archive);
  }

  /**
   * Address: 0x006982B0 (FUN_006982B0, Moho::SPhysBodySerializer::Serialize)
   */
  void SPhysBodySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SerializeSPhysBodyBody(reinterpret_cast<const SPhysBody*>(objectPtr), archive);
  }

  /**
   * Address: 0x006982C0 (FUN_006982C0, serializer registration lane)
   */
  void SPhysBodySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0, cleanup_SPhysBodyTypeInfo)
   */
  void cleanup_SPhysBodyTypeInfo()
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      return;
    }

    SPhysBodyTypeInfoStorageRef().~SPhysBodyTypeInfo();
    gSPhysBodyTypeInfoConstructed = false;
    SPhysBody::sType = nullptr;
  }

  /**
   * Address: 0x00BFD330 (FUN_00BFD330, cleanup_SPhysBodySaveConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodySaveConstruct()
  {
    return UnlinkHelperNode(gSPhysBodySaveConstruct);
  }

  /**
   * Address: 0x00BFD360 (FUN_00BFD360, cleanup_SPhysBodyConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodyConstruct()
  {
    return UnlinkHelperNode(gSPhysBodyConstruct);
  }

  /**
   * Address: 0x00BFD390 (FUN_00BFD390, cleanup_SPhysBodySerializer)
   */
  void cleanup_SPhysBodySerializer()
  {
    (void)UnlinkSPhysBodySerializerHelperNodeVariantA();
  }

  /**
   * Address: 0x00BD5E80 (FUN_00BD5E80, register_SPhysBodyTypeInfo)
   */
  void register_SPhysBodyTypeInfo()
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      new (gSPhysBodyTypeInfoStorage) SPhysBodyTypeInfo();
      gSPhysBodyTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_SPhysBodyTypeInfo);
  }

  /**
   * Address: 0x00BD5EA0 (FUN_00BD5EA0, register_SPhysBodySaveConstruct)
   */
  int register_SPhysBodySaveConstruct()
  {
    (void)InitializeSPhysBodySaveConstructGenericHelperLane();
    gSPhysBodySaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&cleanup_SPhysBodySaveConstruct_atexit);
  }

  /**
   * Address: 0x00BD5ED0 (FUN_00BD5ED0, register_SPhysBodyConstruct)
   */
  int register_SPhysBodyConstruct()
  {
    (void)InitializeSPhysBodyConstructCustomHelperLane();
    gSPhysBodyConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_SPhysBodyConstruct_atexit);
  }

  /**
   * Address: 0x00698730 (FUN_00698730)
   *
   * What it does:
   * Alternate serializer startup leaf that initializes global helper links,
   * binds deserialize/serialize callbacks, and returns the helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* construct_SPhysBodySerializer_SaveLoadStartupLeaf()
  {
    InitializeHelperNode(gSPhysBodySerializer);
    gSPhysBodySerializer.mDeserialize = &SPhysBodySerializer::Deserialize;
    gSPhysBodySerializer.mSerialize = &SPhysBodySerializer::Serialize;
    return HelperSelfNode(gSPhysBodySerializer);
  }

  /**
   * Address: 0x00BD5F10 (FUN_00BD5F10, register_SPhysBodySerializer)
   */
  void register_SPhysBodySerializer()
  {
    (void)construct_SPhysBodySerializer_SaveLoadStartupLeaf();
    (void)std::atexit(&cleanup_SPhysBodySerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SPhysBodyBootstrap
  {
    SPhysBodyBootstrap()
    {
      moho::register_SPhysBodyTypeInfo();
      (void)moho::register_SPhysBodySaveConstruct();
      (void)moho::register_SPhysBodyConstruct();
      moho::register_SPhysBodySerializer();
    }
  };

  [[maybe_unused]] SPhysBodyBootstrap gSPhysBodyBootstrap;
} // namespace
