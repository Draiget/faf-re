#include "moho/math/MathReflection.h"

#include <cstddef>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <float.h>
#include <limits>
#include <new>
#include <typeinfo>

#include <xmmintrin.h>

#include <Windows.h>

#include "gpg/gal/Matrix.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CRandomStream.h"

#pragma init_seg(lib)

namespace
{
  alignas(boost::mutex) std::byte gMathGlobalRandomMutexStorage[sizeof(boost::mutex)]{};
  alignas(moho::CRandomStream) std::byte gMathGlobalRandomStreamStorage[sizeof(moho::CRandomStream)]{};
  bool gMathGlobalRandomMutexConstructed = false;
  bool gMathGlobalRandomStreamConstructed = false;

  template <typename T>
  struct TypeInfoStartupSlot
  {
    alignas(T) static std::byte storage[sizeof(T)];
    static bool constructed;
  };

  template <typename T>
  alignas(T) std::byte TypeInfoStartupSlot<T>::storage[sizeof(T)]{};

  template <typename T>
  bool TypeInfoStartupSlot<T>::constructed = false;

  template <typename T>
  struct SerializerStartupSlot
  {
    alignas(T) static std::byte storage[sizeof(T)];
    static bool constructed;
  };

  template <typename T>
  alignas(T) std::byte SerializerStartupSlot<T>::storage[sizeof(T)]{};

  template <typename T>
  bool SerializerStartupSlot<T>::constructed = false;

  template <typename T>
  [[nodiscard]] T& AccessTypeInfoStartupSlot() noexcept
  {
    auto* const slot = reinterpret_cast<T*>(TypeInfoStartupSlot<T>::storage);
    if (!TypeInfoStartupSlot<T>::constructed) {
      ::new (static_cast<void*>(slot)) T();
      TypeInfoStartupSlot<T>::constructed = true;
    }

    return *slot;
  }

  template <typename T>
  void DestroyTypeInfoStartupSlot() noexcept
  {
    if (!TypeInfoStartupSlot<T>::constructed) {
      return;
    }

    AccessTypeInfoStartupSlot<T>().~T();
    TypeInfoStartupSlot<T>::constructed = false;
  }

  template <typename T>
  [[nodiscard]] T& AccessSerializerStartupSlot() noexcept
  {
    auto* const slot = reinterpret_cast<T*>(SerializerStartupSlot<T>::storage);
    if (!SerializerStartupSlot<T>::constructed) {
      ::new (static_cast<void*>(slot)) T();
      SerializerStartupSlot<T>::constructed = true;
    }

    return *slot;
  }

  template <typename T>
  void DestroySerializerStartupSlot() noexcept
  {
    if (!SerializerStartupSlot<T>::constructed) {
      return;
    }

    AccessSerializerStartupSlot<T>().~T();
    SerializerStartupSlot<T>::constructed = false;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeHelperNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  void UnlinkHelperNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeHelperNode(serializer);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkAndResetSerializerStartupHelperNode() noexcept
  {
    TSerializer& serializer = AccessSerializerStartupSlot<TSerializer>();
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* ResolveIntType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  gpg::RField* AddIntFieldToType(gpg::RType* const typeInfo, const char* const name, const int offset)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField{name, ResolveIntType(), offset});
    return &typeInfo->fields_.back();
  }

  gpg::RField* AddVector3fFieldToType(gpg::RType* const typeInfo, const char* const name, const int offset)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField{name, ResolveVector3fType(), offset});
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x004EABF0 (FUN_004EABF0)
   *
   * What it does:
   * Appends one canonical `"x"/"y"/"z"` float-field trio to the current
   * reflection type at offsets `0/4/8` and returns the `z` field handle.
   */
  [[maybe_unused]] gpg::RField* RegisterXyzFloatReflectionFields(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    if (typeInfo == nullptr) {
      return nullptr;
    }

    typeInfo->AddFieldFloat("x", 0);
    typeInfo->AddFieldFloat("y", 4);
    return typeInfo->AddFieldFloat("z", 8);
  }

  /**
   * Address: 0x004EA910 (FUN_004EA910)
   *
   * What it does:
   * Appends one canonical `"x"/"y"` float-field pair to the current
   * reflection type at offsets `0/4` and returns the `y` field handle.
   */
  [[maybe_unused]] gpg::RField* RegisterXyFloatReflectionFields(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    if (typeInfo == nullptr) {
      return nullptr;
    }

    typeInfo->AddFieldFloat("x", 0);
    return typeInfo->AddFieldFloat("y", 4);
  }

  template <typename TTypeInfo>
  void CleanupTypeInfoAtExit()
  {
    DestroyTypeInfoStartupSlot<TTypeInfo>();
  }

  template <typename TSerializer>
  void CleanupSerializerAtExit()
  {
    DestroySerializerStartupSlot<TSerializer>();
  }

  /**
   * Address: 0x004EE1B0 (FUN_004EE1B0, func_PointsAreSimilar)
   *
   * What it does:
   * Compares two 3D points component-wise and returns true when all axis deltas
   * are within one `0.001f` absolute threshold.
   */
  [[maybe_unused]] [[nodiscard]] bool PointsAreSimilarWithinEpsilon(
    const Wm3::Vector3f& lhs,
    const Wm3::Vector3f& rhs
  ) noexcept
  {
    constexpr float kAxisTolerance = 0.001f;
    return std::fabs(lhs.x - rhs.x) <= kAxisTolerance &&
      std::fabs(lhs.y - rhs.y) <= kAxisTolerance &&
      std::fabs(lhs.z - rhs.z) <= kAxisTolerance;
  }
} // namespace

boost::mutex& moho::math_GlobalRandomMutex = *reinterpret_cast<boost::mutex*>(gMathGlobalRandomMutexStorage);
moho::CRandomStream& moho::math_GlobalRandomStream =
  *reinterpret_cast<moho::CRandomStream*>(gMathGlobalRandomStreamStorage);

namespace moho
{
  VMatrix4 VMatrix4::NaN{};

  /**
   * Address: 0x007A6460 (FUN_007A6460, sub_7A6460)
   *
   * What it does:
   * Returns one process-global random sample in `[0, scale)` using the
   * shared MT stream.
   */
  double MathGlobalRandomUnitScaled(const float scale)
  {
    boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
    const float unit = CMersenneTwister::ToUnitFloat(math_GlobalRandomStream.twister.NextUInt32());
    return static_cast<double>(unit * scale);
  }

  /**
   * Address: 0x00514BC0 (FUN_00514BC0, func_RandomFloatSafe)
   *
   * What it does:
   * Returns one process-global random sample in `[0, 1)` using the shared
   * MT stream under `math_GlobalRandomMutex`.
   */
  double MathGlobalRandomUnitSafe()
  {
    boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
    const float unit = CMersenneTwister::ToUnitFloat(math_GlobalRandomStream.twister.NextUInt32());
    return static_cast<double>(unit);
  }

  /**
   * Address: 0x007A64B0 (FUN_007A64B0, func_DRand)
   *
   * What it does:
   * Returns one process-global random sample in `[minValue, maxValue)` using
   * the shared MT stream.
   */
  double MathGlobalRandomRange(const float minValue, const float maxValue)
  {
    boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
    const float unit = CMersenneTwister::ToUnitFloat(math_GlobalRandomStream.twister.NextUInt32());
    return static_cast<double>(minValue + (maxValue - minValue) * unit);
  }

  /**
   * Address: 0x004EB590 (FUN_004EB590, func_EulerToQuaternion)
   *
   * What it does:
   * Converts Euler roll/pitch/yaw lanes into one quaternion orientation.
   */
  Wm3::Quaternionf EulerToQuaternion(const VEulers3& orientation)
  {
    const float halfRoll = orientation.r * 0.5f;
    const float halfPitch = orientation.p * 0.5f;
    const float halfYaw = orientation.y * 0.5f;

    const float rollCos = std::cos(halfRoll);
    const float rollSin = std::sin(halfRoll);
    const float pitchCos = std::cos(halfPitch);
    const float pitchSin = std::sin(halfPitch);
    const float yawCos = std::cos(halfYaw);
    const float yawSin = std::sin(halfYaw);

    Wm3::Quaternionf orientationOut{};
    orientationOut.w = (yawCos * pitchCos * rollCos) + (yawSin * pitchSin * rollSin);
    orientationOut.x = (yawCos * pitchCos * rollSin) - (yawSin * pitchSin * rollCos);
    orientationOut.y = (pitchSin * yawCos * rollCos) + (yawSin * pitchCos * rollSin);
    orientationOut.z = (yawSin * pitchCos * rollCos) - (pitchSin * yawCos * rollSin);
    return orientationOut;
  }

  /**
   * Address: 0x004EC590 (FUN_004EC590, Moho::VAxes3::VAxes3)
   *
   * What it does:
   * Expands quaternion lanes into a 3x3 orthonormal basis.
   */
  VAxes3::VAxes3(const Wm3::Quaternionf& orientation)
  {
    const float twoX = orientation.x * 2.0f;
    const float twoY = orientation.y * 2.0f;
    const float twoZ = orientation.z * 2.0f;
    const float twoW = orientation.w * 2.0f;

    const float zz = twoZ * orientation.z;
    const float yy = twoY * orientation.y;
    const float yz = twoZ * orientation.y;
    const float xz = twoX * orientation.z;
    const float xy = twoX * orientation.y;
    const float wy = twoW * orientation.y;
    const float wz = twoW * orientation.z;
    const float wx = twoW * orientation.x;
    const float xx = twoX * orientation.x;

    vX.x = 1.0f - (yy + zz);
    vX.y = wz + yz;
    vX.z = wy - xz;

    vY.x = yz - wz;
    vY.y = 1.0f - (yy + xx);
    vY.z = xy + wx;

    vZ.x = xz + wy;
    vZ.y = wx - xy;
    vZ.z = 1.0f - (zz + xx);
  }

  /**
   * Address: 0x004EC6D0 (FUN_004EC6D0, ??0VAxes3@Moho@@QAE@ABVVEulers3@1@@Z)
   *
   * What it does:
   * Converts roll/pitch/yaw Euler lanes to quaternion and then expands that
   * quaternion into one orthonormal basis matrix.
   */
  VAxes3::VAxes3(const VEulers3& orientation)
    : VAxes3(EulerToQuaternion(orientation))
  {
  }

  /**
   * Address: 0x004EC720 (FUN_004EC720, ?OrthoNormalize@VAxes3@Moho@@QAEXXZ)
   * Mangled: ?OrthoNormalize@VAxes3@Moho@@QAEXXZ
   *
   * What it does:
   * Rebuilds the basis from cross products so axes remain orthogonal and
   * unit-length (`vX = normalize(vY x vZ)`, `vZ = normalize(vX x vY)`,
   * `vY = vZ x vX`).
   */
  void VAxes3::OrthoNormalize()
  {
    vX.x = (vZ.z * vY.y) - (vZ.y * vY.z);
    vX.y = (vZ.x * vY.z) - (vY.x * vZ.z);
    vX.z = (vY.x * vZ.y) - (vZ.x * vY.y);
    (void)Wm3::Vector3f::Normalize(&vX);

    vZ.x = (vX.y * vY.z) - (vX.z * vY.y);
    vZ.y = (vY.x * vX.z) - (vX.x * vY.z);
    vZ.z = (vX.x * vY.y) - (vY.x * vX.y);
    (void)Wm3::Vector3f::Normalize(&vZ);

    vY.x = (vZ.y * vX.z) - (vZ.z * vX.y);
    vY.y = (vZ.z * vX.x) - (vZ.x * vX.z);
    vY.z = (vZ.x * vX.y) - (vZ.y * vX.x);
  }

  /**
   * Address: 0x004EC850 (FUN_004EC850, ?IsNormal@VAxes3@Moho@@QBE_NXZ)
   * Mangled: ?IsNormal@VAxes3@Moho@@QBE_NXZ
   *
   * What it does:
   * Checks that all three basis lanes are unit-length and verifies `vX`
   * matches the reconstructed `vZ x vY` lane within epsilon.
   */
  bool VAxes3::IsNormal() const
  {
    constexpr float kUnitLengthEpsilon = 0.001f;
    const auto squaredLength = [](const Wm3::Vector3f& axis) {
      return (axis.x * axis.x) + (axis.y * axis.y) + (axis.z * axis.z);
    };

    if (std::fabs(squaredLength(vX) - 1.0f) > kUnitLengthEpsilon) {
      return false;
    }
    if (std::fabs(squaredLength(vY) - 1.0f) > kUnitLengthEpsilon) {
      return false;
    }
    if (std::fabs(squaredLength(vZ) - 1.0f) > kUnitLengthEpsilon) {
      return false;
    }

    const Wm3::Vector3f reconstructedVX{
      (vZ.z * vY.y) - (vZ.y * vY.z),
      (vZ.x * vY.z) - (vY.x * vZ.z),
      (vY.x * vZ.y) - (vZ.x * vY.y),
    };
    return PointsAreSimilarWithinEpsilon(vX, reconstructedVX);
  }

  msvc8::string ToString(const Wm3::Vector3f& value);

  /**
   * Address: 0x004ED000 (FUN_004ED000, ?ToString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVVAxes3@1@@Z)
   * Mangled: ?ToString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVVAxes3@1@@Z
   *
   * What it does:
   * Formats one basis as `X=(...) Y=(...) Z=(...)` using the existing vector
   * lane formatter.
   */
  msvc8::string ToString(const VAxes3& value)
  {
    const msvc8::string zText = ToString(value.vZ);
    const msvc8::string yText = ToString(value.vY);
    const msvc8::string xText = ToString(value.vX);
    return gpg::STR_Printf("X=(%s) Y=(%s) Z=(%s)", xText.c_str(), yText.c_str(), zText.c_str());
  }

  /**
   * Address: 0x004ECB60 (FUN_004ECB60, ??$Identity@VVAxes3@Moho@@@Moho@@YAABVVAxes3@0@XZ)
   *
   * What it does:
   * Returns a reference to the lazy-initialized identity `VAxes3`. The matrix
   * is latched on first call via a single-bit init guard so the constant is
   * written only once regardless of call frequency.
   */
  template <>
  const VAxes3& Identity<VAxes3>()
  {
    static bool sInitialized = false;
    static VAxes3 sIdentity{};

    if (!sInitialized) {
      sInitialized = true;
      sIdentity.vX = Wm3::Vector3f{1.0f, 0.0f, 0.0f};
      sIdentity.vY = Wm3::Vector3f{0.0f, 1.0f, 0.0f};
      sIdentity.vZ = Wm3::Vector3f{0.0f, 0.0f, 1.0f};
    }

    return sIdentity;
  }

  /**
   * Address: 0x004EDB60 (FUN_004EDB60, Moho::AxisAlignedBox3f::MemberDeserialize)
   *
   * What it does:
   * Loads `Min` and `Max` vector lanes in archive order.
   */
  void AxisAlignedBox3fMemberDeserialize(Wm3::AxisAlignedBox3f* const box, gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(box != nullptr);
    GPG_ASSERT(archive != nullptr);
    if (box == nullptr || archive == nullptr) {
      return;
    }

    archive->ReadFloat(&box->Min.x);
    archive->ReadFloat(&box->Min.y);
    archive->ReadFloat(&box->Min.z);
    archive->ReadFloat(&box->Max.x);
    archive->ReadFloat(&box->Max.y);
    archive->ReadFloat(&box->Max.z);
  }

  /**
   * Address: 0x004EDBB0 (FUN_004EDBB0, Moho::AxisAlignedBox3f::MemberSerialize)
   *
   * What it does:
   * Stores `Min` and `Max` vector lanes in archive order.
   */
  void AxisAlignedBox3fMemberSerialize(const Wm3::AxisAlignedBox3f* const box, gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(box != nullptr);
    GPG_ASSERT(archive != nullptr);
    if (box == nullptr || archive == nullptr) {
      return;
    }

    archive->WriteFloat(box->Min.x);
    archive->WriteFloat(box->Min.y);
    archive->WriteFloat(box->Min.z);
    archive->WriteFloat(box->Max.x);
    archive->WriteFloat(box->Max.y);
    archive->WriteFloat(box->Max.z);
  }

  /**
   * Address: 0x004E9FA0 (FUN_004E9FA0)
   *
   * What it does:
   * Stores one 32-bit lane into caller output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDwordLane9FA0(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    *outLane = value;
    return outLane;
  }

  /**
   * Address: 0x004E9FB0 (FUN_004E9FB0, Moho::AxisAlignedBox3fTypeInfo::AxisAlignedBox3fTypeInfo)
   */
  AxisAlignedBox3fTypeInfo::AxisAlignedBox3fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::AxisAlignedBox3f), this);
  }

  /**
   * Address: 0x004EA040 (FUN_004EA040, Moho::AxisAlignedBox3fTypeInfo::dtr)
   */
  AxisAlignedBox3fTypeInfo::~AxisAlignedBox3fTypeInfo() = default;

  /**
   * Address: 0x004EA030 (FUN_004EA030, Moho::AxisAlignedBox3fTypeInfo::GetName)
   */
  const char* AxisAlignedBox3fTypeInfo::GetName() const
  {
    return "AxisAlignedBox3f";
  }

  /**
   * Address: 0x004EA010 (FUN_004EA010, Moho::AxisAlignedBox3fTypeInfo::Init)
   */
  void AxisAlignedBox3fTypeInfo::Init()
  {
    size_ = sizeof(Wm3::AxisAlignedBox3f);
    gpg::RType::Init();
    AddBlueprintAxisAlignedBox3f();
    Finish();
  }

  /**
   * Address: 0x004EA140 (FUN_004EA140, Moho::AxisAlignedBox3fSerializer::Deserialize)
   */
  void AxisAlignedBox3fSerializer::Deserialize(gpg::ReadArchive* const archive, Wm3::AxisAlignedBox3f* const box)
  {
    AxisAlignedBox3fMemberDeserialize(box, archive);
  }

  /**
   * Address: 0x004EA150 (FUN_004EA150, Moho::AxisAlignedBox3fSerializer::Serialize)
   */
  void AxisAlignedBox3fSerializer::Serialize(gpg::WriteArchive* const archive, Wm3::AxisAlignedBox3f* const box)
  {
    AxisAlignedBox3fMemberSerialize(box, archive);
  }

  /**
   * Address: 0x004EA1A0 (FUN_004EA1A0)
   *
   * What it does:
   * Unlinks the `AxisAlignedBox3fSerializer` startup helper node from its
   * intrusive list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_AxisAlignedBox3fSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<AxisAlignedBox3fSerializer>();
  }

  /**
   * Address: 0x004EA1D0 (FUN_004EA1D0)
   *
   * What it does:
   * Duplicate cleanup lane for `AxisAlignedBox3fSerializer` that performs the
   * same helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_AxisAlignedBox3fSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<AxisAlignedBox3fSerializer>();
  }

  /**
   * Address: 0x00BF1230 (FUN_00BF1230, cleanup_AxisAlignedBox3fSerializer)
   */
  AxisAlignedBox3fSerializer::~AxisAlignedBox3fSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EA200 (FUN_004EA200, Moho::Vector2iTypeInfo::Vector2iTypeInfo)
   */
  Vector2iTypeInfo::Vector2iTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Vector2i), this);
  }

  /**
   * Address: 0x004EA2B0 (FUN_004EA2B0, Moho::Vector2iTypeInfo::dtr)
   */
  Vector2iTypeInfo::~Vector2iTypeInfo() = default;

  /**
   * Address: 0x004EA2A0 (FUN_004EA2A0, Moho::Vector2iTypeInfo::GetName)
   */
  const char* Vector2iTypeInfo::GetName() const
  {
    return "Vector2i";
  }

  /**
   * Address: 0x004EA260 (FUN_004EA260, Moho::Vector2iTypeInfo::Init)
   */
  void Vector2iTypeInfo::Init()
  {
    size_ = sizeof(Vector2i);
    gpg::RType::Init();
    AddIntFieldToType(this, "x", offsetof(Vector2i, x));
    AddIntFieldToType(this, "y", offsetof(Vector2i, y));
    Finish();
  }

  /**
   * Address: 0x004EA370 (FUN_004EA370, Moho::Vector2iSerializer::Deserialize)
   */
  void Vector2iSerializer::Deserialize(gpg::ReadArchive* const archive, Vector2i* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->ReadInt(&vector->x);
    archive->ReadInt(&vector->y);
  }

  /**
   * Address: 0x004EA3A0 (FUN_004EA3A0, Moho::Vector2iSerializer::Serialize)
   */
  void Vector2iSerializer::Serialize(gpg::WriteArchive* const archive, Vector2i* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->WriteInt(vector->x);
    archive->WriteInt(vector->y);
  }

  /**
   * Address: 0x004EA400 (FUN_004EA400)
   *
   * What it does:
   * Unlinks the `Vector2iSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_Vector2iSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector2iSerializer>();
  }

  /**
   * Address: 0x004EA430 (FUN_004EA430)
   *
   * What it does:
   * Duplicate cleanup lane for `Vector2iSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_Vector2iSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector2iSerializer>();
  }

  /**
   * Address: 0x00BF12C0 (FUN_00BF12C0, cleanup_Vector2iSerializer)
   */
  Vector2iSerializer::~Vector2iSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EA4C0 (FUN_004EA4C0, Moho::Vector3iTypeInfo::Vector3iTypeInfo)
   */
  Vector3iTypeInfo::Vector3iTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Vector3i), this);
  }

  /**
   * Address: 0x004EA580 (FUN_004EA580, Moho::Vector3iTypeInfo::dtr)
   */
  Vector3iTypeInfo::~Vector3iTypeInfo() = default;

  /**
   * Address: 0x004EA570 (FUN_004EA570, Moho::Vector3iTypeInfo::GetName)
   */
  const char* Vector3iTypeInfo::GetName() const
  {
    return "Vector3i";
  }

  /**
   * Address: 0x004EA520 (FUN_004EA520, Moho::Vector3iTypeInfo::Init)
   */
  void Vector3iTypeInfo::Init()
  {
    size_ = sizeof(Vector3i);
    gpg::RType::Init();
    AddIntFieldToType(this, "x", offsetof(Vector3i, x));
    AddIntFieldToType(this, "y", offsetof(Vector3i, y));
    AddIntFieldToType(this, "z", offsetof(Vector3i, z));
    Finish();
  }

  /**
   * Address: 0x004EA650 (FUN_004EA650, Moho::Vector3iSerializer::Deserialize)
   */
  void Vector3iSerializer::Deserialize(gpg::ReadArchive* const archive, Vector3i* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->ReadInt(&vector->x);
    archive->ReadInt(&vector->y);
    archive->ReadInt(&vector->z);
  }

  /**
   * Address: 0x004EA690 (FUN_004EA690, Moho::Vector3iSerializer::Serialize)
   */
  void Vector3iSerializer::Serialize(gpg::WriteArchive* const archive, Vector3i* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->WriteInt(vector->x);
    archive->WriteInt(vector->y);
    archive->WriteInt(vector->z);
  }

  /**
   * Address: 0x004EA700 (FUN_004EA700)
   *
   * What it does:
   * Unlinks the `Vector3iSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_Vector3iSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector3iSerializer>();
  }

  /**
   * Address: 0x004EA730 (FUN_004EA730)
   *
   * What it does:
   * Duplicate cleanup lane for `Vector3iSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_Vector3iSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector3iSerializer>();
  }

  /**
   * Address: 0x00BF1350 (FUN_00BF1350, cleanup_Vector3iSerializer)
   */
  Vector3iSerializer::~Vector3iSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EA7C0 (FUN_004EA7C0, Moho::Vector2fTypeInfo::Vector2fTypeInfo)
   */
  Vector2fTypeInfo::Vector2fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Vector2<float>), this);
  }

  /**
   * Address: 0x004EA870 (FUN_004EA870, Moho::Vector2fTypeInfo::dtr)
   */
  Vector2fTypeInfo::~Vector2fTypeInfo() = default;

  /**
   * Address: 0x004EA860 (FUN_004EA860, Moho::Vector2fTypeInfo::GetName)
   */
  const char* Vector2fTypeInfo::GetName() const
  {
    return "Vector2f";
  }

  /**
   * Address: 0x004EA820 (FUN_004EA820, Moho::Vector2fTypeInfo::Init)
   */
  void Vector2fTypeInfo::Init()
  {
    size_ = sizeof(Vector2f);
    gpg::RType::Init();
    (void)RegisterXyFloatReflectionFields(this);
    Finish();
  }

  /**
   * Address: 0x004EA930 (FUN_004EA930, Moho::Vector2fSerializer::Deserialize)
   */
  void Vector2fSerializer::Deserialize(gpg::ReadArchive* const archive, Vector2f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->ReadFloat(&vector->x);
    archive->ReadFloat(&vector->y);
  }

  /**
   * Address: 0x004EA960 (FUN_004EA960, Moho::Vector2fSerializer::Serialize)
   */
  void Vector2fSerializer::Serialize(gpg::WriteArchive* const archive, Vector2f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->WriteFloat(vector->x);
    archive->WriteFloat(vector->y);
  }

  /**
   * Address: 0x004EA9C0 (FUN_004EA9C0)
   *
   * What it does:
   * Unlinks the `Vector2fSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_Vector2fSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector2fSerializer>();
  }

  /**
   * Address: 0x004EA9F0 (FUN_004EA9F0)
   *
   * What it does:
   * Duplicate cleanup lane for `Vector2fSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_Vector2fSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector2fSerializer>();
  }

  /**
   * Address: 0x00BF13E0 (FUN_00BF13E0, cleanup_Vector2fSerializer)
   */
  Vector2fSerializer::~Vector2fSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EAA90 (FUN_004EAA90, Moho::Vector3fTypeInfo::Vector3fTypeInfo)
   */
  Vector3fTypeInfo::Vector3fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Vector3<float>), this);
  }

  /**
   * Address: 0x004EAB50 (FUN_004EAB50, Moho::Vector3fTypeInfo::dtr)
   */
  Vector3fTypeInfo::~Vector3fTypeInfo() = default;

  /**
   * Address: 0x004EAB40 (FUN_004EAB40, Moho::Vector3fTypeInfo::GetName)
   */
  const char* Vector3fTypeInfo::GetName() const
  {
    return "Vector3f";
  }

  /**
   * Address: 0x004EAAF0 (FUN_004EAAF0, Moho::Vector3fTypeInfo::Init)
   */
  void Vector3fTypeInfo::Init()
  {
    size_ = sizeof(Vector3f);
    gpg::RType::Init();
    RegisterXyzFloatReflectionFields(this);
    Finish();
  }

  /**
   * Address: 0x004EAC20 (FUN_004EAC20, Moho::Vector3fSerializer::Deserialize)
   */
  void Vector3fSerializer::Deserialize(gpg::ReadArchive* const archive, Vector3f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->ReadFloat(&vector->x);
    archive->ReadFloat(&vector->y);
    archive->ReadFloat(&vector->z);
  }

  /**
   * Address: 0x004EAC60 (FUN_004EAC60, Moho::Vector3fSerializer::Serialize)
   */
  void Vector3fSerializer::Serialize(gpg::WriteArchive* const archive, Vector3f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->WriteFloat(vector->x);
    archive->WriteFloat(vector->y);
    archive->WriteFloat(vector->z);
  }

  /**
   * Address: 0x004EACD0 (FUN_004EACD0)
   *
   * What it does:
   * Unlinks the `Vector3fSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_Vector3fSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector3fSerializer>();
  }

  /**
   * Address: 0x004EAD00 (FUN_004EAD00)
   *
   * What it does:
   * Duplicate cleanup lane for `Vector3fSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_Vector3fSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector3fSerializer>();
  }

  /**
   * Address: 0x00BF1470 (FUN_00BF1470, cleanup_Vector3fSerializer)
   */
  Vector3fSerializer::~Vector3fSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EADC0 (FUN_004EADC0, Moho::Vector4fTypeInfo::Vector4fTypeInfo)
   */
  Vector4fTypeInfo::Vector4fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Vector4f), this);
  }

  /**
   * Address: 0x004EAE90 (FUN_004EAE90, Moho::Vector4fTypeInfo::dtr)
   */
  Vector4fTypeInfo::~Vector4fTypeInfo() = default;

  /**
   * Address: 0x004EAE80 (FUN_004EAE80, Moho::Vector4fTypeInfo::GetName)
   */
  const char* Vector4fTypeInfo::GetName() const
  {
    return "Vector4f";
  }

  /**
   * Address: 0x004EAE20 (FUN_004EAE20, Moho::Vector4fTypeInfo::Init)
   */
  void Vector4fTypeInfo::Init()
  {
    size_ = sizeof(Vector4f);
    gpg::RType::Init();
    AddFieldFloat("x", offsetof(Vector4f, x));
    AddFieldFloat("y", offsetof(Vector4f, y));
    AddFieldFloat("z", offsetof(Vector4f, z));
    AddFieldFloat("w", offsetof(Vector4f, w));
    Finish();
  }

  /**
   * Address: 0x004EAF70 (FUN_004EAF70, Moho::Vector4fSerializer::Deserialize)
   */
  void Vector4fSerializer::Deserialize(gpg::ReadArchive* const archive, Vector4f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->ReadFloat(&vector->x);
    archive->ReadFloat(&vector->y);
    archive->ReadFloat(&vector->z);
    archive->ReadFloat(&vector->w);
  }

  /**
   * Address: 0x004EAFB0 (FUN_004EAFB0, Moho::Vector4fSerializer::Serialize)
   */
  void Vector4fSerializer::Serialize(gpg::WriteArchive* const archive, Vector4f* const vector)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vector != nullptr);
    if (archive == nullptr || vector == nullptr) {
      return;
    }

    archive->WriteFloat(vector->x);
    archive->WriteFloat(vector->y);
    archive->WriteFloat(vector->z);
    archive->WriteFloat(vector->w);
  }

  /**
   * Address: 0x004EB030 (FUN_004EB030)
   *
   * What it does:
   * Unlinks the `Vector4fSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_Vector4fSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector4fSerializer>();
  }

  /**
   * Address: 0x004EB060 (FUN_004EB060)
   *
   * What it does:
   * Duplicate cleanup lane for `Vector4fSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_Vector4fSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<Vector4fSerializer>();
  }

  /**
   * Address: 0x00BF1500 (FUN_00BF1500, cleanup_Vector4fSerializer)
   */
  Vector4fSerializer::~Vector4fSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EB120 (FUN_004EB120, Moho::QuaternionfTypeInfo::QuaternionfTypeInfo)
   */
  QuaternionfTypeInfo::QuaternionfTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Quaternion<float>), this);
  }

  /**
   * Address: 0x004EB1F0 (FUN_004EB1F0, Moho::QuaternionfTypeInfo::dtr)
   */
  QuaternionfTypeInfo::~QuaternionfTypeInfo() = default;

  /**
   * Address: 0x004EB1E0 (FUN_004EB1E0, Moho::QuaternionfTypeInfo::GetName)
   */
  const char* QuaternionfTypeInfo::GetName() const
  {
    return "Quaternionf";
  }

  /**
   * Address: 0x004EB180 (FUN_004EB180, Moho::QuaternionfTypeInfo::Init)
   */
  void QuaternionfTypeInfo::Init()
  {
    size_ = sizeof(Quaternionf);
    gpg::RType::Init();
    AddFieldFloat("w", offsetof(Quaternionf, w));
    AddFieldFloat("x", offsetof(Quaternionf, x));
    AddFieldFloat("y", offsetof(Quaternionf, y));
    AddFieldFloat("z", offsetof(Quaternionf, z));
    Finish();
  }

  /**
   * Address: 0x004EB2D0 (FUN_004EB2D0, Moho::QuaternionfSerializer::Deserialize)
   */
  void QuaternionfSerializer::Deserialize(gpg::ReadArchive* const archive, Quaternionf* const quaternion)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(quaternion != nullptr);
    if (archive == nullptr || quaternion == nullptr) {
      return;
    }

    archive->ReadFloat(&quaternion->y);
    archive->ReadFloat(&quaternion->z);
    archive->ReadFloat(&quaternion->w);
    archive->ReadFloat(&quaternion->x);
  }

  /**
   * Address: 0x004EB310 (FUN_004EB310, Moho::QuaternionfSerializer::Serialize)
   */
  void QuaternionfSerializer::Serialize(gpg::WriteArchive* const archive, Quaternionf* const quaternion)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(quaternion != nullptr);
    if (archive == nullptr || quaternion == nullptr) {
      return;
    }

    archive->WriteFloat(quaternion->y);
    archive->WriteFloat(quaternion->z);
    archive->WriteFloat(quaternion->w);
    archive->WriteFloat(quaternion->x);
  }

  /**
   * Address: 0x004EB390 (FUN_004EB390)
   *
   * What it does:
   * Unlinks the `QuaternionfSerializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_QuaternionfSerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<QuaternionfSerializer>();
  }

  /**
   * Address: 0x004EB3C0 (FUN_004EB3C0)
   *
   * What it does:
   * Duplicate cleanup lane for `QuaternionfSerializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_QuaternionfSerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<QuaternionfSerializer>();
  }

  /**
   * Address: 0x00BF1590 (FUN_00BF1590, cleanup_QuaternionfSerializer)
   */
  QuaternionfSerializer::~QuaternionfSerializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EBF50 (FUN_004EBF50, Moho::VEulers3TypeInfo::VEulers3TypeInfo)
   */
  VEulers3TypeInfo::VEulers3TypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(VEulers3), this);
  }

  /**
   * Address: 0x004EC020 (FUN_004EC020, Moho::VEulers3TypeInfo::dtr)
   */
  VEulers3TypeInfo::~VEulers3TypeInfo() = default;

  /**
   * Address: 0x004EC010 (FUN_004EC010, Moho::VEulers3TypeInfo::GetName)
   */
  const char* VEulers3TypeInfo::GetName() const
  {
    return "VEulers3";
  }

  /**
   * Address: 0x004EBFB0 (FUN_004EBFB0, Moho::VEulers3TypeInfo::Init)
   */
  void VEulers3TypeInfo::Init()
  {
    size_ = sizeof(VEulers3);
    gpg::RType::Init();
    gpg::RField* const roll = AddFieldFloat("r", offsetof(VEulers3, r));
    gpg::RField* const pitch = AddFieldFloat("p", offsetof(VEulers3, p));
    gpg::RField* const yaw = AddFieldFloat("y", offsetof(VEulers3, y));
    if (roll != nullptr) {
      roll->mName = "Roll";
    }
    if (pitch != nullptr) {
      pitch->mName = "Pitch";
    }
    if (yaw != nullptr) {
      yaw->mName = "Yaw";
    }
    Finish();
  }

  /**
   * Address: 0x004EC100 (FUN_004EC100, Moho::VEulers3Serializer::Deserialize)
   */
  void VEulers3Serializer::Deserialize(gpg::ReadArchive* const archive, VEulers3* const eulers)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(eulers != nullptr);
    if (archive == nullptr || eulers == nullptr) {
      return;
    }

    archive->ReadFloat(&eulers->r);
    archive->ReadFloat(&eulers->p);
    archive->ReadFloat(&eulers->y);
  }

  /**
   * Address: 0x004EC140 (FUN_004EC140, Moho::VEulers3Serializer::Serialize)
   */
  void VEulers3Serializer::Serialize(gpg::WriteArchive* const archive, VEulers3* const eulers)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(eulers != nullptr);
    if (archive == nullptr || eulers == nullptr) {
      return;
    }

    archive->WriteFloat(eulers->r);
    archive->WriteFloat(eulers->p);
    archive->WriteFloat(eulers->y);
  }

  /**
   * Address: 0x004EC1B0 (FUN_004EC1B0)
   *
   * What it does:
   * Unlinks the `VEulers3Serializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_VEulers3SerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VEulers3Serializer>();
  }

  /**
   * Address: 0x004EC1E0 (FUN_004EC1E0)
   *
   * What it does:
   * Duplicate cleanup lane for `VEulers3Serializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_VEulers3SerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VEulers3Serializer>();
  }

  /**
   * Address: 0x00BF1620 (FUN_00BF1620, cleanup_VEulers3Serializer)
   */
  VEulers3Serializer::~VEulers3Serializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004EC360 (FUN_004EC360, Moho::VAxes3TypeInfo::VAxes3TypeInfo)
   */
  VAxes3TypeInfo::VAxes3TypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(VAxes3), this);
  }

  /**
   * Address: 0x004EC410 (FUN_004EC410, Moho::VAxes3TypeInfo::dtr)
   */
  VAxes3TypeInfo::~VAxes3TypeInfo() = default;

  /**
   * Address: 0x004EC400 (FUN_004EC400, Moho::VAxes3TypeInfo::GetName)
   */
  const char* VAxes3TypeInfo::GetName() const
  {
    return "VAxes3";
  }

  /**
   * Address: 0x004EC3C0 (FUN_004EC3C0, Moho::VAxes3TypeInfo::Init)
   */
  void VAxes3TypeInfo::Init()
  {
    size_ = sizeof(VAxes3);
    gpg::RType::Init();
    AddVector3fFieldToType(this, "vX", offsetof(VAxes3, vX));
    AddVector3fFieldToType(this, "vY", offsetof(VAxes3, vY));
    AddVector3fFieldToType(this, "vZ", offsetof(VAxes3, vZ));
    Finish();
  }

  /**
   * Address: 0x004EE050 (FUN_004EE050, Moho::VAxes3Serializer::Deserialize)
   */
  void VAxes3Serializer::Deserialize(gpg::ReadArchive* const archive, VAxes3* const axes)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(axes != nullptr);
    if (archive == nullptr || axes == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(ResolveVector3fType(), &axes->vX, ownerRef);
    archive->Read(ResolveVector3fType(), &axes->vY, ownerRef);
    archive->Read(ResolveVector3fType(), &axes->vZ, ownerRef);
  }

  /**
   * Address: 0x004EE100 (FUN_004EE100, Moho::VAxes3Serializer::Serialize)
   */
  void VAxes3Serializer::Serialize(gpg::WriteArchive* const archive, VAxes3* const axes)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(axes != nullptr);
    if (archive == nullptr || axes == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(ResolveVector3fType(), &axes->vX, ownerRef);
    archive->Write(ResolveVector3fType(), &axes->vY, ownerRef);
    archive->Write(ResolveVector3fType(), &axes->vZ, ownerRef);
  }

  /**
   * Address: 0x004EC530 (FUN_004EC530)
   *
   * What it does:
   * Unlinks the `VAxes3Serializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_VAxes3SerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VAxes3Serializer>();
  }

  /**
   * Address: 0x004EC560 (FUN_004EC560)
   *
   * What it does:
   * Duplicate cleanup lane for `VAxes3Serializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_VAxes3SerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VAxes3Serializer>();
  }

  /**
   * Address: 0x00BF16B0 (FUN_00BF16B0, cleanup_VAxes3Serializer)
   */
  VAxes3Serializer::~VAxes3Serializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004ECBD0 (FUN_004ECBD0, Moho::VEC_LookAt)
   *
   * What it does:
   * Builds one orthonormal basis from a reference up vector and a forward
   * vector, normalizing forward first and falling back to the binary's
   * alternate right-axis lane when the cross product collapses.
   */
  void VEC_LookAt(const Wm3::Vector3f& up, const Wm3::Vector3f& forwardInput, VAxes3* const axes)
  {
    const float forwardLengthSq =
      (forwardInput.x * forwardInput.x) + (forwardInput.y * forwardInput.y) + (forwardInput.z * forwardInput.z);
    if (!(forwardLengthSq > 0.0f)) {
      return;
    }

    const float forwardLength = std::sqrtf(forwardLengthSq);
    float forwardX = std::numeric_limits<float>::max();
    float forwardY = std::numeric_limits<float>::max();
    float forwardZ = std::numeric_limits<float>::max();
    if (forwardLength != 0.0f) {
      const float reciprocalForwardLength = 1.0f / forwardLength;
      forwardX = forwardInput.x * reciprocalForwardLength;
      forwardY = forwardInput.y * reciprocalForwardLength;
      forwardZ = forwardInput.z * reciprocalForwardLength;
    }

    float rightX = (up.y * forwardZ) - (up.z * forwardY);
    float rightY = (up.z * forwardX) - (up.x * forwardZ);
    float rightZ = (up.x * forwardY) - (up.y * forwardX);
    const float rightLengthSq = (rightX * rightX) + (rightY * rightY) + (rightZ * rightZ);
    if (!(rightLengthSq > 0.0f)) {
      // Match the binary fallback lane when the up vector is collinear with forward.
      rightX = (forwardZ * forwardZ) - ((-0.0f - forwardX) * forwardY);
      rightY = ((-0.0f - forwardX) * forwardX) - (forwardY * forwardZ);
      rightZ = (forwardY * forwardY) - (forwardZ * forwardX);
    }

    const float rightLength = std::sqrtf((rightX * rightX) + (rightY * rightY) + (rightZ * rightZ));
    float basisX = std::numeric_limits<float>::max();
    float basisY = std::numeric_limits<float>::max();
    float basisZ = std::numeric_limits<float>::max();
    if (rightLength != 0.0f) {
      const float reciprocalRightLength = 1.0f / rightLength;
      basisX = rightX * reciprocalRightLength;
      basisY = rightY * reciprocalRightLength;
      basisZ = rightZ * reciprocalRightLength;
    }

    axes->vX.x = basisX;
    axes->vX.y = basisY;
    axes->vX.z = basisZ;
    axes->vY.x = (basisZ * forwardY) - (basisY * forwardZ);
    axes->vY.y = (forwardZ * basisX) - (basisZ * forwardX);
    axes->vY.z = (basisY * forwardX) - (forwardY * basisX);
    axes->vZ.x = forwardX;
    axes->vZ.y = forwardY;
    axes->vZ.z = forwardZ;
  }

  /**
   * Address: 0x0050B650 (FUN_0050B650, ?COORDS_LookAt@Moho@@YAXABV?$Vector3@M@Wm3@@PAVVAxes3@1@@Z)
   *
   * What it does:
   * Builds look-at axes using world-up `(0,1,0)` and the supplied forward
   * direction.
   */
  void COORDS_LookAt(const Wm3::Vector3f& forward, VAxes3* const axes)
  {
    const Wm3::Vector3f worldUp{0.0f, 1.0f, 0.0f};
    VEC_LookAt(worldUp, forward, axes);
  }

  /**
   * Address: 0x0050B680 (FUN_0050B680, ?COORDS_LookAtXZ@Moho@@YAXABV?$Vector3@M@Wm3@@PAVVAxes3@1@@Z)
   *
   * What it does:
   * Builds an XZ-plane-aligned basis from one direction vector without
   * normalizing the projected axes.
   */
  VAxes3* COORDS_LookAtXZ(VAxes3* const outAxes, const Wm3::Vector3f& direction)
  {
    const float lengthSq = (direction.x * direction.x) + (direction.y * direction.y) + (direction.z * direction.z);
    if (lengthSq <= 0.0f) {
      return outAxes;
    }

    outAxes->vX.x = direction.z;
    outAxes->vX.y = 0.0f;
    outAxes->vX.z = -direction.x;

    outAxes->vY.x = 0.0f;
    outAxes->vY.y = 1.0f;
    outAxes->vY.z = 0.0f;

    outAxes->vZ.x = direction.x;
    outAxes->vZ.y = 0.0f;
    outAxes->vZ.z = direction.z;
    return outAxes;
  }

  /**
   * Address: 0x004EC4E0 (FUN_004EC4E0, Moho::VAxes3Serializer::DeserializeThunk)
   */
  void DeserializeVAxes3SerializerThunk(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    if (objectPtr == 0) {
      return;
    }

    VAxes3Serializer::Deserialize(
      archive,
      reinterpret_cast<VAxes3*>(static_cast<std::uintptr_t>(objectPtr))
    );
  }

  /**
   * Address: 0x004EC4F0 (FUN_004EC4F0, Moho::VAxes3Serializer::SerializeThunk)
   */
  void SerializeVAxes3SerializerThunk(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    if (objectPtr == 0) {
      return;
    }

    VAxes3Serializer::Serialize(
      archive,
      reinterpret_cast<VAxes3*>(static_cast<std::uintptr_t>(objectPtr))
    );
  }

  /**
   * Address: 0x004F00E0 (FUN_004F00E0, Moho::VMatrix4TypeInfo::VMatrix4TypeInfo)
   */
  VMatrix4TypeInfo::VMatrix4TypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(VMatrix4), this);
  }

  /**
   * Address: 0x004F0170 (FUN_004F0170, Moho::VMatrix4TypeInfo::dtr)
   */
  VMatrix4TypeInfo::~VMatrix4TypeInfo() = default;

  /**
   * Address: 0x004F0160 (FUN_004F0160, Moho::VMatrix4TypeInfo::GetName)
   */
  const char* VMatrix4TypeInfo::GetName() const
  {
    return "VMatrix4";
  }

  /**
   * Address: 0x004F0140 (FUN_004F0140, Moho::VMatrix4TypeInfo::Init)
   */
  void VMatrix4TypeInfo::Init()
  {
    size_ = sizeof(VMatrix4);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x004F0220 (FUN_004F0220, Moho::VMatrix4Serializer::Deserialize)
   */
  void VMatrix4Serializer::Deserialize(gpg::ReadArchive* const archive, VMatrix4* const matrix)
  {
    if (matrix == nullptr) {
      return;
    }

    matrix->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004F0230 (FUN_004F0230, Moho::VMatrix4Serializer::Serialize)
   */
  void VMatrix4Serializer::Serialize(gpg::WriteArchive* const archive, VMatrix4* const matrix)
  {
    if (matrix == nullptr) {
      return;
    }

    matrix->MemberSerialize(archive);
  }

  /**
   * Address: 0x004F0270 (FUN_004F0270)
   *
   * What it does:
   * Unlinks the `VMatrix4Serializer` startup helper node from its intrusive
   * list, rewires it to self-link, and returns that self node.
   */
  gpg::SerHelperBase* cleanup_VMatrix4SerializerVariant1()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VMatrix4Serializer>();
  }

  /**
   * Address: 0x004F02A0 (FUN_004F02A0)
   *
   * What it does:
   * Duplicate cleanup lane for `VMatrix4Serializer` that performs the same
   * helper-node unlink and self-link reset, then returns the self node.
   */
  gpg::SerHelperBase* cleanup_VMatrix4SerializerVariant2()
  {
    return UnlinkAndResetSerializerStartupHelperNode<VMatrix4Serializer>();
  }

  /**
   * Address: 0x004F0300 (FUN_004F0300, Moho::VMatrix4Serializer::RegisterSerializeFunctions)
   */
  void VMatrix4Serializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = VMatrix4::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(VMatrix4));
      VMatrix4::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF1740 (FUN_00BF1740, cleanup_VMatrix4Serializer)
   */
  VMatrix4Serializer::~VMatrix4Serializer() noexcept
  {
    UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x004F0390 (FUN_004F0390, Moho::VMatrix4::MemberDeserialize)
   */
  void VMatrix4::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (archive == nullptr) {
      return;
    }

    for (int row = 0; row < 4; ++row) {
      float* const rowData = &r[row].x;
      for (int col = 0; col < 4; ++col) {
        archive->ReadFloat(&rowData[col]);
      }
    }
  }

  /**
   * Address: 0x004F03D0 (FUN_004F03D0, Moho::VMatrix4::MemberSerialize)
   */
  void VMatrix4::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (archive == nullptr) {
      return;
    }

    for (int row = 0; row < 4; ++row) {
      const float* const rowData = &r[row].x;
      for (int col = 0; col < 4; ++col) {
        archive->WriteFloat(rowData[col]);
      }
    }
  }

  /**
   * Address: 0x004ED8B0 (FUN_004ED8B0)
   *
   * What it does:
   * Initializes one 3-float vector lane from three scalar source lanes.
   */
  [[maybe_unused]] Wm3::Vector3f* InitializeVector3fFromScalarLanes(
    Wm3::Vector3f* const outVector,
    const float* const xLane,
    const float* const yLane,
    const float* const zLane
  ) noexcept
  {
    outVector->x = *xLane;
    outVector->y = *yLane;
    outVector->z = *zLane;
    return outVector;
  }

  /**
   * Address: 0x004ED930 (FUN_004ED930)
   *
   * What it does:
   * Returns one float-lane pointer offset by `index`.
   */
  [[maybe_unused]] float* OffsetFloatLanePointer(
    float* const baseLane,
    const std::int32_t index
  ) noexcept
  {
    return baseLane + index;
  }

  /**
   * Address: 0x004EE300 (FUN_004EE300)
   *
   * What it does:
   * Builds one 4x4 matrix from four row lanes in register-order mapping
   * (`row0=edi`, `row1=esi`, `row2=edx`, `row3=ecx`).
   */
  [[maybe_unused]] VMatrix4* BuildVMatrix4FromRegisterRowLanesA(
    const Vector4f* const laneEdxRow2,
    const Vector4f* const laneEcxRow3,
    const Vector4f* const laneEdiRow0,
    const Vector4f* const laneEsiRow1,
    VMatrix4* const outMatrix
  ) noexcept
  {
    outMatrix->r[0] = *laneEdiRow0;
    outMatrix->r[1] = *laneEsiRow1;
    outMatrix->r[2] = *laneEdxRow2;
    outMatrix->r[3] = *laneEcxRow3;
    return outMatrix;
  }

  /**
   * Address: 0x004EE4D0 (FUN_004EE4D0)
   *
   * What it does:
   * Duplicate lane for building one 4x4 matrix from four row lanes in the
   * same register-order mapping as `FUN_004EE300`.
   */
  [[maybe_unused]] VMatrix4* BuildVMatrix4FromRegisterRowLanesB(
    const Vector4f* const laneEdxRow2,
    const Vector4f* const laneEcxRow3,
    const Vector4f* const laneEdiRow0,
    const Vector4f* const laneEsiRow1,
    VMatrix4* const outMatrix
  ) noexcept
  {
    outMatrix->r[0] = *laneEdiRow0;
    outMatrix->r[1] = *laneEsiRow1;
    outMatrix->r[2] = *laneEdxRow2;
    outMatrix->r[3] = *laneEcxRow3;
    return outMatrix;
  }

  /**
   * Address: 0x004EE980 (FUN_004EE980, Moho::VMatrix4::Set)
   *
   * What it does:
   * Expands quaternion lanes into the matrix 3x3 rotation block and writes
   * translation into row 3 with homogeneous w set to 1.
   */
  void VMatrix4::Set(const Wm3::Quaternionf& quat, const Wm3::Vector3f& vec)
  {
    const float twoX = quat.x * 2.0f;
    const float twoY = quat.y * 2.0f;
    const float twoZ = quat.z * 2.0f;
    const float twoW = quat.w * 2.0f;

    const float zz2 = twoZ * quat.z;
    const float ww2 = twoW * quat.w;
    const float yz2 = twoZ * quat.y;
    const float yy2 = twoY * quat.y;
    const float wy2 = twoW * quat.y;
    const float xy2 = twoX * quat.y;
    const float wz2 = twoW * quat.z;
    const float xz2 = twoX * quat.z;
    const float wx2 = twoX * quat.w;

    r[0].x = 1.0f - (ww2 + zz2);
    r[1].x = yz2 - wx2;
    r[0].y = wx2 + yz2;
    r[1].y = 1.0f - (ww2 + yy2);
    r[2].y = wz2 - xy2;
    r[0].z = wy2 - xz2;
    r[0].w = 0.0f;
    r[1].w = 0.0f;
    r[2].x = xz2 + wy2;
    r[2].w = 0.0f;
    r[1].z = wz2 + xy2;
    r[2].z = 1.0f - (zz2 + yy2);
    r[3].x = vec.x;
    r[3].y = vec.y;
    r[3].z = vec.z;
    r[3].w = 1.0f;
  }

  /**
   * Address: 0x00658EE0 (FUN_00658EE0)
   *
   * What it does:
   * Copies the canonical identity matrix lane into `out` and returns it.
   */
  [[maybe_unused]] VMatrix4* CopyVMatrix4IdentityLane(VMatrix4* const out)
  {
    if (out == nullptr) {
      return nullptr;
    }

    static const VMatrix4 kIdentity = VMatrix4::Identity();
    *out = kIdentity;
    return out;
  }

  /**
   * Address: 0x004EE6B0 (FUN_004EE6B0)
   *
   * What it does:
   * Lazily snapshots `VMatrix4::NaN` into one process-global matrix lane and
   * returns that cached lane.
   */
  [[maybe_unused]] VMatrix4* AccessVMatrix4NaNCache()
  {
    static bool sInitialized = false;
    static VMatrix4 sNaNCache{};

    if (!sInitialized) {
      sInitialized = true;
      sNaNCache = VMatrix4::NaN;
    }

    return &sNaNCache;
  }

  /**
   * Address: 0x004EE6E0 (FUN_004EE6E0, ?VEC_Mul@Moho@@YA?AUVMatrix4@1@ABU21@0@Z)
   *
   * What it does:
   * Returns one matrix product using the binary's `rhs * lhs` call order.
   */
  VMatrix4 VEC_Mul(const VMatrix4& lhs, const VMatrix4& rhs)
  {
    VMatrix4 result{};
    (void)gpg::gal::Math::mul(&result, &rhs, &lhs);
    return result;
  }

  /**
   * Address: 0x004EE710 (FUN_004EE710, ?VEC_Mul4x3@Moho@@YAXAAUVMatrix4@1@ABU21@1@Z)
   *
   * What it does:
   * Computes one affine 4x3 matrix composition (`rhs * lhs`) and writes x/y/z
   * lanes for all rows into `out`.
   */
  void VEC_Mul4x3(const VMatrix4& lhs, VMatrix4& out, const VMatrix4& rhs)
  {
    const float lhs00 = lhs.r[0].x;
    const float lhs01 = lhs.r[0].y;
    const float lhs02 = lhs.r[0].z;
    const float lhs10 = lhs.r[1].x;
    const float lhs11 = lhs.r[1].y;
    const float lhs12 = lhs.r[1].z;
    const float lhs20 = lhs.r[2].x;
    const float lhs21 = lhs.r[2].y;
    const float lhs22 = lhs.r[2].z;
    const float lhs30 = lhs.r[3].x;
    const float lhs31 = lhs.r[3].y;
    const float lhs32 = lhs.r[3].z;

    out.r[0].x = (rhs.r[0].z * lhs20) + (rhs.r[0].y * lhs10) + (rhs.r[0].x * lhs00);
    out.r[0].y = (rhs.r[0].z * lhs21) + (rhs.r[0].y * lhs11) + (rhs.r[0].x * lhs01);
    out.r[0].z = (rhs.r[0].z * lhs22) + (rhs.r[0].y * lhs12) + (rhs.r[0].x * lhs02);

    out.r[1].x = (rhs.r[1].z * lhs20) + (rhs.r[1].y * lhs10) + (rhs.r[1].x * lhs00);
    out.r[1].y = (rhs.r[1].z * lhs21) + (rhs.r[1].y * lhs11) + (rhs.r[1].x * lhs01);
    out.r[1].z = (rhs.r[1].z * lhs22) + (rhs.r[1].y * lhs12) + (rhs.r[1].x * lhs02);

    out.r[2].x = (rhs.r[2].z * lhs20) + (rhs.r[2].y * lhs10) + (rhs.r[2].x * lhs00);
    out.r[2].y = (rhs.r[2].z * lhs21) + (rhs.r[2].y * lhs11) + (rhs.r[2].x * lhs01);
    out.r[2].z = (rhs.r[2].z * lhs22) + (rhs.r[2].y * lhs12) + (rhs.r[2].x * lhs02);

    out.r[3].x = ((rhs.r[3].z * lhs20) + (rhs.r[3].y * lhs10) + (rhs.r[3].x * lhs00)) + lhs30;
    out.r[3].y = ((rhs.r[3].z * lhs21) + (rhs.r[3].y * lhs11) + (rhs.r[3].x * lhs01)) + lhs31;
    out.r[3].z = ((rhs.r[3].z * lhs22) + (rhs.r[3].y * lhs12) + (rhs.r[3].x * lhs02)) + lhs32;
  }

  /**
   * Address: 0x004EEC10 (FUN_004EEC10, ?LoadInverse@VMatrix4@Moho@@QAEXXZ)
   *
   * What it does:
   * Replaces this matrix with its full inverse.
   */
  void VMatrix4::LoadInverse()
  {
    VMatrix4 inverse{};
    (void)gpg::gal::Math::invert(&inverse, this);
    *this = inverse;
  }

  /**
   * Address: 0x004EEC40 (FUN_004EEC40, ?LoadInverse4x3@VMatrix4@Moho@@QAEXXZ)
   *
   * What it does:
   * Replaces this matrix with the inverse lane used by 4x3 call sites.
   */
  void VMatrix4::LoadInverse4x3()
  {
    VMatrix4 inverse{};
    (void)gpg::gal::Math::invert(&inverse, this);
    *this = inverse;
  }

  /**
   * Address: 0x004EEC70 (FUN_004EEC70, ?LoadInverseRigid@VMatrix4@Moho@@QAEXXZ)
   *
   * What it does:
   * Replaces this matrix with the inverse lane used by rigid-transform paths.
   */
  void VMatrix4::LoadInverseRigid()
  {
    VMatrix4 inverse{};
    (void)gpg::gal::Math::invert(&inverse, this);
    *this = inverse;
  }

  /**
   * Address: 0x004EECA0 (FUN_004EECA0, ?LoadTranslate@VMatrix4@Moho@@QAEXMMM@Z)
   *
   * What it does:
   * Overwrites this matrix with one translation matrix.
   */
  void VMatrix4::LoadTranslate(const float x, const float y, const float z)
  {
    (void)gpg::gal::Math::translation(this, x, y, z);
  }

  /**
   * Address: 0x004EECD0 (FUN_004EECD0, ?LoadScale@VMatrix4@Moho@@QAEXMMM@Z)
   *
   * What it does:
   * Overwrites this matrix with one non-uniform scale matrix.
   */
  void VMatrix4::LoadScale(const float x, const float y, const float z)
  {
    (void)gpg::gal::Math::scaling(this, x, y, z);
  }

  /**
   * Address: 0x004EED60 (FUN_004EED60, ?LoadRotate@VMatrix4@Moho@@QAEXABV?$Vector3@M@Wm3@@M@Z)
   *
   * What it does:
   * Overwrites this matrix with one axis-angle rotation matrix.
   */
  void VMatrix4::LoadRotate(const Wm3::Vector3f& axis, const float angleRadians)
  {
    // Preserve the binary's by-value axis staging before calling the D3DX lane.
    const Wm3::Vector3f axisCopy{axis.x, axis.y, axis.z};
    (void)gpg::gal::Math::rotationAxis(this, &axisCopy, angleRadians);
  }

  /**
   * Address: 0x004EEDA0 (FUN_004EEDA0, ?LoadRotate@VMatrix4@Moho@@QAEXABV?$Quaternion@M@Wm3@@@Z)
   *
   * What it does:
   * Overwrites this matrix with one quaternion rotation matrix.
   */
  void VMatrix4::LoadRotate(const Wm3::Quaternionf& rotation)
  {
    // Wm3 lane is `w,x,y,z`; D3DX lane expects contiguous `x,y,z,w`.
    Wm3::Quaternionf d3dRotation{};
    d3dRotation.w = rotation.x;
    d3dRotation.x = rotation.y;
    d3dRotation.y = rotation.z;
    d3dRotation.z = rotation.w;
    (void)gpg::gal::Math::rotationQuaternion(this, &d3dRotation);
  }

  /**
   * Address: 0x00BEE670 (FUN_00BEE670, ??1math_GlobalRandomStream@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for the global random stream singleton.
   */
  void cleanup_math_GlobalRandomStream()
  {
    if (!gMathGlobalRandomStreamConstructed) {
      return;
    }

    math_GlobalRandomStream.~CRandomStream();
    gMathGlobalRandomStreamConstructed = false;
  }

  /**
   * Address: 0x00BC32A0 (FUN_00BC32A0, register_math_GlobalRandomStream)
   *
   * What it does:
   * Seeds the process-global random stream with `GetTickCount() ^ _time64(0)`
   * entropy, clears cached gaussian-pair state, and registers process-exit
   * teardown.
   */
  void register_math_GlobalRandomStream()
  {
    if (!gMathGlobalRandomStreamConstructed) {
      ::new (static_cast<void*>(&math_GlobalRandomStream)) CRandomStream();
      gMathGlobalRandomStreamConstructed = true;
    }

    const std::uint32_t timeSeed = static_cast<std::uint32_t>(std::time(nullptr));
    const std::uint32_t tickSeed = static_cast<std::uint32_t>(::GetTickCount());
    math_GlobalRandomStream.twister.Seed(tickSeed ^ timeSeed);
    math_GlobalRandomStream.hasMarsagliaPair = false;

    (void)std::atexit(&cleanup_math_GlobalRandomStream);
  }

  /**
   * Address: 0x00BEE680 (FUN_00BEE680, ??1math_GlobalRandomMutex@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for the global random-math mutex.
   */
  void cleanup_math_GlobalRandomMutex()
  {
    if (!gMathGlobalRandomMutexConstructed) {
      return;
    }

    math_GlobalRandomMutex.~mutex();
    gMathGlobalRandomMutexConstructed = false;
  }

  /**
   * Address: 0x00BC32E0 (FUN_00BC32E0, register_math_GlobalRandomMutex)
   *
   * What it does:
   * Constructs the process-global random-math mutex and registers process-exit
   * teardown.
   */
  void register_math_GlobalRandomMutex()
  {
    if (!gMathGlobalRandomMutexConstructed) {
      ::new (static_cast<void*>(&math_GlobalRandomMutex)) boost::mutex();
      gMathGlobalRandomMutexConstructed = true;
    }

    (void)std::atexit(&cleanup_math_GlobalRandomMutex);
  }

  /**
   * Address: 0x00BC6C40 (FUN_00BC6C40, register_AxisAlignedBox3fTypeInfo)
   */
  int register_AxisAlignedBox3fTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<AxisAlignedBox3fTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<AxisAlignedBox3fTypeInfo>);
  }

  /**
   * Address: 0x00BC6C60 (FUN_00BC6C60, register_AxisAlignedBox3fSerializer)
   */
  void register_AxisAlignedBox3fSerializer()
  {
    AxisAlignedBox3fSerializer& serializer = AccessSerializerStartupSlot<AxisAlignedBox3fSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&AxisAlignedBox3fSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&AxisAlignedBox3fSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<AxisAlignedBox3fSerializer>);
  }

  /**
   * Address: 0x00BC6CA0 (FUN_00BC6CA0, register_Vector2iTypeInfo)
   */
  int register_Vector2iTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<Vector2iTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<Vector2iTypeInfo>);
  }

  /**
   * Address: 0x00BC6CC0 (FUN_00BC6CC0, register_Vector2iSerializer)
   */
  void register_Vector2iSerializer()
  {
    Vector2iSerializer& serializer = AccessSerializerStartupSlot<Vector2iSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&Vector2iSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Vector2iSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<Vector2iSerializer>);
  }

  /**
   * Address: 0x00BC6D00 (FUN_00BC6D00, register_Vector3iTypeInfo)
   */
  int register_Vector3iTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<Vector3iTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<Vector3iTypeInfo>);
  }

  /**
   * Address: 0x00BC6D20 (FUN_00BC6D20, register_Vector3iSerializer)
   */
  void register_Vector3iSerializer()
  {
    Vector3iSerializer& serializer = AccessSerializerStartupSlot<Vector3iSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&Vector3iSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Vector3iSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<Vector3iSerializer>);
  }

  /**
   * Address: 0x00BC6D60 (FUN_00BC6D60, register_Vector2fTypeInfo)
   */
  int register_Vector2fTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<Vector2fTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<Vector2fTypeInfo>);
  }

  /**
   * Address: 0x00BC6D80 (FUN_00BC6D80, register_Vector2fSerializer)
   */
  void register_Vector2fSerializer()
  {
    Vector2fSerializer& serializer = AccessSerializerStartupSlot<Vector2fSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&Vector2fSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Vector2fSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<Vector2fSerializer>);
  }

  /**
   * Address: 0x00BC6DC0 (FUN_00BC6DC0, register_Vector3fTypeInfo)
   */
  int register_Vector3fTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<Vector3fTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<Vector3fTypeInfo>);
  }

  /**
   * Address: 0x00BC6DE0 (FUN_00BC6DE0, register_Vector3fSerializer)
   */
  void register_Vector3fSerializer()
  {
    Vector3fSerializer& serializer = AccessSerializerStartupSlot<Vector3fSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&Vector3fSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Vector3fSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<Vector3fSerializer>);
  }

  /**
   * Address: 0x00BC6E20 (FUN_00BC6E20, register_Vector4fTypeInfo)
   */
  int register_Vector4fTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<Vector4fTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<Vector4fTypeInfo>);
  }

  /**
   * Address: 0x00BC6E40 (FUN_00BC6E40, register_Vector4fSerializer)
   */
  void register_Vector4fSerializer()
  {
    Vector4fSerializer& serializer = AccessSerializerStartupSlot<Vector4fSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&Vector4fSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Vector4fSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<Vector4fSerializer>);
  }

  /**
   * Address: 0x00BC6E80 (FUN_00BC6E80, register_QuaternionfTypeInfo)
   */
  int register_QuaternionfTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<QuaternionfTypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<QuaternionfTypeInfo>);
  }

  /**
   * Address: 0x00BC6EA0 (FUN_00BC6EA0, register_QuaternionfSerializer)
   */
  void register_QuaternionfSerializer()
  {
    QuaternionfSerializer& serializer = AccessSerializerStartupSlot<QuaternionfSerializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&QuaternionfSerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&QuaternionfSerializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<QuaternionfSerializer>);
  }

  /**
   * Address: 0x00BC6EE0 (FUN_00BC6EE0, register_VEulers3TypeInfo)
   */
  int register_VEulers3TypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<VEulers3TypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<VEulers3TypeInfo>);
  }

  /**
   * Address: 0x00BC6F00 (FUN_00BC6F00, register_VEulers3Serializer)
   */
  void register_VEulers3Serializer()
  {
    VEulers3Serializer& serializer = AccessSerializerStartupSlot<VEulers3Serializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&VEulers3Serializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&VEulers3Serializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<VEulers3Serializer>);
  }

  /**
   * Address: 0x00BC6F40 (FUN_00BC6F40, register_VAxes3TypeInfo)
   */
  int register_VAxes3TypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<VAxes3TypeInfo>();
    return std::atexit(&CleanupTypeInfoAtExit<VAxes3TypeInfo>);
  }

  /**
   * Address: 0x00BC6F60 (FUN_00BC6F60, register_VAxes3Serializer)
   */
  int register_VAxes3Serializer()
  {
    VAxes3Serializer& serializer = AccessSerializerStartupSlot<VAxes3Serializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = &DeserializeVAxes3SerializerThunk;
    serializer.mSerialize = &SerializeVAxes3SerializerThunk;
    return std::atexit(&CleanupSerializerAtExit<VAxes3Serializer>);
  }

  /**
   * Address: 0x00BC7000 (FUN_00BC7000, register_VMatrix4NaN)
   */
  void register_VMatrix4NaN()
  {
    const float nanValue = std::numeric_limits<float>::quiet_NaN();
    for (int row = 0; row < 4; ++row) {
      float* const rowData = &VMatrix4::NaN.r[row].x;
      for (int col = 0; col < 4; ++col) {
        rowData[col] = nanValue;
      }
    }
  }

  /**
   * Address: 0x00BC7090 (FUN_00BC7090, register_VMatrix4TypeInfo)
   */
  void register_VMatrix4TypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<VMatrix4TypeInfo>();
    (void)std::atexit(&CleanupTypeInfoAtExit<VMatrix4TypeInfo>);
  }

  /**
   * Address: 0x00BC70B0 (FUN_00BC70B0, register_VMatrix4Serializer)
   */
  void register_VMatrix4Serializer()
  {
    VMatrix4Serializer& serializer = AccessSerializerStartupSlot<VMatrix4Serializer>();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&VMatrix4Serializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&VMatrix4Serializer::Serialize);
    (void)std::atexit(&CleanupSerializerAtExit<VMatrix4Serializer>);
  }
} // namespace moho

namespace
{
  struct MathReflectionBootstrap
  {
    MathReflectionBootstrap()
    {
      moho::register_math_GlobalRandomStream();
      moho::register_math_GlobalRandomMutex();
      (void)moho::register_AxisAlignedBox3fTypeInfo();
      moho::register_AxisAlignedBox3fSerializer();
      (void)moho::register_Vector2iTypeInfo();
      moho::register_Vector2iSerializer();
      (void)moho::register_Vector3iTypeInfo();
      moho::register_Vector3iSerializer();
      (void)moho::register_Vector2fTypeInfo();
      moho::register_Vector2fSerializer();
      (void)moho::register_Vector3fTypeInfo();
      moho::register_Vector3fSerializer();
      (void)moho::register_Vector4fTypeInfo();
      moho::register_Vector4fSerializer();
      (void)moho::register_QuaternionfTypeInfo();
      moho::register_QuaternionfSerializer();
      (void)moho::register_VEulers3TypeInfo();
      moho::register_VEulers3Serializer();
      (void)moho::register_VAxes3TypeInfo();
      (void)moho::register_VAxes3Serializer();
      moho::register_VMatrix4NaN();
      moho::register_VMatrix4TypeInfo();
      moho::register_VMatrix4Serializer();
    }
  };

  [[maybe_unused]] MathReflectionBootstrap gMathReflectionBootstrap;
} // namespace

extern "C" int global_mode_sse2 = 1;
extern "C" int global_compat_flag = 1;

/**
 * Address: 0x00A8ECD3 (FUN_00A8ECD3, func_SetSSE2)
 *
 * What it does:
 * Enables/disables the SSE2 runtime lane by masking with the startup
 * compatibility flag, then publishes and returns the resulting mode value.
 */
extern "C" int __cdecl RuntimeSetSse2Mode(const int enableSse2)
{
  const int mode = (enableSse2 != 0) ? global_compat_flag : 0;
  global_mode_sse2 = mode;
  return mode;
}

namespace
{
  [[nodiscard]] bool IsDefaultFloatingPointEnvironment() noexcept
  {
    const unsigned int mxcsr = _mm_getcsr() & 0x1F80u;
    if (mxcsr != 0x1F80u) {
      return false;
    }

    unsigned int controlWord = 0;
    return _controlfp_s(&controlWord, 0, 0) == 0 && (controlWord & 0x7Fu) == 0x7Fu;
  }

  [[nodiscard]] double CeilScalarCore(const double value) noexcept
  {
    if (std::isnan(value) || std::isinf(value) || value == 0.0) {
      return value;
    }

    const double truncated = std::trunc(value);
    if (truncated == value) {
      return value;
    }

    if (value < 0.0) {
      // Match CRT negative-subunit lane: ceil(-x) for 0 < x < 1 returns -0.0.
      return value > -1.0 ? -0.0 : truncated;
    }

    return truncated + 1.0;
  }
} // namespace

/**
 * Address: 0x00A8DCD0 (FUN_00A8DCD0, acos)
 *
 * What it does:
 * Preserves the CRT's SSE2/control-word dispatch gate and computes arccosine
 * for the supplied angle lane.
 */
extern "C" double __cdecl acos(double value)
{
  if (global_mode_sse2 != 0) {
    const unsigned int mxcsr = _mm_getcsr() & 0x1F80u;
    if (mxcsr == 0x1F80u) {
      unsigned int controlWord = 0;
      if (_controlfp_s(&controlWord, 0, 0) == 0 && (controlWord & 0x7Fu) == 0x7Fu) {
        return std::atan2(std::sqrt(1.0 - (value * value)), value);
      }
    }
  }

  return std::atan2(std::sqrt(1.0 - (value * value)), value);
}

/**
 * Address: 0x00A840A0 (FUN_00A840A0, ceil)
 *
 * What it does:
 * Preserves the CRT's SSE2/control-word dispatch gate and computes one
 * ceil-rounded scalar with legacy negative-zero behavior.
 */
extern "C" double __cdecl ceil(double value)
{
  if (global_mode_sse2 != 0 && IsDefaultFloatingPointEnvironment()) {
    return CeilScalarCore(value);
  }

  return CeilScalarCore(value);
}
