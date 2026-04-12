#include "VTransform.h"

#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/VMatrix4.h"
#include "Wm3Vector3.h"

namespace
{
  alignas(moho::VTransformTypeInfo) unsigned char gVTransformTypeInfoStorage[sizeof(moho::VTransformTypeInfo)];
  bool gVTransformTypeInfoConstructed = false;
  bool gVTransformTypeInfoPreregistered = false;

  alignas(moho::VTransformSerializer) unsigned char gVTransformSerializerStorage[sizeof(moho::VTransformSerializer)];
  bool gVTransformSerializerConstructed = false;

  gpg::RType* gCachedVector3fType = nullptr;
  gpg::RType* gCachedQuaternionfType = nullptr;

  [[nodiscard]] moho::VTransformTypeInfo& VTransformTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::VTransformTypeInfo*>(gVTransformTypeInfoStorage);
  }

  [[nodiscard]] moho::VTransformSerializer& VTransformSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::VTransformSerializer*>(gVTransformSerializerStorage);
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    if (gCachedVector3fType == nullptr) {
      gCachedVector3fType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return gCachedVector3fType;
  }

  [[nodiscard]] gpg::RType* ResolveQuaternionfType()
  {
    if (gCachedQuaternionfType == nullptr) {
      gCachedQuaternionfType = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }
    return gCachedQuaternionfType;
  }

  void AddRTypeField(gpg::RType& type, const char* const name, const std::type_info& fieldTypeInfo, const int offset)
  {
    type.fields_.push_back(gpg::RField{name, gpg::LookupRType(fieldTypeInfo), offset});
  }

  /**
   * Address: 0x004F08F0 (FUN_004F08F0, gpg::RType::AddField_Quaternionf_0x0r)
   *
   * What it does:
   * Adds the reflected `Quaternionf` field named `r` at offset `0x00`.
   */
  void AddQuaternionRotationField(gpg::RType& type)
  {
    GPG_ASSERT(!type.initFinished_);

    gpg::RType* quaternionType = ResolveQuaternionfType();

    gpg::RField field{};
    field.mName = "r";
    field.mType = quaternionType;
    type.fields_.push_back(field);
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

  void CleanupVTransformTypeInfoAtExit()
  {
    if (!gVTransformTypeInfoConstructed) {
      return;
    }

    VTransformTypeInfoStorageRef().~VTransformTypeInfo();
    gVTransformTypeInfoConstructed = false;
    gVTransformTypeInfoPreregistered = false;
    gCachedVector3fType = nullptr;
    gCachedQuaternionfType = nullptr;
  }

  void CleanupVTransformSerializerAtExit()
  {
    if (!gVTransformSerializerConstructed) {
      return;
    }

    moho::VTransformSerializer& serializer = VTransformSerializerStorageRef();
    UnlinkHelperNode(serializer);
    serializer.~VTransformSerializer();
    gVTransformSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0046FB90 (FUN_0046FB90)
   *
   * Wm3::Vector3<float> const&, Wm3::Quaternion<float> const&
   *
   * What it does:
   * Initializes orientation and translation lanes in binary storage order.
   */
  VTransform::VTransform(const Wm3::Vec3f& position, const Wm3::Quatf& orientation) noexcept
    : orient_(orientation)
    , pos_(position)
  {}

  /**
   * Address: 0x004F0440 (FUN_004F0440)
   * Mangled: ??0VTransform@Moho@@QAE@ABUVMatrix4@1@@Z
   *
   * Moho::VMatrix4 const&
   *
   * IDA signature:
   * int __usercall Moho::VTransform::VTransform@<eax>(int a1@<edi>, int esi0@<esi>);
   *
   * What it does:
   * Builds the upper-left 3x3 from the matrix's first three rows (stride 16),
   * runs the standard trace/max-diagonal quaternion decomposition, then copies
   * the translation lane (last row .xyz) verbatim into pos_.
   */
  VTransform::VTransform(const VMatrix4& matrix) noexcept
  {
    // Lift the 3x3 rotation block out of the row-major matrix.
    const float m[3][3] = {
      {matrix.r[0].x, matrix.r[0].y, matrix.r[0].z},
      {matrix.r[1].x, matrix.r[1].y, matrix.r[1].z},
      {matrix.r[2].x, matrix.r[2].y, matrix.r[2].z},
    };

    // Standard rotation-matrix to quaternion conversion.
    const float trace = m[0][0] + m[1][1] + m[2][2];
    if (trace > 0.0f) {
      const float root = std::sqrt(trace + 1.0f);
      const float invHalfRoot = 0.5f / root;
      orient_.w = root * 0.5f;
      orient_.x = (m[2][1] - m[1][2]) * invHalfRoot;
      orient_.y = (m[0][2] - m[2][0]) * invHalfRoot;
      orient_.z = (m[1][0] - m[0][1]) * invHalfRoot;
    } else {
      // Pick the largest diagonal element to avoid numeric loss.
      static constexpr int kNext[3] = {1, 2, 0};
      int i = 0;
      if (m[1][1] > m[0][0]) {
        i = 1;
      }
      if (m[2][2] > m[i][i]) {
        i = 2;
      }
      const int j = kNext[i];
      const int k = kNext[j];

      const float root = std::sqrt((m[i][i] - m[j][j] - m[k][k]) + 1.0f);
      const float invHalfRoot = 0.5f / root;

      float quat[3]{};
      quat[i] = root * 0.5f;
      orient_.w = (m[k][j] - m[j][k]) * invHalfRoot;
      quat[j] = (m[j][i] + m[i][j]) * invHalfRoot;
      quat[k] = (m[k][i] + m[i][k]) * invHalfRoot;
      orient_.x = quat[0];
      orient_.y = quat[1];
      orient_.z = quat[2];
    }

    pos_.x = matrix.r[3].x;
    pos_.y = matrix.r[3].y;
    pos_.z = matrix.r[3].z;
  }

  /**
   * Address: 0x0046FC90 (FUN_0046FC90)
   *
   * Moho::VTransform const&
   *
   * What it does:
   * Copy-constructs transform state (equivalent to plain struct copy).
   */
  VTransform::VTransform(const VTransform& rhs) noexcept = default;

  /**
   * Address: 0x00470B60 (FUN_00470B60, Moho::VTransform::operator=)
   *
   * What it does:
   * Copies quaternion + translation lanes from rhs.
   */
  VTransform& VTransform::operator=(const VTransform& rhs) noexcept
  {
    orient_ = rhs.orient_;
    pos_ = rhs.pos_;
    return *this;
  }

  /**
   * Address: 0x0046FBF0 (FUN_0046FBF0)
   *
   * What it does:
   * Returns rigid-transform inverse using quaternion conjugate + rotated negated translation.
   */
  VTransform VTransform::Inverse() const noexcept
  {
    VTransform inverted{};
    inverted.orient_.w = orient_.w;
    inverted.orient_.x = -orient_.x;
    inverted.orient_.y = -orient_.y;
    inverted.orient_.z = -orient_.z;

    const Wm3::Vec3f negatedPosition{
      -pos_.x,
      -pos_.y,
      -pos_.z,
    };
    Wm3::MultiplyQuaternionVector(&inverted.pos_, negatedPosition, inverted.orient_);
    return inverted;
  }

  /**
   * Address: 0x00491200 (FUN_00491200, Moho::VTransform::Apply)
   *
   * Wm3::Vector3<float> const &,Wm3::Vector3<float> *
   *
   * What it does:
   * Rotates one input vector by orientation, adds translation, and writes
   * the transformed point to caller output.
   */
  Wm3::Vec3f* VTransform::Apply(const Wm3::Vec3f& source, Wm3::Vec3f* const outPoint) const noexcept
  {
    if (outPoint == nullptr) {
      return nullptr;
    }

    Wm3::Vec3f rotated{};
    Wm3::MultiplyQuaternionVector(&rotated, source, orient_);
    outPoint->x = pos_.x + rotated.x;
    outPoint->y = pos_.y + rotated.y;
    outPoint->z = pos_.z + rotated.z;
    return outPoint;
  }

  /**
   * Address: 0x00549C20 (FUN_00549C20)
   *
   * Moho::VTransform const&, Moho::VTransform const&
   *
   * What it does:
   * Composes transforms in the same order and quaternion algebra as FA binary.
   */
  VTransform VTransform::Compose(const VTransform& lhs, const VTransform& rhs) noexcept
  {
    VTransform out{};

    const Wm3::Quatf& a = lhs.orient_;
    const Wm3::Quatf& b = rhs.orient_;
    out.orient_.w = (a.w * b.w) - (a.x * b.x) - (a.y * b.y) - (a.z * b.z);
    out.orient_.x = (a.z * b.y) + (b.x * a.w) + (a.x * b.w) - (b.z * a.y);
    out.orient_.y = (b.z * a.x) + (b.y * a.w) + (a.y * b.w) - (a.z * b.x);
    out.orient_.z = (a.y * b.x) + (b.z * a.w) + (a.z * b.w) - (b.y * a.x);

    Wm3::Vec3f rotatedPosition{};
    Wm3::MultiplyQuaternionVector(&rotatedPosition, lhs.pos_, rhs.orient_);
    out.pos_.x = rhs.pos_.x + rotatedPosition.x;
    out.pos_.y = rhs.pos_.y + rotatedPosition.y;
    out.pos_.z = rhs.pos_.z + rotatedPosition.z;
    return out;
  }

  /**
   * Address: 0x004ECEA0 (FUN_004ECEA0)
   *
   * What it does:
   * Formats one 3D vector lane as `x=...,y=...,z=...`.
   */
  msvc8::string ToString(const Wm3::Vec3f& value)
  {
    return gpg::STR_Printf("x=%f,y=%f,z=%f", value.x, value.y, value.z);
  }

  /**
   * Address: 0x004ECF10 (FUN_004ECF10)
   *
   * What it does:
   * Formats one quaternion in scalar/vector form (`v=(x,y,z),s=w`).
   */
  msvc8::string ToString(const Wm3::Quatf& value)
  {
    const Wm3::Vec3f vectorLane{value.x, value.y, value.z};
    const msvc8::string vectorText = ToString(vectorLane);
    return gpg::STR_Printf("v=(%s),s=%f", vectorText.c_str(), value.w);
  }

  /**
   * Address: 0x004F04E0 (FUN_004F04E0)
   *
   * What it does:
   * Formats one transform as translation plus quaternion rotation text.
   */
  msvc8::string ToString(const VTransform& value)
  {
    const msvc8::string rotationText = ToString(value.orient_);
    const msvc8::string translationText = ToString(value.pos_);
    return gpg::STR_Printf("t=%s, r={%s}", translationText.c_str(), rotationText.c_str());
  }

  /**
   * Address: 0x004F0680 (FUN_004F0680, Moho::VTransformTypeInfo::dtr)
   */
  VTransformTypeInfo::~VTransformTypeInfo() = default;

  /**
   * Address: 0x004F0670 (FUN_004F0670, Moho::VTransformTypeInfo::GetName)
   */
  const char* VTransformTypeInfo::GetName() const
  {
    return "VTransform";
  }

  /**
   * Address: 0x004F0640 (FUN_004F0640, Moho::VTransformTypeInfo::Init)
   */
  void VTransformTypeInfo::Init()
  {
    size_ = sizeof(VTransform);
    gpg::RType::Init();
    AddRTypeField(*this, "t", typeid(Wm3::Vector3f), offsetof(VTransform, pos_));
    AddQuaternionRotationField(*this);
    Finish();
  }

  /**
   * Address: 0x004F0970 (FUN_004F0970, Moho::VTransform::MemberDeserialize)
   */
  void VTransform::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    const gpg::RRef ownerRef{};
    archive->Read(ResolveVector3fType(), &pos_, ownerRef);
    archive->Read(ResolveQuaternionfType(), &orient_, ownerRef);
  }

  /**
   * Address: 0x004F09E0 (FUN_004F09E0, Moho::VTransform::MemberSerialize)
   */
  void VTransform::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    const gpg::RRef ownerRef{};
    archive->Write(ResolveVector3fType(), &pos_, ownerRef);
    archive->Write(ResolveQuaternionfType(), &orient_, ownerRef);
  }

  /**
   * Address: 0x004F0740 (FUN_004F0740, Moho::VTransformSerializer::Deserialize)
   */
  void VTransformSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    reinterpret_cast<VTransform*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004F0760 (FUN_004F0760, Moho::VTransformSerializer::Serialize)
   */
  void VTransformSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    reinterpret_cast<const VTransform*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
  }

  void VTransformSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = preregister_VTransformTypeInfo();
    if (type == nullptr) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x004F05E0 (FUN_004F05E0, preregister_VTransformTypeInfo)
   */
  gpg::RType* preregister_VTransformTypeInfo()
  {
    if (!gVTransformTypeInfoConstructed) {
      new (gVTransformTypeInfoStorage) VTransformTypeInfo();
      gVTransformTypeInfoConstructed = true;
    }

    if (!gVTransformTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(VTransform), &VTransformTypeInfoStorageRef());
      gVTransformTypeInfoPreregistered = true;
    }

    return &VTransformTypeInfoStorageRef();
  }

  /**
   * Address: 0x00BC7150 (FUN_00BC7150, register_VTransformTypeInfo)
   */
  int register_VTransformTypeInfo()
  {
    (void)preregister_VTransformTypeInfo();
    return std::atexit(&CleanupVTransformTypeInfoAtExit);
  }

  /**
   * Address: 0x00BC7170 (FUN_00BC7170, register_VTransformSerializer)
   */
  void register_VTransformSerializer()
  {
    if (!gVTransformSerializerConstructed) {
      new (gVTransformSerializerStorage) VTransformSerializer();
      gVTransformSerializerConstructed = true;
    }

    VTransformSerializer& serializer = VTransformSerializerStorageRef();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = &VTransformSerializer::Deserialize;
    serializer.mSerialize = &VTransformSerializer::Serialize;
    (void)std::atexit(&CleanupVTransformSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct VTransformBootstrap
  {
    VTransformBootstrap()
    {
      (void)moho::register_VTransformTypeInfo();
      moho::register_VTransformSerializer();
    }
  };

  [[maybe_unused]] VTransformBootstrap gVTransformBootstrap;
} // namespace
