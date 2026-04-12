#include "moho/math/MathReflection.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <new>
#include <typeinfo>

#include <Windows.h>

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
} // namespace

boost::mutex& moho::math_GlobalRandomMutex = *reinterpret_cast<boost::mutex*>(gMathGlobalRandomMutexStorage);
moho::CRandomStream& moho::math_GlobalRandomStream =
  *reinterpret_cast<moho::CRandomStream*>(gMathGlobalRandomStreamStorage);

namespace moho
{
  VMatrix4 VMatrix4::NaN{};

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
    AddFieldFloat("x", offsetof(Vector2f, x));
    AddFieldFloat("y", offsetof(Vector2f, y));
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
    AddFieldFloat("x", offsetof(Vector3f, x));
    AddFieldFloat("y", offsetof(Vector3f, y));
    AddFieldFloat("z", offsetof(Vector3f, z));
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
   * Address: 0x00BF16B0 (FUN_00BF16B0, cleanup_VAxes3Serializer)
   */
  VAxes3Serializer::~VAxes3Serializer() noexcept
  {
    UnlinkHelperNode(*this);
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
