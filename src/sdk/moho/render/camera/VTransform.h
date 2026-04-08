#pragma once

#include <cstddef>
#include <type_traits>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "wm3/Plane3.h"
#include "wm3/Quaternion.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class VTransform
  {
  public:
    Wm3::Quatf orient_; // 0x00 (w,x,y,z)
    Wm3::Vec3f pos_;    // 0x10

    VTransform() noexcept = default;

    /**
     * Address: 0x0046FB90 (FUN_0046FB90)
     *
     * Wm3::Vector3<float> const&, Wm3::Quaternion<float> const&
     *
     * What it does:
     * Initializes orientation and translation lanes in binary storage order.
     */
    VTransform(const Wm3::Vec3f& position, const Wm3::Quatf& orientation) noexcept;

    /**
     * Address: 0x0046FC90 (FUN_0046FC90)
     *
     * Moho::VTransform const&
     *
     * What it does:
     * Copy-constructs transform state (equivalent to plain struct copy).
     */
    VTransform(const VTransform& rhs) noexcept;

    /**
     * Address: 0x00470B60 (FUN_00470B60, Moho::VTransform::operator=)
     *
     * What it does:
     * Copies quaternion + translation lanes from rhs.
     */
    VTransform& operator=(const VTransform& rhs) noexcept;

    /**
     * Address: 0x0046FBF0 (FUN_0046FBF0)
     *
     * What it does:
     * Returns rigid-transform inverse using quaternion conjugate + rotated negated translation.
     */
    [[nodiscard]] VTransform Inverse() const noexcept;

    /**
     * Address: 0x00491200 (FUN_00491200, Moho::VTransform::Apply)
     *
     * Wm3::Vector3<float> const &,Wm3::Vector3<float> *
     *
     * What it does:
     * Rotates one input vector by orientation, adds translation, and writes
     * the transformed point to caller output.
     */
    Wm3::Vec3f* Apply(const Wm3::Vec3f& source, Wm3::Vec3f* outPoint) const noexcept;

    /**
     * Address: 0x00549C20 (FUN_00549C20)
     *
     * Moho::VTransform const&, Moho::VTransform const&
     *
     * What it does:
     * Composes transforms in the same order and quaternion algebra as FA binary.
     */
    [[nodiscard]] static VTransform Compose(const VTransform& lhs, const VTransform& rhs) noexcept;

    /**
     * Address: 0x004F0970 (FUN_004F0970, Moho::VTransform::MemberDeserialize)
     *
     * What it does:
     * Loads translation then orientation lanes from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004F09E0 (FUN_004F09E0, Moho::VTransform::MemberSerialize)
     *
     * What it does:
     * Stores translation then orientation lanes to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  /**
   * Address: 0x004ECEA0 (FUN_004ECEA0)
   *
   * What it does:
   * Formats one 3D vector lane as `x=...,y=...,z=...`.
   */
  [[nodiscard]] msvc8::string ToString(const Wm3::Vec3f& value);

  /**
   * Address: 0x004ECF10 (FUN_004ECF10)
   *
   * What it does:
   * Formats one quaternion in scalar/vector form (`v=(x,y,z),s=w`).
   */
  [[nodiscard]] msvc8::string ToString(const Wm3::Quatf& value);

  /**
   * Address: 0x004F04E0 (FUN_004F04E0)
   *
   * What it does:
   * Formats one transform as translation plus quaternion rotation text.
   */
  [[nodiscard]] msvc8::string ToString(const VTransform& value);

  static_assert(offsetof(VTransform, orient_) == 0x00, "VTransform::orient_ offset must be 0x00");
  static_assert(offsetof(VTransform, pos_) == 0x10, "VTransform::pos_ offset must be 0x10");
  static_assert(sizeof(VTransform) == 0x1C, "VTransform size must be 0x1C");

  /**
   * VFTABLE: 0x00E0BF6C
   * COL: 0x00E66A44
   */
  class VTransformTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004F0680 (FUN_004F0680, Moho::VTransformTypeInfo::dtr)
     */
    ~VTransformTypeInfo() override;

    /**
     * Address: 0x004F0670 (FUN_004F0670, Moho::VTransformTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004F0640 (FUN_004F0640, Moho::VTransformTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * VFTABLE: 0x00E0BF9C
   * COL: 0x00E66A94
   */
  class VTransformSerializer
  {
  public:
    /**
     * Address: 0x004F0740 (FUN_004F0740, Moho::VTransformSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load into `VTransform::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004F0760 (FUN_004F0760, Moho::VTransformSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save into `VTransform::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(sizeof(VTransformTypeInfo) == 0x64, "VTransformTypeInfo size must be 0x64");
  static_assert(offsetof(VTransformSerializer, mHelperNext) == 0x04, "VTransformSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(VTransformSerializer, mHelperPrev) == 0x08, "VTransformSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(VTransformSerializer, mDeserialize) == 0x0C, "VTransformSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(VTransformSerializer, mSerialize) == 0x10, "VTransformSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(VTransformSerializer) == 0x14, "VTransformSerializer size must be 0x14");

  /**
   * Address: 0x004F05E0 (FUN_004F05E0, preregister_VTransformTypeInfo)
   *
   * What it does:
   * Materializes/preregisters startup RTTI storage for `VTransform`.
   */
  [[nodiscard]] gpg::RType* preregister_VTransformTypeInfo();

  /**
   * Address: 0x00BC7150 (FUN_00BC7150, register_VTransformTypeInfo)
   *
   * What it does:
   * Runs `VTransform` type preregistration and installs process-exit cleanup.
   */
  int register_VTransformTypeInfo();

  /**
   * Address: 0x00BC7170 (FUN_00BC7170, register_VTransformSerializer)
   *
   * What it does:
   * Initializes startup serializer helper callbacks for `VTransform` and
   * installs process-exit unlink cleanup.
   */
  void register_VTransformSerializer();

  /**
   * Applies rigid transform `(R,p)` to plane `N*X = C`:
   * transformed plane is `N' = R*N`, `C' = C + Dot(N', p)`.
   */
  template <class T>
  Wm3::Plane3<T> ApplyTransform(const Wm3::Plane3<T>& plane, const VTransform& transform)
  {
    static_assert(std::is_floating_point_v<T>, "ApplyTransform requires floating-point T");

    const Wm3::Vec3f normalF{
      static_cast<float>(plane.Normal.x),
      static_cast<float>(plane.Normal.y),
      static_cast<float>(plane.Normal.z),
    };

    Wm3::Plane3<float> transformed{};
    const Wm3::Vec3f rotatedNormal = transform.orient_.Rotate(normalF);
    transformed.Normal = rotatedNormal;
    transformed.Constant = static_cast<float>(plane.Constant) + Wm3::Vec3f::Dot(rotatedNormal, transform.pos_);
    return Wm3::Plane3<T>::From(transformed);
  }
} // namespace moho
