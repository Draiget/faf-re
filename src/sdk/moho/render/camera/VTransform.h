#pragma once

#include <cstddef>
#include <type_traits>

#include "wm3/Plane3.h"
#include "wm3/Quaternion.h"

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
  };

  static_assert(offsetof(VTransform, orient_) == 0x00, "VTransform::orient_ offset must be 0x00");
  static_assert(offsetof(VTransform, pos_) == 0x10, "VTransform::pos_ offset must be 0x10");
  static_assert(sizeof(VTransform) == 0x1C, "VTransform size must be 0x1C");

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
