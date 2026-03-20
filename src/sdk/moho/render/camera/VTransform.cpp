#include "VTransform.h"

#include "wm3/Vector3.h"

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
   * Address: 0x0046FC90 (FUN_0046FC90)
   *
   * Moho::VTransform const&
   *
   * What it does:
   * Copy-constructs transform state (equivalent to plain struct copy).
   */
  VTransform::VTransform(const VTransform& rhs) noexcept = default;

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
} // namespace moho
