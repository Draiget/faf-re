#pragma once

#include "Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace Wm3
{
  template <class T> struct Sphere3
  {
    Vector3<T> Center{};
    T Radius{};

    constexpr Sphere3() = default;
    constexpr Sphere3(const Vector3<T>& center, const T radius) noexcept :
        Center(center),
        Radius(radius)
    {}

    /**
     * Address: 0x00474260 (FUN_00474260, Wm3::Sphere3f::MemberDeserialize)
     *
     * What it does:
     * Reads reflected center/radius fields from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004742B0 (FUN_004742B0, Wm3::Sphere3f::MemberSerialize)
     *
     * What it does:
     * Writes reflected center/radius fields to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  using Sphere3f = Sphere3<float>;

  static_assert(sizeof(Sphere3f) == 0x10, "Sphere3f size must be 0x10");
} // namespace Wm3
