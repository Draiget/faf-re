// gpg::gal::Math (gpg/gal/MatrixPortable.cpp), the D3DX matrix helpers without D3DX. The expected
// matrices are D3DX's documented layouts (D3DXMatrixRotationX/Y/Z, D3DXMatrixTranslation,
// D3DXMatrixScaling, D3DXMatrixRotationAxis, D3DXMatrixRotationQuaternion, D3DXMatrixMultiply,
// D3DXMatrixInverse): row vectors, `out = lhs * rhs`, translation in the fourth row. Where a
// result is a product of rounded values the comparison allows 1e-6.

#include <gtest/gtest.h>

#include <cmath>

#include "gpg/gal/Matrix.h"
#include "moho/math/Vector3f.h"

using gpg::gal::Matrix;
namespace math = gpg::gal::Math;

namespace
{
  constexpr float kTolerance = 1.0e-6f;

  float At(const Matrix& m, const int row, const int column)
  {
    const float* const lane = &m.r[row].x;
    return lane[column];
  }

  void ExpectMatrix(const Matrix& actual, const float (&expected)[16], const float tolerance = 0.0f)
  {
    for (int index = 0; index < 16; ++index) {
      if (tolerance == 0.0f) {
        EXPECT_EQ(At(actual, index / 4, index % 4), expected[index]) << "row " << index / 4 << " column " << index % 4;
      } else {
        EXPECT_NEAR(At(actual, index / 4, index % 4), expected[index], tolerance) << "row " << index / 4 << " column " << index % 4;
      }
    }
  }

  void ExpectSame(const Matrix& actual, const Matrix& expected, const float tolerance)
  {
    for (int index = 0; index < 16; ++index) {
      EXPECT_NEAR(At(actual, index / 4, index % 4), At(expected, index / 4, index % 4), tolerance)
        << "row " << index / 4 << " column " << index % 4;
    }
  }

  /** The row vector (x, y, z, 1) times `m`. */
  void Transform(const Matrix& m, const float x, const float y, const float z, float (&out)[4])
  {
    for (int column = 0; column < 4; ++column) {
      out[column] = x * At(m, 0, column) + y * At(m, 1, column) + z * At(m, 2, column) + At(m, 3, column);
    }
  }

  const float kIdentity[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
} // namespace

TEST(GalMath, TranslationAndScalingLayouts)
{
  Matrix m{};
  EXPECT_EQ(math::translation(&m, 1.0f, -2.0f, 3.5f), &m);
  ExpectMatrix(m, {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, -2, 3.5f, 1});
  EXPECT_EQ(math::scaling(&m, 2.0f, 3.0f, 0.5f), &m);
  ExpectMatrix(m, {2, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0.5f, 0, 0, 0, 0, 1});
}

TEST(GalMath, AxisRotationsMatchD3DX)
{
  const float angle = 0.3f;
  const float c = std::cos(angle);
  const float s = std::sin(angle);
  Matrix m{};
  math::rotationAxisX(&m, angle);
  ExpectMatrix(m, {1, 0, 0, 0, 0, c, s, 0, 0, -s, c, 0, 0, 0, 0, 1});
  math::rotationAxisY(&m, angle);
  ExpectMatrix(m, {c, 0, -s, 0, 0, 1, 0, 0, s, 0, c, 0, 0, 0, 0, 1});
  math::rotationAxisZ(&m, angle);
  ExpectMatrix(m, {c, s, 0, 0, -s, c, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1});

  // A quarter turn about z takes +x to +y (D3DX's left-handed rotation, looking toward the origin).
  math::rotationAxisZ(&m, 1.57079632679f);
  float point[4];
  Transform(m, 1.0f, 0.0f, 0.0f, point);
  EXPECT_NEAR(point[0], 0.0f, kTolerance);
  EXPECT_NEAR(point[1], 1.0f, kTolerance);
  EXPECT_NEAR(point[3], 1.0f, kTolerance);
}

TEST(GalMath, ArbitraryAxisAndQuaternionAgreeWithTheAxisRotations)
{
  const float angle = 1.1f;
  Matrix expected{};
  Matrix actual{};

  math::rotationAxisZ(&expected, angle);
  const Wm3::Vector3f longZ(0.0f, 0.0f, 2.0f); // not unit length: normalised first
  math::rotationAxis(&actual, &longZ, angle);
  ExpectSame(actual, expected, kTolerance);

  math::rotationAxisX(&expected, angle);
  const Wm3::Vector3f x(1.0f, 0.0f, 0.0f);
  math::rotationAxis(&actual, &x, angle);
  ExpectSame(actual, expected, kTolerance);

  math::rotationAxisY(&expected, -angle);
  const Wm3::Vector3f negativeY(0.0f, -3.0f, 0.0f);
  math::rotationAxis(&actual, &negativeY, angle);
  ExpectSame(actual, expected, kTolerance);

  // The quaternion's four floats in D3DX order x, y, z, w (Wm3's constructor stores its
  // arguments in that order of lanes): a rotation by `angle` about z.
  math::rotationAxisZ(&expected, angle);
  const Wm3::Quaternionf aboutZ(0.0f, 0.0f, std::sin(angle * 0.5f), std::cos(angle * 0.5f));
  math::rotationQuaternion(&actual, &aboutZ);
  ExpectSame(actual, expected, kTolerance);

  const Wm3::Quaternionf none(0.0f, 0.0f, 0.0f, 1.0f);
  math::rotationQuaternion(&actual, &none);
  ExpectMatrix(actual, kIdentity);
}

TEST(GalMath, ProductsTakeRowVectorsLeftToRight)
{
  Matrix translate{};
  Matrix scale{};
  Matrix product{};
  math::translation(&translate, 1.0f, 2.0f, 3.0f);
  math::scaling(&scale, 2.0f, 4.0f, 8.0f);

  // Translate, then scale: (p + t) * s.
  EXPECT_EQ(math::mul(&product, &translate, &scale), &product);
  ExpectMatrix(product, {2, 0, 0, 0, 0, 4, 0, 0, 0, 0, 8, 0, 2, 8, 24, 1});
  // Scale, then translate: p * s + t.
  math::mul(&product, &scale, &translate);
  ExpectMatrix(product, {2, 0, 0, 0, 0, 4, 0, 0, 0, 0, 8, 0, 1, 2, 3, 1});

  // The output may be an input.
  Matrix aliased = translate;
  math::mul(&aliased, &aliased, &scale);
  ExpectMatrix(aliased, {2, 0, 0, 0, 0, 4, 0, 0, 0, 0, 8, 0, 2, 8, 24, 1});

  Matrix identity{};
  math::scaling(&identity, 1.0f, 1.0f, 1.0f);
  math::mul(&product, &translate, &identity);
  ExpectSame(product, translate, 0.0f);
}

TEST(GalMath, InverseUndoesTheMatrix)
{
  Matrix m{};
  Matrix inverse{};
  math::translation(&m, 1.0f, -2.0f, 3.0f);
  EXPECT_EQ(math::invert(&inverse, &m), &inverse);
  ExpectMatrix(inverse, {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, -1, 2, -3, 1});

  math::scaling(&m, 2.0f, 4.0f, 8.0f);
  math::invert(&inverse, &m);
  ExpectMatrix(inverse, {0.5f, 0, 0, 0, 0, 0.25f, 0, 0, 0, 0, 0.125f, 0, 0, 0, 0, 1});

  // A general rigid transform with scale: M * inverse(M) is the identity.
  Matrix rotation{};
  Matrix translation{};
  Matrix scale{};
  Matrix temporary{};
  math::rotationAxisY(&rotation, 0.7f);
  math::translation(&translation, 5.0f, -1.0f, 2.5f);
  math::scaling(&scale, 1.5f, 0.5f, 2.0f);
  math::mul(&temporary, &scale, &rotation);
  math::mul(&m, &temporary, &translation);
  math::invert(&inverse, &m);
  Matrix product{};
  math::mul(&product, &m, &inverse);
  ExpectMatrix(product, kIdentity, 1.0e-5f);

  // In place.
  Matrix inPlace = m;
  math::invert(&inPlace, &inPlace);
  ExpectSame(inPlace, inverse, 0.0f);
}

TEST(GalMath, ASingularMatrixLeavesTheOutputAsItWas)
{
  Matrix singular{};
  math::scaling(&singular, 1.0f, 0.0f, 1.0f);
  Matrix output{};
  math::translation(&output, 7.0f, 8.0f, 9.0f);
  EXPECT_EQ(math::invert(&output, &singular), &output);
  ExpectMatrix(output, {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 7, 8, 9, 1});
}
