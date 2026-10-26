// Engine addition (dedicated-server plan WPR.12, WPL.5): gpg::gal::Math without D3DX, for
// the programs that link the simulation without the client (faf-replay, the game server,
// the Linux build). The client (faf_main) links gpg/gal/Matrix.cpp, the D3DX version.
//
// The matrices are D3DX's (row vectors, `out = lhs * rhs`; the same rotation, scaling and
// translation layouts); products are summed in index order and the inverse is the
// cofactor expansion. Their callers in the simulation's objects are the VMatrix4 helpers
// (MathReflection.cpp) and the effect emitters' bone attachment
// (CEfxEmitter::InterpolatePosition); neither feeds the simulation's checksummed state, so
// a last-bit difference from D3DX's SSE code changes no game result (the core replays
// check that).

#include "gpg/gal/Matrix.h"

#include <cmath>

namespace
{
  using gpg::gal::Matrix;

  void SetIdentity(Matrix& m) noexcept
  {
    m.r[0].x = 1.0f; m.r[0].y = 0.0f; m.r[0].z = 0.0f; m.r[0].w = 0.0f;
    m.r[1].x = 0.0f; m.r[1].y = 1.0f; m.r[1].z = 0.0f; m.r[1].w = 0.0f;
    m.r[2].x = 0.0f; m.r[2].y = 0.0f; m.r[2].z = 1.0f; m.r[2].w = 0.0f;
    m.r[3].x = 0.0f; m.r[3].y = 0.0f; m.r[3].z = 0.0f; m.r[3].w = 1.0f;
  }

  [[nodiscard]] float At(const Matrix& m, const int row, const int column) noexcept
  {
    const float* const lane = &m.r[row].x;
    return lane[column];
  }

  void Set(Matrix& m, const int row, const int column, const float value) noexcept
  {
    float* const lane = &m.r[row].x;
    lane[column] = value;
  }
} // namespace

namespace gpg::gal::Math
{
  Matrix* mul(Matrix* const outMatrix, const Matrix* const lhs, const Matrix* const rhs)
  {
    Matrix result{};
    for (int row = 0; row < 4; ++row) {
      for (int column = 0; column < 4; ++column) {
        float sum = At(*lhs, row, 0) * At(*rhs, 0, column);
        sum += At(*lhs, row, 1) * At(*rhs, 1, column);
        sum += At(*lhs, row, 2) * At(*rhs, 2, column);
        sum += At(*lhs, row, 3) * At(*rhs, 3, column);
        Set(result, row, column, sum);
      }
    }
    *outMatrix = result;
    return outMatrix;
  }

  Matrix* invert(Matrix* const outMatrix, const Matrix* const sourceMatrix)
  {
    float m[16];
    for (int i = 0; i < 16; ++i) {
      m[i] = At(*sourceMatrix, i / 4, i % 4);
    }

    float inv[16];
    inv[0] = m[5] * m[10] * m[15] - m[5] * m[11] * m[14] - m[9] * m[6] * m[15] + m[9] * m[7] * m[14] +
             m[13] * m[6] * m[11] - m[13] * m[7] * m[10];
    inv[4] = -m[4] * m[10] * m[15] + m[4] * m[11] * m[14] + m[8] * m[6] * m[15] - m[8] * m[7] * m[14] -
             m[12] * m[6] * m[11] + m[12] * m[7] * m[10];
    inv[8] = m[4] * m[9] * m[15] - m[4] * m[11] * m[13] - m[8] * m[5] * m[15] + m[8] * m[7] * m[13] +
             m[12] * m[5] * m[11] - m[12] * m[7] * m[9];
    inv[12] = -m[4] * m[9] * m[14] + m[4] * m[10] * m[13] + m[8] * m[5] * m[14] - m[8] * m[6] * m[13] -
              m[12] * m[5] * m[10] + m[12] * m[6] * m[9];
    inv[1] = -m[1] * m[10] * m[15] + m[1] * m[11] * m[14] + m[9] * m[2] * m[15] - m[9] * m[3] * m[14] -
             m[13] * m[2] * m[11] + m[13] * m[3] * m[10];
    inv[5] = m[0] * m[10] * m[15] - m[0] * m[11] * m[14] - m[8] * m[2] * m[15] + m[8] * m[3] * m[14] +
             m[12] * m[2] * m[11] - m[12] * m[3] * m[10];
    inv[9] = -m[0] * m[9] * m[15] + m[0] * m[11] * m[13] + m[8] * m[1] * m[15] - m[8] * m[3] * m[13] -
             m[12] * m[1] * m[11] + m[12] * m[3] * m[9];
    inv[13] = m[0] * m[9] * m[14] - m[0] * m[10] * m[13] - m[8] * m[1] * m[14] + m[8] * m[2] * m[13] +
              m[12] * m[1] * m[10] - m[12] * m[2] * m[9];
    inv[2] = m[1] * m[6] * m[15] - m[1] * m[7] * m[14] - m[5] * m[2] * m[15] + m[5] * m[3] * m[14] +
             m[13] * m[2] * m[7] - m[13] * m[3] * m[6];
    inv[6] = -m[0] * m[6] * m[15] + m[0] * m[7] * m[14] + m[4] * m[2] * m[15] - m[4] * m[3] * m[14] -
             m[12] * m[2] * m[7] + m[12] * m[3] * m[6];
    inv[10] = m[0] * m[5] * m[15] - m[0] * m[7] * m[13] - m[4] * m[1] * m[15] + m[4] * m[3] * m[13] +
              m[12] * m[1] * m[7] - m[12] * m[3] * m[5];
    inv[14] = -m[0] * m[5] * m[14] + m[0] * m[6] * m[13] + m[4] * m[1] * m[14] - m[4] * m[2] * m[13] -
              m[12] * m[1] * m[6] + m[12] * m[2] * m[5];
    inv[3] = -m[1] * m[6] * m[11] + m[1] * m[7] * m[10] + m[5] * m[2] * m[11] - m[5] * m[3] * m[10] -
             m[9] * m[2] * m[7] + m[9] * m[3] * m[6];
    inv[7] = m[0] * m[6] * m[11] - m[0] * m[7] * m[10] - m[4] * m[2] * m[11] + m[4] * m[3] * m[10] +
             m[8] * m[2] * m[7] - m[8] * m[3] * m[6];
    inv[11] = -m[0] * m[5] * m[11] + m[0] * m[7] * m[9] + m[4] * m[1] * m[11] - m[4] * m[3] * m[9] -
              m[8] * m[1] * m[7] + m[8] * m[3] * m[5];
    inv[15] = m[0] * m[5] * m[10] - m[0] * m[6] * m[9] - m[4] * m[1] * m[10] + m[4] * m[2] * m[9] +
              m[8] * m[1] * m[6] - m[8] * m[2] * m[5];

    const float determinant = m[0] * inv[0] + m[1] * inv[4] + m[2] * inv[8] + m[3] * inv[12];
    if (determinant == 0.0f) {
      // D3DXMatrixInverse returns null and leaves the output as it was.
      return outMatrix;
    }

    const float scale = 1.0f / determinant;
    for (int i = 0; i < 16; ++i) {
      Set(*outMatrix, i / 4, i % 4, inv[i] * scale);
    }
    return outMatrix;
  }

  Matrix* translation(Matrix* const outMatrix, const float x, const float y, const float z)
  {
    SetIdentity(*outMatrix);
    outMatrix->r[3].x = x;
    outMatrix->r[3].y = y;
    outMatrix->r[3].z = z;
    return outMatrix;
  }

  Matrix* scaling(Matrix* const outMatrix, const float x, const float y, const float z)
  {
    SetIdentity(*outMatrix);
    outMatrix->r[0].x = x;
    outMatrix->r[1].y = y;
    outMatrix->r[2].z = z;
    return outMatrix;
  }

  Matrix* rotationAxisX(Matrix* const outMatrix, const float angle)
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);
    SetIdentity(*outMatrix);
    outMatrix->r[1].y = c;
    outMatrix->r[1].z = s;
    outMatrix->r[2].y = -s;
    outMatrix->r[2].z = c;
    return outMatrix;
  }

  Matrix* rotationAxisY(Matrix* const outMatrix, const float angle)
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);
    SetIdentity(*outMatrix);
    outMatrix->r[0].x = c;
    outMatrix->r[0].z = -s;
    outMatrix->r[2].x = s;
    outMatrix->r[2].z = c;
    return outMatrix;
  }

  Matrix* rotationAxisZ(Matrix* const outMatrix, const float angle)
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);
    SetIdentity(*outMatrix);
    outMatrix->r[0].x = c;
    outMatrix->r[0].y = s;
    outMatrix->r[1].x = -s;
    outMatrix->r[1].y = c;
    return outMatrix;
  }

  Matrix* rotationAxis(Matrix* const outMatrix, const Wm3::Vector3f* const axis, const float angle)
  {
    float x = axis->x;
    float y = axis->y;
    float z = axis->z;
    const float length = std::sqrt(x * x + y * y + z * z);
    if (length != 0.0f) {
      x /= length;
      y /= length;
      z /= length;
    }
    const float c = std::cos(angle);
    const float s = std::sin(angle);
    const float t = 1.0f - c;

    SetIdentity(*outMatrix);
    outMatrix->r[0].x = t * x * x + c;
    outMatrix->r[0].y = t * x * y + s * z;
    outMatrix->r[0].z = t * x * z - s * y;
    outMatrix->r[1].x = t * x * y - s * z;
    outMatrix->r[1].y = t * y * y + c;
    outMatrix->r[1].z = t * y * z + s * x;
    outMatrix->r[2].x = t * x * z + s * y;
    outMatrix->r[2].y = t * y * z - s * x;
    outMatrix->r[2].z = t * z * z + c;
    return outMatrix;
  }

  Matrix* rotationQuaternion(Matrix* const outMatrix, const Wm3::Quaternionf* const rotation)
  {
    // The caller passes D3DX's lane order, x, y, z, w (VMatrix4::LoadRotate).
    const float* const q = reinterpret_cast<const float*>(rotation);
    const float x = q[0];
    const float y = q[1];
    const float z = q[2];
    const float w = q[3];

    SetIdentity(*outMatrix);
    outMatrix->r[0].x = 1.0f - 2.0f * (y * y + z * z);
    outMatrix->r[0].y = 2.0f * (x * y + z * w);
    outMatrix->r[0].z = 2.0f * (x * z - y * w);
    outMatrix->r[1].x = 2.0f * (x * y - z * w);
    outMatrix->r[1].y = 1.0f - 2.0f * (x * x + z * z);
    outMatrix->r[1].z = 2.0f * (y * z + x * w);
    outMatrix->r[2].x = 2.0f * (x * z + y * w);
    outMatrix->r[2].y = 2.0f * (y * z - x * w);
    outMatrix->r[2].z = 1.0f - 2.0f * (x * x + y * y);
    return outMatrix;
  }
} // namespace gpg::gal::Math
