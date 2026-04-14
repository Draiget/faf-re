#include "GeomCamera3.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "moho/sim/STIMap.h"

namespace
{
  constexpr std::uint32_t kFrustumPlaneCount = 6;
  constexpr float kDefaultLodScale = 1.0f;
  constexpr float kPerspectiveDefaultFovXRadians = 1.5707964f;
  constexpr float kPerspectiveDefaultFovYRadians = 1.5707964f;
  constexpr float kPerspectiveDefaultNearDepth = -10.0f;
  constexpr float kPerspectiveDefaultFarDepth = -10000.0f;
  constexpr float kPerspectiveDefaultAspect = 1.0f;

  const std::array<moho::Vector4f, kFrustumPlaneCount> kClipSpaceFrustumPlanes{
    moho::Vector4f{-1.0f, 0.0f, 0.0f, -1.0f},
    moho::Vector4f{1.0f, 0.0f, 0.0f, -1.0f},
    moho::Vector4f{0.0f, -1.0f, 0.0f, -1.0f},
    moho::Vector4f{0.0f, 1.0f, 0.0f, -1.0f},
    moho::Vector4f{0.0f, 0.0f, -1.0f, 0.0f},
    moho::Vector4f{0.0f, 0.0f, 1.0f, -1.0f},
  };

  [[nodiscard]] moho::Vector4f QuaternionToXyzw(const Wm3::Quatf& quaternion) noexcept
  {
    return {quaternion.x, quaternion.y, quaternion.z, quaternion.w};
  }

  [[nodiscard]] moho::VMatrix4 BuildMatrixFromTransform(const moho::VTransform& transform) noexcept
  {
    return moho::VMatrix4::FromQuatPos(
      QuaternionToXyzw(transform.orient_), transform.pos_.x, transform.pos_.y, transform.pos_.z
    );
  }

  [[nodiscard]] bool InvertMatrixGeneral(const moho::VMatrix4& matrix, moho::VMatrix4* const outInverse) noexcept
  {
    if (!outInverse) {
      return false;
    }

    float augmented[4][8]{
      {matrix.r[0].x, matrix.r[0].y, matrix.r[0].z, matrix.r[0].w, 1.0f, 0.0f, 0.0f, 0.0f},
      {matrix.r[1].x, matrix.r[1].y, matrix.r[1].z, matrix.r[1].w, 0.0f, 1.0f, 0.0f, 0.0f},
      {matrix.r[2].x, matrix.r[2].y, matrix.r[2].z, matrix.r[2].w, 0.0f, 0.0f, 1.0f, 0.0f},
      {matrix.r[3].x, matrix.r[3].y, matrix.r[3].z, matrix.r[3].w, 0.0f, 0.0f, 0.0f, 1.0f},
    };

    for (std::size_t pivotColumn = 0; pivotColumn < 4; ++pivotColumn) {
      std::size_t pivotRow = pivotColumn;
      float pivotMagnitude = std::fabs(augmented[pivotRow][pivotColumn]);
      for (std::size_t row = pivotColumn + 1; row < 4; ++row) {
        const float candidateMagnitude = std::fabs(augmented[row][pivotColumn]);
        if (candidateMagnitude > pivotMagnitude) {
          pivotMagnitude = candidateMagnitude;
          pivotRow = row;
        }
      }

      if (pivotMagnitude == 0.0f) {
        return false;
      }

      if (pivotRow != pivotColumn) {
        for (std::size_t column = 0; column < 8; ++column) {
          std::swap(augmented[pivotColumn][column], augmented[pivotRow][column]);
        }
      }

      const float pivotValue = augmented[pivotColumn][pivotColumn];
      const float reciprocalPivot = 1.0f / pivotValue;
      for (std::size_t column = 0; column < 8; ++column) {
        augmented[pivotColumn][column] *= reciprocalPivot;
      }

      for (std::size_t row = 0; row < 4; ++row) {
        if (row == pivotColumn) {
          continue;
        }

        const float factor = augmented[row][pivotColumn];
        if (factor == 0.0f) {
          continue;
        }

        for (std::size_t column = 0; column < 8; ++column) {
          augmented[row][column] -= factor * augmented[pivotColumn][column];
        }
      }
    }

    outInverse->r[0] = {
      augmented[0][4],
      augmented[0][5],
      augmented[0][6],
      augmented[0][7],
    };
    outInverse->r[1] = {
      augmented[1][4],
      augmented[1][5],
      augmented[1][6],
      augmented[1][7],
    };
    outInverse->r[2] = {
      augmented[2][4],
      augmented[2][5],
      augmented[2][6],
      augmented[2][7],
    };
    outInverse->r[3] = {
      augmented[3][4],
      augmented[3][5],
      augmented[3][6],
      augmented[3][7],
    };
    return true;
  }

  [[nodiscard]] Wm3::Plane3f BuildNormalizedPlane(const moho::Vector4f& clipPlane, const moho::VMatrix4& matrix) noexcept
  {
    const moho::Vector4f transformed = clipPlane * matrix;
    const float reciprocalLength =
      1.0f / std::sqrt((transformed.x * transformed.x) + (transformed.y * transformed.y) + (transformed.z * transformed.z));
    return {
      {transformed.x * reciprocalLength, transformed.y * reciprocalLength, transformed.z * reciprocalLength},
      -transformed.w * reciprocalLength,
    };
  }

  struct ProjectionPoint
  {
    float x{};
    float y{};
    float z{};
  };

  [[nodiscard]] ProjectionPoint
  ProjectFromInverseProjection(const moho::VMatrix4& inverseProjection, const float x, const float y, const float z) noexcept
  {
    const float reciprocalW = 1.0f
                            / ((inverseProjection.r[0].w * x) + (inverseProjection.r[1].w * y) +
                               (inverseProjection.r[2].w * z) + inverseProjection.r[3].w);
    return {
      ((inverseProjection.r[0].x * x) + (inverseProjection.r[1].x * y) + (inverseProjection.r[2].x * z) +
       inverseProjection.r[3].x) *
        reciprocalW,
      ((inverseProjection.r[0].y * x) + (inverseProjection.r[1].y * y) + (inverseProjection.r[2].y * z) +
       inverseProjection.r[3].y) *
        reciprocalW,
      ((inverseProjection.r[0].z * x) + (inverseProjection.r[1].z * y) + (inverseProjection.r[2].z * z) +
       inverseProjection.r[3].z) *
        reciprocalW,
    };
  }

  [[nodiscard]] ProjectionPoint
  ProjectFromMatrix(const moho::VMatrix4& matrix, const float x, const float y, const float z) noexcept
  {
    const float reciprocalW = 1.0f
                            / ((matrix.r[0].w * x) + (matrix.r[1].w * y) + (matrix.r[2].w * z) + matrix.r[3].w);
    return {
      ((matrix.r[0].x * x) + (matrix.r[1].x * y) + (matrix.r[2].x * z) + matrix.r[3].x) * reciprocalW,
      ((matrix.r[0].y * x) + (matrix.r[1].y * y) + (matrix.r[2].y * z) + matrix.r[3].y) * reciprocalW,
      ((matrix.r[0].z * x) + (matrix.r[1].z * y) + (matrix.r[2].z * z) + matrix.r[3].z) * reciprocalW,
    };
  }

  [[nodiscard]] float Distance3(const ProjectionPoint& lhs, const ProjectionPoint& rhs) noexcept
  {
    const float dx = lhs.x - rhs.x;
    const float dy = lhs.y - rhs.y;
    const float dz = lhs.z - rhs.z;
    return std::sqrt((dx * dx) + (dy * dy) + (dz * dz));
  }

  void InitializeFrustumStorage(moho::GeomCamera3* const camera)
  {
    const Wm3::Plane3f defaultPlane{};
    camera->solid1.ResizePlanes(kFrustumPlaneCount, defaultPlane);
    camera->solid2.ResizePlanes(kFrustumPlaneCount, defaultPlane);
  }

  [[nodiscard]] moho::VMatrix4 BuildLookAtMatrix(
    const Wm3::Vector3f& eye, const Wm3::Vector3f& target, const Wm3::Vector3f& up
  ) noexcept
  {
    Wm3::Vector3f forward{target.x - eye.x, target.y - eye.y, target.z - eye.z};
    if (Wm3::Vector3f::Normalize(&forward) == 0.0f) {
      forward = {0.0f, 0.0f, 1.0f};
    }

    Wm3::Vector3f right = Wm3::Vector3f::Cross(up, forward);
    if (Wm3::Vector3f::Normalize(&right) == 0.0f) {
      // Matches the binary fallback lane when up is collinear with forward.
      right.x = (forward.z * forward.z) - ((-0.0f - forward.x) * forward.y);
      right.y = ((-0.0f - forward.x) * forward.x) - (forward.y * forward.z);
      right.z = (forward.y * forward.y) - (forward.z * forward.x);
      Wm3::Vector3f::Normalize(&right);
    }

    const Wm3::Vector3f correctedUp = Wm3::Vector3f::Cross(forward, right);

    moho::VMatrix4 matrix{};
    matrix.r[0] = {right.x, right.y, right.z, 0.0f};
    matrix.r[1] = {correctedUp.x, correctedUp.y, correctedUp.z, 0.0f};
    matrix.r[2] = {forward.x, forward.y, forward.z, 0.0f};
    matrix.r[3] = {eye.x, eye.y, eye.z, 1.0f};
    return matrix;
  }

  [[nodiscard]] Wm3::Quatf
  QuaternionFromBasisColumns(const Wm3::Vector3f& right, const Wm3::Vector3f& up, const Wm3::Vector3f& forward) noexcept
  {
    const float m00 = right.x;
    const float m01 = up.x;
    const float m02 = forward.x;
    const float m10 = right.y;
    const float m11 = up.y;
    const float m12 = forward.y;
    const float m20 = right.z;
    const float m21 = up.z;
    const float m22 = forward.z;
    const float trace = m00 + m11 + m22;

    Wm3::Quatf out{};
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      out.w = 0.25f * s;
      out.x = (m21 - m12) / s;
      out.y = (m02 - m20) / s;
      out.z = (m10 - m01) / s;
    } else if (m00 > m11 && m00 > m22) {
      const float s = std::sqrt(1.0f + m00 - m11 - m22) * 2.0f;
      out.w = (m21 - m12) / s;
      out.x = 0.25f * s;
      out.y = (m01 + m10) / s;
      out.z = (m02 + m20) / s;
    } else if (m11 > m22) {
      const float s = std::sqrt(1.0f + m11 - m00 - m22) * 2.0f;
      out.w = (m02 - m20) / s;
      out.x = (m01 + m10) / s;
      out.y = 0.25f * s;
      out.z = (m12 + m21) / s;
    } else {
      const float s = std::sqrt(1.0f + m22 - m00 - m11) * 2.0f;
      out.w = (m10 - m01) / s;
      out.x = (m02 + m20) / s;
      out.y = (m12 + m21) / s;
      out.z = 0.25f * s;
    }

    out.Normalize();
    return out;
  }

  [[nodiscard]] moho::VMatrix4 BuildD3DProjectionMatrixFov(
    const float fovXRadians,
    const float fovYRadians,
    const float nearDepth,
    const float farDepth,
    const float aspectRatio
  ) noexcept
  {
    const float tanHalfFovX = std::tan(fovXRadians * 0.5f);
    const float tanHalfFovY = std::tan(fovYRadians * 0.5f);

    float halfWidth = tanHalfFovX;
    float halfHeight = tanHalfFovX / aspectRatio;
    if ((tanHalfFovY * aspectRatio) <= tanHalfFovX) {
      halfHeight = tanHalfFovY;
      halfWidth = aspectRatio * halfHeight;
    }

    const float left = -0.0f - halfWidth;
    const float right = halfWidth;
    const float bottom = -0.0f - halfHeight;
    const float top = halfHeight;

    const float reciprocalWidth = 1.0f / (right - left);
    const float reciprocalHeight = 1.0f / (top - bottom);

    moho::VMatrix4 projectionMatrix{};
    projectionMatrix.r[2].x = -0.0f - ((left + halfWidth) * reciprocalWidth);
    projectionMatrix.r[2].y = -0.0f - ((bottom + halfHeight) * reciprocalHeight);
    projectionMatrix.r[2].z = farDepth / (nearDepth - farDepth);
    projectionMatrix.r[2].w = -1.0f;

    projectionMatrix.r[0].x = reciprocalWidth * 2.0f;
    projectionMatrix.r[0].y = 0.0f;
    projectionMatrix.r[0].z = 0.0f;
    projectionMatrix.r[0].w = 0.0f;

    projectionMatrix.r[1].x = 0.0f;
    projectionMatrix.r[1].y = reciprocalHeight * 2.0f;
    projectionMatrix.r[1].z = 0.0f;
    projectionMatrix.r[1].w = 0.0f;

    projectionMatrix.r[3].x = 0.0f;
    projectionMatrix.r[3].y = 0.0f;
    projectionMatrix.r[3].z = (nearDepth * farDepth) / (farDepth - nearDepth);
    projectionMatrix.r[3].w = 0.0f;
    return projectionMatrix;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0046FE30 (FUN_0046FE30, Moho::GeomCamera3::GeomCamera3)
   *
   * What it does:
   * Initializes camera state to identity view/projection defaults and seeds
   * both frustum solids with six planes.
   */
  GeomCamera3::GeomCamera3()
    : solidFlags(0)
    , lodScale(1.0f)
    , viewportFlags(0)
  {
    tranform.orient_ = Wm3::Quatf::Identity();
    tranform.pos_ = {0.0f, 0.0f, 0.0f};
    viewport = VMatrix4::Identity();
    viewport.r[3] = {0.0f, 0.0f, 1.0f, 1.0f};

    InitializeFrustumStorage(this);
    const VTransform identityTransform{};
    Init(identityTransform, VMatrix4::Identity());
    SetLODScale(kDefaultLodScale);
  }

  /**
   * Address: 0x0046FFA0 (FUN_0046FFA0, Moho::GeomCamera3::GeomCamera3)
   *
   * Moho::VTransform const&, Moho::VMatrix4 const&
   *
   * What it does:
   * Initializes camera state and immediately derives view/projection frusta
   * from caller-provided transform and projection.
   */
  GeomCamera3::GeomCamera3(const VTransform& viewTransform, const gpg::gal::Matrix& projectionMatrix)
    : solidFlags(0)
    , lodScale(1.0f)
    , viewportFlags(0)
  {
    tranform.orient_ = Wm3::Quatf::Identity();
    tranform.pos_ = {0.0f, 0.0f, 0.0f};
    viewport = VMatrix4::Identity();
    viewport.r[3] = {0.0f, 0.0f, 1.0f, 1.0f};

    InitializeFrustumStorage(this);
    Init(viewTransform, projectionMatrix);
  }

  /**
   * Address: 0x007421C0 (FUN_007421C0, func_CpyCamera)
   *
   * What it does:
   * Copies transform, view/projection matrix lanes, frustum solids, LOD scale,
   * and viewport matrix lanes from `rhs`.
   */
  GeomCamera3& GeomCamera3::operator=(const GeomCamera3& rhs)
  {
    tranform.orient_.x = rhs.tranform.orient_.x;
    tranform.orient_.y = rhs.tranform.orient_.y;
    tranform.orient_.z = rhs.tranform.orient_.z;
    tranform.orient_.w = rhs.tranform.orient_.w;
    tranform.pos_ = rhs.tranform.pos_;

    projection = rhs.projection;
    view = rhs.view;
    viewProjection = rhs.viewProjection;
    inverseProjection = rhs.inverseProjection;
    inverseView = rhs.inverseView;
    inverseViewProjection = rhs.inverseViewProjection;

    solid1 = rhs.solid1;
    solid2 = rhs.solid2;

    lodScale = rhs.lodScale;
    viewport = rhs.viewport;
    return *this;
  }

  /**
   * Address: 0x00742970 (FUN_00742970, ??1GeomCamera3@Moho@@QAE@XZ)
   *
   * What it does:
   * Releases heap-backed frustum-plane lanes and restores both solids to inline
   * storage prior to member dtors.
   */
  GeomCamera3::~GeomCamera3()
  {
    solid2.planes_.ResetStorageToInline();
    solid1.planes_.ResetStorageToInline();
  }

  /**
   * Address: 0x004700A0 (FUN_004700A0, Moho::GeomCamera3::Init)
   *
   * Moho::VTransform const&, Moho::VMatrix4 const&
   *
   * What it does:
   * Recomputes all derived camera matrices, clipping solids, and viewport
   * scaling coefficients.
   */
  void GeomCamera3::Init(const VTransform& viewTransform, const gpg::gal::Matrix& projectionMatrix)
  {
    tranform = viewTransform;

    const VTransform inverseTransform = viewTransform.Inverse();
    view = BuildMatrixFromTransform(inverseTransform);
    projection = projectionMatrix;
    inverseView = BuildMatrixFromTransform(viewTransform);

    if (!InvertMatrixGeneral(projectionMatrix, &inverseProjection)) {
      inverseProjection = VMatrix4::Identity();
    }

    viewProjection = VMatrix4::Multiply(view, projection);
    inverseViewProjection = VMatrix4::Multiply(inverseProjection, inverseView);

    InitializeFrustumStorage(this);
    for (std::size_t planeIndex = 0; planeIndex < kFrustumPlaneCount; ++planeIndex) {
      const Vector4f& clipPlane = kClipSpaceFrustumPlanes[planeIndex];
      solid1.planes_[planeIndex] = BuildNormalizedPlane(clipPlane, projection);
      solid2.planes_[planeIndex] = BuildNormalizedPlane(clipPlane, viewProjection);
    }

    const ProjectionPoint leftNear = ProjectFromInverseProjection(inverseProjection, -1.0f, 0.0f, 0.0f);
    const ProjectionPoint rightNear = ProjectFromInverseProjection(inverseProjection, 1.0f, 0.0f, 0.0f);
    const ProjectionPoint leftFar = ProjectFromInverseProjection(inverseProjection, -1.0f, 0.0f, 1.0f);
    const ProjectionPoint rightFar = ProjectFromInverseProjection(inverseProjection, 1.0f, 0.0f, 1.0f);

    const float nearWidth = Distance3(leftNear, rightNear);
    const float farWidth = Distance3(leftFar, rightFar);
    const float widthSlope = (farWidth - nearWidth) / (leftFar.z - leftNear.z);
    const float widthIntercept = nearWidth - (leftNear.z * widthSlope);

    const Vector4f viewportRowSource{0.0f, 0.0f, widthSlope, widthIntercept};
    viewport.r[0] = viewportRowSource * view;

    const float reciprocalViewportDepth = 1.0f / viewport.r[3].z;
    viewport.r[2] = viewport.r[0];
    viewport.r[2] *= reciprocalViewportDepth;

    viewport.r[1] = viewport.r[0];
    viewport.r[1] *= lodScale;
  }

  /**
   * Address: 0x00470B90 (FUN_00470B90, Moho::GeomCamera3::SetLODScale)
   *
   * float
   *
   * What it does:
   * Updates LOD scale and rebuilds viewport rows used for distance/LOD
   * conversions.
   */
  void GeomCamera3::SetLODScale(const float value)
  {
    lodScale = value;

    const float reciprocalViewportDepth = 1.0f / viewport.r[3].z;
    viewport.r[2] = viewport.r[0];
    viewport.r[2] *= reciprocalViewportDepth;

    viewport.r[1] = viewport.r[0];
    viewport.r[1] *= lodScale;
  }

  /**
   * Address: 0x00470C70 (FUN_00470C70, Moho::GeomCamera3::Move)
   *
   * Moho::VTransform const&
   *
   * What it does:
   * Applies a new camera transform while preserving current projection.
   */
  void GeomCamera3::Move(const VTransform& viewTransform)
  {
    Init(viewTransform, projection);
  }

  /**
   * Address: 0x00470C80 (FUN_00470C80, Moho::GeomCamera3::SetProjection)
   *
   * Moho::VMatrix4 const&
   *
   * What it does:
   * Applies a new projection while preserving current camera transform.
   */
  void GeomCamera3::SetProjection(const gpg::gal::Matrix& projectionMatrix)
  {
    Init(tranform, projectionMatrix);
  }

  /**
   * Address: 0x00470C90 (FUN_00470C90, Moho::GeomCamera3::Unproject)
   *
   * Wm3::Vector2<float> const&
   *
   * What it does:
   * Converts one screen-space point into a world-space ray using the inverse
   * view-projection matrix and current viewport bounds.
   */
  GeomLine3 GeomCamera3::Unproject(const Wm3::Vector2f& screenPoint) const
  {
    const float viewportX0 = viewport.r[3].x;
    const float viewportX1 = viewport.r[3].x + viewport.r[3].z;
    const float viewportY0 = viewport.r[3].y + viewport.r[3].w;
    const float viewportY1 = viewport.r[3].y;

    const float ndcX = (((screenPoint.x - viewportX0) / (viewportX1 - viewportX0)) * 2.0f) - 1.0f;
    const float ndcY = (((screenPoint.y - viewportY0) / (viewportY1 - viewportY0)) * 2.0f) - 1.0f;

    const ProjectionPoint nearPoint = ProjectFromMatrix(inverseViewProjection, ndcX, ndcY, 0.0f);
    const ProjectionPoint farPoint = ProjectFromMatrix(inverseViewProjection, ndcX, ndcY, 1.0f);

    GeomLine3 line{};
    line.pos = {nearPoint.x, nearPoint.y, nearPoint.z};
    line.dir = {
      farPoint.x - nearPoint.x,
      farPoint.y - nearPoint.y,
      farPoint.z - nearPoint.z,
    };
    line.farthest = Wm3::Vector3f::Normalize(&line.dir);
    line.closest = 0.0f;
    return line;
  }

  /**
   * Address: 0x00470F60 (FUN_00470F60, Moho::GeomCamera3::Project)
   *
   * Wm3::Vector3<float> const&, float, float, float, float
   *
   * What it does:
   * Projects one world point through view-projection and maps NDC into the
   * caller-provided viewport bounds.
   */
  Wm3::Vector2f GeomCamera3::Project(
    const Wm3::Vector3f& worldPoint,
    const float viewportX0,
    const float viewportX1,
    const float viewportY0,
    const float viewportY1
  ) const
  {
    const float reciprocalW = 1.0f
                            / ((viewProjection.r[0].w * worldPoint.x) + (viewProjection.r[1].w * worldPoint.y) +
                               (viewProjection.r[2].w * worldPoint.z) + viewProjection.r[3].w);

    const float projectedX = ((viewProjection.r[0].x * worldPoint.x) + (viewProjection.r[1].x * worldPoint.y) +
                              (viewProjection.r[2].x * worldPoint.z) + viewProjection.r[3].x)
                           * reciprocalW;
    const float projectedY = ((viewProjection.r[0].y * worldPoint.x) + (viewProjection.r[1].y * worldPoint.y) +
                              (viewProjection.r[2].y * worldPoint.z) + viewProjection.r[3].y)
                           * reciprocalW;

    return {
      (((viewportX1 - viewportX0) * (projectedX - -1.0f)) * 0.5f) + viewportX0,
      (((viewportY1 - viewportY0) * (projectedY - -1.0f)) * 0.5f) + viewportY0,
    };
  }

  /**
   * Address: 0x00471080 (FUN_00471080, Moho::GeomCamera3::Project)
   *
   * Wm3::Vector3<float> const&
   *
   * What it does:
   * Projects one world point into current camera viewport coordinates.
   */
  Wm3::Vector2f GeomCamera3::Project(const Wm3::Vector3f& worldPoint) const
  {
    return Project(
      worldPoint,
      viewport.r[3].x,
      viewport.r[3].x + viewport.r[3].z,
      viewport.r[3].y + viewport.r[3].w,
      viewport.r[3].y
    );
  }

  /**
   * Address: 0x004711C0 (FUN_004711C0, Moho::GeomCamera3::Unproject)
   *
   * gpg::Rect2<float> const&
   *
   * What it does:
   * Converts one screen-space rectangle into a world-space frustum solid.
   */
  CGeomSolid3 GeomCamera3::Unproject(const gpg::Rect2f& screenRect) const
  {
    const float viewportX = viewport.r[3].x;
    const float viewportY = viewport.r[3].y;
    const float viewportWidth = viewport.r[3].z;
    const float viewportHeight = viewport.r[3].w;

    const float ndcX0 = (((screenRect.x0 - viewportX) / viewportWidth) * 2.0f) - 1.0f;
    const float ndcX1 = (((screenRect.x1 - viewportX) / viewportWidth) * 2.0f) - 1.0f;
    const float ndcY0 = (((screenRect.z0 - viewportY) / viewportHeight) * 2.0f) - 1.0f;
    const float ndcY1 = (((screenRect.z1 - viewportY) / viewportHeight) * 2.0f) - 1.0f;

    const std::array<Vector4f, kFrustumPlaneCount> clipRectFrustumPlanes{
      Vector4f{-1.0f, 0.0f, 0.0f, ndcX0},
      Vector4f{1.0f, 0.0f, 0.0f, -0.0f - ndcX1},
      Vector4f{0.0f, -1.0f, 0.0f, -0.0f - ndcY1},
      Vector4f{0.0f, 1.0f, 0.0f, ndcY0},
      Vector4f{0.0f, 0.0f, -1.0f, 0.0f},
      Vector4f{0.0f, 0.0f, 1.0f, -1.0f},
    };

    CGeomSolid3 solid;
    solid.ResizePlanes(kFrustumPlaneCount, Wm3::Plane3f{});
    for (std::size_t planeIndex = 0; planeIndex < kFrustumPlaneCount; ++planeIndex) {
      solid.planes_[planeIndex] = BuildNormalizedPlane(clipRectFrustumPlanes[planeIndex], viewProjection);
    }

    return solid;
  }

  /**
   * Address: 0x00471540 (FUN_00471540, Moho::GeomCamera3::LookAt)
   *
   * Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
   *
   * What it does:
   * Reorients the camera transform from eye/target/up and re-initializes all
   * derived camera state using current projection.
   */
  void GeomCamera3::LookAt(const Wm3::Vector3f& eye, const Wm3::Vector3f& target, const Wm3::Vector3f& up)
  {
    const VMatrix4 lookAtMatrix = BuildLookAtMatrix(eye, target, up);

    VTransform viewTransform{};
    viewTransform.orient_ = QuaternionFromBasisColumns(
      {lookAtMatrix.r[0].x, lookAtMatrix.r[0].y, lookAtMatrix.r[0].z},
      {lookAtMatrix.r[1].x, lookAtMatrix.r[1].y, lookAtMatrix.r[1].z},
      {lookAtMatrix.r[2].x, lookAtMatrix.r[2].y, lookAtMatrix.r[2].z}
    );
    viewTransform.pos_ = {lookAtMatrix.r[3].x, lookAtMatrix.r[3].y, lookAtMatrix.r[3].z};

    Init(viewTransform, projection);
  }

  /**
   * Address: 0x00471610 (FUN_00471610, Moho::GeomCamera3::ViewInitOrtho)
   *
   * int, int, float, float
   *
   * What it does:
   * Builds orthographic projection lanes and reinitializes camera state with
   * the current transform.
   */
  void GeomCamera3::ViewInitOrtho(
    const std::int32_t viewportHeight,
    const std::int32_t viewportWidth,
    const float nearDepth,
    const float farDepth
  )
  {
    const float left = static_cast<float>(-viewportWidth) * 0.5f;
    const float right = static_cast<float>(viewportWidth) * 0.5f;
    const float bottom = static_cast<float>(-viewportHeight) * 0.5f;
    const float top = static_cast<float>(viewportHeight) * 0.5f;

    VMatrix4 orthographicProjection{};
    orthographicProjection.r[0].x = 2.0f / (right - left);
    orthographicProjection.r[1].y = 2.0f / (top - bottom);
    orthographicProjection.r[2].z = 1.0f / ((-0.0f - farDepth) - (-0.0f - nearDepth));
    orthographicProjection.r[3].x = ((left + right) / (left - right)) - (1.0f / static_cast<float>(viewportWidth));
    orthographicProjection.r[3].y = ((bottom + top) / (bottom - top)) + (1.0f / static_cast<float>(viewportHeight));
    orthographicProjection.r[3].z = (-0.0f - nearDepth) / ((-0.0f - nearDepth) - (-0.0f - farDepth));
    orthographicProjection.r[3].w = 1.0f;

    Init(tranform, orthographicProjection);
  }

  /**
   * Address: 0x00471770 (FUN_00471770, Moho::GeomCamera3::ViewInitPerspective)
   *
   * float, float, float, float
   *
   * What it does:
   * Rebuilds perspective projection through the original fixed-constant lane
   * and reinitializes camera state.
   */
  void GeomCamera3::ViewInitPerspective(float fovXRadians, float fovYRadians, float nearDepth, float farDepth)
  {
    (void)fovXRadians;
    (void)fovYRadians;
    (void)nearDepth;
    (void)farDepth;

    const VMatrix4 perspectiveProjection = BuildD3DProjectionMatrixFov(
      kPerspectiveDefaultFovXRadians,
      kPerspectiveDefaultFovYRadians,
      kPerspectiveDefaultNearDepth,
      kPerspectiveDefaultFarDepth,
      kPerspectiveDefaultAspect
    );
    Init(tranform, perspectiveProjection);
  }
} // namespace moho
