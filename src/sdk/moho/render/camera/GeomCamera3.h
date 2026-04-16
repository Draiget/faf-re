#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/Matrix.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/math/VMatrix4.h"
#include "VTransform.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  struct GeomLine3;

  struct GeomCamera3
  {
    VTransform tranform;                    // +0x000
    gpg::gal::Matrix projection;            // +0x01C
    gpg::gal::Matrix view;                  // +0x05C
    gpg::gal::Matrix viewProjection;        // +0x09C
    gpg::gal::Matrix inverseProjection;     // +0x0DC
    gpg::gal::Matrix inverseView;           // +0x11C
    gpg::gal::Matrix inverseViewProjection; // +0x15C
    std::uint32_t solidFlags;               // +0x19C
    CGeomSolid3 solid1;                     // +0x1A0
    CGeomSolid3 solid2;                     // +0x210
    float lodScale;                         // +0x280
    VMatrix4 viewport;                      // +0x284
    std::uint32_t viewportFlags;            // +0x2C4

    /**
     * Address: 0x0046FE30 (FUN_0046FE30, Moho::GeomCamera3::GeomCamera3)
     *
     * What it does:
     * Initializes camera state to identity view/projection defaults and seeds
     * both frustum solids with six planes.
     */
    GeomCamera3();

    /**
     * Address: 0x00742970 (FUN_00742970, ??1GeomCamera3@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases frustum-plane heap buffers for both solids and rebinds each
     * lane to inline storage before member teardown.
     */
    ~GeomCamera3();

    /**
     * Address: 0x0046FFA0 (FUN_0046FFA0, Moho::GeomCamera3::GeomCamera3)
     *
     * Moho::VTransform const&, Moho::VMatrix4 const&
     *
     * What it does:
     * Initializes camera state and immediately derives view/projection frusta
     * from caller-provided transform and projection.
     */
    GeomCamera3(const VTransform& viewTransform, const gpg::gal::Matrix& projectionMatrix);

    /**
     * Address: 0x007421C0 (FUN_007421C0, func_CpyCamera)
     *
     * What it does:
     * Copies transform, projection/view matrices, frustum solids, LOD scale,
     * and viewport matrix lanes from `rhs` while preserving local flag lanes.
     */
    GeomCamera3& operator=(const GeomCamera3& rhs);

    /**
     * Address: 0x004700A0 (FUN_004700A0, Moho::GeomCamera3::Init)
     *
     * Moho::VTransform const&, Moho::VMatrix4 const&
     *
     * What it does:
     * Recomputes all derived camera matrices, clipping solids, and viewport
     * scaling coefficients.
     */
    void Init(const VTransform& viewTransform, const gpg::gal::Matrix& projectionMatrix);

    /**
     * Address: 0x00470B90 (FUN_00470B90, Moho::GeomCamera3::SetLODScale)
     *
     * float
     *
     * What it does:
     * Updates LOD scale and rebuilds viewport rows used for distance/LOD
     * conversions.
     */
    void SetLODScale(float value);

    /**
     * Address: 0x00470C70 (FUN_00470C70, Moho::GeomCamera3::Move)
     *
     * Moho::VTransform const&
     *
     * What it does:
     * Applies a new camera transform while preserving current projection.
     */
    void Move(const VTransform& viewTransform);

    /**
     * Address: 0x00470C80 (FUN_00470C80, Moho::GeomCamera3::SetProjection)
     *
     * Moho::VMatrix4 const&
     *
     * What it does:
     * Applies a new projection while preserving current camera transform.
     */
    void SetProjection(const gpg::gal::Matrix& projectionMatrix);

    /**
     * Address: 0x00470C90 (FUN_00470C90, Moho::GeomCamera3::Unproject)
     *
     * Wm3::Vector2<float> const&
     *
     * What it does:
     * Converts one screen-space point into a world-space ray using the
     * inverse view-projection matrix and current viewport bounds.
     */
    [[nodiscard]] GeomLine3 Unproject(const Wm3::Vector2f& screenPoint) const;

    /**
     * Address: 0x00470F60 (FUN_00470F60, Moho::GeomCamera3::Project)
     *
     * Wm3::Vector3<float> const&, float, float, float, float
     *
     * What it does:
     * Projects one world point through view-projection and maps NDC to the
     * caller-provided screen rectangle bounds.
     */
    [[nodiscard]]
    Wm3::Vector2f Project(
      const Wm3::Vector3f& worldPoint,
      float viewportX0,
      float viewportX1,
      float viewportY0,
      float viewportY1
    ) const;

    /**
     * Address: 0x00471080 (FUN_00471080, Moho::GeomCamera3::Project)
     *
     * Wm3::Vector3<float> const&
     *
     * What it does:
     * Projects one world point to current camera viewport coordinates.
     */
    [[nodiscard]] Wm3::Vector2f Project(const Wm3::Vector3f& worldPoint) const;

    /**
     * Address: 0x004711C0 (FUN_004711C0, Moho::GeomCamera3::Unproject)
     *
     * gpg::Rect2<float> const&
     *
     * What it does:
     * Converts one screen-space rectangle to a six-plane world-space frustum
     * solid used for culling/selection tests.
     */
    [[nodiscard]] CGeomSolid3 Unproject(const gpg::Rect2f& screenRect) const;

    /**
     * Address: 0x00471540 (FUN_00471540, Moho::GeomCamera3::LookAt)
     *
     * Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
     *
     * What it does:
     * Reorients camera transform to look from `eye` toward `target` using
     * `up` as roll reference, then rebuilds derived matrices/solids.
     */
    void LookAt(const Wm3::Vector3f& eye, const Wm3::Vector3f& target, const Wm3::Vector3f& up);

    /**
     * Address: 0x00471610 (FUN_00471610, Moho::GeomCamera3::ViewInitOrtho)
     *
     * int, int, float, float
     *
     * What it does:
     * Builds one orthographic projection matrix from integer viewport extents
     * and near/far depth planes, then reinitializes camera state.
     */
    void ViewInitOrtho(std::int32_t viewportHeight, std::int32_t viewportWidth, float nearDepth, float farDepth);

    /**
     * Address: 0x00471770 (FUN_00471770, Moho::GeomCamera3::ViewInitPerspective)
     *
     * float, float, float, float
     *
     * What it does:
     * Rebuilds perspective projection through the original fixed-constant lane
     * and reinitializes camera state.
     */
    void ViewInitPerspective(float fovXRadians, float fovYRadians, float nearDepth, float farDepth);
  };

  /**
   * Address: 0x00741850 (FUN_00741850, func_CpyGeomCameras)
   *
   * What it does:
   * Copies one half-open `GeomCamera3` range into destination storage using
   * `GeomCamera3::operator=` for each element and returns destination end.
   */
  [[nodiscard]] GeomCamera3* CopyGeomCameraRangeAndReturnEnd(
    const GeomCamera3* sourceBegin,
    GeomCamera3* destinationBegin,
    const GeomCamera3* sourceEnd
  );

  /**
   * Address: 0x004EFDD0 (FUN_004EFDD0, Moho::VEC_D3DProjectionMatrixFOV)
   *
   * What it does:
   * Builds one D3D-style perspective projection matrix from FOV, depth, and
   * aspect lanes and returns it by value.
   */
  [[nodiscard]]
  VMatrix4 VEC_D3DProjectionMatrixFOV(
    float fovXRadians,
    float fovYRadians,
    float nearDepth,
    float farDepth,
    float aspectRatio
  );

  /**
   * Address: 0x004EF6E0 (FUN_004EF6E0, ?VEC_LookAtMatrix@Moho@@YA?AUVMatrix4@1@ABV?$Vector3@M@Wm3@@00@Z)
   *
   * What it does:
   * Writes a right-handed view matrix built from `eye`/`target`/`up` vectors
   * into `dest` and returns `dest` for chaining callsites.
   */
  VMatrix4* VEC_LookAtMatrix(
    const Wm3::Vector3f& eye,
    const Wm3::Vector3f& target,
    VMatrix4* dest,
    const Wm3::Vector3f& up
  );

  /**
   * Address: 0x004EF930 (FUN_004EF930, ?VEC_LookAtViewMatrix@Moho@@YA?AUVMatrix4@1@ABV?$Vector3@M@Wm3@@00@Z)
   *
   * What it does:
   * Builds one camera view matrix from `eye`/`target`/`up` by transposing the
   * orientation rows from `VEC_LookAtMatrix` and composing translated row-3
   * lanes (`-dot(position, basisAxis)`).
   */
  VMatrix4* VEC_LookAtViewMatrix(
    const Wm3::Vector3f& eye,
    const Wm3::Vector3f& target,
    VMatrix4* dest,
    const Wm3::Vector3f& up
  );

  static_assert(offsetof(GeomCamera3, solid1) == 0x1A0, "GeomCamera3::solid1 offset must be 0x1A0");
  static_assert(offsetof(GeomCamera3, solid2) == 0x210, "GeomCamera3::solid2 offset must be 0x210");
  static_assert(offsetof(GeomCamera3, lodScale) == 0x280, "GeomCamera3::lodScale offset must be 0x280");
  static_assert(offsetof(GeomCamera3, viewport) == 0x284, "GeomCamera3::viewport offset must be 0x284");
  static_assert(sizeof(GeomCamera3) == 0x2C8, "GeomCamera3 size must be 0x2C8");
} // namespace moho
