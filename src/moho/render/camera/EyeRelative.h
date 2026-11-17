#pragma once

#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  /**
   * Engine addition: the camera's inverse view-projection without the camera's position. A
   * screen-space pass rebuilds a pixel's world point as `p = (ndc, depth, 1) * M`, then
   * `p.xyz / p.w + eye` (eye: `camera.inverseView.r[3]`).
   *
   * The full inverse view-projection holds the eye position scaled by 1/near: about 13,000 with
   * the camera at its closest zoom on a 1024 map (near is 1 % of the eye distance). A float32
   * multiply with it per pixel was off by about 0.003 world units, a third of a pixel's footprint
   * there. Screen-space ambient occlusion read that noise as tilted ground and drew dark streaks
   * that followed the depth rows. Without the translation the entries stay near 1/near and the
   * rebuilt point is accurate to about 0.00002 units. The product is formed in double.
   */
  [[nodiscard]] inline gpg::gal::Matrix EyeRelativeInverseViewProjection(
    const GeomCamera3& camera
  )
  {
    const auto at = [](const gpg::gal::Matrix& m, const int row, const int column) -> double {
      const auto& r = m.r[row];
      return column == 0 ? r.x : column == 1 ? r.y : column == 2 ? r.z : r.w;
    };
    double rotation[4][4];
    for (int row = 0; row < 3; ++row) {
      for (int column = 0; column < 4; ++column) {
        rotation[row][column] = at(camera.inverseView, row, column);
      }
    }
    rotation[3][0] = 0.0;
    rotation[3][1] = 0.0;
    rotation[3][2] = 0.0;
    rotation[3][3] = 1.0;

    gpg::gal::Matrix result = camera.inverseViewProjection;
    for (int row = 0; row < 4; ++row) {
      double sum[4] = {0.0, 0.0, 0.0, 0.0};
      for (int k = 0; k < 4; ++k) {
        const double left = at(camera.inverseProjection, row, k);
        for (int column = 0; column < 4; ++column) {
          sum[column] += left * rotation[k][column];
        }
      }
      result.r[row].x = static_cast<float>(sum[0]);
      result.r[row].y = static_cast<float>(sum[1]);
      result.r[row].z = static_cast<float>(sum[2]);
      result.r[row].w = static_cast<float>(sum[3]);
    }
    return result;
  }
} // namespace moho
