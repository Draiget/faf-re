#pragma once

#include "moho/math/VMatrix4.h"

namespace gpg::gal
{
	using Matrix = moho::VMatrix4;

  namespace Math
  {
    /**
     * Address: 0x00940690 (FUN_00940690, ?mul@Math@gal@gpg@@YAPBUMatrix@23@PAU423@PBU423@1@Z)
     *
     * What it does:
     * Multiplies two matrices through the D3DX matrix-multiply lane and
     * returns `outMatrix`.
     */
    Matrix* mul(Matrix* outMatrix, const Matrix* lhs, const Matrix* rhs);

    /**
     * Address: 0x009406B0 (FUN_009406B0, ?invert@Math@gal@gpg@@YAPBUMatrix@23@PAU423@PBU423@@Z)
     *
     * What it does:
     * Computes matrix inverse through D3DX inverse lane and returns
     * `outMatrix`.
     */
    Matrix* invert(Matrix* outMatrix, const Matrix* sourceMatrix);

    /**
     * Address: 0x00940770 (FUN_00940770, sub_940770)
     *
     * What it does:
     * Builds one translation matrix through the D3DX lane and returns
     * `outMatrix`.
     */
    Matrix* translation(Matrix* outMatrix, float x, float y, float z);

    /**
     * Address: 0x009407A0 (FUN_009407A0, sub_9407A0)
     *
     * What it does:
     * Builds one scale matrix through the D3DX lane and returns `outMatrix`.
     */
    Matrix* scaling(Matrix* outMatrix, float x, float y, float z);

    /**
     * Address: 0x009406D0 (FUN_009406D0, ?rotationAxisX@Math@gal@gpg@@YAPBUMatrix@23@PAU423@M@Z)
     *
     * What it does:
     * Builds an X-axis rotation matrix through the D3DX lane and returns
     * `outMatrix`.
     */
    Matrix* rotationAxisX(Matrix* outMatrix, float angle);

    /**
     * Address: 0x009406F0 (FUN_009406F0, ?rotationAxisY@Math@gal@gpg@@YAPBUMatrix@23@PAU423@M@Z)
     *
     * What it does:
     * Builds a Y-axis rotation matrix through the D3DX lane and returns
     * `outMatrix`.
     */
    Matrix* rotationAxisY(Matrix* outMatrix, float angle);

    /**
     * Address: 0x00940710 (FUN_00940710, ?rotationAxisZ@Math@gal@gpg@@YAPBUMatrix@23@PAU423@M@Z)
     *
     * What it does:
     * Builds a Z-axis rotation matrix through the D3DX lane and returns
     * `outMatrix`.
     */
    Matrix* rotationAxisZ(Matrix* outMatrix, float angle);

    /**
     * Address: 0x00940730 (FUN_00940730, ?rotationAxis@Math@gal@gpg@@YAPBUMatrix@23@PAU423@PBUVector3@23@M@Z)
     *
     * What it does:
     * Builds one axis-angle rotation matrix through the D3DX lane and
     * returns `outMatrix`.
     */
    Matrix* rotationAxis(Matrix* outMatrix, const Wm3::Vector3f* axis, float angle);

    /**
     * Address: 0x00940750 (FUN_00940750, ?rotationQuaternion@Math@gal@gpg@@YAPBUMatrix@23@PAU423@PBUQuaternion@23@@Z)
     *
     * What it does:
     * Builds one quaternion rotation matrix through the D3DX lane and
     * returns `outMatrix`.
     */
    Matrix* rotationQuaternion(Matrix* outMatrix, const Wm3::Quaternionf* rotation);
  } // namespace Math
}
