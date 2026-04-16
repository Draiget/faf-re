#include "GeomCamera3.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

#include "legacy/containers/Vector.h"
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

  /**
   * Address: 0x00742BF0 (FUN_00742BF0, func_CpyCamera)
   *
   * What it does:
   * Copies full geometric camera state except local solid/viewport flag lanes.
   */
  [[nodiscard]] moho::GeomCamera3* CopyGeomCameraStatePreservingFlags(
    moho::GeomCamera3* const destination, const moho::GeomCamera3& source
  )
  {
    destination->tranform.orient_.x = source.tranform.orient_.x;
    destination->tranform.orient_.y = source.tranform.orient_.y;
    destination->tranform.orient_.z = source.tranform.orient_.z;
    destination->tranform.orient_.w = source.tranform.orient_.w;
    destination->tranform.pos_ = source.tranform.pos_;

    destination->projection = source.projection;
    destination->view = source.view;
    destination->viewProjection = source.viewProjection;
    destination->inverseProjection = source.inverseProjection;
    destination->inverseView = source.inverseView;
    destination->inverseViewProjection = source.inverseViewProjection;
    destination->solid1 = source.solid1;
    destination->solid2 = source.solid2;
    destination->lodScale = source.lodScale;
    destination->viewport = source.viewport;
    return destination;
  }

  /**
   * Address: 0x007425B0 (FUN_007425B0, sub_7425B0)
   *
   * What it does:
   * Copies one contiguous camera range `[sourceBegin, sourceEnd)` into
   * `destinationBegin` with per-element camera-state copy and rolls back
   * already-written destination elements on exception before rethrowing.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeAndReturnEnd(
    const moho::GeomCamera3* sourceBegin,
    const moho::GeomCamera3* const sourceEnd,
    moho::GeomCamera3* destinationBegin
  )
  {
    moho::GeomCamera3* destinationCursor = destinationBegin;
    try {
      while (sourceBegin != sourceEnd) {
        if (destinationCursor != nullptr) {
          (void)CopyGeomCameraStatePreservingFlags(destinationCursor, *sourceBegin);
        }
        ++destinationCursor;
        ++sourceBegin;
      }
    } catch (...) {
      for (moho::GeomCamera3* destroyCursor = destinationBegin; destroyCursor != destinationCursor; ++destroyCursor) {
        destroyCursor->~GeomCamera3();
      }
      throw;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x00741880 (FUN_00741880, sub_741880)
   *
   * What it does:
   * Adapter lane used by `std::vector_GeomCamera3::cpy` that forwards one
   * range-copy request into `CopyConstructGeomCameraRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeForVectorCopyAssign(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* const sourceEnd
  )
  {
    return CopyConstructGeomCameraRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007B1290 (FUN_007B1290, sub_7B1290)
   *
   * What it does:
   * Adapter lane used by vector insert/growth paths that forwards one
   * range-copy request into `CopyConstructGeomCameraRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeForVectorInsert(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* const sourceEnd
  )
  {
    return CopyConstructGeomCameraRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00741E40 (FUN_00741E40, sub_741E40)
   *
   * What it does:
   * Alternate ABI adapter lane forwarding GeomCamera range-copy requests into
   * `CopyConstructGeomCameraRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeAdapterAlternateA(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* const sourceEnd
  )
  {
    return CopyConstructGeomCameraRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007B1970 (FUN_007B1970, sub_7B1970)
   *
   * What it does:
   * Alternate ABI adapter lane forwarding GeomCamera range-copy requests into
   * `CopyConstructGeomCameraRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeAdapterAlternateB(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* const sourceEnd
  )
  {
    return CopyConstructGeomCameraRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007B1D20 (FUN_007B1D20, sub_7B1D20)
   *
   * What it does:
   * Alternate ABI adapter lane forwarding GeomCamera range-copy requests into
   * `CopyConstructGeomCameraRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyConstructGeomCameraRangeAdapterAlternateC(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* const sourceEnd
  )
  {
    return CopyConstructGeomCameraRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
  }

  [[nodiscard]] moho::GeomCamera3* CopyGeomCameraIfPresent(
    moho::GeomCamera3* const destination,
    const moho::GeomCamera3* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return CopyGeomCameraStatePreservingFlags(destination, *source);
  }

  /**
   * Address: 0x00742A20 (FUN_00742A20)
   *
   * What it does:
   * Primary adapter lane for nullable `GeomCamera3` state copy into
   * caller-provided destination storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyGeomCameraIfPresentPrimary(
    moho::GeomCamera3* const destination,
    const moho::GeomCamera3* const source
  )
  {
    return CopyGeomCameraIfPresent(destination, source);
  }

  /**
   * Address: 0x00742BA0 (FUN_00742BA0)
   *
   * What it does:
   * Secondary adapter lane for nullable `GeomCamera3` state copy into
   * caller-provided destination storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyGeomCameraIfPresentSecondary(
    moho::GeomCamera3* const destination,
    const moho::GeomCamera3* const source
  )
  {
    return CopyGeomCameraIfPresent(destination, source);
  }

  /**
   * Address: 0x007B12C0 (FUN_007B12C0)
   *
   * What it does:
   * Fills one destination camera range `[destinationBegin, destinationEnd)`
   * from one prototype camera and returns the last assigned destination lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* FillGeomCameraRangeFromPrototype(
    moho::GeomCamera3* destinationBegin,
    const moho::GeomCamera3& prototype,
    moho::GeomCamera3* const destinationEnd
  )
  {
    moho::GeomCamera3* lastAssigned = destinationBegin;
    while (destinationBegin != destinationEnd) {
      lastAssigned = CopyGeomCameraStatePreservingFlags(destinationBegin, prototype);
      ++destinationBegin;
    }
    return lastAssigned;
  }

  /**
   * Address: 0x007B12E0 (FUN_007B12E0)
   *
   * What it does:
   * Copies one camera range backward from `[sourceBegin, sourceEnd)` into the
   * destination tail ending at `destinationEnd` and returns destination begin.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyGeomCameraRangeBackward(
    const moho::GeomCamera3* const sourceBegin,
    const moho::GeomCamera3* sourceEnd,
    moho::GeomCamera3* destinationEnd
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      (void)CopyGeomCameraStatePreservingFlags(destinationEnd, *sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x007B19A0 (FUN_007B19A0)
   *
   * What it does:
   * Fills one destination camera range `[destinationBegin, destinationEnd)`
   * from one prototype camera and returns the last assigned destination lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* FillGeomCameraRangeFromPrototypeLaneA(
    moho::GeomCamera3* const destinationBegin,
    const moho::GeomCamera3* const sourceCamera,
    moho::GeomCamera3* const destinationEnd
  )
  {
    return FillGeomCameraRangeFromPrototype(destinationBegin, *sourceCamera, destinationEnd);
  }

  /**
   * Address: 0x007B19D0 (FUN_007B19D0)
   *
   * What it does:
   * Copies cameras backward from `sourceCursor` down to (but excluding)
   * `sourceStop` into destination storage and returns the resulting
   * destination cursor.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyGeomCameraRangeBackwardInclusiveLaneA(
    moho::GeomCamera3* sourceCursor,
    moho::GeomCamera3* destinationCursor,
    moho::GeomCamera3* const sourceStop
  )
  {
    while (sourceCursor != sourceStop) {
      (void)CopyGeomCameraStatePreservingFlags(destinationCursor, *sourceCursor);
      --sourceCursor;
      --destinationCursor;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x007B1D50 (FUN_007B1D50)
   *
   * What it does:
   * Copies one camera range backward from `[sourceBegin, sourceEnd)` into the
   * destination tail ending at `destinationEnd` and returns destination begin.
   */
  [[maybe_unused]] [[nodiscard]] moho::GeomCamera3* CopyGeomCameraRangeBackwardLaneA(
    moho::GeomCamera3* const destinationEnd,
    moho::GeomCamera3* const sourceEnd,
    const moho::GeomCamera3* const sourceBegin
  )
  {
    return CopyGeomCameraRangeBackward(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x007AEB10 (FUN_007AEB10, helper lane behind CAM_GetAllCameras)
   *
   * What it does:
   * Appends one `GeomCamera3` view to a legacy vector and returns the new end
   * cursor after any buffer growth has completed.
   */
  [[maybe_unused, nodiscard]] moho::GeomCamera3* AppendGeomCameraViewAndReturnEnd(
    msvc8::vector<moho::GeomCamera3>& cameras, const moho::GeomCamera3& camera
  )
  {
    cameras.push_back(camera);
    return cameras.empty() ? nullptr : &cameras[0] + cameras.size();
  }

  struct GeomCameraVectorCloneRuntimeView
  {
    std::uint32_t runtimeLane00 = 0;
    moho::GeomCamera3* first = nullptr; // +0x04
    moho::GeomCamera3* last = nullptr;  // +0x08
    moho::GeomCamera3* end = nullptr;   // +0x0C
  };
  static_assert(
    offsetof(GeomCameraVectorCloneRuntimeView, first) == 0x04,
    "GeomCameraVectorCloneRuntimeView::first offset must be 0x04"
  );
  static_assert(
    offsetof(GeomCameraVectorCloneRuntimeView, last) == 0x08,
    "GeomCameraVectorCloneRuntimeView::last offset must be 0x08"
  );
  static_assert(
    offsetof(GeomCameraVectorCloneRuntimeView, end) == 0x0C,
    "GeomCameraVectorCloneRuntimeView::end offset must be 0x0C"
  );

  /**
   * Address: 0x007AEA30 (FUN_007AEA30)
   *
   * What it does:
   * Clones one contiguous `GeomCamera3` storage span into `destination`,
   * allocating exact-sized backing storage and copy-constructing each camera.
   */
  [[maybe_unused]] GeomCameraVectorCloneRuntimeView* CloneGeomCameraVectorStorage(
    const GeomCameraVectorCloneRuntimeView* const source,
    GeomCameraVectorCloneRuntimeView* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    destination->first = nullptr;
    destination->last = nullptr;
    destination->end = nullptr;

    if (source == nullptr || source->first == nullptr || source->last == nullptr) {
      return destination;
    }

    const std::size_t count = static_cast<std::size_t>(source->last - source->first);
    if (count == 0u) {
      return destination;
    }

    constexpr std::size_t kMaxElementCount =
      static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max() / sizeof(moho::GeomCamera3));
    if (count > kMaxElementCount) {
      throw std::length_error("vector<T> too long");
    }

    auto* const storage = static_cast<moho::GeomCamera3*>(::operator new(sizeof(moho::GeomCamera3) * count));
    destination->first = storage;
    destination->last = storage;
    destination->end = storage + count;

    try {
      for (std::size_t index = 0; index < count; ++index) {
        new (storage + index) moho::GeomCamera3(source->first[index]);
        destination->last = storage + index + 1;
      }
    } catch (...) {
      while (destination->last != destination->first) {
        --destination->last;
        destination->last->~GeomCamera3();
      }
      ::operator delete(storage);
      destination->first = nullptr;
      destination->end = nullptr;
      throw;
    }

    return destination;
  }

  struct DwordVectorCloneRuntimeView
  {
    std::uint32_t runtimeLane00 = 0;
    std::uint32_t* first = nullptr; // +0x04
    std::uint32_t* last = nullptr;  // +0x08
    std::uint32_t* end = nullptr;   // +0x0C
  };
  static_assert(
    offsetof(DwordVectorCloneRuntimeView, first) == 0x04,
    "DwordVectorCloneRuntimeView::first offset must be 0x04"
  );
  static_assert(
    offsetof(DwordVectorCloneRuntimeView, last) == 0x08,
    "DwordVectorCloneRuntimeView::last offset must be 0x08"
  );
  static_assert(
    offsetof(DwordVectorCloneRuntimeView, end) == 0x0C,
    "DwordVectorCloneRuntimeView::end offset must be 0x0C"
  );

  /**
   * Address: 0x007AEBC0 (FUN_007AEBC0)
   *
   * What it does:
   * Clones one contiguous dword-vector storage span into `destination` with
   * checked element-count overflow semantics.
   */
  [[maybe_unused]] DwordVectorCloneRuntimeView* CloneDwordVectorStorage(
    const DwordVectorCloneRuntimeView* const source,
    DwordVectorCloneRuntimeView* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    destination->first = nullptr;
    destination->last = nullptr;
    destination->end = nullptr;

    if (source == nullptr || source->first == nullptr || source->last == nullptr) {
      return destination;
    }

    const std::size_t count = static_cast<std::size_t>(source->last - source->first);
    if (count == 0u) {
      return destination;
    }

    constexpr std::size_t kMaxElementCount = 0x3FFFFFFFu;
    if (count > kMaxElementCount) {
      throw std::length_error("vector<T> too long");
    }

    auto* const storage = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * count));
    destination->first = storage;
    destination->last = storage;
    destination->end = storage + count;

    const std::size_t byteCount = sizeof(std::uint32_t) * count;
    std::memcpy(storage, source->first, byteCount);
    destination->last = destination->end;
    return destination;
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
    (void)CopyGeomCameraStatePreservingFlags(this, rhs);
    return *this;
  }

  /**
   * Address: 0x00741850 (FUN_00741850, func_CpyGeomCameras)
   *
   * What it does:
   * Copies one half-open source camera range into destination storage by
   * calling `GeomCamera3::operator=` per element and returns destination end.
   */
  [[nodiscard]] GeomCamera3* CopyGeomCameraRangeAndReturnEnd(
    const GeomCamera3* sourceBegin,
    GeomCamera3* destinationBegin,
    const GeomCamera3* sourceEnd
  )
  {
    const GeomCamera3* source = sourceBegin;
    GeomCamera3* destination = destinationBegin;
    while (source != sourceEnd) {
      (void)CopyGeomCameraStatePreservingFlags(destination, *source);
      ++source;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x00741E10 (FUN_00741E10)
   *
   * What it does:
   * Register-shape adapter that copies one half-open camera range from
   * `[sourceBegin, sourceEnd)` into destination storage and returns the
   * destination end cursor.
   */
  [[maybe_unused]] [[nodiscard]] GeomCamera3* CopyGeomCameraRangeDestinationFirst(
    GeomCamera3* const destinationBegin,
    const GeomCamera3* const sourceBegin,
    const GeomCamera3* const sourceEnd
  )
  {
    return CopyGeomCameraRangeAndReturnEnd(sourceBegin, destinationBegin, sourceEnd);
  }

  /**
   * Address: 0x007406E0 (FUN_007406E0)
   *
   * What it does:
   * Destroys one contiguous `GeomCamera3` range `[begin, end)` by invoking the
   * camera destructor for each element in forward order.
   */
  [[maybe_unused]] void DestroyGeomCameraRange(
    GeomCamera3* begin,
    GeomCamera3* const end
  )
  {
    while (begin != end) {
      begin->~GeomCamera3();
      ++begin;
    }
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
   * Address: 0x004EFDD0 (FUN_004EFDD0, Moho::VEC_D3DProjectionMatrixFOV)
   *
   * What it does:
   * Builds one D3D-style perspective projection matrix from caller FOV/depth
   * lanes and returns it by value.
   */
  VMatrix4
  VEC_D3DProjectionMatrixFOV(
    const float fovXRadians,
    const float fovYRadians,
    const float nearDepth,
    const float farDepth,
    const float aspectRatio
  )
  {
    return BuildD3DProjectionMatrixFov(fovXRadians, fovYRadians, nearDepth, farDepth, aspectRatio);
  }

  /**
   * Address: 0x004EF6E0 (FUN_004EF6E0, ?VEC_LookAtMatrix@Moho@@YA?AUVMatrix4@1@ABV?$Vector3@M@Wm3@@00@Z)
   *
   * What it does:
   * Builds one right-handed view matrix from eye/target/up vectors with the
   * same forward-collinear fallback lane the binary uses, then writes the
   * result into `dest` and returns it for expression chaining.
   */
  VMatrix4* VEC_LookAtMatrix(
    const Wm3::Vector3f& eye,
    const Wm3::Vector3f& target,
    VMatrix4* const dest,
    const Wm3::Vector3f& up
  )
  {
    *dest = BuildLookAtMatrix(eye, target, up);
    return dest;
  }

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
    VMatrix4* const dest,
    const Wm3::Vector3f& up
  )
  {
    VMatrix4 lookAt{};
    const VMatrix4* const source = VEC_LookAtMatrix(eye, target, &lookAt, up);

    const float m00 = source->r[0].x;
    const float m01 = source->r[0].y;
    const float m02 = source->r[0].z;
    const float m10 = source->r[1].x;
    const float m11 = source->r[1].y;
    const float m12 = source->r[1].z;
    const float m20 = source->r[2].x;
    const float m21 = source->r[2].y;
    const float m22 = source->r[2].z;
    const float m30 = source->r[3].x;
    const float m31 = source->r[3].y;
    const float m32 = source->r[3].z;

    dest->r[0].x = m00;
    dest->r[0].y = m10;
    dest->r[0].z = m20;
    dest->r[0].w = 0.0f;

    dest->r[1].x = m01;
    dest->r[1].y = m11;
    dest->r[1].z = m21;
    dest->r[1].w = 0.0f;

    dest->r[2].x = m02;
    dest->r[2].y = m12;
    dest->r[2].z = m22;
    dest->r[2].w = 0.0f;

    dest->r[3].x = -((m32 * m02) + (m31 * m01) + (m30 * m00));
    dest->r[3].y = -((m32 * m12) + (m31 * m11) + (m30 * m10));
    dest->r[3].z = -((m32 * m22) + (m31 * m21) + (m30 * m20));
    dest->r[3].w = 1.0f;

    return dest;
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

    const VMatrix4 perspectiveProjection = VEC_D3DProjectionMatrixFOV(
      kPerspectiveDefaultFovXRadians,
      kPerspectiveDefaultFovYRadians,
      kPerspectiveDefaultNearDepth,
      kPerspectiveDefaultFarDepth,
      kPerspectiveDefaultAspect
    );
    Init(tranform, perspectiveProjection);
  }
} // namespace moho
