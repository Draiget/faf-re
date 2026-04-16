#include "moho/ui/SelectionDragger.h"

#include <algorithm>
#include <limits>
#include <new>

#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CWldSession.h"

namespace
{
  class ISelectionDraggerRuntimeLane
  {
  public:
    ISelectionDraggerRuntimeLane() noexcept
      : mSelectionListHead(nullptr)
    {}

    virtual ~ISelectionDraggerRuntimeLane() = default;

  public:
    moho::SelectionDraggerLink* mSelectionListHead; // +0x04
  };
  static_assert(sizeof(ISelectionDraggerRuntimeLane) == 0x08, "ISelectionDraggerRuntimeLane size must be 0x08");
  static_assert(
    offsetof(ISelectionDraggerRuntimeLane, mSelectionListHead) == 0x04,
    "ISelectionDraggerRuntimeLane::mSelectionListHead offset must be 0x04"
  );

  /**
   * Address: 0x00864040 (FUN_00864040)
   *
   * What it does:
   * Constructs one selection-dragger interface base lane by clearing the
   * intrusive list-head pointer and installing the interface vtable.
   */
  [[maybe_unused]] ISelectionDraggerRuntimeLane* InitializeISelectionDraggerRuntimeLane(
    ISelectionDraggerRuntimeLane* const outLane
  ) noexcept
  {
    return ::new (outLane) ISelectionDraggerRuntimeLane();
  }

  [[nodiscard]] float InvalidSelectionScreenCoord() noexcept
  {
    static bool initialized = false;
    static float invalidCoord = 0.0f;
    if (!initialized) {
      initialized = true;
      invalidCoord = std::numeric_limits<float>::quiet_NaN();
    }
    return invalidCoord;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008637F0 (FUN_008637F0, ??0SelectionDragger@Moho@@...)
   *
   * What it does:
   * Initializes list/session/camera lanes, captures drag-start screen
   * coordinates from `CWldSession::CursorScreenPos`, and seeds the world
   * position from `CWldSession::CursorWorldPos` when available (otherwise
   * from the process-wide invalid vector singleton).
   */
  SelectionDragger::SelectionDragger(CameraImpl* const camera, CWldSession* const session)
    : mSelectionListHead(nullptr)
    , mSess(session)
    , mCam(camera)
    , mX0(0.0f)
    , mY0(0.0f)
    , mPos(Invalid<Wm3::Vector3f>())
  {
    if (session == nullptr) {
      return;
    }

    if (session->mCursorWorldState[0] != 0u) {
      mPos = session->CursorWorldPos;
    }

    mX0 = session->CursorScreenPos.x;
    mY0 = session->CursorScreenPos.y;
  }

  SelectionDragger::~SelectionDragger()
  {
    while (mSelectionListHead != nullptr) {
      SelectionDraggerLink* const next = mSelectionListHead->mNext;
      mSelectionListHead->mOwnerHead = nullptr;
      mSelectionListHead->mNext = nullptr;
      mSelectionListHead = next;
    }
  }

  /**
   * Address: 0x00864000 (FUN_00864000, Moho::SelectionDragger::dtr)
   *
   * What it does:
   * Runs dragger cleanup and conditionally frees this object when bit 0 of
   * `deleteFlags` is set.
   */
  SelectionDragger* SelectionDragger::DeleteWithFlag(const std::uint8_t deleteFlags) noexcept
  {
    this->~SelectionDragger();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }

  /**
   * Address: 0x00864CB0 (FUN_00864CB0, ??0SelectionDragger2D@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes 2D dragger endpoint lanes from the shared invalid-screen
   * sentinel and clears stretch activity state.
   */
  SelectionDragger2D::SelectionDragger2D(CameraImpl* const camera, CWldSession* const session)
    : SelectionDragger(camera, session)
    , mStretch(0)
    , pad_0025{0, 0, 0}
    , mX1(InvalidSelectionScreenCoord())
    , mY1(InvalidSelectionScreenCoord())
  {}

  /**
   * Address: 0x00864FC0 (FUN_00864FC0, Moho::SelectionDragger2D::Func5)
   *
   * What it does:
   * Canonicalizes drag endpoints into a min/max screen rectangle and
   * unprojects that rectangle into a world-space solid through the active
   * camera.
   */
  CGeomSolid3 SelectionDragger2D::BuildSelectionSolid() const
  {
    gpg::Rect2f screenRect{};
    screenRect.x0 = std::min(mX0, mX1);
    screenRect.x1 = std::max(mX0, mX1);
    screenRect.z0 = std::min(mY0, mY1);
    screenRect.z1 = std::max(mY0, mY1);
    return mCam->CameraGetView().Unproject(screenRect);
  }
} // namespace moho
