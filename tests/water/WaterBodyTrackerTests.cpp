// The body tracker of the water simulation (src/moho/terrain/water/HullDisplacement.h): a body that stays at the pose
// its bins were worked out from is only kept (Hold), one that moved goes through Update and emits the change. Pure C++.

#include <cstdio>
#include <vector>

#include "moho/terrain/water/HullDisplacement.h"

namespace
{
  int gFailed = 0;
  int gPassed = 0;

  void Check(
    const bool condition,
    const char* const what
  )
  {
    if (condition) {
      ++gPassed;
    } else {
      ++gFailed;
      std::printf("FAILED: %s\n", what);
    }
  }

  moho::water::BodyPose PoseAt(
    const float x,
    const void* const shape
  )
  {
    moho::water::BodyPose pose;
    pose.values[0] = x;
    pose.values[7] = pose.values[8] = pose.values[9] = 1.0f;
    pose.shape = shape;
    return pose;
  }
} // namespace

int main()
{
  using moho::water::BodyBin;
  using moho::water::BodyTracker;
  int shapeA = 0;
  int shapeB = 0;
  int body = 0;
  BodyTracker tracker;
  int emitted = 0;
  const auto emit = [&](const float, const float, const float) {
    ++emitted;
  };

  tracker.BeginFrame();
  Check(!tracker.Hold(&body, PoseAt(1.0f, &shapeA)), "a body never seen is not held");
  std::vector<BodyBin> bins = {{0, 0, 1.0f}, {1, 0, 2.0f}};
  tracker.Update(&body, bins, emit);
  tracker.Remember(&body, PoseAt(1.0f, &shapeA));
  Check(emitted == 0, "the first update of a body emits nothing");
  tracker.EndFrame();
  Check(tracker.Size() == 1, "the body is tracked");

  tracker.BeginFrame();
  Check(tracker.Hold(&body, PoseAt(1.0f, &shapeA)), "the same pose is held");
  tracker.EndFrame();
  Check(tracker.Size() == 1, "a held body is kept by EndFrame");

  tracker.BeginFrame();
  Check(!tracker.Hold(&body, PoseAt(1.5f, &shapeA)), "another position is not held");
  Check(!tracker.Hold(&body, PoseAt(1.0f, &shapeB)), "another shape is not held");
  bins = {{0, 0, 1.0f}, {1, 0, 3.0f}, {2, 0, 0.5f}};
  tracker.Update(&body, bins, emit);
  Check(emitted == 2, "the moved body emits the two bins that changed");
  Check(!tracker.Hold(&body, PoseAt(1.5f, &shapeA)), "after an Update the old pose does not hold until Remember");
  tracker.Remember(&body, PoseAt(1.5f, &shapeA));
  tracker.EndFrame();

  tracker.BeginFrame();
  Check(tracker.Hold(&body, PoseAt(1.5f, &shapeA)), "the new pose is held");
  tracker.EndFrame();

  tracker.BeginFrame();
  tracker.EndFrame();
  Check(tracker.Size() == 0, "a body that is neither held nor updated is forgotten");

  tracker.BeginFrame();
  Check(!tracker.Hold(&body, PoseAt(1.5f, &shapeA)), "a forgotten body is not held");
  std::printf("%d checks passed, %d failed\n", gPassed, gFailed);
  return gFailed == 0 ? 0 : 1;
}
