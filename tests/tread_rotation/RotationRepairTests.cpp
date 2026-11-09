// CTextureScroller::Tick on a real entity: in-place rotation advances motion-derived scroll by
// how far the tread contact points moved, and every no-motion case keeps the prior pair.
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <limits>

#include <gtest/gtest.h>

#include "moho/entity/CTextureScroller.h"
#include "moho/entity/Entity.h"

namespace
{
  using namespace moho;

  void Check(const bool ok, const char* const why)
  {
    EXPECT_TRUE(ok) << why;
  }

  struct Fixture
  {
    Entity entity{nullptr, 0u};
    CTextureScroller scroller{&entity};

    Fixture()
    {
      SScroller def;
      def.mType = SCROLLTYPE_MotionDerived;
      def.mFloat24 = 1;
      def.mFloat28 = 1;
      scroller.SetScroller(def);
    }

    auto& Data() { return entity.mVarDat; }

    void SetPriorPair()
    {
      Data().mScrollBeatStart = {3.0f, -4.0f};
      Data().mScrollBeatEnd = {3.25f, -4.5f};
    }

    void Yaw(const float half) { Data().mCurTransform.orient_ = {std::cos(half), 0, std::sin(half), 0}; }

    void CheckPriorPairKept(const char* const why)
    {
      Check(
        Data().mScrollBeatStart.x == 3.0f && Data().mScrollBeatStart.y == -4.0f && Data().mScrollBeatEnd.x == 3.25f &&
          Data().mScrollBeatEnd.y == -4.5f,
        why
      );
    }
  };

  // The expected value is quaternion-vector rotation in double precision, not a copy of the
  // scroller's scalar matrix and projection code.
  struct DVec
  {
    double x, y, z;
  };

  DVec Add(const DVec a, const DVec b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
  DVec Mul(const DVec a, const double k) { return {a.x * k, a.y * k, a.z * k}; }
  DVec Cross(const DVec a, const DVec b) { return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x}; }
  double Dot(const DVec a, const DVec b) { return a.x * b.x + a.y * b.y + a.z * b.z; }

  DVec Rotate(const Wm3::Quatf& q, const DVec v)
  {
    const DVec u{q.x, q.y, q.z};
    return Add(v, Add(Mul(Cross(u, v), 2.0 * q.w), Mul(Cross(u, Cross(u, v)), 2.0)));
  }

  double SideDelta(const Wm3::Quatf& last, const Wm3::Quatf& cur)
  {
    const DVec side = Add(Rotate(cur, {1, 0, 0}), Mul(Rotate(last, {1, 0, 0}), -1));
    const DVec forward = Mul(Add(Rotate(cur, {0, 0, 1}), Rotate(last, {0, 0, 1})), 0.5);
    return Dot(side, forward);
  }

  void CheckRepeatedAxis(const float ax, const float ay, const float az, const float scale)
  {
    Fixture f;
    f.scroller.mScroller.mFloat28 = scale;
    const float inverse = 1.0f / std::sqrt(ax * ax + ay * ay + az * az);
    for (unsigned i = 1; i <= 2048; ++i) {
      f.Data().mLastTransform = f.Data().mCurTransform;
      const float half = 0.0005f * static_cast<float>(i);
      const float sn = std::sin(half);
      f.Data().mCurTransform.orient_ = {std::cos(half), ax * inverse * sn, ay * inverse * sn, az * inverse * sn};
      const double expected = SideDelta(f.Data().mLastTransform.orient_, f.Data().mCurTransform.orient_) * scale;
      const auto before = f.Data().mScrollBeatEnd;
      f.scroller.Tick();
      Check(std::fabs((f.Data().mScrollBeatEnd.x - before.x) - expected) < 0.00001, "repeated axis left delta");
      Check(std::fabs((f.Data().mScrollBeatEnd.y - before.y) + expected) < 0.00001, "repeated axis right delta");
    }
  }

  void CheckYawInBothDirections()
  {
    for (const float yaw : {0.1f, -0.1f}) {
      Fixture f;
      f.Yaw(yaw);
      f.scroller.Tick();
      const float expected = std::sin(2 * yaw);
      Check(std::fabs(f.Data().mScrollBeatEnd.x + expected) < 0.00001f, "yaw left tread");
      Check(std::fabs(f.Data().mScrollBeatEnd.y - expected) < 0.00001f, "yaw right tread");
    }
  }

  void CheckNoMotionKeepsPriorPair()
  {
    {
      Fixture f;
      f.SetPriorPair();
      f.scroller.Tick();
      f.CheckPriorPairKept("stationary");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Data().mCurTransform.orient_ = {-1, 0, 0, 0};
      f.scroller.Tick();
      f.CheckPriorPairKept("equivalent quaternion sign");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Data().mCurTransform.orient_ = {1, -0.0f, -0.0f, -0.0f};
      f.scroller.Tick();
      f.CheckPriorPairKept("signed zero orientation");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Data().mCurTransform.orient_ = {std::cos(0.1f), 0, 0, std::sin(0.1f)};
      f.scroller.Tick();
      f.CheckPriorPairKept("roll has zero projection");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Yaw(0.1f);
      f.scroller.mScroller.mFloat24 = 0;
      f.scroller.Tick();
      f.CheckPriorPairKept("zero side offset");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Yaw(0.1f);
      f.scroller.mScroller.mFloat28 = 0;
      f.scroller.Tick();
      f.CheckPriorPairKept("zero multiplier");
    }
    {
      Fixture f;
      f.SetPriorPair();
      f.Data().mCurTransform.orient_.y = std::numeric_limits<float>::quiet_NaN();
      f.scroller.Tick();
      f.CheckPriorPairKept("invalid orientation");
    }
  }

  void CheckTranslationUnchanged()
  {
    for (const float sign : {1.0f, -1.0f}) {
      Fixture f;
      f.SetPriorPair();
      f.Data().mCurTransform.pos_.z = 0.125f * sign;
      f.scroller.Tick();
      Check(f.Data().mScrollBeatStart.x == 3.25f && f.Data().mScrollBeatEnd.x == 3.25f + 0.125f * sign, "translation");

      f.Data().mLastTransform = f.Data().mCurTransform;
      const auto start = f.Data().mScrollBeatStart;
      const auto end = f.Data().mScrollBeatEnd;
      f.scroller.Tick();
      Check(f.Data().mScrollBeatStart.x == start.x && f.Data().mScrollBeatEnd.x == end.x, "stop after translation");
    }
  }

  void CheckManualModeUntouched()
  {
    Fixture f;
    f.scroller.mScroller.mType = SCROLLTYPE_Manual;
    f.scroller.mScroller.mFloat04 = 0.25f;
    f.scroller.mScroller.mFloat08 = -0.5f;
    f.scroller.Tick();
    Check(f.Data().mScrollBeatEnd.x == 0.25f && f.Data().mScrollBeatEnd.y == -0.5f, "manual mode");
  }
} // namespace

TEST(Existing_RotationRepair, YawInBothDirections)
{
  CheckYawInBothDirections();
}

TEST(Existing_RotationRepair, NoMotionKeepsPriorPair)
{
  CheckNoMotionKeepsPriorPair();
}

TEST(Existing_RotationRepair, TranslationUnchanged)
{
  CheckTranslationUnchanged();
}

TEST(Existing_RotationRepair, ManualModeUntouched)
{
  CheckManualModeUntouched();
}

TEST(Existing_RotationRepair, RepeatedAxis)
{
  CheckRepeatedAxis(0, 1, 0, 1);       // yaw
  CheckRepeatedAxis(1, 0, 0, 1);       // pitch: zero projection
  CheckRepeatedAxis(0, 0, 1, 1);       // roll: zero projection
  CheckRepeatedAxis(1, 2, 3, 0.75f);   // tilted axis
  CheckRepeatedAxis(1, 2, 3, -0.75f);  // tilted axis, negative scale
}
