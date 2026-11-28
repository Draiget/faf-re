// The pending-pipeline helpers of gpg/gal/PipelineDefer.h (ren_AsyncPipelines): a finished build leaves the pending
// list as soon as the list is full, not only when a draw asks for its key again, and a build that threw becomes a
// null pipeline instead of an exception in the draw that takes it. A build's end says whether it may build later, and
// a pipeline refused for want of memory is tried six times in all, over 15.5 s, the last in place (PipelineRetries).

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include "gpg/gal/PipelineDefer.h"

namespace
{
  using Pending = std::unordered_map<std::string, std::future<int>>;
  using Built = std::unordered_map<std::string, int>;
  using gpg::gal::PipelineBuildEnd;
  using gpg::gal::PipelineRetries;
  using namespace std::chrono_literals;

  std::future<int> Ready(
    const int value
  )
  {
    std::promise<int> promise;
    promise.set_value(value);
    return promise.get_future();
  }

  template <class Error>
  std::future<int> Failed(
    const Error& error
  )
  {
    std::promise<int> promise;
    promise.set_exception(std::make_exception_ptr(error));
    return promise.get_future();
  }

  std::future<int> Threw()
  {
    return Failed(std::runtime_error("out of memory"));
  }
} // namespace

TEST(
  GalPipelineDefer,
  FinishedBuildsLeaveThePendingList
)
{
  std::promise<int> running;
  Pending pending;
  pending.emplace("done", Ready(7));
  pending.emplace("running", running.get_future());
  pending.emplace("threw", Threw());
  pending.emplace("taken", std::future<int>{}); // no shared state: dropped
  Built built;

  gpg::gal::CollectFinishedPipelines(pending, built);

  ASSERT_EQ(pending.size(), 1U);
  EXPECT_EQ(pending.count("running"), 1U);
  ASSERT_EQ(built.size(), 2U);
  EXPECT_EQ(built.at("done"), 7);
  EXPECT_EQ(built.at("threw"), 0); // kept as a failure
  running.set_value(1);
}

TEST(
  GalPipelineDefer,
  AFullListOfFinishedBuildsFreesEverySlot
)
{
  Pending pending;
  for (unsigned index = 0U; index < gpg::gal::kMaxPendingPipelines; ++index) {
    pending.emplace("key" + std::to_string(index), Ready(static_cast<int>(index) + 1));
  }
  Built built;

  gpg::gal::CollectFinishedPipelines(pending, built);

  EXPECT_TRUE(pending.empty());
  EXPECT_EQ(built.size(), gpg::gal::kMaxPendingPipelines);
}

TEST(
  GalPipelineDefer,
  ABuildThatThrewIsANullPipeline
)
{
  std::future<int> build = Threw();
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(build), 0);
}

TEST(
  GalPipelineDefer,
  ABuildsEndSaysWhetherItMayBuildLater
)
{
  PipelineBuildEnd end = PipelineBuildEnd::kRefused;
  std::future<int> built = Ready(3);
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(built, &end), 3);
  EXPECT_EQ(end, PipelineBuildEnd::kBuilt);

  std::future<int> forNow = Failed(gpg::gal::PipelineRefused{true});
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(forNow, &end), 0);
  EXPECT_EQ(end, PipelineBuildEnd::kRefusedForNow);

  std::future<int> noMemory = Failed(std::bad_alloc());
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(noMemory, &end), 0);
  EXPECT_EQ(end, PipelineBuildEnd::kRefusedForNow) << "the build itself ran out of memory";

  std::future<int> refused = Failed(gpg::gal::PipelineRefused{false});
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(refused, &end), 0);
  EXPECT_EQ(end, PipelineBuildEnd::kRefused);

  std::future<int> other = Threw();
  EXPECT_EQ(gpg::gal::TakeBuiltPipeline(other, &end), 0);
  EXPECT_EQ(end, PipelineBuildEnd::kRefused);
}

TEST(
  GalPipelineDefer,
  FinishedBuildsAreSettledWithHowTheyEnded
)
{
  std::promise<int> running;
  Pending pending;
  pending.emplace("done", Ready(7));
  pending.emplace("refused", Failed(gpg::gal::PipelineRefused{true}));
  pending.emplace("running", running.get_future());
  std::map<std::string, std::pair<int, PipelineBuildEnd>> settled;
  const auto settle = [&settled](const std::string& key, const int pipeline, const PipelineBuildEnd end) {
    settled.emplace(key, std::make_pair(pipeline, end));
  };

  gpg::gal::SettleFinishedPipelines(pending, settle);

  ASSERT_EQ(pending.size(), 1U);
  EXPECT_EQ(pending.count("running"), 1U);
  ASSERT_EQ(settled.size(), 2U);
  EXPECT_EQ(settled.at("done"), std::make_pair(7, PipelineBuildEnd::kBuilt));
  EXPECT_EQ(settled.at("refused"), std::make_pair(0, PipelineBuildEnd::kRefusedForNow));
  running.set_value(1);
}

TEST(
  GalPipelineDefer,
  ARefusalForWantOfMemoryIsTriedSixTimesInAllTheLastInPlace
)
{
  ASSERT_EQ(gpg::gal::kPipelineTries, 6U);
  PipelineRetries retries;
  const PipelineRetries::Clock::time_point start{};
  EXPECT_EQ(retries.TurnOf("p", start), PipelineRetries::Turn::kFirst);
  const std::chrono::milliseconds waits[] = {500ms, 1000ms, 2000ms, 4000ms, 8000ms};
  PipelineRetries::Clock::time_point now = start;
  for (unsigned refusals = 1U; refusals < gpg::gal::kPipelineTries; ++refusals) {
    ASSERT_TRUE(retries.Refused("p", now)) << "refusal " << refusals << " has another try after it";
    const std::chrono::milliseconds wait = waits[refusals - 1U];
    EXPECT_EQ(PipelineRetries::Spacing(refusals), wait);
    EXPECT_EQ(retries.TurnOf("p", now + wait - 1ns), PipelineRetries::Turn::kWaiting);
    now += wait;
    const unsigned next = refusals + 1U;
    const PipelineRetries::Turn due =
      (next < gpg::gal::kPipelineTries) ? PipelineRetries::Turn::kAgain : PipelineRetries::Turn::kLast;
    EXPECT_EQ(retries.TurnOf("p", now), due) << "try " << next;
  }
  EXPECT_EQ(now - start, 15500ms);
  EXPECT_FALSE(retries.Refused("p", now)) << "the last try's refusal is for good";
  EXPECT_EQ(retries.TurnOf("p", now), PipelineRetries::Turn::kFirst) << "and forgotten";

  ASSERT_TRUE(retries.Refused("q", now));
  retries.Forget("q"); // built at its next try
  EXPECT_EQ(retries.TurnOf("q", now), PipelineRetries::Turn::kFirst);
  ASSERT_TRUE(retries.Refused("r", now));
  retries.Clear(); // the device went
  EXPECT_EQ(retries.TurnOf("r", now), PipelineRetries::Turn::kFirst);
}
