// The pending-pipeline helpers of gpg/gal/PipelineDefer.h (ren_AsyncPipelines): a finished build leaves the pending
// list as soon as the list is full, not only when a draw asks for its key again, and a build that threw becomes a
// null pipeline instead of an exception in the draw that takes it.

#include <gtest/gtest.h>

#include <future>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "gpg/gal/PipelineDefer.h"

namespace
{
  using Pending = std::unordered_map<std::string, std::future<int>>;
  using Built = std::unordered_map<std::string, int>;

  std::future<int> Ready(
    const int value
  )
  {
    std::promise<int> promise;
    promise.set_value(value);
    return promise.get_future();
  }

  std::future<int> Threw()
  {
    std::promise<int> promise;
    promise.set_exception(std::make_exception_ptr(std::runtime_error("out of memory")));
    return promise.get_future();
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
