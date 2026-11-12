// Engine addition (PR #396): RScmResource::GetSkeleton builds the skeleton on first use, and sim
// workers reach it through effect ticks (CEffectManagerImpl, GetBoneWorldTransform) while the sim
// thread does too. Several threads asking for one resource's skeleton at once must all get the
// same skeleton, built once. The model is made in memory: one bone, one vertex.

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/animation/CAniSkel.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"

namespace
{
  // File layout: header (0x40), bone name "root" at 0x40, one bone record (0x6C) at 0x50,
  // one vertex (0x44) at 0xBC, three 16-bit indices at 0x100.
  constexpr std::uint32_t kNameOffset = 0x40;
  constexpr std::uint32_t kBoneOffset = 0x50;
  constexpr std::uint32_t kBoneRecordBytes = 0x6C;
  constexpr std::uint32_t kVertexOffset = kBoneOffset + kBoneRecordBytes; // 0xBC
  constexpr std::uint32_t kIndexOffset = kVertexOffset + sizeof(moho::SScmVertex);
  constexpr std::uint32_t kFileBytes = kIndexOffset + 3 * sizeof(std::uint16_t);

  void PutU32(
    std::vector<std::uint8_t>& bytes,
    const std::size_t at,
    const std::uint32_t value
  )
  {
    std::memcpy(bytes.data() + at, &value, sizeof(value));
  }

  void PutF32(
    std::vector<std::uint8_t>& bytes,
    const std::size_t at,
    const float value
  )
  {
    std::memcpy(bytes.data() + at, &value, sizeof(value));
  }

  boost::shared_ptr<const moho::SScmFile> MakeOneBoneScm()
  {
    auto* const image = new std::vector<std::uint8_t>(kFileBytes, 0u);
    std::vector<std::uint8_t>& bytes = *image;
    PutU32(bytes, offsetof(moho::SScmFile, mBoneTableOffset), kBoneOffset);
    PutU32(bytes, offsetof(moho::SScmFile, mSkinBoneCount), 1u);
    PutU32(bytes, offsetof(moho::SScmFile, mVertexOffset), kVertexOffset);
    PutU32(bytes, offsetof(moho::SScmFile, mVertexCount), 1u);
    PutU32(bytes, offsetof(moho::SScmFile, mIndexDataOffset), kIndexOffset);
    PutU32(bytes, offsetof(moho::SScmFile, mIndexCount), 3u);
    PutU32(bytes, offsetof(moho::SScmFile, mBoneTotalCount), 1u);
    std::memcpy(bytes.data() + kNameOffset, "root", 5);

    // Bone record: identity basis rows, identity local rotation (w first), no parent.
    PutF32(bytes, kBoneOffset + 0x00, 1.0f);
    PutF32(bytes, kBoneOffset + 0x14, 1.0f);
    PutF32(bytes, kBoneOffset + 0x28, 1.0f);
    PutF32(bytes, kBoneOffset + 0x4C, 1.0f);
    PutU32(bytes, kBoneOffset + 0x60, 0xFFFFFFFFu);

    // One vertex at (1, 2, 3) bound to bone 0.
    PutF32(bytes, kVertexOffset + 0x00, 1.0f);
    PutF32(bytes, kVertexOffset + 0x04, 2.0f);
    PutF32(bytes, kVertexOffset + 0x08, 3.0f);

    const auto* const file = reinterpret_cast<const moho::SScmFile*>(bytes.data());
    return boost::shared_ptr<const moho::SScmFile>(file, [image](const moho::SScmFile*) {
      delete image;
    });
  }

  boost::shared_ptr<moho::RScmResource> MakeResource()
  {
    return boost::shared_ptr<moho::RScmResource>(new moho::RScmResource("test/one_bone.scm", MakeOneBoneScm()));
  }
} // namespace

TEST(
  SkeletonBuild,
  OneThreadBuildsTheFileBones
)
{
  const boost::shared_ptr<moho::RScmResource> resource = MakeResource();
  const boost::shared_ptr<const moho::CAniSkel> skeleton = resource->GetSkeleton();
  ASSERT_NE(skeleton.get(), nullptr);
  ASSERT_EQ(skeleton->mBones.size(), 1u);
  EXPECT_STREQ(skeleton->mBones.begin()[0].mBoneName, "root");
  EXPECT_EQ(skeleton->mBones.begin()[0].mParentBoneIndex, -1);
  EXPECT_EQ(resource->GetSkeleton().get(), skeleton.get()) << "a second call must return the built skeleton";
}

TEST(
  SkeletonBuild,
  ThreadsStartingTogetherShareOneSkeleton
)
{
  constexpr int kThreads = 8;
  constexpr int kRounds = 500;

  for (int round = 0; round < kRounds; ++round) {
    const boost::shared_ptr<moho::RScmResource> resource = MakeResource();
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::vector<const moho::CAniSkel*> seen(kThreads, nullptr);
    std::vector<std::size_t> boneCounts(kThreads, 0u);

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
      threads.emplace_back([&, t] {
        ready.fetch_add(1);
        while (!go.load(std::memory_order_acquire)) {}
        const boost::shared_ptr<const moho::CAniSkel> skeleton = resource->GetSkeleton();
        seen[t] = skeleton.get();
        boneCounts[t] = skeleton ? skeleton->mBones.size() : 0u;
      });
    }
    while (ready.load() != kThreads) {}
    go.store(true, std::memory_order_release);
    for (std::thread& thread : threads) {
      thread.join();
    }

    for (int t = 0; t < kThreads; ++t) {
      ASSERT_NE(seen[t], nullptr) << "round " << round << " thread " << t;
      ASSERT_EQ(seen[t], seen[0]) << "round " << round << ": thread " << t << " got another skeleton";
      ASSERT_EQ(boneCounts[t], 1u) << "round " << round << ": thread " << t << " saw an unfinished skeleton";
    }
    ASSERT_EQ(resource->GetSkeleton().get(), seen[0]) << "round " << round;
  }
}
