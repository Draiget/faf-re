// Statistics assertions exercise the same source-bound functions and payloads
// as ordinary upload tests. Device calls and world construction remain adapters.
namespace {
TEST_F(ParticleUpload, StatsLinearPressureCountsOnlyUnconsumedPayloadOnce) {
  CWorldParticles world(2); world.BeginPoolStatsSession();
  auto& bucket=world.P(0); Pending(bucket,1001);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  EXPECT_TRUE(bucket.pendingParticles.empty());
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  Pending(bucket,501);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particleBuffersPeak,2U);
  EXPECT_EQ(stats->particleBuffersCapacity,2U);
  EXPECT_EQ(stats->particlesPoolDropped,1102U);
  EXPECT_EQ(stats->pendingParticlesUploadDiscarded,0U);
  EXPECT_EQ(bucket.activeWorkItems[0]->mRenderStartIndex,200);
  EXPECT_EQ(bucket.activeWorkItems[1]->mRenderStartIndex,200);
}
TEST_F(ParticleUpload, StatsPartialTailAdmitsOneThenDropsNine) {
  CWorldParticles world(1); world.BeginPoolStatsSession();
  auto& bucket=world.P(0); Active(bucket,199); Pending(bucket,10,200);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particlesPoolDropped,9U);
  EXPECT_EQ(stats->particleBuffersPeak,1U);
  EXPECT_EQ(bucket.activeWorkItems[0]->mRenderStartIndex,200);
}
TEST_F(ParticleUpload, StatsNormalAndRefractionShareConcurrentPeakNotAcquisitionSum) {
  CWorldParticles world(3); world.BeginPoolStatsSession();
  auto& a=world.P(0); auto& b=world.P(1,0,true);
  Active(a,200); Active(b,200);
  RecycleAndDestroyParticleBucketWorkItems(a);
  Active(a,200);
  PruneExpiredParticleBucketWorkItems(a,10000);
  PruneExpiredParticleBucketWorkItems(b,10000);
  EXPECT_EQ(world.mAvailableParticleBuffers.size(),3U);
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particleBuffersPeak,2U);
  EXPECT_EQ(stats->particleBuffersCapacity,3U);
  EXPECT_EQ(stats->particlesPoolDropped,0U);
  EXPECT_EQ(stats->pendingParticlesUploadDiscarded,0U);
}
TEST_F(ParticleUpload, StatsBeginSamplesUnavailableSlotsAcrossSessions) {
  CWorldParticles world(2);
  auto* first=world.AcquireParticleBuffer(); auto* second=world.AcquireParticleBuffer();
  ASSERT_NE(first,nullptr); ASSERT_NE(second,nullptr);
  world.BeginPoolStatsSession();
  auto& b=world.P(0); Pending(b,7);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(b,0));
  world.BeginPoolStatsSession(); // repeated begin must not zero the loss
  const auto one=particlePoolStats.EndSession(); ASSERT_TRUE(one);
  EXPECT_EQ(one->particleBuffersPeak,2U); EXPECT_EQ(one->particlesPoolDropped,7U);
  world.ReleaseParticleBuffer(first); world.ReleaseParticleBuffer(second);
  world.BeginPoolStatsSession();
  const auto two=particlePoolStats.EndSession(); ASSERT_TRUE(two);
  EXPECT_EQ(two->particleBuffersPeak,0U); EXPECT_EQ(two->particlesPoolDropped,0U);
  EXPECT_EQ(two->particleBuffersCapacity,2U);
}
TEST_F(ParticleUpload, StatsLockDiscardAfterConsumedPrefixIsNotPoolPressure) {
  CWorldParticles world(3); world.BeginPoolStatsSession();
  auto& bucket=world.P(0); Pending(bucket,1001);
  beforeUnlock=[] { failLock=true; };
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  beforeUnlock={}; failLock=false;
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particlesPoolDropped,0U);
  EXPECT_EQ(stats->pendingParticlesUploadDiscarded,801U);
  EXPECT_EQ(stats->particleBuffersPeak,2U);
  EXPECT_EQ(bucket.activeWorkItems.size(),2U);
  EXPECT_EQ(bucket.activeWorkItems.front()->mRenderStartIndex,200);
}
TEST_F(ParticleUpload, StatsPublicHelperNullBufferCountsPendingNotPreviousLiveRecords) {
  particlePoolStats.BeginSession();
  SParticleRenderWorkItem work; work.mIntervalCapacityHint=200;
  work.mRenderStartIndex=1; work.mIntervals.push_back({0,100});
  CWorldParticles world; auto& b=world.P(0); Pending(b,7);
  UploadPendingParticlesIntoWorkItem(work,0,b.pendingParticles);
  EXPECT_TRUE(b.pendingParticles.empty()); EXPECT_TRUE(work.mIntervals.empty());
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->pendingParticlesUploadDiscarded,7U);
  EXPECT_EQ(stats->particlesPoolDropped,0U);
}
TEST_F(ParticleUpload, StatsCopyFallbackAndOrdinaryCleanupDoNotCountDrops) {
  CWorldParticles world(2); world.BeginPoolStatsSession();
  auto& b=world.P(0); Pending(b,201);
  device.failCopy=[](const auto&) { return true; };
  Pass(world);
  auto expected=Sequence(1,200); expected.insert(expected.begin(),201);
  EXPECT_EQ(DrawnIds(device),expected); // production draws work items in reverse order
  RecycleAndDestroyParticleBucketWorkItems(b);
  Pending(b,9); b.pendingParticles.clear(); // discard on ordinary bucket cleanup is excluded
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particlesPoolDropped,0U);
  EXPECT_EQ(stats->pendingParticlesUploadDiscarded,0U);
  EXPECT_EQ(stats->particleBuffersPeak,2U);
}
TEST_F(ParticleUpload, StatsEmptyPoolPressureCountsPayloadNotProbes) {
  CWorldParticles world; world.BeginPoolStatsSession();
  EXPECT_EQ(world.AcquireParticleBuffer(),nullptr);
  auto& b=world.P(0); Pending(b,13);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(b,0));
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(b,0));
  const auto stats=particlePoolStats.EndSession(); ASSERT_TRUE(stats);
  EXPECT_EQ(stats->particlesPoolDropped,13U);
  EXPECT_EQ(stats->particleBuffersPeak,0U);
}
} // namespace
