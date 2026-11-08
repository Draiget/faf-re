namespace {
TEST_F(ParticleUpload, ReviewPublicWrapperConsumesExactlyOneBatch) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture);
  auto* buffer=world.AcquireParticleBuffer();
  auto* work=static_cast<SParticleRenderWorkItem*>(::operator new(sizeof(SParticleRenderWorkItem)));
  InitializeParticleRenderWorkItem(*work,200,buffer);
  bucket.activeWorkItems.push_back(work);
  UploadPendingParticlesIntoWorkItem(*work,7,bucket.pendingParticles);
  ASSERT_EQ(bucket.pendingParticles.size(),201U);
  ASSERT_EQ(work->mRenderStartIndex,200U);
  EXPECT_EQ(texture.references,402);
  for(std::size_t i=0;i<201;++i) {
    EXPECT_EQ(bucket.pendingParticles[i].mPos.x,201+i);
    EXPECT_EQ(bucket.pendingParticles[i].mInterop,0);
    EXPECT_EQ(bucket.pendingParticles[i].mTexture.tex,&texture);
    EXPECT_EQ(bucket.pendingParticles[i].mRampTexture.tex,&texture);
    EXPECT_EQ(bucket.pendingParticles[i].mTypeTag.view(),"particle-probe-tag-long-enough-to-own-heap");
  }
  UploadPendingParticlesIntoWorkItem(*work,7,bucket.pendingParticles);
  EXPECT_EQ(bucket.pendingParticles.size(),201U);
  EXPECT_EQ(texture.references,402);
  bucket.pendingParticles.clear();
}
TEST_F(ParticleUpload, ReviewNullBufferDirectWrapperDiscardsAndResets) {
  CParticleTexture texture; CWorldParticles world(0); auto& bucket=world.P(0);
  Seed(bucket,401,texture); SParticleRenderWorkItem work;
  work.mIntervalCapacityHint=200;
  UploadPendingParticlesIntoWorkItem(work,7,bucket.pendingParticles);
  EXPECT_TRUE(bucket.pendingParticles.empty()); EXPECT_EQ(texture.references,0);
  EXPECT_EQ(work.mRenderStartIndex,0U); EXPECT_EQ(work.mIntervalCursor,0U);
}
TEST_F(ParticleUpload, ReviewSecondLockNullRetainsFirstUploadedBatch) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture); int calls=0;
  beforeLock=[&]{if(++calls==2) failLock=true;};
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));
  beforeLock={}; failLock=false;
  ASSERT_EQ(bucket.activeWorkItems.size(),2U);
  EXPECT_EQ(bucket.activeWorkItems[0]->mRenderStartIndex,200U);
  EXPECT_EQ(bucket.activeWorkItems[1]->mRenderStartIndex,0U);
  EXPECT_TRUE(bucket.activeWorkItems[1]->mIntervals.empty());
  EXPECT_TRUE(bucket.pendingParticles.empty()); EXPECT_EQ(texture.references,0);
}
}
