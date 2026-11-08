namespace {
TEST_F(ParticleUpload, ObservePendingAtUnlockDocumentsTransientContract) {
  CParticleTexture texture; CWorldParticles world(5); auto& bucket=world.P(0);
  Seed(bucket,1000,texture);std::vector<std::size_t> sizes,emptyPrefixes;
  beforeUnlock=[&]{
    sizes.push_back(bucket.pendingParticles.size());std::size_t empty=0;
    for(const auto& p:bucket.pendingParticles) {
      if(p.mTexture.tex!=nullptr||p.mRampTexture.tex!=nullptr||!p.mTypeTag.view().empty())break;
      ++empty;
    }
    emptyPrefixes.push_back(empty);
  };
  ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));beforeUnlock={};
  if (ren_ParticleLinearUpload > 0) {
  EXPECT_EQ(sizes,(std::vector<std::size_t>{1000,1000,1000,200,0}));
  EXPECT_EQ(emptyPrefixes,(std::vector<std::size_t>{200,400,600,0,0}));
  } else {
  EXPECT_EQ(sizes,(std::vector<std::size_t>{800,600,400,200,0}));
  EXPECT_EQ(emptyPrefixes,(std::vector<std::size_t>{0,0,0,0,0}));
  }
  EXPECT_EQ(texture.references,0);EXPECT_TRUE(bucket.pendingParticles.empty());
}
TEST_F(ParticleUpload, ControlledAppendFromUnlockRetainsInputOrder) {
  CParticleTexture texture;CWorldParticles world(4);auto& bucket=world.P(0);
  Seed(bucket,401,texture);int calls=0;
  beforeUnlock=[&]{if(++calls==1) Seed(bucket,1,texture,9000);};
  ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));beforeUnlock={};
  std::vector<int> ids;
  for(auto* wi:bucket.activeWorkItems) {
    const auto* b=static_cast<ParticleBuffer*>(wi->mParticleBuffer);
    for(std::size_t i=0;i<wi->mRenderStartIndex;++i){float id;std::memcpy(&id,b->mInstanceVertexBuffer->bytes.data()+92*i,4);ids.push_back(static_cast<int>(id));}
  }
  auto expected=Sequence(1,401);expected.push_back(9000);EXPECT_EQ(ids,expected);
  EXPECT_EQ(texture.references,0);EXPECT_TRUE(bucket.pendingParticles.empty());
}
} // namespace

namespace
{
  TEST_F(ParticleUpload, CallbackSwitchChangeAppliesOnlyToNextEnsureCall)
  {
    for (const int initial : {0, 1}) {
      SCOPED_TRACE(initial);
      CParticleTexture texture;
      CWorldParticles world(10);
      auto& bucket = world.P(0);
      Seed(bucket, 1000, texture);
      ren_ParticleLinearUpload = initial;
      std::vector<std::size_t> sizes;
      beforeLock = [&] {
        ren_ParticleLinearUpload = 1 - initial;
      };
      beforeUnlock = [&] {
        sizes.push_back(bucket.pendingParticles.size());
      };
      ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket, 7));
      beforeLock = {};
      beforeUnlock = {};
      EXPECT_EQ(sizes, initial == 1 ? (std::vector<std::size_t>{1000, 1000, 1000, 200, 0})
                                   : (std::vector<std::size_t>{800, 600, 400, 200, 0}));
      std::size_t expected = 1;
      for (const auto* item : bucket.activeWorkItems) {
        const auto* buffer = static_cast<const ParticleBuffer*>(item->mParticleBuffer);
        for (std::size_t index = 0; index < item->mRenderStartIndex; ++index) {
          float id = 0;
          std::memcpy(&id, buffer->mInstanceVertexBuffer->bytes.data() + 92 * index, sizeof(id));
          EXPECT_EQ(id, static_cast<float>(expected++));
        }
      }
      EXPECT_EQ(expected, 1001U);
      EXPECT_EQ(texture.references, 0);

      Seed(bucket, 1000, texture);
      beforeUnlock = [&] {
        sizes.push_back(bucket.pendingParticles.size());
      };
      sizes.clear();
      ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket, 7));
      beforeUnlock = {};
      EXPECT_EQ(sizes, initial == 0 ? (std::vector<std::size_t>{1000, 1000, 1000, 200, 0})
                                   : (std::vector<std::size_t>{800, 600, 400, 200, 0}));
      EXPECT_TRUE(bucket.pendingParticles.empty());
      EXPECT_EQ(texture.references, 0);
    }
  }

  TEST_F(ParticleUpload, CallbackSwitchChangeAndThrowPreserveRemainingOrder)
  {
    for (const int initial : {0, 1}) {
      SCOPED_TRACE(initial);
      CParticleTexture texture;
      CWorldParticles world(3);
      auto& bucket = world.P(0);
      Seed(bucket, 401, texture);
      ren_ParticleLinearUpload = initial;
      beforeUnlock = [&] {
        ren_ParticleLinearUpload = 1 - initial;
        throw std::runtime_error("switch change at unlock");
      };
      EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket, 7), std::runtime_error);
      beforeUnlock = {};
      ASSERT_EQ(bucket.pendingParticles.size(), 201U);
      EXPECT_EQ(texture.references, 402);
      for (std::size_t index = 0; index < 201; ++index) {
        EXPECT_EQ(bucket.pendingParticles[index].mPos.x, 201 + index);
        EXPECT_EQ(bucket.pendingParticles[index].mInterop, 0);
      }
      EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket, 7));
      EXPECT_TRUE(bucket.pendingParticles.empty());
      EXPECT_EQ(texture.references, 0);
    }
  }
}
