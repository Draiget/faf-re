// Test-only global allocation failpoint. It arms only around the unchanged
// Ensure/Upload call. Recording and assertions execute after disarming.
#include <array>
#include <limits>
#include <new>
#include <sstream>
namespace allocation_probe {
struct Entry { void* pointer=nullptr; std::size_t bytes=0; };
inline std::array<Entry,16384> entries{};
inline bool armed=false;
inline bool persistent=false;
inline void (*onRequest)(std::size_t)=nullptr;
inline std::size_t observed=0, failAt=std::numeric_limits<std::size_t>::max();
inline std::array<std::size_t,16384> requestSizes{};
void* Allocate(std::size_t bytes) {
  if (armed) {
    if(observed>=requestSizes.size()) std::abort();
    requestSizes[observed++]=bytes;
    if(onRequest) onRequest(observed);
    if(observed==failAt || (persistent && observed>failAt)) throw std::bad_alloc();
  }
  void* result=std::malloc(bytes==0?1:bytes);
  if(result==nullptr) throw std::bad_alloc();
  if(armed) {
    auto it=std::find_if(entries.begin(),entries.end(),[](const Entry& e){return e.pointer==nullptr;});
    if(it==entries.end()) std::abort();
    *it={result,bytes};
  }
  return result;
}
void Free(void* p) noexcept {
  if(p==nullptr) return;
  for(auto& entry:entries) if(entry.pointer==p) {entry={}; break;}
  std::free(p);
}
void Arm(std::size_t point) {
  if(std::any_of(entries.begin(),entries.end(),[](const Entry& e){return e.pointer!=nullptr;})) std::abort();
  observed=0; failAt=point; armed=true;
}
}
void* operator new(std::size_t bytes) {return allocation_probe::Allocate(bytes);}
void* operator new[](std::size_t bytes) {return allocation_probe::Allocate(bytes);}
void operator delete(void* p) noexcept {allocation_probe::Free(p);}
void operator delete[](void* p) noexcept {allocation_probe::Free(p);}
void* operator new(std::size_t bytes,const std::nothrow_t&) noexcept {try{return allocation_probe::Allocate(bytes);}catch(...){return nullptr;}}
void* operator new[](std::size_t bytes,const std::nothrow_t&) noexcept {try{return allocation_probe::Allocate(bytes);}catch(...){return nullptr;}}
void operator delete(void* p,const std::nothrow_t&) noexcept {allocation_probe::Free(p);}
void operator delete[](void* p,const std::nothrow_t&) noexcept {allocation_probe::Free(p);}
void operator delete(void* p,std::size_t) noexcept {allocation_probe::Free(p);}
void operator delete[](void* p,std::size_t) noexcept {allocation_probe::Free(p);}


namespace {
std::size_t LiveTrackedAllocations() {
  return std::count_if(allocation_probe::entries.begin(),allocation_probe::entries.end(),
                       [](const auto& e){return e.pointer!=nullptr;});
}
void ExpectOwnerPartition(const CWorldParticles& world, const SParticleRenderBucket& bucket) {
  // Follow actual resource identities. Counts alone could hide one duplicated
  // buffer and one orphan, or a work item that has been prematurely destroyed.
  std::set<const ParticleBuffer*> seen;
  std::vector<const ParticleBuffer*> available;
  for (auto* buffer : world.mAvailableParticleBuffers) {
    EXPECT_TRUE(seen.insert(buffer).second);
    available.push_back(buffer);
  }
  for (auto* work : bucket.activeWorkItems) {
    ASSERT_NE(work,nullptr);
    auto* buffer=static_cast<ParticleBuffer*>(work->mParticleBuffer);
    ASSERT_NE(buffer,nullptr);
    EXPECT_TRUE(seen.insert(buffer).second);
    EXPECT_EQ(work->mIntervalCapacityHint,static_cast<std::uint32_t>(buffer->mMaxParticles));
    EXPECT_NE(buffer->mInstanceVertexBuffer,nullptr);
    EXPECT_EQ(buffer->mInstanceVertexBuffer->bytes.size(),200U*92U);
  }
  ASSERT_EQ(seen.size(),world.owned_p.size());
  for (const auto& buffer:world.owned_p) EXPECT_EQ(seen.count(buffer.get()),1U);
  // Acquire must consume the original FIFO prefix, not return a failed borrow
  // at the tail and silently reorder future allocations.
  const auto linked=bucket.activeWorkItems.size();
  ASSERT_EQ(available.size()+linked,world.owned_p.size());
  for(std::size_t i=0;i<linked;++i)
    EXPECT_EQ(bucket.activeWorkItems[i]->mParticleBuffer,world.owned_p[i].get());
  for(std::size_t i=0;i<available.size();++i)
    EXPECT_EQ(available[i],world.owned_p[linked+i].get());
}
struct FailureRun {std::size_t requests; bool threw;};
FailureRun RunOwnedScenario(gpg::gal::Device& device, int scenario, std::size_t point, bool persistent) {
  using namespace allocation_probe;
  sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
  gpg::gal::Device::current=&device;ren_ParticleBatch=scenario==4?1:0;
  bool threw=false;std::size_t requests=0;
  {
    CParticleTexture texture;
    CWorldParticles world(scenario==3?0:4);auto& bucket=world.P(0);
    if(scenario==1||scenario==2) {
      Seed(bucket,scenario==1?200:199,texture,5000);
      EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
    }
    auto* const previous=bucket.activeWorkItems.empty()?nullptr:bucket.activeWorkItems.front();
    std::vector<std::uint8_t> committedBytes;
    if(previous) committedBytes=world.owned_p.front()->mInstanceVertexBuffer->bytes;
    Seed(bucket,scenario==0?1:401,texture);
    allocation_probe::persistent=persistent;
    Arm(point);
    try {(void)EnsureAndFillParticleBucketWorkItems(bucket,7);}
    catch(const std::bad_alloc&){threw=true;}
    catch(...){armed=false;throw;}
    armed=false;requests=observed;
    ExpectOwnerPartition(world,bucket);
    if(previous) {
      EXPECT_FALSE(bucket.activeWorkItems.empty());
      EXPECT_EQ(bucket.activeWorkItems.front(),previous);
      EXPECT_EQ(previous->mParticleBuffer,world.owned_p.front().get());
      const auto originalBytes=(scenario==1?200U:199U)*92U;
      EXPECT_EQ(std::memcmp(committedBytes.data(),world.owned_p.front()->mInstanceVertexBuffer->bytes.data(),originalBytes),0);
    }
    if(scenario==0 && point<=2U) {
      EXPECT_TRUE(bucket.activeWorkItems.empty());
      EXPECT_EQ(world.mAvailableParticleBuffers.size(),4U);
      EXPECT_EQ(bucket.pendingParticles.size(),1U);
      EXPECT_EQ(bucket.pendingParticles.front().mPos.x,1);
      EXPECT_EQ(texture.references,2);
    }
    if(scenario==3) { EXPECT_EQ(requests,0U); EXPECT_FALSE(threw); EXPECT_TRUE(bucket.pendingParticles.empty()); }
  }
  sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
  EXPECT_EQ(LiveTrackedAllocations(),0U) << "An allocated object or interval block has no owner after world teardown";
  return {requests,threw};
}
TEST_F(ParticleUpload, WorkItemAllocationFailureKeepsExactAvailableOwners) {
  auto result=RunOwnedScenario(device,0,1,true);
  EXPECT_TRUE(result.threw);EXPECT_EQ(result.requests,1U);
}
TEST_F(ParticleUpload, ActiveVectorFailureDeletesUnlinkedItemAndKeepsExactAvailableOwners) {
  auto result=RunOwnedScenario(device,0,2,true);
  EXPECT_TRUE(result.threw);EXPECT_EQ(result.requests,2U);
}
TEST_F(ParticleUpload, EveryAllocationFailureRetainsOneOwnerPerBufferAndNoOrphanItem) {
  std::size_t failures=0;
  for(int scenario=0;scenario<5;++scenario) {
    auto success=RunOwnedScenario(device,scenario,std::numeric_limits<std::size_t>::max(),false);
    ASSERT_FALSE(success.threw);
    for(bool persistent:{false,true}) for(std::size_t point=1;point<=success.requests;++point) {
      SCOPED_TRACE(std::to_string(scenario)+"/"+std::to_string(point)+"/persistent="+std::to_string(persistent));
      auto result=RunOwnedScenario(device,scenario,point,persistent);
      EXPECT_TRUE(result.threw);EXPECT_EQ(result.requests,point);++failures;
    }
  }
  EXPECT_GT(failures,200U);
  std::cout<<"OWNERSHIP_FAILURE_POINTS="<<failures<<"\n";
}
TEST_F(ParticleUpload, RealInitializerHasNoAllocationAndMatchesDefaultConstruction) {
  alignas(SParticleRenderWorkItem) std::byte raw[sizeof(SParticleRenderWorkItem)];
  auto* item=reinterpret_cast<SParticleRenderWorkItem*>(raw);
  ParticleBuffer buffer;
  std::unique_ptr<SParticleRenderWorkItem> constructed;
  // This real initializer cannot be meaningfully injected at an internal
  // allocation: there are none. Arm persistent failure at the first allocation
  // to prove that fact without replacing the implementation with a throwing fake.
  allocation_probe::persistent=true;allocation_probe::Arm(1);
  InitializeParticleRenderWorkItem(*item,200,&buffer);
  const auto requests=allocation_probe::observed;allocation_probe::armed=false;
  constructed=std::make_unique<SParticleRenderWorkItem>();
  constructed->mParticleBuffer=&buffer;constructed->mIntervalCapacityHint=200;
  EXPECT_EQ(requests,0U);
  EXPECT_EQ(item->mParticleBuffer,constructed->mParticleBuffer);
  EXPECT_EQ(item->mIntervalCapacityHint,constructed->mIntervalCapacityHint);
  EXPECT_EQ(item->mIntervalCursor,constructed->mIntervalCursor);
  EXPECT_EQ(item->mRenderStartIndex,constructed->mRenderStartIndex);
  EXPECT_EQ(item->mIntervals.size(),constructed->mIntervals.size());
  EXPECT_EQ(item->mIntervals.capacity(),constructed->mIntervals.capacity());
  EXPECT_EQ(item->mIntervals.data(),constructed->mIntervals.data());
  item->mIntervals.~vector();
}
TEST_F(ParticleUpload, ExhaustionRemainsAllocationFreeWithPersistentFailure) {
  auto result=RunOwnedScenario(device,3,1,true);
  EXPECT_FALSE(result.threw);EXPECT_EQ(result.requests,0U);
}
TEST_F(ParticleUpload, LinkedWorkItemOwnsBufferAtLockUnlockAndMirrorThrowBoundaries) {
  for(int boundary=0;boundary<3;++boundary) {
    SCOPED_TRACE(boundary);CParticleTexture texture;CWorldParticles world(4);auto& bucket=world.P(0);
    Seed(bucket,401,texture);ren_ParticleBatch=1;
    const auto fail=[&]{ExpectOwnerPartition(world,bucket);throw std::runtime_error("injected adapter boundary");};
    if(boundary==0) beforeLock=fail;
    if(boundary==1) beforeUnlock=fail;
    if(boundary==2) device.failCopy=[&](const Copy&)->bool {fail();return false;};
    EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::runtime_error);
    beforeLock={};beforeUnlock={};device.failCopy={};
    ExpectOwnerPartition(world,bucket);
    ASSERT_EQ(bucket.activeWorkItems.size(),1U);
    auto* work=bucket.activeWorkItems.front();
    EXPECT_EQ(work->mRenderStartIndex,boundary==0?0U:200U);
    EXPECT_EQ(bucket.pendingParticles.size(),boundary==0?401U:201U);
    RecycleAndDestroyParticleBucketWorkItems(bucket);
    EXPECT_EQ(world.mAvailableParticleBuffers.size(),4U);
    // FIFO recycling moves the formerly used first buffer to the back.
    EXPECT_EQ(world.mAvailableParticleBuffers.back(),world.owned_p.front().get());
  }
}
} // namespace

namespace {
CWorldParticles* callbackWorld=nullptr;
std::array<ParticleBuffer*,4> callbackBorrowed{};
std::size_t callbackPoint=0,callbackCount=0;
void BorrowFromAllocationCallback(std::size_t point) {
  if(point!=callbackPoint)return;
  for(std::size_t i=0;i<callbackCount;++i)callbackBorrowed[i]=callbackWorld->AcquireParticleBuffer();
}
TEST_F(ParticleUpload, AllocationCallbackUsesActualAcquiredBufferOrRemovesEmptyItem) {
  for(std::size_t point:{1U,2U}) for(std::size_t count:{1U,4U}) {
    SCOPED_TRACE(std::to_string(point)+"/"+std::to_string(count));
    ren_ParticleBatch=0;
    {
      CParticleTexture texture;CWorldParticles world(4);auto& bucket=world.P(0);Seed(bucket,1,texture);
      callbackWorld=&world;callbackPoint=point;callbackCount=count;callbackBorrowed.fill(nullptr);
      allocation_probe::onRequest=BorrowFromAllocationCallback;
      allocation_probe::persistent=false;allocation_probe::Arm(std::numeric_limits<std::size_t>::max());
      const bool returned=EnsureAndFillParticleBucketWorkItems(bucket,7);
      allocation_probe::armed=false;allocation_probe::onRequest=nullptr;
      EXPECT_EQ(returned,count==1U);
      EXPECT_TRUE(bucket.pendingParticles.empty());EXPECT_EQ(texture.references,0);
      for(std::size_t i=0;i<count;++i)EXPECT_EQ(callbackBorrowed[i],world.owned_p[i].get());
      if(count==1U) {
        ASSERT_EQ(bucket.activeWorkItems.size(),1U);
        EXPECT_EQ(bucket.activeWorkItems.front()->mParticleBuffer,world.owned_p[1].get());
        EXPECT_EQ(bucket.activeWorkItems.front()->mRenderStartIndex,1U);
        EXPECT_EQ(world.mAvailableParticleBuffers.size(),2U);
        EXPECT_EQ(world.mAvailableParticleBuffers.front(),world.owned_p[2].get());
      } else {
        EXPECT_TRUE(bucket.activeWorkItems.empty());EXPECT_TRUE(world.mAvailableParticleBuffers.empty());
      }
      // Callback-owned borrows are returned explicitly, never by the candidate.
      for(std::size_t i=0;i<count;++i)world.ReleaseParticleBuffer(callbackBorrowed[i]);
    }
    EXPECT_EQ(LiveTrackedAllocations(),0U);
  }
  callbackWorld=nullptr;
}
}
namespace {
struct StateWriter {
  std::string bytes;
  template<class T> void Put(const T& v) {static_assert(std::is_trivially_copyable_v<T>);bytes.append(reinterpret_cast<const char*>(&v),sizeof(v));}
  void Bytes(const void* p,std::size_t size){Put(size);bytes.append(reinterpret_cast<const char*>(p),size);}
  void String(std::string_view text){Bytes(text.data(),text.size());}
};
int BufferId(const CWorldParticles& world,const ParticleBuffer* buffer) {
  for(std::size_t i=0;i<world.owned_p.size();++i) if(world.owned_p[i].get()==buffer) return static_cast<int>(i);
  return -1;
}
int VertexId(const CWorldParticles& world,const VertexBuffer* buffer) {
  if(buffer==sParticleMirror.mBuffer.get()) return -2;
  if(buffer==sParticleGather.mBuffer.get()) return -3;
  for(std::size_t i=0;i<world.owned_p.size();++i) if(world.owned_p[i]->mInstanceVertexBuffer.get()==buffer) return static_cast<int>(i);
  return -1;
}
void WriteState(StateWriter& w,const CWorldParticles& world,const SParticleRenderBucket& bucket,
                const CParticleTexture& texture,const gpg::gal::Device& device) {
  w.Put(texture.references.load());w.Put(bucket.pendingParticles.size());
  for(const auto& p:bucket.pendingParticles) {
    w.Put(p.mPos.x);w.Put(p.mPos.y);w.Put(p.mPos.z);w.Put(p.mDir.x);w.Put(p.mDir.y);w.Put(p.mDir.z);w.Put(p.mAccel.x);w.Put(p.mAccel.y);w.Put(p.mAccel.z);w.Put(p.mInterop);w.Put(p.mLifetime);
    w.String(p.mTypeTag.view());w.Put(p.mTexture.tex==&texture);w.Put(p.mRampTexture.tex==&texture);
  }
  w.Put(world.mAvailableParticleBuffers.size());
  for(auto* b:world.mAvailableParticleBuffers) w.Put(BufferId(world,b));
  w.Put(bucket.activeWorkItems.size());
  for(auto* wi:bucket.activeWorkItems) {
    w.Put(BufferId(world,static_cast<ParticleBuffer*>(wi->mParticleBuffer)));
    w.Put(wi->mRenderStartIndex);w.Put(wi->mIntervalCursor);w.Put(wi->mIntervalCapacityHint);
    w.Put(wi->mIntervals.size());for(const auto& interval:wi->mIntervals){w.Put(interval.beginFrame);w.Put(interval.lifeFrames);}
  }
  for(const auto& b:world.owned_p) w.Bytes(b->mInstanceVertexBuffer->bytes.data(),b->mInstanceVertexBuffer->bytes.size());
  std::vector<std::pair<int,std::uint32_t>> slots;
  for(const auto& [b,slot]:sParticleMirror.mSlotOf) slots.emplace_back(BufferId(world,b),slot);
  std::sort(slots.begin(),slots.end());w.Put(slots.size());for(const auto& [id,slot]:slots){w.Put(id);w.Put(slot);}
  std::vector<std::pair<int,bool>> mirrors;
  for(const auto& [b,valid]:sParticleMirror.mMirrored) mirrors.emplace_back(BufferId(world,b),valid);
  std::sort(mirrors.begin(),mirrors.end());w.Put(mirrors.size());for(const auto& [id,valid]:mirrors){w.Put(id);w.Put(valid);}
  w.Put(sParticleMirror.mSlotsUsed);w.Put(sParticleMirror.mFreeSlots.size());for(auto slot:sParticleMirror.mFreeSlots)w.Put(slot);
  // Store only slots relevant to this scenario, not the whole 12 MB mirror.
  w.Put(sParticleMirror.mBuffer!=nullptr);
  if(sParticleMirror.mBuffer) w.Bytes(sParticleMirror.mBuffer->bytes.data(),sParticleMirror.mSlotsUsed*256U*92U);
  w.Put(device.copies.size());for(const auto& c:device.copies){w.Put(VertexId(world,c.source));w.Put(VertexId(world,c.destination));w.Put(c.sourceOffset);w.Put(c.destinationOffset);w.Put(c.bytes);w.Put(c.success);}
}
struct AllocationOutcome {std::size_t requests; bool threw; std::string state; std::vector<std::size_t> leaks;};
AllocationOutcome RunAllocationScenario(gpg::gal::Device& device,int scenario,std::size_t failAt) {
  using namespace allocation_probe;
  sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
  gpg::gal::Device::current=&device;ren_ParticleBatch=scenario>=3?1:0;
  StateWriter w;bool threw=false,returned=false;std::size_t requests=0;
  {
    CParticleTexture texture;
    CWorldParticles world(scenario==2?1:3);auto& bucket=world.P(0);
    if(scenario==1||scenario==4){Seed(bucket,199,texture,5000);EnsureAndFillParticleBucketWorkItems(bucket,0);}
    Seed(bucket,401,texture);
    Arm(failAt);
    try {returned=EnsureAndFillParticleBucketWorkItems(bucket,7);}
    catch(const std::bad_alloc&){threw=true;}
    catch(...){armed=false;throw;}
    armed=false;requests=observed;
    w.Put(returned);w.Put(threw);w.Put(requests);
    for(std::size_t i=0;i<requests;++i)w.Put(requestSizes[i]);
    WriteState(w,world,bucket,texture,device);
  }
  sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
  std::vector<std::size_t> leaks;
  for(auto& e:entries) if(e.pointer) leaks.push_back(e.bytes);
  std::sort(leaks.begin(),leaks.end());w.Put(leaks.size());for(auto b:leaks)w.Put(b);
  EXPECT_TRUE(leaks.empty());
  return {requests,threw,std::move(w.bytes),std::move(leaks)};
}

TEST_F(ParticleUpload, SuccessfulStateSnapshotsPreservePriorBaseline) {
  const char* outDir=std::getenv("PARTICLE_SUCCESS_STATE_DIR");
  if(outDir==nullptr)GTEST_SKIP()<<"Snapshot export not requested";
  for(int scenario=0;scenario<5;++scenario) {
    const auto result=RunAllocationScenario(device,scenario,std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(result.threw);
    std::ofstream output(std::string(outDir)+"/scenario-"+std::to_string(scenario)+"-fail-0.bin",std::ios::binary);
    output.write(result.state.data(),static_cast<std::streamsize>(result.state.size()));
    ASSERT_TRUE(output.good());
  }
}
}

namespace {
void ExpectFirstUploadedId(const SParticleRenderBucket& bucket, float expected) {
  ASSERT_EQ(bucket.activeWorkItems.size(),1U);
  auto* buffer=static_cast<ParticleBuffer*>(bucket.activeWorkItems.front()->mParticleBuffer);
  ASSERT_NE(buffer,nullptr);
  float actual=0;
  std::memcpy(&actual,buffer->mInstanceVertexBuffer->bytes.data(),sizeof(actual));
  EXPECT_EQ(actual,expected);
  EXPECT_EQ(bucket.activeWorkItems.front()->mRenderStartIndex,1U);
}
void RetryAfterPrelinkFailure(gpg::gal::Device& device,std::size_t point) {
  {
    CParticleTexture texture; CWorldParticles world(1);auto& bucket=world.P(0);
    auto* original=world.owned_p.front().get();
    Seed(bucket,1,texture,41);
    allocation_probe::persistent=true;allocation_probe::Arm(point);
    bool threw=false;
    try {(void)EnsureAndFillParticleBucketWorkItems(bucket,7);}
    catch(const std::bad_alloc&) {threw=true;}
    catch(...) {allocation_probe::armed=false;throw;}
    allocation_probe::armed=false;allocation_probe::persistent=false;
    EXPECT_TRUE(threw);EXPECT_EQ(allocation_probe::observed,point);
    ExpectOwnerPartition(world,bucket);
    ASSERT_EQ(bucket.pendingParticles.size(),1U);
    EXPECT_EQ(bucket.pendingParticles.front().mPos.x,41);
    EXPECT_EQ(bucket.pendingParticles.front().mInterop,0U);
    EXPECT_EQ(texture.references,2);
    EXPECT_TRUE(bucket.activeWorkItems.empty());
    EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));
    EXPECT_TRUE(bucket.pendingParticles.empty());EXPECT_EQ(texture.references,0);
    ExpectOwnerPartition(world,bucket);ExpectFirstUploadedId(bucket,41);
    EXPECT_EQ(bucket.activeWorkItems.front()->mParticleBuffer,original);
    PruneExpiredParticleBucketWorkItems(bucket,10000);
    EXPECT_TRUE(bucket.activeWorkItems.empty());
    ASSERT_EQ(world.mAvailableParticleBuffers.size(),1U);
    EXPECT_EQ(world.mAvailableParticleBuffers.front(),original);
    Seed(bucket,1,texture,91);
    EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,11));
    ExpectFirstUploadedId(bucket,91);ExpectOwnerPartition(world,bucket);
    EXPECT_EQ(bucket.activeWorkItems.front()->mParticleBuffer,original);
    RecycleAndDestroyParticleBucketWorkItems(bucket);
    EXPECT_TRUE(bucket.activeWorkItems.empty());EXPECT_EQ(texture.references,0);
    ASSERT_EQ(world.mAvailableParticleBuffers.size(),1U);
    EXPECT_EQ(world.mAvailableParticleBuffers.front(),original);
  }
  sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
  EXPECT_EQ(LiveTrackedAllocations(),0U);
}
TEST_F(ParticleUpload, WorkItemAllocationFailureCanRetryPruneAndReuseSameBucket) {
  RetryAfterPrelinkFailure(device,1);
}
TEST_F(ParticleUpload, ActiveVectorFailureCanRetryPruneAndReuseSameBucket) {
  RetryAfterPrelinkFailure(device,2);
}
TEST_F(ParticleUpload, AllocationCallbackLateExhaustionCanRefillRetryAndReuseSameBucket) {
  for(std::size_t point:{1U,2U}) {
    SCOPED_TRACE(point);
    {
      CParticleTexture texture;CWorldParticles world(1);auto& bucket=world.P(0);
      auto* original=world.owned_p.front().get();Seed(bucket,1,texture,41);
      callbackWorld=&world;callbackPoint=point;callbackCount=1;callbackBorrowed.fill(nullptr);
      allocation_probe::onRequest=BorrowFromAllocationCallback;
      allocation_probe::persistent=false;allocation_probe::Arm(std::numeric_limits<std::size_t>::max());
      bool returned=false;
      try {returned=EnsureAndFillParticleBucketWorkItems(bucket,7);}
      catch(...) {allocation_probe::armed=false;allocation_probe::onRequest=nullptr;callbackWorld=nullptr;throw;}
      allocation_probe::armed=false;allocation_probe::onRequest=nullptr;callbackWorld=nullptr;
      EXPECT_FALSE(returned);EXPECT_EQ(callbackBorrowed[0],original);
      EXPECT_TRUE(bucket.activeWorkItems.empty());EXPECT_TRUE(world.mAvailableParticleBuffers.empty());
      EXPECT_TRUE(bucket.pendingParticles.empty());EXPECT_EQ(texture.references,0);
      world.ReleaseParticleBuffer(callbackBorrowed[0]);
      // Exhaustion deliberately discarded the old payload; retry with new payload.
      Seed(bucket,1,texture,91);
      EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,11));
      ExpectOwnerPartition(world,bucket);ExpectFirstUploadedId(bucket,91);
      EXPECT_EQ(bucket.activeWorkItems.front()->mParticleBuffer,original);
      RecycleAndDestroyParticleBucketWorkItems(bucket);
      EXPECT_TRUE(bucket.activeWorkItems.empty());EXPECT_EQ(texture.references,0);
      ASSERT_EQ(world.mAvailableParticleBuffers.size(),1U);
      EXPECT_EQ(world.mAvailableParticleBuffers.front(),original);
      Seed(bucket,1,texture,121);
      EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,15));
      ExpectOwnerPartition(world,bucket);ExpectFirstUploadedId(bucket,121);
      EXPECT_EQ(bucket.activeWorkItems.front()->mParticleBuffer,original);
    }
    sParticleGather={};sParticleMirror={};device=gpg::gal::Device{};
    EXPECT_EQ(LiveTrackedAllocations(),0U);
  }
}
}
