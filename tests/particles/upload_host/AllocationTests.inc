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
inline std::size_t observed=0, failAt=std::numeric_limits<std::size_t>::max();
inline std::array<std::size_t,16384> requestSizes{};
void* Allocate(std::size_t bytes) {
  if (armed) {
    if(observed>=requestSizes.size()) std::abort();
    requestSizes[observed++]=bytes;
    if(observed==failAt) throw std::bad_alloc();
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
  // Both versions already leak an unlinked work item when activeWorkItems
  // growth throws. Report those raw blocks, then reclaim test-process storage.
  // This is test cleanup, not a production leak fix or a leak-free result.
  for(auto& e:entries) if(e.pointer){void* p=e.pointer;e={};std::free(p);}
  return {requests,threw,std::move(w.bytes),std::move(leaks)};
}
TEST_F(ParticleUpload, EveryEnsureAllocationFailureHasDeterministicBoundaryState) {
  const char* outDir=std::getenv("PARTICLE_STATE_DIR");
  ASSERT_NE(outDir,nullptr)<<"Provide an existing output directory for exact switch-off/switch-on comparison";
  // Truncate only our manifest. Old state files are deliberately ignored.
  std::ofstream manifest(std::string(outDir) + "/run-files.txt", std::ios::trunc);
  ASSERT_TRUE(manifest.good());
  std::size_t injected=0;
  for(int scenario=0;scenario<5;++scenario) {
    auto success=RunAllocationScenario(device,scenario,std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(success.threw);
    const auto save=[&](std::size_t point,const AllocationOutcome& result){
      const std::string filename = "scenario-" + std::to_string(scenario) + "-fail-" + std::to_string(point) + ".bin";
      std::ofstream f(std::string(outDir) + "/" + filename, std::ios::binary);
      f.write(result.state.data(), static_cast<std::streamsize>(result.state.size()));
      f.close();
      ASSERT_TRUE(f.good());
      manifest << filename << '\n';
      manifest.flush();
      ASSERT_TRUE(manifest.good());
      std::cout<<"ALLOC,"<<scenario<<","<<point<<","<<result.requests<<","<<result.threw<<","<<result.leaks.size();
      for(auto size:result.leaks)std::cout<<","<<size;std::cout<<"\n";
    };
    save(0,success);
    for(std::size_t point=1;point<=success.requests;++point) {
      SCOPED_TRACE(std::to_string(scenario)+"/"+std::to_string(point));
      auto result=RunAllocationScenario(device,scenario,point);
      EXPECT_TRUE(result.threw);EXPECT_EQ(result.requests,point);save(point,result);++injected;
    }
  }
  EXPECT_GT(injected,50U);std::cout<<"ALLOCATION_FAILURE_POINTS="<<injected<<"\n";
}
}
