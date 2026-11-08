// Real production scalar sidecar, containers, payload structs, and selected
// complete definitions; graphics and unrelated world collaborators are adapters.
#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include "platform/LayoutAsserts.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "legacy/containers/AutoPtr.h"
#include "moho/misc/CountedObject.h"
#undef static_assert
#include "platform/posix/win32/Windows.h"
#include "legacy/containers/String.cpp"
#include "moho/particles/ParticlePoolStats.h"
#include "Wm3Vector3.h"

namespace host {
inline bool failNothrow=false;
inline std::vector<std::string> events, logs;
inline std::function<void()> logger;
inline int logAttempts=0;
}
// Only the explicit nothrow session allocation is fault-injected. Ordinary new,
// allocator behavior, legacy container internals, and deletes remain unchanged.
void* operator new(std::size_t size,const std::nothrow_t&) noexcept {
  if(host::failNothrow) {host::failNothrow=false; return nullptr;}
  try {return ::operator new(size);} catch(...) {return nullptr;}
}
void operator delete(void* ptr,const std::nothrow_t&) noexcept {::operator delete(ptr);}
namespace gpg {
void Logf(const char* format,...) {
  ++host::logAttempts; host::events.push_back("log");
  char output[1024]; va_list args; va_start(args,format); std::vsnprintf(output,sizeof(output),format,args); va_end(args);
  host::logs.emplace_back(output);
  if(host::logger) host::logger();
}
}
namespace moho {
struct CParticleTexture {
  using TextureResourceHandle=std::shared_ptr<int>;
  int references=0;
  void AddReferenceAtomic() noexcept {++references;}
  bool ReleaseReferenceAtomic() noexcept {--references; return false;}
};
using CountedPtr_CParticleTexture=CountedPtr<CParticleTexture>;
class CWorldParticles;
struct ID3DVertexSheet;
}
#include "Payload.inc"
namespace host {const bool sourceDefaultLargePools=moho::ren_LargeParticlePools;}
namespace moho {
struct ID3DVertexStream {
  struct LockCall {int first,count; bool noOverwrite,discard;};
  std::vector<float> bytes=std::vector<float>(400*13,0);
  std::vector<LockCall> locks;
  bool fail=false; int unlocks=0;
  void* Lock(int first,int count,bool noOverwrite,bool discard) {
    locks.push_back({first,count,noOverwrite,discard});
    if(first<0 || count<0 || first+count>400) throw std::out_of_range("trail adapter vertex bounds");
    if(fail) return nullptr;
    return bytes.data()+first*13;
  }
  void Unlock() {++unlocks;}
};
struct ID3DVertexSheet {
  ID3DVertexStream stream;
  ID3DVertexStream* GetVertStream(unsigned lane) {if(lane) throw std::out_of_range("stream lane"); return &stream;}
};
struct CD3DVertexFormat {};
struct ID3DDeviceResources {
  int created=0,failAt=-1;
  CD3DVertexFormat format;
  CD3DVertexFormat* GetVertexFormat(int token) {if(token!=12) throw std::invalid_argument("format"); return &format;}
  ID3DVertexSheet* NewVertexSheet(unsigned usage,int frequency,CD3DVertexFormat* f) {
    if(created==failAt) throw std::runtime_error("injected trail resource creation failure");
    if(usage!=1 || frequency!=400 || f!=&format) throw std::invalid_argument("resource contract");
    ++created; return new ID3DVertexSheet;
  }
};
struct CD3DDevice {ID3DDeviceResources resources; ID3DDeviceResources* GetResources(){return &resources;}};
inline CD3DDevice device;
inline CD3DDevice* D3D_GetDevice(){return &device;}
struct ParticleBuffer {
  int mMaxParticles=0; bool mInitialized=false;
  std::shared_ptr<int> mVertexFormat,mQuadVertexBuffer,mInstanceVertexBuffer,mQuadIndexBuffer;
  void Shutdown(); void Reset();
};
// Particle bucket contents are not exercised in this independent trail suite.
struct SParticleRenderBucket {};
inline void DestroyParticleRenderBucket(SParticleRenderBucket&) {throw std::logic_error("unexpected particle lane");}
inline void ResetParticleBucketKeyResources(int&) {}
inline void ResetTrailBucketKeyResources(int&) {}
struct CWorldParticles {
  fa::list<ParticleBuffer*> mAvailableParticleBuffers,mParticleBuffers;
  TrailSegmentPool mTrailSegmentPool;
  fa::map<int,SParticleRenderBucket*> mParticleBuckets,mRefractingParticleBuckets;
  fa::map<int,STrailRenderBucket*> mTrailBuckets;
  struct {fa::map<int,int> mBuckets;} mBeams;
  void* mCachedParticleBucket=nullptr; void* mCachedTrailBucket=nullptr;
  int mParticleBucketLookupKey=0,mTrailBucketLookupKey=0,mBeatsSincePause=0;
  bool mInstantiated=false;
  void Init(); void ClearRenderBuckets(); void BeginPoolStatsSession() noexcept;
  const fa::list<ParticleBuffer*>& PooledBuffers() const noexcept {return mParticleBuffers;}
  ParticleBuffer* AcquireParticleBuffer(); void ReleaseParticleBuffer(ParticleBuffer*);
  STrailSegmentBuffer* AcquireTrailSegmentBuffer(); void ReleaseTrailSegmentBuffer(STrailSegmentBuffer*);
};
inline CWorldParticles sWorldParticles;
inline std::shared_ptr<int> sSharedTrailQuadIndexSheet;
inline bool RebuildSharedTrailQuadIndexSheet(){sSharedTrailQuadIndexSheet=std::make_shared<int>(1); return true;}
void ResetParticleRenderWorkItemIntervals(SParticleRenderWorkItem&);
void DestroyWorldParticlesSingleton();
}
#include "Production.inc"
static_assert(sizeof(STrailVertex)==13*sizeof(float));

namespace LuaPlus {struct LuaState {};}
namespace moho {
struct RRuleGameRules {}; struct CWldMap {}; struct SWldSessionInfo {};
struct SSyncData {int dropped=0;};
struct CWldSession {
  inline static bool throwConstruction=false;
  inline static int destroyed=0;
  CWldSession(fa::auto_ptr<LuaPlus::LuaState>&,fa::auto_ptr<RRuleGameRules>&,fa::auto_ptr<CWldMap>&,SWldSessionInfo&) {
    host::events.push_back("construct"); if(throwConstruction) throw std::runtime_error("constructor failure");
  }
  ~CWldSession(){++destroyed;host::events.push_back("delete_session");}
  void DoBeat(fa::auto_ptr<SSyncData> data){host::events.push_back("beat"); particlePoolStats.DropTrailSegments(data->dropped);}
};
inline CWldSession* gActiveWldSession=nullptr;
struct SimDriver {
  std::deque<SSyncData*> queue;
  ~SimDriver(){for(auto* p:queue) delete p;}
  void ShutDown(){host::events.push_back("shutdown");}
  bool HasSyncData(){return !queue.empty();}
  void GetSyncData(SSyncData*& out){out=queue.front();queue.pop_front();}
};
inline std::unique_ptr<SimDriver> sSimDriver;
enum class EReplaySimSwap {None,Other};
inline EReplaySimSwap sReplaySimSwap=EReplaySimSwap::Other;
inline fa::vector<SSyncData*> sReplayHeldBeats;
inline void DropEarlySim(){host::events.push_back("drop_early");}
inline void REPLAY_OnTeardown(){host::events.push_back("replay_teardown");}
struct Sound {void StopAllSounds(){host::events.push_back("sound");}};
inline Sound* USER_GetSound(){static Sound s;return &s;}
inline int WLD_GetOnTeardownCallbacks(){return 0;}
inline int DoTeardownCallbacks(int){host::events.push_back("callbacks");return 0;}
struct UIProvider {void DestroyGameInterface(){host::events.push_back("destroy_ui");}};
inline UIProvider* sWldUIProvider=nullptr;
struct UIManager {int SetNewLuaState(void*){host::events.push_back("lua_clear");return 0;}};
inline UIManager uiManager; inline UIManager* g_UIManager=&uiManager;
enum class EWldFrameAction {Inactive,Other}; inline EWldFrameAction gWldFrameAction=EWldFrameAction::Other;
}
#include "Lifecycle.inc"
#include "SourceContracts.inc"
using namespace moho;

namespace {
class StatsHost : public testing::Test {
protected:
  void SetUp() override {
    host::logger={}; host::logs.clear();host::events.clear();host::logAttempts=0;host::failNothrow=false;
    particlePoolStats={}; device.resources.created=0;device.resources.failAt=-1; ren_LargeParticlePools=1;
    CWldSession::throwConstruction=false;CWldSession::destroyed=0;
  }
  void TearDown() override {
    host::logger={}; if(gActiveWldSession) {delete gActiveWldSession;gActiveWldSession=nullptr;}
    sSimDriver.reset();delete sWldUIProvider;sWldUIProvider=nullptr;
    for(auto* held:sReplayHeldBeats) delete held; sReplayHeldBeats.clear();
    sWorldParticles.ClearRenderBuckets();DestroyWorldParticlesSingleton();particlePoolStats={};
  }
  void SmallPool(int count) {
    sWorldParticles.mInstantiated=true;
    for(int i=0;i<count;++i) {
      auto* b=new STrailSegmentBuffer; b->maxSegments=100; b->vertexSheet=new ID3DVertexSheet;
      sWorldParticles.mTrailSegmentPool.insert(b);particlePoolStats.AddTrailBuffer();
    }
  }
  STrailRenderBucket& Bucket(int key=0) {
    auto* bucket=new STrailRenderBucket;bucket->owner=&sWorldParticles;sWorldParticles.mTrailBuckets[key]=bucket; return *bucket;
  }
  void Pending(STrailRenderBucket& b,std::size_t count,float life=100) {
    for(std::size_t i=0;i<count;++i) {
      SWorldTrail t;t.mStartPos={1,2,3};t.mEndPos={4,5,6};t.mStartTangent={7,8,9};t.mEndTangent={10,11,12};
      t.mLifetime=life;t.mStartAge=0;t.mEndAge=0;t.mSize=2;b.pendingTrails.push_back(t);
    }
  }
  ParticlePoolSessionStats End() {auto s=particlePoolStats.EndSession();EXPECT_TRUE(s);return s.value_or(ParticlePoolSessionStats{});}
  CWldSession* Create() {
    fa::auto_ptr<LuaPlus::LuaState> state;fa::auto_ptr<RRuleGameRules> rules;fa::auto_ptr<CWldMap> map;SWldSessionInfo info;
    return WLD_CreateSession(state,rules,map,info);
  }
};
TEST_F(StatsHost,InactiveCallsDoNotContaminateNextSession) {
  particlePoolStats.DropParticles(3);particlePoolStats.DropTrailSegments(7);particlePoolStats.DiscardPendingTrailUpload(8);
  EXPECT_FALSE(particlePoolStats.EndSession());particlePoolStats.BeginSession();auto s=End();
  EXPECT_EQ(s.particlesPoolDropped,0u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,0u);
  particlePoolStats.DropParticles(9);particlePoolStats.BeginSession();EXPECT_EQ(End().particlesPoolDropped,0u);
}
TEST_F(StatsHost,ZeroActivitySessionAndRepeatedEnd) {
  particlePoolStats.BeginSession();auto s=End();EXPECT_EQ(s.particleBuffersPeak,0u);EXPECT_EQ(s.trailBuffersPeak,0u);
  EXPECT_FALSE(particlePoolStats.EndSession());EndParticlePoolStatsSession();EXPECT_EQ(host::logAttempts,0);
}
TEST_F(StatsHost,NextSessionRetainsCapacityButResetsSessionCounters) {
  particlePoolStats.SetParticleCapacity(400);SmallPool(2);particlePoolStats.BeginSession();
  particlePoolStats.ObserveTrailAcquire(0);particlePoolStats.DropTrailSegments(7);auto first=End();EXPECT_EQ(first.trailBuffersPeak,2u);
  particlePoolStats.BeginSession();auto second=End();EXPECT_EQ(second.particleBuffersCapacity,400u);EXPECT_EQ(second.trailBuffersCapacity,2u);
  EXPECT_EQ(second.trailBuffersPeak,0u);EXPECT_EQ(second.trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,RepeatedBeginPreservesPeaksAndLosses) {
  SmallPool(3);sWorldParticles.BeginPoolStatsSession();particlePoolStats.ObserveTrailAcquire(0);particlePoolStats.DropTrailSegments(9);
  sWorldParticles.BeginPoolStatsSession();auto s=End();EXPECT_EQ(s.trailBuffersPeak,3u);EXPECT_EQ(s.trailSegmentsPoolDropped,9u);
}
TEST_F(StatsHost,InconsistentCountsDoNotUnderflow) {
  particlePoolStats.BeginSession();particlePoolStats.ObserveParticleAcquire(1,2);particlePoolStats.ObserveTrailAcquire(1);
  auto s=End();EXPECT_EQ(s.particleBuffersPeak,0u);EXPECT_EQ(s.trailBuffersPeak,0u);
}
TEST_F(StatsHost,CumulativeCountersDoNotWrapAtSizeTLimit) {
  particlePoolStats.BeginSession();
  const auto maximum=std::numeric_limits<std::size_t>::max();
  particlePoolStats.DropParticles(maximum);particlePoolStats.DropParticles(1);
  particlePoolStats.DropTrailSegments(maximum);particlePoolStats.DropTrailSegments(1);
  particlePoolStats.DiscardPendingParticleUpload(maximum);particlePoolStats.DiscardPendingParticleUpload(1);
  particlePoolStats.DiscardPendingTrailUpload(maximum);particlePoolStats.DiscardPendingTrailUpload(1);
  const auto s=End();
  constexpr bool reachesCounterLimit =
    std::numeric_limits<std::size_t>::digits >= std::numeric_limits<std::uint64_t>::digits;
  std::uint64_t expected;
  if constexpr (reachesCounterLimit) {
    expected=std::numeric_limits<std::uint64_t>::max();
  } else {
    expected=static_cast<std::uint64_t>(maximum)+1U;
  }
  EXPECT_EQ(s.particlesPoolDropped,expected);
  EXPECT_EQ(s.trailSegmentsPoolDropped,expected);
  EXPECT_EQ(s.pendingParticlesUploadDiscarded,expected);
  EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,expected);
  EXPECT_EQ(s.saturated,reachesCounterLimit);
}
TEST_F(StatsHost,AcquireReleaseReacquirePreservesPeak) {
  SmallPool(3);sWorldParticles.BeginPoolStatsSession();auto* a=sWorldParticles.AcquireTrailSegmentBuffer();auto* b=sWorldParticles.AcquireTrailSegmentBuffer();
  sWorldParticles.ReleaseTrailSegmentBuffer(a);auto* c=sWorldParticles.AcquireTrailSegmentBuffer();
  sWorldParticles.ReleaseTrailSegmentBuffer(b);sWorldParticles.ReleaseTrailSegmentBuffer(c);auto s=End();EXPECT_EQ(s.trailBuffersPeak,2u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,EmptyAcquireWithoutDiscardIsNotLoss) {
  sWorldParticles.BeginPoolStatsSession();EXPECT_EQ(sWorldParticles.AcquireTrailSegmentBuffer(),nullptr);
  auto s=End();EXPECT_EQ(s.trailBuffersPeak,0u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,TrailPressureCountsSegmentsNotVertices) {
  SmallPool(2);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,205);
  EXPECT_FALSE(EnsureAndFillTrailBucketWorkItems(b,0));EXPECT_TRUE(b.pendingTrails.empty());ASSERT_EQ(b.activeWorkItems.size(),2u);
  EXPECT_EQ(b.activeWorkItems[0]->mIntervals.size(),100u);EXPECT_EQ(b.activeWorkItems[1]->mIntervals.size(),100u);
  auto s=End();EXPECT_EQ(s.trailBuffersPeak,2u);EXPECT_EQ(s.trailSegmentsPoolDropped,5u);EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,0u);
}
TEST_F(StatsHost,PartialTailDropsOnlyRemainingSegments) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,97);EXPECT_TRUE(EnsureAndFillTrailBucketWorkItems(b,0));
  Pending(b,8);EXPECT_FALSE(EnsureAndFillTrailBucketWorkItems(b,1));auto* buffer=static_cast<STrailSegmentBuffer*>(b.activeWorkItems[0]->mParticleBuffer);
  ASSERT_EQ(buffer->vertexSheet->stream.locks.size(),2u);EXPECT_EQ(buffer->vertexSheet->stream.locks[1].first,388);EXPECT_EQ(buffer->vertexSheet->stream.locks[1].count,12);
  auto s=End();EXPECT_EQ(s.trailSegmentsPoolDropped,5u);EXPECT_EQ(s.trailBuffersPeak,1u);
}
TEST_F(StatsHost,NullBufferCountsAllPendingSeparatelyAndClearsPriorIntervals) {
  particlePoolStats.BeginSession();auto& b=Bucket();Pending(b,7);
  SParticleRenderWorkItem work;work.mIntervalCapacityHint=100;work.mIntervals.push_back({0,100});work.mRenderStartIndex=1;
  EXPECT_FALSE(UploadPendingTrailsIntoWorkItem(work,0,b.pendingTrails));EXPECT_TRUE(work.mIntervals.empty());EXPECT_EQ(work.mRenderStartIndex,0u);
  auto s=End();EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,7u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,NullLockCountsPendingNotPriorIntervalsOrVertices) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,97);EXPECT_TRUE(EnsureAndFillTrailBucketWorkItems(b,0));
  auto* buffer=static_cast<STrailSegmentBuffer*>(b.activeWorkItems[0]->mParticleBuffer);buffer->vertexSheet->stream.fail=true;Pending(b,8);
  EXPECT_TRUE(EnsureAndFillTrailBucketWorkItems(b,0));EXPECT_TRUE(b.activeWorkItems[0]->mIntervals.empty());
  auto s=End();EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,8u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,ZeroPendingAndFullWorkItemAreNotUploadDiscard) {
  particlePoolStats.BeginSession();fa::vector<SWorldTrail> pending;SParticleRenderWorkItem work;work.mIntervalCapacityHint=0;
  EXPECT_FALSE(UploadPendingTrailsIntoWorkItem(work,0,pending));pending.push_back(SWorldTrail{});
  EXPECT_TRUE(UploadPendingTrailsIntoWorkItem(work,0,pending));EXPECT_EQ(pending.size(),1u);auto s=End();EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,0u);
}
TEST_F(StatsHost,SuccessfulUploadPacksFourVerticesPerSegment) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,1);EXPECT_TRUE(EnsureAndFillTrailBucketWorkItems(b,3));
  auto* buffer=static_cast<STrailSegmentBuffer*>(b.activeWorkItems[0]->mParticleBuffer);auto& stream=buffer->vertexSheet->stream;
  ASSERT_EQ(stream.locks.size(),1u);EXPECT_EQ(stream.locks[0].count,4);EXPECT_EQ(stream.unlocks,1);EXPECT_EQ(buffer->mappedVertexData,nullptr);
  auto* vertices=reinterpret_cast<const STrailVertex*>(stream.bytes.data());EXPECT_EQ(vertices[0].position.x,1);EXPECT_EQ(vertices[1].position.x,4);
  EXPECT_EQ(vertices[0].tangent.x,-7);EXPECT_EQ(vertices[3].tangent.x,7);EXPECT_EQ(vertices[0].age,4);EXPECT_EQ(vertices[0].lifetime,100);
  EXPECT_EQ(End().trailSegmentsPoolDropped,0u);
}
TEST_F(StatsHost,ExpiryReturnsBuffersWithoutLoss) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,1,1);EnsureAndFillTrailBucketWorkItems(b,0);
  PruneExpiredTrailBucketWorkItems(b,2);EXPECT_EQ(b.activeWorkItems.size(),1u);PruneExpiredTrailBucketWorkItems(b,3);EXPECT_TRUE(b.activeWorkItems.empty());
  EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),1u);auto s=End();EXPECT_EQ(s.trailSegmentsPoolDropped,0u);EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,0u);
}
TEST_F(StatsHost,ReplayStyleClearPreservesSessionAndAllowsContinuedCollection) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,103);EnsureAndFillTrailBucketWorkItems(b,0);Pending(b,8);
  sWorldParticles.ClearRenderBuckets();EXPECT_EQ(host::logAttempts,0);EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),1u);
  auto& next=Bucket(1);Pending(next,104);EnsureAndFillTrailBucketWorkItems(next,0);auto s=End();EXPECT_EQ(s.trailSegmentsPoolDropped,7u);
  EXPECT_EQ(s.pendingTrailSegmentsUploadDiscarded,0u);EXPECT_EQ(s.trailBuffersCapacity,1u);
}
TEST_F(StatsHost,PoolDestroyKeepsCurrentSummaryButClearsFutureMetadata) {
  SmallPool(1);sWorldParticles.BeginPoolStatsSession();auto& b=Bucket();Pending(b,102);EnsureAndFillTrailBucketWorkItems(b,0);
  sWorldParticles.ClearRenderBuckets();DestroyWorldParticlesSingleton();DestroyWorldParticlesSingleton();auto s=End();
  EXPECT_EQ(s.trailBuffersCapacity,1u);EXPECT_EQ(s.trailBuffersPeak,1u);EXPECT_EQ(s.trailSegmentsPoolDropped,2u);
  sWorldParticles.BeginPoolStatsSession();auto next=End();EXPECT_EQ(next.trailBuffersCapacity,0u);EXPECT_EQ(next.trailBuffersPeak,0u);
}
TEST_F(StatsHost,LegacyInitUsesRealizedCapacityAndPersistsAcrossSessions) {
  ren_LargeParticlePools=0;sWorldParticles.BeginPoolStatsSession();sWorldParticles.Init();
  EXPECT_EQ(sWorldParticles.mParticleBuffers.size(),400u);EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),100u);
  auto first=End();EXPECT_EQ(first.particleBuffersCapacity,400u);EXPECT_EQ(first.trailBuffersCapacity,100u);
  ren_LargeParticlePools=1;sWorldParticles.Init();sWorldParticles.BeginPoolStatsSession();auto next=End();
  EXPECT_EQ(next.particleBuffersCapacity,400u);EXPECT_EQ(next.trailBuffersCapacity,100u);
}
TEST_F(StatsHost,LargeInitKeepsExistingDefaultCaps) {
  sWorldParticles.Init();sWorldParticles.BeginPoolStatsSession();auto s=End();
  EXPECT_EQ(s.particleBuffersCapacity,4096u);EXPECT_EQ(s.trailBuffersCapacity,400u);EXPECT_EQ(s.trailBuffersPeak,0u);
}
TEST_F(StatsHost,PartialTrailInitializationRecordsEachSuccessfulInsert) {
  ren_LargeParticlePools=0;device.resources.failAt=3;sWorldParticles.BeginPoolStatsSession();EXPECT_THROW(sWorldParticles.Init(),std::runtime_error);
  EXPECT_TRUE(sWorldParticles.mInstantiated);EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),3u);
  auto& b=Bucket();Pending(b,301);EXPECT_FALSE(EnsureAndFillTrailBucketWorkItems(b,0));auto s=End();
  EXPECT_EQ(s.trailBuffersCapacity,3u);EXPECT_EQ(s.trailBuffersPeak,3u);EXPECT_EQ(s.trailSegmentsPoolDropped,1u);EXPECT_EQ(s.particleBuffersCapacity,400u);
}
TEST_F(StatsHost,NextSessionSeedsInheritedUnavailableAndExhaustedPools) {
  ren_LargeParticlePools=0;sWorldParticles.Init();sWorldParticles.BeginPoolStatsSession();
  std::vector<STrailSegmentBuffer*> held;while(auto* b=sWorldParticles.AcquireTrailSegmentBuffer()) held.push_back(b);
  auto* particle=sWorldParticles.AcquireParticleBuffer();End();sWorldParticles.BeginPoolStatsSession();
  EXPECT_EQ(sWorldParticles.AcquireTrailSegmentBuffer(),nullptr);auto s=End();
  EXPECT_EQ(s.trailBuffersPeak,100u);EXPECT_EQ(s.particleBuffersPeak,1u);EXPECT_EQ(s.trailSegmentsPoolDropped,0u);
  for(auto* b:held) sWorldParticles.ReleaseTrailSegmentBuffer(b);sWorldParticles.ReleaseParticleBuffer(particle);
}
TEST_F(StatsHost,DeviceResetDropsGpuHandlesWithoutResettingStatistics) {
  ren_LargeParticlePools=false;sWorldParticles.Init();sWorldParticles.BeginPoolStatsSession();
  auto* p=sWorldParticles.AcquireParticleBuffer();p->mInitialized=true;p->mInstanceVertexBuffer=std::make_shared<int>(7);
  particlePoolStats.DropParticles(5);particlePoolStats.DropTrailSegments(9);ResetWorldParticleBuffers();
  EXPECT_FALSE(p->mInitialized);EXPECT_FALSE(p->mInstanceVertexBuffer);EXPECT_EQ(p->mMaxParticles,200);
  auto s=End();EXPECT_EQ(s.particleBuffersPeak,1u);EXPECT_EQ(s.particleBuffersCapacity,400u);EXPECT_EQ(s.trailBuffersCapacity,100u);
  EXPECT_EQ(s.particlesPoolDropped,5u);EXPECT_EQ(s.trailSegmentsPoolDropped,9u);EXPECT_EQ(host::logAttempts,0);
  sWorldParticles.ReleaseParticleBuffer(p);
}
TEST_F(StatsHost,SessionLoggerPublishesOnceWithNamedMetrics) {
  particlePoolStats.BeginSession();particlePoolStats.DropParticles(2);particlePoolStats.DropTrailSegments(3);
  particlePoolStats.DiscardPendingParticleUpload(4);particlePoolStats.DiscardPendingTrailUpload(5);EndParticlePoolStatsSession();EndParticlePoolStatsSession();
  ASSERT_EQ(host::logs.size(),1u);EXPECT_NE(host::logs[0].find("pool drops particles=2 trail_segments=3"),std::string::npos);
  EXPECT_NE(host::logs[0].find("upload discards pending_particles=4 pending_trail_segments=5"),std::string::npos);EXPECT_NE(host::logs[0].find("saturated=0"),std::string::npos);
}
TEST_F(StatsHost,ThrowingLoggerCannotEscapeOrRepeatSummary) {
  particlePoolStats.BeginSession();host::logger=[] {throw std::runtime_error("logger failure");};
  EXPECT_NO_THROW(EndParticlePoolStatsSession());EndParticlePoolStatsSession();EXPECT_EQ(host::logAttempts,1);EXPECT_FALSE(particlePoolStats.EndSession());
}
TEST_F(StatsHost,ReentrantLoggerCannotDuplicateCurrentSession) {
  particlePoolStats.BeginSession();host::logger=[] {EndParticlePoolStatsSession();};
  EndParticlePoolStatsSession();EXPECT_EQ(host::logAttempts,1);EXPECT_FALSE(particlePoolStats.EndSession());
}
TEST_F(StatsHost,SuccessfulCreateBeginsAndDestroyIsIdempotent) {
  ASSERT_NE(Create(),nullptr);particlePoolStats.DropTrailSegments(4);WLD_DestroySession();WLD_DestroySession();
  EXPECT_EQ(CWldSession::destroyed,1);EXPECT_EQ(gActiveWldSession,nullptr);ASSERT_EQ(host::logs.size(),1u);EXPECT_NE(host::logs[0].find("trail_segments=4"),std::string::npos);
}
TEST_F(StatsHost,ConstructorFailureDoesNotBeginSession) {
  CWldSession::throwConstruction=true;EXPECT_THROW(Create(),std::runtime_error);particlePoolStats.DropTrailSegments(7);EndParticlePoolStatsSession();
  EXPECT_EQ(host::logAttempts,0);EXPECT_EQ(gActiveWldSession,nullptr);EXPECT_FALSE(particlePoolStats.EndSession());
}
TEST_F(StatsHost,AllocationFailureDoesNotBeginSession) {
  host::failNothrow=true;EXPECT_EQ(Create(),nullptr);EXPECT_FALSE(host::failNothrow);EndParticlePoolStatsSession();
  EXPECT_EQ(host::logAttempts,0);EXPECT_EQ(gActiveWldSession,nullptr);EXPECT_EQ(CWldSession::destroyed,0);
}
TEST_F(StatsHost,TeardownIncludesFinalDrainThenLogsBeforeDestruction) {
  SmallPool(1);ASSERT_NE(Create(),nullptr);auto& b=Bucket();Pending(b,102);EnsureAndFillTrailBucketWorkItems(b,0);
  host::logger=[] {EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),0u);};
  sSimDriver=std::make_unique<SimDriver>();sSimDriver->queue.push_back(new SSyncData{7});sSimDriver->queue.push_back(new SSyncData{8});
  sReplayHeldBeats.push_back(new SSyncData{99});sWldUIProvider=new UIProvider;
  WLD_Teardown();WLD_DestroySession();ASSERT_EQ(host::logs.size(),1u);EXPECT_NE(host::logs[0].find("trail_segments=17"),std::string::npos);
  auto pos=[](const char* e){return std::find(host::events.begin(),host::events.end(),e)-host::events.begin();};
  EXPECT_LT(pos("beat"),pos("log"));EXPECT_LT(pos("destroy_ui"),pos("log"));EXPECT_LT(pos("log"),pos("lua_clear"));EXPECT_LT(pos("log"),pos("delete_session"));
  EXPECT_EQ(sWorldParticles.mTrailSegmentPool.size(),1u);
  EXPECT_EQ(CWldSession::destroyed,1);EXPECT_EQ(sReplaySimSwap,EReplaySimSwap::None);EXPECT_EQ(gWldFrameAction,EWldFrameAction::Inactive);EXPECT_FALSE(sSimDriver);
}
TEST_F(StatsHost,FullRestartPublishesOneSummaryPerSuccessfulCreate) {
  ASSERT_NE(Create(),nullptr);particlePoolStats.DropTrailSegments(11);WLD_Teardown();ASSERT_NE(Create(),nullptr);particlePoolStats.DropTrailSegments(2);WLD_Teardown();
  ASSERT_EQ(host::logs.size(),2u);EXPECT_NE(host::logs[0].find("trail_segments=11"),std::string::npos);EXPECT_NE(host::logs[1].find("trail_segments=2"),std::string::npos);
}
TEST_F(StatsHost,RepeatedTeardownWithoutSessionDoesNotLog) {
  WLD_Teardown();WLD_Teardown();WLD_DestroySession();EXPECT_EQ(host::logAttempts,0);
}
TEST(StatsStaticContract,ProductionLargePoolDefaultIsEnabled) {EXPECT_TRUE(host::sourceDefaultLargePools);}
TEST(StatsStaticContract,ReplayResetCallsClearWithoutStatsBoundary) {
  const std::string source=source_contracts::replay_reset;EXPECT_NE(source.find("ClearRenderBuckets"),std::string::npos);
  EXPECT_EQ(source.find("EndParticlePoolStatsSession"),std::string::npos);EXPECT_EQ(source.find("BeginPoolStatsSession"),std::string::npos);EXPECT_EQ(source.find("particlePoolStats"),std::string::npos);
}
TEST(StatsStaticContract,SidecarIsFixedScalarStorageWithoutHotAllocations) {
  RecordProperty("stats_size_bytes",static_cast<int>(sizeof(ParticlePoolStats)));
  RecordProperty("summary_size_bytes",static_cast<int>(sizeof(ParticlePoolSessionStats)));
  EXPECT_TRUE(std::is_trivially_copyable_v<ParticlePoolStats>);EXPECT_LE(sizeof(ParticlePoolStats),128u);
  std::string source=source_contracts::stats_header;
  for(const char* forbidden:{"new ","malloc(","std::vector","std::map","std::mutex","std::atomic","Logf(","for (","while ("}) EXPECT_EQ(source.find(forbidden),std::string::npos)<<forbidden;
}
} // namespace
