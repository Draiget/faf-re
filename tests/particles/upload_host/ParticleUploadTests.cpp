// Source-bound host checks for pending particle upload. Graphics operations and
// texture destruction use synchronous adapters; this is not a GPU/game test.
#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <type_traits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>
// Match the repository's host/x64 layout configuration only around its container header.
#include "platform/LayoutAsserts.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/String.h"
#include "moho/misc/CountedObject.h"
#undef static_assert
#include "platform/posix/win32/Windows.h"
#include "legacy/containers/String.cpp"
#include "gpg/gal/GpuDriven.h"

namespace boost { template<class T> using shared_ptr = std::shared_ptr<T>; }
#ifndef _WIN32
// Only the diagnostic environment lookup is platform-adapted. Tests require
// ordinary batching, not either diagnostic render mode.
inline int getenv_s(std::size_t* length, char* value, std::size_t size, const char* name)
{
  const char* found = std::getenv(name);
  *length = found != nullptr ? std::strlen(found) + 1U : 0U;
  if (*length > size) return 34;
  if (found != nullptr) std::memcpy(value, found, *length);
  else if (size != 0U) value[0] = '\0';
  return 0;
}
#endif
namespace gpg::gal {
struct VertexBufferContext { std::uint32_t type_=0, usage_=0, stride_=0, vertexCount_=0; };
struct VertexBuffer {
  explicit VertexBuffer(const VertexBufferContext& context) : context(context), bytes(context.stride_ * context.vertexCount_, 0xCD) {}
  VertexBufferContext context;
  std::vector<std::uint8_t> bytes;
};
struct Copy {
  const VertexBuffer* source;
  const VertexBuffer* destination;
  std::uint32_t sourceOffset, destinationOffset, bytes;
  bool success;
};
struct Draw {
  const VertexBuffer* source;
  int first, count;
  bool original;
  std::vector<std::uint8_t> bytes;
};
struct Device {
  inline static Device* current = nullptr;
  std::vector<Copy> copies;
  std::vector<Draw> draws;
  std::function<bool(const Copy&)> failCopy;
  static Device* GetInstance() { return current; }
  std::uint32_t GetGpuDrivenFeatures() const { return kGpuFeatureBufferCopy; }
  std::uint32_t GetGpuDrivenVerified() const { return kGpuPathParticleBatch; }
  boost::shared_ptr<VertexBuffer> CreateVertexBuffer(const VertexBufferContext* context) {
    return std::make_shared<VertexBuffer>(*context);
  }
  bool CopyVertexBufferRegion(VertexBuffer& to, std::uint32_t toOffset, const VertexBuffer& from,
                              std::uint32_t fromOffset, std::uint32_t size) {
    if (toOffset > to.bytes.size() || size > to.bytes.size()-toOffset ||
        fromOffset > from.bytes.size() || size > from.bytes.size()-fromOffset)
      throw std::out_of_range("production requested an out-of-bounds vertex copy");
    Copy call{&from, &to, fromOffset, toOffset, size, true};
    call.success = !failCopy || !failCopy(call);
    copies.push_back(call);
    if (call.success) std::memcpy(to.bytes.data()+toOffset, from.bytes.data()+fromOffset, size);
    return call.success;
  }
  void RecordDraw(const boost::shared_ptr<VertexBuffer>& source, int count, int first, bool original) {
    if (first < 0 || count < 0 || static_cast<std::size_t>(first+count)*92U > source->bytes.size())
      throw std::out_of_range("production requested an out-of-bounds draw");
    const auto begin = source->bytes.begin()+first*92;
    draws.push_back({source.get(), first, count, original, {begin, begin+count*92}});
  }
};
struct RenderProfileScope { explicit RenderProfileScope(const char*) {} };
}
inline constexpr int kParticleBufferCapacity = 200;
inline constexpr std::uint32_t kTrailSegmentCapacity = 100;
namespace moho {
struct GeomCamera3 {};
struct ID3DRenderTarget {};
struct CD3DDevice { void SelectFxFile(const char*) {} void SetColorWriteState(bool,bool) {} };
inline CD3DDevice* D3D_GetDevice() { static CD3DDevice d; return &d; }
inline void BindParticleCameraShaderState(GeomCamera3*,int,float) {}
inline void DrawBeamParticle(int,float,bool) {}
inline float efx_ParticleWaterSurface = 0;
struct BackgroundVar {
  bool Exists() const { return false; }
  void SetRenderTargetTexture(const boost::shared_ptr<ID3DRenderTarget>&) {}
};
inline BackgroundVar shaderVarParticleBackgroundTexture;
// Data fields used by the unchanged upload function. Resource handles and
// shader selection are outside this recorder's verification boundary.
struct CParticleTexture {
  std::atomic<int> references{0};
  inline static std::uint64_t retains=0, releases=0;
  bool deleteOnZero=false;
  int id=-1;
  std::vector<int>* retireLog=nullptr;
  void AddReferenceAtomic() noexcept { ++references; ++retains; }
  bool ReleaseReferenceAtomic() noexcept {
    const int left=--references; ++releases;
    if(left<0) std::abort();
    if(left==0 && deleteOnZero) { retireLog->push_back(id); delete this; return true; }
    return false;
  }
};
using CountedPtr_CParticleTexture = CountedPtr<CParticleTexture>;
} // namespace moho
#include "Wm3Vector3.h"
namespace gpg { class ReadArchive; class WriteArchive; }
namespace moho {
#include "ParticlePayload.inc"
inline std::function<void()> beforeLock, beforeUnlock, beforeMirror, beforeAppend;
inline bool failLock=false;
struct ParticleBuffer {
  struct Instanced { std::uint8_t data[0x5C]; };
  int mMaxParticles = kParticleBufferCapacity;
  boost::shared_ptr<gpg::gal::VertexBuffer> mInstanceVertexBuffer;
  ParticleBuffer() {
    gpg::gal::VertexBufferContext context{};
    context.stride_ = sizeof(Instanced); context.vertexCount_ = mMaxParticles;
    mInstanceVertexBuffer = gpg::gal::Device::GetInstance()->CreateVertexBuffer(&context);
  }
  Instanced* Lock(int count) { return Lock(0, count); }
  Instanced* Lock(int first, int count) {
    if (beforeLock) beforeLock();
    if (failLock) return nullptr;
    if (first < 0 || count < 0 || first + count > mMaxParticles)
      throw std::out_of_range("production requested an out-of-bounds particle lock");
    return reinterpret_cast<Instanced*>(mInstanceVertexBuffer->bytes.data()+first*sizeof(Instanced));
  }
  void UnlockInstanceBuffer() { if (beforeUnlock) beforeUnlock(); }
  void Render(int count, int first) {
    gpg::gal::Device::GetInstance()->RecordDraw(mInstanceVertexBuffer, count, first, true);
  }
  void RenderInstances(const boost::shared_ptr<gpg::gal::VertexBuffer>& source, int count, int first) {
    gpg::gal::Device::GetInstance()->RecordDraw(source, count, first, false);
  }
};
struct SParticleRenderInterval { float beginFrame=0, lifeFrames=0; };
struct SParticleRenderWorkItem {
  void* mParticleBuffer=nullptr;
  fa::vector<SParticleRenderInterval> mIntervals;
  std::uint32_t mIntervalCursor=0, mRenderStartIndex=0, mIntervalCapacityHint=0;
};
struct CWorldParticles;
struct SParticleRenderBucket {
  CWorldParticles* owner;
  std::string tag = "regular";
  fa::vector<SWorldParticle> pendingParticles;
  fa::vector<SParticleRenderWorkItem*> activeWorkItems;
  void SelectTechnique() {}
};
// RenderEffects includes its trail lane, which is always empty in these tests.
// Fail if future test edits accidentally execute an unverified trail adapter.
struct STrailRenderBucket { fa::vector<int> pendingTrails; };
inline void PruneExpiredTrailBucketWorkItems(STrailRenderBucket&, float) { throw std::logic_error("trail adapter executed"); }
inline bool RenderTrailBucket(STrailRenderBucket&, float, bool) { throw std::logic_error("trail adapter executed"); }
struct Key {
  float sortScalar;
  int key;
  bool operator<(const Key& r) const { return std::tie(sortScalar,key)<std::tie(r.sortScalar,r.key); }
};
struct CWorldParticles {
  fa::list<ParticleBuffer*> mAvailableParticleBuffers;
  std::set<void*> mTrailSegmentPool;
  std::map<Key,SParticleRenderBucket*> mParticleBuckets, mRefractingParticleBuckets;
  std::map<Key,STrailRenderBucket*> mTrailBuckets;
  int mBeatsSincePause=0, mBeams=0;
  std::vector<std::unique_ptr<ParticleBuffer>> owned_p;
  std::vector<std::unique_ptr<SParticleRenderBucket>> owned_pb;
  explicit CWorldParticles(std::size_t count=0) {
    for (std::size_t i=0; i<count; ++i) {
      owned_p.push_back(std::make_unique<ParticleBuffer>());
      mAvailableParticleBuffers.push_back(owned_p.back().get());
    }
  }
  ~CWorldParticles();
  void Init() {}
  ParticleBuffer* AcquireParticleBuffer();
  void ReleaseParticleBuffer(ParticleBuffer*);
  char RenderEffects(GeomCamera3*,char,char,int,float);
  void RenderRefractingEffects(GeomCamera3*,int,float,const boost::shared_ptr<ID3DRenderTarget>&);
  SParticleRenderBucket& P(int key, float scalar=0, bool refract=false) {
    owned_pb.push_back(std::make_unique<SParticleRenderBucket>(SParticleRenderBucket{this, "regular", {}, {}}));
    (refract ? mRefractingParticleBuckets : mParticleBuckets)[{scalar,key}] = owned_pb.back().get();
    return *owned_pb.back();
  }
};
void ResetParticleRenderWorkItemIntervals(SParticleRenderWorkItem&);
SParticleRenderWorkItem* DestroyParticleRenderWorkItem(SParticleRenderWorkItem*);
SParticleRenderWorkItem* InitializeParticleRenderWorkItem(SParticleRenderWorkItem&,std::uint32_t,void*);
bool AdvanceParticleRenderWorkItemCursorToFrame(SParticleRenderWorkItem&,float);
void ForgetMirroredParticles(const ParticleBuffer&);
void MirrorUploadedParticles(ParticleBuffer&,std::uint32_t,std::uint32_t);
bool ParticleBatchActive();
inline int ren_ParticleBatch = 1;
} // namespace moho
#include "ParticleBatchProduction.inc"
static_assert(sizeof(SParticleInstance) == sizeof(moho::ParticleBuffer::Instanced));
namespace moho {
inline CWorldParticles::~CWorldParticles() {
  for (auto& bucket : owned_pb) RecycleAndDestroyParticleBucketWorkItems(*bucket);
}
inline void Pending(SParticleRenderBucket& bucket, std::size_t count, int id=1, float life=100) {
  for (std::size_t i=0; i<count; ++i) {
    SWorldParticle particle;
    particle.mPos = {static_cast<float>(id+static_cast<int>(i)), 3, 4};
    particle.mDir = {5, 6, 7}; particle.mAccel = {8, 9, 10};
    particle.mBeginSize=1; particle.mEndSize=2;
    particle.mAngle=11; particle.mRotationCurve=12; particle.mLifetime=life;
    particle.mFramerate=13; particle.mValue1=14; particle.mTextureSelection=15;
    particle.mRampSelection=16; particle.mValue3=17; particle.mResistance=2;
    bucket.pendingParticles.push_back(particle);
  }
}
inline void Active(SParticleRenderBucket& bucket, std::size_t count=1, float life=100, int id=1) {
  Pending(bucket,count,id,life);
  ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
}
inline void Pass(CWorldParticles& world, int lane=0, int tick=10) {
  if (lane == 2) world.RenderRefractingEffects(nullptr,tick,0,{});
  else (void)world.RenderEffects(nullptr,static_cast<char>(lane),false,tick,0);
}
} // namespace moho

namespace {
using namespace moho;
using gpg::gal::Copy;
using gpg::gal::VertexBuffer;
constexpr std::size_t kStride = sizeof(ParticleBuffer::Instanced);
std::vector<int> DrawnIds(const gpg::gal::Device& device) {
  std::vector<int> ids;
  for (const auto& draw : device.draws) {
    for (int i=0; i<draw.count; ++i) {
      float id=0;
      std::memcpy(&id,draw.bytes.data()+static_cast<std::size_t>(i)*kStride,sizeof(id));
      ids.push_back(static_cast<int>(id));
    }
  }
  return ids;
}
std::vector<int> Sequence(int first, int count) {
  std::vector<int> ids;
  for (int i=0; i<count; ++i) ids.push_back(first+i);
  return ids;
}
void ExpectExactBytes(const gpg::gal::Draw& draw, const ParticleBuffer& buffer, int first, int count) {
  const auto begin=buffer.mInstanceVertexBuffer->bytes.begin()+first*kStride;
  EXPECT_EQ(draw.bytes, (std::vector<std::uint8_t>{begin,begin+count*kStride}));
}
class ParticleUpload : public testing::Test {
protected:
  gpg::gal::Device device;
  void SetUp() override {
    beforeLock={}; beforeUnlock={}; beforeMirror={}; beforeAppend={}; failLock=false;
    ASSERT_EQ(std::getenv("FAF_PARTICLE_BATCH_DIAG"), nullptr) << "Unset diagnostics for ordinary batching";
    sParticleGather = {}; sParticleMirror = {};
    gpg::gal::Device::current = &device;
    const char* linear = std::getenv("PARTICLE_LINEAR_UPLOAD");
    const char* batch = std::getenv("PARTICLE_BATCH");
    ren_ParticleLinearUpload = linear != nullptr ? std::atoi(linear) : 0;
    ren_ParticleBatch = batch != nullptr ? std::atoi(batch) : 1;
    ASSERT_EQ(ParticleBatchActive(), ren_ParticleBatch != 0);
  }
  void TearDown() override {
    beforeLock={}; beforeUnlock={}; beforeMirror={}; beforeAppend={}; failLock=false;
    sParticleGather={}; sParticleMirror={}; gpg::gal::Device::current=nullptr;
  }
  void ClearTrace() { device.copies.clear(); device.draws.clear(); }
  void ExpectSlotsUnique() {
    std::set<std::uint32_t> allocated;
    for (const auto& [buffer,slot] : sParticleMirror.mSlotOf) {
      EXPECT_NE(buffer,nullptr); EXPECT_TRUE(allocated.insert(slot).second);
    }
    for (const auto slot : sParticleMirror.mFreeSlots) EXPECT_TRUE(allocated.insert(slot).second);
    EXPECT_EQ(allocated.size(),sParticleMirror.mSlotsUsed);
  }
};


static_assert(!std::is_trivially_copyable_v<SWorldParticle>);
static_assert(!std::is_nothrow_move_constructible_v<SWorldParticle>); // legacy Vector3 declaration
static_assert(!std::is_nothrow_move_assignable_v<SWorldParticle>); // audited scalar-only Vector3 body
static_assert(!std::is_nothrow_swappable_v<SWorldParticle>);
static_assert(std::is_nothrow_destructible_v<SWorldParticle>);
void Seed(SParticleRenderBucket& bucket, std::size_t n, CParticleTexture& texture, int id=1) {
  Pending(bucket,n,id);
  for (auto& p : bucket.pendingParticles) {
    p.mTexture.reset(&texture); p.mRampTexture.reset(&texture);
    p.mTypeTag.assign_owned("particle-probe-tag-long-enough-to-own-heap");
  }
}
void ResetCounts() { CParticleTexture::retains=0; CParticleTexture::releases=0; }
TEST_F(ParticleUpload, RelocationCountsAcrossBatchBoundaries) {
  for (std::size_t n : {0U,1U,199U,200U,201U,399U,400U,401U,1000U,4000U,40000U}) {
    SCOPED_TRACE(n); CParticleTexture texture;
    CWorldParticles world((n+199U)/200U); auto& bucket=world.P(0);
    Seed(bucket,n,texture); ResetCounts();
    auto begin=std::chrono::steady_clock::now();
    EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));
    auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-begin).count();
    std::uint64_t shifts=0; for (auto remaining=n; remaining>200; remaining-=200) shifts+=remaining-200;
    if (ren_ParticleLinearUpload > 0) {
      EXPECT_LE(CParticleTexture::retains,2U*n);
      EXPECT_EQ(CParticleTexture::releases,CParticleTexture::retains+2U*n);
    } else {
      EXPECT_EQ(CParticleTexture::retains,shifts*2U);
      EXPECT_EQ(CParticleTexture::releases,shifts*2U+2U*n);
    }
    EXPECT_EQ(texture.references,0); EXPECT_TRUE(bucket.pendingParticles.empty());
    std::cout<<"COST n="<<n<<" shifts="<<shifts<<" retain="<<CParticleTexture::retains<<" release="<<CParticleTexture::releases<<" ns="<<ns<<"\n";
    std::size_t id=1;
    for(auto* wi:bucket.activeWorkItems) {
      auto* buffer=static_cast<ParticleBuffer*>(wi->mParticleBuffer);
      for(std::size_t i=0;i<wi->mRenderStartIndex;++i) {
        SParticleInstance actual{};
        std::memcpy(&actual,buffer->mInstanceVertexBuffer->bytes.data()+92*i,92);
        EXPECT_EQ(actual.posX,static_cast<float>(id++)); EXPECT_EQ(actual.interop,7);
        EXPECT_EQ(actual.lifetime,100); EXPECT_EQ(actual.inverseResistance,0.5f);
      }
    }
    EXPECT_EQ(id,n+1);
  }
}
TEST_F(ParticleUpload, LiveFragmentationStillDropsWithoutExpiredDescriptor) {
  CParticleTexture texture; CWorldParticles world(1); auto& bucket=world.P(0);
  Seed(bucket,200,texture); ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  auto* wi=bucket.activeWorkItems[0]; wi->mIntervals[199].lifeFrames=100;
  for(int i=0;i<199;++i) wi->mIntervals[i].lifeFrames=1;
  PruneExpiredParticleBucketWorkItems(bucket,10);
  ASSERT_EQ(wi->mIntervalCursor,199U); Seed(bucket,1,texture,9000);
  EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(bucket,10));
  EXPECT_EQ(wi->mRenderStartIndex,200U); EXPECT_TRUE(bucket.pendingParticles.empty());
  EXPECT_EQ(world.mAvailableParticleBuffers.size(),0U);
}
TEST_F(ParticleUpload, ConsumedReferencesAreReleasedBeforeUnlock) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture); std::vector<int> observed;
  beforeUnlock=[&]{observed.push_back(texture.references);};
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7)); beforeUnlock={};
  EXPECT_EQ(observed,(std::vector<int>{402,2,0}));
}
TEST_F(ParticleUpload, FailedLockDropsPendingAndResetsCurrentItem) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,1,texture); ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
  Seed(bucket,401,texture); failLock=true;
  EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7)); failLock=false;
  EXPECT_EQ(texture.references,0); EXPECT_TRUE(bucket.pendingParticles.empty());
  ASSERT_EQ(bucket.activeWorkItems.size(),1U);
  EXPECT_TRUE(bucket.activeWorkItems[0]->mIntervals.empty());
  EXPECT_EQ(bucket.activeWorkItems[0]->mRenderStartIndex,0U);
}
TEST_F(ParticleUpload, ThrowFromSecondLockLeavesOnlyUnconsumedOriginalOrder) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture); int calls=0;
  beforeLock=[&]{if(++calls==2) throw std::runtime_error("lock failure");};
  EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::runtime_error); beforeLock={};
  ASSERT_EQ(bucket.pendingParticles.size(),201U); EXPECT_EQ(texture.references,402);
  for(std::size_t i=0;i<201;++i) { EXPECT_EQ(bucket.pendingParticles[i].mPos.x,201+i); EXPECT_EQ(bucket.pendingParticles[i].mInterop,0); }
}
TEST_F(ParticleUpload, ThrowFromFirstUnlockStillConsumesCompletedBatch) {
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture); beforeUnlock=[]{throw std::runtime_error("unlock failure");};
  EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::runtime_error); beforeUnlock={};
  ASSERT_EQ(bucket.pendingParticles.size(),201U); EXPECT_EQ(texture.references,402);
  EXPECT_EQ(bucket.pendingParticles[0].mPos.x,201); EXPECT_EQ(bucket.pendingParticles[0].mInterop,0);
}
TEST_F(ParticleUpload, EmptyPoolDropsWithoutMovingPayloads) {
  CParticleTexture texture; CWorldParticles world(0); auto& bucket=world.P(0);
  Seed(bucket,401,texture); ResetCounts(); EXPECT_FALSE(EnsureAndFillParticleBucketWorkItems(bucket,7));
  EXPECT_EQ(CParticleTexture::retains,0U); EXPECT_EQ(CParticleTexture::releases,802U); EXPECT_EQ(texture.references,0);
}

TEST_F(ParticleUpload, FullUploadedBytesAndIntervalsAcrossPartialTail) {
  for(int tail:{0,1,199,200}) for(int n:{0,1,199,200,201,399,400,401,4000}) {
    SCOPED_TRACE(std::to_string(tail)+"/"+std::to_string(n));
    CParticleTexture texture; CWorldParticles world(32); auto& bucket=world.P(0);
    Seed(bucket,tail,texture,10000); ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,0));
    Seed(bucket,n,texture); ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7));
    std::size_t seen=0;
    for(auto* wi:bucket.activeWorkItems) {
      auto* b=static_cast<ParticleBuffer*>(wi->mParticleBuffer);
      EXPECT_EQ(wi->mIntervals.size(),wi->mRenderStartIndex);
      for(std::size_t i=0;i<wi->mRenderStartIndex;++i,++seen) {
        float id=seen<static_cast<std::size_t>(tail)?10000+seen:seen-tail+1;
        float frame=seen<static_cast<std::size_t>(tail)?0:7;
        SParticleInstance expected{id,3,4,11,1,0.01f,5,6,7,12,8,9,10,frame,100,13,14,15,16,17,2,0.5f,0.25f};
        EXPECT_EQ(std::memcmp(b->mInstanceVertexBuffer->bytes.data()+92*i,&expected,92),0);
        EXPECT_EQ(wi->mIntervals[i].beginFrame,frame); EXPECT_EQ(wi->mIntervals[i].lifeFrames,100);
      }
    }
    EXPECT_EQ(seen,tail+n); EXPECT_EQ(texture.references,0);
  }
}
TEST_F(ParticleUpload, DifferentLastReferenceTexturesAndUniqueTagsSurviveThrow) {
  std::vector<std::unique_ptr<CParticleTexture>> textures;
  CWorldParticles world(3); auto& bucket=world.P(0);
  Pending(bucket,401);
  for(int i=0;i<802;++i) textures.push_back(std::make_unique<CParticleTexture>());
  for(int i=0;i<401;++i) {
    auto& p=bucket.pendingParticles[i]; p.mTexture.reset(textures[2*i].get()); p.mRampTexture.reset(textures[2*i+1].get());
    p.mTypeTag.assign_owned(("unique-owned-particle-tag-for-probe-"+std::to_string(i)).c_str());
  }
  beforeUnlock=[&]{
    for(int i=0;i<802;++i) EXPECT_EQ(textures[i]->references,i<400?0:1);
    throw std::runtime_error("stop after one committed batch");
  };
  EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::runtime_error); beforeUnlock={};
  ASSERT_EQ(bucket.pendingParticles.size(),201U);
  for(int i=0;i<201;++i) {
    auto& p=bucket.pendingParticles[i];
    EXPECT_EQ(p.mTexture.tex,textures[400+2*i].get()); EXPECT_EQ(p.mRampTexture.tex,textures[401+2*i].get());
    EXPECT_EQ(p.mTypeTag.view(),"unique-owned-particle-tag-for-probe-"+std::to_string(i+200));
  }
  bucket.pendingParticles.clear();
  for(auto& t:textures) EXPECT_EQ(t->references,0);
}
TEST_F(ParticleUpload, MirrorExceptionConsumesOnlyCompletedBatch) {
  // This case specifically exercises the mirror failure boundary.
  ren_ParticleBatch = 1;
  CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
  Seed(bucket,401,texture);
  device.failCopy=[](const Copy&)->bool{throw std::runtime_error("copy exception");};
  EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::runtime_error); device.failCopy={};
  ASSERT_EQ(bucket.pendingParticles.size(),201U); EXPECT_EQ(texture.references,402);
  EXPECT_EQ(bucket.pendingParticles[0].mPos.x,201); EXPECT_EQ(bucket.pendingParticles[0].mInterop,0);
}
#ifdef APPEND_HOOK
TEST_F(ParticleUpload, PartialSecondBatchAppendExceptionMatchesPendingAndIntervals) {
  for(int failAt:{201,250,400}) {
    CParticleTexture texture; CWorldParticles world(3); auto& bucket=world.P(0);
    Seed(bucket,401,texture); int calls=0;
    beforeAppend=[&]{if(++calls==failAt) throw std::bad_alloc();};
    EXPECT_THROW(EnsureAndFillParticleBucketWorkItems(bucket,7),std::bad_alloc); beforeAppend={};
    ASSERT_EQ(bucket.pendingParticles.size(),201U); EXPECT_EQ(texture.references,402);
    for(int i=0;i<201;++i) {
      EXPECT_EQ(bucket.pendingParticles[i].mPos.x,201+i);
      EXPECT_EQ(bucket.pendingParticles[i].mInterop,i<=failAt-201?7:0);
    }
    ASSERT_EQ(bucket.activeWorkItems.size(),2U);
    EXPECT_EQ(bucket.activeWorkItems[1]->mRenderStartIndex,0U);
    EXPECT_EQ(bucket.activeWorkItems[1]->mIntervals.size(),static_cast<std::size_t>(failAt-201));
  }
}
#endif

TEST_F(ParticleUpload, LastReferencesReallyDeleteAtEveryUnlockBoundary) {
  for(int mode:{0,1,2}) {
    SCOPED_TRACE(mode); std::vector<int> retired; retired.reserve(802);
    CWorldParticles world(3); auto& bucket=world.P(0); Pending(bucket,401);
    const auto make=[&](int id){auto* t=new CParticleTexture; t->deleteOnZero=true; t->id=id; t->retireLog=&retired; return t;};
    CParticleTexture* shared=mode==2?make(0):nullptr;
    for(int i=0;i<401;++i) {
      auto* t=shared?shared:make(mode==0?2*i:i);
      bucket.pendingParticles[i].mTexture.reset(t);
      bucket.pendingParticles[i].mRampTexture.reset(mode==0?make(2*i+1):t);
      bucket.pendingParticles[i].mTypeTag.assign_owned(("unique-real-delete-particle-tag-"+std::to_string(i)).c_str());
    }
    int uploaded=0;
    beforeUnlock=[&]{
      uploaded=std::min(uploaded+200,401);
      const std::size_t expected=mode==0?uploaded*2:mode==1?uploaded:(uploaded==401?1:0);
      ASSERT_EQ(retired.size(),expected);
      auto sorted=retired; std::sort(sorted.begin(),sorted.end());
      for(std::size_t i=0;i<sorted.size();++i) EXPECT_EQ(sorted[i],i);
    };
    EXPECT_TRUE(EnsureAndFillParticleBucketWorkItems(bucket,7)); beforeUnlock={};
    EXPECT_EQ(retired.size(),mode==0?802U:mode==1?401U:1U);
  }
}
TEST_F(ParticleUpload, BenchmarkWarmUploadMatrix) {
  if(std::getenv("PARTICLE_BENCHMARK")==nullptr) GTEST_SKIP()<<"Opt-in timing; not a game benchmark";
  ren_ParticleBatch=0;
  for(std::size_t n:{0U,1U,199U,200U,201U,400U,1000U,4000U,40000U}) {
    for(int poolMode:{0,1,2}) {
      const auto pool=poolMode==0?0U:poolMode==1?1U:(n+199U)/200U;
      CParticleTexture texture; CWorldParticles world(pool); auto& bucket=world.P(0);
      for(int repeat=-1;repeat<7;++repeat) {
        Seed(bucket,n,texture); ResetCounts();
        const auto start=std::chrono::steady_clock::now();
        const bool ok=EnsureAndFillParticleBucketWorkItems(bucket,7);
        const auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
        if(repeat>=0) std::cout<<"BENCH,"<<n<<","<<poolMode<<","<<repeat<<","<<ns<<","<<CParticleTexture::retains<<","<<CParticleTexture::releases<<","<<ok<<"\n";
        EXPECT_EQ(texture.references,0); EXPECT_TRUE(bucket.pendingParticles.empty());
        RecycleAndDestroyParticleBucketWorkItems(bucket);
      }
    }
  }
}
} // namespace

#include "BoundaryTests.inc"
#include "CallbackTests.inc"
#ifdef PARTICLE_ALLOCATION_TEST
#include "AllocationTests.inc"
#endif
