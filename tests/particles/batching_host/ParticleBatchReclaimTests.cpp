// Extension of PR #338's source-bound host fixture. The world/bucket/Pass
// scaffolding is retained; upload, interval lifecycle, reclaim, mirror and
// gather algorithms now come from the selected production source, unchanged.
// Graphics storage/copies/draws remain an explicit synchronous byte recorder.
#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
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
#undef static_assert
#include "gpg/gal/GpuDriven.h"
#include "moho/particles/ParticlePoolReclaim.h"

namespace boost { template<class T> using shared_ptr = std::shared_ptr<T>; }
// The pending-upload cursor names the payload's owned members and vector type.
// Stand-ins with the same ownership shape; tests/particles/upload_host binds the real ones.
namespace Wm3 { template<class T> struct Vector3 { T x{}, y{}, z{}; }; }
namespace fa { struct string { std::string value; }; }
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
using Vector3 = Wm3::Vector3<float>;
struct SWorldParticle {
  Vector3 mPos, mDir, mAccel;
  std::shared_ptr<int> mTexture, mRampTexture;
  fa::string mTypeTag;
  float mInterop=0, mLifetime=100, mFramerate=0, mValue1=0, mTextureSelection=0;
  float mRampSelection=0, mValue3=0, mResistance=1, mBeginSize=1, mEndSize=2;
  float mAngle=0, mRotationCurve=0;
};
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
    if (first < 0 || count < 0 || first + count > mMaxParticles)
      throw std::out_of_range("production requested an out-of-bounds particle lock");
    return reinterpret_cast<Instanced*>(mInstanceVertexBuffer->bytes.data()+first*sizeof(Instanced));
  }
  void UnlockInstanceBuffer() {}
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
// PARTICLE_LINEAR_UPLOAD sets ren_ParticleLinearUpload, so the reclaim cases also run with linear consumption.
static const bool kLinearUploadFromEnvironment = [] {
  if (const char* value = std::getenv("PARTICLE_LINEAR_UPLOAD")) moho::ren_ParticleLinearUpload = std::atoi(value);
  return true;
}();
namespace moho {
inline CWorldParticles::~CWorldParticles() {
  for (auto& bucket : owned_pb) RecycleAndDestroyParticleBucketWorkItems(*bucket);
}
inline void Pending(SParticleRenderBucket& bucket, std::size_t count, int id=1, float life=100) {
  for (std::size_t i=0; i<count; ++i) {
    SWorldParticle particle;
    particle.mPos = {static_cast<float>(id+static_cast<int>(i)), 3, 4};
    particle.mDir = {5, 6, 7}; particle.mAccel = {8, 9, 10};
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
class ParticleBatchReclaim : public testing::Test {
protected:
  gpg::gal::Device device;
  void SetUp() override {
    ASSERT_EQ(std::getenv("FAF_PARTICLE_BATCH_DIAG"), nullptr) << "Unset diagnostics for ordinary batching";
    sParticleGather = {}; sParticleMirror = {};
    gpg::gal::Device::current=&device; ren_ParticleBatch=1;
    ASSERT_TRUE(ParticleBatchActive());
  }
  void TearDown() override {
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
class ParticleBatchReclaimLane : public ParticleBatchReclaim, public testing::WithParamInterface<int> {};

TEST_P(ParticleBatchReclaimLane, EarlyReclaimAndRefillDrawOnlyNewBytes) {
  CWorldParticles world(1);
  auto& early=world.P(0,0,GetParam()==2);
  auto& later=world.P(1,0,GetParam()==2);
  Active(later,200,1,1000);
  auto* recycled=static_cast<ParticleBuffer*>(later.activeWorkItems[0]->mParticleBuffer);
  ASSERT_TRUE(sParticleMirror.mMirrored.at(recycled));
  Pending(early,3,9000);
  ASSERT_TRUE(world.mAvailableParticleBuffers.empty());
  ClearTrace(); Pass(world,GetParam());
  ASSERT_EQ(early.activeWorkItems.size(),1U);
  EXPECT_EQ(early.activeWorkItems[0]->mParticleBuffer,recycled);
  EXPECT_TRUE(later.activeWorkItems.empty());
  EXPECT_EQ(DrawnIds(device),Sequence(9000,3));
  ASSERT_EQ(device.draws.size(),1U); EXPECT_FALSE(device.draws[0].original);
  ExpectExactBytes(device.draws[0],*recycled,0,3);
  ASSERT_EQ(device.copies.size(),2U);
  EXPECT_EQ(device.copies[0].destination,sParticleMirror.mBuffer.get());
  EXPECT_EQ(device.copies[1].source,sParticleMirror.mBuffer.get());
  ExpectSlotsUnique();
  ClearTrace(); Pass(world,GetParam(),11);
  EXPECT_EQ(DrawnIds(device),Sequence(9000,3));
  EXPECT_EQ(device.copies.size(),1U); // no second upload, only gathering the live range
  EXPECT_TRUE(world.mAvailableParticleBuffers.empty());
  ExpectSlotsUnique();
}

TEST_P(ParticleBatchReclaimLane, PartialExpiryAfterReuseGathersOnlyTheLiveSubrange) {
  CWorldParticles world(1);
  auto& early=world.P(0,0,GetParam()==2); auto& expired=world.P(1,0,GetParam()==2);
  Active(expired,200,1,1000);
  Pending(early,2,9000,1); Pending(early,1,9002,100);
  Pass(world,GetParam(),10);
  auto* buffer=static_cast<ParticleBuffer*>(early.activeWorkItems[0]->mParticleBuffer);
  ClearTrace(); Pass(world,GetParam(),12);
  EXPECT_EQ(early.activeWorkItems[0]->mIntervalCursor,2U);
  EXPECT_EQ(DrawnIds(device),(std::vector<int>{9002}));
  ASSERT_EQ(device.copies.size(),1U);
  EXPECT_EQ(device.copies[0].source,sParticleMirror.mBuffer.get());
  EXPECT_EQ(device.copies[0].sourceOffset,(sParticleMirror.mSlotOf.at(buffer)*256U+2U)*kStride);
  EXPECT_EQ(device.copies[0].bytes,kStride);
  ASSERT_EQ(device.draws.size(),1U); ExpectExactBytes(device.draws[0],*buffer,2,1);
  ExpectSlotsUnique();
}

TEST_F(ParticleBatchReclaim, SuffixPruneAndRepeatedForgetReleaseOneSlotOnly) {
  CWorldParticles world(3);
  auto& early=world.P(0); auto& expired=world.P(1); auto& live=world.P(2);
  Active(expired,200,1,1000); Active(live,200,100,2000);
  auto* old=static_cast<ParticleBuffer*>(expired.activeWorkItems[0]->mParticleBuffer);
  auto* liveBuffer=static_cast<ParticleBuffer*>(live.activeWorkItems[0]->mParticleBuffer);
  auto* held=world.AcquireParticleBuffer(); ASSERT_NE(held,nullptr);
  Pending(early,1,3000);
  ASSERT_TRUE(detail::ReclaimRemainingBucketsUnderPressure<200>(world.mParticleBuckets.begin(),
    world.mParticleBuckets.end(),world.mAvailableParticleBuffers.size(),early.pendingParticles.size(),
    false,false,0,10,PruneExpiredParticleBucketWorkItems));
  EXPECT_TRUE(expired.activeWorkItems.empty());
  EXPECT_EQ(sParticleMirror.mSlotOf.count(old),0U);
  EXPECT_EQ(sParticleMirror.mMirrored.count(old),0U);
  ASSERT_EQ(sParticleMirror.mFreeSlots.size(),1U);
  ASSERT_EQ(world.mAvailableParticleBuffers.size(),1U);
  PruneExpiredParticleBucketWorkItems(expired,10); // retained normal per-bucket prune
  ForgetMirroredParticles(*old); ForgetMirroredParticles(*old);
  EXPECT_EQ(sParticleMirror.mFreeSlots.size(),1U);
  EXPECT_EQ(world.mAvailableParticleBuffers.size(),1U);
  ASSERT_TRUE(EnsureAndFillParticleBucketWorkItems(early,10));
  EXPECT_EQ(early.activeWorkItems[0]->mParticleBuffer,old);
  world.ReleaseParticleBuffer(held);
  auto& third=world.P(3); Active(third,1,100,4000);
  EXPECT_NE(sParticleMirror.mSlotOf.at(old),sParticleMirror.mSlotOf.at(held));
  EXPECT_NE(sParticleMirror.mSlotOf.at(old),sParticleMirror.mSlotOf.at(liveBuffer));
  ExpectSlotsUnique();
  ClearTrace(); Pass(world);
  auto expected=std::vector<int>{3000};
  auto liveIds=Sequence(2000,200); expected.insert(expected.end(),liveIds.begin(),liveIds.end());
  expected.push_back(4000);
  EXPECT_EQ(DrawnIds(device),expected);
}

TEST_P(ParticleBatchReclaimLane, FailedMirrorCopyAfterReuseGathersOriginalAndStaysInvalidOnAppend) {
  CWorldParticles world(1);
  auto& early=world.P(0,0,GetParam()==2); auto& expired=world.P(1,0,GetParam()==2);
  Active(expired,200,1,1000);
  auto* recycled=static_cast<ParticleBuffer*>(expired.activeWorkItems[0]->mParticleBuffer);
  auto* mirror=sParticleMirror.mBuffer.get();
  device.failCopy=[mirror](const Copy& copy){return copy.destination==mirror;};
  Pending(early,3,7000); ClearTrace(); Pass(world,GetParam());
  ASSERT_EQ(device.copies.size(),2U);
  EXPECT_FALSE(device.copies[0].success); EXPECT_TRUE(device.copies[1].success);
  EXPECT_EQ(device.copies[1].source,recycled->mInstanceVertexBuffer.get());
  EXPECT_FALSE(sParticleMirror.mMirrored.at(recycled));
  EXPECT_EQ(DrawnIds(device),Sequence(7000,3));
  ASSERT_EQ(device.draws.size(),1U); ExpectExactBytes(device.draws[0],*recycled,0,3);
  device.failCopy={}; Pending(early,1,8000); ClearTrace(); Pass(world,GetParam(),11);
  EXPECT_FALSE(sParticleMirror.mMirrored.at(recycled));
  ASSERT_EQ(device.copies.size(),1U); // no partial mirror recovery after a failed prefix
  EXPECT_EQ(device.copies[0].source,recycled->mInstanceVertexBuffer.get());
  EXPECT_EQ(DrawnIds(device),(std::vector<int>{7000,7001,7002,8000}));
  ASSERT_EQ(device.draws.size(),1U); ExpectExactBytes(device.draws[0],*recycled,0,4);
  ExpectSlotsUnique();
}

TEST_P(ParticleBatchReclaimLane, FailedSecondGatherFallsBackToOriginalBuffersWithoutDuplicateDraw) {
  CWorldParticles world(2);
  auto& early=world.P(0,0,GetParam()==2);
  Active(world.P(1,0,GetParam()==2),200,1,1000);
  Active(world.P(2,0,GetParam()==2),200,1,2000);
  Pending(early,201,9000);
  int gatherCalls=0;
  device.failCopy=[&](const Copy& copy){
    if (copy.destination->context.vertexCount_ != 16384U) return false;
    return ++gatherCalls==2;
  };
  ClearTrace(); Pass(world,GetParam());
  ASSERT_EQ(early.activeWorkItems.size(),2U);
  auto expected=std::vector<int>{9200}; const auto rest=Sequence(9000,200);
  expected.insert(expected.end(),rest.begin(),rest.end());
  EXPECT_EQ(DrawnIds(device),expected);
  ASSERT_EQ(device.draws.size(),2U); // first successful gather copy was never drawn
  EXPECT_TRUE(device.draws[0].original); EXPECT_TRUE(device.draws[1].original);
  for (std::size_t i=0; i<2; ++i) {
    auto* buffer=static_cast<ParticleBuffer*>(early.activeWorkItems[1-i]->mParticleBuffer);
    EXPECT_EQ(device.draws[i].source,buffer->mInstanceVertexBuffer.get());
    ExpectExactBytes(device.draws[i],*buffer,0,i==0 ? 1 : 200);
  }
  EXPECT_EQ(gatherCalls,2); ExpectSlotsUnique();
}

TEST_F(ParticleBatchReclaim, RepeatedEarlyReuseKeepsBothSlotsUniqueAndDrawOrderStable) {
  CWorldParticles world(2); auto& a=world.P(0); auto& b=world.P(1);
  Active(b,201,1,1000);
  for (int cycle=0; cycle<32; ++cycle) {
    SCOPED_TRACE(cycle);
    auto& target=cycle%2==0 ? a : b;
    Pending(target,201,10000+cycle*1000,1);
    ClearTrace(); Pass(world,0,10+cycle*10);
    auto expected=std::vector<int>{10200+cycle*1000}; const auto rest=Sequence(10000+cycle*1000,200);
    expected.insert(expected.end(),rest.begin(),rest.end());
    EXPECT_EQ(DrawnIds(device),expected);
    EXPECT_EQ(sParticleMirror.mSlotsUsed,2U);
    EXPECT_EQ(sParticleMirror.mSlotOf.size(),2U);
    EXPECT_TRUE(sParticleMirror.mFreeSlots.empty()); ExpectSlotsUnique();
  }
}

TEST_F(ParticleBatchReclaim, BatchOffReuseCannotDrawPreviousMirrorWhenReenabled) {
  CWorldParticles world(1); auto& early=world.P(0); auto& expired=world.P(1);
  Active(expired,200,1,1000); Pending(early,3,9000);
  ren_ParticleBatch=0; ClearTrace(); Pass(world);
  EXPECT_EQ(DrawnIds(device),Sequence(9000,3));
  EXPECT_TRUE(sParticleMirror.mSlotOf.empty()); EXPECT_TRUE(sParticleMirror.mMirrored.empty());
  ren_ParticleBatch=1; ClearTrace(); Pass(world,0,11);
  EXPECT_EQ(DrawnIds(device),Sequence(9000,3));
  ASSERT_EQ(device.copies.size(),1U);
  auto* buffer=static_cast<ParticleBuffer*>(early.activeWorkItems[0]->mParticleBuffer);
  EXPECT_EQ(device.copies[0].source,buffer->mInstanceVertexBuffer.get()); ExpectSlotsUnique();
}

// More than two batches pending in one bucket: with ren_ParticleLinearUpload=1 the first two
// batches take the cursor's deferred path and the third the short-tail erase. Three expired
// buckets are reclaimed for it; the 601st particle finds no buffer and is discarded.
TEST_P(ParticleBatchReclaimLane, ReclaimFeedsAMultiBatchBucketInOrder) {
  if (const char* linear=std::getenv("PARTICLE_LINEAR_UPLOAD")) ASSERT_EQ(ren_ParticleLinearUpload,std::atoi(linear));
  CWorldParticles world(3);
  const bool refract=GetParam()==2;
  auto& early=world.P(0,0,refract);
  for (int key=1; key<=3; ++key) Active(world.P(key,0,refract),200,1,1000*key);
  ASSERT_TRUE(world.mAvailableParticleBuffers.empty());
  Pending(early,601,9000);
  ClearTrace(); Pass(world,GetParam());
  EXPECT_TRUE(early.pendingParticles.empty());
  ASSERT_EQ(early.activeWorkItems.size(),3U);
  for (std::size_t k=0; k<3; ++k) {
    const auto* item=early.activeWorkItems[k];
    EXPECT_EQ(item->mRenderStartIndex,200U);
    const auto& bytes=static_cast<ParticleBuffer*>(item->mParticleBuffer)->mInstanceVertexBuffer->bytes;
    for (int i=0; i<200; ++i) {
      float id=0; std::memcpy(&id,bytes.data()+static_cast<std::size_t>(i)*kStride,sizeof(id));
      ASSERT_EQ(static_cast<int>(id),9000+static_cast<int>(k)*200+i) << "work item " << k << " slot " << i;
    }
  }
  auto drawn=DrawnIds(device); std::sort(drawn.begin(),drawn.end());
  EXPECT_EQ(drawn,Sequence(9000,600));
  for (const auto& [key,bucket] : (refract ? world.mRefractingParticleBuckets : world.mParticleBuckets))
    if (bucket!=&early) EXPECT_TRUE(bucket->activeWorkItems.empty());
  ExpectSlotsUnique();
}

INSTANTIATE_TEST_SUITE_P(NormalWaterRefraction,ParticleBatchReclaimLane,testing::Values(0,1,2));
} // namespace
