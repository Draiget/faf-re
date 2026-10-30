// Run the SAME test against separate baseline/candidate real engine builds.
#include <bit>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <initializer_list>
#include "moho/entity/Entity.h"
#include "moho/entity/CTextureScroller.h"
namespace {
using namespace moho;
void Check(bool ok,const char* why){if(!ok){std::fprintf(stderr,"FAIL %s\n",why);std::exit(1);}}
struct Fixture {
 Entity entity{nullptr,0u};CTextureScroller scroller{&entity};
 Fixture(){SScroller def;def.mType=SCROLLTYPE_MotionDerived;def.mFloat24=1;def.mFloat28=1;scroller.SetScroller(def);}
 auto& Data(){return entity.mVarDat;}
 void PriorPair(){Data().mScrollBeatStart={3.0f,-4.0f};Data().mScrollBeatEnd={3.25f,-4.5f};}
 void Yaw(float half){Data().mCurTransform.orient_={std::cos(half),0,std::sin(half),0};}
 void Tick(){scroller.Tick();}
 void Retained(){Check(Data().mScrollBeatStart.x==3 && Data().mScrollBeatStart.y==-4 && Data().mScrollBeatEnd.x==3.25f && Data().mScrollBeatEnd.y==-4.5f,"prior pair unchanged");}
 void Print(const char* name){const auto&d=Data();std::printf("TRACE %s %08x %08x %08x %08x\n",name,std::bit_cast<unsigned>(d.mScrollBeatStart.x),std::bit_cast<unsigned>(d.mScrollBeatStart.y),std::bit_cast<unsigned>(d.mScrollBeatEnd.x),std::bit_cast<unsigned>(d.mScrollBeatEnd.y));}
};
// Independent geometric oracle: quaternion-vector cross-product rotation in
// double precision, not a copy of the producer's scalar matrix/projection code.
struct DVec { double x,y,z; };
DVec Add(DVec a,DVec b){return {a.x+b.x,a.y+b.y,a.z+b.z};}
DVec Mul(DVec a,double k){return {a.x*k,a.y*k,a.z*k};}
DVec Cross(DVec a,DVec b){return {a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x};}
double Dot(DVec a,DVec b){return a.x*b.x+a.y*b.y+a.z*b.z;}
DVec Rotate(const Wm3::Quatf& q,DVec v){const DVec u{q.x,q.y,q.z};return Add(v,Add(Mul(Cross(u,v),2.0*q.w),Mul(Cross(u,Cross(u,v)),2.0)));}
double SideDelta(const Wm3::Quatf& last,const Wm3::Quatf& cur){
 const auto side=Add(Rotate(cur,{1,0,0}),Mul(Rotate(last,{1,0,0}),-1));
 const auto forward=Mul(Add(Rotate(cur,{0,0,1}),Rotate(last,{0,0,1})),.5);
 return Dot(side,forward);
}
void RepeatedAxis(bool candidate,float ax,float ay,float az,float scale,const char* name){
 Fixture f;f.scroller.mScroller.mFloat28=scale;
 const float inverse=1.0f/std::sqrt(ax*ax+ay*ay+az*az);
 for(unsigned i=1;i<=2048;++i){
  f.Data().mLastTransform=f.Data().mCurTransform;
  const float half=.0005f*static_cast<float>(i),sn=std::sin(half);
  f.Data().mCurTransform.orient_={std::cos(half),ax*inverse*sn,ay*inverse*sn,az*inverse*sn};
  const double expected=SideDelta(f.Data().mLastTransform.orient_,f.Data().mCurTransform.orient_)*scale;
  const auto before=f.Data().mScrollBeatEnd;f.Tick();
  if(candidate){
   Check(std::fabs((f.Data().mScrollBeatEnd.x-before.x)-expected)<.00001,"repeated axis left geometric delta");
   Check(std::fabs((f.Data().mScrollBeatEnd.y-before.y)+expected)<.00001,"repeated axis right geometric delta");
  }else Check(f.Data().mScrollBeatEnd.x==before.x&&f.Data().mScrollBeatEnd.y==before.y,"baseline suppresses orientation-only axis");
 }
 f.Print(name);
}
}
int main(int argc,char**argv){
 Check(argc==2,"baseline|candidate selector");const bool candidate=std::strcmp(argv[1],"candidate")==0;
 Check(candidate||std::strcmp(argv[1],"baseline")==0,"valid selector");
 for(float yaw:{.1f,-.1f}){
  Fixture f;f.Yaw(yaw);f.Tick();
  const float expected=std::sin(2*yaw);
  Check(candidate?(std::fabs(f.Data().mScrollBeatEnd.x+expected)<.00001f && std::fabs(f.Data().mScrollBeatEnd.y-expected)<.00001f):(f.Data().mScrollBeatEnd.x==0 && f.Data().mScrollBeatEnd.y==0),"rotation source outcome");
  f.Print(yaw>0?"yaw_positive":"yaw_negative");
 }
 {Fixture f;f.PriorPair();f.Tick();f.Retained();f.Print("stationary");}
 {Fixture f;f.PriorPair();f.Data().mCurTransform.orient_={-1,0,0,0};f.Tick();f.Retained();f.Print("equivalent_quaternion_sign");}
 {Fixture f;f.PriorPair();f.Data().mCurTransform.orient_={1,-0.0f,-0.0f,-0.0f};f.Tick();f.Retained();f.Print("signed_zero_orientation");}
 {Fixture f;f.PriorPair();f.Data().mCurTransform.orient_={std::cos(.1f),0,0,std::sin(.1f)};f.Tick();f.Retained();f.Print("roll_zero_projection");}
 {Fixture f;f.PriorPair();f.Yaw(.1f);f.scroller.mScroller.mFloat24=0;f.Tick();f.Retained();f.Print("zero_side_offset");}
 {Fixture f;f.PriorPair();f.Yaw(.1f);f.scroller.mScroller.mFloat28=0;f.Tick();f.Retained();f.Print("zero_multiplier");}
 {Fixture f;f.PriorPair();f.Data().mCurTransform.orient_.y=std::numeric_limits<float>::quiet_NaN();f.Tick();f.Retained();f.Print("invalid_orientation");}
 for(float sign:{1.0f,-1.0f}){
  Fixture f;f.PriorPair();f.Data().mCurTransform.pos_.z=.125f*sign;f.Tick();
  Check(f.Data().mScrollBeatStart.x==3.25f&&f.Data().mScrollBeatEnd.x==3.25f+.125f*sign,"translation unchanged");f.Print(sign>0?"translation":"reverse");
  f.Data().mLastTransform=f.Data().mCurTransform;auto a=f.Data().mScrollBeatStart,b=f.Data().mScrollBeatEnd;f.Tick();
  Check(f.Data().mScrollBeatStart.x==a.x&&f.Data().mScrollBeatEnd.x==b.x,"stop after translation unchanged");f.Print("stop_after_move");
 }
 {Fixture f;f.scroller.mScroller.mType=SCROLLTYPE_Manual;f.scroller.mScroller.mFloat04=.25f;f.scroller.mScroller.mFloat08=-.5f;f.Tick();Check(f.Data().mScrollBeatEnd.x==.25f&&f.Data().mScrollBeatEnd.y==-.5f,"manual mode untouched");f.Print("manual");}
 RepeatedAxis(candidate,0,1,0,1,"repeated_yaw");
 RepeatedAxis(candidate,1,0,0,1,"repeated_pitch_zero");
 RepeatedAxis(candidate,0,0,1,1,"repeated_roll_zero");
 RepeatedAxis(candidate,1,2,3,.75f,"repeated_tilted_positive");
 RepeatedAxis(candidate,1,2,3,-.75f,"repeated_tilted_negative_scale");
 std::printf("PASS real Tick rotation guard comparison variant=%s; not live scheduler/render/replay acceptance\n",argv[1]);
}
