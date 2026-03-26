#include "CAniActor.h"

#include "moho/animation/CAniPose.h"

using namespace moho;

/**
 * Address: 0x005E3CF0 (FUN_005E3CF0, ?GetSkeleton@CAniActor@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
 */
boost::shared_ptr<const CAniSkel> CAniActor::GetSkeleton() const
{
  return mPose.px->GetSkeleton();
}
