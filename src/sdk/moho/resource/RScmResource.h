#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "Wm3AxisAlignedBox3.h"
#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  struct SScmFile;
  class CAniSkel;

  class RScmResource : public boost::enable_shared_from_this<RScmResource>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00538BF0 (FUN_00538BF0,
     * ??0RScmResource@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
     *
     * What it does:
     * Binds one SCM data-owner lane + resource path and computes cached
     * bounds/size from embedded bone-bounds samples.
     */
    RScmResource(gpg::StrArg resourcePath, const boost::shared_ptr<const SScmFile>& scmFile);

    /**
     * Address: 0x00538DB0 (FUN_00538DB0,
     * ?GetSkeleton@RScmResource@Moho@@QAE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     */
    [[nodiscard]] boost::shared_ptr<const CAniSkel> GetSkeleton();

  public:
    msvc8::string mName;                   // +0x08
    boost::shared_ptr<const SScmFile> mFile; // +0x24
    CAniSkel* mSkeleton;                   // +0x2C
    Wm3::AxisAlignedBox3f mBounds;         // +0x30
    float mSize;                           // +0x48
  };

  static_assert(offsetof(RScmResource, mName) == 0x08, "RScmResource::mName offset must be 0x08");
  static_assert(offsetof(RScmResource, mFile) == 0x24, "RScmResource::mFile offset must be 0x24");
  static_assert(offsetof(RScmResource, mSkeleton) == 0x2C, "RScmResource::mSkeleton offset must be 0x2C");
  static_assert(offsetof(RScmResource, mBounds) == 0x30, "RScmResource::mBounds offset must be 0x30");
  static_assert(offsetof(RScmResource, mSize) == 0x48, "RScmResource::mSize offset must be 0x48");
  static_assert(sizeof(RScmResource) == 0x4C, "RScmResource size must be 0x4C");

  /**
   * Address: 0x00BC91A0 (FUN_00BC91A0)
   *
   * What it does:
   * Resolves `RScmResource` RTTI and registers the `"models"` prefetch lane.
   */
  void register_RScmResourceModelPrefetchType();
} // namespace moho
