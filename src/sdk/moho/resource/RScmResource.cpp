#include "moho/resource/RScmResource.h"

#include <cmath>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/SScmFile.h"
#include "moho/serialization/PrefetchHandleBase.h"

#pragma init_seg(lib)

namespace
{
  [[nodiscard]] std::size_t LargestAxisByAbsoluteComponent(const float values[3]) noexcept
  {
    const bool yDominatesX = std::fabs(values[1]) > std::fabs(values[0]);
    const std::size_t dominantAxis = yDominatesX ? 1u : 0u;
    if (std::fabs(values[2]) <= std::fabs(values[dominantAxis])) {
      return dominantAxis;
    }

    return 2u;
  }

  struct RScmResourcePrefetchBootstrap
  {
    RScmResourcePrefetchBootstrap()
    {
      moho::register_RScmResourceModelPrefetchType();
    }
  };

  RScmResourcePrefetchBootstrap gRScmResourcePrefetchBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RScmResource::sType = nullptr;

  /**
   * Address: 0x00538BF0 (FUN_00538BF0,
   * ??0RScmResource@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
   *
   * What it does:
   * Binds one SCM data-owner lane + resource path and computes cached
   * bounds/size from embedded bone-bounds samples.
   */
  RScmResource::RScmResource(const gpg::StrArg resourcePath, const boost::shared_ptr<const SScmFile>& scmFile) :
    mName(resourcePath),
    mFile(scmFile),
    mSkeleton(nullptr),
    mBounds(Empty<Wm3::AxisAlignedBox3f>()),
    mSize(0.0f)
  {
    const std::int32_t sampleCount = static_cast<std::int32_t>(mFile->mBoneBoundsSampleCount);
    const SScmBoneBoundsSample* const samples = scm_file::GetBoneBoundsSamples(*mFile);

    for (std::int32_t sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex) {
      const SScmBoneBoundsSample& sample = samples[sampleIndex];

      if (sample.mLocalPositionX < mBounds.Min.x) {
        mBounds.Min.x = sample.mLocalPositionX;
      }
      if (sample.mLocalPositionY < mBounds.Min.y) {
        mBounds.Min.y = sample.mLocalPositionY;
      }
      if (sample.mLocalPositionZ < mBounds.Min.z) {
        mBounds.Min.z = sample.mLocalPositionZ;
      }

      if (sample.mLocalPositionX > mBounds.Max.x) {
        mBounds.Max.x = sample.mLocalPositionX;
      }
      if (sample.mLocalPositionY > mBounds.Max.y) {
        mBounds.Max.y = sample.mLocalPositionY;
      }
      if (sample.mLocalPositionZ > mBounds.Max.z) {
        mBounds.Max.z = sample.mLocalPositionZ;
      }
    }

    float axisExtents[3]{};
    axisExtents[0] = mBounds.Max.x - mBounds.Min.x;
    axisExtents[1] = mBounds.Max.y - mBounds.Min.y;
    axisExtents[2] = mBounds.Max.z - mBounds.Min.z;

    const std::size_t dominantAxis = LargestAxisByAbsoluteComponent(axisExtents);
    mSize = axisExtents[dominantAxis] * 1.2f;
  }

  /**
   * Address: 0x00BC91A0 (FUN_00BC91A0)
   *
   * What it does:
   * Resolves `RScmResource` RTTI and registers the `"models"` prefetch lane.
   */
  void register_RScmResourceModelPrefetchType()
  {
    gpg::RType* resourceType = RScmResource::sType;
    if (resourceType == nullptr) {
      resourceType = gpg::LookupRType(typeid(RScmResource));
      RScmResource::sType = resourceType;
    }

    RES_RegisterPrefetchType("models", resourceType);
  }
} // namespace moho
