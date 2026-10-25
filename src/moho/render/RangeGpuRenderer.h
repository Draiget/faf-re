#pragma once

#include <span>
#include <boost/shared_ptr.hpp>
#include "gpg/gal/GpuDriven.h"
#include "moho/misc/RangeExtractor.h"
#include "moho/render/GpuArrayStream.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
  class VertexBuffer;
} // namespace gpg::gal

namespace moho
{
  class RangeRenderer;
  class GeomCamera3;

  extern int ren_GpuRanges;
  extern int ren_MergeRanges;

  struct RangeEnvelopeInstance
  {
    float thickness;
    float isInner;
    float padding[2];
    float points[48][2];
  };
  static_assert(sizeof(RangeEnvelopeInstance) == 400, "RangeEnvelopeInstance size must be 400 bytes");

  class RangeGpuRenderer
  {
  public:
    [[nodiscard]] static RangeGpuRenderer& Get();

    [[nodiscard]] bool IsActive();

    bool CastEnvelopes(
      RangeRenderer& renderer,
      const GeomCamera3& cameraView,
      std::span<const RangeEnvelopeInstance> instances
    );

  private:
    RangeGpuRenderer() = default;

    bool RefreshCylinder(RangeRenderer& renderer);

    gpg::gal::Device* mDevice = nullptr;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mCylinder;
    const gpg::gal::VertexBuffer* mCylinderSource = nullptr;
    GpuArrayStream mEnvelopeStream{"RangeEnvelopes", sizeof(RangeEnvelopeInstance)};
    bool mSupported = false;
  };
} // namespace moho
