#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_Atmosphere`): height fog lit by the sun, with shafts of light and shadow where hills block
// it (AtmosphereShader.h). The fog lies over the low ground (its density falls off with height above the map's
// low ground or its water), takes the map's sun and ambient colours, and never takes more than
// `ren_AtmosphereMax` of a pixel's colour, so units stay visible. Off by default. Direct3D 12 and Vulkan only (it
// reads the bound depth target, as ren_Ao does). The sun-height bake runs once per map and sun direction; each
// frame costs one half-resolution compute pass and one full-screen composite.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  struct GeomCamera3;

  extern int ren_Atmosphere;

  class Atmosphere
  {
  public:
    [[nodiscard]] static Atmosphere& Get();

    /** `ren_Atmosphere` is on, the renderer is Direct3D 12 or Vulkan with compute, and the programs built. */
    [[nodiscard]] bool IsActive();

    /**
     * Fogs the bound colour target over the view at (`x`, `y`), `width` by `height`, from the bound depth. Call it
     * with the world view's viewport set, after the water. `focus` is the camera's distance to its focus point.
     */
    void Render(const GeomCamera3& camera, float focus, int x, int y, int width, int height);

  private:
    /** Bakes the sun heights for the map's heightfield and `sun` when either changed; false when it can't. */
    [[nodiscard]] bool PrepareSunHeights(const float sun[3]);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompute;
    boost::shared_ptr<gpg::gal::GpuProgram> mBake;
    boost::shared_ptr<gpg::gal::GpuProgram> mComposite;
    boost::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;

    // The bake: the heightfield it was made from, the sun, the buffers.
    const void* mBakedField = nullptr;
    std::uint64_t mBakedRevision = ~0ULL; // HeightFieldRevision() of the bake
    std::int32_t mFieldWidth = 0;
    std::int32_t mFieldHeight = 0;
    float mBakedSun[3]{};
    boost::shared_ptr<gpg::gal::GpuBuffer> mHeights;
    boost::shared_ptr<gpg::gal::GpuBuffer> mSunHeights;
    std::uint32_t mCellSize = 1U;
    std::uint32_t mCellsAcross = 0U;
    std::uint32_t mCellsDown = 0U;
    float mLowGround = 0.0f;   // the map's low ground: a fifth of its samples lie under it
    float mHeightRange = 0.0f; // highest sample less lowest
    bool mBaked = false;
    // A change of the same field (a building's flattened ground, the map editor's brush) repacks it a slice a frame.
    std::vector<std::uint32_t> mPacked; // the heights as uploaded, two samples per element
    bool mRepacking = false;
    std::uint64_t mRepackRevision = 0U; // the revision the repack under way reads
    std::size_t mRepackNext = 0U;       // its next element
    double mRepackMilliseconds = 0.0;   // its slowest slice, for the log
    std::uint32_t mEditLogs = 0U;
  };
} // namespace moho
