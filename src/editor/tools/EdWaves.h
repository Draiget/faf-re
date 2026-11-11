#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * A wave generator as the `.scmap` keeps it (WaveGenerator::Save 0x00888250, FAForeverMapEditor's WaveGenerator):
   * two texture paths, then 17 floats.
   */
  struct WaveRecord
  {
    std::string texture;
    std::string ramp;
    float position[3] = {0.0f, 0.0f, 0.0f};
    /** The texture's turn; the waves travel at angle - 90 degrees (every retail shore wave, SCMP_001's 1408). */
    float angle = 0.0f;
    float velocity[3] = {0.0f, 0.0f, 0.0f};
    float lifetime[2] = {0.0f, 0.0f};
    /** Seconds between waves, picked between these. */
    float period[2] = {0.0f, 0.0f};
    /** A wave's size when it starts and when it ends. */
    float scale[2] = {1.0f, 1.0f};
    /** The texture's animation frames (FAFME's FrameCount), its frame rate range, and its strips (StripCount). */
    float frameCount = 1.0f;
    float frameRate[2] = {1.0f, 1.0f};
    float stripCount = 1.0f;

    bool operator==(const WaveRecord& other) const;
  };

  /** The wave system's section of a `.scmap` (WaveSystem::Save 0x00889AD0): a count, then each generator. */
  std::string WaveRecordsToBytes(const std::vector<WaveRecord>& waves);
  bool WaveRecordsFromBytes(const std::string& bytes, std::vector<WaveRecord>& waves);

  /** FAForeverMapEditor's waves file (`.scmwaves`, JsonUtility's dump of its WaveData): game coordinates, radians. */
  std::string WavesToScmwaves(const std::vector<WaveRecord>& waves);
  bool WavesFromScmwaves(const std::string& text, std::vector<WaveRecord>& waves, std::string& error);

  /** What a generator of a kind gets (the GPG editor's wave pattern, first parameter set): ranges are min, max. */
  struct WavePattern
  {
    std::string name;
    std::string texture;
    std::string ramp;
    float speed = 0.04f;
    float speedVariance = 0.0f;
    float lifetime[2] = {30.0f, 70.0f};
    float period[2] = {4.5f, 5.5f};
    float scale[2] = {1.0f, 1.0f};
    float scaleVariance = 0.0f;
    float frameCount = 1.0f;
    float frameRate[2] = {1.0f, 1.0f};
    float stripCount = 1.0f;
  };

  /** The editor's own patterns, measured from the retail maps' generators (SCMP_001). */
  const std::vector<WavePattern>& BuiltInWavePatterns();
  /**
   * A `wavepatterns.lua` (`patterns = { { name, preview, parameters = { { texture, ramp, period, periodVariance, speed,
   * speedVariance, lifetime, lifetimeVariance, scale = { a, b }, scaleVariance, frameCount, frameRate,
   * frameRateVariance, stripCount } } } }`, as FAForeverMapEditor ships one): each pattern's first parameter set.
   */
  bool ParseWavePatterns(const std::string& lua, std::vector<WavePattern>& patterns, std::string& error);

  /** A place on the shore: where a wave starts and the way to the shore (radians, game x/z: 0 is +x, pi/2 is +z). */
  struct ShorePoint
  {
    float x = 0.0f;
    float z = 0.0f;
    float heading = 0.0f;
  };

  /**
   * The cells where the ground crosses `depth` below the water (`heights`: (width + 1) x (height + 1) samples), each
   * facing uphill; only those whose heading is within `rangeDegrees` of `centreDegrees` (180: all).
   */
  std::vector<ShorePoint> FindShorePoints(
    const std::vector<float>& heights,
    int width,
    int height,
    float waterLevel,
    float depth,
    float centreDegrees,
    float rangeDegrees
  );

  /** About `density` (0 to 1) of the points, none closer than `spacing` to another, picked by `seed`. */
  std::vector<ShorePoint>
  PickShorePoints(std::vector<ShorePoint> points, float density, float spacing, std::uint32_t seed);

  /** A generator of `pattern` at a point, on the water, travelling to the shore; `seed` varies its speed and scale. */
  WaveRecord MakeShoreWave(const WavePattern& pattern, const ShorePoint& point, float waterLevel, std::uint32_t& seed);
} // namespace faf::editor
