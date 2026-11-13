// the field engine core (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md, stage T1). Engine independent (no
// moho types), so it is tested on its own (tests/editor/FieldTests.cpp).
//
// A Grid is a float32 raster with a world placement: sample (x, z) lies at world position (ox + x * cell, oz + z *
// cell). Heights are world units (the document's words / 128), masks are 0..1. Ops are pure functions of their input
// grids and parameters; every output sample is computed from the inputs only (no accumulation across threads), and
// reductions combine fixed row chunks in chunk order, so the result is bit identical for any thread count. Noise is a
// function of (lattice position, seed) only.
//
// Compile flags that matter for the golden checksums: no fast-math, no FMA contraction (the .cpp pins fp_contract off).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace faf::editor::field
{
  struct Grid
  {
    int w = 0;
    int h = 0;
    float cell = 1.0f; // world units between neighbouring samples
    float ox = 0.0f;   // world position of sample (0, 0)
    float oz = 0.0f;
    std::vector<float> v;

    Grid() = default;
    Grid(
      int width,
      int height,
      float cellSize,
      float x0,
      float z0,
      float fill = 0.0f
    )
      : w(width)
      , h(height)
      , cell(cellSize)
      , ox(x0)
      , oz(z0)
      , v(static_cast<std::size_t>(width) * static_cast<std::size_t>(height), fill)
    {}
    [[nodiscard]] std::size_t Count() const noexcept
    {
      return static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
    }
    [[nodiscard]] float At(
      int x,
      int z
    ) const
    {
      return v[static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)];
    }
    float& At(
      int x,
      int z
    )
    {
      return v[static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)];
    }
    [[nodiscard]] bool SameShape(
      const Grid& o
    ) const noexcept
    {
      return w == o.w && h == o.h;
    }
  };

  using GridPtr = std::shared_ptr<const Grid>;

  /** The parameters of an op: numbers, strings and number arrays by name (Lua tables are flattened into these). */
  struct Params
  {
    std::map<std::string, double> num;
    std::map<std::string, std::string> str;
    std::map<std::string, std::vector<double>> arr;

    [[nodiscard]] double N(const char* key, double fallback) const;
    [[nodiscard]] bool Has(
      const char* key
    ) const
    {
      return num.count(key) != 0;
    }
    [[nodiscard]] std::string S(const char* key, const char* fallback) const;
    [[nodiscard]] const std::vector<double>* A(const char* key) const;
  };

  struct OpArgs
  {
    Params p;
    std::map<std::string, GridPtr> in;            // named input grids: a, b, mask, dx, dz, like
    std::map<std::string, Grid>* extra = nullptr; // when set, ops with more than one result (erosion: wear, deposit,
                                                  // flow ...) store the others here by name
  };

  /** Ops that live in their own files (EdErosion.cpp) register themselves here at start-up; RunOp / OpNames know them
   * like the built-in ones. */
  using ExternalOpFn = bool (*)(const OpArgs&, Grid&, std::string&);
  void RegisterOp(const char* name, ExternalOpFn fn);

  /**
   * An optional front door for ops (the GPU compute backend, EdGpuOps.cpp). RunOp asks the interceptor first: true = it
   * made `out` (RunOp returns true at once), false = run the CPU op. The interceptor must leave `out` untouched when it
   * returns false, must never throw, and must be thread safe (ops can run on worker threads). Null (the default) =
   * every op is a CPU op.
   */
  using OpInterceptor = bool (*)(const std::string& name, const OpArgs& args, Grid& out);
  void SetOpInterceptor(OpInterceptor fn);

  /** Runs op `name`. false with `err` set on a bad op name, missing input or parameter. Consults the interceptor first.
   */
  bool RunOp(const std::string& name, const OpArgs& args, Grid& out, std::string& err);

  /** RunOp without the interceptor and without statistics: always the CPU op (the GPU self test and the tests compare
   * against it). */
  bool RunOpCpu(const std::string& name, const OpArgs& args, Grid& out, std::string& err);

  // ---- per-op statistics (which backend ran how many ops, for the perf report)
  // -------------------------------------------------------------------------
  struct OpStat
  {
    std::uint64_t cpuCalls = 0;
    double cpuMs = 0.0;
    std::uint64_t gpuCalls = 0;
    double gpuMs = 0.0;
    std::uint64_t fallbacks = 0; // the GPU was tried and failed, the CPU op ran instead
  };
  /** RunOp records the CPU runs itself (RunOpCpu does not); the interceptor records its GPU runs and fall-backs. Thread
   * safe. */
  void NoteOpGpu(const std::string& name, double ms);
  void NoteOpFallback(const std::string& name);
  /** A copy of the table (op name -> stat). `reset` clears it afterwards. */
  [[nodiscard]] std::map<std::string, OpStat> OpStats(bool reset);

  /** Names of all ops (sorted). */
  [[nodiscard]] const std::vector<std::string>& OpNames();

  // ---- thread pool
  // -----------------------------------------------------------------------------------------------------------------------------
  /** Number of worker threads including the caller (1 = everything runs inline). Changing it never changes any result.
   */
  void SetThreads(int n);
  [[nodiscard]] int Threads();
  /** Runs fn(i) for i in [0, count); i is handed out dynamically, fn must only write data that belongs to i. */
  void ParallelFor(int count, const std::function<void(int)>& fn);

  // ---- analysis helpers
  // ------------------------------------------------------------------------------------------------------------------------
  struct Stats
  {
    float min = 0, max = 0;
    double mean = 0, sd = 0;
  };
  [[nodiscard]] Stats Measure(const Grid& g);
  /** FNV-1a over the sample bit patterns (-0 is read as +0), the dimensions are part of the hash. */
  [[nodiscard]] std::uint64_t Checksum(const Grid& g);
  /** Bilinear sample at world position (clamped to the grid). */
  [[nodiscard]] float SampleWorld(const Grid& g, double wx, double wz);
  /** Box-average downsample to pw x ph values (the preview thumbnail). */
  void Downsample(const Grid& g, int pw, int ph, std::vector<float>& out);
  // ---- improved noise lattice (rotate = 1)
  // -------------------------------------------------------------------------------------------------------- Plain
  // fractal noise sums octaves on lattices that all share the axes and, with a lacunarity of 2, the same lattice lines:
  // the sum has visible straight seams and every octave prefers the same eight directions. With `rotate` every octave
  // looks at the world through its own frame: a turn by an irrational angle (the golden angle times the octave) and a
  // shift of the origin, so no two octaves share a lattice line or an axis. Literal tables (no libm): the same bits
  // with every compiler.

  struct OctaveFrame
  {
    double c, s;   // cosine and sine of the turn
    double ox, oz; // shift (lattice units of that octave)
  };

  /** The frame of octave o (0..15; higher octaves reuse the frames with a shift). */
  inline const OctaveFrame& OctaveFrameOf(
    const int o
  )
  {
    static const OctaveFrame kFrames[16] = {
      {-0.737368878078320, 0.675490294261524, 11.7000, 3.3000},
      {0.087425724716960, -0.996171040864828, 185.0137, 95.0721},
      {0.608438860978863, 0.793600751291696, 358.3274, 186.8442},
      {-0.984713485315429, -0.174181950379312, 531.6411, 278.6163},
      {0.843755294812397, -0.536728052626323, 704.9548, 370.3884},
      {-0.259604304901489, 0.965715074375778, 878.2685, 462.1605},
      {-0.460907024713369, -0.887448429245255, 1051.5822, 553.9326},
      {0.939321296324118, 0.343038630874102, 1224.8959, 645.7047},
      {-0.924345556137805, 0.381556408474936, 1398.2096, 737.4768},
      {0.423845995047911, -0.905734272555614, 1571.5233, 829.2489},
      {0.299283864444873, 0.954164120307897, 1744.8370, 921.0210},
      {-0.865211209753230, -0.501407581232426, 1918.1507, 1012.7931},
      {0.976675773628176, -0.214719429041258, 2091.4644, 1104.5652},
      {-0.575129429139739, 0.818062430219966, 2264.7781, 1196.3373},
      {-0.128510689798993, -0.991708123697384, 2438.0918, 1288.1094},
      {0.764648995456043, 0.644446982883824, 2611.4055, 1379.8815},
    };
    return kFrames[o & 15];
  }

  /** 64 unit gradient directions (an even spread of angles: no axis is preferred, unlike the classic eight). */
  inline const float (
    *Gradients64()
  )[2]
  {
    static const float kG[64][2] = {
      {0.998795456f, 0.049067674f},   {0.989176510f, 0.146730474f},   {0.970031253f, 0.242980180f},
      {0.941544065f, 0.336889853f},   {0.903989293f, 0.427555093f},   {0.857728610f, 0.514102744f},
      {0.803207531f, 0.595699304f},   {0.740951125f, 0.671558955f},   {0.671558955f, 0.740951125f},
      {0.595699304f, 0.803207531f},   {0.514102744f, 0.857728610f},   {0.427555093f, 0.903989293f},
      {0.336889853f, 0.941544065f},   {0.242980180f, 0.970031253f},   {0.146730474f, 0.989176510f},
      {0.049067674f, 0.998795456f},   {-0.049067674f, 0.998795456f},  {-0.146730474f, 0.989176510f},
      {-0.242980180f, 0.970031253f},  {-0.336889853f, 0.941544065f},  {-0.427555093f, 0.903989293f},
      {-0.514102744f, 0.857728610f},  {-0.595699304f, 0.803207531f},  {-0.671558955f, 0.740951125f},
      {-0.740951125f, 0.671558955f},  {-0.803207531f, 0.595699304f},  {-0.857728610f, 0.514102744f},
      {-0.903989293f, 0.427555093f},  {-0.941544065f, 0.336889853f},  {-0.970031253f, 0.242980180f},
      {-0.989176510f, 0.146730474f},  {-0.998795456f, 0.049067674f},  {-0.998795456f, -0.049067674f},
      {-0.989176510f, -0.146730474f}, {-0.970031253f, -0.242980180f}, {-0.941544065f, -0.336889853f},
      {-0.903989293f, -0.427555093f}, {-0.857728610f, -0.514102744f}, {-0.803207531f, -0.595699304f},
      {-0.740951125f, -0.671558955f}, {-0.671558955f, -0.740951125f}, {-0.595699304f, -0.803207531f},
      {-0.514102744f, -0.857728610f}, {-0.427555093f, -0.903989293f}, {-0.336889853f, -0.941544065f},
      {-0.242980180f, -0.970031253f}, {-0.146730474f, -0.989176510f}, {-0.049067674f, -0.998795456f},
      {0.049067674f, -0.998795456f},  {0.146730474f, -0.989176510f},  {0.242980180f, -0.970031253f},
      {0.336889853f, -0.941544065f},  {0.427555093f, -0.903989293f},  {0.514102744f, -0.857728610f},
      {0.595699304f, -0.803207531f},  {0.671558955f, -0.740951125f},  {0.740951125f, -0.671558955f},
      {0.803207531f, -0.595699304f},  {0.857728610f, -0.514102744f},  {0.903989293f, -0.427555093f},
      {0.941544065f, -0.336889853f},  {0.970031253f, -0.242980180f},  {0.989176510f, -0.146730474f},
      {0.998795456f, -0.049067674f},
    };
    return kG;
  }

} // namespace faf::editor::field
