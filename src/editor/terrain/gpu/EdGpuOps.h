// EDITOR GPU compute: the registry of GPU implementations of field ops, the policy that decides when to use them, the
// statistics and the self test (EdGpu.h has the device side, docs/projects/editor/GPU_COMPUTE.md the whole picture).
// Plain C++, no Direct3D: tested with the CPU emulator (tests/EdGpuTest.cpp).
//
// How an op gets to the GPU: RunOp (EdFieldCore.cpp) asks TryRun first. TryRun runs the GPU version only when every
// condition holds, and on ANY other outcome returns false so the CPU op runs as before:
//   policy.enabled (ed_gpu_compute)   the backend may work (Backend::MayWork)   the op has a registered GpuOpFn   the
//   field has at least policy.minCells samples (ed_gpu_min_cells) the backend is not busy with another thread's op
//   (never waits)   the GpuOpFn returns Done (Unsupported = parameters it does not handle, an error = something failed:
//   both fall back).
#pragma once

#include <expected>
#include <string>
#include <vector>

#include "editor/terrain/EdFieldCore.h"
#include "editor/terrain/gpu/EdGpu.h"

namespace faf::editor::gpu
{
  /** What a GPU op did when nothing failed. A failure is the op's error instead (something went wrong on the device,
   * the text says what): the CPU op runs, the fall-back is counted and the reason kept (LastOpError). */
  enum class OpResult
  {
    Done,        // `out` is complete
    Unsupported, // these inputs / parameters are not handled on the GPU: the CPU op runs (nothing is counted as a
                 // failure)
  };

  /** A GPU version of CPU op `name`: same parameters, same result (within float tolerance). Must leave `out` untouched
   * unless it returns Done. May throw nothing the caller cannot take (TryRun catches). */
  using GpuOpFn = std::expected<OpResult, std::string> (*)(Executor& ex, const field::OpArgs& args, field::Grid& out);

  /** Console variables ed_gpu_compute / ed_gpu_min_cells (EdGpuLua.cpp binds them to these). */
  struct Policy
  {
    bool enabled = true; // ed_gpu_compute
    float minCells =
      65536.0f; // ed_gpu_min_cells: smaller fields stay on the CPU (upload + download cost more than they save)
    bool selfTestFirst = true; // ed_gpu_selftest_first: the self test runs once before the first real op of a session;
                               // a device that fails it is switched off (the CPU does everything)
  };
  [[nodiscard]] Policy& GetPolicy();

  /** Registers the GPU version of the CPU op `name` (once per name; a second call replaces the first). Static
   * initialisers of op files call this. `minCells` >= 0: this op's own threshold (iterated ops like erosion pay off on
   * small fields); the op runs from min(minCells, policy.minCells) samples on. Negative = the policy's. */
  void RegisterGpuOp(const char* name, GpuOpFn fn, float minCells = -1.0f);
  /** The op's own threshold (negative = none). */
  [[nodiscard]] float GpuOpMinCells(const std::string& name);
  [[nodiscard]] std::vector<std::string> GpuOpNames();

  /** Samples the op will produce, from its inputs (`a`, else `like`, else width * height). */
  [[nodiscard]] double CellsOf(const field::OpArgs& args);

  /** The interceptor RunOp consults (see the header comment). Thread safe. */
  bool TryRun(const std::string& name, const field::OpArgs& args, field::Grid& out);
  /** Installs TryRun as the field engine's interceptor (EdGpuLua.cpp does this at start-up; the test does it
   * explicitly). */
  void Install();

  /**
   * A function TryRun calls before it uses the backend for the first time, again on every later call until it returns
   * true (EdGpuLua.cpp: finds the adapter the game's Direct3D 9 device runs on, which is only safe on the main thread;
   * false = "not yet / not on this thread").
   */
  using BeforeUseFn = bool (*)();
  void SetBeforeUseHook(BeforeUseFn fn);

  /** True once the self test has passed on the current device (set by RunSelfTest() and by TryRun's first-use test). */
  [[nodiscard]] bool SelfTestPassed();
  /** Forget it (after a device reset). */
  void ResetSelfTestState();

  /** The reason of the last failed op or refused lease ("blur: ..."), empty if none. */
  [[nodiscard]] std::string LastOpError();
  void SetLastOpError(const std::string& text);

  // ---- building blocks for ops that need a blur
  // --------------------------------------------------------------------------------------------------

  /** True when a Gaussian blur of a w x h field with this sigma (samples) is one dispatch the driver will not reset
   * (the blur op refuses wider ones too: the CPU does them). */
  [[nodiscard]] bool BlurAffordable(int w, int h, double sigma);
  /**
   * Gaussian blur of a field that lives on the device: the CPU GaussBlur (EdFieldUtil.h) = the `blur` op, sigma in
   * samples (> 1e-6), clamped edges. `src` -> `tmp` (rows) -> `dst` (columns): `dst` may be `src`, `tmp` must be
   * another field of the same size. Same arithmetic as the CPU, in the same order.
   */
  [[nodiscard]] std::expected<void, std::string>
  BlurDevice(Executor& ex, const Resource& src, Resource& tmp, Resource& dst, int w, int h, double sigma);

  // ---- self test
  // -----------------------------------------------------------------------------------------------------------------------------

  struct SelfTestPart
  {
    std::string name;
    bool ok = false;
    std::string detail;
    double ms = 0.0;
  };

  struct SelfTestReport
  {
    bool ok = false;         // every required part passed
    bool texturesOk = false; // the texture part (optional: a device without it still serves buffer kernels)
    double ms = 0.0;
    std::string error; // why nothing ran (no device ...)
    std::vector<SelfTestPart> parts;
  };

  /** Runs the self test on `ex`: scale + offset on 64 x 64, a group shared memory reduction, the blur op against the
   * CPU op, a texture sample against the CPU. */
  [[nodiscard]] SelfTestReport RunSelfTest(Executor& ex);
  /** The same on the process backend (takes the lease, waits for it; a device failure marks the backend failed). */
  [[nodiscard]] SelfTestReport RunSelfTest();
} // namespace faf::editor::gpu
