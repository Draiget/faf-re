// Small device-free helpers of gpg/gal and its backends: the backends' error reporting and
// diagnostic switches (backends/common/BackendErrors.h), the guarded lock copy
// (backends/common/LockShadow.h), the recent-pipeline table (backends/common/PipelineMemo.h), the
// driver version text (backends/common/RuntimeInfo.h), the float16 conversion (HalfFloat.h, IEEE
// 754 binary16 with the D3DX rounding its header states), the gal string helpers (StringUtils.h,
// 0x00408450 and 0x008EA3B0) and the D3D9 state cache (StateCache.h).

#include <gtest/gtest.h>

#include <windows.h>

#include <d3d9.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/HalfFloat.h"
#include "gpg/gal/StateCache.h"
#include "gpg/gal/StringUtils.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/common/LockShadow.h"
#include "gpg/gal/backends/common/PipelineMemo.h"
#include "gpg/gal/backends/common/RuntimeInfo.h"
#include "legacy/containers/String.h"

namespace backend = gpg::gal::backend;

namespace
{
  /** Sets an environment variable for one test and restores it afterwards. */
  class ScopedEnvironment
  {
  public:
    ScopedEnvironment(const char* const name, const char* const value)
      : mName(name)
    {
      if (const char* const previous = std::getenv(name)) {
        mPrevious = previous;
        mHadPrevious = true;
      }
      _putenv_s(name, value);
    }
    ~ScopedEnvironment() { _putenv_s(mName.c_str(), mHadPrevious ? mPrevious.c_str() : ""); }
    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

  private:
    std::string mName;
    std::string mPrevious;
    bool mHadPrevious = false;
  };

  struct Thrown
  {
    std::string file;
    int line = 0;
    std::string message;
  };

  template <class Call>
  Thrown Catch(Call&& call)
  {
    Thrown thrown;
    try {
      call();
    } catch (const gpg::gal::Error& error) {
      thrown.file = error.GetFile();
      thrown.line = error.GetLine();
      thrown.message = error.what();
    }
    return thrown;
  }
} // namespace

TEST(GalBackendErrors, ErrorsCarryFileLineAndTheHresultText)
{
  const Thrown hresult = Catch([] { backend::ThrowHresult("DeviceD3D12.cpp", 42, E_OUTOFMEMORY); });
  EXPECT_EQ(hresult.file, "DeviceD3D12.cpp");
  EXPECT_EQ(hresult.line, 42);
  EXPECT_EQ(hresult.message, "HRESULT 0x8007000E (Ran out of memory)");

  const Thrown plain = Catch([] { backend::ThrowError(nullptr, 3, nullptr); });
  EXPECT_EQ(plain.file, "");
  EXPECT_EQ(plain.line, 3);
  EXPECT_EQ(plain.message, "");

  EXPECT_NO_THROW(backend::CheckHresult("x.cpp", 1, S_OK));
  EXPECT_NO_THROW(backend::CheckHresult("x.cpp", 1, S_FALSE));
  const Thrown failed = Catch([] { backend::CheckHresult("x.cpp", 7, E_FAIL); });
  EXPECT_EQ(failed.line, 7);
  EXPECT_EQ(failed.message, "HRESULT 0x80004005 (An undetermined error occurred)");
  const Thrown unknown = Catch([] { backend::CheckHresult("x.cpp", 8, static_cast<HRESULT>(0x80FF0001UL)); });
  EXPECT_EQ(unknown.message, "HRESULT 0x80FF0001 (n/a)");
}

TEST(GalBackendErrors, SetupFailureSwitchNamesBackends)
{
  {
    const ScopedEnvironment unset("FAF_GAL_FAIL_SETUP", "");
    EXPECT_FALSE(backend::SetupFailureRequested("d3d12"));
  }
  {
    const ScopedEnvironment every("FAF_GAL_FAIL_SETUP", "1");
    EXPECT_TRUE(backend::SetupFailureRequested("d3d12"));
    EXPECT_TRUE(backend::SetupFailureRequested("vulkan"));
    EXPECT_FALSE(backend::SetupFailureRequested(nullptr));
  }
  {
    const ScopedEnvironment list("FAF_GAL_FAIL_SETUP", "d3d12,vulkan");
    EXPECT_TRUE(backend::SetupFailureRequested("d3d12"));
    EXPECT_TRUE(backend::SetupFailureRequested("vulkan"));
    EXPECT_FALSE(backend::SetupFailureRequested("d3d11"));
    EXPECT_FALSE(backend::SetupFailureRequested("d3d1")) << "a prefix of a listed name";
    EXPECT_FALSE(backend::SetupFailureRequested("vulk"));
  }
  {
    const ScopedEnvironment separators("FAF_GAL_FAIL_SETUP", "xd3d12; vulkan d3d11");
    EXPECT_FALSE(backend::SetupFailureRequested("d3d12")) << "part of a longer name";
    EXPECT_TRUE(backend::SetupFailureRequested("vulkan"));
    EXPECT_TRUE(backend::SetupFailureRequested("d3d11"));
  }
  {
    const ScopedEnvironment other("FAF_GAL_FAIL_SETUP", "10");
    EXPECT_FALSE(backend::SetupFailureRequested("d3d12")) << "only a lone 1 means every backend";
  }
}

TEST(GalBackendErrors, DiagnosticSwitchesDefaultToDirect3D9Behaviour)
{
  // Both are read once per process; they only differ when the switches were set at start.
  const char* const centres = std::getenv("FAF_GAL_D3D10_PIXEL_CENTRES");
  if (centres == nullptr || centres[0] != '1') {
    EXPECT_EQ(backend::Direct3D9PixelCentreShift(), 0.5f);
  }
  const char* const cull = std::getenv("FAF_GAL_D3D10_CULL");
  if (cull == nullptr || cull[0] != '1') {
    EXPECT_FALSE(backend::Direct3D10TechniqueCull());
  }
}

TEST(GalLockShadow, TheGuardBandCatchesWritesPastTheLockedRange)
{
  constexpr std::uint8_t kGuard = 0xA5U;
  const std::uint64_t before = backend::LockShadow::TotalBytes();
  {
    backend::LockShadow shadow;
    EXPECT_TRUE(shadow.Released());
    shadow.Reset(32U);
    EXPECT_FALSE(shadow.Released());
    EXPECT_GE(backend::LockShadow::TotalBytes(), before + 32U + 256U);
    for (std::size_t index = 0U; index < 32U; ++index) {
      EXPECT_EQ(shadow.data()[index], 0U);
    }
    for (std::size_t index = 32U; index < 32U + 256U; ++index) {
      ASSERT_EQ(shadow.data()[index], kGuard) << index;
    }

    std::uint8_t* const locked = shadow.Map(8U, 16U, "vertex buffer");
    EXPECT_EQ(locked, shadow.data() + 8U);
    std::memset(locked, 0x11, 16U);
    shadow.CheckGuard("vertex buffer");
    EXPECT_EQ(shadow.data()[32], kGuard);

    // A write past the end is found and the band re-armed.
    shadow.data()[33] = 0x00U;
    shadow.data()[40] = 0x00U;
    shadow.CheckGuard("vertex buffer");
    EXPECT_EQ(shadow.data()[33], kGuard);
    EXPECT_EQ(shadow.data()[40], kGuard);

    // A lock past the end grows the copy to cover it, guarded behind the locked range.
    std::uint8_t* const grown = shadow.Map(24U, 16U, nullptr);
    EXPECT_EQ(grown, shadow.data() + 24U);
    std::memset(grown, 0x22, 16U);
    shadow.CheckGuard(nullptr);
    for (std::size_t index = 40U; index < 40U + 256U; ++index) {
      ASSERT_EQ(shadow.data()[index], kGuard) << index;
    }

    // A whole-buffer lock moves the band back to the buffer's end.
    EXPECT_EQ(shadow.Map(0U, 0U, "index buffer"), shadow.data());
    EXPECT_EQ(shadow.data()[32], kGuard);
    EXPECT_EQ(shadow.data()[24], 0x22U) << "the data itself is kept";

    shadow.Release();
    EXPECT_TRUE(shadow.Released());
    EXPECT_EQ(backend::LockShadow::TotalBytes(), before);
    shadow.Reset(8U);
  }
  EXPECT_EQ(backend::LockShadow::TotalBytes(), before) << "the destructor gives the bytes back";
}

TEST(GalPipelineMemo, FindsOnlyStoredInputs)
{
  struct Inputs
  {
    std::uint64_t format;
    std::uint32_t state;
    std::uint32_t topology;
  };
  gpg::gal::PipelineMemo<Inputs, std::uintptr_t> memo;
  Inputs first;
  std::memset(&first, 0, sizeof(first));
  first.format = 7U;
  first.state = 3U;
  Inputs second = first;
  second.topology = 4U;

  EXPECT_EQ(memo.Find(first), 0U);
  memo.Store(first, 0x1000U);
  EXPECT_EQ(memo.Find(first), 0x1000U);
  EXPECT_EQ(memo.Find(second), 0U) << "a pipeline is never returned for other inputs";
  memo.Store(second, 0x2000U);
  EXPECT_EQ(memo.Find(second), 0x2000U);

  memo.Clear();
  EXPECT_EQ(memo.Find(first), 0U);
  EXPECT_EQ(memo.Find(second), 0U);

  // Many inputs share 64 slots: whatever is found is right, the rest is a miss.
  for (std::uint32_t index = 0U; index < 500U; ++index) {
    Inputs inputs = first;
    inputs.state = index;
    memo.Store(inputs, 0x10000U + index);
  }
  for (std::uint32_t index = 0U; index < 500U; ++index) {
    Inputs inputs = first;
    inputs.state = index;
    const std::uintptr_t found = memo.Find(inputs);
    EXPECT_TRUE(found == 0U || found == 0x10000U + index) << index;
  }
  Inputs last = first;
  last.state = 499U;
  EXPECT_EQ(memo.Find(last), 0x10000U + 499U) << "the latest store of a slot is found";
}

TEST(GalRuntimeInfo, DriverVersionsAreFourSixteenBitFields)
{
  EXPECT_EQ(gpg::gal::common::FormatWindowsDriverVersion(0x001F000D00110E4CULL), "31.13.17.3660");
  EXPECT_EQ(gpg::gal::common::FormatWindowsDriverVersion(0U), "0.0.0.0");
  EXPECT_EQ(gpg::gal::common::FormatWindowsDriverVersion(~0ULL), "65535.65535.65535.65535");

  gpg::gal::DeviceRuntimeInfo info;
  info.api = "D3D12";
  info.adapter = "Test adapter";
  info.dedicatedVideoMemory = 1024ULL * 1024ULL * 1024ULL;
  EXPECT_NO_THROW(gpg::gal::common::LogRuntimeInfo("D3D12", info));
}

TEST(GalHalfFloat, ExactValuesAndSpecialCases)
{
  using gpg::gal::FloatToHalf;
  EXPECT_EQ(FloatToHalf(0.0f), 0x0000U);
  EXPECT_EQ(FloatToHalf(-0.0f), 0x8000U);
  EXPECT_EQ(FloatToHalf(1.0f), 0x3C00U);
  EXPECT_EQ(FloatToHalf(-2.0f), 0xC000U);
  EXPECT_EQ(FloatToHalf(0.5f), 0x3800U);
  EXPECT_EQ(FloatToHalf(65504.0f), 0x7BFFU) << "the largest finite half";
  EXPECT_EQ(FloatToHalf(std::ldexp(1.0f, -14)), 0x0400U) << "the smallest normal half";
  EXPECT_EQ(FloatToHalf(std::ldexp(1.0f, -24)), 0x0001U) << "the smallest subnormal half";
  EXPECT_EQ(FloatToHalf(std::ldexp(3.0f, -24)), 0x0003U);
  EXPECT_EQ(FloatToHalf(-std::ldexp(1.0f, -15)), 0x8200U);

  // Past the range, infinities and NaNs: infinity of the same sign; below half the smallest
  // subnormal: zero.
  EXPECT_EQ(FloatToHalf(65536.0f), 0x7C00U);
  EXPECT_EQ(FloatToHalf(1.0e9f), 0x7C00U);
  EXPECT_EQ(FloatToHalf(-1.0e9f), 0xFC00U);
  EXPECT_EQ(FloatToHalf(std::numeric_limits<float>::infinity()), 0x7C00U);
  EXPECT_EQ(FloatToHalf(-std::numeric_limits<float>::infinity()), 0xFC00U);
  EXPECT_EQ(FloatToHalf(std::numeric_limits<float>::quiet_NaN()), 0x7C00U);
  EXPECT_EQ(FloatToHalf(std::ldexp(1.0f, -26)), 0x0000U);
  EXPECT_EQ(FloatToHalf(-std::ldexp(1.0f, -30)), 0x8000U);
}

TEST(GalHalfFloat, RoundsToNearestAndHalfwayDown)
{
  using gpg::gal::FloatToHalf;
  EXPECT_EQ(FloatToHalf(0.1f), 0x2E66U);
  EXPECT_EQ(FloatToHalf(1.0f / 3.0f), 0x3555U);
  // 1 + 2^-11 and 1 + 3 * 2^-11 lie exactly between two halves: D3DX rounds both down (IEEE
  // round-to-even would take the second up to 0x3C02).
  EXPECT_EQ(FloatToHalf(1.0f + std::ldexp(1.0f, -11)), 0x3C00U);
  EXPECT_EQ(FloatToHalf(1.0f + std::ldexp(3.0f, -11)), 0x3C01U);
  EXPECT_EQ(FloatToHalf(2049.0f), 0x6800U);
  // Just above halfway goes up.
  EXPECT_EQ(FloatToHalf(1.0f + std::ldexp(1.0f, -11) + std::ldexp(1.0f, -23)), 0x3C01U);
  EXPECT_EQ(FloatToHalf(2049.0f + 1.0f / 256.0f), 0x6801U);
}

TEST(GalStringUtils, CompareIsBoundedAndNormalised)
{
  using gpg::gal::STR_Compare;
  EXPECT_EQ(STR_Compare("abcd", "abcd", 4U), 0);
  EXPECT_EQ(STR_Compare("abcd", "abce", 4U), -1);
  EXPECT_EQ(STR_Compare("abce", "abcd", 4U), 1);
  EXPECT_EQ(STR_Compare("b", "a", 1U), 1);
  EXPECT_EQ(STR_Compare("x", "y", 0U), 0) << "nothing to compare";
  EXPECT_EQ(STR_Compare("abcdefgh", "abcdefgX", 7U), 0) << "only the first 7 bytes";
  EXPECT_EQ(STR_Compare("abcdeXgh", "abcdeYgh", 8U), -1);
  EXPECT_EQ(STR_Compare("abcdefg", "abcdefh", 7U), -1);
  EXPECT_EQ(STR_Compare("abcdefghi", "abcdefghj", 9U), -1);
  EXPECT_EQ(STR_Compare("abcdefghZ", "abcdefghA", 9U), 1);
  EXPECT_EQ(STR_Compare("\xFF", "\x01", 1U), 1) << "bytes compare unsigned";
  EXPECT_EQ(STR_Compare("ab", "ab", 2U), 0);
  EXPECT_EQ(STR_Compare("abc", "abd", 3U), -1);
}

TEST(GalStringUtils, FindInRangeWantsAnExactMatch)
{
  fa::string names[3] = {fa::string("alpha"), fa::string("beta"), fa::string("alphabet")};
  fa::string* const begin = names;
  fa::string* const end = names + 3;
  const char* search = "alpha";
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, end, &search), names + 0);
  search = "alphabet";
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, end, &search), names + 2);
  search = "beta";
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, end, &search), names + 1);
  search = "alp";
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, end, &search), end) << "a prefix is not a match";
  search = "alphabets";
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, end, &search), end);
  EXPECT_EQ(gpg::gal::STR_FindInRange(begin, begin, &search), begin) << "an empty range";
}

TEST(GalStateCache, OnlyAChangedValueNeedsADeviceCall)
{
  gpg::gal::StateCache<_D3DRENDERSTATETYPE, unsigned int> cache;
  EXPECT_TRUE(cache.Update(D3DRS_ZENABLE, 1U)) << "the first value of a state";
  EXPECT_FALSE(cache.Update(D3DRS_ZENABLE, 1U)) << "the same value again";
  EXPECT_TRUE(cache.Update(D3DRS_ZENABLE, 0U));
  EXPECT_FALSE(cache.Update(D3DRS_ZENABLE, 0U));
  EXPECT_TRUE(cache.Update(D3DRS_CULLMODE, 0U)) << "another state is cached on its own";
  EXPECT_FALSE(cache.Update(D3DRS_ZENABLE, 0U));

  gpg::gal::StateCache<_D3DSAMPLERSTATETYPE, unsigned int> sampler;
  EXPECT_TRUE(sampler.Update(D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP));
  EXPECT_FALSE(sampler.Update(D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP));
}
