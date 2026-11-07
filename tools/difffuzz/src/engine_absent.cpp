// Engine definitions the standalone difffuzz build does not compile (plan
// WPR.21). moho/collision/CColPrimitiveBase.cpp is compiled whole for the
// collision rows; its box SetTransform (VAxes3), CColPrimitiveBase::Collide
// (the assert) and Vector4f.cpp's ToString (STR_Printf) reach TUs that pull in
// reflection, the renderer's math and gpg's strings. No target calls those
// paths: reaching one aborts. faf_math_dump links the engine and does not use
// this file.

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/math/MathReflection.h"

#include <cstdio>
#include <cstdlib>

namespace
{
  [[noreturn]] void NoEngineDefinition(const char* const name)
  {
    std::fprintf(stderr, "difffuzz: %s called, but this build does not compile its engine TU\n", name);
    std::abort();
  }
} // namespace

namespace gpg
{
  void HandleAssertFailure(const char*, int, const char*) { NoEngineDefinition("gpg::HandleAssertFailure"); }
  fa::string STR_Printf(const char*, ...) { NoEngineDefinition("gpg::STR_Printf"); }
} // namespace gpg

namespace moho
{
  VAxes3::VAxes3(const Wm3::Quaternionf&) { NoEngineDefinition("moho::VAxes3::VAxes3(quat) (MathReflection.cpp)"); }
} // namespace moho
