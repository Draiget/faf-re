#pragma once

// Engine addition (dedicated-server plan WPL.5): <intrin.h> for the Linux build. clang's own
// intrin.h is for Microsoft targets; on Linux the x86 intrinsics come from <x86intrin.h>, and
// the MSVC-only ones the shared code names (the _Interlocked* family) are clang builtins
// under -fms-extensions.

#include <x86intrin.h>
