#pragma once

// Engine addition (dedicated-server plan WPL.5): <intrin.h> for the POSIX builds. clang's own
// intrin.h is for Microsoft targets; elsewhere the x86 intrinsics come from <x86intrin.h>. On
// ARM64 there are none to give: the shared code's x86 intrinsics are behind FAFRE_ARCH_X86 /
// FAFRE_ARCH_X64, with portable code for the rest (platform/SpinPause.h, platform/FpControl.h).

#include "../../PlatformDefines.h"

#if FAFRE_ARCH_X86 || FAFRE_ARCH_X64
#include <x86intrin.h>
#endif
