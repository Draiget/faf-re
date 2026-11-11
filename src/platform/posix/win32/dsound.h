#pragma once

// Engine addition (dedicated-server plan WPL.5): <dsound.h> for the Linux build. What the shared
// code uses from it is declared in platform/posix/win32/Windows.h.

#include <Windows.h>

// The volume range DirectSound attenuates in, in hundredths of a decibel: the client's movie volume
// is kept in these units (issue #255).
#define DSBVOLUME_MIN (-10000)
#define DSBVOLUME_MAX 0
