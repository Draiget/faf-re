#pragma once

// Engine addition (dedicated-server plan WPL.5): <mmreg.h> for the Linux build. What the shared
// code uses from it is declared in platform/posix/win32/Windows.h.
//
// The Linux client (issue #258) also takes the wave formats from here, with the Windows layout
// (packed to one byte: WAVEFORMATEX is 18 bytes, WAVEFORMATEXTENSIBLE 40): the audio engine reads
// the final mix format through them, as FAudio's FAudioWaveFormatEx(tensible) lays it out.

#include <Windows.h>

#pragma pack(push, 1)
struct tWAVEFORMATEX
{
  WORD wFormatTag;
  WORD nChannels;
  DWORD nSamplesPerSec;
  DWORD nAvgBytesPerSec;
  WORD nBlockAlign;
  WORD wBitsPerSample;
  WORD cbSize;
};
using WAVEFORMATEX = tWAVEFORMATEX;

struct WAVEFORMATEXTENSIBLE
{
  WAVEFORMATEX Format;
  union
  {
    WORD wValidBitsPerSample;
    WORD wSamplesPerBlock;
    WORD wReserved;
  } Samples;
  DWORD dwChannelMask;
  GUID SubFormat;
};
#pragma pack(pop)

static_assert(sizeof(WAVEFORMATEX) == 18, "WAVEFORMATEX has its Windows size");
static_assert(sizeof(WAVEFORMATEXTENSIBLE) == 40, "WAVEFORMATEXTENSIBLE has its Windows size");
