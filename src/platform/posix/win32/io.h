#pragma once

// Engine addition (dedicated-server plan WPL.5): the MSVC CRT <io.h> directory search the
// shared code uses (the VFS's mount-point and directory walks, Lua's io.dir), for the Linux
// build. Implemented in platform/posix/Win32Shim.cpp.

#if defined(_WIN32)
#error "platform/posix/win32/io.h is for builds without the Windows SDK"
#endif

#include <Windows.h>

#include <cstdint>

#define _A_NORMAL 0x00u
#define _A_RDONLY 0x01u
#define _A_HIDDEN 0x02u
#define _A_SYSTEM 0x04u
#define _A_SUBDIR 0x10u
#define _A_ARCH 0x20u

struct __finddata64_t
{
  unsigned attrib;
  __time64_t time_create;
  __time64_t time_access;
  __time64_t time_write;
  std::int64_t size;
  char name[260];
};

/**
 * Matches the last component of `spec` against the directory named by the rest, as the CRT
 * does on NTFS: case-insensitively, `*.*` matching every name, "." and ".." included, in
 * NTFS's order (names compared by their upper-case form). Directory components themselves
 * are taken as the file system spells them. Returns -1 with errno ENOENT when nothing
 * matches.
 */
std::intptr_t _findfirst64(const char* spec, __finddata64_t* data);
int _findnext64(std::intptr_t handle, __finddata64_t* data);
int _findclose(std::intptr_t handle);
