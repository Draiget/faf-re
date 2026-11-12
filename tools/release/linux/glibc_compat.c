/*
 * The few glibc 2.36 and 2.38 functions Microsoft's Linux build of DXC (libdxcompiler.so, libdxil.so;
 * built on Ubuntu 24.04) calls, so the Linux download runs on glibc 2.34 (issue #394; from Julian
 * Cooper's faf-re fork, tools/linux-build/glibc-compat). tools/release/linux/package.sh builds it as
 * libfaf-glibc-compat.so, adds it to the DXC libraries' DT_NEEDED and marks their GLIBC_2.35+ version
 * requirements weak (elf_glibc_versions.py), so they load on glibc 2.34.
 *
 * The definitions are unversioned. The engine loads DXC with dlopen (platform/posix/dxc/DxcGlue.cpp),
 * and the dynamic linker searches the global scope (the program, libc, libm) before a dlopen'ed
 * library's own dependencies, so on glibc 2.38 and newer DXC still binds to glibc's own functions;
 * these are used only where glibc lacks them. The engine itself never calls them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>

#define FAF_COMPAT_EXPORT __attribute__((visibility("default")))

/*
 * glibc 2.38's C23 strtol family: the C11 functions, plus a "0b"/"0B" prefix for base 0 and 2.
 */
static int faf_binary_prefix(
  const char* text,
  int base
)
{
  if (base != 0 && base != 2) {
    return 0;
  }
  while (*text == ' ' || (*text >= '\t' && *text <= '\r')) {
    ++text;
  }
  if (*text == '+' || *text == '-') {
    ++text;
  }
  return text[0] == '0' && (text[1] == 'b' || text[1] == 'B') && (text[2] == '0' || text[2] == '1');
}

static const char* faf_after_binary_prefix(
  const char* text
)
{
  while (*text != '0') {
    ++text;
  }
  return text + 2;
}

#define FAF_C23_STRTO(name, type, c11)                                                                                 \
  FAF_COMPAT_EXPORT type name(const char* restrict text, char** restrict end, int base)                                \
  {                                                                                                                    \
    if (faf_binary_prefix(text, base)) {                                                                               \
      const char* p = text;                                                                                            \
      while (*p == ' ' || (*p >= '\t' && *p <= '\r')) {                                                                \
        ++p;                                                                                                           \
      }                                                                                                                \
      const int negative = *p == '-';                                                                                  \
      type value = c11(faf_after_binary_prefix(text), end, 2);                                                         \
      return negative ? (type)(0 - value) : value;                                                                     \
    }                                                                                                                  \
    return c11(text, end, base);                                                                                       \
  }

FAF_C23_STRTO(
  __isoc23_strtol,
  long,
  strtol
)
FAF_C23_STRTO(
  __isoc23_strtoul,
  unsigned long,
  strtoul
)
FAF_C23_STRTO(
  __isoc23_strtoll,
  long long,
  strtoll
)
FAF_C23_STRTO(
  __isoc23_strtoull,
  unsigned long long,
  strtoull
)

/* glibc 2.36's arc4random, on the getrandom system call (glibc 2.25). */
static void faf_random_bytes(
  void* buffer,
  size_t size
)
{
  unsigned char* out = (unsigned char*)buffer;
  while (size > 0) {
    const ssize_t got = getrandom(out, size, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      abort(); /* as glibc's arc4random: it never returns without randomness */
    }
    out += got;
    size -= (size_t)got;
  }
}

FAF_COMPAT_EXPORT uint32_t arc4random(
  void
)
{
  uint32_t value;
  faf_random_bytes(&value, sizeof value);
  return value;
}

/*
 * fmod@GLIBC_2.38 is glibc's fmod without the old SVID error wrapper; the remainder is the same exact
 * value. x87 FPREM computes it exactly, so this needs no libm and cannot bind back to itself.
 */
FAF_COMPAT_EXPORT double fmod(
  double x,
  double y
)
{
  long double rx = x;
  const long double ry = y;
  unsigned short status;
  do {
    __asm__ volatile("fprem\n\tfnstsw %1" : "+t"(rx), "=a"(status) : "u"(ry));
  } while (status & 0x0400); /* C2: the reduction is not complete yet */
  return (double)rx;
}
