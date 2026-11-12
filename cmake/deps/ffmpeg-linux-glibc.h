/*
 * Force-included into the Linux client's FFmpeg (cmake/FafLinuxClient.cmake) so the download runs on
 * glibc 2.34 (issue #394; from Julian Cooper's faf-re fork). glibc 2.35 added a new hypot,
 * hypot@GLIBC_2.35, and links new calls to it; this binds FFmpeg's calls (libavutil) to the hypot
 * every glibc since 2.2.5 has. The simulation never calls libm's hypot, and the movie decoder's results
 * are only drawn. tools/release/linux/package.sh fails when the engine needs a glibc newer than 2.34.
 */
#include <features.h>
#if defined(__x86_64__) && defined(__GLIBC__)
__asm__(".symver hypot,hypot@GLIBC_2.2.5");
#endif
