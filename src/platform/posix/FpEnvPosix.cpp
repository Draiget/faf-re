// Engine addition (dedicated-server plan WPL.9): the floating-point environment of every
// POSIX thread is the one the Windows x64 build's threads run with (WPL.8: x87 control word
// 0x027F, MXCSR 0x1F80 on every thread of headless at beat 1).
//
// x86-64:
//   x87 control word 0x027F: 53-bit precision, round to nearest, every exception masked.
//                    Linux starts threads at 0x037F (64-bit precision).
//   MXCSR 0x1F80:    round to nearest, every exception masked, no flush-to-zero, no
//                    denormals-are-zero. The Linux default, set anyway so nothing inherited
//                    can leave FTZ/DAZ on.
//   The main thread gets it before any static initialiser (constructor priority 100); every
//   other thread at its start, through `-Wl,--wrap=pthread_create` (cmake/FafPosix.cmake):
//   the legacy threads, std::thread and the sim worker pool all start threads there.
//
// ARM64:
//   FPCR 0:          round to nearest, IEEE denormals, NaN propagation, no traps - what
//                    MXCSR 0x1F80 means on x86 (platform/FpControl.h). The x87 routines are
//                    software there and set their own precision. A new thread starts at 0 on
//                    Linux and macOS whatever its creator runs with (tests/linux/ToolchainCheck),
//                    so there is no thread start to intercept (Apple's linker has no --wrap
//                    either); the main thread is set here, and every simulation thread loads it
//                    again in platform::SetX87PrecisionControl.

#if !FAFRE_PLATFORM_WINDOWS

#include "platform/posix/FpEnvPosix.h"

#include "platform/FpControl.h"

#include <cstddef>
#include <cstdint>
#include <new>

#include <pthread.h>

namespace platform::posix
{
  void SetSimFloatingPointEnvironment() noexcept
  {
#if FAFRE_ARCH_X64
    const std::uint16_t controlWord = kSimX87ControlWord;
    asm volatile("fldcw %0" : : "m"(controlWord));
    platform::WriteMxcsr(kSimMxcsr);
#else
    platform::LoadSimFloatingPointControl();
#endif
  }

  FloatingPointState ReadFloatingPointEnvironment() noexcept
  {
    FloatingPointState state{};
#if FAFRE_ARCH_X64
    std::uint16_t controlWord = 0;
    asm volatile("fnstcw %0" : "=m"(controlWord));
    state.x87ControlWord = controlWord;
    state.mxcsr = platform::ReadMxcsr();
#else
    state.fpcr = platform::ReadFpcr();
#endif
    return state;
  }
} // namespace platform::posix

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wprio-ctor-dtor"
  __attribute__((constructor(100))) void SetMainThreadFloatingPointEnvironment()
  {
    platform::posix::SetSimFloatingPointEnvironment();
  }
#pragma clang diagnostic pop
} // namespace

#if FAFRE_ARCH_X64
namespace
{
  struct ThreadStart
  {
    void* (*routine)(void*);
    void* argument;
  };

  void* StartWithSimFloatingPointEnvironment(
    void* const raw
  )
  {
    const ThreadStart start = *static_cast<ThreadStart*>(raw);
    ::operator delete(raw);
    platform::posix::SetSimFloatingPointEnvironment();
    return start.routine(start.argument);
  }
} // namespace

extern "C" int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);

extern "C" int __wrap_pthread_create(
  pthread_t* const thread,
  const pthread_attr_t* const attributes,
  void* (*const routine)(void*),
  void* const argument
)
{
  auto* const start = static_cast<ThreadStart*>(::operator new(sizeof(ThreadStart), std::nothrow));
  if (start == nullptr) {
    return __real_pthread_create(thread, attributes, routine, argument);
  }
  start->routine = routine;
  start->argument = argument;
  const int result = __real_pthread_create(thread, attributes, &StartWithSimFloatingPointEnvironment, start);
  if (result != 0) {
    ::operator delete(start);
  }
  return result;
}
#endif // FAFRE_ARCH_X64

#if FAFRE_PLATFORM_MACOS // the default thread stack is 512 KB (platform/PosixCompat.h redirects here)
#undef pthread_create
extern "C" int pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);

/// pthread_create with Linux's 8 MB stack for a thread started without attributes (std::thread,
/// the legacy threads); attributes a caller passes are its own choice and go through unchanged.
extern "C" int faf_pthread_create(
  pthread_t* const thread,
  const pthread_attr_t* const attributes,
  void* (*const routine)(void*),
  void* const argument
)
{
  if (attributes != nullptr) {
    return ::pthread_create(thread, attributes, routine, argument);
  }
  pthread_attr_t wider;
  if (::pthread_attr_init(&wider) != 0) {
    return ::pthread_create(thread, nullptr, routine, argument);
  }
  (void)::pthread_attr_setstacksize(&wider, 8uz << 20);
  const int result = ::pthread_create(thread, &wider, routine, argument);
  (void)::pthread_attr_destroy(&wider);
  return result;
}
#endif

#endif // !FAFRE_PLATFORM_WINDOWS
