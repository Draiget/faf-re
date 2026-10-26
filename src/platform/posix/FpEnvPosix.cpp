// Engine addition (dedicated-server plan WPL.9): the floating-point environment of every
// Linux thread is the one the Windows x64 build's threads run with (WPL.8: x87 control word
// 0x027F, MXCSR 0x1F80 on every thread of faf-replay at beat 1).
//
//   x87 control word 0x027F: 53-bit precision, round to nearest, every exception masked.
//                    Linux starts threads at 0x037F (64-bit precision).
//   MXCSR 0x1F80:    round to nearest, every exception masked, no flush-to-zero, no
//                    denormals-are-zero. The Linux default, set anyway so nothing inherited
//                    can leave FTZ/DAZ on.
//
// The main thread gets it before any static initialiser (constructor priority 100); every
// other thread at its start, through `-Wl,--wrap=pthread_create` (cmake/FafLinux.cmake):
// boost.thread, std::thread and the sim worker pool all start threads there.

#if !defined(_WIN32)

#include "platform/posix/FpEnvPosix.h"

#include <cstdint>
#include <new>

#include <pthread.h>

namespace platform::posix
{
  void SetSimFloatingPointEnvironment() noexcept
  {
    const std::uint16_t controlWord = kSimX87ControlWord;
    const std::uint32_t mxcsr = kSimMxcsr;
    asm volatile("fldcw %0" : : "m"(controlWord));
    asm volatile("ldmxcsr %0" : : "m"(mxcsr));
  }

  FloatingPointState ReadFloatingPointEnvironment() noexcept
  {
    FloatingPointState state{};
    std::uint16_t controlWord = 0;
    std::uint32_t mxcsr = 0;
    asm volatile("fnstcw %0" : "=m"(controlWord));
    asm volatile("stmxcsr %0" : "=m"(mxcsr));
    state.x87ControlWord = controlWord;
    state.mxcsr = mxcsr;
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

  struct ThreadStart
  {
    void* (*routine)(void*);
    void* argument;
  };

  void* StartWithSimFloatingPointEnvironment(void* const raw)
  {
    const ThreadStart start = *static_cast<ThreadStart*>(raw);
    ::operator delete(raw);
    platform::posix::SetSimFloatingPointEnvironment();
    return start.routine(start.argument);
  }
} // namespace

extern "C" int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);

extern "C" int __wrap_pthread_create(
  pthread_t* const thread, const pthread_attr_t* const attributes, void* (*const routine)(void*), void* const argument
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

#endif // !defined(_WIN32)
