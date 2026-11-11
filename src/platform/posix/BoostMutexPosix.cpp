// Engine addition (issues #255, #256): boost 1.34's libs/thread/src/mutex.cpp for POSIX, with
// recursive mutexes, in place of compiling that file as it is.
//
// On Windows boost::mutex, try_mutex and timed_mutex are critical sections and Win32 mutexes,
// which the thread holding them may take again, and the engine relies on it: STAT_GetLuaTable
// (moho/misc/StatItem.cpp) holds a stat item's lock while StatItem::GetString takes it again. With
// boost's plain pthread mutex the same call deadlocks the Linux client's main thread in its first
// frame. Here every pthread mutex boost's file creates is a recursive one, as on Windows; the
// rest of boost's code is used unchanged.

#include <pthread.h>

#include <boost/thread/detail/config.hpp>
#include <boost/thread/exceptions.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/xtime.hpp>

namespace
{
  // pthread_mutex_init with no attributes made recursive (boost always passes none).
  int RecursivePthreadMutexInit(
    pthread_mutex_t* const mutex,
    const pthread_mutexattr_t* const attributes
  )
  {
    if (attributes != nullptr) {
      return pthread_mutex_init(mutex, attributes);
    }
    pthread_mutexattr_t recursive;
    pthread_mutexattr_init(&recursive);
    pthread_mutexattr_settype(&recursive, PTHREAD_MUTEX_RECURSIVE);
    const int result = pthread_mutex_init(mutex, &recursive);
    pthread_mutexattr_destroy(&recursive);
    return result;
  }
} // namespace

#define pthread_mutex_init RecursivePthreadMutexInit
#include "libs/thread/src/mutex.cpp"
#undef pthread_mutex_init
