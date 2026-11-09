#pragma once

#if defined(TRACY_ENABLE)
#  include <tracy/Tracy.hpp>

#  define FAF_PROFILE_FRAME(name)                  FrameMarkNamed(name)
#  define FAF_PROFILE_FRAME_DEFAULT()              FrameMark
#  define FAF_PROFILE_ZONE()                       ZoneScoped
#  define FAF_PROFILE_ZONE_NAMED(name)             ZoneScopedN(name)
#  define FAF_PROFILE_ZONE_TEXT(str, len)          ZoneText(str, len)
// A zone named at run time (a task's type, a Lua function): `name` is a C string the
// profiler copies. Costs more than a named zone; for breakdowns, not for every call.
#  define FAF_PROFILE_ZONE_TRANSIENT(name)         ZoneTransientN(fafTransientZone, name, true)
#  define FAF_PROFILE_SET_THREAD_NAME(name)        tracy::SetThreadName(name)
#  define FAF_PROFILE_ALLOC(ptr, size)             TracyAlloc(ptr, size)
#  define FAF_PROFILE_FREE(ptr)                    TracyFree(ptr)
#  define FAF_PROFILE_ALLOC_NAMED(ptr, size, name) TracyAllocN(ptr, size, name)
#  define FAF_PROFILE_FREE_NAMED(ptr, name)        TracyFreeN(ptr, name)
#else
#  define FAF_PROFILE_FRAME(name)                  ((void)0)
#  define FAF_PROFILE_FRAME_DEFAULT()              ((void)0)
#  define FAF_PROFILE_ZONE()                       ((void)0)
#  define FAF_PROFILE_ZONE_NAMED(name)             ((void)0)
#  define FAF_PROFILE_ZONE_TEXT(str, len)          ((void)0)
#  define FAF_PROFILE_ZONE_TRANSIENT(name)         ((void)0)
#  define FAF_PROFILE_SET_THREAD_NAME(name)        ((void)0)
#  define FAF_PROFILE_ALLOC(ptr, size)             ((void)0)
#  define FAF_PROFILE_FREE(ptr)                    ((void)0)
#  define FAF_PROFILE_ALLOC_NAMED(ptr, size, name) ((void)0)
#  define FAF_PROFILE_FREE_NAMED(ptr, name)        ((void)0)
#endif
