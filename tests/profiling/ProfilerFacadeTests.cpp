#include "gpg/core/profiling/Profiler.h"
#include <cassert>
#include <string>

int main()
{
  FAF_PROFILE_FRAME("TestFrame");
  FAF_PROFILE_FRAME_DEFAULT();
  {
    FAF_PROFILE_ZONE();
    FAF_PROFILE_ZONE_NAMED("TestZone");
    const char* tag = "info";
    FAF_PROFILE_ZONE_TEXT(tag, 4);
  }
  FAF_PROFILE_SET_THREAD_NAME("MainTestThread");

  // Verify macros produce valid expressions in conditionals
  if (true)
    FAF_PROFILE_ZONE_NAMED("TrueBranch");
  else
    FAF_PROFILE_ZONE_NAMED("FalseBranch");

  return 0;
}
