#include "headless/HeadlessMain.h"

namespace
{
  const bool sRegistered = (gGameReplayPlayerMain = &HEADLESS_Main, true);
}
