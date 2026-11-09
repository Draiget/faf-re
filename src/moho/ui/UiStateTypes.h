#pragma once

#include <cstdint>

// Engine addition (dedicated-server plan WPL.4, WPL.5): the user interface's state and event
// enumerations the simulation's reflection names (gpg::RRef::CurrentUIState and the
// EMauiEventType reflection in gpg/core/reflection/Reflection.cpp), moved unchanged out of
// moho/ui/UiRuntimeTypes.h so that file can name them without the user interface's headers.

namespace moho
{
  enum EUIState : std::int32_t
  {
    UIS_none = 0,
    UIS_splash = 1,
    UIS_frontend = 2,
    UIS_game = 3,
    UIS_lobby = 4,
  };

  extern EUIState sUIState;

  enum EMauiEventType : std::int32_t
  {
    MET_Unknown = 0,
    MET_MouseMotion = 1,
    MET_MouseEnter = 2,
    MET_MouseHover = 3,
    MET_MouseExit = 4,
    MET_ButtonPress = 5,
    MET_ButtonDClick = 6,
    MET_ButtonRelease = 7,
    MET_WheelRotation = 8,
    MET_KeyUp = 9,
    MET_KeyDown = 10,
    MET_Char = 11,
  };
} // namespace moho
