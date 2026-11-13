#pragma once

#include "platform/Window.h"
#include "platform/shell/event.h"

class ShellWindow;

/**
 * Fills a shell mouse event of `event`'s type from a window-system event aimed at `target`:
 * position, buttons, modifiers and wheel. A wheel event's position is on the screen, as
 * WM_MOUSEWHEEL's was (CMauiEventMapper takes it back to the client); the others stay in
 * `target`'s client pixels.
 */
void ShellFillMouseEvent(ShellMouseEvent& event, const ShellWindow& target, const platform::window::Event& source);
