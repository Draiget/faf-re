// The shell's mouse events from window-system events (src/platform/shell/mouse.h): a wheel event's position
// is on the screen, as WM_MOUSEWHEEL's was, so CMauiEventMapper's ScreenToClient lands it back on the
// pixel under the cursor; the other mouse events stay in client pixels.
#include "platform/shell/Shell.h"
#include "platform/shell/mouse.h"

#include <gtest/gtest.h>

namespace
{
  // A window whose client area starts at (300, 120) on the screen: a windowed game not in the corner.
  constexpr int kClientLeft = 300;
  constexpr int kClientTop = 120;

  platform::window::Event MouseAt(
    const platform::window::EventType type,
    const int x,
    const int y
  )
  {
    platform::window::Event source;
    source.type = type;
    source.x = x;
    source.y = y;
    return source;
  }
} // namespace

TEST(
  ShellMouseEvent,
  WheelPositionComesBackToTheCursorThroughScreenToClient
)
{
  ShellWindow window;
  window.SetClientArea(kClientLeft, kClientTop, 1024, 768);
  platform::window::Event source = MouseAt(platform::window::EventType::MouseWheel, 10, 20);
  source.wheel = 1.0f;

  ShellMouseEvent event(SHELL_EVT_MOUSEWHEEL);
  ShellFillMouseEvent(event, window, source);

  EXPECT_EQ(event.m_x, kClientLeft + 10);
  EXPECT_EQ(event.m_y, kClientTop + 20);
  int x = event.m_x;
  int y = event.m_y;
  window.ScreenToClient(&x, &y);
  EXPECT_EQ(x, 10);
  EXPECT_EQ(y, 20);
  EXPECT_EQ(event.m_wheelRotation, 120);
  EXPECT_EQ(event.m_wheelDelta, 120);
}

TEST(
  ShellMouseEvent,
  WheelDownIsANegativeNotch
)
{
  ShellWindow window;
  window.SetClientArea(kClientLeft, kClientTop, 1024, 768);
  platform::window::Event source = MouseAt(platform::window::EventType::MouseWheel, 0, 0);
  source.wheel = -1.0f;

  ShellMouseEvent event(SHELL_EVT_MOUSEWHEEL);
  ShellFillMouseEvent(event, window, source);

  EXPECT_EQ(event.m_wheelRotation, -120);
  EXPECT_EQ(event.m_x, kClientLeft);
  EXPECT_EQ(event.m_y, kClientTop);
}

TEST(
  ShellMouseEvent,
  MotionAndClicksStayInClientPixels
)
{
  ShellWindow window;
  window.SetClientArea(kClientLeft, kClientTop, 1024, 768);
  platform::window::Event source = MouseAt(platform::window::EventType::MouseMove, 10, 20);
  source.buttonsDown = platform::window::kLeftDown;

  ShellMouseEvent motion(SHELL_EVT_MOTION);
  ShellFillMouseEvent(motion, window, source);
  EXPECT_EQ(motion.m_x, 10);
  EXPECT_EQ(motion.m_y, 20);
  EXPECT_TRUE(motion.m_leftDown);

  ShellMouseEvent press(SHELL_EVT_LEFT_DOWN);
  ShellFillMouseEvent(press, window, MouseAt(platform::window::EventType::MouseDown, 10, 20));
  EXPECT_EQ(press.m_x, 10);
  EXPECT_EQ(press.m_y, 20);
}
