#include <gtest/gtest.h>

#include "moho/console/CConCommand.h"

namespace moho
{
  extern bool ui_FactoryPreOrders;
  [[nodiscard]] bool IsFactoryPreOrdersEnabled();
  void SetFactoryPreOrdersEnabled(bool enabled);
}

TEST(PlannedFactoryPreOrdersTest, DefaultIsEnabled)
{
  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(PlannedFactoryPreOrdersTest, SetFactoryPreOrdersEnabledTogglesState)
{
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(PlannedFactoryPreOrdersTest, ConCommandExecutionTogglesState)
{
  moho::CON_Execute("ui_FactoryPreOrders 0");
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::CON_Execute("ui_FactoryPreOrders 1");
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}
