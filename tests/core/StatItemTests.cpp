// The stats tree (moho/misc/StatItem.h): army and unit statistics, kept in the sim and in its saves. Values,
// their text forms, the per-tick pulse that publishes a value to the realtime slot, and the tree.

#include "moho/misc/StatItem.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

namespace
{
  std::int32_t FloatBits(const float value)
  {
    std::int32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  std::string Text(moho::StatItem& stat, const bool realtime)
  {
    fa::string value;
    stat.GetString(realtime, &value);
    return value.c_str();
  }

  /** A child the parent owns: StatItem's destructor deletes its children. */
  moho::StatItem* NewChild(moho::StatItem& parent, const char* const name)
  {
    auto* const child = new moho::StatItem(name);
    parent.AttachChild(child);
    return child;
  }
} // namespace

// An integer stat reads its primary slot as int, float and "%i" text (0x00418750 formats with "%i" at 0xE00F54);
// the realtime slot is separate and stays 0 until a pulse publishes the value.
TEST(MohoStatItem, IntegerStatReadsAsIntFloatAndText)
{
  moho::StatItem stat("Units_Built");
  stat.SynchronizeAsInt();
  EXPECT_EQ(stat.mType, moho::EStatType::kInt);
  const std::int32_t value = 42;
  EXPECT_EQ(stat.SetInt(&value), 0); // returns the previous bits
  EXPECT_EQ(stat.GetInt(false), 42);
  EXPECT_EQ(stat.GetFloat(false), 42.0f);
  EXPECT_EQ(Text(stat, false), "42");
  EXPECT_EQ(stat.GetInt(true), 0);
  EXPECT_EQ(stat.SetInt(nullptr), 42); // a null value stores 0 (0x00751370)
  EXPECT_EQ(stat.GetInt(false), 0);
}

// A float stat keeps the float's bits; AddFloat adds atomically, and the text is "%.2f" (0xE00F58).
TEST(MohoStatItem, FloatStatAddsAndPrintsTwoDecimals)
{
  moho::StatItem stat("Economy_Mass");
  stat.SynchronizeAsFloat();
  stat.StorePrimaryBits(FloatBits(2.5f));
  float delta = 1.25f;
  (void)stat.AddFloat(&delta);
  EXPECT_EQ(stat.GetFloat(false), 3.75f);
  EXPECT_EQ(stat.GetInt(false), 3); // truncated
  EXPECT_EQ(Text(stat, false), "3.75");
  delta = -10.0f;
  (void)stat.AddFloat(&delta);
  EXPECT_EQ(Text(stat, false), "-6.25");
}

// A string stat parses its text for the numeric reads, as atoi and atof do.
TEST(MohoStatItem, StringStatParsesItsText)
{
  moho::StatItem stat("Name");
  stat.mType = moho::EStatType::kString;
  stat.SetValue(fa::string("12.5 units"));
  EXPECT_EQ(Text(stat, false), "12.5 units");
  EXPECT_EQ(stat.GetInt(false), 12);
  EXPECT_EQ(stat.GetFloat(false), 12.5f);
  stat.Clear(false);
  EXPECT_EQ(Text(stat, false), "");
}

// A tick pulse (ClearChildren(1), 0x00418A90) publishes each tick-mode stat's primary value to its realtime slot
// and clears the primary; stats in another pulse mode keep their values.
TEST(MohoStatItem, TickPulsePublishesAndClearsOnlyTickStats)
{
  moho::StatItem root("Root");
  moho::StatItem* const perTick = NewChild(root, "PerTick");
  moho::StatItem* const kept = NewChild(root, "Kept");
  for (moho::StatItem* const stat : {perTick, kept}) {
    stat->SynchronizeAsInt();
    const std::int32_t seven = 7;
    (void)stat->SetInt(&seven);
  }
  (void)perTick->Release(static_cast<std::int32_t>(moho::EPulseMode::kTick)); // Release sets the pulse mode

  root.ClearChildren(static_cast<std::int32_t>(moho::EPulseMode::kTick));
  EXPECT_EQ(perTick->GetInt(true), 7);
  EXPECT_EQ(perTick->GetInt(false), 0);
  EXPECT_EQ(kept->GetInt(false), 7);
  EXPECT_EQ(kept->GetInt(true), 0);
}

// Clear(true) clears the whole subtree; Clear(false) only the stat itself (0x00418B00).
TEST(MohoStatItem, RecursiveClearReachesEveryDescendant)
{
  moho::StatItem root("Root");
  root.SynchronizeAsInt();
  moho::StatItem* const child = NewChild(root, "Child");
  moho::StatItem* const grandchild = NewChild(*child, "Grandchild");
  const std::int32_t five = 5;
  for (moho::StatItem* const stat : {&root, child, grandchild}) {
    stat->SynchronizeAsInt();
    (void)stat->SetInt(&five);
  }
  root.Clear(false);
  EXPECT_EQ(root.GetInt(false), 0);
  EXPECT_EQ(child->GetInt(false), 5);
  root.Clear(true);
  EXPECT_EQ(child->GetInt(false), 0);
  EXPECT_EQ(grandchild->GetInt(false), 0);
}

// Children are found by exact name among the direct children only; re-attaching moves a child between parents.
TEST(MohoStatItem, ChildrenAreFoundByNameAndMove)
{
  moho::StatItem root("Root");
  moho::StatItem* const a = NewChild(root, "A");
  moho::StatItem* const b = NewChild(root, "B");
  moho::StatItem* const deep = NewChild(*a, "Deep");
  EXPECT_EQ(root.FindDirectChildByName(fa::string("A")), a);
  EXPECT_EQ(root.FindDirectChildByName(fa::string("B")), b);
  EXPECT_EQ(root.FindDirectChildByName(fa::string("Deep")), nullptr);
  EXPECT_EQ(root.FindDirectChildByName(fa::string("a")), nullptr);

  b->AttachChild(deep); // moves from A to B
  EXPECT_EQ(a->FindDirectChildByName(fa::string("Deep")), nullptr);
  EXPECT_EQ(b->FindDirectChildByName(fa::string("Deep")), deep);
}
