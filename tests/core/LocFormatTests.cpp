// moho::LocFormat (moho/client/Localization.h): the player-name messages' localized text, filled in without printf.
// The binary passed that text to printf as the format (the lobby's "Lost connection to %s." at 0x007C60CB-0x007C60CE,
// CLobby::Msgf 0x007C7FC0), so a '%' in a translation read arguments that were never passed.

#include <cstdio>
#include <string>
#include <gtest/gtest.h>

#include "moho/client/Localization.h"

namespace
{
  std::string Printf(
    const char* const format,
    const char* const name
  )
  {
    char buffer[256]{};
    std::snprintf(buffer, sizeof(buffer), format, name);
    return buffer;
  }
} // namespace

TEST(
  LocFormat,
  ShippedTranslationsComeOutAsPrintfMadeThem
)
{
  // Engine0002-0005 and Engine0017 as loc/US, DE, CZ and CN ship them: one "%s" each.
  const char* const shipped[] = {
    "%s disconnected.",
    "Lost connection to %s.",
    "Connection to %s established.",
    "Connecting to %s...",
    "%s has been ejected due to connectivity issues.",
    "Verbindung zu %s wird hergestellt ...",
    "Ztraceno spojen\xC3\xAD s: %s.",
    "\xE4\xB8\x8E%s\xE7\x9A\x84\xE8\xBF\x9E\xE6\x8E\xA5\xE4\xB8\xAD\xE6\x96\xAD\xE3\x80\x82",
  };
  for (const char* const text : shipped) {
    EXPECT_EQ(moho::LocFormat(text, {"Alice"}), Printf(text, "Alice")) << text;
  }
}

TEST(
  LocFormat,
  OtherSpecifiersStayAsText
)
{
  EXPECT_EQ(moho::LocFormat("%d %s %n %x %", {"Bob"}), "%d Bob %n %x %");
  EXPECT_EQ(moho::LocFormat("100%% for %s", {"Bob"}), "100% for Bob");
}

TEST(
  LocFormat,
  ArgumentsAreUsedInOrderAndMissingOnesAreEmpty
)
{
  EXPECT_EQ(moho::LocFormat("%s and %s", {"A", "B"}), "A and B");
  EXPECT_EQ(moho::LocFormat("%s and %s", {"A"}), "A and ");
  EXPECT_EQ(moho::LocFormat("No currently active session", {}), "No currently active session");
  EXPECT_EQ(moho::LocFormat("", {"A"}), "");
}

TEST(
  LocFormat,
  ANameIsCopiedNotExpanded
)
{
  EXPECT_EQ(moho::LocFormat("%s disconnected.", {"100%%%s%n"}), "100%%%s%n disconnected.");
}
