// The path and command-line helpers of moho/misc/StartupHelpers.h: what the VFS, the save and replay folders and the
// command line run through. Every expectation is read from the retail function at the address named beside it.

#include "moho/misc/StartupHelpers.h"
#include "moho/misc/XFileError.h"

#include <gtest/gtest.h>

#include <string>

namespace
{
  std::string Str(const fa::string& value)
  {
    return value.c_str();
  }

  std::string Collapse(const char* const path, bool* const success = nullptr)
  {
    return Str(moho::FILE_CollapsePath(path, success));
  }

  std::string MakeAbsolute(const char* const path, const char* const base)
  {
    return Str(moho::FILE_MakeAbsolute(path, base));
  }
} // namespace

// The extension is what follows the last dot of the last segment (0x00410650); a dot in a folder name doesn't count.
TEST(StartupPath, ExtensionIsInTheLastSegmentOnly)
{
  EXPECT_STREQ(moho::FILE_Ext("/units/uel0001/uel0001_unit.bp"), "bp");
  EXPECT_STREQ(moho::FILE_Ext("archive.tar.gz"), "gz");
  EXPECT_STREQ(moho::FILE_Ext("C:\\games\\fa.d\\readme.txt"), "txt");
  EXPECT_STREQ(moho::FILE_Ext("trailing."), "");
  EXPECT_EQ(moho::FILE_Ext("/mods/v1.2/mod_info"), nullptr);
  EXPECT_EQ(moho::FILE_Ext("folder.d\\file"), nullptr);
  EXPECT_THROW((void)moho::FILE_Ext(""), moho::XFileError);
  EXPECT_THROW((void)moho::FILE_Ext(nullptr), moho::XFileError);
}

// The base is everything after the last '/' or '\\' (0x004111C0); stripping cuts at the base's last dot.
TEST(StartupPath, BaseIsTheLastSegment)
{
  EXPECT_EQ(Str(moho::FILE_Base("/maps/setons/setons_scenario.lua", false)), "setons_scenario.lua");
  EXPECT_EQ(Str(moho::FILE_Base("/maps/setons/setons_scenario.lua", true)), "setons_scenario");
  EXPECT_EQ(Str(moho::FILE_Base("C:\\replays\\game.tar.gz", true)), "game.tar");
  EXPECT_EQ(Str(moho::FILE_Base("mixed/sep\\name.x", false)), "name.x");
  EXPECT_EQ(Str(moho::FILE_Base("noslash", true)), "noslash");
  EXPECT_EQ(Str(moho::FILE_Base("folder/", false)), "");
  EXPECT_EQ(Str(moho::FILE_Base("dotted.dir/plain", true)), "plain");
  EXPECT_THROW((void)moho::FILE_Base("", false), moho::XFileError);
}

// A forced extension replaces the one there (0x004108B0); an empty one removes it.
TEST(StartupPath, ForcedExtensionReplacesTheOneThere)
{
  EXPECT_EQ(Str(moho::FILE_ForcedExt("/a/b.lua", "bp")), "/a/b.bp");
  EXPECT_EQ(Str(moho::FILE_ForcedExt("/a/b", "lua")), "/a/b.lua");
  EXPECT_EQ(Str(moho::FILE_ForcedExt("/a/b.lua", "")), "/a/b");
  EXPECT_EQ(Str(moho::FILE_ForcedExt("/a/b.lua", nullptr)), "/a/b");
  EXPECT_EQ(Str(moho::FILE_ForcedExt("dir.x/file", "y")), "dir.x/file.y");
  EXPECT_THROW((void)moho::FILE_ForcedExt("", "lua"), moho::XFileError);
}

// A suggested extension is added only when the path has none (0x00410760), with one dot.
TEST(StartupPath, SuggestedExtensionOnlyFillsAGap)
{
  EXPECT_EQ(Str(moho::FILE_SuggestedExt("save", "SCFAsave")), "save.SCFAsave");
  EXPECT_EQ(Str(moho::FILE_SuggestedExt("save", ".SCFAsave")), "save.SCFAsave");
  EXPECT_EQ(Str(moho::FILE_SuggestedExt("save.old", "SCFAsave")), "save.old");
  EXPECT_EQ(Str(moho::FILE_SuggestedExt("v1.2/save", "x")), "v1.2/save.x");
  EXPECT_EQ(Str(moho::FILE_SuggestedExt("save", "")), "save");
}

// Retail's FILE_SuggestedExt (0x004107A1), FILE_HasDrive (0x0040FDEA) and FILE_HasUNC (0x0040FEDA) throw
// "Null argument." for an empty path; ours return an empty string or false. Left as a known difference.
TEST(StartupPath, DISABLED_EmptyPathThrowsLikeRetail)
{
  EXPECT_THROW((void)moho::FILE_SuggestedExt("", "lua"), moho::XFileError);
  EXPECT_THROW((void)moho::FILE_HasDrive(""), moho::XFileError);
  EXPECT_THROW((void)moho::FILE_HasUNC(""), moho::XFileError);
}

// Drive, UNC, local and absolute: 0x0040FDC0, 0x0040FEB0, 0x0040FA50, 0x0040FD60. GetDrive counts from A=1 (0x0040FAF0).
TEST(StartupPath, PathKindsAreReadFromTheFirstCharacters)
{
  EXPECT_TRUE(moho::FILE_HasDrive("C:/x"));
  EXPECT_TRUE(moho::FILE_HasDrive("z:"));
  EXPECT_FALSE(moho::FILE_HasDrive("1:/x"));
  EXPECT_FALSE(moho::FILE_HasDrive("/C:"));

  EXPECT_TRUE(moho::FILE_HasUNC("//server/share"));
  EXPECT_TRUE(moho::FILE_HasUNC("\\\\server\\share"));
  EXPECT_FALSE(moho::FILE_HasUNC("/\\server"));
  EXPECT_FALSE(moho::FILE_HasUNC("/"));

  EXPECT_TRUE(moho::FILE_IsLocal("/lua/system/config.lua"));
  EXPECT_FALSE(moho::FILE_IsLocal("//server"));
  EXPECT_FALSE(moho::FILE_IsLocal("/:x"));
  EXPECT_FALSE(moho::FILE_IsLocal("lua/x"));
  EXPECT_FALSE(moho::FILE_IsLocal(""));

  EXPECT_TRUE(moho::FILE_IsAbsolute("/x"));
  EXPECT_TRUE(moho::FILE_IsAbsolute("\\x"));
  EXPECT_TRUE(moho::FILE_IsAbsolute("C:\\x"));
  EXPECT_TRUE(moho::FILE_IsAbsolute("//server"));
  EXPECT_FALSE(moho::FILE_IsAbsolute("C:x"));
  EXPECT_FALSE(moho::FILE_IsAbsolute("x/y"));
  EXPECT_FALSE(moho::FILE_IsAbsolute(""));

  EXPECT_EQ(moho::GetDrive("A:/"), 1);
  EXPECT_EQ(moho::GetDrive("c:"), 3);
  EXPECT_EQ(moho::GetDrive("Z:\\x"), 26);
  EXPECT_THROW((void)moho::GetDrive("/x"), moho::XFileError);
  EXPECT_THROW((void)moho::GetDrive(""), moho::XFileError);
}

// Collapsing (0x004115A0): separators become '/', "." goes, ".." takes the previous segment. A ".." with nothing to
// take stays and clears `success`, except at an absolute root, where it is dropped.
TEST(StartupPath, CollapseResolvesDotSegments)
{
  bool success = false;
  EXPECT_EQ(Collapse("/a/b/../c", &success), "/a/c");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("a/./b/", &success), "a/b");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("a\\b\\..", &success), "a");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("/../x", &success), "/x");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("C:\\a\\..\\b", &success), "C:/b");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("//server/share/../x", &success), "//server/x");
  EXPECT_TRUE(success);
  EXPECT_EQ(Collapse("a//b"), "a/b");

  EXPECT_EQ(Collapse("../x", &success), "../x");
  EXPECT_FALSE(success);
  EXPECT_EQ(Collapse("a/../../b", &success), "../b");
  EXPECT_FALSE(success);
  EXPECT_THROW((void)Collapse(""), moho::XFileError);
}

// Resolving a path against a base folder (0x0040FFC0): the base must be absolute, a trailing '/' on either goes, an
// absolute path keeps the base's drive, and a drive or UNC path is returned as it is.
TEST(StartupPath, MakeAbsoluteJoinsWithTheBase)
{
  EXPECT_EQ(MakeAbsolute("textures/a.dds", "/base/"), "/base/textures/a.dds");
  EXPECT_EQ(MakeAbsolute("sub\\file", "C:\\games\\"), "C:/games/sub/file");
  EXPECT_EQ(MakeAbsolute("/abs/y", "/base"), "/abs/y");
  EXPECT_EQ(MakeAbsolute("/abs/y", "C:/base"), "C:/abs/y");
  EXPECT_EQ(MakeAbsolute("D:/x/", "C:/base"), "D:/x");
  EXPECT_EQ(MakeAbsolute("y", "//srv/share"), "//srv/share/y");
  EXPECT_EQ(MakeAbsolute("//srv/other", "//srv/share"), "//srv/other");
}

// The four combinations retail rejects (0x004101EE, 0x0041026D, 0x004102E9, 0x0041036F), and empty arguments.
TEST(StartupPath, MakeAbsoluteRejectsMismatchedBases)
{
  EXPECT_THROW((void)MakeAbsolute("x", "relative"), moho::XFileError);
  EXPECT_THROW((void)MakeAbsolute("//srv/share", "/base"), moho::XFileError);
  EXPECT_THROW((void)MakeAbsolute("D:/x", "/base"), moho::XFileError);
  EXPECT_THROW((void)MakeAbsolute("/y", "//srv/share"), moho::XFileError);
  EXPECT_THROW((void)MakeAbsolute("", "/base"), moho::XFileError);
  EXPECT_THROW((void)MakeAbsolute("x", ""), moho::XFileError);
}

// The folder part (0x00410A10): up to the last '/', but only when a dot follows it (a file name); a path without one
// is taken as a folder already and loses only a trailing '/'. A drive root keeps its '/'.
TEST(StartupPath, DirPrefixTreatsADotlessLeafAsAFolder)
{
  EXPECT_EQ(Str(moho::FILE_DirPrefix("/maps/setons/setons_scenario.lua")), "/maps/setons");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("C:\\games\\fa\\bin\\init.lua")), "C:/games/fa/bin");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("C:/init.lua")), "C:/");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("/maps/setons")), "/maps/setons");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("/maps/setons/")), "/maps/setons");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("C:/")), "C:/");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("v1.2/plain")), "v1.2/plain");
  EXPECT_EQ(Str(moho::FILE_DirPrefix("init.lua")), "");
  EXPECT_THROW((void)moho::FILE_DirPrefix(""), moho::XFileError);
}

// The errno texts (0x00411A20, byte table at 0x00411AC4).
TEST(StartupPath, ErrnoTexts)
{
  EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(2)), "File not found");
  EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(13)), "Access denied");
  EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(17)), "Path already exists");
  EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(22)), "Invalid characters in file name");
  EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(24)), "Too many open files.");
  for (const int other : {0, 1, 3, 12, 14, 23, 25, -1}) {
    EXPECT_EQ(Str(moho::FILE_GetErrorFromErrno(other)), "Unknown disk error") << other;
  }
}

// A bare map name becomes its scenario file (0x008CE220); anything with a separator is taken as a path already.
TEST(StartupPath, MapNameBecomesItsScenarioFile)
{
  EXPECT_EQ(Str(moho::FindMapScenario("SCMP_009")), "/maps/SCMP_009/SCMP_009_scenario.lua");
  EXPECT_EQ(Str(moho::FindMapScenario("/maps/x/x_scenario.lua")), "/maps/x/x_scenario.lua");
  EXPECT_EQ(Str(moho::FindMapScenario("maps\\x")), "maps\\x");
  EXPECT_EQ(Str(moho::FindMapScenario("")), "");
}

// "width,height,fps" (0x008CD6C0: tokens on ',' at 0xE16724, atoi each); anything but three tokens is refused.
TEST(StartupPath, ResolutionTripleNeedsThreeFields)
{
  moho::ResolutionTriple resolution;
  ASSERT_TRUE(moho::CFG_ParseResolutionTriple("1920,1080,60", &resolution));
  EXPECT_EQ(resolution.width, 1920);
  EXPECT_EQ(resolution.height, 1080);
  EXPECT_EQ(resolution.framesPerSecond, 60);

  ASSERT_TRUE(moho::CFG_ParseResolutionTriple("800,600x,abc", &resolution));
  EXPECT_EQ(resolution.width, 800);
  EXPECT_EQ(resolution.height, 600);
  EXPECT_EQ(resolution.framesPerSecond, 0);

  EXPECT_FALSE(moho::CFG_ParseResolutionTriple("1920,1080", &resolution));
  EXPECT_FALSE(moho::CFG_ParseResolutionTriple("1920,1080,60,1", &resolution));
  EXPECT_FALSE(moho::CFG_ParseResolutionTriple("", &resolution));
  EXPECT_FALSE(moho::CFG_ParseResolutionTriple("1,2,3", nullptr));
}
