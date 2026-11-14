#include "editor/doc/EdModProject.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace faf::editor
{
  namespace
  {
    bool Has(
      const std::string& text,
      const std::string& part
    )
    {
      return text.find(part) != std::string::npos;
    }

    std::string Read(
      const std::filesystem::path& path
    )
    {
      std::ifstream in(path, std::ios::binary);
      std::ostringstream text;
      text << in.rdbuf();
      return text.str();
    }

    /** The unit uel0201 has weapons MainGun (1) and AAGun (2). */
    int Weapons(
      const std::string& id,
      const std::string& label
    )
    {
      if (id != "uel0201") {
        return 0;
      }
      return label == "MainGun" ? 1 : label == "AAGun" ? 2 : 0;
    }

    /** A fresh folder under the test run's temporary folder. */
    std::filesystem::path Fresh(
      const char* name
    )
    {
      const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_mod_tests" / name;
      std::error_code ec;
      std::filesystem::remove_all(folder, ec);
      std::filesystem::create_directories(folder, ec);
      return folder;
    }
  } // namespace

  TEST(
    ModProject,
    AMergeBlueprintHoldsOnlyTheChangesAndWeaponsByTheirPlace
  )
  {
    const std::map<std::string, double> edits = {
      {"Economy.BuildCostMass", 60.0},
      {"Defense.MaxHealth", 412.5},
      {"Weapon:AAGun.Damage", 20.0},
      {"Weapon:MainGun.MaxRadius", 26.0},
      {"Weapon:Missing.Damage", 5.0},
      {"Bad Key", 1.0},
    };
    std::vector<std::string> dropped;
    const std::string text = ModMergeBlueprint("uel0201", edits, Weapons, &dropped);
    EXPECT_EQ(text.rfind(kModProjectMark, 0), 0U);
    EXPECT_TRUE(Has(text, "UnitBlueprint {\n    Merge = true,\n    BlueprintId = 'uel0201',\n"));
    EXPECT_TRUE(Has(text, "    Defense = {\n        MaxHealth = 412.5,\n    },\n"));
    EXPECT_TRUE(Has(text, "    Economy = {\n        BuildCostMass = 60,\n    },\n"));
    EXPECT_TRUE(Has(
      text,
      "    Weapon = {\n        [1] = {\n            MaxRadius = 26,\n        },\n        [2] = {\n            Damage = "
      "20,\n"
      "        },\n    },\n"
    ));
    EXPECT_EQ(dropped, (std::vector<std::string>{"Bad Key", "Weapon:Missing.Damage"}));
    EXPECT_TRUE(ModMergeBlueprint("uel0201", {{"Weapon:Missing.Damage", 5.0}}, Weapons).empty());
    std::string label;
    std::string field;
    ASSERT_TRUE(ModWeaponKey("Weapon:Heavy Gun.RateOfFire", label, field));
    EXPECT_EQ(label, "Heavy Gun");
    EXPECT_EQ(field, "RateOfFire");
    EXPECT_FALSE(ModWeaponKey("Economy.BuildTime", label, field));
  }

  TEST(
    ModProject,
    ChangesBackAtTheGamesValueGoAway
  )
  {
    ModProject p;
    EXPECT_TRUE(SetModEdit(p, "uel0201", "Economy.BuildCostMass", 60.0, 54.0));
    EXPECT_FALSE(SetModEdit(p, "uel0201", "Economy.BuildCostMass", 60.0, 54.0)) << "no change";
    EXPECT_TRUE(SetModEdit(p, "uel0201", "Economy.BuildCostMass", 54.0, 54.0));
    EXPECT_TRUE(p.Empty());
    EXPECT_FALSE(SetModEdit(p, "uel0201", "Economy.BuildCostMass", 54.0, 54.0));
    EXPECT_TRUE(ModProjectNameOk("My balance mod-2"));
    EXPECT_FALSE(ModProjectNameOk("../escape"));
    EXPECT_FALSE(ModProjectNameOk(" padded"));
    EXPECT_TRUE(ModUnitIdOk("uel0201"));
    EXPECT_FALSE(ModUnitIdOk("UEL0201"));
    EXPECT_FALSE(ModUnitIdOk("../x"));
  }

  TEST(
    ModProject,
    TheProjectFileAndModInfoReadBack
  )
  {
    ModProject p;
    p.name = "Balance \"test\"";
    p.author = "someone";
    p.description = "line one\nline 'two'";
    p.version = 3;
    p.uid = NewModUid();
    p.edits["uel0201"]["Economy.BuildCostMass"] = 60.0;
    p.edits["uel0201"]["Weapon:Main Gun.Damage"] = 12.25;
    p.edits["ura0203"]["Physics.MaxSpeed"] = 9.5;
    ModProject back;
    std::string error;
    ASSERT_TRUE(LoadModProject(SaveModProject(p), back, error)) << error;
    EXPECT_EQ(back.name, p.name);
    EXPECT_EQ(back.description, p.description);
    EXPECT_EQ(back.version, 3);
    EXPECT_EQ(back.edits, p.edits);
    EXPECT_FALSE(LoadModProject("{\"name\": \"x\"}", back, error));
    EXPECT_FALSE(
      LoadModProject("{\"editorModProject\": 1, \"edits\": [{\"id\": \"a\", \"key\": \"b\"}]}", back, error)
    );
    const std::string info = ModInfoText(p);
    EXPECT_TRUE(Has(info, "name = 'Balance \"test\"'\n"));
    EXPECT_TRUE(Has(info, "description = 'line one\\nline \\'two\\''\n"));
    EXPECT_EQ(ModInfoUid(info), p.uid);
    EXPECT_EQ(p.uid.size(), 36U);
    EXPECT_NE(NewModUid(), p.uid);
  }

  TEST(
    ModProject,
    WritingKeepsTheUidLeavesForeignFilesAndRemovesStaleOnes
  )
  {
    const std::filesystem::path folder = Fresh("write");
    ModProject p;
    p.name = "Write test";
    p.uid = NewModUid();
    p.edits["uel0201"]["Economy.BuildCostMass"] = 60.0;
    p.edits["ura0203"]["Physics.MaxSpeed"] = 9.5;
    // A unit file someone wrote by hand: left alone.
    std::filesystem::create_directories(folder / "units" / "ura0203");
    std::ofstream(folder / "units" / "ura0203" / "ura0203_unit.bp", std::ios::binary)
      << "UnitBlueprint { Merge = true }\n";
    ModWriteReport report = WriteModProject(folder, p, Weapons, {});
    EXPECT_TRUE(Has(Read(folder / "units" / "uel0201" / "uel0201_unit.bp"), "BuildCostMass = 60,"));
    EXPECT_EQ(Read(folder / "units" / "ura0203" / "ura0203_unit.bp"), "UnitBlueprint { Merge = true }\n");
    ASSERT_EQ(report.problems.size(), 1U);
    EXPECT_TRUE(Has(report.problems[0], "isn't one the project made"));
    // Reopened: the same uid and changes.
    ModProject back;
    std::string error;
    bool fromBackup = true;
    ASSERT_TRUE(OpenModProject(folder, back, error, &fromBackup)) << error;
    EXPECT_FALSE(fromBackup);
    EXPECT_EQ(back.uid, p.uid);
    EXPECT_EQ(back.edits, p.edits);
    const std::vector<std::string> listed = ModProjectsIn(folder.parent_path());
    EXPECT_NE(std::find(listed.begin(), listed.end(), "write"), listed.end())
      << "(other tests keep their folders beside it)";
    // A unit back at the game's values: its file goes; a file that doesn't compile isn't written.
    p.edits.erase("uel0201");
    p.edits["xsl0101"]["Economy.BuildTime"] = 100.0;
    report = WriteModProject(folder, p, Weapons, [](const std::string& text, const std::string& name) {
      return name.find("xsl0101") != std::string::npos ? std::string("line 3: unexpected symbol") : std::string();
    });
    EXPECT_FALSE(std::filesystem::exists(folder / "units" / "uel0201"));
    EXPECT_FALSE(std::filesystem::exists(folder / "units" / "xsl0101" / "xsl0101_unit.bp"));
    EXPECT_EQ(
      std::count_if(
        report.problems.begin(),
        report.problems.end(),
        [](const std::string& s) {
      return Has(s, "doesn't compile");
    }
      ),
      1
    );
    // A damaged project file: the copy before it.
    std::ofstream(folder / "editor_project.json", std::ios::binary | std::ios::trunc) << "{ broken";
    ASSERT_TRUE(OpenModProject(folder, back, error, &fromBackup)) << error;
    EXPECT_TRUE(fromBackup);
    EXPECT_EQ(back.edits.count("uel0201"), 1U) << "the .bak holds the project before the last write";
  }

  TEST(
    ModProject,
    DerivedUnitsAreMadeByTheProjectsBlueprintHook
  )
  {
    const auto gameHas = [](const std::string& id) {
      return id == "uel0201" || id == "ura0203";
    };
    ModProject p;
    std::string error;
    EXPECT_FALSE(AddModDerived(p, "xel01", "uel0201", "", "", gameHas, error)) << "too short";
    EXPECT_FALSE(AddModDerived(p, "ura0203", "uel0201", "", "", gameHas, error)) << "the game has it";
    EXPECT_FALSE(AddModDerived(p, "xel0201", "nope0001", "", "", gameHas, error)) << "no base";
    ASSERT_TRUE(AddModDerived(p, "xel0201", "uel0201", "Lab 'Tank'", "Heavier", gameHas, error)) << error;
    EXPECT_FALSE(AddModDerived(p, "xel0201", "uel0201", "", "", gameHas, error)) << "derived already";
    EXPECT_EQ(ModSourceUnit(p, "xel0201"), "uel0201");
    EXPECT_EQ(ModSourceUnit(p, "uel0201"), "uel0201");
    p.edits["xel0201"]["Economy.BuildCostMass"] = 156.0;
    p.edits["xel0201"]["Weapon:MainGun.Damage"] = 40.0;
    p.edits["uel0201"]["Economy.BuildCostMass"] = 81.0;
    const std::string hook = ModDerivedHook(p, Weapons);
    EXPECT_EQ(hook.rfind(kModProjectMark, 0), 0U);
    EXPECT_TRUE(Has(hook, "    local oldModBlueprints = ModBlueprints\n"));
    EXPECT_TRUE(Has(hook, "    function ModBlueprints(all_bps)\n        oldModBlueprints(all_bps)\n"));
    EXPECT_TRUE(Has(hook, "local bp = table.merged(table.deepcopy(source), delta)"));
    EXPECT_TRUE(Has(
      hook,
      "        Derive('xel0201', 'uel0201', 'Lab \\'Tank\\'', 'Heavier', false, false, {\n            Economy = {\n"
      "                BuildCostMass = 156,\n            },\n            Weapon = {\n                [1] = {\n"
      "                    Damage = 40,\n                },\n            },\n        })\n"
    )) << hook;
    EXPECT_FALSE(Has(hook, "BuildCostMass = 81")) << "the base unit's own change is its merge blueprint's";
    // Saved and read back.
    ModProject back;
    ASSERT_TRUE(LoadModProject(SaveModProject(p), back, error)) << error;
    EXPECT_EQ(back.derived, p.derived);
    EXPECT_EQ(back.edits, p.edits);
    // Written: the hook, a merge blueprint for uel0201 only; without derived units the hook goes.
    const std::filesystem::path folder = Fresh("derived");
    ModWriteReport report = WriteModProject(folder, p, Weapons, {});
    EXPECT_TRUE(report.problems.empty());
    EXPECT_TRUE(Has(Read(folder / kModHookFile), "Derive('xel0201'"));
    EXPECT_TRUE(std::filesystem::exists(folder / "units" / "uel0201" / "uel0201_unit.bp"));
    EXPECT_FALSE(std::filesystem::exists(folder / "units" / "xel0201"));
    p.derived.clear();
    p.edits.erase("xel0201");
    EXPECT_TRUE(ModDerivedHook(p, Weapons).empty());
    report = WriteModProject(folder, p, Weapons, {});
    EXPECT_FALSE(std::filesystem::exists(folder / kModHookFile));
  }

  TEST(
    ModProject,
    ChecksFindWhatTheGameWouldNotTake
  )
  {
    ModProject p;
    p.name = "Checks";
    p.uid = NewModUid();
    ModCheckFacts facts;
    facts.gameHas = [](const std::string& id) {
      return id == "uel0201" || id == "ura0203";
    };
    facts.weaponIndex = Weapons;
    facts.gameHasFile = [](const std::string& path) {
      return path.find("xel0201") == std::string::npos;
    };
    const auto count = [](const std::vector<ModIssue>& issues, const std::string& part) {
      return std::count_if(issues.begin(), issues.end(), [&](const ModIssue& i) {
        return i.text.find(part) != std::string::npos;
      });
    };
    std::vector<ModIssue> issues = CheckModProject(p, facts);
    EXPECT_EQ(count(issues, "nothing changed yet"), 1);
    p.edits["uel0201"]["Weapon:Missing.Damage"] = 5;
    p.edits["uel0201"]["Defense.MaxHealth"] = 0;
    p.edits["uel0201"]["Economy.BuildTime"] = -1;
    p.edits["zzz0001"]["Economy.BuildCostMass"] = 10;
    p.edits["uel0201"]["Bad Key!"] = 1;
    p.derived["xel0201"] = {"uel0201", "", ""};
    p.derived["ura0203"] = {"nope0001", "Name", ""};
    facts.diskUid = "00000000-0000-4000-a000-000000000000";
    facts.written = false;
    issues = CheckModProject(p, facts);
    EXPECT_EQ(count(issues, "uel0201 has no weapon Missing"), 1);
    EXPECT_EQ(count(issues, "health 0 (it dies"), 1);
    EXPECT_EQ(count(issues, "BuildTime -1"), 1);
    EXPECT_EQ(count(issues, "zzz0001: the game has no such unit"), 1);
    EXPECT_EQ(count(issues, "Bad Key! isn't a blueprint path"), 1);
    EXPECT_EQ(count(issues, "derived unit xel0201 has no name"), 1);
    EXPECT_EQ(count(issues, "derived unit xel0201 shows uel0201's icon"), 1);
    p.derived["xel0201"].icon = true;
    EXPECT_EQ(count(CheckModProject(p, facts), "shows uel0201's icon"), 0);
    EXPECT_NE(
      ModDerivedHook(p, Weapons).find("Derive('xel0201', 'uel0201', '', '', true, false, {"), std::string::npos
    );
    EXPECT_NE(ModDerivedHook(p, Weapons).find("bp.Display.IconName = id"), std::string::npos);
    EXPECT_EQ(ModUnitIconFile("xel0201"), "icons/units/xel0201_icon.dds");
    ModProject back;
    std::string error;
    ASSERT_TRUE(LoadModProject(SaveModProject(p), back, error));
    EXPECT_TRUE(back.derived.at("xel0201").icon);
    EXPECT_EQ(count(issues, "derived unit ura0203: the game has a unit with that id"), 1);
    EXPECT_EQ(count(issues, "the game has no unit nope0001"), 1);
    EXPECT_EQ(count(issues, "another uid"), 1);
    EXPECT_EQ(count(issues, "not written yet"), 1);
    EXPECT_EQ(
      std::count_if(
        issues.begin(),
        issues.end(),
        [](const ModIssue& i) {
      return i.level == 'E';
    }
      ),
      5
    ) << "health, the unknown unit, the bad key, the two derived ones; BuildTime is a warning";
  }

  TEST(
    ModProject,
    AReleaseLeavesTheEditorsOwnFilesOut
  )
  {
    ModProject p;
    p.name = "My Balance";
    p.version = 3;
    const ModRelease r = PlanModRelease(
      p,
      {"mod_info.lua",
       "editor_project.json",
       "editor_project.json.bak",
       "units/uel0201/uel0201_unit.bp",
       "hook/lua/system/Blueprints.lua",
       "units/x.bp.writing",
       "Thumbs.db"}
    );
    EXPECT_EQ(r.folder, "My_Balance");
    EXPECT_EQ(r.zipName, "My_Balance.v3.zip");
    EXPECT_EQ(
      r.files,
      (std::vector<std::string>{"hook/lua/system/Blueprints.lua", "mod_info.lua", "units/uel0201/uel0201_unit.bp"})
    );
  }

  TEST(
    ModProject,
    BinaryFilesAreTheProjectsWhenItWroteThem
  )
  {
    const std::filesystem::path folder = Fresh("binary");
    ModProject p;
    p.name = "Binary";
    std::string error;
    std::filesystem::create_directories(folder / "icons" / "units");
    std::ofstream(folder / "icons" / "units" / "other_icon.dds", std::ios::binary) << "someone else's";
    EXPECT_FALSE(ModWriteBinary(p, folder, "icons/units/other_icon.dds", "DDS ", error));
    EXPECT_NE(error.find("isn't one the project made"), std::string::npos);
    ASSERT_TRUE(ModWriteBinary(p, folder, "icons/units/xel0301_icon.dds", std::string("DDS \0\1", 6), error)) << error;
    ASSERT_TRUE(ModWriteBinary(p, folder, "icons/units/xel0301_icon.dds", "DDS again", error))
      << "its own: written over";
    EXPECT_EQ(Read(folder / "icons" / "units" / "xel0301_icon.dds"), "DDS again");
    EXPECT_FALSE(ModWriteBinary(p, folder, "../escape.dds", "x", error));
    ModProject back;
    ASSERT_TRUE(LoadModProject(SaveModProject(p), back, error)) << error;
    EXPECT_EQ(back.files, (std::set<std::string>{"icons/units/xel0301_icon.dds"}));
  }

  TEST(
    ModProject,
    ADerivedUnitWithAScriptOfItsOwn
  )
  {
    ModProject p;
    p.name = "Script Test";
    p.uid = "11111111-2222-3333-4444-555555555555";
    p.derived["xel0202"] = {"uel0201", "Scripted", "", false, true};
    const std::string hook = ModDerivedHook(p, Weapons);
    EXPECT_TRUE(Has(hook, "if mod.uid == '11111111-2222-3333-4444-555555555555' then here = mod.location end"));
    EXPECT_TRUE(Has(hook, "bp.ScriptModule = here .. '/units/' .. id .. '/' .. id .. '_script.lua'"));
    EXPECT_TRUE(Has(hook, "Derive('xel0202', 'uel0201', 'Scripted', '', false, true, {"));
    // Written once, then the modder's.
    const std::filesystem::path folder = Fresh("script");
    (void)WriteModProject(folder, p, Weapons, {});
    const std::filesystem::path script = folder / ModUnitScriptFile("xel0202");
    const std::string first = Read(script);
    EXPECT_TRUE(Has(first, "local Base = import('/units/uel0201/uel0201_script.lua').TypeClass")) << first;
    EXPECT_TRUE(Has(first, "XEL0202 = Class(Base) {"));
    EXPECT_TRUE(Has(first, "TypeClass = XEL0202"));
    {
      std::ofstream out(script, std::ios::binary | std::ios::trunc);
      out << "-- the modder's own\n";
    }
    (void)WriteModProject(folder, p, Weapons, {});
    EXPECT_EQ(Read(script), "-- the modder's own\n") << "not written over";
    ModProject back;
    std::string error;
    ASSERT_TRUE(LoadModProject(SaveModProject(p), back, error)) << error;
    EXPECT_TRUE(back.derived["xel0202"].script);
  }
} // namespace faf::editor
