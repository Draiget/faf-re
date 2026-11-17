#pragma once

// The new unit wizard (FAF Studio's unitwiz.lua and unitcheck.lua, MOD_UNIT_EDITOR_DESIGN.md stage S4): a unit with its
// own id inside a mod project, made from a template and never from a copy of a blueprint. A unit is a SPEC (kept in the
// project's `editor_newunits.json`): template, faction, tech, name, categories, who builds it, economy / defence /
// physics numbers, weapons, sounds, animations, mesh (an OBJ file or a placeholder), textures. The generators turn a
// spec into the project's files:
//
//   units/<id>/<id>_unit.bp        the blueprint, field by field from the template's donor unit, the spec and the unit
//                                  lab's edits
//   units/<id>/<id>_script.lua     the class from the template (faction + kind), one ClassWeapon per weapon label
//   units/<id>/<id>_strings.lua    the <LOC> keys of the name and the description
//   units/<id>/<id>_lod0.scm       the OBJ (groups bound to the template's bones, or a skeleton made of the groups), or
//                                  a box-and-turret placeholder in the template's skeleton
//   units/<id>/<id>_albedo.dds ... the textures given, or placeholders
//   textures/ui/common/icons/units/<id>_icon.dds   a quick icon of the mesh
//
// The templates take pieces of vanilla units by reference (`tools/data/unitwizdata.lua`, Studio's generated table:
// skeletons, sound sets, animation paths, weapon fields, the numbers a unit of that kind needs). Engine independent
// (tests/editor/UnitWizardTests.cpp); what needs the game comes in through callbacks.

#include "editor/doc/EdJsonTree.h"
#include "editor/tools/EdScm.h"

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  /** The editor's built-in data files (tools/data, EmbedData.cmake): a file's text, or empty. */
  const std::string& EmbeddedEditorData(const std::string& name);

  /** Studio's generated donor table, read once. */
  struct UnitWizardData
  {
    JsonTree root;
    [[nodiscard]] const JsonTree* Donor(const std::string& id) const;
    /** The donor unit of a template and faction. */
    [[nodiscard]] std::string DonorOf(const std::string& templateId, const std::string& faction) const;
  };
  [[nodiscard]] std::expected<void, std::string> LoadUnitWizardData(const std::string& text, UnitWizardData& out);

  struct UnitTemplate
  {
    const char* id;
    const char* label;
    const char* layer; // land | water | air | structure
    bool mobile;
    bool builder;
    std::vector<const char*> kinds; // weapon kinds it offers
    const char* defaultKind;        // "" none
  };
  [[nodiscard]] const std::vector<UnitTemplate>& UnitTemplates();
  [[nodiscard]] const UnitTemplate* UnitTemplateOf(const std::string& id);
  [[nodiscard]] const std::vector<const char*>& UnitFactions();
  struct UnitBuildKey
  {
    const char* key;
    const char* label;
    const char* category;
  };
  [[nodiscard]] const std::vector<UnitBuildKey>& UnitBuildKeys();
  /** "Direct fire gun", "Cannon" ... */
  [[nodiscard]] const char* UnitWeaponKindName(const std::string& kind);

  struct UnitWizardWeapon
  {
    std::string label = "MainGun";
    std::string kind = "direct";
    std::string name;
    double damage = 10.0;
    double range = 20.0;
    double rof = 1.0;
    double damageRadius = 0.0;
    double minRange = 0.0;
    std::string projectile;
  };

  struct UnitWizardMesh
  {
    std::string source;        // OBJ file on disk; empty: the placeholder
    std::string axis = "y_up"; // y_up | z_up
    float yaw = 0.0f;          // degrees
    bool mirrorX = false;
    bool flipWinding = false;
    bool flipV = true;
    std::string skeleton = "template"; // template | groups
    float length = 0.0f;               // the longest horizontal side in game units
    int lods = 1;
  };

  struct UnitWizardSpec
  {
    std::string id;
    std::string templateId;
    std::string faction = "UEF";
    int tech = 1;
    std::string name;
    std::string description;
    std::vector<std::string> catAdd;
    std::vector<std::string> catDel;
    std::vector<std::string> buildBy;
    std::map<std::string, double> economy;
    std::map<std::string, double> defense;
    std::map<std::string, double> physics;
    std::map<std::string, double> intel;
    std::string sounds;            // a donor id: its sound set
    std::string anim = "template"; // template | none
    std::vector<UnitWizardWeapon> weapons;
    UnitWizardMesh mesh;
    std::string albedo;
    std::string normal;
    std::string specular;
    bool icon = true;
    int footprintX = 1;
    int footprintZ = 1;
    /** Physics.MotionType (RULEUMT_Land ...); empty: the template's. */
    std::string motionType;
    /** Economy.BuildableCategory (what the unit builds), one expression each; empty: the template's. */
    std::vector<std::string> buildable;
  };

  /** The first line of the files the wizard writes: change the unit in the wizard; without it a file is the user's. */
  [[nodiscard]] const char* UnitWizardMark();

  /** A unit id: lower case letters and digits, a letter first, at least 6 characters. */
  [[nodiscard]] bool ValidUnitId(const std::string& id);
  /** Nothing, or why not (`taken(id)`: the game or the project has it). */
  [[nodiscard]] std::expected<void, std::string>
  CheckUnitId(const std::string& id, const std::function<bool(const std::string&)>& taken);
  /** A free id: z + faction letter + type letter + four digits (zel0001 ...). */
  [[nodiscard]] std::string SuggestUnitId(
    const std::string& templateId,
    const std::string& faction,
    const std::function<bool(const std::string&)>& taken
  );
  [[nodiscard]] std::vector<std::string> DefaultBuildBy(const UnitTemplate& t, int tech);

  /** A new spec of a template and faction, its numbers starting at the donor's. */
  [[nodiscard]] std::expected<UnitWizardSpec, std::string> NewUnitSpec(
    const UnitWizardData& data,
    const std::string& templateId,
    const std::string& faction,
    const std::string& id
  );
  /** A weapon of `kind` with the donor's numbers for the spec's faction. */
  [[nodiscard]] UnitWizardWeapon NewUnitWeapon(
    const UnitWizardData& data,
    const UnitWizardSpec& spec,
    const std::string& kind,
    const std::string& label
  );

  /** The unit's categories (sorted). */
  [[nodiscard]] std::vector<std::string> UnitCategories(const UnitWizardData& data, const UnitWizardSpec& spec);
  /** World size (x, y, z) of the unit's mesh (the donor's scaled to the spec's length, or the mesh's own). */
  [[nodiscard]] std::array<float, 3>
  UnitDims(const UnitWizardData& data, const UnitWizardSpec& spec, const float* bounds);

  /** The template's bones (the donor's, positions scaled to the spec's size). */
  [[nodiscard]] std::vector<ScmBone> UnitTemplateBones(const UnitWizardData& data, const UnitWizardSpec& spec);

  /**
   * The blueprint as a table (`edits`: the unit lab's changes, `Economy.BuildCostMass` or `Weapon:<label>.Damage`,
   * applied last); `bounds` the mesh's (6 numbers in mesh units) or null for the donor's.
   */
  [[nodiscard]] JsonTree UnitBlueprint(
    const UnitWizardData& data,
    const UnitWizardSpec& spec,
    const std::map<std::string, double>& edits,
    const float* bounds
  );
  /** A table as Lua text (sorted keys, `Sound { ... }` for sound tables, short lists on one line). */
  [[nodiscard]] std::string LuaTableText(const JsonTree& value, const std::string& indent);
  [[nodiscard]] std::string UnitBlueprintText(
    const UnitWizardData& data,
    const UnitWizardSpec& spec,
    const std::map<std::string, double>& edits,
    const float* bounds
  );
  [[nodiscard]] std::string UnitScriptText(const UnitWizardData& data, const UnitWizardSpec& spec);
  [[nodiscard]] std::string UnitStringsText(const UnitWizardSpec& spec);

  /** What the mesh build made. */
  struct UnitMeshInfo
  {
    int vertices = 0;
    int triangles = 0;
    int bones = 0;
    float bounds[6] = {0, 0, 0, 0, 0, 0}; // mesh units
    std::vector<std::string> groups;
    std::vector<std::string> warnings;
    bool placeholder = false;
  };
  /** The unit's `.scm`: from the OBJ text when there is one, else the placeholder. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string>
  UnitMesh(const UnitWizardData& data, const UnitWizardSpec& spec, const std::string& objText, UnitMeshInfo& info);

  /** A placeholder texture (albedo, normal, spec) as RGBA rows, 64 x 64. */
  [[nodiscard]] std::vector<std::uint8_t> UnitPlaceholderPixels(const std::string& kind, const std::string& faction);
  /** RGBA pixels as an uncompressed 32-bit DDS (A8R8G8B8, one level). */
  [[nodiscard]] std::vector<std::uint8_t> DdsFromRgba(const std::vector<std::uint8_t>& rgba, int width, int height);
  /** A quick icon of a mesh: its triangles seen from the front and above, shaded, tinted by the faction (RGBA). */
  [[nodiscard]] std::vector<std::uint8_t> UnitQuickIcon(
    const std::vector<std::array<float, 3>>& positions,
    const std::vector<std::uint32_t>& indexes,
    const std::string& faction,
    int size
  );

  /** The spec file of a project (`editor_newunits.json`) and back. */
  [[nodiscard]] std::string UnitSpecsText(const std::vector<UnitWizardSpec>& specs);
  [[nodiscard]] std::expected<std::vector<UnitWizardSpec>, std::string> ReadUnitSpecs(const std::string& text);

  /** A validator's finding (Studio's unitcheck.lua): E error, W warning, I information. */
  struct UnitCheck
  {
    char severity = 'W';
    std::string text;
  };
  /** What the checks read from the game (null: that check is left out). */
  struct UnitCheckGame
  {
    std::function<bool(const std::string&)> unitExists;       // the game has a unit with this id (not ours)
    std::function<bool(const std::string&)> projectileExists; // a projectile blueprint path
    std::function<bool(const std::string&)> fileExists;       // a game file (animations)
  };
  /**
   * The checks of a unit written into `folder` (the project): files there, the id, the blueprint's numbers and weapons,
   * the bones the blueprint names against the mesh, the weapon labels against the script, the categories, the
   * structure's footprint, the LODs, the mesh's limits, the icon.
   */
  [[nodiscard]] std::vector<UnitCheck> CheckWizardUnit(
    const UnitWizardData& data,
    const UnitWizardSpec& spec,
    const std::string& folder,
    const UnitCheckGame& game
  );

  /** Writes the unit's files into the project folder; text files only while they carry the mark. Lines into `report`.
   */
  bool WriteWizardUnit(
    const UnitWizardData& data,
    const UnitWizardSpec& spec,
    const std::map<std::string, double>& edits,
    const std::string& folder,
    std::vector<std::string>& report
  );
} // namespace faf::editor
