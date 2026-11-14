// What editor mods read and change of the map's props, decals and units (ui/EdModHost.cpp's Editor table), each change
// one undo step through the same edits the view's own tools make.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdDecalShape.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMapStats.h"
#include "editor/tools/EdMarkers.h"
#include "gpg/core/utils/Logging.h"
#include "moho/mesh/Mesh.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  std::vector<EdMapScene::ModObject> EdMapScene::ModProps() const
  {
    std::vector<ModObject> out;
    const EdDocument::PropSnapshot props = mDocument.PropsNow();
    out.reserve(props.entries.size());
    for (const moho::CWldPropEntry& entry : props.entries) {
      ModObject o;
      o.what = entry.mBlueprintPath.c_str();
      o.x = entry.mTransform.pos_.x;
      o.y = entry.mTransform.pos_.y;
      o.z = entry.mTransform.pos_.z;
      out.push_back(std::move(o));
    }
    return out;
  }

  std::string EdMapScene::ModAddProp(
    const std::string& blueprint,
    const float x,
    const float z,
    const float scale
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mMap->mProps == nullptr) {
      return "no map is open in the view";
    }
    if (blueprint.empty()) {
      return "no prop blueprint";
    }
    if (x < 0.0f || z < 0.0f || x > static_cast<float>(field->width - 1) || z > static_cast<float>(field->height - 1)) {
      return "the point is off the map";
    }
    if (mTools != nullptr && mTools->HasPropBlueprints() && mTools->PropBlueprintNamed(blueprint).empty()) {
      return "the game has no prop " + blueprint;
    }
    BeginObjectStroke();
    moho::CWldPropEntry entry;
    entry.mBlueprintPath.assign(blueprint.c_str());
    entry.mTransform.pos_ = Wm3::Vec3f{x, PlacementHeight(x, z), z};
    entry.mTransform.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
    PropRecord record = PropRecordFor(blueprint, entry.mTransform);
    record.values[12] = record.values[13] = record.values[14] = scale > 0.0f ? scale : 1.0f;
    entry.mTransform = record.loaded;
    mDocument.AddProp(entry, record);
    mProps.push_back(MakePropInstance(entry));
    mObjectsChanged = true;
    mDocument.SetModified(true);
    (void)EndObjectStroke();
    return {};
  }

  std::string EdMapScene::ModRemoveProp(
    const int index
  )
  {
    const EdDocument::PropSnapshot props = mDocument.PropsNow();
    if (mMap == nullptr || index < 0 || static_cast<std::size_t>(index) >= props.entries.size()) {
      return "no prop at that index";
    }
    BeginObjectStroke();
    if (static_cast<std::size_t>(index) < mProps.size()) {
      delete mProps[static_cast<std::size_t>(index)];
      mProps.erase(mProps.begin() + index);
    }
    mDocument.DeletePropAt(static_cast<std::size_t>(index));
    // The selection holds indexes: those after the removed one moved down.
    mSelection.clear();
    mObjectsChanged = true;
    mDocument.SetModified(true);
    (void)EndObjectStroke();
    return {};
  }

  std::vector<EdMapScene::ModObject> EdMapScene::ModDecals() const
  {
    std::vector<ModObject> out;
    for (const DecalState& d : mDocument.DecalsNow()) {
      ModObject o;
      o.what = d.names[0];
      o.x = d.position[0];
      o.y = d.position[1];
      o.z = d.position[2];
      o.size = std::max(d.scale[0], d.scale[2]);
      out.push_back(std::move(o));
    }
    return out;
  }

  std::string EdMapScene::ModAddDecal(
    const std::string& texture,
    const float x,
    const float z,
    const float size,
    const float heading
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    moho::IDecalManager* const decals = mDocument.Decals();
    if (field == nullptr || decals == nullptr) {
      return "no map is open in the view";
    }
    if (texture.empty() || size <= 0.0f) {
      return "a texture and a size above 0";
    }
    if (x < 0.0f || z < 0.0f || x > static_cast<float>(field->width - 1) || z > static_cast<float>(field->height - 1)) {
      return "the point is off the map";
    }
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    const DecalFootprint footprint = DecalAround(x, z, size, size, heading);
    DecalState state;
    state.type = DecalTypeForTexture(texture);
    state.names[0] = texture;
    state.scale[0] = footprint.sizeX;
    state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
    state.scale[2] = footprint.sizeZ;
    state.position[0] = footprint.x;
    state.position[1] = GroundHeightAt(x, z);
    state.position[2] = footprint.z;
    state.orientation[1] = heading;
    if (AddDecal(*decals, state) == nullptr) {
      return "the decal couldn't be made (is " + texture + " a texture of the game?)";
    }
    mDocument.DecalsEdited(std::move(before));
    mDocument.SetModified(true);
    return {};
  }

  std::vector<EdMapScene::ModObject> EdMapScene::ModUnits() const
  {
    std::vector<ModObject> out;
    for (const SaveEntry& army : mDocument.SaveData().Armies()) {
      UnitGroup group;
      std::string error;
      if (!ParseUnitGroup(army.Get("Units"), group, error)) {
        continue;
      }
      std::vector<const SaveUnit*> units;
      CollectUnits(group, units);
      for (const SaveUnit* u : units) {
        ModObject o;
        o.what = u->type;
        o.name = u->name;
        o.army = army.name;
        o.x = u->position[0];
        o.y = u->position[1];
        o.z = u->position[2];
        out.push_back(std::move(o));
      }
    }
    return out;
  }

  std::string EdMapScene::ModAddUnit(
    const std::string& type,
    const std::string& army,
    const float x,
    const float z,
    std::string& name
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return "no map is open in the view";
    }
    if (type.empty() || army.empty()) {
      return "a unit blueprint id and an army";
    }
    if (x < 0.0f || z < 0.0f || x > static_cast<float>(field->width - 1) || z > static_cast<float>(field->height - 1)) {
      return "the point is off the map";
    }
    const auto& armies = mDocument.SaveData().Armies();
    if (std::none_of(armies.begin(), armies.end(), [&army](const SaveEntry& e) {
      return e.name == army;
    })) {
      return "the map has no army " + army;
    }
    int highest = 0;
    for (const SaveEntry& entry : armies) {
      UnitGroup group;
      std::string error;
      if (ParseUnitGroup(entry.Get("Units"), group, error)) {
        highest = std::max(highest, HighestUnitNumber(group));
      }
    }
    SaveUnit unit;
    unit.name = "UNIT_" + std::to_string(highest + 1);
    unit.type = type;
    unit.position[0] = x;
    unit.position[2] = z;
    int fitX = 1;
    int fitZ = 1;
    const std::string fit = UnitFitAt(type, x, z, fitX, fitZ);
    if (fitX > 1 || fitZ > 1) {
      unit.position[0] = SnapFootprint(x, fitX);
      unit.position[2] = SnapFootprint(z, fitZ);
    }
    unit.position[1] = UnitRestHeight(unit.position[0], unit.position[2]);
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    if (!EditArmyUnits(army, [&](UnitGroup& group) {
      AddUnit(group, unit);
    })) {
      return "the army's units couldn't be read";
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    name = unit.name;
    if (!fit.empty()) {
      gpg::Warnf("editor: an editor mod placed %s where it doesn't fit: %s", type.c_str(), fit.c_str());
    }
    return {};
  }
  std::vector<EdMapScene::ResourceFit> EdMapScene::ResourceFits(
    const std::string& extractor,
    const std::string& plant
  ) const
  {
    std::vector<ResourceFit> out;
    if (mMap == nullptr) {
      return out;
    }
    const EdDocument::PropSnapshot props = mDocument.PropsNow();
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const std::string type = MarkerTypeOf(marker);
      if (type != "Mass" && type != "Hydrocarbon") {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!MarkerPosition(marker, x, y, z)) {
        continue;
      }
      ResourceFit fit;
      fit.marker = marker.name;
      fit.mass = type == "Mass";
      fit.x = x;
      fit.z = z;
      int sizeX = 1;
      int sizeZ = 1;
      fit.problem = UnitFitAt(type == "Mass" ? extractor : plant, x, z, sizeX, sizeZ);
      for (const moho::CWldPropEntry& p : props.entries) {
        if (
          std::fabs(p.mTransform.pos_.x - x) < static_cast<float>(sizeX) * 0.5f &&
          std::fabs(p.mTransform.pos_.z - z) < static_cast<float>(sizeZ) * 0.5f
        ) {
          ++fit.props;
        }
      }
      out.push_back(std::move(fit));
    }
    return out;
  }
} // namespace faf::editor
