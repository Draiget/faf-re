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
#include <map>
#include <ranges>

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
      if (!ParseUnitGroup(army.Get("Units"), group)) {
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
      if (ParseUnitGroup(entry.Get("Units"), group)) {
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
  void EdMapScene::PlaceUnitLine(
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    if (mTools == nullptr || mTools->UnitType().empty()) {
      return;
    }
    int sizeX = 1;
    int sizeZ = 1;
    (void)UnitFitAt(mTools->UnitType(), x0, z0, sizeX, sizeZ);
    const float spacing = static_cast<float>(std::max({sizeX, sizeZ, 1}));
    const float dx = x1 - x0;
    const float dz = z1 - z0;
    const float length = std::hypot(dx, dz);
    const int count = static_cast<int>(length / spacing) + 1;
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    mUnitBatch = true;
    mUnitBatchPlaced.clear();
    for (int i = 0; i < count; ++i) {
      const float t = length > 0.0f ? static_cast<float>(i) * spacing / length : 0.0f;
      PlaceUnits(x0 + dx * t, z0 + dz * t);
    }
    mUnitBatch = false;
    mLineEnd[0] = x1;
    mLineEnd[1] = z1;
    mLineEndKept = true;
    if (mUnitBatchPlaced.empty()) {
      return;
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    mUnitSelection = mUnitBatchPlaced;
    gpg::Logf(
      "editor: %zu %s units along a line of %.1f, %.0f apart (one undo step)",
      mUnitBatchPlaced.size(),
      mTools->UnitType().c_str(),
      static_cast<double>(length),
      static_cast<double>(spacing)
    );
    mUnitBatchPlaced.clear();
  }

  void EdMapScene::AskContextMenu()
  {
    TakeContextPick({mWidth / 2, mHeight / 2});
    mContextAsk = true;
  }

  void EdMapScene::TakeContextPick(
    const POINT at
  )
  {
    mContextPoint = {};
    float x = 0.0f;
    float z = 0.0f;
    if (mMap == nullptr || !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), x, z)) {
      return;
    }
    mContextPoint.valid = true;
    mContextPoint.x = x;
    mContextPoint.z = z;
    mContextPoint.height = GroundHeightAt(x, z);
    const PickHit hit = PickAnything(at);
    if (hit.kind == PickKind::None) {
      return;
    }
    // What is under the pointer becomes the selection (unless it is part of it already), so the menu acts on it.
    bool already = false;
    switch (hit.kind) {
    case PickKind::Prop:
      already = std::find(mSelection.begin(), mSelection.end(), hit.index) != mSelection.end();
      mContextPoint.what = "a prop";
      break;
    case PickKind::Marker: {
      const SaveEntry& marker = mDocument.SaveData().Markers()[static_cast<std::size_t>(hit.index)];
      already = std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end();
      mContextPoint.marker = marker.name;
      mContextPoint.markerType = MarkerTypeOf(marker);
      mContextPoint.what = "marker " + marker.name + " (" + mContextPoint.markerType + ")";
      break;
    }
    case PickKind::Unit: {
      const auto& ref = mUnitRefs[static_cast<std::size_t>(hit.index)];
      const std::pair<std::string, std::string> key{ref.army, ref.name};
      already = std::find(mUnitSelection.begin(), mUnitSelection.end(), key) != mUnitSelection.end();
      mContextPoint.unitArmy = ref.army;
      mContextPoint.unitName = ref.name;
      mContextPoint.what = "unit " + ref.name + " of " + ref.army;
      break;
    }
    case PickKind::Decal:
      already = std::find(mDecalSelection.begin(), mDecalSelection.end(), hit.index) != mDecalSelection.end();
      mContextPoint.what = "a decal";
      break;
    default:
      break;
    }
    if (already && hit.kind == SelectedKind()) {
      return;
    }
    ClearAllSelections();
    mSelectKind = hit.kind;
    switch (hit.kind) {
    case PickKind::Prop:
      mSelection.push_back(hit.index);
      break;
    case PickKind::Marker:
      mMarkerSelection.push_back(mContextPoint.marker);
      break;
    case PickKind::Unit:
      mUnitSelection.emplace_back(mContextPoint.unitArmy, mContextPoint.unitName);
      break;
    case PickKind::Decal:
      mDecalSelection.push_back(hit.index);
      break;
    default:
      break;
    }
  }

  std::vector<std::vector<std::string>> EdMapScene::GroupPathsOf(
    const std::string& army
  ) const
  {
    std::vector<std::vector<std::string>> paths;
    for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
      UnitGroup root;
      if (entry.name != army || !ParseUnitGroup(entry.Get("Units"), root)) {
        continue;
      }
      paths.push_back({});
      std::vector<std::pair<const UnitGroup*, std::vector<std::string>>> open{{&root, {}}};
      while (!open.empty()) {
        auto [group, path] = open.back();
        open.pop_back();
        for (auto& child : group->groups | std::views::reverse) {
          std::vector<std::string> next = path;
          next.push_back(child.name);
          open.emplace_back(&child, next);
        }
        if (!path.empty()) {
          paths.push_back(path);
        }
      }
    }
    return paths;
  }

  bool EdMapScene::SnapMarkerToGrid(
    const std::string& name
  )
  {
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (marker.name != name || !MarkerPosition(marker, x, y, z)) {
        continue;
      }
      const float gx = std::floor(x) + 0.5f;
      const float gz = std::floor(z) + 0.5f;
      EditMarker(name, "position", Vector3Value(gx, GroundHeightAt(gx, gz), gz));
      gpg::Logf(
        "editor: %s snapped to the build grid: %.2f, %.2f -> %.1f, %.1f",
        name.c_str(),
        static_cast<double>(x),
        static_cast<double>(z),
        static_cast<double>(gx),
        static_cast<double>(gz)
      );
      return true;
    }
    return false;
  }

  std::string EdMapScene::RulerText() const
  {
    const float segment = std::hypot(mRulerTo[0] - mRulerFrom[0], mRulerTo[1] - mRulerFrom[1]);
    if (mRulerDone.empty()) {
      return DistanceText(segment);
    }
    float total = segment;
    for (const std::array<float, 4>& seg : mRulerDone) {
      total += std::hypot(seg[2] - seg[0], seg[3] - seg[1]);
    }
    return DistanceText(segment) + ", total " + DistanceText(total) + " over " + std::to_string(mRulerDone.size() + 1) +
      " segments";
  }

  bool EdMapScene::TurnEverySelected(
    const float radians
  )
  {
    // Studio's gizmo turn of any selection: every selected prop, marker, unit and decal turns about its own middle.
    bool any = false;
    if (!mSelection.empty()) {
      TurnSelection(radians); // props: their own undo step (with their mirrored copies)
      any = true;
    }
    if (!mMarkerSelection.empty() || !mUnitSelection.empty()) {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      bool changed = false;
      for (SaveEntry& marker : mDocument.SaveData().Markers()) {
        if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) == mMarkerSelection.end()) {
          continue;
        }
        std::vector<double> o = ValueNumbers(marker.Get("orientation"));
        o.resize(3, 0.0);
        o[1] += radians;
        marker.Set("orientation", Vector3Value(o[0], o[1], o[2]));
        changed = true;
      }
      std::map<std::string, std::vector<std::string>> byArmy;
      for (const auto& [army, name] : mUnitSelection) {
        byArmy[army].push_back(name);
      }
      for (const auto& [army, names] : byArmy) {
        changed = EditArmyUnits(
                    army,
                    [&names, radians](UnitGroup& group) {
          for (const std::string& name : names) {
            if (SaveUnit* const u = FindUnit(group, name); u != nullptr) {
              u->orientation[1] += radians;
            }
          }
        }
                  ) ||
          changed;
      }
      if (changed) {
        mDocument.SaveDataEdited(std::move(before));
        if (!mUnitSelection.empty()) {
          ReloadUnits();
        }
        any = true;
      }
    }
    if (!mDecalSelection.empty()) {
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      EdDocument::DecalSnapshot next = before;
      for (const int index : mDecalSelection) {
        if (index < 0 || static_cast<std::size_t>(index) >= next.size()) {
          continue;
        }
        DecalState& d = next[static_cast<std::size_t>(index)];
        DecalFootprint was;
        was.x = d.position[0];
        was.z = d.position[2];
        was.sizeX = d.scale[0];
        was.sizeZ = d.scale[2];
        was.yaw = d.orientation[1];
        float cx = 0.0f, cz = 0.0f;
        DecalCentre(was, cx, cz);
        const DecalFootprint now = DecalAround(cx, cz, was.sizeX, was.sizeZ, was.yaw + radians);
        d.position[0] = now.x;
        d.position[2] = now.z;
        d.orientation[1] = was.yaw + radians;
      }
      if (!(next == before)) {
        mDocument.RestoreDecals(next);
        mDocument.DecalsEdited(std::move(before));
        any = true;
      }
    }
    if (any) {
      mDocument.SetModified(true);
    }
    return any;
  }

  void EdMapScene::ReseatOnGround(
    const std::vector<SampleRect>& rects
  )
  {
    // FAF Studio's Resnap (sim.lua, after sculpting, ramps, stamps, generators and imports): what stands on changed
    // ground is put back on it. Props now (cheap, the view shows it); units once no stroke is painting (their save
    // text is rewritten), below.
    if (mMap == nullptr || rects.empty()) {
      return;
    }
    const auto inside = [&rects](const float x, const float z) {
      for (const SampleRect& r : rects) {
        if (
          x >= static_cast<float>(r.x0) - 1.0f && x <= static_cast<float>(r.x1) + 1.0f &&
          z >= static_cast<float>(r.z0) - 1.0f && z <= static_cast<float>(r.z1) + 1.0f
        ) {
          return true;
        }
      }
      return false;
    };
    if (mMap->mProps != nullptr) {
      auto& entries = mMap->mProps->mEntries;
      bool moved = false;
      for (std::size_t i = 0; i < entries.size(); ++i) {
        moho::CWldPropEntry& entry = entries[i];
        const float x = entry.mTransform.pos_.x;
        const float z = entry.mTransform.pos_.z;
        if (!inside(x, z)) {
          continue;
        }
        const float y = PlacementHeight(x, z);
        if (std::fabs(y - entry.mTransform.pos_.y) < 0.001f) {
          continue;
        }
        entry.mTransform.pos_.y = y;
        if (i < mProps.size() && mProps[i] != nullptr) {
          mProps[i]->SetStance(entry.mTransform, entry.mTransform);
        }
        moved = true;
      }
      if (moved) {
        mDocument.SetModified(true);
      }
    }
    for (const UnitRef& unit : mUnitRefs) {
      if (inside(unit.position.x, unit.position.z)) {
        mReseatUnits = true;
        break;
      }
    }
  }

  void EdMapScene::ReseatUnitsNow()
  {
    if (!mReseatUnits || mPainting || mMap == nullptr) {
      return;
    }
    mReseatUnits = false;
    // Per army, the units whose saved height is off the ground now.
    std::map<std::string, std::vector<std::pair<std::string, float>>> lift;
    for (const UnitRef& unit : mUnitRefs) {
      const float y = UnitRestHeight(unit.position.x, unit.position.z);
      if (std::fabs(y - unit.position.y) > 0.01f) {
        lift[unit.army].emplace_back(unit.name, y);
      }
    }
    if (lift.empty()) {
      return;
    }
    std::size_t count = 0;
    for (const auto& [army, units] : lift) {
      (void)EditArmyUnits(army, [&units, &count](UnitGroup& group) {
        for (const auto& [name, y] : units) {
          if (SaveUnit* const u = FindUnit(group, name); u != nullptr) {
            u->position[1] = y;
            ++count;
          }
        }
      });
    }
    ReloadUnits();
    mDocument.SetModified(true);
    gpg::Logf("editor: %zu units put back on the ground after the height change", count);
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
