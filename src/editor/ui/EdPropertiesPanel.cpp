// The Properties panel (View > Properties): the selected marker, unit, prop or decal, by kind, Blender-style -- a
// header with its kind and name, its transform as labelled rows, then what its kind has.

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <string>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/ui/EdHelp.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    const char* KindName(const SelectionProperties::Kind kind)
    {
      switch (kind) {
      case SelectionProperties::Kind::Marker:
        return "Marker";
      case SelectionProperties::Kind::Unit:
        return "Unit";
      case SelectionProperties::Kind::Prop:
        return "Prop";
      case SelectionProperties::Kind::Decal:
        return "Decal";
      default:
        return "";
      }
    }

    ImVec4 KindColour(const SelectionProperties::Kind kind)
    {
      switch (kind) {
      case SelectionProperties::Kind::Marker:
        return ImVec4(0.85f, 0.45f, 0.85f, 1.0f);
      case SelectionProperties::Kind::Unit:
        return ImVec4(0.35f, 0.60f, 0.95f, 1.0f);
      case SelectionProperties::Kind::Prop:
        return ImVec4(0.40f, 0.75f, 0.40f, 1.0f);
      case SelectionProperties::Kind::Decal:
        return ImVec4(0.90f, 0.65f, 0.30f, 1.0f);
      default:
        return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
      }
    }
  } // namespace

  void EdShell::DrawPropertiesPanel()
  {
    if (!ImGui::Begin("Properties", &mShowProperties)) {
      ImGui::End();
      return;
    }
    const SelectionProperties& now = mTools.SelectionPropertiesNow();
    if (now.kind == SelectionProperties::Kind::None) {
      mPropertiesEditing = false;
      ImGui::TextDisabled("Nothing selected.");
      HelpNote("Select a marker, unit, prop or decal (the Select tool picks any of them) to see and edit it here.");
      ImGui::End();
      return;
    }
    // While a field is held or typed in, the panel keeps its own copy; the view's values come back after.
    const bool sameThing = mPropertiesEdit.kind == now.kind && mPropertiesEdit.name == now.name;
    if (!mPropertiesEditing || !sameThing) {
      mPropertiesEdit = now;
      (void)std::snprintf(mPropertiesName, sizeof(mPropertiesName), "%s", now.name.c_str());
    }
    SelectionProperties& edit = mPropertiesEdit;
    bool active = false;
    const auto send = [&](PropertyEdit::What what, const float a, const float b, const float c) {
      PropertyEdit change;
      change.what = what;
      change.values[0] = a;
      change.values[1] = b;
      change.values[2] = c;
      mTools.AskPropertyEdit(change);
    };

    // A picture first where the game has one: a unit's build icon, a decal's own texture.
    {
      std::string picture;
      if (now.kind == SelectionProperties::Kind::Unit && !now.type.empty()) {
        std::string id = now.type;
        for (char& c : id) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        picture = "/textures/ui/common/icons/units/" + id + "_icon.dds";
      } else if (now.kind == SelectionProperties::Kind::Decal && !now.type.empty()) {
        picture = now.type;
      }
      if (!picture.empty()) {
        mTools.Library().Pump(2);
        const float side = ImGui::GetFrameHeight() * 2.6f;
        const std::uint64_t image = mTools.Library().Thumbnail(picture, true);
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (image != 0U) {
          ImGui::Image(static_cast<ImTextureID>(image), ImVec2(side, side));
        } else {
          ImGui::Dummy(ImVec2(side, side));
          ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + side, at.y + side), IM_COL32(58, 65, 75, 255), 4.0f);
        }
        ImGui::SameLine();
        ImGui::BeginGroup();
        if (now.kind == SelectionProperties::Kind::Unit) {
          const std::string title = mTools.UnitTypeName(now.type);
          ImGui::TextUnformatted(title.empty() ? now.type.c_str() : title.c_str());
          ImGui::TextDisabled("%s  |  %s", now.type.c_str(), now.owner.c_str());
        } else {
          const std::size_t slash = now.type.find_last_of('/');
          ImGui::TextUnformatted(slash == std::string::npos ? now.type.c_str() : now.type.c_str() + slash + 1);
          ImGui::TextDisabled("%.0f x %.0f", static_cast<double>(now.size[0]), static_cast<double>(now.size[1]));
        }
        ImGui::EndGroup();
      }
    }
    // The header: its kind as a chip, its name (a marker's can be renamed), how many more are selected.
    {
      const ImVec4 colour = KindColour(now.kind);
      ImGui::PushStyleColor(ImGuiCol_Button, colour);
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, colour);
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, colour);
      ImGui::SmallButton(KindName(now.kind));
      ImGui::PopStyleColor(3);
      ImGui::SameLine();
      if (now.kind == SelectionProperties::Kind::Marker) {
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputText("##name", mPropertiesName, sizeof(mPropertiesName), ImGuiInputTextFlags_EnterReturnsTrue) &&
            now.name != mPropertiesName && mPropertiesName[0] != '\0') {
          PropertyEdit change;
          change.what = PropertyEdit::What::Name;
          change.value = mPropertiesName;
          mTools.AskPropertyEdit(change);
        }
        active = active || ImGui::IsItemActive();
      } else {
        ImGui::TextUnformatted(now.name.c_str());
      }
      if (now.count > 1) {
        ImGui::TextDisabled("and %d more selected (the first is edited)", now.count - 1);
      }
    }

    // Transform: labelled rows, the label to the right of a fixed column as Blender lays them out.
    const float labelWidth = ImGui::CalcTextSize("Location X").x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
    const auto row = [&](const char* const label) {
      ImGui::AlignTextToFramePadding();
      const float width = ImGui::CalcTextSize(label).x;
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + labelWidth - width - ImGui::GetStyle().ItemSpacing.x);
      ImGui::TextDisabled("%s", label);
      ImGui::SameLine(labelWidth + ImGui::GetStyle().WindowPadding.x);
      ImGui::SetNextItemWidth(-1.0f);
    };
    if (ImGui::CollapsingHeader("Transform", ImGuiTreeNodeFlags_DefaultOpen)) {
      bool moved = false;
      row("Location X");
      ImGui::DragFloat("##x", &edit.position[0], 0.1f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      row("Height");
      ImGui::DragFloat("##y", &edit.position[1], 0.05f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      row("Z");
      ImGui::DragFloat("##z", &edit.position[2], 0.1f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      if (moved) {
        send(PropertyEdit::What::Position, edit.position[0], edit.position[1], edit.position[2]);
      }
      row("Heading");
      ImGui::DragFloat("##heading", &edit.heading, 0.5f, -180.0f, 180.0f, "%.1f deg");
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        send(PropertyEdit::What::Heading, edit.heading, 0.0f, 0.0f);
      }
      active = active || ImGui::IsItemActive();
      if (now.kind == SelectionProperties::Kind::Decal) {
        bool sized = false;
        row("Size X");
        ImGui::DragFloat("##sx", &edit.size[0], 0.1f, 0.1f, 4096.0f, "%.2f");
        sized = sized || ImGui::IsItemDeactivatedAfterEdit();
        active = active || ImGui::IsItemActive();
        row("Size Z");
        ImGui::DragFloat("##sz", &edit.size[1], 0.1f, 0.1f, 4096.0f, "%.2f");
        sized = sized || ImGui::IsItemDeactivatedAfterEdit();
        active = active || ImGui::IsItemActive();
        if (sized) {
          send(PropertyEdit::What::Size, edit.size[0], edit.size[1], 0.0f);
        }
      }
    }

    // What the kind has.
    switch (now.kind) {
    case SelectionProperties::Kind::Marker:
      if (ImGui::CollapsingHeader("Marker", ImGuiTreeNodeFlags_DefaultOpen)) {
        row("Type");
        ImGui::TextUnformatted(now.type.c_str());
        // Each field edited as its value: a number, a tick, a colour, a vector or text; written back in the save's form.
        mPropertiesFields.resize(now.fields.size());
        for (std::size_t i = 0; i < now.fields.size(); ++i) {
          const auto& [key, value] = now.fields[i];
          if (!mPropertiesEditing || !sameThing) {
            mPropertiesFields[i] = value;
          }
          ImGui::PushID(static_cast<int>(i));
          row(key.c_str());
          const auto ask = [&](const std::string& written) {
            if (written != value) {
              PropertyEdit change;
              change.what = PropertyEdit::What::Field;
              change.key = key;
              change.value = written;
              mTools.AskPropertyEdit(change);
            }
          };
          std::string& held = mPropertiesFields[i];
          if (held.rfind("FLOAT(", 0) == 0) {
            const std::vector<double> numbers = ValueNumbers(held);
            float number = numbers.empty() ? 0.0f : static_cast<float>(numbers.front());
            if (ImGui::DragFloat("##float", &number, 0.1f, 0.0f, 0.0f, "%.2f")) {
              held = FloatValue(number);
            }
            if (ImGui::IsItemDeactivatedAfterEdit()) {
              ask(held);
            }
          } else if (held.rfind("BOOLEAN(", 0) == 0) {
            bool on = held.find("true") != std::string::npos;
            if (ImGui::Checkbox("##bool", &on)) {
              held = BooleanValue(on);
              ask(held);
            }
          } else if (held.rfind("VECTOR3(", 0) == 0) {
            const std::vector<double> numbers = ValueNumbers(held);
            float v[3] = {0.0f, 0.0f, 0.0f};
            for (std::size_t n = 0; n < 3 && n < numbers.size(); ++n) {
              v[n] = static_cast<float>(numbers[n]);
            }
            if (ImGui::DragFloat3("##vector", v, 0.1f, 0.0f, 0.0f, "%.2f")) {
              held = Vector3Value(v[0], v[1], v[2]);
            }
            if (ImGui::IsItemDeactivatedAfterEdit()) {
              ask(held);
            }
          } else if (held.rfind("STRING(", 0) == 0 && key == "color" && ValueString(held).size() == 8) {
            // A colour: the save's `aarrggbb` hex.
            const unsigned long argb = std::strtoul(ValueString(held).c_str(), nullptr, 16);
            float colour[4] = {static_cast<float>((argb >> 16) & 0xFF) / 255.0f, static_cast<float>((argb >> 8) & 0xFF) / 255.0f,
                               static_cast<float>(argb & 0xFF) / 255.0f, static_cast<float>((argb >> 24) & 0xFF) / 255.0f};
            if (ImGui::ColorEdit4("##colour", colour, ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_DisplayHex)) {
              const auto byte = [](const float c) { return static_cast<unsigned>(std::lround(std::clamp(c, 0.0f, 1.0f) * 255.0f)); };
              char hex[16];
              (void)std::snprintf(hex, sizeof(hex), "%02x%02x%02x%02x", byte(colour[3]), byte(colour[0]), byte(colour[1]), byte(colour[2]));
              held = StringValue(hex);
            }
            if (ImGui::IsItemDeactivatedAfterEdit()) {
              ask(held);
            }
          } else if (held.rfind("STRING(", 0) == 0) {
            char buffer[512];
            (void)std::snprintf(buffer, sizeof(buffer), "%s", ValueString(held).c_str());
            if (ImGui::InputText("##text", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
              ask(StringValue(buffer));
            }
            held = StringValue(buffer);
          } else {
            // Anything else as the save writes it.
            char buffer[512];
            (void)std::snprintf(buffer, sizeof(buffer), "%s", held.c_str());
            if (ImGui::InputText("##raw", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
              ask(buffer);
            }
            held = buffer;
          }
          active = active || ImGui::IsItemActive();
          ImGui::PopID();
        }
      }
      // An adaptive map: which army this resource spawns with, which option group it belongs to (_tables.lua).
      if ((now.type == "Mass" || now.type == "Hydrocarbon") && ImGui::CollapsingHeader("Adaptive map", ImGuiTreeNodeFlags_DefaultOpen)) {
        const bool hydro = now.type == "Hydrocarbon";
        const std::vector<ScenarioTeam> teams = mDocument.Teams();
        const int slots = teams.empty() ? 0 : static_cast<int>(teams.front().armies.size());
        AdaptiveTables tables;
        std::string error;
        const bool adaptive = mDocument.Adaptive();
        if (adaptive && !ParseAdaptiveTables(mDocument.TablesText(), tables, error)) {
          ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.0f), "_tables.lua doesn't read: %s", error.c_str());
        } else if (!adaptive) {
          HelpNote("Not an adaptive map. Adaptive maps (FAF's \"Ultimate maps\" script by CookieNoob and KeyBlue) spawn each "
                   "player's resources only when that player is in the game, and let the lobby's options add or remove groups of "
                   "resources. The editor writes the _tables.lua; the script's _script.lua and _options.lua come from an adaptive "
                   "map (copy them into this map's folder).");
          if (ImGui::Button("Make this map adaptive", ImVec2(-1.0f, 0.0f))) {
            AdaptiveTables fresh;
            fresh.maxPlayers = std::max(slots, 1);
            fresh.mexArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
            fresh.hydroArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
            mDocument.SetTablesText(WithAdaptiveTables("", fresh));
          }
        } else if (AdaptiveEntry(now.name, hydro).empty()) {
          // The script finds resources by name ("Mass 07" for the entry 7): a marker named otherwise can't be in a table.
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "The script finds resources by name: \"%s 07\".", hydro ? "Hydrocarbon" : "Mass");
          int highest = 0;
          const std::string prefix = hydro ? "Hydrocarbon " : "Mass ";
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            if (marker.name.rfind(prefix, 0) == 0) {
              highest = std::max(highest, std::atoi(marker.name.c_str() + prefix.size()));
            }
          }
          char next[64];
          (void)std::snprintf(next, sizeof(next), "%s%02d", prefix.c_str(), highest + 1);
          if (ImGui::Button((std::string("Rename to ") + next).c_str(), ImVec2(-1.0f, 0.0f))) {
            PropertyEdit change;
            change.what = PropertyEdit::What::Name;
            change.value = next;
            mTools.AskPropertyEdit(change);
          }
        } else {
          // Tables without the script that reads them do nothing in the game.
          if (AdaptiveTablesPath(mDocument.Script()).empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
            ImGui::TextWrapped("This map's _script.lua doesn't read its tables yet: put the adaptive _script.lua and "
                               "_options.lua in its folder, importing %s.", mDocument.Facts().tablesPath.c_str());
            ImGui::PopStyleColor();
          }
          // The edit: a copy of the tables changed, written into the file's text as one undo step.
          AdaptiveTables changed = tables;
          bool edited = false;
          const auto remove = [&](std::vector<std::string>& list) {
            const auto found = std::find(list.begin(), list.end(), now.name);
            if (found != list.end()) {
              list.erase(found);
              return true;
            }
            return false;
          };

          // Spawns with: the army whose presence it needs (its line in spwnMexArmy / spwnHydroArmy).
          std::vector<std::vector<std::string>>& byArmy = hydro ? changed.hydroArmy : changed.mexArmy;
          int army = 0;
          for (std::size_t i = 0; i < byArmy.size(); ++i) {
            if (std::find(byArmy[i].begin(), byArmy[i].end(), now.name) != byArmy[i].end()) {
              army = static_cast<int>(i) + 1;
            }
          }
          const int armyCount = std::max({changed.maxPlayers, slots, static_cast<int>(byArmy.size())});
          const auto armyName = [&](const int a) { return a == 0 ? std::string("Always (any players)") : "ARMY_" + std::to_string(a); };
          row("Spawns with");
          if (ImGui::BeginCombo("##adaptivearmy", armyName(army).c_str())) {
            for (int a = 0; a <= armyCount; ++a) {
              if (ImGui::Selectable(armyName(a).c_str(), a == army) && a != army) {
                for (std::vector<std::string>& list : byArmy) {
                  (void)remove(list);
                }
                if (a > 0) {
                  if (static_cast<int>(byArmy.size()) < a) {
                    byArmy.resize(static_cast<std::size_t>(a));
                  }
                  byArmy[static_cast<std::size_t>(a - 1)].push_back(now.name);
                }
                edited = true;
              }
            }
            ImGui::EndCombo();
          }

          // Option group: one table of the lobby's options and its group (the option's key k removes groups k and above).
          std::string table;
          int group = 0;
          for (const auto& [name, groups] : changed.options) {
            for (std::size_t g = 0; g < groups.size(); ++g) {
              if (std::find(groups[g].begin(), groups[g].end(), now.name) != groups[g].end()) {
                table = name;
                group = static_cast<int>(g) + 1;
              }
            }
          }
          const auto labelOf = [](const std::string& name) {
            for (const OptionTable& option : KnownOptionTables()) {
              if (name == option.name) {
                return std::string(option.label);
              }
            }
            return name.empty() ? std::string("None") : name;
          };
          const auto place = [&](const std::string& toTable, const int toGroup) {
            for (auto& [name, groups] : changed.options) {
              for (std::vector<std::string>& list : groups) {
                (void)remove(list);
              }
            }
            if (!toTable.empty()) {
              auto found = std::find_if(changed.options.begin(), changed.options.end(), [&](const auto& entry) { return entry.first == toTable; });
              if (found == changed.options.end()) {
                changed.options.emplace_back(toTable, std::vector<std::vector<std::string>>{});
                found = std::prev(changed.options.end());
              }
              if (static_cast<int>(found->second.size()) < toGroup) {
                found->second.resize(static_cast<std::size_t>(toGroup));
              }
              found->second[static_cast<std::size_t>(toGroup - 1)].push_back(now.name);
            }
            edited = true;
          };
          row("Option");
          if (ImGui::BeginCombo("##adaptivetable", labelOf(table).c_str())) {
            if (ImGui::Selectable("None", table.empty()) && !table.empty()) {
              place("", 0);
            }
            for (const OptionTable& option : KnownOptionTables()) {
              if (option.hydro == hydro && ImGui::Selectable(option.label, table == option.name) && table != option.name) {
                place(option.name, 1);
              }
            }
            ImGui::EndCombo();
          }
          if (!table.empty()) {
            int wanted = group;
            row("Group");
            if (ImGui::InputInt("##adaptivegroup", &wanted) && wanted >= 1 && wanted <= 16 && wanted != group) {
              place(table, wanted);
            }
          }
          if (!hydro) {
            bool forward = std::find(changed.forwardCrazyrush.begin(), changed.forwardCrazyrush.end(), now.name) != changed.forwardCrazyrush.end();
            bool one = std::find(changed.crazyrushOne.begin(), changed.crazyrushOne.end(), now.name) != changed.crazyrushOne.end();
            row("Crazyrush");
            if (ImGui::Checkbox("Forward", &forward)) {
              if (!remove(changed.forwardCrazyrush)) {
                changed.forwardCrazyrush.push_back(now.name);
              }
              edited = true;
            }
            ImGui::SameLine();
            if (ImGui::Checkbox("The one core mex", &one)) {
              if (!remove(changed.crazyrushOne)) {
                changed.crazyrushOne.push_back(now.name);
              }
              edited = true;
            }
          }
          if (edited) {
            // The script reads armies up to maxPlayerOnMap: never fewer than the lobby's slots.
            changed.maxPlayers = std::max(changed.maxPlayers, slots);
            mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), changed));
          }
          HelpNote("Spawns with: the resource is there only when that army's player is in the game. Option: the lobby's option "
                   "of that name removes groups from its key up, so group 1 goes first. Written to _tables.lua as one undo step.");
        }
      }
      break;
    case SelectionProperties::Kind::Unit:
      if (ImGui::CollapsingHeader("Unit", ImGuiTreeNodeFlags_DefaultOpen)) {
        row("Blueprint");
        ImGui::TextUnformatted(now.type.c_str());
        row("Army");
        ImGui::TextUnformatted(now.owner.c_str());
      }
      break;
    case SelectionProperties::Kind::Prop:
      if (ImGui::CollapsingHeader("Prop", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextWrapped("%s", now.type.c_str());
        if (!now.details.empty()) {
          ImGui::TextDisabled("%s", now.details.c_str());
        }
      }
      break;
    case SelectionProperties::Kind::Decal:
      if (ImGui::CollapsingHeader("Decal", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextWrapped("%s", now.type.c_str());
      }
      break;
    default:
      break;
    }
    HelpNote("Drag a value or type one (Enter); each change is one undo step. With several selected, the first is edited.");
    mPropertiesEditing = active;
    ImGui::End();
  }
} // namespace faf::editor
