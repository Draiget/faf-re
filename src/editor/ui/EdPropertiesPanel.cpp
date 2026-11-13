// The Properties panel (View > Properties): the selected marker, unit, prop or decal, by kind, Blender-style -- a
// header with its kind and name, its transform as labelled rows, then what its kind has.

#include <cctype>
#include "editor/ui/EdControls.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <string>

#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/EdShell.h"
#include "editor/ui/EdHelp.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    const char* KindName(
      const SelectionProperties::Kind kind
    )
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

    ImVec4 KindColour(
      const SelectionProperties::Kind kind
    )
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
    if (!ImGui::Begin(Panel("Properties"), &mShowProperties)) {
      ImGui::End();
      return;
    }
    // The map border while the toolbar's border button is on.
    if (mTools.EditingBorder()) {
      if (Section("Map border")) {
        mTools.DrawPlayableArea();
      }
      ImGui::Spacing();
    }
    // The game's own units selected in the editor's view in front of a play.
    if (!mTools.LiveSelection().empty()) {
      DrawLiveUnitPanel();
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
      } else if (now.kind == SelectionProperties::Kind::Prop && !now.type.empty()) {
        picture = now.type;
      }
      if (!picture.empty()) {
        mTools.Library().Pump(2);
        const float side = ImGui::GetFrameHeight() * 2.6f;
        const std::uint64_t image = now.kind == SelectionProperties::Kind::Prop
          ? mTools.PropPicture(picture)
          : mTools.Library().Thumbnail(picture, true);
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (image != 0U) {
          ImGui::Image(static_cast<ImTextureID>(image), ImVec2(side, side));
        } else {
          ImGui::Dummy(ImVec2(side, side));
          ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + side, at.y + side), LineU32(), 4.0f);
        }
        ImGui::SameLine();
        ImGui::BeginGroup();
        if (now.kind == SelectionProperties::Kind::Unit) {
          const std::string title = mTools.UnitTypeName(now.type);
          ImGui::TextUnformatted(title.empty() ? now.type.c_str() : title.c_str());
          ImGui::TextDisabled("%s  |  %s", now.type.c_str(), now.owner.c_str());
        } else if (now.kind == SelectionProperties::Kind::Prop) {
          ImGui::TextUnformatted(now.name.c_str());
          ImGui::TextDisabled("prop");
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
      // The mockup's pill: the kind's colour faint behind its words in that colour, as tall as the name field beside
      // it.
      const ImVec4 colour = KindColour(now.kind);
      const char* const kind = KindName(now.kind);
      const ImVec2 words = ImGui::CalcTextSize(kind);
      const float height = ImGui::GetFrameHeight();
      const float width = std::round(words.x + ImGui::GetStyle().FramePadding.x * 2.0f);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      // Its own id: the section below has the same word ("Unit"), and two items with one id are an ImGui error.
      ImGui::Dummy(ImVec2(width, height));
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      draw->AddRectFilled(
        at,
        ImVec2(at.x + width, at.y + height),
        ImGui::GetColorU32(ImVec4(colour.x, colour.y, colour.z, 0.22f)),
        ImGui::GetStyle().FrameRounding
      );
      const ImVec4 ink(
        colour.x + (1.0f - colour.x) * 0.35f,
        colour.y + (1.0f - colour.y) * 0.35f,
        colour.z + (1.0f - colour.z) * 0.35f,
        1.0f
      );
      draw->AddText(
        ImVec2(at.x + (width - words.x) * 0.5f, at.y + (height - words.y) * 0.5f), ImGui::GetColorU32(ink), kind
      );
      ImGui::SameLine();
      if (now.kind == SelectionProperties::Kind::Marker) {
        ImGui::SetNextItemWidth(-1.0f);
        if (
          ImGui::InputText("##name", mPropertiesName, sizeof(mPropertiesName), ImGuiInputTextFlags_EnterReturnsTrue) &&
          now.name != mPropertiesName && mPropertiesName[0] != '\0'
        ) {
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
    if (Section("Transform")) {
      bool moved = false;
      row("Location X");
      FillDragFloat("##x", &edit.position[0], 0.1f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      row("Height");
      FillDragFloat("##y", &edit.position[1], 0.05f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      row("Z");
      FillDragFloat("##z", &edit.position[2], 0.1f, 0.0f, 0.0f, "%.2f");
      moved = moved || ImGui::IsItemDeactivatedAfterEdit();
      active = active || ImGui::IsItemActive();
      if (moved) {
        send(PropertyEdit::What::Position, edit.position[0], edit.position[1], edit.position[2]);
      }
      row("Heading");
      FillDragFloat("##heading", &edit.heading, 0.5f, -180.0f, 180.0f, "%.1f deg");
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        send(PropertyEdit::What::Heading, edit.heading, 0.0f, 0.0f);
      }
      active = active || ImGui::IsItemActive();
      if (now.kind == SelectionProperties::Kind::Decal) {
        bool sized = false;
        row("Size X");
        FillDragFloat("##sx", &edit.size[0], 0.1f, 0.1f, 4096.0f, "%.2f");
        sized = sized || ImGui::IsItemDeactivatedAfterEdit();
        active = active || ImGui::IsItemActive();
        row("Size Z");
        FillDragFloat("##sz", &edit.size[1], 0.1f, 0.1f, 4096.0f, "%.2f");
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
      if (Section("Marker")) {
        row("Type");
        ImGui::TextUnformatted(now.type.c_str());
        if (const MarkerType* const type = FindMarkerType(now.type); type != nullptr) {
          ImGui::SameLine();
          ImGui::TextDisabled("(%s)", type->group);
        }
        // What the game does with this type (FAF's Lua), so a mapper knows what placing one changes.
        if (const char* const use = MarkerTypeUse(now.type); use[0] != '\0') {
          ImGui::PushTextWrapPos(0.0f);
          ImGui::TextDisabled("In the game: %s", use);
          ImGui::PopTextWrapPos();
        }
        // Each field edited as its value: a number, a tick, a colour, a vector or text; written back in the save's
        // form.
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
            if (FillDragFloat("##float", &number, 0.1f, 0.0f, 0.0f, "%.2f")) {
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
            float colour[4] = {
              static_cast<float>((argb >> 16) & 0xFF) / 255.0f,
              static_cast<float>((argb >> 8) & 0xFF) / 255.0f,
              static_cast<float>(argb & 0xFF) / 255.0f,
              static_cast<float>((argb >> 24) & 0xFF) / 255.0f
            };
            if (ImGui::ColorEdit4("##colour", colour, ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_DisplayHex)) {
              const auto byte = [](const float c) {
                return static_cast<unsigned>(std::lround(std::clamp(c, 0.0f, 1.0f) * 255.0f));
              };
              char hex[16];
              (void)std::snprintf(
                hex, sizeof(hex), "%02x%02x%02x%02x", byte(colour[3]), byte(colour[0]), byte(colour[1]), byte(colour[2])
              );
              held = StringValue(hex);
            }
            if (ImGui::IsItemDeactivatedAfterEdit()) {
              ask(held);
            }
          } else if (held.rfind("STRING(", 0) == 0 && key == "prop" && FindMarkerType(now.type) != nullptr) {
            // A known type's model: the type sets it (editors draw it; the game doesn't read it), so it isn't typed in.
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%s", ValueString(held).c_str());
            ImGui::SetItemTooltip(
              "Set by the marker's type (%s): the model editors draw for it. The game doesn't read it.",
              now.type.c_str()
            );
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
          if (const char* const use = MarkerFieldUse(key); use[0] != '\0') {
            ImGui::SetItemTooltip("%s", use);
          }
          ImGui::PopID();
        }
      }
      // An adaptive map: which army this resource spawns with, which option group it belongs to (_tables.lua).
      if ((now.type == "Mass" || now.type == "Hydrocarbon") && Section("Adaptive map")) {
        const bool hydro = now.type == "Hydrocarbon";
        const std::vector<ScenarioTeam> teams = mDocument.Teams();
        const int slots = teams.empty() ? 0 : static_cast<int>(teams.front().armies.size());
        AdaptiveTables tables;
        std::string error;
        const bool adaptive = mDocument.Adaptive();
        if (adaptive && !ParseAdaptiveTables(mDocument.TablesText(), tables, error)) {
          ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.0f), "_tables.lua doesn't read: %s", error.c_str());
        } else if (!adaptive) {
          HelpNote(
            "Not an adaptive map. Adaptive maps (FAF's \"Ultimate maps\" script by CookieNoob and KeyBlue) spawn each "
            "player's resources only when that player is in the game, and let the lobby's options add or remove groups "
            "of "
            "resources. The editor writes the _tables.lua; the script's _script.lua and _options.lua come from an "
            "adaptive "
            "map (copy them into this map's folder)."
          );
          if (ImGui::Button("Make this map adaptive", ImVec2(-1.0f, 0.0f))) {
            AdaptiveTables fresh;
            fresh.maxPlayers = std::max(slots, 1);
            fresh.mexArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
            fresh.hydroArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
            mDocument.SetTablesText(WithAdaptiveTables("", fresh));
          }
        } else if (AdaptiveEntry(now.name, hydro).empty()) {
          // The script finds resources by name ("Mass 07" for the entry 7): a marker named otherwise can't be in a
          // table.
          ImGui::TextColored(
            ImVec4(0.95f, 0.75f, 0.30f, 1.0f),
            "The script finds resources by name: \"%s 07\".",
            hydro ? "Hydrocarbon" : "Mass"
          );
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
            ImGui::TextWrapped(
              "This map's _script.lua doesn't read its tables yet: put the adaptive _script.lua and "
              "_options.lua in its folder, importing %s.",
              mDocument.Facts().tablesPath.c_str()
            );
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
          const auto armyName = [&](const int a) {
            return a == 0 ? std::string("Always (any players)") : "ARMY_" + std::to_string(a);
          };
          row("Spawns with");
          if (EdBeginCombo("##adaptivearmy", armyName(army).c_str())) {
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

          // Option group: one table of the lobby's options and its group (the option's key k removes groups k and
          // above).
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
              auto found = std::find_if(changed.options.begin(), changed.options.end(), [&](const auto& entry) {
                return entry.first == toTable;
              });
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
          if (EdBeginCombo("##adaptivetable", labelOf(table).c_str())) {
            if (ImGui::Selectable("None", table.empty()) && !table.empty()) {
              place("", 0);
            }
            for (const OptionTable& option : KnownOptionTables()) {
              if (
                option.hydro == hydro && ImGui::Selectable(option.label, table == option.name) && table != option.name
              ) {
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
            bool forward = std::find(changed.forwardCrazyrush.begin(), changed.forwardCrazyrush.end(), now.name) !=
              changed.forwardCrazyrush.end();
            bool one = std::find(changed.crazyrushOne.begin(), changed.crazyrushOne.end(), now.name) !=
              changed.crazyrushOne.end();
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
          HelpNote(
            "Spawns with: the resource is there only when that army's player is in the game. Option: the lobby's "
            "option "
            "of that name removes groups from its key up, so group 1 goes first. Written to _tables.lua as one undo "
            "step."
          );
          if (ImGui::Button("The whole map's adaptive setup (Map panel)", ImVec2(-1.0f, 0.0f))) {
            mShowMap = true;
            ImGui::SetWindowFocus(Panel("Map"));
          }
          ImGui::SetItemTooltip(
            "Every army's resources, the option tables and their groups, and the lobby options in _options.lua"
          );
        }
      }
      break;
    case SelectionProperties::Kind::Unit:
      if (Section("Unit")) {
        row("Blueprint");
        ImGui::TextUnformatted(now.type.c_str());
        row("Army");
        ImGui::TextUnformatted(now.owner.c_str());
        DrawUnitFate(now);
      }
      break;
    case SelectionProperties::Kind::Prop:
      if (Section("Prop")) {
        ImGui::TextWrapped("%s", now.type.c_str());
        if (!now.details.empty()) {
          ImGui::TextDisabled("%s", now.details.c_str());
        }
        // Another prop in its place: the game's props as pictures (user ask 2026-11-11, WPE.55).
        if (
          ImGui::Button(mPropBrowserOpen ? "Close the prop browser" : "Change to another prop...", ImVec2(-1.0f, 0.0f))
        ) {
          mPropBrowserOpen = !mPropBrowserOpen;
        }
        if (mPropBrowserOpen) {
          DrawPropBrowser(now.type, now.count);
        }
      }
      break;
    case SelectionProperties::Kind::Decal:
      if (Section("Decal")) {
        ImGui::TextWrapped("%s", now.type.c_str());
      }
      break;
    default:
      break;
    }
    HelpNote(
      "Drag a value or type one (Enter); each change is one undo step. With several selected, the first is edited."
    );
    mPropertiesEditing = active;
    ImGui::End();
  }

  void EdShell::DrawPropBrowser(
    const std::string& current,
    const int selected
  )
  {
    const std::vector<std::string>& blueprints = mTools.PropBlueprints();
    if (blueprints.empty()) {
      ImGui::TextDisabled("The props come once the game's rules are built after startup.");
      return;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint(
      "##propbrowserfilter", "search (rock, pine, wreck...)", mPropBrowserFilter, sizeof(mPropBrowserFilter)
    );
    std::string filter = mPropBrowserFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    // "/env/evergreen/props/rocks/fieldstone02_prop.bp" is "fieldstone02", in "evergreen / rocks".
    const auto shortName = [](const std::string& path) {
      std::size_t start = path.find_last_of('/');
      std::string name = path.substr(start == std::string::npos ? 0 : start + 1);
      if (name.size() > 8 && name.compare(name.size() - 8, 8, "_prop.bp") == 0) {
        name.resize(name.size() - 8);
      }
      return name;
    };
    std::string chosen;
    const float tile = ImGui::GetFrameHeight() * 3.2f;
    const float labelHeight = ImGui::GetTextLineHeight() + 2.0f;
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    if (
      ImGui::BeginChild(
        "##propbrowser",
        ImVec2(0.0f, FillHeight(ImGui::GetFrameHeightWithSpacing() * 4.0f, (tile + labelHeight + spacing) * 2.5f)),
        ImGuiChildFlags_Borders
      )
    ) {
      const int columns =
        std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + spacing) / (tile + spacing)));
      int shown = 0;
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      for (const std::string& blueprint : blueprints) {
        if (!filter.empty() && blueprint.find(filter) == std::string::npos) {
          continue;
        }
        if (shown % columns != 0) {
          ImGui::SameLine(0.0f, spacing);
        }
        ++shown;
        ImGui::PushID(blueprint.c_str());
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("##tile", ImVec2(tile, tile + labelHeight))) {
          chosen = blueprint;
        }
        const bool hovered = ImGui::IsItemHovered();
        ImGui::PopID();
        // Only tiles in view ask for their picture (there are thousands of props).
        if (!ImGui::IsItemVisible()) {
          continue;
        }
        const bool isCurrent = blueprint == current;
        draw->AddRectFilled(at, ImVec2(at.x + tile, at.y + tile), SurfaceU32(), 4.0f);
        if (const std::uint64_t image = mTools.PropPicture(blueprint); image != 0U) {
          draw->AddImage(
            static_cast<ImTextureID>(image),
            ImVec2(at.x + 2.0f, at.y + 2.0f),
            ImVec2(at.x + tile - 2.0f, at.y + tile - 2.0f)
          );
        }
        const ImU32 border = isCurrent ? AccentU32() : hovered ? InkU32() : LineU32();
        draw->AddRect(at, ImVec2(at.x + tile, at.y + tile), border, 4.0f, 0, isCurrent ? 2.0f : 1.0f);
        std::string name = shortName(blueprint);
        while (name.size() > 3 && ImGui::CalcTextSize(name.c_str()).x > tile) {
          name.resize(name.size() - 1);
        }
        draw->AddText(
          ImVec2(at.x, at.y + tile + 1.0f),
          ImGui::GetColorU32(isCurrent ? ImGuiCol_Text : ImGuiCol_TextDisabled),
          name.c_str()
        );
        if (hovered) {
          ImGui::SetTooltip(
            "%s\nclick: %s",
            blueprint.c_str(),
            selected > 1 ? "every selected prop becomes this one" : "the prop becomes this one"
          );
        }
      }
      if (shown == 0) {
        ImGui::TextDisabled("No prop matches \"%s\".", mPropBrowserFilter);
      }
      // `/propswap` (test runs): the first tile the filter shows, as a click on it.
      if (mTestPropSwap && shown > 0) {
        mTestPropSwap = false;
        for (const std::string& blueprint : blueprints) {
          if (chosen.empty() && (filter.empty() || blueprint.find(filter) != std::string::npos)) {
            chosen = blueprint;
          }
        }
        gpg::Logf("editor: /propswap: the browser's first tile for \"%s\" is %s", mPropBrowserFilter, chosen.c_str());
      }
    }
    ImGui::EndChild();
    if (!chosen.empty() && chosen != current) {
      PropertyEdit change;
      change.what = PropertyEdit::What::Blueprint;
      change.value = chosen;
      mTools.AskPropertyEdit(change);
    }
  }
} // namespace faf::editor
