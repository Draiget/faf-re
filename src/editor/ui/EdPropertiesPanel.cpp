// The Properties panel (View > Properties): the selected marker, unit, prop or decal, by kind, Blender-style -- a
// header with its kind and name, its transform as labelled rows, then what its kind has.

#include <cstdio>
#include <cstring>
#include <string>

#include "editor/EdShell.h"
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
        // Its other fields as `_save.lua` writes them; Enter applies one.
        mPropertiesFields.resize(now.fields.size());
        for (std::size_t i = 0; i < now.fields.size(); ++i) {
          const auto& [key, value] = now.fields[i];
          if (!mPropertiesEditing || !sameThing) {
            mPropertiesFields[i] = value;
          }
          ImGui::PushID(static_cast<int>(i));
          row(key.c_str());
          char buffer[512];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", mPropertiesFields[i].c_str());
          if (ImGui::InputText("##field", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue) && value != buffer) {
            PropertyEdit change;
            change.what = PropertyEdit::What::Field;
            change.key = key;
            change.value = buffer;
            mTools.AskPropertyEdit(change);
          }
          mPropertiesFields[i] = buffer;
          active = active || ImGui::IsItemActive();
          ImGui::PopID();
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
