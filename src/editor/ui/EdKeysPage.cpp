#include "editor/ui/EdKeysPage.h"
#include "editor/ui/EdControls.h"

#include <algorithm>
#include <cstdio>
#include <vector>

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    struct KeysPageState
    {
      std::string id; // the command whose key is being set, or empty
      int slot = -1;  // its slot
      int startFrame = 0;
      int endFrame = -1; // the frame a key ended the wait: that key is the page's, no command's
      char filter[128] = {};
    };

    KeysPageState& State()
    {
      static KeysPageState state;
      return state;
    }

    /** An ImGui key's name as the editor writes keys, or empty (modifiers, the keypad, mouse buttons, ","). */
    [[nodiscard]] std::string KeyName(
      const ImGuiKey key
    )
    {
      if (key >= ImGuiKey_A && key <= ImGuiKey_Z) {
        return std::string(1, static_cast<char>('A' + (key - ImGuiKey_A)));
      }
      if (key >= ImGuiKey_0 && key <= ImGuiKey_9) {
        return std::string(1, static_cast<char>('0' + (key - ImGuiKey_0)));
      }
      if (key >= ImGuiKey_F1 && key <= ImGuiKey_F24) {
        return "F" + std::to_string(key - ImGuiKey_F1 + 1);
      }
      static const std::pair<ImGuiKey, const char*> kNames[] = {
        {ImGuiKey_Backspace, "Backspace"},
        {ImGuiKey_Tab, "Tab"},
        {ImGuiKey_Enter, "Enter"},
        {ImGuiKey_Escape, "Escape"},
        {ImGuiKey_Space, "Space"},
        {ImGuiKey_PageUp, "PageUp"},
        {ImGuiKey_PageDown, "PageDown"},
        {ImGuiKey_End, "End"},
        {ImGuiKey_Home, "Home"},
        {ImGuiKey_LeftArrow, "Left"},
        {ImGuiKey_UpArrow, "Up"},
        {ImGuiKey_RightArrow, "Right"},
        {ImGuiKey_DownArrow, "Down"},
        {ImGuiKey_Insert, "Insert"},
        {ImGuiKey_Delete, "Delete"},
        {ImGuiKey_Semicolon, ";"},
        {ImGuiKey_Equal, "="},
        {ImGuiKey_Minus, "-"},
        {ImGuiKey_Period, "."},
        {ImGuiKey_Slash, "/"},
        {ImGuiKey_GraveAccent, "`"},
        {ImGuiKey_LeftBracket, "["},
        {ImGuiKey_Backslash, "\\"},
        {ImGuiKey_RightBracket, "]"},
        {ImGuiKey_Apostrophe, "'"},
      };
      for (const auto& [code, name] : kNames) {
        if (code == key) {
          return name;
        }
      }
      return {};
    }

    /** The title of every other command bound to `chord`, joined; empty when it's only this one's. */
    [[nodiscard]] std::vector<const EdCommand*> Others(
      const EdCommands& commands,
      const EdCommand& self,
      const std::string& chord
    )
    {
      std::vector<const EdCommand*> out;
      for (const EdCommand* const other : commands.AllForChord(chord)) {
        if (other->id != self.id) {
          out.push_back(other);
        }
      }
      return out;
    }

    /** Takes `chord` away from the command `id`. */
    void TakeChord(
      EdCommands& commands,
      const std::string& id,
      const std::string& chord
    )
    {
      const EdCommand* const command = commands.Find(id);
      if (command == nullptr) {
        return;
      }
      std::vector<std::string> chords = SplitChords(command->keys);
      chords.erase(std::remove(chords.begin(), chords.end(), chord), chords.end());
      std::string keys;
      for (const std::string& left : chords) {
        keys += (keys.empty() ? "" : ", ") + left;
      }
      (void)commands.SetKeys(id, keys);
    }
  } // namespace

  std::string PanelChordPressed()
  {
    const ImGuiIO& io = ImGui::GetIO();
    for (int k = ImGuiKey_NamedKey_BEGIN; k < ImGuiKey_NamedKey_END; ++k) {
      const ImGuiKey key = static_cast<ImGuiKey>(k);
      if (!ImGui::IsKeyPressed(key, false)) {
        continue;
      }
      const std::string name = KeyName(key);
      if (!name.empty()) {
        return ChordOf(name, io.KeyCtrl, io.KeyShift, io.KeyAlt);
      }
    }
    return {};
  }

  bool KeysPageCapturing()
  {
    // Also on the frame a key ended the wait: the panels' keys run their commands after the page drew, and that key
    // was the page's.
    return !State().id.empty() || State().endFrame == ImGui::GetFrameCount();
  }

  bool DrawKeysPage(
    EdCommands& commands,
    const EdKeyDefaults& defaults
  )
  {
    KeysPageState& s = State();
    bool changed = false;

    // A key while one waits: Escape stops waiting, Backspace takes the key away, any other sets it. The frame of the
    // click itself doesn't count.
    if (!s.id.empty() && ImGui::GetFrameCount() > s.startFrame) {
      const std::string chord = PanelChordPressed();
      if (!chord.empty()) {
        const EdCommand* const command = commands.Find(s.id);
        if (chord == "Escape" || command == nullptr) {
          // waiting stops, nothing changes
        } else {
          const std::string keys = WithKeySlot(command->keys, s.slot, chord == "Backspace" ? "" : chord);
          if (keys != command->keys) {
            gpg::Logf(
              "editor: keys: %s %s -> %s",
              s.id.c_str(),
              command->keys.empty() ? "(none)" : command->keys.c_str(),
              keys.empty() ? "(none)" : keys.c_str()
            );
            (void)commands.SetKeys(s.id, keys);
            changed = true;
          }
        }
        s.id.clear();
        s.slot = -1;
        s.endFrame = ImGui::GetFrameCount();
      }
    }

    const std::vector<std::pair<std::string, std::string>> clashes = commands.Clashes();
    ImGui::SetNextItemWidth(Em(260.0f));
    ImGui::InputTextWithHint("##keysfilter", "Find a command or a key", s.filter, sizeof(s.filter));
    ImGui::SameLine();
    if (ImGui::Button("Reset all")) {
      for (const EdCommand& command : commands.All()) {
        const auto found = defaults.find(command.id);
        const std::string keys = found == defaults.end() ? std::string() : found->second;
        if (command.keys != keys) {
          (void)commands.SetKeys(command.id, keys);
          changed = true;
        }
      }
      gpg::Logf("editor: keys: every command's keys reset");
    }
    ImGui::SameLine();
    if (clashes.empty()) {
      ImGui::TextDisabled("Click a key to change it: Escape keeps it, Backspace takes it away.");
    } else {
      ImGui::TextColored(
        ImVec4(0.95f, 0.70f, 0.25f, 1.0f),
        clashes.size() == 1 ? "%zu key runs more than one command" : "%zu keys run more than one command",
        clashes.size()
      );
    }

    constexpr ImGuiTableFlags kFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
      ImGuiTableFlags_SizingStretchProp;
    if (!ImGui::BeginTable("##keys", 4, kFlags, ImVec2(0.0f, ImGui::GetContentRegionAvail().y))) {
      return changed;
    }
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Command", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthFixed, Em(170.0f));
    ImGui::TableSetupColumn("Other key", ImGuiTableColumnFlags_WidthFixed, Em(170.0f));
    ImGui::TableSetupColumn("##reset", ImGuiTableColumnFlags_WidthFixed, Em(70.0f));
    ImGui::TableHeadersRow();

    const std::string filter = s.filter;
    std::string category;
    for (const EdCommand& command : commands.All()) {
      if (!command.palette) {
        continue;
      }
      if (
        !filter.empty() && FuzzyScore(filter, command.category + " " + command.title) == 0 &&
        FuzzyScore(filter, command.keys) == 0
      ) {
        continue;
      }
      if (command.category != category) {
        category = command.category;
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::PushStyleColor(ImGuiCol_Text, AccentColor());
        ImGui::TextUnformatted(category.c_str());
        ImGui::PopStyleColor();
      }
      ImGui::PushID(command.id.c_str());
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(command.title.c_str());
      if (!command.description.empty() && ImGui::IsItemHovered()) {
        EdSetTooltip("%s\n%s", command.id.c_str(), command.description.c_str());
      } else if (ImGui::IsItemHovered()) {
        EdSetTooltip("%s", command.id.c_str());
      }
      std::vector<std::pair<std::string, const EdCommand*>> shared;
      for (int slot = 0; slot < kKeySlots; ++slot) {
        ImGui::TableSetColumnIndex(1 + slot);
        ImGui::PushID(slot);
        const std::string chord = KeySlot(command.keys, slot);
        const bool waiting = s.id == command.id && s.slot == slot;
        const std::vector<const EdCommand*> others =
          chord.empty() ? std::vector<const EdCommand*>{} : Others(commands, command, chord);
        for (const EdCommand* const other : others) {
          shared.emplace_back(chord, other);
        }
        // Waiting: the accent; shared with another command: amber; empty: the frame colour with dim text, so the
        // keys that are set stand out.
        int pushed = 0;
        if (waiting) {
          ImGui::PushStyleColor(ImGuiCol_Button, AccentColor(0.55f));
          pushed = 1;
        } else if (!others.empty()) {
          ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.75f, 0.50f, 0.10f, 0.55f));
          pushed = 1;
        } else if (chord.empty()) {
          ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
          ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
          pushed = 2;
        }
        const char* const label = waiting ? "Press a key..." : chord.empty() ? "-" : chord.c_str();
        if (ImGui::Button(label, ImVec2(-1.0f, 0.0f))) {
          s.id = command.id;
          s.slot = slot;
          s.startFrame = ImGui::GetFrameCount();
        }
        ImGui::PopStyleColor(pushed);
        ImGui::PopID();
      }
      ImGui::TableSetColumnIndex(3);
      const auto found = defaults.find(command.id);
      const std::string base = found == defaults.end() ? std::string() : found->second;
      if (command.keys != base) {
        if (ImGui::SmallButton("Reset")) {
          (void)commands.SetKeys(command.id, base);
          changed = true;
        }
        if (ImGui::IsItemHovered()) {
          EdSetTooltip("Back to %s", base.empty() ? "no key" : base.c_str());
        }
      }
      // A key another command has: said under the row, with a button that takes it from the other.
      for (const auto& [chord, other] : shared) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::Indent(Em(14.0f));
        ImGui::TextColored(
          ImVec4(0.95f, 0.70f, 0.25f, 1.0f),
          "%s also runs %s > %s",
          chord.c_str(),
          other->category.c_str(),
          other->title.c_str()
        );
        ImGui::Unindent(Em(14.0f));
        ImGui::TableSetColumnIndex(1);
        ImGui::PushID(other->id.c_str());
        ImGui::PushID(chord.c_str());
        if (ImGui::SmallButton("Take it from there")) {
          gpg::Logf("editor: keys: %s taken from %s for %s", chord.c_str(), other->id.c_str(), command.id.c_str());
          TakeChord(commands, other->id, chord);
          changed = true;
        }
        ImGui::PopID();
        ImGui::PopID();
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
    return changed;
  }
} // namespace faf::editor
