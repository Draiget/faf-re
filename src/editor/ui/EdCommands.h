#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * One thing the editor can do. Every menu item, key, toolbar button and the command palette run commands from one
   * registry, so each shows the same title and keys and says the same reason when it can't run. `why` returns that
   * reason (empty: it can run now); `checked` puts a tick by it in menus.
   */
  struct EdCommand
  {
    std::string id;       // "file.save"
    std::string title;    // "Save"
    std::string category; // "File"
    std::string keys;     // "Ctrl+S", or more than one chord: "Ctrl+Y, Ctrl+Shift+Z"
    std::string description;
    std::function<void()> run;
    std::function<std::string()> why;
    std::function<bool()> checked;
    /** False for the commands a menu makes one of per entry (each recent map): the palette leaves them out. */
    bool palette = true;
  };

  /** A menu entry: a command, a separator, or a submenu with fixed items or items made when it opens. */
  struct EdMenuItem
  {
    std::string command; // a command's id
    std::string label;   // a submenu's label, or a label in place of the command's title
    bool separator = false;
    std::vector<EdMenuItem> items;                     // a fixed submenu
    std::function<std::vector<EdMenuItem>()> provider; // a submenu filled when it opens (Open Recent)
  };

  /** One menu of the title bar: its label (an `&` before the letter Alt opens it with) and entries. */
  struct EdMenu
  {
    std::string label;
    std::vector<EdMenuItem> items;
  };

  class EdCommands
  {
  public:
    /** Adds the command, or replaces the one with the same id; its keys are written canonically. */
    void Add(EdCommand command);
    [[nodiscard]] const EdCommand* Find(std::string_view id) const;
    /** Why it can't run now: empty when it can, "no such command" when there is none. */
    [[nodiscard]] std::string WhyNot(std::string_view id) const;
    [[nodiscard]] bool Checked(std::string_view id) const;
    /** Runs it when it can run; false, with nothing done, when it can't or doesn't exist. */
    bool Run(std::string_view id);
    /** The command one of whose chords is `chord` (any spelling ParseChord takes), or null. */
    [[nodiscard]] const EdCommand* ForChord(std::string_view chord) const;
    /** Pairs of commands that share a chord, with the chord: Settings › Keys warns about each. */
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> Clashes() const;
    /** Gives the command other keys (Settings › Keys); false when there is no such command. */
    bool SetKeys(std::string_view id, std::string_view keys);
    /** A title that follows the state ("Play" / "Stop"); false when there is no such command. */
    bool SetTitle(std::string_view id, std::string_view title);
    [[nodiscard]] const std::vector<EdCommand>& All() const noexcept
    {
      return mCommands;
    }

  private:
    std::vector<EdCommand> mCommands;
  };

  /**
   * A chord as the editor writes it: modifiers in the order Ctrl, Shift, Alt, then the key ("ctrl+shift+s" and
   * "Shift+Control+S" give "Ctrl+Shift+S"; "del" gives "Delete"). Empty when it isn't one chord.
   */
  [[nodiscard]] std::string CanonicalChord(std::string_view chord);
  /** Each chord of a command's keys, canonical; "Ctrl+Y, Ctrl+Shift+Z" gives two. Bad chords are left out. */
  [[nodiscard]] std::vector<std::string> SplitChords(std::string_view keys);
  /** The keys written canonically, chords joined by ", ". */
  [[nodiscard]] std::string CanonicalKeys(std::string_view keys);

  /**
   * How well a palette query matches a text: 0 when it doesn't (each letter of the query must appear in the text, in
   * order, case aside; spaces in the query match anywhere), higher the better: letters at the start of words and runs
   * of letters count more, and the text starting with the query most.
   */
  [[nodiscard]] int FuzzyScore(std::string_view query, std::string_view text);

  /** The label without its `&` (the letter Alt opens it with): "&File" gives "File". */
  [[nodiscard]] std::string MenuLabelText(std::string_view label);
  /** The letter after the `&`, upper-case, or 0. */
  [[nodiscard]] char MenuAccessKey(std::string_view label);
} // namespace faf::editor
