#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /**
   * The editor's settings that must be known before its window and panels exist (Settings › Appearance's title
   * row, Viewport's renderer) and the others Settings changes: `settings.ini` in the editor's settings folder, one
   * `<key>=<value>` a line. The theme, the panels' scale and the layout stay in layout.ini, which ImGui reads with
   * the panels; the keys in keys.ini.
   */
  class EdSettings
  {
  public:
    /** Reads the file's lines over the defaults; what it can't use is returned, one text per line. */
    std::vector<std::string> Read(std::string_view text);
    /** The file's text: every setting, defaults included, so the file says what there is. */
    [[nodiscard]] std::string Write() const;

    [[nodiscard]] std::string Get(std::string_view key) const;
    [[nodiscard]] bool GetBool(std::string_view key) const;
    [[nodiscard]] int GetInt(std::string_view key) const;
    /** Sets a known key to a value it takes (see Allowed); false and nothing changed otherwise. */
    bool Set(std::string_view key, std::string_view value);
    bool SetBool(std::string_view key, bool value);
    bool SetInt(std::string_view key, int value);
    /** The values a key takes, or empty for "0" / "1" keys and unknown ones. */
    [[nodiscard]] static std::vector<std::string> Allowed(std::string_view key);
    [[nodiscard]] static bool Known(std::string_view key);

    // The keys.
    /** "own": the editor draws its title row; "windows": Windows' caption (remote desktop, screen readers). */
    static constexpr const char* kTitleBar = "TitleBar";
    /** "auto" (Direct3D 12, then Vulkan), "d3d12" or "vulkan"; `/d3d12` and `/vulkan` win. */
    static constexpr const char* kRenderer = "Renderer";
    /** Frames a second while the editor isn't the window in front and no play runs: 0 (no cap), 10, 30, 60. */
    static constexpr const char* kBackgroundFps = "BackgroundFps";
    /** The panels' help lines in full (View > Full help text). */
    static constexpr const char* kFullHelp = "FullHelp";
    /** The panels stay while a play runs (View > Panels while playing). */
    static constexpr const char* kPanelsWhilePlaying = "PanelsWhilePlaying";

  private:
    std::map<std::string, std::string, std::less<>> mValues;
  };
} // namespace faf::editor
