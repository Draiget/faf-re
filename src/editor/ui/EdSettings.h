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
    /** The start screen when the editor starts without a map asked for. */
    static constexpr const char* kStartScreen = "StartScreen";
    /** The start screen's FAF vault rows (your uploads, most played, the vault half of its search). */
    static constexpr const char* kVaultItems = "VaultItems";
    /** Autosave while a map has unsaved changes. */
    static constexpr const char* kAutosave = "Autosave";
    /** Minutes between autosaves: 1, 2, 5 or 10. */
    static constexpr const char* kAutosaveMinutes = "AutosaveMinutes";
    /** Backups of a map's files a map keeps (made before the first save of a session): 0, 3, 10 or 30. */
    static constexpr const char* kBackups = "Backups";
    static constexpr const char* kPopouts = "Popouts";
    static constexpr const char* kIdleFps = "IdleFps";
    static constexpr const char* kFormat = "Format";
    /**
     * Graphics (FAF Studio's graphics settings, on this engine's switches): each "auto" (the engine's own default) or
     * a value. Shadows, bloom, FXAA and ambient occlusion "on" / "off"; the shadow map's size 1024 / 2048 / 4096;
     * texture detail "high" / "medium" / "low" (mip levels skipped 0 / 1 / 2); anisotropic filtering 0 / 4 / 8 / 16.
     */
    static constexpr const char* kGfxShadows = "GfxShadows";
    static constexpr const char* kGfxShadowSize = "GfxShadowSize";
    static constexpr const char* kGfxBloom = "GfxBloom";
    static constexpr const char* kGfxFxaa = "GfxFxaa";
    static constexpr const char* kGfxAo = "GfxAo";
    static constexpr const char* kGfxTextureDetail = "GfxTextureDetail";
    static constexpr const char* kGfxAnisotropy = "GfxAnisotropy";
    // FAF Studio's other graphics settings (graphics.lua): the game's fidelity, shadow distance, model detail, vsync.
    static constexpr const char* kGfxFidelity = "GfxFidelity";
    static constexpr const char* kGfxShadowDistance = "GfxShadowDistance";
    static constexpr const char* kGfxModelDetail = "GfxModelDetail";
    static constexpr const char* kGfxVsync = "GfxVsync";
    /** Studio's shadow quality (`shadow_Fidelity` Off / Low / Medium / High). */
    static constexpr const char* kGfxShadowQuality = "GfxShadowQuality";
    /** Studio's quality presets: "low", "medium", "high", "ultra" set the graphics settings together. */
    bool ApplyGraphicsPreset(const std::string& preset);
    /** The preset the graphics settings match now, or "custom". */
    [[nodiscard]] std::string GraphicsPreset() const;
    /** The terrain tools' GPU compute backend (FAF Studio's ed_gpu_compute) and the smallest field it takes. */
    static constexpr const char* kGpuCompute = "GpuCompute";
    static constexpr const char* kGpuMinCells = "GpuMinCells";
    /** The console lines the graphics settings stand for (none for "auto"), in a fixed order. */
    [[nodiscard]] std::vector<std::string> GraphicsCommands() const;
    /** settings.ini's format now: a file of a newer one is read but never written over. */
    static constexpr int kFormatNow = 1;
    /** The Format line the file had (0: none, a file from before formats).*/
    [[nodiscard]] int FileFormat() const noexcept
    {
      return mFileFormat;
    }

  private:
    std::map<std::string, std::string, std::less<>> mValues;
    int mFileFormat = 0;
  };
} // namespace faf::editor
