#pragma once

#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdFieldStack.h"

#include <algorithm>
#include <expected>
#include <functional>
#include <vector>
#include <string>

namespace faf::editor
{
  /**
   * Terrain > Fields (FAF Studio's Fields panel, "advanced"): the field library op by op on the map's heights. Pick an
   * op, type its parameters, Apply onto the stack (each result the next one's input), Back drops the last; the top is
   * shown as a picture; "Put on the map" writes it as one undo step.
   */
  class EdFieldsPanel
  {
  public:
    /** The map's heights now, in map units (false when no map is open). */
    void SetGroundSource(
      std::function<bool(field::Grid&)> source
    )
    {
      mGround = std::move(source);
    }
    void Draw(bool& open, bool mapOpen);
    /** The heights to put on the map, once each time "Put on the map" was pressed. */
    bool TakeCommit(field::Grid& out);
    /** Commit to layer (FAF Studio's Fields): the top of the stack (0..1) as a paint layer's mask; the layer 1..8. */
    bool TakeLayerCommit(field::Grid& out, int& layer);
    /**
     * Generate (FAF Studio's fieldgen.lua): a relief preset mixed into the ground that is there. The app computes it
     * (it knows the markers, the playable area and the water) and gives back the change for the picture.
     */
    struct QuickGenSettings
    {
      int preset = 0; // QuickGenPresets
      int blend = 0;  // add, multiply, max (raise only), min (lower only), replace
      float amplitude = 18.0f;
      float strength = 1.0f;
      float scale = 140.0f;
      int seed = 1;
      float detail = 0.5f;  // how fine the finest octave is, 0..1
      float warp = 0.5f;    // 0..1 of the feature size
      float gullies = 0.0f; // 0..1: a brief droplet erosion after the relief (FAF Studio's gullies)
      int mask = 0; // 0 whole map, 1 playable area, 2 the area named below
      std::string area;
      float feather = 24.0f;
      bool keepFlat = true;
      float flatRadius = 24.0f;
      bool keepWater = true;
    };
    /** FAF Studio's fieldgen presets: their defaults; each builds its relief from several field ops (EdApp). */
    struct QuickGenPreset
    {
      const char* label;
      const char* tip;
      float scale;
      float amplitude;
      float gullies;
      float warp;
      float detail;
    };
    [[nodiscard]] static const std::vector<QuickGenPreset>& QuickGenPresets();
    /** Preview (false) or Apply (true) asked, with the settings. */
    [[nodiscard]] bool TakeQuickGen(
      QuickGenSettings& settings,
      bool& apply
    )
    {
      if (mQuickAsk == 0) {
        return false;
      }
      settings = mQuick;
      apply = mQuickAsk == 2;
      mQuickAsk = 0;
      return true;
    }
    void SetQuickGenResult(
      field::Grid change,
      std::string text
    )
    {
      mQuickChange = std::move(change);
      mQuickText = std::move(text);
    }
    void SetAreaNames(
      std::vector<std::string> areas
    )
    {
      mAreas = std::move(areas);
    }
    /** Test runs (`/quickgen <preset>,<blend>`): Apply with that preset and blend. */
    void AskQuickGen(
      const int preset,
      const int blend
    )
    {
      mQuick.preset = preset;
      mQuick.blend = blend;
      const QuickGenPreset& p = QuickGenPresets()[static_cast<std::size_t>(std::clamp(preset, 0, 5))];
      mQuick.scale = p.scale;
      mQuick.amplitude = p.amplitude;
      mQuick.warp = p.warp;
      mQuick.detail = p.detail;
      mQuick.gullies = p.gullies;
      mQuickAsk = 2;
    }
    /** Test runs: start from the map, apply `op` with `params`; the status says how it went, or the error. */
    [[nodiscard]] std::expected<std::string, std::string> RunForTest(const std::string& op, const std::string& params);
    [[nodiscard]] const FieldStack& Stack() const noexcept
    {
      return mStack;
    }

  private:
    std::function<bool(field::Grid&)> mGround;
    FieldStack mStack;
    int mOp = 0;
    char mFilter[64] = {};
    char mParams[1024] = "radius = 4\n";
    std::string mStatus;
    bool mCommitAsked = false;
    bool mLayerCommitAsked = false;
    int mCommitLayer = 1;
    /** Live preview: the last op applied again half a second after its parameters change. */
    bool mLive = false;
    std::string mLiveParams;
    double mLiveDue = -1.0;
    QuickGenSettings mQuick;
    int mQuickAsk = 0; // 1 preview, 2 apply
    field::Grid mQuickChange;
    std::string mQuickText;
    std::vector<std::string> mAreas;
    void DrawQuickGen();
  };
} // namespace faf::editor
