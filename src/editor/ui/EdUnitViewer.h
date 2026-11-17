#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <memory>

#include "editor/tools/EdUnitIcon.h"
#include "editor/tools/EdUnitPreview.h"

#include <functional>

namespace moho
{
  class CD3DDynamicTextureSheet;
}

namespace faf::editor
{
  class EdModPanel;
  class EdUnitLabPanel;

  /**
   * Unit viewer (the Units workspace): the unit lab's unit (a derived unit's base) drawn by the game's model thumbnail
   * renderer (REN_RequestThumbnail, as the prop pictures), turned by dragging or the heading and pitch fields; its
   * mesh, levels of detail and scale. Make icon draws it once more, frames the drawn part, makes a 64 x 64 DXT5 icon
   * and writes it into the open mod project as `icons/units/<id>_icon.dds` (a derived unit then names it).
   */
  class EdUnitViewer
  {
  public:
    EdUnitViewer(EdUnitLabPanel& lab, EdModPanel& project);

    void Draw(bool& open);
    /** Draws the icon of the lab's unit into the project (done a few frames later, when the renderer has drawn it). */
    [[nodiscard]] std::expected<void, std::string> AskIcon();
    /** Called once a frame (also while the panel is hidden): finishes an icon asked for. */
    void Frame();
    [[nodiscard]] int DrawnPixels() const noexcept
    {
      return mDrawnPixels;
    }
    /** The view shows the projectile of this weapon (its place in the blueprint), or the unit (-1). */
    void ShowWeapon(
      const int weapon
    ) noexcept
    {
      mShowWeapon = weapon;
    }
    [[nodiscard]] const std::string& Status() const noexcept
    {
      return mStatus;
    }
    /** Brings the panel to the front of its dock the next time it is drawn. */
    void Focus() noexcept
    {
      mFocus = true;
    }
    void SetAngles(
      const float heading,
      const float pitch
    ) noexcept
    {
      mHeading = heading;
      mPitch = pitch;
    }

    /** The animated unit in the view (the scene reads and fills it). */
    [[nodiscard]] UnitPreviewState& Preview() noexcept
    {
      return mPreview;
    }

    /** The game's icon of a unit, decoded to `side` x `side` RGBA bytes (set by the app). */
    std::function<bool(const std::string&, int, std::vector<std::uint8_t>&)> loadGameIcon;
    /** Icons for every unit the project edits or derives, one after another. */
    void AskBatch();
    [[nodiscard]] std::expected<void, std::string> AskIconFor(const std::string& unit);
    /** Test runs (`/iconrecipe`): the icon's recipe; how many of its three pictures the last icon made. */
    void SetIconRecipe(
      const float heading,
      const float pitch,
      const float fov,
      const float fill,
      const float edge
    ) noexcept
    {
      mIconHeading = heading;
      mIconPitch = pitch;
      mIconFov = fov;
      mIconFill = fill;
      mIconEdge = edge;
    }
    [[nodiscard]] int IconPictureCount() const noexcept
    {
      return (mIconPictures[0] != 0U ? 1 : 0) + (mIconPictures[1] != 0U ? 1 : 0) + (mIconPictures[2] != 0U ? 1 : 0);
    }
    /** After Make icon: how the made icon compares with the game's (empty before). */
    [[nodiscard]] const std::string& Comparison() const noexcept
    {
      return mCompare;
    }

  private:
    void DrawInView(const std::string& source);
    std::vector<std::string> mBatch;
    int mBatchTotal = 0;
    IconToneFit mTone;
    bool mToneOn = false;
    std::string mCompare;
    std::vector<std::uint8_t> mShipped;
    std::vector<std::uint8_t> mMade;
    // The icon's recipe (FAF Studio's Icons panel): its own turn, the field of view (0: the game's flat thumbnail),
    // how much of the icon the unit fills, the light edge; and the pictures of the last icon (render, game,
    // difference).
    float mIconHeading = 35.0f;
    float mIconPitch = 15.0f;
    float mIconFov = 0.0f;
    float mIconFill = 0.9f;
    float mIconEdge = 0.0f;
    bool mIconRequest = false; // Request is drawing an icon (its recipe, not the view's turn)
    std::uint64_t mIconPictures[3] = {0, 0, 0};
    std::vector<std::pair<std::uint64_t, int>> mRetiredPictures; // freed a few frames later
    void SetIconPicture(int which, const std::vector<std::uint32_t>& bgra);
    UnitPreviewState mPreview;
    bool Request(
      std::shared_ptr<moho::CD3DDynamicTextureSheet>& sheet,
      int side,
      const std::string& unit,
      int projectileOf = -1
    );
    /** -1: the unit; else the projectile of that weapon (its place in the blueprint's list) is shown. */
    int mShowWeapon = -1;
    std::string mFailed; // the last key whose picture couldn't be asked for (not asked again)

    EdUnitLabPanel& mLab;
    EdModPanel& mProject;
    std::shared_ptr<moho::CD3DDynamicTextureSheet> mSheet;
    std::string mShown; // unit and angles the sheet was asked for
    int mSinceAsked = 0;
    int mDrawnPixels = 0;
    float mHeading = 35.0f; // degrees
    float mPitch = 15.0f;
    // An icon being made.
    std::shared_ptr<moho::CD3DDynamicTextureSheet> mIconSheet;
    std::string mIconUnit;
    int mIconFrames = -1;
    int mIconPass = 0;                       // 0 the black render, 1 the white one
    std::vector<std::uint32_t> mIconOnBlack; // the first pass's pixels
    std::string mStatus;
    bool mFocus = false;
  };
} // namespace faf::editor
