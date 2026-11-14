#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "boost/shared_ptr.h"

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
    bool AskIcon(std::string& error);
    /** Called once a frame (also while the panel is hidden): finishes an icon asked for. */
    void Frame();
    [[nodiscard]] int DrawnPixels() const noexcept
    {
      return mDrawnPixels;
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

  private:
    bool Request(boost::shared_ptr<moho::CD3DDynamicTextureSheet>& sheet, int side, const std::string& unit);

    EdUnitLabPanel& mLab;
    EdModPanel& mProject;
    boost::shared_ptr<moho::CD3DDynamicTextureSheet> mSheet;
    std::string mShown; // unit and angles the sheet was asked for
    int mSinceAsked = 0;
    int mDrawnPixels = 0;
    float mHeading = 35.0f; // degrees
    float mPitch = 15.0f;
    // An icon being made.
    boost::shared_ptr<moho::CD3DDynamicTextureSheet> mIconSheet;
    std::string mIconUnit;
    int mIconFrames = -1;
    std::string mStatus;
    bool mFocus = false;
  };
} // namespace faf::editor
