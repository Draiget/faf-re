#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  class EdTextureLibrary;

  /**
   * A texture input as the particle and material editors show it (user ask 2026-11-11: a browser, not a dropdown): the
   * picked texture's picture and name as a button; a click opens a browser of pictures (a grid, a search, a folder
   * filter, a larger picture and the path on hover), a click on one picks it.
   */
  class EdTexturePicker
  {
  public:
    /**
     * Draws the field for `path` with the textures in `choices` (game paths); true when the user picked another.
     * `withAlpha` shows the pictures with their alpha (particles: their shape) over a dark ground.
     */
    bool Field(const char* id, std::string& path, const std::vector<std::string>& choices, EdTextureLibrary& library, bool withAlpha);
    /** Test runs: the next field drawn opens its browser. */
    void AskOpen() noexcept { mOpenAsk = true; }

  private:
    bool mOpenAsk = false;
    char mSearch[96] = {};
    int mFolder = 0; // 0: all folders
    std::vector<std::string> mFolders;
    std::size_t mFoldersFor = 0; // the choices' count the folders were listed for
    float mTile = 96.0f;
  };
} // namespace faf::editor
