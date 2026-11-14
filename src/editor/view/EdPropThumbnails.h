#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <memory>

namespace moho
{
  class CD3DDynamicTextureSheet;
}

namespace faf::editor
{
  /**
   * Pictures of prop models for the panels: each blueprint's mesh drawn into a small texture sheet by the game's own
   * thumbnail renderer (REN_RequestThumbnail, the renderer the game's 3D model controls use, CMauiMesh), which the
   * viewport runs as it draws its next frame. Asked for by blueprint path; a few new ones are started each frame.
   */
  class EdPropThumbnails
  {
  public:
    ~EdPropThumbnails();
    /**
     * Where the pictures are kept between runs (empty: not kept): a picture made once is written there after the view
     * has drawn it, and read from there the next time instead of drawing the model again.
     */
    void SetCacheFolder(
      const std::filesystem::path& folder
    )
    {
      mCacheFolder = folder;
    }
    /** How many pictures came from the cache and how many were written to it, this run. */
    [[nodiscard]] int CacheHits() const noexcept
    {
      return mCacheHits;
    }
    [[nodiscard]] int CacheWrites() const noexcept
    {
      return mCacheWrites;
    }
    /** The picture of a prop blueprint (`/env/.../x_prop.bp`) as an ImTextureID, or 0 until its sheet exists. */
    [[nodiscard]] std::uint64_t Get(const std::string& blueprintPath);

    /** Starts up to `count` of the pictures asked for since (needs the game's rules and the device). */
    void Pump(int count);

    /** Drops every picture (the device went away, or the editor closes). */
    void Clear();
    /** Test runs (`/thumbdump`): the first made thumbnail whose blueprint has `name` in it, saved as a 32-bit .bmp. */
    bool Save(const std::string& name, const std::string& file, std::string& blueprint);

    [[nodiscard]] std::size_t Count() const noexcept
    {
      return mEntries.size();
    }

  private:
    struct Entry
    {
      std::shared_ptr<moho::CD3DDynamicTextureSheet> sheet;
      bool failed = false;
      std::uint64_t image = 0; // read from the cache
      int age = 0;             // pumps since the model was asked to be drawn
      bool kept = false;       // written to the cache (or came from it)
    };
    std::filesystem::path mCacheFolder;
    int mCacheHits = 0;
    int mCacheWrites = 0;
    std::map<std::string, Entry> mEntries;
    std::vector<std::string> mWanted;
  };
} // namespace faf::editor
