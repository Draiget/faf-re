#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A DDS image inside a `.scmap`: its 4-byte length, then the image ("DDS ", a 124-byte header, the data). */
  struct ImageChunk
  {
    /** Where its length starts, and its size with the length. */
    std::size_t at = 0;
    std::size_t size = 0;
  };

  /**
   * The length-prefixed DDS images in `bytes` from `from` on, in order: a "DDS " whose header size is 124 and whose
   * length fits the bytes left; each found one is skipped whole, so nothing inside an image is taken for another.
   */
  std::vector<ImageChunk> FindImageChunks(const std::string& bytes, std::size_t from);

  /**
   * `bytes` with each image `keep` marks replaced by the same-numbered one of `originals` (each a whole chunk, length
   * first). Nothing changes when the counts differ.
   */
  std::string WithOriginalImages(const std::string& bytes, const std::vector<ImageChunk>& chunks, const std::vector<std::string>& originals,
                                 const std::vector<bool>& keep);
} // namespace faf::editor
