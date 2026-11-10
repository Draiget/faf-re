#include "editor/doc/EdImageChunks.h"

#include <cstdint>
#include <cstring>

namespace faf::editor
{
  std::vector<ImageChunk> FindImageChunks(const std::string& bytes, std::size_t from)
  {
    std::vector<ImageChunk> chunks;
    std::size_t at = from;
    while (true) {
      const std::size_t magic = bytes.find("DDS ", at);
      if (magic == std::string::npos) {
        break;
      }
      if (magic < from + 4 || magic + 8 > bytes.size()) {
        at = magic + 1;
        continue;
      }
      std::int32_t length = 0;
      std::uint32_t headerSize = 0;
      std::memcpy(&length, bytes.data() + magic - 4, sizeof(length));
      std::memcpy(&headerSize, bytes.data() + magic + 4, sizeof(headerSize));
      if (headerSize != 124 || length < 128 || magic + static_cast<std::size_t>(length) > bytes.size()) {
        at = magic + 1;
        continue;
      }
      chunks.push_back({magic - 4, static_cast<std::size_t>(length) + 4});
      at = magic + static_cast<std::size_t>(length);
    }
    return chunks;
  }

  std::string WithOriginalImages(const std::string& bytes, const std::vector<ImageChunk>& chunks, const std::vector<std::string>& originals,
                                 const std::vector<bool>& keep)
  {
    if (chunks.size() != originals.size() || keep.size() != chunks.size()) {
      return bytes;
    }
    std::string out;
    out.reserve(bytes.size());
    std::size_t at = 0;
    for (std::size_t i = 0; i < chunks.size(); ++i) {
      out.append(bytes, at, chunks[i].at - at);
      if (keep[i]) {
        out += originals[i];
      } else {
        out.append(bytes, chunks[i].at, chunks[i].size);
      }
      at = chunks[i].at + chunks[i].size;
    }
    out.append(bytes, at, std::string::npos);
    return out;
  }
} // namespace faf::editor
