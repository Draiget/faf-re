#include "editor/tools/EdTextureLibrary.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>

#include "editor/doc/EdMapFile.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    }

    [[nodiscard]] bool EndsWith(const std::string& text, const std::string& tail)
    {
      return text.size() >= tail.size() && text.compare(text.size() - tail.size(), tail.size(), tail) == 0;
    }
  } // namespace

  std::string LayerTextureName(const std::string& path)
  {
    if (path.empty()) {
      return "(empty)";
    }
    std::string name = path.substr(path.find_last_of('/') + 1);
    const std::string lower = Lower(name);
    for (const char* const suffix : {"_albedo.dds", ".dds"}) {
      if (EndsWith(lower, suffix)) {
        name.resize(name.size() - std::string(suffix).size());
        break;
      }
    }
    return name;
  }

  EdTextureLibrary::~EdTextureLibrary()
  {
    for (const auto& [path, image] : mThumbnails) {
      if (image != 0U) {
        EdImGuiRenderer::DestroyImage(image);
      }
    }
  }

  const std::vector<LayerTexture>& EdTextureLibrary::Textures()
  {
    if (mListed) {
      return mTextures;
    }
    mListed = true;
    mTextures.clear();
    moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
    if (vfs == nullptr) {
      return mTextures;
    }
    // By type: the file system's wildcard never matches a pattern ending in '*'.
    fa::vector<fa::string> found;
    vfs->EnumerateFiles("/env", "*.dds", true, &found);
    std::set<std::string> all;
    for (const fa::string& file : found) {
      all.insert(file.c_str());
    }
    std::set<std::string> lowerAll;
    for (const std::string& path : all) {
      lowerAll.insert(Lower(path));
    }
    for (const std::string& path : all) {
      const std::string lower = Lower(path);
      if (lower.find("/layers/") == std::string::npos || EndsWith(lower, "_normals.dds") || EndsWith(lower, "_normal.dds")) {
        continue;
      }
      LayerTexture texture;
      texture.path = path;
      // The biome: the folder after /env/.
      const std::size_t start = lower.find("/env/");
      if (start != std::string::npos) {
        const std::size_t end = lower.find('/', start + 5);
        texture.biome = path.substr(start + 5, end == std::string::npos ? std::string::npos : end - start - 5);
      }
      texture.name = LayerTextureName(path);
      // Its normal map: the albedo's name with _normals, when the data has it.
      if (EndsWith(lower, "_albedo.dds")) {
        const std::string base = path.substr(0, path.size() - std::string("_albedo.dds").size());
        for (const char* const suffix : {"_normals.dds", "_normal.dds"}) {
          if (lowerAll.count(Lower(base + suffix)) != 0) {
            texture.normals = base + suffix;
            break;
          }
        }
      }
      mTextures.push_back(std::move(texture));
    }
    std::sort(mTextures.begin(), mTextures.end(), [](const LayerTexture& a, const LayerTexture& b) {
      return Lower(a.biome) != Lower(b.biome) ? Lower(a.biome) < Lower(b.biome) : Lower(a.name) < Lower(b.name);
    });
    return mTextures;
  }

  std::uint64_t EdTextureLibrary::Thumbnail(const std::string& path, const bool withAlpha)
  {
    if (path.empty()) {
      return 0U;
    }
    const auto found = mThumbnails.find(path);
    if (found != mThumbnails.end()) {
      return found->second;
    }
    mThumbnails.emplace(path, 0U);
    mWanted.push_back(path);
    if (withAlpha) {
      mWithAlpha.insert(path);
    }
    return 0U;
  }

  void EdTextureLibrary::Pump(const int count)
  {
    gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
    for (int i = 0; i < count && !mWanted.empty() && codec != nullptr; ++i) {
      const std::string path = mWanted.front();
      mWanted.pop_front();
      std::string bytes;
      if (!ReadGameFile(path, bytes)) {
        continue;
      }
      // Decoded straight to a small 32-bit image (the decoder resizes and converts).
      gpg::gal::imaging::DecodeOptions options;
      options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      options.width = kThumbnail;
      options.height = kThumbnail;
      options.mipLevels = 1;
      gpg::gal::imaging::Image image;
      if (FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
          image.format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        continue;
      }
      const auto& level = image.subresources.front();
      const std::uint32_t opaque = mWithAlpha.count(path) != 0 ? 0u : 0xFF000000u;
      std::vector<std::uint32_t> pixels(static_cast<std::size_t>(level.width) * level.height);
      for (std::uint32_t y = 0; y < level.height; ++y) {
        const std::uint8_t* const row = image.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch;
        for (std::uint32_t x = 0; x < level.width; ++x) {
          std::uint32_t pixel = 0;
          std::memcpy(&pixel, row + static_cast<std::size_t>(x) * 4U, 4U);
          // Opaque: a layer's alpha is its specular or the upper layer's blend, not its shape.
          pixels[static_cast<std::size_t>(y) * level.width + x] = pixel | opaque;
        }
      }
      mThumbnails[path] = EdImGuiRenderer::CreateImage(static_cast<int>(level.width), static_cast<int>(level.height), pixels.data());
    }
  }
} // namespace faf::editor
