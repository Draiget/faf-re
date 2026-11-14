#include "editor/view/EdPropThumbnails.h"

#include "editor/tools/EdAssetCatalog.h"
#include "editor/ui/EdImGuiRenderer.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/mesh/MeshThumbnailRenderer.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

#include <cstring>
#include <fstream>
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

namespace faf::editor
{
  namespace
  {
    /** The sheet's side in pixels, and its format as the game's model controls make theirs (CMauiMesh, `push 2`). */
    constexpr int kSide = 128;
    constexpr int kSheetFormat = 2;
  } // namespace

  std::uint64_t EdPropThumbnails::Get(
    const std::string& blueprintPath
  )
  {
    auto found = mEntries.find(blueprintPath);
    if (found == mEntries.end() && !mCacheFolder.empty()) {
      // Drawn in an earlier run: the picture from the cache.
      int width = 0;
      int height = 0;
      std::vector<std::uint32_t> pixels;
      if (ReadThumbFile(ThumbCacheFile(mCacheFolder, blueprintPath), width, height, pixels)) {
        Entry& entry = mEntries[blueprintPath];
        entry.image = EdImGuiRenderer::CreateImage(width, height, pixels.data());
        entry.kept = true;
        ++mCacheHits;
        return entry.image;
      }
    }
    if (found == mEntries.end()) {
      if (std::find(mWanted.begin(), mWanted.end(), blueprintPath) == mWanted.end()) {
        mWanted.push_back(blueprintPath);
      }
      return 0U;
    }
    if (found->second.image != 0U) {
      return found->second.image;
    }
    if (found->second.failed || !found->second.sheet) {
      return 0U;
    }
    moho::ID3DTextureSheet::TextureHandle texture;
    (void)found->second.sheet->GetTexture(texture);
    // The texture lives as long as the sheet, which this keeps.
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(texture.get()));
  }

  bool EdPropThumbnails::Save(
    const std::string& name,
    const std::string& file,
    std::string& blueprint
  )
  {
    for (auto& [path, entry] : mEntries) {
      if (path.find(name) == std::string::npos || entry.failed || !entry.sheet) {
        continue;
      }
      std::uint32_t pitch = 0;
      void* bits = nullptr;
      if (!entry.sheet->Lock(&pitch, &bits)) {
        return false;
      }
      // A bottom-up 32-bit BMP: the sheet's rows from the last.
      std::vector<std::uint8_t> out(54 + static_cast<std::size_t>(kSide) * kSide * 4, 0);
      const auto put32 = [&](const std::size_t at, const std::uint32_t value) {
        std::memcpy(out.data() + at, &value, 4);
      };
      out[0] = 'B';
      out[1] = 'M';
      put32(2, static_cast<std::uint32_t>(out.size()));
      put32(10, 54);
      put32(14, 40);
      put32(18, kSide);
      put32(22, kSide);
      out[26] = 1;
      out[28] = 32;
      for (int y = 0; y < kSide; ++y) {
        std::memcpy(
          out.data() + 54 + static_cast<std::size_t>(kSide - 1 - y) * kSide * 4,
          static_cast<const std::uint8_t*>(bits) + static_cast<std::size_t>(y) * pitch,
          static_cast<std::size_t>(kSide) * 4
        );
      }
      (void)entry.sheet->Unlock();
      std::ofstream stream(file, std::ios::binary | std::ios::trunc);
      stream.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
      blueprint = path;
      return static_cast<bool>(stream);
    }
    return false;
  }

  void EdPropThumbnails::Pump(
    int count
  )
  {
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (rules == nullptr || device == nullptr || device->GetResources() == nullptr) {
      return;
    }
    // Pictures the view has drawn by now (a few pumps after asking) go into the cache, a few a pump.
    if (!mCacheFolder.empty()) {
      int writes = 4;
      for (auto& [path, entry] : mEntries) {
        if (writes == 0) {
          break;
        }
        if (entry.kept || entry.failed || !entry.sheet || ++entry.age < 4) {
          continue;
        }
        entry.kept = true;
        --writes;
        std::uint32_t pitch = 0;
        void* bits = nullptr;
        if (!entry.sheet->Lock(&pitch, &bits)) {
          continue;
        }
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide);
        bool drawn = false;
        for (int y = 0; y < kSide; ++y) {
          std::memcpy(
            pixels.data() + static_cast<std::size_t>(y) * kSide,
            static_cast<const std::uint8_t*>(bits) + static_cast<std::size_t>(y) * pitch,
            static_cast<std::size_t>(kSide) * 4
          );
        }
        (void)entry.sheet->Unlock();
        for (const std::uint32_t pixel : pixels) {
          drawn = drawn || (pixel >> 24U) != 0U;
        }
        // An empty sheet (not drawn yet, or a model that drew nothing) isn't kept.
        if (drawn && WriteThumbFile(ThumbCacheFile(mCacheFolder, path), kSide, kSide, pixels.data())) {
          ++mCacheWrites;
        } else if (!drawn) {
          entry.kept = false;
          entry.age = entry.age > 40 ? -1000000 : entry.age; // gives up after a while
        }
      }
    }
    while (count > 0 && !mWanted.empty()) {
      const std::string path = mWanted.front();
      mWanted.erase(mWanted.begin());
      if (mEntries.count(path) != 0) {
        continue;
      }
      --count;
      Entry& entry = mEntries[path];
      // The blueprint as a prop's entity finds it, then its mesh.
      moho::RResId id{};
      const fa::string full(path.c_str());
      gpg::STR_CopyFilename(&id.name, &full);
      const moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
      const moho::RMeshBlueprint* const mesh =
        blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
      if (mesh == nullptr) {
        entry.failed = true;
        continue;
      }
      moho::ID3DDeviceResources::DynamicTextureSheetHandle sheet;
      (void)device->GetResources()->NewDynamicTextureSheet(sheet, kSide, kSide, kSheetFormat);
      if (!sheet) {
        entry.failed = true;
        continue;
      }
      // A clear sheet first, as the game's model controls start theirs (CMauiMesh::ClearThumbnailSheet).
      std::uint32_t pitch = 0;
      void* bits = nullptr;
      if (sheet->Lock(&pitch, &bits)) {
        std::memset(bits, 0, static_cast<std::size_t>(sheet->GetTextureSizeInBytes()));
        (void)sheet->Unlock();
      }
      // A three-quarter view: turned 35 degrees about the vertical (w, x, y, z).
      const float half = 0.5f * 35.0f * 3.14159265f / 180.0f;
      const Wm3::Quatf turn(std::cos(half), 0.0f, std::sin(half), 0.0f);
      (void)moho::REN_RequestThumbnail(
        mesh, turn, 0xFFFFFFFFu, Wm3::Vec3f{1.0f, 1.0f, 1.0f}, sheet, gpg::Rect2f{0.0f, 0.0f, 1.0f, 1.0f}
      );
      entry.sheet = std::move(sheet);
    }
  }

  EdPropThumbnails::~EdPropThumbnails()
  {
    Clear();
  }

  void EdPropThumbnails::Clear()
  {
    for (const auto& [path, entry] : mEntries) {
      if (entry.image != 0U) {
        EdImGuiRenderer::DestroyImage(entry.image);
      }
    }
    mEntries.clear();
    mWanted.clear();
  }
} // namespace faf::editor
