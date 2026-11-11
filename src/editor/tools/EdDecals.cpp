#include "editor/tools/EdDecals.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace faf::editor
{
  namespace
  {
    std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
      return text;
    }

    Wm3::Vec3f Vec(const float (&value)[3])
    {
      return Wm3::Vec3f{value[0], value[1], value[2]};
    }

    void Copy(const Wm3::Vec3f& from, float (&to)[3])
    {
      to[0] = from.x;
      to[1] = from.y;
      to[2] = from.z;
    }

    /** Puts a state's fields on a decal, touching the textures only when their names change (setting one loads it). */
    void Apply(moho::CWldTerrainDecal& decal, const DecalState& state)
    {
      decal.mType = static_cast<moho::EWldTerrainDecalType>(state.type);
      for (int slot = 0; slot < 2; ++slot) {
        if (state.names[slot] != decal.mNames[slot].c_str() && !state.names[slot].empty()) {
          decal.SetName(fa::string(state.names[slot].c_str()), slot);
        }
      }
      decal.SetParameters(Vec(state.orientation), Vec(state.position), Vec(state.scale));
      decal.SetCutoffLOD(state.cutoff > 0.0f ? state.cutoff : decal.ComputeCutoffLOD(-1.0f));
      decal.mNearCutoff = state.nearCutoff;
    }
  } // namespace

  bool DecalState::operator==(const DecalState& other) const
  {
    return index == other.index && type == other.type && names[0] == other.names[0] && names[1] == other.names[1] &&
           std::memcmp(scale, other.scale, sizeof(scale)) == 0 && std::memcmp(position, other.position, sizeof(position)) == 0 &&
           std::memcmp(orientation, other.orientation, sizeof(orientation)) == 0 && cutoff == other.cutoff &&
           nearCutoff == other.nearCutoff;
  }

  DecalState CaptureDecal(const moho::CWldTerrainDecal& decal)
  {
    DecalState state;
    state.index = decal.mIndex;
    state.type = static_cast<int>(decal.mType);
    state.names[0] = decal.mNames[0].c_str();
    state.names[1] = decal.mNames[1].c_str();
    Copy(decal.mScale, state.scale);
    Copy(decal.mPosition, state.position);
    Copy(decal.mOrientation, state.orientation);
    state.cutoff = decal.mCutoffLOD;
    state.nearCutoff = decal.mNearCutoff;
    return state;
  }

  std::vector<DecalState> CaptureDecals(moho::IDecalManager& manager)
  {
    std::vector<DecalState> decals;
    const std::int32_t count = manager.GetDecalCount();
    decals.reserve(static_cast<std::size_t>(std::max(count, 0)));
    for (std::int32_t i = 0; i < count; ++i) {
      if (const moho::CWldTerrainDecal* const decal = manager.GetDecal(i); decal != nullptr) {
        decals.push_back(CaptureDecal(*decal));
      }
    }
    return decals;
  }

  moho::CWldTerrainDecal* FindDecal(moho::IDecalManager& manager, const int index)
  {
    const std::int32_t count = manager.GetDecalCount();
    for (std::int32_t i = 0; i < count; ++i) {
      moho::CWldTerrainDecal* const decal = manager.GetDecal(i);
      if (decal != nullptr && decal->mIndex == index) {
        return decal;
      }
    }
    return nullptr;
  }

  void RestoreDecals(moho::IDecalManager& manager, const std::vector<DecalState>& decals)
  {
    std::map<int, moho::CWldTerrainDecal*> current;
    const std::int32_t count = manager.GetDecalCount();
    for (std::int32_t i = 0; i < count; ++i) {
      if (moho::CWldTerrainDecal* const decal = manager.GetDecal(i); decal != nullptr) {
        current[decal->mIndex] = decal;
      }
    }
    std::set<int> wanted;
    for (const DecalState& state : decals) {
      wanted.insert(state.index);
      const auto found = current.find(state.index);
      if (found == current.end()) {
        Apply(*manager.NewDecal(state.index), state);
      } else if (!(CaptureDecal(*found->second) == state)) {
        Apply(*found->second, state);
      }
    }
    for (const auto& [index, decal] : current) {
      if (wanted.count(index) == 0) {
        manager.DestroyDecal(decal);
      }
    }
  }

  std::string DecalKey(const DecalState& state)
  {
    std::string key = state.names[0];
    key.push_back('\0');
    key += state.names[1];
    key.push_back('\0');
    const auto bytes = [&key](const void* const data, const std::size_t size) { key.append(static_cast<const char*>(data), size); };
    bytes(&state.type, sizeof(state.type));
    bytes(state.scale, sizeof(state.scale));
    bytes(state.position, sizeof(state.position));
    bytes(state.orientation, sizeof(state.orientation));
    bytes(&state.cutoff, sizeof(state.cutoff));
    bytes(&state.nearCutoff, sizeof(state.nearCutoff));
    return key;
  }

  DecalMirror MirrorDecals(moho::IDecalManager& live, const std::vector<DecalState>& before, const std::vector<DecalState>& after)
  {
    // How many of each decal (by content) went (> 0) or came (< 0).
    std::unordered_map<std::string, int> change;
    for (const DecalState& state : before) {
      ++change[DecalKey(state)];
    }
    for (const DecalState& state : after) {
      --change[DecalKey(state)];
    }
    DecalMirror result;
    std::unordered_map<std::string, std::vector<moho::CWldTerrainDecal*>> liveByKey;
    bool liveRead = false;
    for (const auto& [key, count] : change) {
      if (count <= 0) {
        continue;
      }
      if (!liveRead) {
        liveRead = true;
        const std::int32_t total = live.GetDecalCount();
        for (std::int32_t i = 0; i < total; ++i) {
          if (moho::CWldTerrainDecal* const decal = live.GetDecal(i); decal != nullptr) {
            liveByKey[DecalKey(CaptureDecal(*decal))].push_back(decal);
          }
        }
      }
      std::vector<moho::CWldTerrainDecal*>& found = liveByKey[key];
      for (int n = 0; n < count; ++n) {
        if (found.empty()) {
          ++result.missing; // not in the play (it differed from the map before the edit)
          continue;
        }
        live.DestroyDecal(found.back());
        found.pop_back();
        ++result.removed;
      }
    }
    for (const DecalState& state : after) {
      int& count = change[DecalKey(state)];
      if (count < 0 && AddDecal(live, state) != nullptr) {
        ++count;
        ++result.added;
      }
    }
    return result;
  }

  moho::CWldTerrainDecal* AddDecal(moho::IDecalManager& manager, const DecalState& state)
  {
    moho::CWldTerrainDecal* const decal = manager.LoadDecal(nullptr);
    if (decal != nullptr) {
      Apply(*decal, state);
    }
    return decal;
  }

  DecalFootprint FootprintOf(const moho::CWldTerrainDecal& decal)
  {
    DecalFootprint footprint;
    footprint.x = decal.mPosition.x;
    footprint.z = decal.mPosition.z;
    footprint.sizeX = decal.mScale.x;
    footprint.sizeZ = decal.mScale.z;
    footprint.yaw = decal.mOrientation.y;
    return footprint;
  }

  std::vector<DecalTexture> ListDecalTextures()
  {
    std::vector<DecalTexture> textures;
    moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
    if (vfs == nullptr) {
      return textures;
    }
    fa::vector<fa::string> found;
    vfs->EnumerateFiles("/env", "*.dds", true, &found);
    std::set<std::string> seen;
    for (const fa::string& file : found) {
      const std::string path = file.c_str();
      const std::string lower = Lower(path);
      if (lower.find("/decals/") == std::string::npos || !seen.insert(lower).second) {
        continue;
      }
      DecalTexture texture;
      texture.path = path;
      const std::size_t start = lower.find("/env/");
      if (start != std::string::npos) {
        const std::size_t end = lower.find('/', start + 5);
        texture.biome = path.substr(start + 5, end == std::string::npos ? std::string::npos : end - start - 5);
      }
      const std::size_t slash = path.find_last_of('/');
      texture.name = path.substr(slash + 1, path.size() - slash - 1 - 4);
      texture.type = DecalTypeForTexture(path);
      textures.push_back(std::move(texture));
    }
    // An albedo's spec map: the same name with _spec.
    std::map<std::string, std::string> byLower;
    for (const DecalTexture& texture : textures) {
      byLower[Lower(texture.path)] = texture.path;
    }
    for (DecalTexture& texture : textures) {
      const std::string lower = Lower(texture.path);
      const std::string from = "_albedo.dds";
      if (lower.size() > from.size() && lower.compare(lower.size() - from.size(), from.size(), from) == 0) {
        const auto partner = byLower.find(lower.substr(0, lower.size() - from.size()) + "_spec.dds");
        if (partner != byLower.end()) {
          texture.pair = partner->second;
        }
      }
    }
    std::sort(textures.begin(), textures.end(), [](const DecalTexture& a, const DecalTexture& b) {
      return Lower(a.biome) != Lower(b.biome) ? Lower(a.biome) < Lower(b.biome) : Lower(a.name) < Lower(b.name);
    });
    return textures;
  }
} // namespace faf::editor
