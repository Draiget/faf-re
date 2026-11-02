#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

// Engine addition, server mode (plan WP11.2, WPL.4): the strategic underlay each entity shows,
// by file path. The sim holds the underlay as a texture, which only a client can load (without
// one the texture is null: CD3DBatchTexture.h sBatchTextureFromFile), so the path is recorded
// where the sim sets it and the frame builder sends that.

namespace faf::remote
{
  /** `Entity::SetStrategicUnderlay`: the entity's underlay is now `path` (empty: none). */
  void SetUnderlayPath(std::uint32_t entityId, const std::string& path);
  /** A recon blip takes its unit's underlay. */
  void CopyUnderlayPath(std::uint32_t fromEntityId, std::uint32_t toEntityId);
  /** The entity is gone. */
  void ForgetUnderlayPath(std::uint32_t entityId);
  /**
   * One reader's copy of the paths (plan WPR.35): every entity update of every view asks for its
   * entity's underlay and hardly any entity has one, so the readers on the sim's workers must not
   * share a lock. `Refresh` takes the lock only when the paths changed since its last call.
   */
  class CUnderlayPathReader
  {
  public:
    void Refresh();
    /** The entity's underlay path as of the last `Refresh`, or null. */
    [[nodiscard]] const std::string* Find(const std::uint32_t entityId) const
    {
      if (mPaths.empty()) {
        return nullptr;
      }
      const auto it = mPaths.find(entityId);
      return it != mPaths.end() ? &it->second : nullptr;
    }

  private:
    std::uint64_t mVersion = 0;
    std::unordered_map<std::uint32_t, std::string> mPaths;
  };
} // namespace faf::remote
