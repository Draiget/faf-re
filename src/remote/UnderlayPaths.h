#pragma once

#include <cstdint>
#include <string>

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
  /** The entity's underlay path, or empty. */
  [[nodiscard]] std::string UnderlayPath(std::uint32_t entityId);
} // namespace faf::remote
