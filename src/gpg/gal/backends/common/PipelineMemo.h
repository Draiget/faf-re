#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace gpg::gal
{
  /**
   * Engine addition: `ren_PipelineMemo` (moho). Finding a draw's pipeline meant building a string key field by field,
   * which allocates, and hashing it. A draw repeats a pipeline used moments ago, so a small table answers first.
   */
  inline bool gPipelineMemo = true;

  /**
   * Engine addition: `ren_UsedTextureTable` (moho). Direct3D 12 / Vulkan rebuilt an effect pass's texture table (64
   * descriptors) whenever any texture binding of the effect changed. The mesh depth pass binds each material's albedo
   * though its `Depth` technique reads none, so it rebuilt the table for every bucket. With this, a change only in
   * slots the pass's compiled shaders don't read (`effects::CompiledEntry::textureSlots`) keeps the table.
   */
  inline bool gUsedTextureTable = true;

  /**
   * Engine addition: `ren_VulkanDynamicConstants` (moho). Vulkan allocated and wrote a descriptor set for every
   * $Globals snapshot, which a skinned mesh draw takes each time (its bone palettes). With this, set 1 is a dynamic
   * uniform buffer: one set per upload buffer and frame, and a draw binds it with its snapshot's offset. Changes
   * between frames.
   */
  inline bool gVulkanDynamicConstants = true;

  /**
   * A table of recent pipelines by the raw bytes of everything a pipeline depends on. `Inputs` is cleared with memset
   * before it is filled. An entry that gets overwritten is only found the slow way next time, and a pipeline
   * is never returned unless all its inputs match.
   */
  template <class Inputs, class Pipeline>
  class PipelineMemo
  {
  public:
    [[nodiscard]] Pipeline Find(const Inputs& inputs) const noexcept
    {
      const Entry& entry = mEntries[Slot(inputs)];
      if (entry.pipeline != Pipeline{} && std::memcmp(&entry.inputs, &inputs, sizeof(Inputs)) == 0) {
        return entry.pipeline;
      }
      return Pipeline{};
    }

    void Store(const Inputs& inputs, const Pipeline pipeline) noexcept
    {
      Entry& entry = mEntries[Slot(inputs)];
      std::memcpy(static_cast<void*>(&entry.inputs), &inputs, sizeof(Inputs));
      entry.pipeline = pipeline;
    }

    /** Required whenever the pipelines themselves are released. */
    void Clear() noexcept
    {
      for (Entry& entry : mEntries) {
        entry.pipeline = Pipeline{};
      }
    }

  private:
    struct Entry
    {
      Inputs inputs;
      Pipeline pipeline{};
    };

    [[nodiscard]] static std::size_t Slot(const Inputs& inputs) noexcept
    {
      const auto* const bytes = reinterpret_cast<const unsigned char*>(&inputs);
      std::uint64_t hash = 0U;
      for (std::size_t offset = 0U; offset + sizeof(std::uint64_t) <= sizeof(Inputs); offset += sizeof(std::uint64_t)) {
        std::uint64_t word;
        std::memcpy(&word, bytes + offset, sizeof(word));
        hash = (hash ^ word) * 0x9E3779B97F4A7C15ULL;
      }
      return static_cast<std::size_t>(hash >> 58U);
    }

    std::array<Entry, 64> mEntries{};
  };
} // namespace gpg::gal
