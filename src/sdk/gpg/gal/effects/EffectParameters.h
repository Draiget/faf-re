#pragma once

// FAF addition, not in the shipped binary.
//
// The CPU side of an effect's parameters for the backends without an effect
// framework (Direct3D 12, Vulkan): one $Globals image in the layout
// ComputeConstantLayout predicts (and DXC produces), written by the gal
// EffectVariable setters with Direct3D 9 / Effects 11 semantics, plus the
// texture each texture parameter is bound to. A pass snapshots it when it
// begins, as ID3DXEffect::BeginPass and Effects 11's Apply do.

#include <cstdint>
#include <span>
#include <vector>

#include "EffectDescription.h"
#include "ModernHlsl.h"
#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class RenderTarget;
  class Texture;
} // namespace gpg::gal

namespace gpg::gal::effects
{
  /** What one texture parameter is bound to. */
  struct TextureBinding
  {
    boost::shared_ptr<Texture> texture;
    boost::shared_ptr<RenderTarget> renderTarget;

    [[nodiscard]] bool Empty() const noexcept { return texture == nullptr && renderTarget == nullptr; }
  };

  class ParameterStore
  {
  public:
    ParameterStore() = default;

    /** Lays out the image and writes every parameter's default value. */
    void Initialize(const EffectDescription& description, const ConstantLayout& layout);

    /** The $Globals image (a multiple of 16 bytes; empty when the effect has no numeric parameters). */
    [[nodiscard]] std::span<const std::uint8_t> Constants() const noexcept { return mImage; }

    /** Bumped by every write, so a backend can tell an unchanged image. */
    [[nodiscard]] std::uint64_t Version() const noexcept { return mVersion; }
    /** Bumped by every texture binding change only. */
    [[nodiscard]] std::uint64_t TextureVersion() const noexcept { return mTextureVersion; }

    // Setters, by index into EffectDescription::parameters. A parameter the
    // shaders never read (no constant slot) accepts and drops the value.

    /** SetFloatArray, and SetValue on float data: `count` packed floats. */
    void SetFloats(std::uint32_t parameter, const float* values, std::uint32_t count);
    /** SetValue: `bytes` of packed 4-byte components (D3D9's layout), any scalar type. */
    void SetPacked(std::uint32_t parameter, const void* data, std::uint32_t bytes);
    void SetVector(std::uint32_t parameter, const float* vector4);
    void SetVectorArray(std::uint32_t parameter, const float* vectors4, std::uint32_t count);
    /** A row-major 4x4 matrix (D3DXMATRIX), as Effects 11's SetMatrix. */
    void SetMatrix(std::uint32_t parameter, const float* matrix16);
    void SetMatrixArray(std::uint32_t parameter, const float* matrices16, std::uint32_t count);
    /** SetFloat / SetInt / SetBool: converted to the parameter's type; a vector gets it in every component. */
    void SetScalar(std::uint32_t parameter, double value);

    void SetTexture(std::uint32_t parameter, const boost::shared_ptr<Texture>& texture);
    void SetRenderTarget(std::uint32_t parameter, const boost::shared_ptr<RenderTarget>& renderTarget);
    [[nodiscard]] const TextureBinding& Binding(std::uint32_t parameter) const;

  private:
    struct Target
    {
      const ConstantSlot* slot = nullptr;
      const Parameter* parameter = nullptr;
    };

    [[nodiscard]] Target Find(std::uint32_t parameter) const noexcept;
    void WriteComponent(std::uint32_t offset, ScalarType type, std::uint32_t bits, bool fromFloat);
    void WriteMatrix(const Target& target, std::uint32_t element, const float* matrix16);

    const EffectDescription* mDescription = nullptr;
    const ConstantLayout* mLayout = nullptr;
    std::vector<std::int32_t> mSlotByParameter; // -1: no slot
    std::vector<std::uint8_t> mImage;
    std::vector<TextureBinding> mBindings;      // by parameter index
    std::uint64_t mVersion = 1;
    std::uint64_t mTextureVersion = 1;
  };
} // namespace gpg::gal::effects
