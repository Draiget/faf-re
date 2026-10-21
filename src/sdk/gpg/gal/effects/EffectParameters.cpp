// FAF addition, not in the shipped binary: see EffectParameters.h.

#include "EffectParameters.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/Texture.hpp"

namespace gpg::gal::effects
{
  namespace
  {
    [[nodiscard]] std::uint32_t FloatBits(const float value) noexcept
    {
      std::uint32_t bits = 0U;
      std::memcpy(&bits, &value, sizeof(bits));
      return bits;
    }

    [[nodiscard]] float BitsFloat(const std::uint32_t bits) noexcept
    {
      float value = 0.0f;
      std::memcpy(&value, &bits, sizeof(value));
      return value;
    }

    const TextureBinding kNoBinding{};
  } // namespace

  void ParameterStore::Initialize(const EffectDescription& description, const ConstantLayout& layout)
  {
    mDescription = &description;
    mLayout = &layout;
    mSlotByParameter.assign(description.parameters.size(), -1);
    for (std::size_t index = 0U; index < layout.slots.size(); ++index) {
      mSlotByParameter[layout.slots[index].parameter] = static_cast<std::int32_t>(index);
    }
    mImage.assign((layout.size + 15U) / 16U * 16U, 0U);
    mBindings.assign(description.parameters.size(), TextureBinding{});

    // Defaults: initializers are written in declaration order, element by
    // element, row by row, as the D3D9 effect framework reads them.
    for (std::uint32_t index = 0U; index < description.parameters.size(); ++index) {
      const Parameter& parameter = description.parameters[index];
      if (parameter.defaults.empty() || mSlotByParameter[index] < 0) {
        continue;
      }
      if (parameter.parameterClass == ParameterClass::Struct) {
        std::vector<std::uint32_t> words;
        for (const float value : parameter.defaults) {
          words.push_back(FloatBits(value));
        }
        SetPacked(index, words.data(), static_cast<std::uint32_t>(words.size() * 4U));
      } else {
        SetFloats(index, parameter.defaults.data(), static_cast<std::uint32_t>(parameter.defaults.size()));
      }
    }
    mVersion = 1U;
  }

  ParameterStore::Target ParameterStore::Find(const std::uint32_t parameter) const noexcept
  {
    Target target;
    if (mDescription == nullptr || parameter >= mSlotByParameter.size()) {
      return target;
    }
    target.parameter = &mDescription->parameters[parameter];
    const std::int32_t slot = mSlotByParameter[parameter];
    if (slot >= 0) {
      target.slot = &mLayout->slots[static_cast<std::size_t>(slot)];
    }
    return target;
  }

  void ParameterStore::WriteComponent(const std::uint32_t offset, const ScalarType type, const std::uint32_t bits, const bool fromFloat)
  {
    if (offset + 4U > mImage.size()) {
      return;
    }
    std::uint32_t stored = bits;
    if (fromFloat) {
      const float value = BitsFloat(bits);
      switch (type) {
      case ScalarType::Int:
        stored = static_cast<std::uint32_t>(static_cast<std::int32_t>(value));
        break;
      case ScalarType::Uint:
        stored = static_cast<std::uint32_t>(std::max(0.0f, value));
        break;
      case ScalarType::Bool:
        stored = (value != 0.0f) ? 1U : 0U;
        break;
      case ScalarType::Float:
        break;
      }
    }
    std::memcpy(mImage.data() + offset, &stored, sizeof(stored));
  }

  void ParameterStore::WriteMatrix(const Target& target, const std::uint32_t element, const float* const matrix16)
  {
    const Parameter& parameter = *target.parameter;
    const std::uint32_t base = target.slot->offset + element * target.slot->elementStride;
    for (std::uint32_t row = 0U; row < parameter.rows && row < 4U; ++row) {
      for (std::uint32_t column = 0U; column < parameter.columns && column < 4U; ++column) {
        const std::uint32_t offset = parameter.columnMajor ? base + column * 16U + row * 4U : base + row * 16U + column * 4U;
        WriteComponent(offset, parameter.scalarType, FloatBits(matrix16[row * 4U + column]), true);
      }
    }
  }

  void ParameterStore::SetFloats(const std::uint32_t parameter, const float* const values, const std::uint32_t count)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || values == nullptr) {
      return;
    }
    const Parameter& description = *target.parameter;
    const std::uint32_t elements = std::max<std::uint32_t>(description.elements, 1U);
    switch (description.parameterClass) {
    case ParameterClass::Scalar:
      for (std::uint32_t element = 0U; element < std::min(count, elements); ++element) {
        WriteComponent(target.slot->offset + element * 16U, description.scalarType, FloatBits(values[element]), true);
      }
      break;

    case ParameterClass::Vector: {
      // `columns` floats per element, as D3D9's SetFloatArray.
      const std::uint32_t columns = std::max<std::uint32_t>(description.columns, 1U);
      for (std::uint32_t index = 0U; index < count && index / columns < elements; ++index) {
        WriteComponent(
          target.slot->offset + (index / columns) * 16U + (index % columns) * 4U, description.scalarType, FloatBits(values[index]), true
        );
      }
      break;
    }

    case ParameterClass::Matrix: {
      const std::uint32_t matrices = std::min(count / 16U, elements);
      if (matrices != 0U && count % 16U == 0U) {
        for (std::uint32_t element = 0U; element < matrices; ++element) {
          WriteMatrix(target, element, values + element * 16U);
        }
        break;
      }
      // Packed rows x columns, as SetValue hands them over.
      SetPacked(parameter, values, count * 4U);
      return;
    }

    default:
      SetPacked(parameter, values, count * 4U);
      return;
    }
    ++mVersion;
  }

  void ParameterStore::SetPacked(const std::uint32_t parameter, const void* const data, const std::uint32_t bytes)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || data == nullptr) {
      return;
    }
    const Parameter& description = *target.parameter;
    const auto* const words = static_cast<const std::uint32_t*>(data);
    const std::uint32_t wordCount = bytes / 4U;
    const std::uint32_t elements = std::max<std::uint32_t>(description.elements, 1U);
    std::uint32_t next = 0U;

    if (description.parameterClass == ParameterClass::Struct) {
      for (std::uint32_t element = 0U; element < elements && next < wordCount; ++element) {
        const std::uint32_t base = target.slot->offset + element * target.slot->elementStride;
        for (const ConstantMember& member : target.slot->members) {
          const std::uint32_t registers = (member.parameterClass == ParameterClass::Matrix) ? member.rows : 1U;
          const std::uint32_t perRegister = member.columns;
          for (std::uint32_t memberElement = 0U; memberElement < member.elements; ++memberElement) {
            for (std::uint32_t row = 0U; row < registers; ++row) {
              for (std::uint32_t column = 0U; column < perRegister && next < wordCount; ++column) {
                WriteComponent(
                  base + member.offset + memberElement * member.elementStride + row * 16U + column * 4U, member.scalarType, words[next++],
                  false
                );
              }
            }
          }
        }
      }
      ++mVersion;
      return;
    }

    if (description.parameterClass != ParameterClass::Scalar && description.parameterClass != ParameterClass::Vector &&
        description.parameterClass != ParameterClass::Matrix) {
      return;
    }
    const bool matrix = description.parameterClass == ParameterClass::Matrix;
    const std::uint32_t registers = matrix ? (description.columnMajor ? description.columns : description.rows) : 1U;
    const std::uint32_t perRegister = matrix ? (description.columnMajor ? description.rows : description.columns) : description.columns;
    for (std::uint32_t element = 0U; element < elements && next < wordCount; ++element) {
      const std::uint32_t base = target.slot->offset + element * target.slot->elementStride;
      if (matrix && description.columnMajor) {
        // Packed input is row by row; the image holds columns.
        for (std::uint32_t row = 0U; row < description.rows; ++row) {
          for (std::uint32_t column = 0U; column < description.columns && next < wordCount; ++column) {
            WriteComponent(base + column * 16U + row * 4U, description.scalarType, words[next++], false);
          }
        }
        continue;
      }
      for (std::uint32_t row = 0U; row < registers; ++row) {
        for (std::uint32_t column = 0U; column < perRegister && next < wordCount; ++column) {
          WriteComponent(base + row * 16U + column * 4U, description.scalarType, words[next++], false);
        }
      }
    }
    ++mVersion;
  }

  void ParameterStore::SetVector(const std::uint32_t parameter, const float* const vector4)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || vector4 == nullptr) {
      return;
    }
    const Parameter& description = *target.parameter;
    const std::uint32_t components =
      (description.parameterClass == ParameterClass::Vector) ? std::min<std::uint32_t>(description.columns, 4U)
      : (description.parameterClass == ParameterClass::Scalar) ? 1U
                                                               : 4U;
    for (std::uint32_t column = 0U; column < components; ++column) {
      WriteComponent(target.slot->offset + column * 4U, description.scalarType, FloatBits(vector4[column]), true);
    }
    ++mVersion;
  }

  void ParameterStore::SetVectorArray(const std::uint32_t parameter, const float* const vectors4, const std::uint32_t count)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || vectors4 == nullptr) {
      return;
    }
    const Parameter& description = *target.parameter;
    const std::uint32_t elements = std::max<std::uint32_t>(description.elements, 1U);
    const std::uint32_t components = std::min<std::uint32_t>(std::max<std::uint32_t>(description.columns, 1U), 4U);
    for (std::uint32_t element = 0U; element < std::min(count, elements); ++element) {
      for (std::uint32_t column = 0U; column < components; ++column) {
        WriteComponent(
          target.slot->offset + element * target.slot->elementStride + column * 4U, description.scalarType,
          FloatBits(vectors4[element * 4U + column]), true
        );
      }
    }
    ++mVersion;
  }

  void ParameterStore::SetMatrix(const std::uint32_t parameter, const float* const matrix16)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || matrix16 == nullptr) {
      return;
    }
    if (target.parameter->parameterClass == ParameterClass::Matrix) {
      WriteMatrix(target, 0U, matrix16);
      ++mVersion;
      return;
    }
    SetFloats(parameter, matrix16, 16U);
  }

  void ParameterStore::SetMatrixArray(const std::uint32_t parameter, const float* const matrices16, const std::uint32_t count)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr || matrices16 == nullptr || target.parameter->parameterClass != ParameterClass::Matrix) {
      return;
    }
    const std::uint32_t elements = std::max<std::uint32_t>(target.parameter->elements, 1U);
    for (std::uint32_t element = 0U; element < std::min(count, elements); ++element) {
      WriteMatrix(target, element, matrices16 + element * 16U);
    }
    ++mVersion;
  }

  void ParameterStore::SetScalar(const std::uint32_t parameter, const double value)
  {
    const Target target = Find(parameter);
    if (target.slot == nullptr) {
      return;
    }
    const Parameter& description = *target.parameter;
    const std::uint32_t bits = FloatBits(static_cast<float>(value));
    if (description.parameterClass == ParameterClass::Vector) {
      for (std::uint32_t column = 0U; column < std::min<std::uint32_t>(description.columns, 4U); ++column) {
        WriteComponent(target.slot->offset + column * 4U, description.scalarType, bits, true);
      }
    } else if (description.parameterClass == ParameterClass::Scalar) {
      WriteComponent(target.slot->offset, description.scalarType, bits, true);
    } else {
      return;
    }
    ++mVersion;
  }

  void ParameterStore::SetTexture(const std::uint32_t parameter, const boost::shared_ptr<Texture>& texture)
  {
    if (parameter >= mBindings.size()) {
      return;
    }
    mBindings[parameter].texture = texture;
    mBindings[parameter].renderTarget.reset();
    ++mVersion;
    ++mTextureVersion;
  }

  void ParameterStore::SetRenderTarget(const std::uint32_t parameter, const boost::shared_ptr<RenderTarget>& renderTarget)
  {
    if (parameter >= mBindings.size()) {
      return;
    }
    mBindings[parameter].renderTarget = renderTarget;
    mBindings[parameter].texture.reset();
    ++mVersion;
    ++mTextureVersion;
  }

  const TextureBinding& ParameterStore::Binding(const std::uint32_t parameter) const
  {
    return (parameter < mBindings.size()) ? mBindings[parameter] : kNoBinding;
  }
} // namespace gpg::gal::effects
