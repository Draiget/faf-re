#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x009045E0 (FUN_009045E0)
   *
   * unsigned int,void *
   *
   * What it does:
   * Initializes one D3D10 vertex-format wrapper from caller format/declaration
   * inputs and rebuilds per-stream stride lanes.
   */
  VertexFormatD3D10::VertexFormatD3D10(const std::uint32_t format, ID3D10InputLayout* const vertexDeclaration)
    : vertexDeclaration_(nullptr)
  {
    formatCode_ = 0x17U;
    Initialize(format, vertexDeclaration);
  }

  /**
   * Address: 0x009041E0 (FUN_009041E0)
   * Address: 0x00904260 (FUN_00904260, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the input layout and leaves format code `0x17`, then the
   * `VertexFormat` base destructor frees the stride vector (inlined,
   * 0x00904225).
   */
  VertexFormatD3D10::~VertexFormatD3D10()
  {
    ResetDeclaration();
  }

  /**
   * Address: 0x00904180 (FUN_00904180)
   *
   * What it does:
   * Releases the input layout and restores format code `0x17`.
   */
  void VertexFormatD3D10::ResetDeclaration()
  {
    SafeRelease(vertexDeclaration_);
    formatCode_ = 0x17U;
  }

  /**
   * Address: 0x00904280 (FUN_00904280)
   *
   * What it does:
   * Validates that one retained declaration handle is bound and returns it.
   */
  ID3D10InputLayout* VertexFormatD3D10::ValidateLayoutOrThrow()
  {
    if (vertexDeclaration_ == nullptr) {
      ThrowGalError("VertexFormatD3D10.cpp", 149, "invalid vertex layout");
    }

    return vertexDeclaration_;
  }

  /**
   * Address: 0x00904500 (FUN_00904500)
   *
   * unsigned int,void *
   *
   * What it does:
   * Rebinds declaration state, validates static table ownership for the format
   * token, and rebuilds per-stream stride lanes from recovered element records.
   */
  std::uint32_t VertexFormatD3D10::Initialize(const std::uint32_t format, ID3D10InputLayout* const vertexDeclaration)
  {
    ResetDeclaration();
    vertexDeclaration_ = vertexDeclaration;
    formatCode_ = format;

    const D3D10_INPUT_ELEMENT_DESC* const layoutElements = GetVertexLayoutElementsOrThrow(formatCode_);
    const std::uint32_t layoutElementCount = GetVertexLayoutElementCountOrThrow(formatCode_);

    streamStrides_.clear();

    std::uint32_t result = layoutElementCount;
    for (std::uint32_t index = 0; index < layoutElementCount; ++index) {
      const D3D10_INPUT_ELEMENT_DESC& element = layoutElements[index];
      if (streamStrides_.size() <= element.InputSlot) {
        streamStrides_.resize(element.InputSlot + 1U, 0U);
      }

      std::uint32_t& streamStride = streamStrides_[element.InputSlot];
      const std::uint32_t candidate = element.AlignedByteOffset + GetTextureFormatBlockBytes(element.Format);
      result = (streamStride > candidate) ? streamStride : candidate;
      streamStride = result;
    }

    return result;
  }
}

