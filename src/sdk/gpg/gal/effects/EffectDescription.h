#pragma once

// FAF addition, not in the shipped binary.
//
// The engine-side description of an effect: what Direct3D 9's and 10's effect
// frameworks (and Effects 11) did for the gal backends, for the APIs that have
// no effect framework - Direct3D 12 and Vulkan. It is built from the effect
// source after the D3D11 override layer has rewritten it into the D3D10
// dialect (d3d11::TranslateEffectSource), so every pass already carries
// explicit blend / depth-stencil / rasterizer state objects:
//
//   - parameters (numeric globals with their defaults and annotations,
//     textures), which the gal EffectVariable writes;
//   - sampler states and the texture each one reads;
//   - techniques and passes: annotations, state objects, and the vertex and
//     pixel shader each pass compiles, with its compile-time arguments.
//
// The shader functions themselves become plain HLSL (ModernHlsl.h), compiled
// once per backend through DXC.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gpg::gal::effects
{
  /** One annotation (`< string name = "value"; int n = 3; >`). */
  struct Annotation
  {
    enum class Kind : std::uint8_t
    {
      String,
      Int,
      Float,
      Bool,
    };

    std::string name;
    Kind kind = Kind::String;
    std::string text;   // String
    double number = 0.0; // Int, Float, Bool (0 / 1)
  };

  using Annotations = std::vector<Annotation>;

  [[nodiscard]] const Annotation* FindAnnotation(const Annotations& annotations, std::string_view name) noexcept;

  enum class ParameterClass : std::uint8_t
  {
    Scalar,
    Vector,
    Matrix,
    Struct,
    Texture,
    Other, // strings and anything the shaders cannot read
  };

  enum class ScalarType : std::uint8_t
  {
    Float,
    Int,
    Bool,
    Uint,
  };

  /** One effect parameter: a non-static global of the effect source. */
  struct Parameter
  {
    std::string name;
    std::string typeName;
    ParameterClass parameterClass = ParameterClass::Other;
    ScalarType scalarType = ScalarType::Float;
    std::uint32_t rows = 1;       // matrices: rows; vectors and scalars: 1
    std::uint32_t columns = 1;    // vectors: components
    std::uint32_t elements = 0;   // array size; 0 for a single value
    std::vector<float> defaults;  // packed row by row, element by element; empty for zero
    bool columnMajor = false;     // declared `column_major`
    bool unsized = false;         // `float k[] = {...}`: `elements` counts the initializer
    Annotations annotations;
    std::size_t begin = 0;        // the declaration's span in the parsed source
    std::size_t end = 0;
  };

  /** A member of a struct type (struct-typed parameters, such as sky.fx's aCirrus). */
  struct StructMember
  {
    std::string name;
    std::string typeName;
    ParameterClass parameterClass = ParameterClass::Other;
    ScalarType scalarType = ScalarType::Float;
    std::uint32_t rows = 1;
    std::uint32_t columns = 1;
    std::uint32_t elements = 0;
  };

  struct StructType
  {
    std::string name;
    std::string aliasOf; // a typedef of this struct: the struct's own name
    std::vector<StructMember> members;
  };

  // State values use the Direct3D 11 / 12 enumerator values (they are the
  // same in both); Vulkan translates them.
  struct BlendDesc
  {
    bool alphaToCoverage = false;
    bool enable = false;
    std::uint8_t srcBlend = 2;      // ONE
    std::uint8_t destBlend = 1;     // ZERO
    std::uint8_t blendOp = 1;       // ADD
    std::uint8_t srcBlendAlpha = 2;
    std::uint8_t destBlendAlpha = 1;
    std::uint8_t blendOpAlpha = 1;
    std::uint8_t writeMask = 0x0F;
  };

  struct StencilFaceDesc
  {
    std::uint8_t failOp = 1;      // KEEP
    std::uint8_t depthFailOp = 1; // KEEP
    std::uint8_t passOp = 1;      // KEEP
    std::uint8_t func = 8;        // ALWAYS
  };

  struct DepthStencilDesc
  {
    bool depthEnable = true;
    bool depthWrite = true;
    std::uint8_t depthFunc = 4; // LESS_EQUAL (the technique default pack)
    bool stencilEnable = false;
    std::uint8_t stencilReadMask = 0xFF;
    std::uint8_t stencilWriteMask = 0xFF;
    StencilFaceDesc front;
    StencilFaceDesc back;

    /** Every field packed into 56 bits (ops and funcs are 1..10 in D3D's numbering): a cache key. */
    [[nodiscard]] std::uint64_t PackedKey() const noexcept
    {
      const auto face = [](const StencilFaceDesc& desc) {
        return static_cast<std::uint64_t>(desc.failOp & 0x0FU) | (static_cast<std::uint64_t>(desc.depthFailOp & 0x0FU) << 4U) |
               (static_cast<std::uint64_t>(desc.passOp & 0x0FU) << 8U) | (static_cast<std::uint64_t>(desc.func & 0x0FU) << 12U);
      };
      return static_cast<std::uint64_t>(depthEnable ? 1U : 0U) | (static_cast<std::uint64_t>(depthWrite ? 1U : 0U) << 1U) |
             (static_cast<std::uint64_t>(depthFunc & 0x0FU) << 2U) | (static_cast<std::uint64_t>(stencilEnable ? 1U : 0U) << 6U) |
             (static_cast<std::uint64_t>(stencilReadMask) << 8U) | (static_cast<std::uint64_t>(stencilWriteMask) << 16U) |
             (face(front) << 24U) | (face(back) << 40U);
    }
  };

  struct RasterizerDesc
  {
    std::uint8_t fillMode = 3; // SOLID
    std::uint8_t cullMode = 3; // BACK
    bool frontCounterClockwise = false;
    std::int32_t depthBias = 0;
    float depthBiasClamp = 0.0f;
    float slopeScaledDepthBias = 0.0f;
    bool depthClipEnable = false;
    bool scissorEnable = false;
    bool multisampleEnable = true;
    bool antialiasedLineEnable = false;
  };

  /** One sampler state and the texture parameter it reads. */
  struct SamplerDesc
  {
    enum class Kind : std::uint8_t
    {
      Texture2D,
      TextureCube,
      Texture3D,
    };

    std::string name;
    std::string declaredType; // sampler, sampler2D, samplerCUBE, ...
    std::string texture;      // the parameter named by `Texture = <...>`
    Kind kind = Kind::Texture2D;
    // Fields a sampler_state leaves out take the Direct3D 10/11 defaults, as
    // the effect frameworks of those APIs (and so the D3D11 backend) give them.
    std::uint32_t filter = 0x15;  // MIN_MAG_MIP_LINEAR
    std::uint8_t addressU = 3;    // CLAMP
    std::uint8_t addressV = 3;
    std::uint8_t addressW = 3;
    std::uint32_t maxAnisotropy = 16;
    float mipLodBias = 0.0f;
    float borderColor[4]{};
    float minLod = -3.402823466e+38f;
    float maxLod = 3.402823466e+38f;
    std::size_t begin = 0; // the declaration's span in the parsed source
    std::size_t end = 0;
  };

  /**
   * Direct3D 9's alpha test as a pass sets it (D3DRS_ALPHAFUNC, D3DRS_ALPHAREF).
   * Direct3D 10 and later have none; ModernHlsl emulates it in the pixel shader.
   */
  struct AlphaTestDesc
  {
    std::uint8_t func = 8; // D3DCMPFUNC: 1 NEVER ... 8 ALWAYS
    std::uint8_t ref = 0;  // compared with the colour's alpha in 8-bit units
  };

  /** `VertexShader = compile vs_4_1 Function( arguments )`. */
  struct ShaderReference
  {
    std::string function;
    std::string arguments; // the compile-time (uniform) argument list, as written
    std::string entry;     // the entry point ModernHlsl generated for it
  };

  struct Pass
  {
    std::string name;
    Annotations annotations;
    std::optional<BlendDesc> blend; // absent: the pass leaves blending as the technique pack sets it
    float blendFactor[4]{};
    std::uint32_t sampleMask = 0xFFFFFFFFU;
    std::optional<DepthStencilDesc> depthStencil;
    std::uint32_t stencilRef = 0;
    std::optional<RasterizerDesc> rasterizer;
    std::optional<AlphaTestDesc> alphaTest; // set when the Direct3D 9 pass enables alpha testing
    ShaderReference vertexShader;
    ShaderReference pixelShader;
  };

  struct Technique
  {
    std::string name;
    Annotations annotations;
    std::vector<Pass> passes;
  };

  struct EffectDescription
  {
    std::vector<Parameter> parameters;
    std::vector<StructType> structs;
    std::vector<SamplerDesc> samplers;
    std::vector<Technique> techniques;
    std::vector<std::string> notes; // what the parser could not represent
    bool direct3D9PassStates = false; // ApplyDirect3D9PassStates read the original source

    [[nodiscard]] const Parameter* FindParameter(std::string_view name) const noexcept;
    [[nodiscard]] const Technique* FindTechnique(std::string_view name) const noexcept;
    [[nodiscard]] const StructType* FindStruct(std::string_view name) const noexcept;
  };

  /**
   * Parses effect source in the D3D10 dialect, preprocessed and rewritten by
   * the D3D11 override layer (no `#` directives, pass states as state
   * objects). Throws std::runtime_error on input it cannot structure.
   */
  [[nodiscard]] EffectDescription ParseEffect(std::string_view source);

  /**
   * Reads the Direct3D 9 pass states that the D3D10 dialect drops from the
   * effect's original source (the `#ifndef DIRECT3D10` blocks the
   * preprocessor removed) and records them on the matching passes: today the
   * alpha test, which FAF's effects still rely on (water2's HighFidelityPS
   * returns the land mask in alpha and lets AlphaFunc = NotEqual discard it).
   */
  void ApplyDirect3D9PassStates(std::string_view originalSource, EffectDescription& description);
} // namespace gpg::gal::effects
