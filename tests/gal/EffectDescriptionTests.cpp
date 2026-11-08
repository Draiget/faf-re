// gpg/gal/effects/EffectDescription.h: the effect parser of the Direct3D 12 and Vulkan backends. The
// sources are small effects in the D3D10 dialect the D3D11 override layer hands on, with the
// constructs the game's effects use (state objects, sampler_state blocks, annotations, typedef'd
// structs, `compile` and `CompileShader` shader references). Expected state values are the
// Direct3D 11 enumerators from d3d11.h, and the values of fields a state block leaves out are the
// defaults Effects 11 gives them (dependencies/FX11/EffectNonRuntime.cpp: SSamplerBlock,
// SDepthStencilBlock, SRasterizerBlock, SBlendBlock).

#include <gtest/gtest.h>

#include <d3d11.h>
#include <d3d9.h>

#include <cfloat>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "gpg/gal/effects/EffectDescription.h"

using namespace gpg::gal::effects;

namespace
{
  constexpr std::uint8_t U8(const int value)
  {
    return static_cast<std::uint8_t>(value);
  }

  constexpr std::uint32_t U32(const int value)
  {
    return static_cast<std::uint32_t>(value);
  }

  bool HasNote(const EffectDescription& description, const std::string& note)
  {
    for (const std::string& line : description.notes) {
      if (line == note) {
        return true;
      }
    }
    return false;
  }

  const char* const kParameters = R"fx(
float4x4 WorldViewProj : WORLDVIEWPROJECTION;
float Time < string UIName = "Time"; float UIMin = 0.5; int Steps = 0x01 + 0x02 + 0x10 + 0x04; bool Visible = true; uint Mask = 0x0F; > = 2.5;
float3 LightDir = float3( 0.5, -1, 0.25 );
int Mode = 3;
bool Enabled = true;
row_major float3x4 Bones[4];
column_major float4x4 Projection;
float Weights[] = { 1, 2, 3 };
float4 Colours[2] = { float4( 1, 0, 0, 1 ), float4( 0, 1, 0, 1 ) };
static const float kHidden = 4;
const float Visible2 = 7;
texture BaseTexture;
string Description = "not a shader value";
half2 HalfPair = { 1, 2 };
dword Flags = 5;
uint Count = 6;
matrix Generic;
vector Direction;
float Sum( float a, float b );
struct CirrusLayer { float2 scroll; float4 colour : COLOR0; float weights[3]; };
CirrusLayer aCirrus;
typedef CirrusLayer CirrusAlias;
CirrusAlias bCirrus;
)fx";
} // namespace

TEST(GalEffectDescription, ParametersTakeTheirTypeShapeAndDefaults)
{
  const EffectDescription effect = ParseEffect(kParameters);

  const Parameter* const matrix = effect.FindParameter("WorldViewProj");
  ASSERT_NE(matrix, nullptr);
  EXPECT_EQ(matrix->parameterClass, ParameterClass::Matrix);
  EXPECT_EQ(matrix->scalarType, ScalarType::Float);
  EXPECT_EQ(matrix->rows, 4U);
  EXPECT_EQ(matrix->columns, 4U);
  EXPECT_EQ(matrix->elements, 0U);
  EXPECT_TRUE(matrix->defaults.empty());
  EXPECT_FALSE(matrix->columnMajor);
  EXPECT_EQ(matrix->typeName, "float4x4");

  const Parameter* const time = effect.FindParameter("Time");
  ASSERT_NE(time, nullptr);
  EXPECT_EQ(time->parameterClass, ParameterClass::Scalar);
  EXPECT_EQ(time->defaults, std::vector<float>{2.5f});

  const Parameter* const light = effect.FindParameter("LightDir");
  ASSERT_NE(light, nullptr);
  EXPECT_EQ(light->parameterClass, ParameterClass::Vector);
  EXPECT_EQ(light->columns, 3U);
  EXPECT_EQ(light->defaults, (std::vector<float>{0.5f, -1.0f, 0.25f}));

  const Parameter* const mode = effect.FindParameter("Mode");
  ASSERT_NE(mode, nullptr);
  EXPECT_EQ(mode->parameterClass, ParameterClass::Scalar);
  EXPECT_EQ(mode->scalarType, ScalarType::Int);
  EXPECT_EQ(mode->defaults, std::vector<float>{3.0f});

  const Parameter* const enabled = effect.FindParameter("Enabled");
  ASSERT_NE(enabled, nullptr);
  EXPECT_EQ(enabled->scalarType, ScalarType::Bool);
  EXPECT_EQ(enabled->defaults, std::vector<float>{1.0f});

  const Parameter* const bones = effect.FindParameter("Bones");
  ASSERT_NE(bones, nullptr);
  EXPECT_EQ(bones->parameterClass, ParameterClass::Matrix);
  EXPECT_EQ(bones->rows, 3U);
  EXPECT_EQ(bones->columns, 4U);
  EXPECT_EQ(bones->elements, 4U);
  EXPECT_FALSE(bones->columnMajor);
  EXPECT_FALSE(bones->unsized);

  const Parameter* const projection = effect.FindParameter("Projection");
  ASSERT_NE(projection, nullptr);
  EXPECT_TRUE(projection->columnMajor);
  EXPECT_EQ(projection->parameterClass, ParameterClass::Matrix);

  const Parameter* const weights = effect.FindParameter("Weights");
  ASSERT_NE(weights, nullptr);
  EXPECT_TRUE(weights->unsized);
  EXPECT_EQ(weights->elements, 3U);
  EXPECT_EQ(weights->defaults, (std::vector<float>{1.0f, 2.0f, 3.0f}));

  const Parameter* const colours = effect.FindParameter("Colours");
  ASSERT_NE(colours, nullptr);
  EXPECT_EQ(colours->elements, 2U);
  EXPECT_EQ(colours->columns, 4U);
  EXPECT_EQ(colours->defaults, (std::vector<float>{1, 0, 0, 1, 0, 1, 0, 1}));

  EXPECT_EQ(effect.FindParameter("kHidden"), nullptr) << "static globals are not parameters";
  const Parameter* const constant = effect.FindParameter("Visible2");
  ASSERT_NE(constant, nullptr) << "const globals stay parameters, as in the D3D9 effect framework";
  EXPECT_EQ(constant->parameterClass, ParameterClass::Scalar);
  EXPECT_EQ(constant->defaults, std::vector<float>{7.0f});

  const Parameter* const texture = effect.FindParameter("BaseTexture");
  ASSERT_NE(texture, nullptr);
  EXPECT_EQ(texture->parameterClass, ParameterClass::Texture);

  const Parameter* const description = effect.FindParameter("Description");
  ASSERT_NE(description, nullptr);
  EXPECT_EQ(description->parameterClass, ParameterClass::Other);
  EXPECT_TRUE(description->defaults.empty());

  const Parameter* const half = effect.FindParameter("HalfPair");
  ASSERT_NE(half, nullptr);
  EXPECT_EQ(half->parameterClass, ParameterClass::Vector);
  EXPECT_EQ(half->scalarType, ScalarType::Float);
  EXPECT_EQ(half->columns, 2U);
  EXPECT_EQ(half->defaults, (std::vector<float>{1.0f, 2.0f}));

  const Parameter* const flags = effect.FindParameter("Flags");
  ASSERT_NE(flags, nullptr);
  EXPECT_EQ(flags->scalarType, ScalarType::Uint);
  const Parameter* const count = effect.FindParameter("Count");
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(count->scalarType, ScalarType::Uint);

  const Parameter* const generic = effect.FindParameter("Generic");
  ASSERT_NE(generic, nullptr);
  EXPECT_EQ(generic->parameterClass, ParameterClass::Matrix);
  EXPECT_EQ(generic->rows, 4U);
  EXPECT_EQ(generic->columns, 4U);
  const Parameter* const direction = effect.FindParameter("Direction");
  ASSERT_NE(direction, nullptr);
  EXPECT_EQ(direction->parameterClass, ParameterClass::Vector);
  EXPECT_EQ(direction->columns, 4U);

  EXPECT_EQ(effect.FindParameter("Sum"), nullptr) << "a function prototype is not a parameter";
  EXPECT_EQ(effect.FindParameter("missing"), nullptr);
}

TEST(GalEffectDescription, ParameterSpansCoverTheirDeclaration)
{
  const std::string source = kParameters;
  const EffectDescription effect = ParseEffect(source);
  const Parameter* const light = effect.FindParameter("LightDir");
  ASSERT_NE(light, nullptr);
  EXPECT_EQ(source.substr(light->begin, light->end - light->begin), "float3 LightDir = float3( 0.5, -1, 0.25 );");
  const Parameter* const weights = effect.FindParameter("Weights");
  ASSERT_NE(weights, nullptr);
  EXPECT_EQ(source.substr(weights->begin, weights->end - weights->begin), "float Weights[] = { 1, 2, 3 };");
}

TEST(GalEffectDescription, AnnotationsKeepKindTextAndFoldedNumbers)
{
  const EffectDescription effect = ParseEffect(kParameters);
  const Parameter* const time = effect.FindParameter("Time");
  ASSERT_NE(time, nullptr);
  ASSERT_EQ(time->annotations.size(), 5U);

  const Annotation* const name = FindAnnotation(time->annotations, "UIName");
  ASSERT_NE(name, nullptr);
  EXPECT_EQ(name->kind, Annotation::Kind::String);
  EXPECT_EQ(name->text, "Time");

  const Annotation* const minimum = FindAnnotation(time->annotations, "UIMin");
  ASSERT_NE(minimum, nullptr);
  EXPECT_EQ(minimum->kind, Annotation::Kind::Float);
  EXPECT_DOUBLE_EQ(minimum->number, 0.5);

  const Annotation* const steps = FindAnnotation(time->annotations, "Steps");
  ASSERT_NE(steps, nullptr);
  EXPECT_EQ(steps->kind, Annotation::Kind::Int);
  EXPECT_DOUBLE_EQ(steps->number, 23.0) << "folded as the effect compiler folds it";
  EXPECT_EQ(steps->text, "0x01 + 0x02 + 0x10 + 0x04");

  const Annotation* const visible = FindAnnotation(time->annotations, "Visible");
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->kind, Annotation::Kind::Bool);
  EXPECT_DOUBLE_EQ(visible->number, 1.0);

  const Annotation* const mask = FindAnnotation(time->annotations, "Mask");
  ASSERT_NE(mask, nullptr);
  EXPECT_EQ(mask->kind, Annotation::Kind::Int);
  EXPECT_DOUBLE_EQ(mask->number, 15.0);

  EXPECT_EQ(FindAnnotation(time->annotations, "missing"), nullptr);
  EXPECT_EQ(FindAnnotation({}, "UIName"), nullptr);
}

TEST(GalEffectDescription, StructsAndTypedefsAreRecordedAndNotNumeric)
{
  const EffectDescription effect = ParseEffect(kParameters);

  const StructType* const layer = effect.FindStruct("CirrusLayer");
  ASSERT_NE(layer, nullptr);
  EXPECT_TRUE(layer->aliasOf.empty());
  ASSERT_EQ(layer->members.size(), 3U);
  EXPECT_EQ(layer->members[0].name, "scroll");
  EXPECT_EQ(layer->members[0].parameterClass, ParameterClass::Vector);
  EXPECT_EQ(layer->members[0].columns, 2U);
  EXPECT_EQ(layer->members[1].name, "colour");
  EXPECT_EQ(layer->members[1].typeName, "float4");
  EXPECT_EQ(layer->members[1].columns, 4U);
  EXPECT_EQ(layer->members[2].name, "weights");
  EXPECT_EQ(layer->members[2].parameterClass, ParameterClass::Scalar);
  EXPECT_EQ(layer->members[2].elements, 3U);

  const StructType* const alias = effect.FindStruct("CirrusAlias");
  ASSERT_NE(alias, nullptr);
  EXPECT_EQ(alias->aliasOf, "CirrusLayer");
  EXPECT_EQ(alias->members.size(), 3U);
  EXPECT_EQ(effect.FindStruct("missing"), nullptr);

  const Parameter* const a = effect.FindParameter("aCirrus");
  ASSERT_NE(a, nullptr);
  EXPECT_EQ(a->parameterClass, ParameterClass::Struct);
  const Parameter* const b = effect.FindParameter("bCirrus");
  ASSERT_NE(b, nullptr);
  EXPECT_EQ(b->parameterClass, ParameterClass::Struct);
}

TEST(GalEffectDescription, SamplerStatesTakeTheirFieldsAndEffects11Defaults)
{
  const EffectDescription effect = ParseEffect(R"fx(
texture BaseTexture;
sampler2D BaseSampler = sampler_state
{
    Texture = <BaseTexture>;
    Filter = MIN_MAG_MIP_POINT;
    AddressU = WRAP;
    AddressV = MIRROR;
    AddressW = BORDER;
    MaxAnisotropy = 4;
    MipLODBias = -0.5;
    BorderColor = float4( 1, 0.5, 0.25, 0 );
    MinLOD = 1;
    MaxLOD = 8;
};
samplerCUBE SkySampler = sampler_state { Texture = (SkyTexture); };
sampler3D VolumeSampler = sampler_state { Texture = <VolumeTexture>; Filter = ANISOTROPIC; AddressU = MIRROR_ONCE; AddressV = CLAMP; };
sampler PlainSampler = sampler_state { Texture = <BaseTexture>; Filter = COMPARISON_MIN_MAG_MIP_LINEAR; AddressU = Unknown; };
sampler2D LinearSampler = sampler_state { Filter = MIN_LINEAR_MAG_MIP_POINT; };
)fx");
  ASSERT_EQ(effect.samplers.size(), 5U);

  const SamplerDesc& base = effect.samplers[0];
  EXPECT_EQ(base.name, "BaseSampler");
  EXPECT_EQ(base.declaredType, "sampler2D");
  EXPECT_EQ(base.texture, "BaseTexture");
  EXPECT_EQ(base.kind, SamplerDesc::Kind::Texture2D);
  EXPECT_EQ(base.filter, U32(D3D11_FILTER_MIN_MAG_MIP_POINT));
  EXPECT_EQ(base.addressU, U8(D3D11_TEXTURE_ADDRESS_WRAP));
  EXPECT_EQ(base.addressV, U8(D3D11_TEXTURE_ADDRESS_MIRROR));
  EXPECT_EQ(base.addressW, U8(D3D11_TEXTURE_ADDRESS_BORDER));
  EXPECT_EQ(base.maxAnisotropy, 4U);
  EXPECT_FLOAT_EQ(base.mipLodBias, -0.5f);
  EXPECT_FLOAT_EQ(base.borderColor[0], 1.0f);
  EXPECT_FLOAT_EQ(base.borderColor[1], 0.5f);
  EXPECT_FLOAT_EQ(base.borderColor[2], 0.25f);
  EXPECT_FLOAT_EQ(base.borderColor[3], 0.0f);
  EXPECT_FLOAT_EQ(base.minLod, 1.0f);
  EXPECT_FLOAT_EQ(base.maxLod, 8.0f);

  // Everything left out: Effects 11's SSamplerBlock defaults.
  const SamplerDesc& sky = effect.samplers[1];
  EXPECT_EQ(sky.kind, SamplerDesc::Kind::TextureCube);
  EXPECT_EQ(sky.texture, "SkyTexture");
  EXPECT_EQ(sky.filter, U32(D3D11_FILTER_MIN_MAG_MIP_LINEAR));
  EXPECT_EQ(sky.addressU, U8(D3D11_TEXTURE_ADDRESS_CLAMP));
  EXPECT_EQ(sky.addressV, U8(D3D11_TEXTURE_ADDRESS_CLAMP));
  EXPECT_EQ(sky.addressW, U8(D3D11_TEXTURE_ADDRESS_CLAMP));
  EXPECT_EQ(sky.maxAnisotropy, U32(D3D11_DEFAULT_MAX_ANISOTROPY));
  EXPECT_FLOAT_EQ(sky.mipLodBias, D3D11_DEFAULT_MIP_LOD_BIAS);
  for (const float component : sky.borderColor) {
    EXPECT_FLOAT_EQ(component, D3D11_DEFAULT_BORDER_COLOR_COMPONENT);
  }
  EXPECT_EQ(sky.minLod, -FLT_MAX);
  EXPECT_EQ(sky.maxLod, FLT_MAX);

  const SamplerDesc& volume = effect.samplers[2];
  EXPECT_EQ(volume.kind, SamplerDesc::Kind::Texture3D);
  EXPECT_EQ(volume.filter, U32(D3D11_FILTER_ANISOTROPIC));
  EXPECT_EQ(volume.addressU, U8(D3D11_TEXTURE_ADDRESS_MIRROR_ONCE));
  EXPECT_EQ(volume.addressV, U8(D3D11_TEXTURE_ADDRESS_CLAMP));

  const SamplerDesc& plain = effect.samplers[3];
  EXPECT_EQ(plain.declaredType, "sampler");
  EXPECT_EQ(plain.kind, SamplerDesc::Kind::Texture2D);
  EXPECT_EQ(plain.filter, U32(D3D11_FILTER_COMPARISON_MIN_MAG_MIP_LINEAR));
  EXPECT_EQ(plain.addressU, U8(D3D11_TEXTURE_ADDRESS_CLAMP)) << "an unknown address mode keeps the default";

  const SamplerDesc& linear = effect.samplers[4];
  EXPECT_EQ(linear.filter, U32(D3D11_FILTER_MIN_LINEAR_MAG_MIP_POINT));
  EXPECT_TRUE(linear.texture.empty());

  EXPECT_EQ(effect.FindParameter("BaseSampler"), nullptr) << "samplers are not parameters";
}

TEST(GalEffectDescription, BlendStatesBlendAlphaWithTheColourFactorsAsDirect3D9)
{
  const EffectDescription effect = ParseEffect(R"fx(
BlendState Additive
{
    BlendEnable[0] = TRUE;
    BlendEnable[1] = FALSE;
    SrcBlend = SRC_COLOR;
    DestBlend = INV_DEST_COLOR;
    BlendOp = REV_SUBTRACT;
    SrcBlendAlpha = ONE;
    DestBlendAlpha = ZERO;
    BlendOpAlpha = ADD;
    RenderTargetWriteMask[0] = 0x07;
    RenderTargetWriteMask[1] = 0x00;
    AlphaToCoverageEnable = TRUE;
};
BlendState Prefixed { BlendEnable[0] = 1; SrcBlend = D3D10_BLEND_SRC_ALPHA; DestBlend = D3D11_BLEND_INV_SRC_ALPHA; BlendOp = D3D10_BLEND_OP_MAX; };
BlendState Empty { };
technique10 T
{
    pass Additive { SetBlendState( Additive, float4( 0.25, 0.5, 0.75, 1 ), 0xFFFFFFFF ); }
    pass Prefixed { SetBlendState( Prefixed, float4( 0, 0, 0, 0 ), 0x0000000F ); }
    pass Empty { SetBlendState( Empty, float4( 0, 0, 0, 0 ), 0xFFFFFFFF ); }
}
)fx");
  const Technique* const technique = effect.FindTechnique("T");
  ASSERT_NE(technique, nullptr);
  ASSERT_EQ(technique->passes.size(), 3U);

  const Pass& additive = technique->passes[0];
  ASSERT_TRUE(additive.blend.has_value());
  EXPECT_TRUE(additive.blend->enable);
  EXPECT_TRUE(additive.blend->alphaToCoverage);
  EXPECT_EQ(additive.blend->srcBlend, U8(D3D11_BLEND_SRC_COLOR));
  EXPECT_EQ(additive.blend->destBlend, U8(D3D11_BLEND_INV_DEST_COLOR));
  EXPECT_EQ(additive.blend->blendOp, U8(D3D11_BLEND_OP_REV_SUBTRACT));
  // D3D9 without SEPARATEALPHABLENDENABLE blends alpha with the colour factors: a colour factor
  // read for the alpha channel is the matching alpha factor.
  EXPECT_EQ(additive.blend->srcBlendAlpha, U8(D3D11_BLEND_SRC_ALPHA));
  EXPECT_EQ(additive.blend->destBlendAlpha, U8(D3D11_BLEND_INV_DEST_ALPHA));
  EXPECT_EQ(additive.blend->blendOpAlpha, U8(D3D11_BLEND_OP_REV_SUBTRACT));
  EXPECT_EQ(additive.blend->writeMask, U8(D3D11_COLOR_WRITE_ENABLE_RED | D3D11_COLOR_WRITE_ENABLE_GREEN | D3D11_COLOR_WRITE_ENABLE_BLUE));
  EXPECT_FLOAT_EQ(additive.blendFactor[0], 0.25f);
  EXPECT_FLOAT_EQ(additive.blendFactor[1], 0.5f);
  EXPECT_FLOAT_EQ(additive.blendFactor[2], 0.75f);
  EXPECT_FLOAT_EQ(additive.blendFactor[3], 1.0f);
  EXPECT_EQ(additive.sampleMask, 0xFFFFFFFFU);

  const Pass& prefixed = technique->passes[1];
  ASSERT_TRUE(prefixed.blend.has_value());
  EXPECT_TRUE(prefixed.blend->enable);
  EXPECT_EQ(prefixed.blend->srcBlend, U8(D3D11_BLEND_SRC_ALPHA));
  EXPECT_EQ(prefixed.blend->destBlend, U8(D3D11_BLEND_INV_SRC_ALPHA));
  EXPECT_EQ(prefixed.blend->blendOp, U8(D3D11_BLEND_OP_MAX));
  EXPECT_EQ(prefixed.blend->srcBlendAlpha, U8(D3D11_BLEND_SRC_ALPHA));
  EXPECT_EQ(prefixed.blend->destBlendAlpha, U8(D3D11_BLEND_INV_SRC_ALPHA));
  EXPECT_EQ(prefixed.blend->writeMask, U8(D3D11_COLOR_WRITE_ENABLE_ALL));
  EXPECT_EQ(prefixed.sampleMask, 0x0000000FU);

  // Effects 11's SBlendBlock defaults.
  const Pass& empty = technique->passes[2];
  ASSERT_TRUE(empty.blend.has_value());
  EXPECT_FALSE(empty.blend->enable);
  EXPECT_FALSE(empty.blend->alphaToCoverage);
  EXPECT_EQ(empty.blend->srcBlend, U8(D3D11_BLEND_ONE));
  EXPECT_EQ(empty.blend->destBlend, U8(D3D11_BLEND_ZERO));
  EXPECT_EQ(empty.blend->blendOp, U8(D3D11_BLEND_OP_ADD));
  EXPECT_EQ(empty.blend->srcBlendAlpha, U8(D3D11_BLEND_ONE));
  EXPECT_EQ(empty.blend->destBlendAlpha, U8(D3D11_BLEND_ZERO));
  EXPECT_EQ(empty.blend->blendOpAlpha, U8(D3D11_BLEND_OP_ADD));
  EXPECT_EQ(empty.blend->writeMask, U8(D3D11_COLOR_WRITE_ENABLE_ALL));
}

TEST(GalEffectDescription, DepthStencilStatesTakeEveryField)
{
  const EffectDescription effect = ParseEffect(R"fx(
DepthStencilState Stencilled
{
    DepthEnable = FALSE;
    DepthWriteMask = ZERO;
    DepthFunc = GREATER_EQUAL;
    StencilEnable = TRUE;
    StencilReadMask = 0x80;
    StencilWriteMask = 0x7F;
    FrontFaceStencilFail = ZERO;
    FrontFaceStencilDepthFail = INCR;
    FrontFaceStencilPass = KEEP;
    FrontFaceStencilFunc = NOT_EQUAL;
    BackFaceStencilFail = REPLACE;
    BackFaceStencilDepthFail = DECR;
    BackFaceStencilPass = INCR_SAT;
    BackFaceStencilFunc = NEVER;
};
DepthStencilState Defaults { };
DepthStencilState Inverted { BackFaceStencilFail = INVERT; BackFaceStencilPass = DECR_SAT; FrontFaceStencilFunc = D3D11_COMPARISON_LESS_EQUAL; DepthWriteMask = ALL; };
technique10 T
{
    pass P0 { SetDepthStencilState( Stencilled, 0x03 ); }
    pass P1 { SetDepthStencilState( Defaults, 0 ); }
    pass P2 { SetDepthStencilState( Inverted, 255 ); }
}
)fx");
  const Technique* const technique = effect.FindTechnique("T");
  ASSERT_NE(technique, nullptr);
  ASSERT_EQ(technique->passes.size(), 3U);

  const Pass& stencilled = technique->passes[0];
  ASSERT_TRUE(stencilled.depthStencil.has_value());
  const DepthStencilDesc& desc = *stencilled.depthStencil;
  EXPECT_FALSE(desc.depthEnable);
  EXPECT_FALSE(desc.depthWrite);
  EXPECT_EQ(desc.depthFunc, U8(D3D11_COMPARISON_GREATER_EQUAL));
  EXPECT_TRUE(desc.stencilEnable);
  EXPECT_EQ(desc.stencilReadMask, 0x80U);
  EXPECT_EQ(desc.stencilWriteMask, 0x7FU);
  EXPECT_EQ(desc.front.failOp, U8(D3D11_STENCIL_OP_ZERO));
  EXPECT_EQ(desc.front.depthFailOp, U8(D3D11_STENCIL_OP_INCR));
  EXPECT_EQ(desc.front.passOp, U8(D3D11_STENCIL_OP_KEEP));
  EXPECT_EQ(desc.front.func, U8(D3D11_COMPARISON_NOT_EQUAL));
  EXPECT_EQ(desc.back.failOp, U8(D3D11_STENCIL_OP_REPLACE));
  EXPECT_EQ(desc.back.depthFailOp, U8(D3D11_STENCIL_OP_DECR));
  EXPECT_EQ(desc.back.passOp, U8(D3D11_STENCIL_OP_INCR_SAT));
  EXPECT_EQ(desc.back.func, U8(D3D11_COMPARISON_NEVER));
  EXPECT_EQ(stencilled.stencilRef, 3U);

  // Effects 11's SDepthStencilBlock defaults.
  const Pass& defaults = technique->passes[1];
  ASSERT_TRUE(defaults.depthStencil.has_value());
  EXPECT_TRUE(defaults.depthStencil->depthEnable);
  EXPECT_TRUE(defaults.depthStencil->depthWrite);
  EXPECT_EQ(defaults.depthStencil->depthFunc, U8(D3D11_COMPARISON_LESS));
  EXPECT_FALSE(defaults.depthStencil->stencilEnable);
  EXPECT_EQ(defaults.depthStencil->stencilReadMask, U8(D3D11_DEFAULT_STENCIL_READ_MASK));
  EXPECT_EQ(defaults.depthStencil->stencilWriteMask, U8(D3D11_DEFAULT_STENCIL_WRITE_MASK));
  for (const StencilFaceDesc* const face : {&defaults.depthStencil->front, &defaults.depthStencil->back}) {
    EXPECT_EQ(face->failOp, U8(D3D11_STENCIL_OP_KEEP));
    EXPECT_EQ(face->depthFailOp, U8(D3D11_STENCIL_OP_KEEP));
    EXPECT_EQ(face->passOp, U8(D3D11_STENCIL_OP_KEEP));
    EXPECT_EQ(face->func, U8(D3D11_COMPARISON_ALWAYS));
  }

  const Pass& inverted = technique->passes[2];
  ASSERT_TRUE(inverted.depthStencil.has_value());
  EXPECT_EQ(inverted.depthStencil->back.failOp, U8(D3D11_STENCIL_OP_INVERT));
  EXPECT_EQ(inverted.depthStencil->back.passOp, U8(D3D11_STENCIL_OP_DECR_SAT));
  EXPECT_EQ(inverted.depthStencil->front.func, U8(D3D11_COMPARISON_LESS_EQUAL));
  EXPECT_TRUE(inverted.depthStencil->depthWrite);
  EXPECT_EQ(inverted.stencilRef, 255U);
}

TEST(GalEffectDescription, DepthStencilPackedKeyFollowsItsBitLayout)
{
  // The header's layout: depth enable bit 0, depth write bit 1, depth func bits 2-5, stencil
  // enable bit 6, read mask bits 8-15, write mask bits 16-23, the front face from bit 24 and
  // the back face from bit 40 (fail, depth fail, pass, func: four bits each).
  const DepthStencilDesc defaults{};
  EXPECT_EQ(defaults.PackedKey(), 0x0081'1181'11FF'FF13ULL);

  DepthStencilDesc changed = defaults;
  changed.back.func = 2;
  EXPECT_EQ(changed.PackedKey() ^ defaults.PackedKey(), static_cast<std::uint64_t>(8U ^ 2U) << 52U);
  changed = defaults;
  changed.stencilEnable = true;
  EXPECT_EQ(changed.PackedKey() ^ defaults.PackedKey(), 1ULL << 6U);
  changed = defaults;
  changed.stencilWriteMask = 0x0F;
  EXPECT_EQ(changed.PackedKey() ^ defaults.PackedKey(), static_cast<std::uint64_t>(0xFFU ^ 0x0FU) << 16U);
}

TEST(GalEffectDescription, RasterizerStatesConvertDirect3D9DepthBiases)
{
  const EffectDescription effect = ParseEffect(R"fx(
RasterizerState Wire
{
    FillMode = WIREFRAME;
    CullMode = FRONT;
    FrontCounterClockwise = TRUE;
    DepthBias = -0.00001;
    SlopeScaledDepthBias = 1.5;
    DepthBiasClamp = 0.25;
    ScissorEnable = TRUE;
    MultisampleEnable = TRUE;
    AntialiasedLineEnable = TRUE;
    DepthClipEnable = FALSE;
};
RasterizerState IntegerBias { CullMode = NONE; DepthBias = 3; };
RasterizerState Folded { DepthBias = 2 * 4; };
RasterizerState Defaults { };
technique10 T
{
    pass P0 { SetRasterizerState( Wire ); }
    pass P1 { SetRasterizerState( IntegerBias ); }
    pass P2 { SetRasterizerState( Folded ); }
    pass P3 { SetRasterizerState( Defaults ); }
}
)fx");
  const Technique* const technique = effect.FindTechnique("T");
  ASSERT_NE(technique, nullptr);
  ASSERT_EQ(technique->passes.size(), 4U);

  const RasterizerDesc& wire = *technique->passes[0].rasterizer;
  EXPECT_EQ(wire.fillMode, U8(D3D11_FILL_WIREFRAME));
  EXPECT_EQ(wire.cullMode, U8(D3D11_CULL_FRONT));
  EXPECT_TRUE(wire.frontCounterClockwise);
  // D3D9's bias is a fraction of the depth range; D3D10+ counts steps of the 24-bit depth buffer:
  // -0.00001 * 2^24 = -167.77, to the nearest step.
  EXPECT_EQ(wire.depthBias, -168);
  EXPECT_FLOAT_EQ(wire.slopeScaledDepthBias, 1.5f);
  EXPECT_FLOAT_EQ(wire.depthBiasClamp, 0.25f);
  EXPECT_TRUE(wire.scissorEnable);
  EXPECT_TRUE(wire.multisampleEnable);
  EXPECT_TRUE(wire.antialiasedLineEnable);
  EXPECT_FALSE(wire.depthClipEnable);

  const RasterizerDesc& integer = *technique->passes[1].rasterizer;
  EXPECT_EQ(integer.cullMode, U8(D3D11_CULL_NONE));
  EXPECT_EQ(integer.depthBias, 3) << "a whole number is already in depth steps";

  EXPECT_EQ(technique->passes[2].rasterizer->depthBias, 8);

  // Effects 11's SRasterizerBlock defaults.
  const RasterizerDesc& defaults = *technique->passes[3].rasterizer;
  EXPECT_EQ(defaults.fillMode, U8(D3D11_FILL_SOLID));
  EXPECT_EQ(defaults.cullMode, U8(D3D11_CULL_BACK));
  EXPECT_FALSE(defaults.frontCounterClockwise);
  EXPECT_EQ(defaults.depthBias, D3D11_DEFAULT_DEPTH_BIAS);
  EXPECT_FLOAT_EQ(defaults.depthBiasClamp, D3D11_DEFAULT_DEPTH_BIAS_CLAMP);
  EXPECT_FLOAT_EQ(defaults.slopeScaledDepthBias, D3D11_DEFAULT_SLOPE_SCALED_DEPTH_BIAS);
  EXPECT_TRUE(defaults.depthClipEnable);
  EXPECT_FALSE(defaults.scissorEnable);
  EXPECT_FALSE(defaults.multisampleEnable);
  EXPECT_FALSE(defaults.antialiasedLineEnable);
}

TEST(GalEffectDescription, TechniquesPassesAndShaderReferences)
{
  const EffectDescription effect = ParseEffect(R"fx(
BlendState Opaque { BlendEnable[0] = FALSE; };
technique10 Draw < string Category = "opaque"; int Order = 2; >
{
    pass P0 < bool Lit = false; >
    {
        SetBlendState( Opaque, float4( 0, 0, 0, 0 ), 0xFFFFFFFF );
        SetVertexShader( CompileShader( vs_4_0, MainVS( 2, true ) ) );
        SetGeometryShader( NULL );
        SetPixelShader( CompileShader( ps_4_0, MainPS() ) );
    }
    pass P1
    {
        VertexShader = compile vs_4_1 MainVS( 1, false );
        PixelShader = compile ps_4_1 MainPS;
        SetBlendState( Missing, float4( 0, 0, 0, 0 ), 0xFFFFFFFF );
        SetDepthStencilState( AlsoMissing, 0 );
        SetRasterizerState( StillMissing );
        ZEnable = false;
    }
    pass P2 { VertexShader = NULL; PixelShader = NULL; }
}
technique Simple { pass { VertexShader = compile vs_4_0 MainVS( 0, false ); } }
technique11 Eleven { }
)fx");
  ASSERT_EQ(effect.techniques.size(), 3U);
  EXPECT_EQ(effect.FindTechnique("missing"), nullptr);

  const Technique* const draw = effect.FindTechnique("Draw");
  ASSERT_NE(draw, nullptr);
  const Annotation* const category = FindAnnotation(draw->annotations, "Category");
  ASSERT_NE(category, nullptr);
  EXPECT_EQ(category->text, "opaque");
  const Annotation* const order = FindAnnotation(draw->annotations, "Order");
  ASSERT_NE(order, nullptr);
  EXPECT_DOUBLE_EQ(order->number, 2.0);
  ASSERT_EQ(draw->passes.size(), 3U);

  const Pass& p0 = draw->passes[0];
  EXPECT_EQ(p0.name, "P0");
  const Annotation* const lit = FindAnnotation(p0.annotations, "Lit");
  ASSERT_NE(lit, nullptr);
  EXPECT_EQ(lit->kind, Annotation::Kind::Bool);
  EXPECT_DOUBLE_EQ(lit->number, 0.0);
  EXPECT_EQ(p0.vertexShader.function, "MainVS");
  EXPECT_EQ(p0.vertexShader.arguments, "2, true");
  EXPECT_EQ(p0.pixelShader.function, "MainPS");
  EXPECT_EQ(p0.pixelShader.arguments, "");
  EXPECT_TRUE(p0.blend.has_value());
  EXPECT_FALSE(p0.depthStencil.has_value());
  EXPECT_FALSE(p0.rasterizer.has_value());
  EXPECT_FALSE(p0.alphaTest.has_value());

  const Pass& p1 = draw->passes[1];
  EXPECT_EQ(p1.vertexShader.function, "MainVS");
  EXPECT_EQ(p1.vertexShader.arguments, "1, false");
  EXPECT_EQ(p1.pixelShader.function, "MainPS") << "a compile without an argument list";
  EXPECT_FALSE(p1.blend.has_value());
  EXPECT_FALSE(p1.depthStencil.has_value());
  EXPECT_FALSE(p1.rasterizer.has_value());
  EXPECT_TRUE(HasNote(effect, "technique Draw: unknown blend state Missing"));
  EXPECT_TRUE(HasNote(effect, "technique Draw: unknown depth-stencil state AlsoMissing"));
  EXPECT_TRUE(HasNote(effect, "technique Draw: unknown rasterizer state StillMissing"));
  EXPECT_TRUE(HasNote(effect, "technique Draw: pass statement ignored: ZEnable = false"));

  const Pass& p2 = draw->passes[2];
  EXPECT_TRUE(p2.vertexShader.function.empty());
  EXPECT_TRUE(p2.pixelShader.function.empty());

  const Technique* const simple = effect.FindTechnique("Simple");
  ASSERT_NE(simple, nullptr);
  ASSERT_EQ(simple->passes.size(), 1U);
  EXPECT_EQ(simple->passes[0].name, "");
  EXPECT_EQ(simple->passes[0].vertexShader.arguments, "0, false");

  const Technique* const eleven = effect.FindTechnique("Eleven");
  ASSERT_NE(eleven, nullptr);
  EXPECT_TRUE(eleven->passes.empty());
}

TEST(GalEffectDescription, DirectivesAreSkippedAndMalformedInputIsHandled)
{
  const EffectDescription withDirectives = ParseEffect("#define sqrt(x) sqrt(abs(x))\n#line 4 \"a.fx\"\nfloat a = 1;\n");
  ASSERT_EQ(withDirectives.parameters.size(), 1U);
  EXPECT_EQ(withDirectives.parameters[0].name, "a");

  EXPECT_THROW(static_cast<void>(ParseEffect("float f() { return 1;")), std::runtime_error);
  EXPECT_THROW(static_cast<void>(ParseEffect("technique10 T { pass P0 { ")), std::runtime_error);

  EffectDescription garbage;
  EXPECT_NO_THROW(garbage = ParseEffect("= = ; x ; ; < > ; float a < int x = 1 ;"));
  EXPECT_TRUE(garbage.techniques.empty());
  const Parameter* const a = garbage.FindParameter("a");
  ASSERT_NE(a, nullptr) << "an annotation block that never closes is not an annotation";
  EXPECT_TRUE(a->annotations.empty());
  EXPECT_TRUE(a->defaults.empty());

  EXPECT_TRUE(ParseEffect("").parameters.empty());
}

TEST(GalDirect3D9PassStates, AlphaTestsAreReadFromTheOriginalSource)
{
  // The translated source the parser saw: the D3D10 dialect has no alpha test.
  EffectDescription description = ParseEffect(R"fx(
technique10 Water < string Note = "a // b"; >
{
    pass P0 { SetVertexShader( CompileShader( vs_4_0, VS() ) ); }
    pass P1 { }
    pass P2 { }
    pass P3 { }
}
)fx");
  // The effect as the game ships it: the alpha test sits in `#ifndef DIRECT3D10` sections and
  // after the state macros, which end without a ';'.
  ApplyDirect3D9PassStates(R"fx(
// technique Water { pass P0 { AlphaTestEnable = true; AlphaFunc = Less; } }
/* technique Water { pass P0 { AlphaTestEnable = true; AlphaFunc = Less; } } */
technique Water < string Note = "a // b"; >
{
    pass P0
    {
        AlphaState( AlphaBlend_Disable )
        DepthState( Depth_Enable )
#ifndef DIRECT3D10
        AlphaTestEnable = true;
        AlphaRef = 0x00;
        AlphaFunc = NotEqual;
#endif
        VertexShader = compile vs_1_1 VS();
    }
    pass P1
    {
        AlphaTestEnable = true;
        AlphaFunc = Always;
    }
    pass P2
    {
        AlphaTestEnable = TRUE;
        AlphaFunc = 5;
        AlphaRef = 300;
    }
    pass P3
    {
        AlphaTestEnable = false;
        AlphaFunc = Less;
    }
}
technique Unknown { pass P0 { AlphaTestEnable = true; AlphaFunc = Less; } }
)fx",
                           description);
  EXPECT_TRUE(description.direct3D9PassStates);
  const Technique* const water = description.FindTechnique("Water");
  ASSERT_NE(water, nullptr);
  ASSERT_EQ(water->passes.size(), 4U);

  ASSERT_TRUE(water->passes[0].alphaTest.has_value());
  EXPECT_EQ(water->passes[0].alphaTest->func, U8(D3DCMP_NOTEQUAL));
  EXPECT_EQ(water->passes[0].alphaTest->ref, 0U);
  EXPECT_FALSE(water->passes[1].alphaTest.has_value()) << "ALWAYS passes everything: no test";
  ASSERT_TRUE(water->passes[2].alphaTest.has_value());
  EXPECT_EQ(water->passes[2].alphaTest->func, U8(D3DCMP_GREATER));
  EXPECT_EQ(water->passes[2].alphaTest->ref, 300U & 0xFFU) << "D3DRS_ALPHAREF is 8 bits";
  EXPECT_FALSE(water->passes[3].alphaTest.has_value());

  EXPECT_TRUE(HasNote(description, "2 passes take Direct3D 9's alpha test"));
}

TEST(GalDirect3D9PassStates, NothingToReadLeavesThePassesAlone)
{
  EffectDescription description = ParseEffect("technique10 T { pass P0 { } }");
  ApplyDirect3D9PassStates("", description);
  EXPECT_TRUE(description.direct3D9PassStates);
  EXPECT_FALSE(description.techniques[0].passes[0].alphaTest.has_value());
  EXPECT_TRUE(description.notes.empty());

  // A pass name the original lacks, and more passes in the original than were parsed.
  ApplyDirect3D9PassStates("technique T { pass { AlphaTestEnable = 1; AlphaFunc = 9; } pass { AlphaTestEnable = 1; AlphaFunc = less; } }",
                           description);
  EXPECT_FALSE(description.techniques[0].passes[0].alphaTest.has_value()) << "an out-of-range function keeps ALWAYS";
  ASSERT_EQ(description.techniques[0].passes.size(), 1U);
}
