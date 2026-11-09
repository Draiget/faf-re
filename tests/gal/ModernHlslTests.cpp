// gpg/gal/effects/ModernHlsl.h: the rewrite of an effect into plain HLSL for DXC, and the $Globals
// layout the parameter store writes. The layouts follow the HLSL constant-buffer packing rules
// ("Packing rules for constant variables", Direct3D HLSL documentation): a scalar or vector packs
// into the current 16-byte register when it fits, arrays, structs and multi-register matrices
// start a register, every array element starts one, and a row-major matrix takes a register per
// row (a column-major one per column). The rewrite is checked for the properties ModernHlsl.h
// promises: removed effect constructs, views and samplers on fixed registers, local copies of
// written globals, modern stage semantics and one entry point per (stage, function, arguments).

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "GalTestSupport.h"
#include "gpg/gal/effects/EffectDescription.h"
#include "gpg/gal/effects/ModernHlsl.h"
#include "gpg/gal/effects/ShadowCascades.h"
#include "gpg/gal/effects/TextureFiltering.h"

using namespace gpg::gal::effects;
using faf_gal_tests::Count;

namespace
{
  struct Generated
  {
    EffectDescription description;
    ModernEffect modern;
  };

  Generated Generate(const std::string& source)
  {
    Generated result;
    result.description = ParseEffect(source);
    result.modern = GenerateModernHlsl(source, result.description);
    return result;
  }

  bool Contains(const std::string& text, const std::string& needle)
  {
    return text.find(needle) != std::string::npos;
  }

  bool HasNote(const std::vector<std::string>& notes, const std::string& note)
  {
    for (const std::string& line : notes) {
      if (line == note) {
        return true;
      }
    }
    return false;
  }

  /** The slot of the parameter named `name`. */
  const ConstantSlot* Slot(const EffectDescription& description, const ConstantLayout& layout, const std::string& name)
  {
    for (std::uint32_t index = 0U; index < description.parameters.size(); ++index) {
      if (description.parameters[index].name == name) {
        return layout.Find(index);
      }
    }
    return nullptr;
  }

  void ExpectSlot(
    const EffectDescription& description, const ConstantLayout& layout, const std::string& name, const std::uint32_t offset,
    const std::uint32_t size, const std::uint32_t stride
  )
  {
    const ConstantSlot* const slot = Slot(description, layout, name);
    ASSERT_NE(slot, nullptr) << name;
    EXPECT_EQ(slot->offset, offset) << name;
    EXPECT_EQ(slot->size, size) << name;
    EXPECT_EQ(slot->elementStride, stride) << name;
  }
} // namespace

TEST(GalConstantLayout, ScalarsAndVectorsPackIntoRegistersWithoutCrossingThem)
{
  const EffectDescription description = ParseEffect(R"fx(
float a;
float2 b;
float2 c;
float d;
float3 e;
float f;
float1 g;
float3 h;
float4 i;
texture t;
string s = "x";
float j;
)fx");
  const ConstantLayout layout = ComputeConstantLayout(description);
  ExpectSlot(description, layout, "a", 0U, 4U, 16U);
  ExpectSlot(description, layout, "b", 4U, 8U, 16U);   // 4 + 8 fits the first register
  ExpectSlot(description, layout, "c", 16U, 8U, 16U);  // 12 + 8 would cross it
  ExpectSlot(description, layout, "d", 24U, 4U, 16U);
  ExpectSlot(description, layout, "e", 32U, 12U, 16U); // 28 + 12 would cross
  ExpectSlot(description, layout, "f", 44U, 4U, 16U);  // fills the register exactly
  ExpectSlot(description, layout, "g", 48U, 4U, 16U);
  ExpectSlot(description, layout, "h", 52U, 12U, 16U); // float1 + float3 share a register
  ExpectSlot(description, layout, "i", 64U, 16U, 16U);
  ExpectSlot(description, layout, "j", 80U, 4U, 16U);
  EXPECT_EQ(Slot(description, layout, "t"), nullptr) << "textures are not in $Globals";
  EXPECT_EQ(Slot(description, layout, "s"), nullptr) << "nor are strings";
  EXPECT_EQ(layout.size, 84U);
  EXPECT_EQ(layout.slots.size(), 10U);
}

TEST(GalConstantLayout, ArraysAndMatricesStartRegisters)
{
  const EffectDescription description = ParseEffect(R"fx(
float x;
float4x4 world;
float y;
float weights[3];
float z;
float3x4 rowMajor;
column_major float3x4 columnMajor;
float4 colours[2];
float2x2 small;
float1x4 oneRow;
float w;
)fx");
  const ConstantLayout layout = ComputeConstantLayout(description);
  ExpectSlot(description, layout, "x", 0U, 4U, 16U);
  ExpectSlot(description, layout, "world", 16U, 64U, 64U);
  ExpectSlot(description, layout, "y", 80U, 4U, 16U);
  ExpectSlot(description, layout, "weights", 96U, 36U, 16U);    // two full registers and one float
  ExpectSlot(description, layout, "z", 132U, 4U, 16U);          // packs after the last element
  ExpectSlot(description, layout, "rowMajor", 144U, 48U, 48U);  // 3 rows of float4
  ExpectSlot(description, layout, "columnMajor", 192U, 60U, 64U); // 4 columns of float3
  ExpectSlot(description, layout, "colours", 256U, 32U, 16U);
  ExpectSlot(description, layout, "small", 288U, 24U, 32U);     // 2 rows of float2
  ExpectSlot(description, layout, "oneRow", 320U, 16U, 16U);    // one register: packs like a float4, which 312 + 16 would cross
  ExpectSlot(description, layout, "w", 336U, 4U, 16U);
  EXPECT_EQ(layout.size, 340U);
}

TEST(GalConstantLayout, StructsStartARegisterAndLayOutTheirMembers)
{
  const EffectDescription description = ParseEffect(R"fx(
struct Layer { float2 a; float3 b; float c[2]; float4x4 m; };
struct Small { float2 uv; float k; };
struct WithTexture { float k; texture t; };
float x;
Layer one;
Small pair[2];
WithTexture skipped;
Unknown alsoSkipped;
float y;
)fx");
  const ConstantLayout layout = ComputeConstantLayout(description);
  ExpectSlot(description, layout, "x", 0U, 4U, 16U);
  ExpectSlot(description, layout, "one", 16U, 128U, 128U);
  ExpectSlot(description, layout, "pair", 144U, 28U, 16U);
  ExpectSlot(description, layout, "y", 172U, 4U, 16U);
  EXPECT_EQ(Slot(description, layout, "skipped"), nullptr);
  EXPECT_EQ(Slot(description, layout, "alsoSkipped"), nullptr);

  const ConstantSlot* const one = Slot(description, layout, "one");
  ASSERT_NE(one, nullptr);
  ASSERT_EQ(one->members.size(), 4U);
  EXPECT_EQ(one->members[0].offset, 0U);
  EXPECT_EQ(one->members[0].size, 8U);
  EXPECT_EQ(one->members[1].offset, 16U); // 8 + 12 would cross the register
  EXPECT_EQ(one->members[1].size, 12U);
  EXPECT_EQ(one->members[2].offset, 32U);
  EXPECT_EQ(one->members[2].size, 20U);
  EXPECT_EQ(one->members[2].elements, 2U);
  EXPECT_EQ(one->members[2].elementStride, 16U);
  EXPECT_EQ(one->members[3].offset, 64U);
  EXPECT_EQ(one->members[3].size, 64U);
  EXPECT_EQ(one->members[3].parameterClass, ParameterClass::Matrix);
  EXPECT_EQ(one->members[3].rows, 4U);

  const ConstantSlot* const pair = Slot(description, layout, "pair");
  ASSERT_NE(pair, nullptr);
  ASSERT_EQ(pair->members.size(), 2U);
  EXPECT_EQ(pair->members[1].offset, 8U);
  EXPECT_EQ(pair->members[1].elements, 1U);

  EXPECT_EQ(layout.Find(99U), nullptr);
}

TEST(GalModernHlsl, EffectConstructsBecomePlainHlsl)
{
  Generated generated = Generate(faf_gal_tests::kDrawEffect);
  const std::string& hlsl = generated.modern.hlsl;

  EXPECT_TRUE(Contains(hlsl, "struct faf_sampler")) << "the prelude";
  EXPECT_TRUE(Contains(hlsl, "#define sqrt(x) sqrt(abs(x))")) << "D3D9's sqrt on |x|";
  EXPECT_FALSE(Contains(hlsl, "technique10"));
  EXPECT_FALSE(Contains(hlsl, "BlendState"));
  EXPECT_FALSE(Contains(hlsl, "sampler_state"));
  EXPECT_FALSE(Contains(hlsl, "string Name"));
  EXPECT_FALSE(Contains(hlsl, "sampler2D"));
  EXPECT_FALSE(Contains(hlsl, "samplerCUBE"));

  // Numeric parameters stay globals, without their initializers.
  EXPECT_TRUE(Contains(hlsl, "float4x4 WorldViewProj;"));
  EXPECT_TRUE(Contains(hlsl, "float Scale;"));
  EXPECT_TRUE(Contains(hlsl, "float4 Tint;"));
  EXPECT_FALSE(Contains(hlsl, "Scale = 1"));

  // Texture views and samplers on fixed registers; the never-sampled texture has none.
  ASSERT_EQ(generated.modern.textures.size(), 2U);
  EXPECT_EQ(generated.modern.textures[0].parameter, "BaseTexture");
  EXPECT_EQ(generated.modern.textures[0].dimension, TextureDimension::Texture2D);
  EXPECT_EQ(generated.modern.textures[0].slot, 0U);
  EXPECT_EQ(generated.modern.textures[1].parameter, "EnvTexture");
  EXPECT_EQ(generated.modern.textures[1].dimension, TextureDimension::TextureCube);
  EXPECT_EQ(generated.modern.textures[1].slot, 1U);
  EXPECT_TRUE(Contains(hlsl, "Texture2D BaseTexture : register(t0);"));
  EXPECT_TRUE(Contains(hlsl, "TextureCube EnvTexture__faf_cube : register(t1);"));
  EXPECT_FALSE(Contains(hlsl, "UnusedTexture"));
  EXPECT_TRUE(Contains(hlsl, "SamplerState faf_smp_BaseSampler : register(s0);"));
  EXPECT_TRUE(Contains(hlsl, "SamplerState faf_smp_EnvSampler : register(s1);"));
  EXPECT_TRUE(Contains(hlsl, "#define BaseSampler faf_make_sampler(BaseTexture, faf_nullCube, faf_null3D, faf_smp_BaseSampler)"));
  EXPECT_TRUE(Contains(hlsl, "#define EnvSampler faf_make_sampler(faf_null2D, EnvTexture__faf_cube, faf_null3D, faf_smp_EnvSampler)"));

  // A sampler-typed function parameter takes the joined type.
  EXPECT_TRUE(Contains(hlsl, "float4 Lookup( faf_sampler s, float2 uv )"));

  // The vertex shader writes a global: it works on a local copy.
  EXPECT_TRUE(Contains(hlsl, "float faf_local_Scale = Scale;"));
  EXPECT_TRUE(Contains(hlsl, "faf_local_Scale = faf_local_Scale * 2;"));
  EXPECT_TRUE(Contains(hlsl, "position * faf_local_Scale + bias"));
  EXPECT_EQ(Count(hlsl, "faf_local_Tint"), 0U) << "a global only read keeps no copy";

  // The vertex output struct takes the stage-boundary semantic.
  EXPECT_TRUE(Contains(hlsl, "float4 pos : SV_Position;"));
  EXPECT_TRUE(Contains(hlsl, "float2 uv : TEXCOORD0;"));

  EXPECT_EQ(generated.modern.constants.size, 96U);
  EXPECT_TRUE(generated.modern.notes.empty());
}

TEST(GalModernHlsl, OneEntryPointPerStageFunctionAndArguments)
{
  Generated generated = Generate(faf_gal_tests::kDrawEffect);
  const std::vector<ShaderEntry>& entries = generated.modern.entries;
  ASSERT_EQ(entries.size(), 3U);
  EXPECT_EQ(entries[0].stage, ShaderStage::Vertex);
  EXPECT_EQ(entries[0].function, "MainVS");
  EXPECT_EQ(entries[0].arguments, "0.5");
  EXPECT_EQ(entries[0].name, "faf_entry_vs_0");
  EXPECT_EQ(entries[1].stage, ShaderStage::Pixel);
  EXPECT_EQ(entries[1].function, "MainPS");
  EXPECT_EQ(entries[1].name, "faf_entry_ps_1");
  EXPECT_EQ(entries[2].arguments, "1.5");
  EXPECT_EQ(entries[2].name, "faf_entry_vs_2");

  const Technique* const draw = generated.description.FindTechnique("Draw");
  ASSERT_NE(draw, nullptr);
  ASSERT_EQ(draw->passes.size(), 3U);
  EXPECT_EQ(draw->passes[0].vertexShader.entry, "faf_entry_vs_0");
  EXPECT_EQ(draw->passes[0].pixelShader.entry, "faf_entry_ps_1");
  EXPECT_EQ(draw->passes[1].vertexShader.entry, "faf_entry_vs_0") << "the same function and arguments share an entry";
  EXPECT_EQ(draw->passes[1].pixelShader.entry, "faf_entry_ps_1");
  EXPECT_EQ(draw->passes[2].vertexShader.entry, "faf_entry_vs_2");
  EXPECT_EQ(draw->passes[2].pixelShader.entry, "faf_entry_ps_1");

  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "VSOut faf_entry_vs_0(float3 position : POSITION, float2 uv : TEXCOORD0)"));
  EXPECT_TRUE(Contains(hlsl, "return MainVS(position, uv, 0.5);"));
  EXPECT_TRUE(Contains(hlsl, "return MainVS(position, uv, 1.5);"));
  EXPECT_TRUE(Contains(hlsl, "float4 faf_entry_ps_1(VSOut i) : SV_Target0"));
  EXPECT_TRUE(Contains(hlsl, "return MainPS(i);"));
  EXPECT_EQ(Count(hlsl, "faf_entry_"), 3U);
}

TEST(GalModernHlsl, EntryWrappersRewriteSemanticsAndFillUniforms)
{
  Generated generated = Generate(R"fx(
struct VSOut { float4 pos : POSITION; float2 uv : TEXCOORD0; };
void PlainVS( float4 p : POSITION, float3 normal : NORMAL0, float3 unused : NORMAL, out float4 op : POSITION0, out float2 ouv : TEXCOORD0 )
{
    op = p + float4( normal + unused, 0 );
    ouv = p.xy;
}
float4 DepthPS( float4 pos : VPOS, float2 uv : TEXCOORD0, out float depth : DEPTH, uniform float k = 0.25, uniform int mode ) : COLOR
{
    depth = k;
    return float4( uv, pos.z, mode );
}
technique10 T
{
    pass P0
    {
        VertexShader = compile vs_4_0 PlainVS();
        PixelShader = compile ps_4_0 DepthPS();
    }
    pass P1
    {
        VertexShader = compile vs_4_0 PlainVS();
        PixelShader = compile ps_4_0 Missing();
    }
}
)fx");
  const std::string& hlsl = generated.modern.hlsl;
  // A void vertex shader with out parameters: SV_Position on the out position, no `return`.
  EXPECT_TRUE(Contains(hlsl, "void faf_entry_vs_0(float4 p : POSITION, float3 normal : NORMAL0, out float4 op : SV_Position, out float2 ouv : TEXCOORD0)"));
  // Two inputs on one semantic: the second reads the first.
  EXPECT_TRUE(Contains(hlsl, "    PlainVS(p, normal, (float3)normal, op, ouv);"));
  EXPECT_TRUE(Contains(hlsl, "float4 faf_entry_ps_1(float4 pos : SV_Position, float2 uv : TEXCOORD0, out float depth : SV_Depth) : SV_Target0"));
  // Uniform parameters the pass leaves out: their default, or 0.
  EXPECT_TRUE(Contains(hlsl, "return DepthPS(pos, uv, depth, 0.25, 0);"));

  EXPECT_TRUE(HasNote(generated.modern.notes, "technique T: shader function Missing not found"));
  const Technique* const technique = generated.description.FindTechnique("T");
  ASSERT_NE(technique, nullptr);
  EXPECT_TRUE(technique->passes[1].pixelShader.entry.empty());
  EXPECT_EQ(technique->passes[1].vertexShader.entry, "faf_entry_vs_0");
}

TEST(GalModernHlsl, StructRolesFollowTheStagesThatUseThem)
{
  Generated generated = Generate(R"fx(
struct Vertex { float4 position : POSITION0; float4 colour : COLOR0; };
typedef Vertex Pixel;
struct PSOut { float4 c0 : COLOR0; float4 c1 : COLOR1; float d : DEPTH; };
struct Both { float4 p : POSITION; };
struct Unused { float4 p : POSITION; };
Vertex MainVS( float3 v : POSITION0 ) { Vertex r = (Vertex)0; r.position = float4( v, 1 ); return r; }
PSOut MainPS( Pixel i ) { PSOut o = (PSOut)0; o.c0 = i.colour; o.c1 = i.colour; o.d = 0.5; return o; }
Both PassVS( Both b ) { return b; }
technique10 T
{
    pass P0 { VertexShader = compile vs_4_0 MainVS(); PixelShader = compile ps_4_0 MainPS(); }
    pass P1 { VertexShader = compile vs_4_0 PassVS(); }
}
)fx");
  const std::string& hlsl = generated.modern.hlsl;
  // Vertex (and its typedef Pixel): a vertex output, so POSITION0 becomes SV_Position.
  EXPECT_TRUE(Contains(hlsl, "struct Vertex\n{\n    float4 position : SV_Position;\n    float4 colour : COLOR0;\n};"));
  EXPECT_TRUE(Contains(hlsl, "struct PSOut\n{\n    float4 c0 : SV_Target0;\n    float4 c1 : SV_Target1;\n    float d : SV_Depth;\n};"));
  EXPECT_TRUE(Contains(hlsl, "struct Unused { float4 p : POSITION; };")) << "a struct no stage uses is kept as written";
  EXPECT_TRUE(Contains(hlsl, "struct Both { float4 p : POSITION; };"));
  EXPECT_TRUE(HasNote(generated.modern.notes, "struct Both is both a vertex input and a stage output; semantics left as written"));
}

TEST(GalModernHlsl, UntypedAndVolumeSamplersGetEveryViewTheyAreReadIn)
{
  Generated generated = Generate(R"fx(
texture Shared;
texture Volume;
sampler AnySampler = sampler_state { Texture = <Shared>; };
sampler3D VolumeSampler = sampler_state { Texture = <Volume>; };
sampler2D Unbound = sampler_state { Filter = MIN_MAG_MIP_POINT; };
float4 PS2D( float2 uv : TEXCOORD0 ) : COLOR0 { return tex2D( AnySampler, uv ); }
float4 PSCube( float3 dir : TEXCOORD0 ) : COLOR0 { return texCUBE( AnySampler, dir ) + tex3D( VolumeSampler, dir ) + tex2D( Unbound, dir.xy ); }
)fx");
  const std::vector<TextureSlot>& textures = generated.modern.textures;
  ASSERT_EQ(textures.size(), 4U);
  EXPECT_EQ(textures[0].parameter, "Shared");
  EXPECT_EQ(textures[0].dimension, TextureDimension::Texture2D);
  EXPECT_EQ(textures[1].parameter, "Shared");
  EXPECT_EQ(textures[1].dimension, TextureDimension::TextureCube);
  EXPECT_EQ(textures[2].parameter, "Shared");
  EXPECT_EQ(textures[2].dimension, TextureDimension::Texture3D) << "the source has a tex3D lookup";
  EXPECT_EQ(textures[3].parameter, "Volume");
  EXPECT_EQ(textures[3].dimension, TextureDimension::Texture3D);
  EXPECT_EQ(textures[3].slot, 3U);

  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "#define AnySampler faf_make_sampler(Shared, Shared__faf_cube, Shared__faf_3d, faf_smp_AnySampler)"));
  EXPECT_TRUE(Contains(hlsl, "Texture3D Volume__faf_3d : register(t3);"));
  EXPECT_TRUE(Contains(hlsl, "#define VolumeSampler faf_make_sampler(faf_null2D, faf_nullCube, Volume__faf_3d, faf_smp_VolumeSampler)"));
  EXPECT_TRUE(Contains(hlsl, "#define Unbound faf_make_sampler(faf_null2D, faf_nullCube, faf_null3D, faf_smp_Unbound)"));
  EXPECT_TRUE(Contains(hlsl, "SamplerState faf_smp_Unbound : register(s2);"));
}

// Engine addition (ren_ShadowCascades): the lighting shadow samplers read through the cascade atlas, the
// blur samplers on the same texture don't, and a sampler passed on whole keeps the plain type.
TEST(GalModernHlsl, ShadowLookupSamplersReadThroughTheCascadeAtlas)
{
  const std::string body = R"fx(
texture ShadowTexture;
sampler2D ShadowSampler = sampler_state { Texture = (ShadowTexture); };
sampler2D ShadowVerticalBlurSampler = sampler_state { Texture = (ShadowTexture); };
float4 LitPS( float4 shadow : TEXCOORD0 ) : COLOR0 { return tex2D( ShadowSampler, shadow.xy ).g * tex2Dproj(ShadowSampler, shadow); }
float4 BlurPS( float2 uv : TEXCOORD0 ) : COLOR0 { return tex2D( ShadowVerticalBlurSampler, uv ); }
)fx";
  const std::string source = std::string(ShadowCascadeDeclaration()) + body;
  Generated generated = Generate(source);
  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "#define ShadowSampler faf_make_shadow_sampler(ShadowTexture, faf_nullCube, faf_null3D, faf_smp_ShadowSampler)"));
  EXPECT_TRUE(Contains(hlsl, "#define ShadowVerticalBlurSampler faf_make_sampler("));
  EXPECT_TRUE(Contains(hlsl, "float4 faf_ShadowCascades[9];"));
  EXPECT_TRUE(Contains(hlsl, "float2 faf_shadow_uv(float2 uv)"));
  EXPECT_LT(hlsl.find("float4 faf_ShadowCascades[9];"), hlsl.find("float2 faf_shadow_uv(float2 uv)")) << "the helpers read the parameter";
  EXPECT_FALSE(HasNote(generated.modern.notes, "a shadow sampler is used other than in a tex2D lookup; shadow cascades are off"));

  // Without the parameter (an effect the runtime didn't give it) nothing changes.
  Generated plain = Generate(body);
  EXPECT_TRUE(Contains(plain.modern.hlsl, "#define ShadowSampler faf_make_sampler("));
  EXPECT_FALSE(Contains(plain.modern.hlsl, "faf_shadow_uv"));

  // A sampler handed to a function can't take the cascade type: the effect keeps the plain one and the
  // shadow renderer is told to keep the single map.
  gShadowCascadesBlocked.store(false);
  const std::string passed = std::string(ShadowCascadeDeclaration()) + R"fx(
texture shadowTexture;
sampler2D shadowSampler = sampler_state { Texture = (shadowTexture); };
float Look( sampler2D s, float2 uv ) { return tex2D( s, uv ).r; }
float4 PassPS( float2 uv : TEXCOORD0 ) : COLOR0 { return Look( shadowSampler, uv ); }
)fx";
  Generated blocked = Generate(passed);
  EXPECT_TRUE(Contains(blocked.modern.hlsl, "#define shadowSampler faf_make_sampler("));
  EXPECT_TRUE(HasNote(blocked.modern.notes, "a shadow sampler is used other than in a tex2D lookup; shadow cascades are off"));
  EXPECT_TRUE(gShadowCascadesBlocked.load());
  gShadowCascadesBlocked.store(false);
}

// Engine addition (tessellation): a pass naming a hull and a domain function gets attributed entry points around
// them, with the vertex shader's output as the patch's control point.
TEST(GalModernHlsl, TessellatedPassesGetHullAndDomainEntries)
{
  Generated generated = Generate(faf_gal_tests::kTessellatedEffect);
  ASSERT_EQ(generated.description.techniques.size(), 1U);
  const Pass& pass = generated.description.techniques[0].passes[0];
  EXPECT_TRUE(pass.Tessellated());
  EXPECT_FALSE(pass.tessellationDropped);
  EXPECT_FALSE(pass.hullShader.entry.empty());
  EXPECT_FALSE(pass.domainShader.entry.empty());
  std::uint32_t hulls = 0U;
  std::uint32_t domains = 0U;
  for (const ShaderEntry& entry : generated.modern.entries) {
    hulls += (entry.stage == ShaderStage::Hull) ? 1U : 0U;
    domains += (entry.stage == ShaderStage::Domain) ? 1U : 0U;
  }
  EXPECT_EQ(hulls, 1U);
  EXPECT_EQ(domains, 1U);
  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "InputPatch<ControlPoint, 3> faf_patch"));
  EXPECT_TRUE(Contains(hlsl, "OutputPatch<ControlPoint, 3> faf_patch"));
  EXPECT_TRUE(Contains(hlsl, "Place(faf_weights, faf_patch[0], faf_patch[1], faf_patch[2], 2.0)")) << "the pass's argument";
  EXPECT_TRUE(Contains(hlsl, "Factors(faf_patch[0], faf_patch[1], faf_patch[2])"));
}

// A hull shader without its domain shader (or the reverse) is not a tessellated pass: the pass keeps neither
// and is marked, so the engine's load check refuses it rather than drawing patch points as triangles.
TEST(GalModernHlsl, AHullShaderWithoutItsDomainShaderDropsBoth)
{
  std::string source = faf_gal_tests::kTessellatedEffect;
  const std::string domain = "        SetDomainShader( CompileShader( ds_5_0, Place( 2.0 ) ) );\n";
  const std::size_t at = source.find(domain);
  ASSERT_NE(at, std::string::npos);
  source.erase(at, domain.size());
  Generated generated = Generate(source);
  const Pass& pass = generated.description.techniques[0].passes[0];
  EXPECT_FALSE(pass.Tessellated());
  EXPECT_TRUE(pass.tessellationDropped);
  EXPECT_TRUE(pass.hullShader.entry.empty());
  EXPECT_TRUE(HasNote(generated.modern.notes, "technique Tessellated: a hull shader needs a domain shader and the reverse; ignored"));
}

// A domain function that doesn't take the weights and three points can't be wrapped: both stages go.
TEST(GalModernHlsl, ADomainFunctionWithTheWrongParametersDropsTheTessellation)
{
  std::string source = faf_gal_tests::kTessellatedEffect;
  const std::string head = "Surface Place( float3 weights, ControlPoint a, ControlPoint b, ControlPoint c, uniform float scale )";
  const std::size_t at = source.find(head);
  ASSERT_NE(at, std::string::npos);
  source.replace(at, head.size(), "Surface Place( float3 weights, ControlPoint a, ControlPoint b, uniform float scale )");
  const std::string body = "a.position * weights.x + b.position * weights.y + c.position * weights.z";
  const std::size_t bodyAt = source.find(body);
  ASSERT_NE(bodyAt, std::string::npos);
  source.replace(bodyAt, body.size(), "a.position * weights.x + b.position * weights.y");
  Generated generated = Generate(source);
  const Pass& pass = generated.description.techniques[0].passes[0];
  EXPECT_TRUE(pass.tessellationDropped);
  EXPECT_TRUE(pass.hullShader.entry.empty());
  EXPECT_TRUE(pass.domainShader.entry.empty());
  EXPECT_TRUE(HasNote(generated.modern.notes, "technique Tessellated: Place needs 4 varying parameters"));
}

// Engine addition (ren_TextureAnisotropy): only a trilinear sampler that wraps both ways turns anisotropic.
TEST(GalTextureFiltering, OnlyTiledTrilinearSamplersTurnAnisotropic)
{
  const int saved = gTextureAnisotropy;
  SamplerDesc tiled{};
  tiled.filter = 0x15U; // MIN_MAG_MIP_LINEAR
  tiled.addressU = 1U;  // WRAP
  tiled.addressV = 1U;
  SamplerDesc clamped = tiled;
  clamped.addressU = 3U; // CLAMP
  SamplerDesc point = tiled;
  point.filter = 0x00U; // MIN_MAG_MIP_POINT
  SamplerDesc noMips = tiled;
  noMips.filter = 0x14U; // MIN_MAG_LINEAR_MIP_POINT

  gTextureAnisotropy = 8;
  EXPECT_EQ(WithTextureAnisotropy(tiled).filter, 0x55U);
  EXPECT_EQ(WithTextureAnisotropy(tiled).maxAnisotropy, 8U);
  EXPECT_EQ(WithTextureAnisotropy(clamped).filter, 0x15U) << "clamped textures keep their filter";
  EXPECT_EQ(WithTextureAnisotropy(point).filter, 0x00U);
  EXPECT_EQ(WithTextureAnisotropy(noMips).filter, 0x14U);
  SamplerDesc lookup = tiled;
  lookup.texture = "lookupTexture";
  EXPECT_EQ(WithTextureAnisotropy(lookup).filter, 0x15U) << "lookup tables read by computed coordinates keep theirs";
  tiled.texture = "Stratum0AlbedoTexture";
  EXPECT_EQ(WithTextureAnisotropy(tiled).filter, 0x55U);

  gTextureAnisotropy = 32;
  EXPECT_EQ(WithTextureAnisotropy(tiled).maxAnisotropy, 16U) << "capped at what the APIs allow";
  gTextureAnisotropy = 1;
  EXPECT_EQ(WithTextureAnisotropy(tiled).filter, 0x15U) << "1 leaves every sampler as written";
  gTextureAnisotropy = 0;
  EXPECT_EQ(WithTextureAnisotropy(tiled).filter, 0x15U);
  gTextureAnisotropy = saved;
}

TEST(GalModernHlsl, Direct3D9AlphaTestIsEmulatedInThePixelEntry)
{
  const std::string source = R"fx(
struct PSOut { float4 colour : COLOR0; };
float4 VS( float4 p : POSITION ) : POSITION { return p; }
float4 WaterPS( float4 p : TEXCOORD0 ) : COLOR0 { return p; }
PSOut StructPS( float4 p : TEXCOORD0 ) { PSOut o; o.colour = p; return o; }
void VoidPS( float4 p : TEXCOORD0, out float4 c : COLOR0 ) { c = p; }
void AlphaTestD3D10( float a, int f, int r ) { if ( a < 0.5 ) discard; }
technique10 Water
{
    pass P0 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 WaterPS(); }
    pass P1 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 WaterPS(); }
    pass P2 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 StructPS(); }
    pass P3 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 VoidPS(); }
}
)fx";
  EffectDescription description = ParseEffect(source);
  ApplyDirect3D9PassStates(R"fx(
technique Water
{
    pass P0 { AlphaTestEnable = true; AlphaFunc = NotEqual; AlphaRef = 0; }
    pass P1 { }
    pass P2 { AlphaTestEnable = true; AlphaFunc = GreaterEqual; AlphaRef = 128; }
    pass P3 { AlphaTestEnable = true; AlphaFunc = Less; AlphaRef = 1; }
}
)fx",
                           description);
  const ModernEffect modern = GenerateModernHlsl(source, description);
  const std::string& hlsl = modern.hlsl;

  // P0 and P1 call the same function, but only P0 tests alpha: two entries.
  const Technique& water = description.techniques[0];
  EXPECT_NE(water.passes[0].pixelShader.entry, water.passes[1].pixelShader.entry);
  EXPECT_TRUE(Contains(hlsl, "    float4 faf_output = WaterPS(p);\n"
                             "    uint faf_alpha = (uint)round(saturate(faf_output.a) * 255.0);\n"
                             "    uint faf_ref = 0u;\n"
                             "    if (!(faf_alpha != faf_ref)) discard;\n"
                             "    return faf_output;\n"));
  // A struct output tests its first float4 member.
  EXPECT_TRUE(Contains(hlsl, "saturate(faf_output.colour.a)"));
  EXPECT_TRUE(Contains(hlsl, "if (!(faf_alpha >= faf_ref)) discard;"));
  EXPECT_TRUE(Contains(hlsl, "uint faf_ref = 128u;"));
  // Without a float4 colour to test, the pass is noted and runs untested.
  EXPECT_TRUE(HasNote(modern.notes, "technique Water: alpha test on VoidPS without a float4 colour"));
  // The effects' own D3D10 stand-in is emptied: the entry wrapper tests instead.
  EXPECT_FALSE(Contains(hlsl, "if ( a < 0.5 ) discard;"));
  EXPECT_TRUE(Contains(hlsl, "void AlphaTestD3D10( float a, int f, int r ) { }"));

  // Without the original source the stand-in stays as written.
  EffectDescription plain = ParseEffect(source);
  EXPECT_TRUE(Contains(GenerateModernHlsl(source, plain).hlsl, "if ( a < 0.5 ) discard;"));
}

TEST(GalModernHlsl, DirectivesStaticsAndFunctionsWithoutEntriesPassThrough)
{
  Generated generated = Generate("#define FOO 1\nstatic const float kScale = 2;\nfloat Helper( float x ) { return x * kScale; }\nfloat Shadowed;\nfloat Shadow( float Shadowed ) { Shadowed = 1; return Shadowed; }\nfloat Local() { float Shadowed = 2; Shadowed += 1; return Shadowed; }\n");
  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "#define FOO 1\n"));
  EXPECT_TRUE(Contains(hlsl, "static const float kScale = 2;"));
  EXPECT_TRUE(Contains(hlsl, "float Helper( float x ) { return x * kScale; }"));
  EXPECT_EQ(Count(hlsl, "faf_local_Shadowed"), 0U) << "a parameter or local of the same name shadows the global";
  EXPECT_TRUE(generated.modern.entries.empty());
  EXPECT_TRUE(Contains(hlsl, "// ---- entry points (generated) ----"));
}

TEST(GalModernHlsl, WritesThroughIndicesSwizzlesAndIncrementsMakeCopies)
{
  Generated generated = Generate(R"fx(
float4 Colour;
float Counter;
float Total;
float4 Palette[2];
float ReadOnly;
float4 PS( float4 c : COLOR0 ) : COLOR0
{
    Colour.rgb = c.rgb;
    ++Counter;
    Total -= ReadOnly;
    Palette[1].x *= 2;
    return Colour + Counter + Total + Palette[1] + ReadOnly;
}
technique10 T { pass P0 { PixelShader = compile ps_4_0 PS(); } }
)fx");
  const std::string& hlsl = generated.modern.hlsl;
  EXPECT_TRUE(Contains(hlsl, "float4 faf_local_Colour = Colour;"));
  EXPECT_TRUE(Contains(hlsl, "float faf_local_Counter = Counter;"));
  EXPECT_TRUE(Contains(hlsl, "float faf_local_Total = Total;"));
  EXPECT_TRUE(Contains(hlsl, "float4 faf_local_Palette[2] = Palette;"));
  EXPECT_EQ(Count(hlsl, "faf_local_ReadOnly"), 0U);
}

TEST(GalModernHlsl, RegisterBudgetOverflowIsNoted)
{
  std::string source;
  for (int index = 0; index < 65; ++index) {
    const std::string number = std::to_string(index);
    source += "texture T" + number + ";\nsampler2D S" + number + " = sampler_state { Texture = <T" + number + ">; };\n";
  }
  Generated generated = Generate(source);
  EXPECT_EQ(generated.modern.textures.size(), 65U);
  EXPECT_TRUE(HasNote(generated.modern.notes, "more texture views than the register budget"));
  EXPECT_TRUE(HasNote(generated.modern.notes, "more samplers than the register budget"));
}
